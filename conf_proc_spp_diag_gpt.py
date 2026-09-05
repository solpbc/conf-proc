#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded, fail-closed GPT and sysfs partition discovery for SPP diagnostics.

Sysfs supplies kernel topology only.  The requested PARTUUID is matched solely
against the on-disk GPT partition-entry unique GUID.
"""

from __future__ import annotations

from dataclasses import dataclass
import fcntl
import os
import re
import stat
import struct
import zlib


_SECTOR = 512
_ENTRY_COUNT = 128
_ENTRY_SIZE = 128
_ARRAY_BYTES = _ENTRY_COUNT * _ENTRY_SIZE
_ARRAY_SECTORS = _ARRAY_BYTES // _SECTOR
_MAX_METADATA_BYTES = 64 * 1024
_MAX_DISKS = 256
_MAX_CLASS_ENTRIES = 65_536
_MAX_ANCESTORS = 64
_TEXT_CAP = 4096
_BLKSSZGET = 0x1268
_BLKGETSIZE64 = 0x80081272
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")


@dataclass(frozen=True)
class FixtureNodeBinding:
    """Test-only identity of a regular fixture object, keyed by sysfs dev."""

    devnum: tuple[int, int]
    st_dev: int
    st_ino: int


@dataclass(frozen=True)
class TopologyRoots:
    class_block_root: str
    dev_block_root: str
    virtual_root: str
    device_root: str
    fixture_bindings: dict[tuple[int, int], FixtureNodeBinding] | None = None

    @classmethod
    def production(cls) -> "TopologyRoots":
        return cls("/sys/class/block", "/sys/dev/block", "/sys/devices/virtual", "/dev")


@dataclass(frozen=True)
class SelectedPartition:
    fd: int
    devnum: tuple[int, int]
    object_identity: tuple[int, int, int]
    size_sectors: int
    fixture: bool


@dataclass(frozen=True)
class _Disk:
    key: tuple[int, int]
    devnum: tuple[int, int]
    devname: str


@dataclass(frozen=True)
class _Partition:
    parent_key: tuple[int, int]
    devnum: tuple[int, int]
    devname: str
    number: int
    start: int
    size: int


@dataclass(frozen=True)
class _Match:
    disk_key: tuple[int, int]
    number: int
    start: int
    size: int


def resolve_partuuid(partuuid: str, roots: TopologyRoots | None = None) -> SelectedPartition:
    """Resolve one GPT unique GUID to one retained, topology-proven partition FD."""

    if _UUID.fullmatch(partuuid) is None:
        raise OSError("invalid PARTUUID")
    roots = TopologyRoots.production() if roots is None else roots
    wanted = _uuid_to_gpt(partuuid)
    first_disks, _first_partitions = _scan_topology(roots)
    matches: list[_Match] = []
    for disk in first_disks.values():
        match = _scan_disk(roots, disk, wanted)
        if match is not None:
            matches.append(match)
            if len(matches) > 1:
                raise OSError("PARTUUID is duplicated across GPT disks")
    if not matches:
        raise OSError("PARTUUID is absent from eligible GPT disks")

    winner = matches[0]
    second_disks, partitions = _scan_topology(roots)
    if set(second_disks) != set(first_disks):
        raise OSError("sysfs disk topology changed during discovery")
    for key, disk in first_disks.items():
        if second_disks[key] != disk:
            raise OSError("sysfs disk identity changed during discovery")
    candidates = [
        part for part in partitions
        if part.parent_key == winner.disk_key and part.number == winner.number
        and part.start == winner.start and part.size == winner.size
    ]
    if len(candidates) != 1:
        raise OSError("GPT entry has no unique matching partition topology")
    selected = _open_node(roots, candidates[0].devname, candidates[0].devnum)
    try:
        _revalidate(selected)
        expected_bytes = _checked_mul(candidates[0].size, _SECTOR)
        if _node_size(selected.fd, selected.fixture) != expected_bytes:
            raise OSError("partition device size disagrees with GPT")
        return SelectedPartition(
            selected.fd,
            selected.devnum,
            selected.object_identity,
            candidates[0].size,
            selected.fixture,
        )
    except Exception:
        os.close(selected.fd)
        raise


def read_selected_exact(selected: SelectedPartition, count: int, offset: int = 0) -> bytes:
    if type(count) is not int or type(offset) is not int or count < 0 or offset < 0:
        raise OSError("invalid selected-device read")
    _revalidate(selected)
    size = _node_size(selected.fd, selected.fixture)
    if selected.size_sectors <= 0 or size != _checked_mul(selected.size_sectors, _SECTOR):
        raise OSError("selected-device size changed")
    if _checked_add(offset, count) > size:
        raise OSError("selected-device read exceeds bounds")
    return _pread_exact(selected.fd, count, offset, size)


def close_selected(selected: SelectedPartition) -> None:
    os.close(selected.fd)


def _scan_topology(roots: TopologyRoots) -> tuple[dict[tuple[int, int], _Disk], tuple[_Partition, ...]]:
    virtual_fd = os.open(roots.virtual_root, os.O_RDONLY | _odirectory() | os.O_CLOEXEC)
    class_fd = os.open(roots.class_block_root, os.O_RDONLY | _odirectory() | os.O_CLOEXEC)
    dev_block_fd = os.open(roots.dev_block_root, os.O_RDONLY | _odirectory() | os.O_CLOEXEC)
    try:
        virtual_identity = _identity(virtual_fd)
        names = os.listdir(class_fd)
        if len(names) > _MAX_CLASS_ENTRIES:
            raise OSError("too many sysfs block objects")
        disks: dict[tuple[int, int], _Disk] = {}
        partitions: list[_Partition] = []
        partition_numbers: dict[tuple[int, int], set[int]] = {}
        partition_count: dict[tuple[int, int], int] = {}
        for name in names:
            if name in (".", ".."):
                continue
            object_fd = _open_dir_at(class_fd, name)
            physical_fd = -1
            try:
                class_identity = _identity(object_fd)
                devnum = _read_dev(object_fd)
                physical_fd = _open_dir_at(dev_block_fd, _dev_text(devnum))
                if _identity(physical_fd) != class_identity or _read_dev(physical_fd) != devnum:
                    raise OSError("class/dev-block device identity mismatch")
                if _has_virtual_ancestor(physical_fd, virtual_identity):
                    continue
                partition_number = _optional_uint(physical_fd, "partition")
                if partition_number is None:
                    disk = _read_disk(physical_fd)
                    _add_disk(disks, disk)
                    continue
                partition, parent = _read_partition(physical_fd, partition_number)
                _add_disk(disks, parent)
                numbers = partition_numbers.setdefault(parent.key, set())
                count = partition_count.get(parent.key, 0) + 1
                if count > _ENTRY_COUNT or partition.number in numbers:
                    raise OSError("duplicate or excessive partition topology")
                partition_count[parent.key] = count
                numbers.add(partition.number)
                partitions.append(partition)
            finally:
                if physical_fd >= 0:
                    os.close(physical_fd)
                os.close(object_fd)
        return disks, tuple(partitions)
    finally:
        os.close(dev_block_fd)
        os.close(class_fd)
        os.close(virtual_fd)


def _add_disk(disks: dict[tuple[int, int], _Disk], disk: _Disk) -> None:
    previous = disks.get(disk.key)
    if previous is not None:
        if previous != disk:
            raise OSError("inconsistent disk topology identity")
        return
    if len(disks) >= _MAX_DISKS:
        raise OSError("too many eligible physical disks")
    disks[disk.key] = disk


def _read_disk(fd: int) -> _Disk:
    if _optional_uint(fd, "partition") is not None:
        raise OSError("whole disk has partition attribute")
    fields = _uevent(fd)
    devnum = _read_dev(fd)
    if fields["DEVTYPE"] != "disk" or _uevent_dev(fields) != devnum:
        raise OSError("invalid whole-disk uevent")
    return _Disk(_identity(fd), devnum, _safe_devname(fields["DEVNAME"]))


def _read_partition(fd: int, partition_number: int) -> tuple[_Partition, _Disk]:
    if not 1 <= partition_number <= _ENTRY_COUNT:
        raise OSError("invalid sysfs partition number")
    fields = _uevent(fd)
    devnum = _read_dev(fd)
    if fields["DEVTYPE"] != "partition" or _uevent_dev(fields) != devnum:
        raise OSError("invalid partition uevent")
    if _parse_uint(fields.get("PARTN", ""), _ENTRY_COUNT) != partition_number:
        raise OSError("PARTN disagrees with partition attribute")
    start = _require_uint(fd, "start")
    size = _require_uint(fd, "size")
    if size == 0:
        raise OSError("zero-sized partition")
    _checked_add(start, size - 1)
    parent_fd = _open_dir_at(fd, "..")
    try:
        parent = _read_disk(parent_fd)
    finally:
        os.close(parent_fd)
    return _Partition(parent.key, devnum, _safe_devname(fields["DEVNAME"]), partition_number, start, size), parent


def _scan_disk(roots: TopologyRoots, disk: _Disk, wanted: bytes) -> _Match | None:
    selected = _open_node(roots, disk.devname, disk.devnum)
    try:
        _revalidate(selected)
        size = _node_size(selected.fd, selected.fixture)
        if size % _SECTOR or size < 2 * _SECTOR:
            raise OSError("disk has invalid 512-byte sector geometry")
        sectors = size // _SECTOR
        final_lba = sectors - 1
        if 3 * _SECTOR + 2 * _ARRAY_BYTES > _MAX_METADATA_BYTES:
            raise OSError("GPT metadata read budget is invalid")
        mbr = _pread_exact(selected.fd, _SECTOR, 0, size)
        primary = _pread_exact(selected.fd, _SECTOR, _SECTOR, size)
        backup = _pread_exact(selected.fd, _SECTOR, _checked_mul(final_lba, _SECTOR), size)
        protective = _protective_mbr_state(mbr, final_lba)
        marked = protective != 0 or primary[:8] == b"EFI PART" or backup[:8] == b"EFI PART"
        # These are the only three observations needed to classify a readable
        # disk as ordinary.  Anything that looks partly like GPT is fatal.
        if not marked:
            return None
        if protective != 1 or primary[:8] != b"EFI PART" or backup[:8] != b"EFI PART":
            raise OSError("partial GPT indication")
        first = _parse_header(primary, current=1, final=final_lba)
        second = _parse_header(backup, current=final_lba, final=final_lba)
        _check_headers(first, second, final_lba)
        first_array = _pread_exact(selected.fd, _ARRAY_BYTES, _checked_mul(first["array_lba"], _SECTOR), size)
        second_array = _pread_exact(selected.fd, _ARRAY_BYTES, _checked_mul(second["array_lba"], _SECTOR), size)
        if _crc32(first_array) != first["array_crc"] or _crc32(second_array) != second["array_crc"] or first_array != second_array:
            raise OSError("GPT partition arrays disagree")
        matches: list[_Match] = []
        seen_guids: set[bytes] = set()
        ranges: list[tuple[int, int]] = []
        for index in range(_ENTRY_COUNT):
            entry = first_array[index * _ENTRY_SIZE:(index + 1) * _ENTRY_SIZE]
            type_guid, unique_guid = entry[:16], entry[16:32]
            if not any(type_guid):
                if any(entry):
                    raise OSError("nonzero empty GPT entry")
                continue
            if not any(unique_guid) or unique_guid in seen_guids:
                raise OSError("invalid or duplicate GPT unique GUID")
            seen_guids.add(unique_guid)
            start, end = struct.unpack_from("<QQ", entry, 32)
            if start > end or start < first["first_usable"] or end > first["last_usable"]:
                raise OSError("GPT entry range is invalid")
            for other_start, other_end in ranges:
                if not (end < other_start or start > other_end):
                    raise OSError("GPT entries overlap")
            ranges.append((start, end))
            if unique_guid == wanted:
                matches.append(_Match(disk.key, index + 1, start, _checked_add(end - start, 1)))
        if len(matches) > 1:
            raise OSError("PARTUUID is duplicated within GPT")
        return matches[0] if matches else None
    finally:
        os.close(selected.fd)


def _protective_mbr_state(data: bytes, final_lba: int) -> int:
    """Return 1 valid protective, 0 ordinary, -1 malformed protective indication."""
    entries = [data[446 + index * 16:462 + index * 16] for index in range(4)]
    protective_seen = any(entry[4] == 0xEE for entry in entries)
    nonempty = [entry for entry in entries if any(entry)]
    if not protective_seen:
        return 0
    if data[510:512] != b"\x55\xaa" or len(nonempty) != 1:
        return -1
    entry = nonempty[0]
    start, count = struct.unpack_from("<II", entry, 8)
    expected_count = min(final_lba, 0xffffffff)
    if entry[0] != 0 or entry[4] != 0xEE or start != 1 or count != expected_count:
        return -1
    return 1


def _parse_header(data: bytes, *, current: int, final: int) -> dict[str, int | bytes]:
    if len(data) != _SECTOR or data[:8] != b"EFI PART":
        raise OSError("GPT header signature is invalid")
    revision, header_size, header_crc, reserved = struct.unpack_from("<IIII", data, 8)
    if revision != 0x00010000 or not 92 <= header_size <= _SECTOR or reserved != 0:
        raise OSError("GPT header fields are invalid")
    checked = bytearray(data[:header_size])
    checked[16:20] = b"\0" * 4
    if _crc32(checked) != header_crc:
        raise OSError("GPT header CRC is invalid")
    current_lba, alternate_lba, first_usable, last_usable = struct.unpack_from("<QQQQ", data, 24)
    array_lba = struct.unpack_from("<Q", data, 72)[0]
    entry_count, entry_size, array_crc = struct.unpack_from("<III", data, 80)
    if current_lba != current or alternate_lba > final or entry_count != _ENTRY_COUNT or entry_size != _ENTRY_SIZE:
        raise OSError("GPT header geometry is invalid")
    if (
        first_usable > last_usable
        or first_usable < 2
        or last_usable >= final
        or not any(data[56:72])
    ):
        raise OSError("GPT usable range or disk GUID is invalid")
    array_end = _checked_add(array_lba, _ARRAY_SECTORS - 1)
    if array_lba > final or array_end > final:
        raise OSError("GPT array exceeds disk")
    return {
        "header_size": header_size, "current": current_lba, "alternate": alternate_lba,
        "first_usable": first_usable, "last_usable": last_usable, "disk_guid": data[56:72],
        "array_lba": array_lba, "array_crc": array_crc,
    }


def _check_headers(first: dict[str, int | bytes], second: dict[str, int | bytes], final: int) -> None:
    if first["alternate"] != final or second["alternate"] != 1:
        raise OSError("GPT headers are not reciprocal")
    for key in ("header_size", "first_usable", "last_usable", "disk_guid", "array_crc"):
        if first[key] != second[key]:
            raise OSError("GPT headers disagree")
    first_range = (int(first["array_lba"]), _checked_add(int(first["array_lba"]), _ARRAY_SECTORS - 1))
    second_range = (int(second["array_lba"]), _checked_add(int(second["array_lba"]), _ARRAY_SECTORS - 1))
    usable = (int(first["first_usable"]), int(first["last_usable"]))
    for start, end in (first_range, second_range):
        if (
            start == 0
            or start <= 1 <= end
            or start <= final <= end
            or not (end < usable[0] or start > usable[1])
        ):
            raise OSError("GPT array overlaps header or usable range")
    if not (first_range[1] < second_range[0] or second_range[1] < first_range[0]):
        raise OSError("GPT arrays overlap")


def _open_node(roots: TopologyRoots, devname: str, devnum: tuple[int, int]) -> SelectedPartition:
    path = os.path.join(roots.device_root, devname)
    before = os.lstat(path)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | _nofollow())
    try:
        opened = os.fstat(fd)
        fixture = roots.fixture_bindings is not None
        if fixture:
            binding = roots.fixture_bindings.get(devnum)
            if (
                binding is None
                or binding.devnum != devnum
                or not stat.S_ISREG(opened.st_mode)
                or (opened.st_dev, opened.st_ino) != (binding.st_dev, binding.st_ino)
            ):
                raise OSError("fixture device identity changed")
        elif not stat.S_ISBLK(opened.st_mode) or opened.st_rdev != os.makedev(*devnum):
            raise OSError("device node does not match sysfs dev")
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise OSError("device pathname changed during open")
        return SelectedPartition(fd, devnum, (opened.st_dev, opened.st_ino, opened.st_rdev), 0, fixture)
    except Exception:
        os.close(fd)
        raise


def _revalidate(selected: SelectedPartition) -> None:
    opened = os.fstat(selected.fd)
    if (opened.st_dev, opened.st_ino, opened.st_rdev) != selected.object_identity:
        raise OSError("selected descriptor identity changed")
    if selected.fixture:
        if not stat.S_ISREG(opened.st_mode):
            raise OSError("fixture descriptor is not regular")
    elif not stat.S_ISBLK(opened.st_mode) or opened.st_rdev != os.makedev(*selected.devnum):
        raise OSError("selected descriptor is not expected block device")


def _node_size(fd: int, fixture: bool) -> int:
    if fixture:
        size = os.fstat(fd).st_size
    else:
        try:
            logical = struct.unpack("I", fcntl.ioctl(fd, _BLKSSZGET, struct.pack("I", 0)))[0]
            size = struct.unpack("Q", fcntl.ioctl(fd, _BLKGETSIZE64, struct.pack("Q", 0)))[0]
        except OSError as exc:
            raise OSError("could not inspect block geometry") from exc
        if logical != _SECTOR:
            raise OSError("logical sector size is not 512")
    if type(size) is not int or size < 0:
        raise OSError("invalid device size")
    return size


def _pread_exact(fd: int, count: int, offset: int, size: int) -> bytes:
    if count < 0 or offset < 0 or _checked_add(offset, count) > size:
        raise OSError("device read exceeds bounds")
    chunks: list[bytes] = []
    total = 0
    while total < count:
        chunk = os.pread(fd, count - total, offset + total)
        if not chunk:
            raise OSError("short device read")
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def _uevent(fd: int) -> dict[str, str]:
    raw = _read_text_at(fd, "uevent", _TEXT_CAP)
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise OSError("non-ascii sysfs uevent") from exc
    fields: dict[str, str] = {}
    for line in lines:
        if "=" not in line:
            raise OSError("malformed sysfs uevent")
        key, value = line.split("=", 1)
        if not key or key in fields:
            raise OSError("malformed sysfs uevent")
        fields[key] = value
    if not {"DEVNAME", "DEVTYPE", "MAJOR", "MINOR"} <= set(fields):
        raise OSError("incomplete sysfs uevent")
    return fields


def _uevent_dev(fields: dict[str, str]) -> tuple[int, int]:
    return _parse_uint(fields["MAJOR"], (1 << 20) - 1), _parse_uint(fields["MINOR"], (1 << 20) - 1)


def _read_dev(fd: int) -> tuple[int, int]:
    text = _read_text_at(fd, "dev", 64).decode("ascii").strip()
    if text.count(":") != 1:
        raise OSError("malformed sysfs dev")
    major, minor = text.split(":", 1)
    return _parse_uint(major, (1 << 20) - 1), _parse_uint(minor, (1 << 20) - 1)


def _dev_text(devnum: tuple[int, int]) -> str:
    return f"{devnum[0]}:{devnum[1]}"


def _optional_uint(fd: int, name: str) -> int | None:
    try:
        return _require_uint(fd, name)
    except FileNotFoundError:
        return None


def _require_uint(fd: int, name: str) -> int:
    return _parse_uint(_read_text_at(fd, name, 64).decode("ascii").strip(), (1 << 64) - 1)


def _read_text_at(dirfd: int, name: str, cap: int) -> bytes:
    fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | _nofollow(), dir_fd=dirfd)
    try:
        node = os.fstat(fd)
        if not stat.S_ISREG(node.st_mode):
            raise OSError("sysfs attribute is not regular")
        result = bytearray()
        while len(result) <= cap:
            chunk = os.read(fd, min(1024, cap + 1 - len(result)))
            if not chunk:
                return bytes(result)
            result.extend(chunk)
        raise OSError("sysfs attribute exceeds cap")
    finally:
        os.close(fd)


def _has_virtual_ancestor(fd: int, virtual_identity: tuple[int, int]) -> bool:
    current = os.dup(fd)
    try:
        for _depth in range(_MAX_ANCESTORS):
            if _identity(current) == virtual_identity:
                return True
            parent = _open_dir_at(current, "..")
            if _identity(parent) == _identity(current):
                os.close(parent)
                return False
            os.close(current)
            current = parent
        raise OSError("sysfs ancestry exceeds bound")
    finally:
        try:
            os.close(current)
        except OSError:
            pass


def _open_dir_at(dirfd: int, name: str) -> int:
    return os.open(name, os.O_RDONLY | _odirectory() | os.O_CLOEXEC, dir_fd=dirfd)


def _identity(fd: int) -> tuple[int, int]:
    value = os.fstat(fd)
    return value.st_dev, value.st_ino


def _safe_devname(value: str) -> str:
    if not value or "/" in value or value in (".", "..") or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-" for c in value):
        raise OSError("invalid DEVNAME")
    return value


def _parse_uint(value: str, maximum: int) -> int:
    if not value or not value.isdecimal():
        raise OSError("invalid unsigned integer")
    parsed = int(value, 10)
    if parsed > maximum:
        raise OSError("unsigned integer exceeds bound")
    return parsed


def _uuid_to_gpt(value: str) -> bytes:
    # GPT stores the first three RFC-4122 fields little-endian.
    return bytes.fromhex(value[0:8])[::-1] + bytes.fromhex(value[9:13])[::-1] + bytes.fromhex(value[14:18])[::-1] + bytes.fromhex(value[19:23] + value[24:])


def _crc32(data: bytes | bytearray) -> int:
    return zlib.crc32(data) & 0xffffffff


def _checked_add(left: int, right: int) -> int:
    if left < 0 or right < 0 or left > (1 << 64) - 1 - right:
        raise OSError("integer overflow")
    return left + right


def _checked_mul(left: int, right: int) -> int:
    if left < 0 or right < 0 or (left and right > ((1 << 64) - 1) // left):
        raise OSError("integer overflow")
    return left * right


def _nofollow() -> int:
    return getattr(os, "O_NOFOLLOW", 0)


def _odirectory() -> int:
    return getattr(os, "O_DIRECTORY", 0)
