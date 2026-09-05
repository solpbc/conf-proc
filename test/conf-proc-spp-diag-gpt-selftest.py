#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Fixture-only checks for production GPT/sysfs PARTUUID discovery.

The fixtures are ordinary files plus a target-shaped sysfs directory.  They
exercise the real parser and discovery functions; no resolver operation is
replaced with a final-answer fake.
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import conf_proc_spp_diag_gpt as gpt  # noqa: E402
import conf_proc_spp_diag_controller as controller  # noqa: E402

SECTOR = 512
SECTORS = 256
PRIMARY_ARRAY = 2
BACKUP_ARRAY = SECTORS - 1 - 32
FIRST_USABLE = 34
LAST_USABLE = BACKUP_ARRAY - 1
DISK_GUID = "12345678-9abc-def0-1234-56789abcdef0"
TYPE_GUID = "00112233-4455-6677-8899-aabbccddeeff"
TARGET_UUID = "01234567-89ab-cdef-1032-547698badcfe"
OTHER_UUID = "89abcdef-0123-4567-89ab-cdef01234567"


def _gpt_uuid(value: str) -> bytes:
    return (
        bytes.fromhex(value[:8])[::-1]
        + bytes.fromhex(value[9:13])[::-1]
        + bytes.fromhex(value[14:18])[::-1]
        + bytes.fromhex(value[19:23] + value[24:])
    )


def _header(current: int, alternate: int, array_lba: int, entries: bytes) -> bytes:
    header = bytearray(SECTOR)
    header[:8] = b"EFI PART"
    struct.pack_into("<IIIIQQQQ", header, 8, 0x00010000, 92, 0, 0, current, alternate, FIRST_USABLE, LAST_USABLE)
    header[56:72] = _gpt_uuid(DISK_GUID)
    struct.pack_into("<QIII", header, 72, array_lba, 128, 128, zlib.crc32(entries) & 0xffffffff)
    struct.pack_into("<I", header, 16, zlib.crc32(header[:92]) & 0xffffffff)
    return bytes(header)


def make_gpt(entries: tuple[tuple[str, int, int], ...] = ((TARGET_UUID, 40, 47),)) -> bytes:
    """Build a valid 512-byte-sector GPT with deliberately asymmetric GUIDs."""

    image = bytearray(SECTORS * SECTOR)
    image[446 + 4] = 0xEE
    struct.pack_into("<II", image, 446 + 8, 1, SECTORS - 1)
    image[510:512] = b"\x55\xaa"
    table = bytearray(128 * 128)
    for number, (unique, start, end) in enumerate(entries):
        offset = number * 128
        table[offset:offset + 16] = _gpt_uuid(TYPE_GUID)
        table[offset + 16:offset + 32] = _gpt_uuid(unique)
        struct.pack_into("<QQ", table, offset + 32, start, end)
    image[SECTOR:2 * SECTOR] = _header(1, SECTORS - 1, PRIMARY_ARRAY, table)
    image[(SECTORS - 1) * SECTOR:SECTORS * SECTOR] = _header(SECTORS - 1, 1, BACKUP_ARRAY, table)
    image[PRIMARY_ARRAY * SECTOR:(PRIMARY_ARRAY + 32) * SECTOR] = table
    image[BACKUP_ARRAY * SECTOR:(BACKUP_ARRAY + 32) * SECTOR] = table
    return bytes(image)


class Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.class_root = root / "sys/class/block"
        self.devblock_root = root / "sys/dev/block"
        self.virtual_root = root / "sys/devices/virtual"
        self.device_root = root / "dev"
        self.class_root.mkdir(parents=True)
        self.devblock_root.mkdir(parents=True)
        self.virtual_root.mkdir(parents=True)
        self.device_root.mkdir()

    def add_disk(
        self, name: str, major: int, minor: int, image: bytes, *, virtual: bool = False, readable: bool = True,
        entry: tuple[str, int, int] | None = None,
    ) -> None:
        base = (self.virtual_root if virtual else self.root / "sys/devices/physical") / name
        base.mkdir(parents=True)
        self._attrs(base, name, "disk", major, minor)
        node = self.device_root / name
        node.write_bytes(image)
        if not readable:
            node.chmod(0)
        self._link(self.class_root / name, base)
        self._link(self.devblock_root / f"{major}:{minor}", base)
        if entry is not None:
            uuid, start, end = entry
            part = base / f"{name}p1"
            part.mkdir()
            self._attrs(part, f"{name}p1", "partition", major, minor + 1, partn=1, start=start, size=end - start + 1)
            part_node = self.device_root / f"{name}p1"
            part_node.write_bytes((uuid.encode("ascii") * 512)[:(end - start + 1) * SECTOR])
            self._link(self.class_root / f"{name}p1", part)
            self._link(self.devblock_root / f"{major}:{minor + 1}", part)

    @staticmethod
    def _link(link: Path, target: Path) -> None:
        os.symlink(str(target), link)

    @staticmethod
    def _attrs(
        directory: Path, devname: str, devtype: str, major: int, minor: int, *, partn: int | None = None,
        start: int | None = None, size: int | None = None,
    ) -> None:
        (directory / "dev").write_text(f"{major}:{minor}\n", encoding="ascii")
        lines = [f"MAJOR={major}", f"MINOR={minor}", f"DEVNAME={devname}", f"DEVTYPE={devtype}"]
        if partn is not None:
            lines.append(f"PARTN={partn}")
            (directory / "partition").write_text(f"{partn}\n", encoding="ascii")
            (directory / "start").write_text(f"{start}\n", encoding="ascii")
            (directory / "size").write_text(f"{size}\n", encoding="ascii")
        # Deliberately poisoned: this parser must never consult PARTUUID.
        lines.append("PARTUUID=ffffffff-ffff-ffff-ffff-ffffffffffff")
        (directory / "uevent").write_text("\n".join(lines) + "\n", encoding="ascii")

    def roots(self) -> gpt.TopologyRoots:
        bindings: dict[tuple[int, int], gpt.FixtureNodeBinding] = {}
        for link in self.devblock_root.iterdir():
            major, minor = (int(value) for value in link.name.split(":"))
            fields = (link.resolve() / "uevent").read_text(encoding="ascii").splitlines()
            devname = next(value.split("=", 1)[1] for value in fields if value.startswith("DEVNAME="))
            node = os.stat(self.device_root / devname)
            bindings[(major, minor)] = gpt.FixtureNodeBinding((major, minor), node.st_dev, node.st_ino)
        return gpt.TopologyRoots(
            str(self.class_root), str(self.devblock_root), str(self.virtual_root), str(self.device_root), bindings,
        )


def _fixture(root: Path, *, include_decoy: bool = True) -> tuple[Fixture, gpt.TopologyRoots]:
    fixture = Fixture(root)
    if include_decoy:
        fixture.add_disk("ordinary", 8, 8, b"\0" * (SECTORS * SECTOR))
    fixture.add_disk("gptdisk", 8, 16, make_gpt(), entry=(TARGET_UUID, 40, 47))
    return fixture, fixture.roots()


def _expect_failure(action) -> None:
    try:
        action()
    except OSError:
        return
    raise AssertionError("malformed discovery input was accepted")


def test_python_gpt_discovery_and_retained_fd(root: Path) -> None:
    fixture, roots = _fixture(root)
    selected = gpt.resolve_partuuid(TARGET_UUID, roots)
    try:
        assert selected.devnum == (8, 17)
        assert gpt.read_selected_exact(selected, 4096).startswith(TARGET_UUID.encode("ascii"))
        # The controller's production read path takes the same direct-root
        # seam; it does not get a path returned from a PARTUUID lookup.
        assert controller._read_binding_device(TARGET_UUID, roots).startswith(TARGET_UUID.encode("ascii"))
        replacement = fixture.device_root / "replacement"
        replacement.write_bytes(b"X" * 4096)
        os.replace(replacement, fixture.device_root / "gptdiskp1")
        # The retained descriptor remains the original topology-proven object.
        assert gpt.read_selected_exact(selected, 4096).startswith(TARGET_UUID.encode("ascii"))
    finally:
        gpt.close_selected(selected)


def test_uuid_truth_and_gpt_fail_closed_cases(root: Path) -> None:
    fixture, roots = _fixture(root)
    _expect_failure(lambda: gpt.resolve_partuuid(OTHER_UUID, roots))
    fixture.add_disk("duplicate", 8, 24, make_gpt(), entry=(TARGET_UUID, 40, 47))
    _expect_failure(lambda: gpt.resolve_partuuid(TARGET_UUID, fixture.roots()))

    # A UUID-only mutation that recomputes both arrays and both header CRCs is
    # still valid GPT, so old UUID discovery must fail on UUID truth alone.
    image = make_gpt(((OTHER_UUID, 40, 47),))
    (fixture.device_root / "gptdisk").write_bytes(image)
    (fixture.device_root / "duplicate").write_bytes(image)
    _expect_failure(lambda: gpt.resolve_partuuid(TARGET_UUID, fixture.roots()))


def test_gpt_indications_and_topology_are_fail_closed(root: Path) -> None:
    fixture, roots = _fixture(root)
    image_path = fixture.device_root / "gptdisk"
    image = bytearray(image_path.read_bytes())
    image[SECTOR:SECTOR + 8] = b"BROKEN!!"
    image_path.write_bytes(image)
    _expect_failure(lambda: gpt.resolve_partuuid(TARGET_UUID, roots))

    shutil.rmtree(root)
    root.mkdir()
    fixture, roots = _fixture(root)
    part_dir = fixture.root / "sys/devices/physical/gptdisk/gptdiskp1"
    (part_dir / "start").write_text("41\n", encoding="ascii")
    _expect_failure(lambda: gpt.resolve_partuuid(TARGET_UUID, roots))

    shutil.rmtree(root)
    root.mkdir()
    fixture = Fixture(root)
    fixture.add_disk("virtual", 8, 32, make_gpt(), virtual=True, entry=(TARGET_UUID, 40, 47))
    _expect_failure(lambda: gpt.resolve_partuuid(TARGET_UUID, fixture.roots()))


def _fresh(root: Path) -> tuple[Fixture, gpt.TopologyRoots]:
    shutil.rmtree(root)
    root.mkdir()
    return _fixture(root)


def _rewrite_header(image: bytearray, lba: int) -> None:
    offset = lba * SECTOR
    struct.pack_into("<I", image, offset + 16, 0)
    struct.pack_into("<I", image, offset + 16, zlib.crc32(image[offset:offset + 92]) & 0xffffffff)


def test_gpt_validation_and_topology_matrix(root: Path) -> None:
    fixture, roots = _fixture(root)
    disk = fixture.device_root / "gptdisk"
    image = bytearray(disk.read_bytes())
    image[(SECTORS - 1) * SECTOR:(SECTORS - 1) * SECTOR + 8] = b"NOT GPT!"
    disk.write_bytes(image)
    _expect_failure(lambda: gpt.resolve_partuuid(TARGET_UUID, roots))

    fixture, roots = _fresh(root)
    disk = fixture.device_root / "gptdisk"
    image = bytearray(disk.read_bytes())
    image[PRIMARY_ARRAY * SECTOR] ^= 1  # primary array CRC is now wrong.
    disk.write_bytes(image)
    _expect_failure(lambda: gpt.resolve_partuuid(TARGET_UUID, roots))

    fixture, roots = _fresh(root)
    disk = fixture.device_root / "gptdisk"
    image = bytearray(disk.read_bytes())
    # Rechecksum the changed backup array/header: arrays remain individually
    # valid but are no longer mutually byte-identical.
    image[BACKUP_ARRAY * SECTOR] ^= 1
    struct.pack_into("<I", image, (SECTORS - 1) * SECTOR + 88,
                     zlib.crc32(image[BACKUP_ARRAY * SECTOR:(BACKUP_ARRAY + 32) * SECTOR]) & 0xffffffff)
    _rewrite_header(image, SECTORS - 1)
    disk.write_bytes(image)
    _expect_failure(lambda: gpt.resolve_partuuid(TARGET_UUID, roots))

    fixture, roots = _fresh(root)
    disk = fixture.device_root / "gptdisk"
    image = bytearray(disk.read_bytes())
    struct.pack_into("<Q", image, (SECTORS - 1) * SECTOR + 40, FIRST_USABLE + 1)
    _rewrite_header(image, SECTORS - 1)
    disk.write_bytes(image)
    _expect_failure(lambda: gpt.resolve_partuuid(TARGET_UUID, roots))

    fixture, roots = _fresh(root)
    disk = fixture.device_root / "gptdisk"
    disk.write_bytes(disk.read_bytes()[:-1])
    _expect_failure(lambda: gpt.resolve_partuuid(TARGET_UUID, roots))

    fixture, roots = _fresh(root)
    (fixture.device_root / "gptdisk").unlink()
    _expect_failure(lambda: gpt.resolve_partuuid(TARGET_UUID, roots))

    fixture, roots = _fresh(root)
    part = fixture.root / "sys/devices/physical/gptdisk/gptdiskp1"
    (part / "uevent").write_text(
        "MAJOR=8\nMINOR=17\nDEVNAME=gptdiskp1\nDEVTYPE=partition\nPARTN=2\n", encoding="ascii",
    )
    _expect_failure(lambda: gpt.resolve_partuuid(TARGET_UUID, roots))

    fixture, roots = _fresh(root)
    part = fixture.root / "sys/devices/physical/gptdisk/gptdiskp1"
    (part / "dev").write_text("8:99\n", encoding="ascii")
    _expect_failure(lambda: gpt.resolve_partuuid(TARGET_UUID, roots))

    fixture, roots = _fresh(root)
    duplicate = make_gpt(((TARGET_UUID, 40, 47), (TARGET_UUID, 48, 55)))
    (fixture.device_root / "gptdisk").write_bytes(duplicate)
    _expect_failure(lambda: gpt.resolve_partuuid(TARGET_UUID, roots))


def test_disk_candidate_bound(root: Path) -> None:
    fixture = Fixture(root)
    for minor in range(257):
        fixture.add_disk(f"disk{minor}", 9, minor, b"\0" * (2 * SECTOR))
    _expect_failure(lambda: gpt.resolve_partuuid(TARGET_UUID, fixture.roots()))


def test_c_direct_fixture_resolver(root: Path) -> None:
    _fixture(root)
    source = root / "direct-resolver.c"
    binary = root / "direct-resolver"
    escaped = str(ROOT / "spp-diag-runtime-src/spp_diag_handoff.c").replace("\\", "\\\\").replace('"', '\\"')
    source.write_text(
        f'''#define main embedded_handoff_main
#include "{escaped}"
#undef main

int main(int argc, char **argv) {{
    char class_root[PATH_MAX], dev_block_root[PATH_MAX], virtual_root[PATH_MAX], device_root[PATH_MAX];
    struct stat ordinary, disk, part;
    struct spp_diag_fixture_node_binding bindings[3];
    if (argc != 2 || snprintf(class_root, sizeof(class_root), "%s/sys/class/block", argv[1]) < 0 ||
        snprintf(dev_block_root, sizeof(dev_block_root), "%s/sys/dev/block", argv[1]) < 0 ||
        snprintf(virtual_root, sizeof(virtual_root), "%s/sys/devices/virtual", argv[1]) < 0 ||
        snprintf(device_root, sizeof(device_root), "%s/dev", argv[1]) < 0 ||
        stat("{root}/dev/ordinary", &ordinary) != 0 || stat("{root}/dev/gptdisk", &disk) != 0 || stat("{root}/dev/gptdiskp1", &part) != 0) return 2;
    bindings[0] = (struct spp_diag_fixture_node_binding){{8, 8, ordinary.st_dev, ordinary.st_ino}};
    bindings[1] = (struct spp_diag_fixture_node_binding){{8, 16, disk.st_dev, disk.st_ino}};
    bindings[2] = (struct spp_diag_fixture_node_binding){{8, 17, part.st_dev, part.st_ino}};
    struct spp_diag_resolver_roots roots = {{class_root, dev_block_root, virtual_root, device_root, bindings, 3}};
    char id[32]; dev_t rdev = 0; int fd = -1; unsigned char data[8];
    if (spp_diag_resolve_partuuid_at(&roots, "{TARGET_UUID}", id, sizeof(id), &rdev, &fd) != 0) return 10;
    if (strcmp(id, "8:17") != 0) return 11;
    if (rdev != makedev(8, 17)) return 12;
    if (pread(fd, data, sizeof(data), 0) != (ssize_t)sizeof(data)) return 13;
    return close(fd) == 0 ? 0 : 4;
}}
''', encoding="utf-8",
    )
    command = ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", "-o", str(binary), str(source)]
    compiled = subprocess.run(command, capture_output=True, text=True)
    assert compiled.returncode == 0, compiled.stderr
    ran = subprocess.run([str(binary), str(root)], capture_output=True, text=True)
    assert ran.returncode == 0, (ran.returncode, ran.stdout, ran.stderr)


def main() -> None:
    tests = (
        test_python_gpt_discovery_and_retained_fd,
        test_uuid_truth_and_gpt_fail_closed_cases,
        test_gpt_indications_and_topology_are_fail_closed,
        test_gpt_validation_and_topology_matrix,
        test_disk_candidate_bound,
        test_c_direct_fixture_resolver,
    )
    with tempfile.TemporaryDirectory(dir="/var/tmp") as temporary:
        root = Path(temporary)
        for test in tests:
            case = root / test.__name__
            case.mkdir()
            test(case)
            print(f"ok   {test.__name__}")
    print(f"SPP GPT resolver: ok ({len(tests)} tests)")


if __name__ == "__main__":
    main()
