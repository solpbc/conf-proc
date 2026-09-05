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


def _header(current: int, alternate: int, array_lba: int, entries: bytes, first_usable: int, last_usable: int) -> bytes:
    header = bytearray(SECTOR)
    header[:8] = b"EFI PART"
    struct.pack_into("<IIIIQQQQ", header, 8, 0x00010000, 92, 0, 0, current, alternate, first_usable, last_usable)
    header[56:72] = _gpt_uuid(DISK_GUID)
    struct.pack_into("<QIII", header, 72, array_lba, 128, 128, zlib.crc32(entries) & 0xffffffff)
    struct.pack_into("<I", header, 16, zlib.crc32(header[:92]) & 0xffffffff)
    return bytes(header)


def make_gpt(
    entries: tuple[tuple[str, int, int], ...] = ((TARGET_UUID, 40, 47),), *, primary_array: int = PRIMARY_ARRAY,
    backup_array: int = BACKUP_ARRAY, first_usable: int = FIRST_USABLE, last_usable: int = LAST_USABLE,
) -> bytes:
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
    image[SECTOR:2 * SECTOR] = _header(1, SECTORS - 1, primary_array, table, first_usable, last_usable)
    image[(SECTORS - 1) * SECTOR:SECTORS * SECTOR] = _header(
        SECTORS - 1, 1, backup_array, table, first_usable, last_usable,
    )
    image[primary_array * SECTOR:(primary_array + 32) * SECTOR] = table
    image[backup_array * SECTOR:(backup_array + 32) * SECTOR] = table
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
        self, name: str, major: int, minor: int, image: bytes, *, virtual: bool = False,
        entry: tuple[str, int, int] | None = None,
    ) -> None:
        base = (self.virtual_root if virtual else self.root / "sys/devices/physical") / name
        base.mkdir(parents=True)
        self._attrs(base, name, "disk", major, minor)
        node = self.device_root / name
        node.write_bytes(image)
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


class CResolverProbe:
    """Directly include the native resolver and run it against these fixtures."""

    def __init__(self, directory: Path) -> None:
        source = directory / "direct-resolver.c"
        self.binary = directory / "direct-resolver"
        escaped = str(ROOT / "spp-diag-runtime-src/spp_diag_handoff.c").replace("\\", "\\\\").replace('"', '\\"')
        source.write_text(
            f'''#define main embedded_handoff_main
#include "{escaped}"
#undef main

int main(int argc, char **argv) {{
    static const char *const names[] = {{"ordinary", "gptdisk", "gptdiskp1", "duplicate", "duplicatep1", "rogue"}};
    static const unsigned int majors[] = {{8, 8, 8, 8, 8, 8}};
    static const unsigned int minors[] = {{8, 16, 17, 24, 25, 30}};
    char class_root[PATH_MAX], dev_block_root[PATH_MAX], virtual_root[PATH_MAX], device_root[PATH_MAX], path[PATH_MAX], replacement[PATH_MAX];
    struct spp_diag_fixture_node_binding bindings[sizeof(names) / sizeof(names[0])];
    size_t binding_count = 0;
    if (argc < 4 || argc > 5 || snprintf(class_root, sizeof(class_root), "%s/sys/class/block", argv[1]) < 0 ||
        snprintf(dev_block_root, sizeof(dev_block_root), "%s/sys/dev/block", argv[1]) < 0 ||
        snprintf(virtual_root, sizeof(virtual_root), "%s/sys/devices/virtual", argv[1]) < 0 ||
        snprintf(device_root, sizeof(device_root), "%s/dev", argv[1]) < 0) return 2;
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {{
        struct stat node;
        if (snprintf(path, sizeof(path), "%s/%s", device_root, names[i]) < 0) return 3;
        if (lstat(path, &node) != 0) continue;
        bindings[binding_count++] = (struct spp_diag_fixture_node_binding){{majors[i], minors[i], node.st_dev, node.st_ino}};
    }}
    struct spp_diag_resolver_roots roots = {{class_root, dev_block_root, virtual_root, device_root, bindings, binding_count}};
    char id[32]; dev_t rdev = 0; int fd = -1; int result;
    result = spp_diag_resolve_partuuid_at(&roots, argv[2], id, sizeof(id), &rdev, &fd);
    if ((strcmp(argv[3], "ok") == 0 && result != 0) || (strcmp(argv[3], "fail") == 0 && result == 0)) {{
        if (fd >= 0) close(fd);
        return 10;
    }}
    if (strcmp(argv[3], "fail") == 0) return 0;
    if (strcmp(id, "8:17") != 0 || rdev != makedev(8, 17)) {{ close(fd); return 11; }}
    if (argc == 5) {{
        unsigned char data[8];
        if (snprintf(path, sizeof(path), "%s/replacement", device_root) < 0 ||
            snprintf(replacement, sizeof(replacement), "%s/gptdiskp1", device_root) < 0 ||
            rename(path, replacement) != 0) {{ close(fd); return 12; }}
        if (pread(fd, data, sizeof(data), 0) != (ssize_t)sizeof(data) || memcmp(data, argv[2], sizeof(data)) != 0) {{ close(fd); return 13; }}
    }}
    return close(fd) == 0 ? 0 : 14;
}}
''',
            encoding="utf-8",
        )
        command = ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", "-o", str(self.binary), str(source)]
        compiled = subprocess.run(command, capture_output=True, text=True)
        assert compiled.returncode == 0, compiled.stderr

    def run(self, root: Path, partuuid: str, *, success: bool, substitute: bool = False) -> None:
        arguments = [str(self.binary), str(root), partuuid, "ok" if success else "fail"]
        if substitute:
            arguments.append("substitute")
        ran = subprocess.run(arguments, capture_output=True, text=True)
        assert ran.returncode == 0, (ran.returncode, ran.stdout, ran.stderr)


def _expect_both_failure(probe: CResolverProbe, fixture: Fixture, roots: gpt.TopologyRoots, partuuid: str = TARGET_UUID) -> None:
    _expect_failure(lambda: gpt.resolve_partuuid(partuuid, roots))
    probe.run(fixture.root, partuuid, success=False)


def _rewrite_header(image: bytearray, lba: int) -> None:
    offset = lba * SECTOR
    struct.pack_into("<I", image, offset + 16, 0)
    struct.pack_into("<I", image, offset + 16, zlib.crc32(image[offset:offset + 92]) & 0xffffffff)


def _mutate_entry_table(image: bytearray, mutate) -> None:
    primary_lba = struct.unpack_from("<Q", image, SECTOR + 72)[0]
    backup_lba = struct.unpack_from("<Q", image, (SECTORS - 1) * SECTOR + 72)[0]
    table = bytearray(image[primary_lba * SECTOR:(primary_lba + 32) * SECTOR])
    mutate(table)
    for array_lba, header_lba in ((primary_lba, 1), (backup_lba, SECTORS - 1)):
        image[array_lba * SECTOR:(array_lba + 32) * SECTOR] = table
        struct.pack_into("<I", image, header_lba * SECTOR + 88, zlib.crc32(table) & 0xffffffff)
        _rewrite_header(image, header_lba)


def _case(root: Path, name: str) -> tuple[Fixture, gpt.TopologyRoots]:
    case = root / name
    case.mkdir()
    return _fixture(case)


def test_retained_descriptors_and_fixture_binding(root: Path, probe: CResolverProbe) -> None:
    fixture, roots = _case(root, "retained")
    selected = gpt.resolve_partuuid(TARGET_UUID, roots)
    try:
        assert selected.devnum == (8, 17)
        assert selected.size_sectors == 8
        assert gpt.read_selected_exact(selected, 4096).startswith(TARGET_UUID.encode("ascii"))
        replacement = fixture.device_root / "replacement"
        replacement.write_bytes(b"X" * 4096)
        os.replace(replacement, fixture.device_root / "gptdiskp1")
        assert gpt.read_selected_exact(selected, 4096).startswith(TARGET_UUID.encode("ascii"))
    finally:
        gpt.close_selected(selected)

    fixture, roots = _case(root, "controller-replacement")
    replacement = fixture.device_root / "replacement"
    replacement.write_bytes(b"X" * 4096)
    original_resolver = controller.resolve_partuuid

    def resolve_then_replace(partuuid: str, supplied_roots=None):
        retained = gpt.resolve_partuuid(partuuid, supplied_roots)
        os.replace(replacement, fixture.device_root / "gptdiskp1")
        return retained

    controller.resolve_partuuid = resolve_then_replace
    try:
        assert controller._read_binding_device(TARGET_UUID, roots).startswith(TARGET_UUID.encode("ascii"))
    finally:
        controller.resolve_partuuid = original_resolver

    fixture, roots = _case(root, "binding-key")
    bindings = dict(roots.fixture_bindings or {})
    binding = bindings[(8, 16)]
    bindings[(8, 16)] = gpt.FixtureNodeBinding((8, 99), binding.st_dev, binding.st_ino)
    bad_roots = gpt.TopologyRoots(
        roots.class_block_root, roots.dev_block_root, roots.virtual_root, roots.device_root, bindings,
    )
    _expect_failure(lambda: gpt.resolve_partuuid(TARGET_UUID, bad_roots))

    fixture, _roots = _case(root, "native-substitution")
    (fixture.device_root / "replacement").write_bytes(b"X" * 4096)
    probe.run(fixture.root, TARGET_UUID, success=True, substitute=True)


def test_uuid_and_gpt_validation_matrix(root: Path, probe: CResolverProbe) -> None:
    fixture, roots = _case(root, "missing")
    _expect_both_failure(probe, fixture, roots, OTHER_UUID)

    fixture, roots = _case(root, "malformed-protective-mbr")
    image = bytearray((fixture.device_root / "gptdisk").read_bytes())
    image[446] = 1
    (fixture.device_root / "gptdisk").write_bytes(image)
    _expect_both_failure(probe, fixture, roots)

    for name, mutate in (
        ("primary-signature", lambda image: image.__setitem__(slice(SECTOR, SECTOR + 8), b"NOT GPT!")),
        ("backup-signature", lambda image: image.__setitem__(slice((SECTORS - 1) * SECTOR, (SECTORS - 1) * SECTOR + 8), b"NOT GPT!")),
        ("primary-header-crc", lambda image: image.__setitem__(SECTOR + 56, image[SECTOR + 56] ^ 1)),
        ("backup-header-crc", lambda image: image.__setitem__((SECTORS - 1) * SECTOR + 56, image[(SECTORS - 1) * SECTOR + 56] ^ 1)),
        ("primary-array-crc", lambda image: image.__setitem__(PRIMARY_ARRAY * SECTOR, image[PRIMARY_ARRAY * SECTOR] ^ 1)),
    ):
        fixture, roots = _case(root, name)
        image = bytearray((fixture.device_root / "gptdisk").read_bytes())
        mutate(image)
        (fixture.device_root / "gptdisk").write_bytes(image)
        _expect_both_failure(probe, fixture, roots)

    fixture, roots = _case(root, "array-contradiction")
    image = bytearray((fixture.device_root / "gptdisk").read_bytes())
    image[BACKUP_ARRAY * SECTOR] ^= 1
    struct.pack_into("<I", image, (SECTORS - 1) * SECTOR + 88,
                     zlib.crc32(image[BACKUP_ARRAY * SECTOR:(BACKUP_ARRAY + 32) * SECTOR]) & 0xffffffff)
    _rewrite_header(image, SECTORS - 1)
    (fixture.device_root / "gptdisk").write_bytes(image)
    _expect_both_failure(probe, fixture, roots)

    for name, array_lba in (("array-usable-overlap", FIRST_USABLE), ("array-overflow", (1 << 64) - 1)):
        fixture, roots = _case(root, name)
        image = bytearray((fixture.device_root / "gptdisk").read_bytes())
        struct.pack_into("<Q", image, SECTOR + 72, array_lba)
        _rewrite_header(image, 1)
        (fixture.device_root / "gptdisk").write_bytes(image)
        _expect_both_failure(probe, fixture, roots)

    fixture, roots = _case(root, "array-array-overlap")
    image = bytearray((fixture.device_root / "gptdisk").read_bytes())
    struct.pack_into("<Q", image, (SECTORS - 1) * SECTOR + 72, PRIMARY_ARRAY)
    _rewrite_header(image, SECTORS - 1)
    (fixture.device_root / "gptdisk").write_bytes(image)
    _expect_both_failure(probe, fixture, roots)

    fixture = Fixture(root / "noncanonical-arrays")
    image = make_gpt(primary_array=4, backup_array=200, first_usable=36, last_usable=199)
    fixture.add_disk("ordinary", 8, 8, b"\0" * (SECTORS * SECTOR))
    fixture.add_disk("gptdisk", 8, 16, image, entry=(TARGET_UUID, 40, 47))
    roots = fixture.roots()
    selected = gpt.resolve_partuuid(TARGET_UUID, roots)
    try:
        assert selected.size_sectors == 8
    finally:
        gpt.close_selected(selected)
    probe.run(fixture.root, TARGET_UUID, success=True)

    for name, mutate in (
        ("nonzero-empty-entry", lambda table: table.__setitem__(slice(0, 16), b"\0" * 16)),
        ("zero-entry-uuid", lambda table: table.__setitem__(slice(16, 32), b"\0" * 16)),
        ("entry-outside-usable", lambda table: struct.pack_into("<Q", table, 32, 2)),
    ):
        fixture, roots = _case(root, name)
        image = bytearray((fixture.device_root / "gptdisk").read_bytes())
        _mutate_entry_table(image, mutate)
        (fixture.device_root / "gptdisk").write_bytes(image)
        _expect_both_failure(probe, fixture, roots)

    fixture, roots = _case(root, "duplicate-within")
    (fixture.device_root / "gptdisk").write_bytes(make_gpt(((TARGET_UUID, 40, 47), (TARGET_UUID, 48, 55))))
    _expect_both_failure(probe, fixture, roots)

    fixture = Fixture(root / "duplicate-across")
    fixture.add_disk("ordinary", 8, 8, b"\0" * (SECTORS * SECTOR))
    fixture.add_disk("gptdisk", 8, 16, make_gpt(), entry=(TARGET_UUID, 40, 47))
    fixture.add_disk("duplicate", 8, 24, make_gpt(), entry=(TARGET_UUID, 40, 47))
    _expect_both_failure(probe, fixture, fixture.roots())

    fixture, roots = _case(root, "uuid-recrc-mutation")
    # make_gpt independently reconstructs both arrays and both header CRCs.
    (fixture.device_root / "gptdisk").write_bytes(make_gpt(((OTHER_UUID, 40, 47),)))
    _expect_both_failure(probe, fixture, roots)
    selected = gpt.resolve_partuuid(OTHER_UUID, roots)
    gpt.close_selected(selected)
    probe.run(fixture.root, OTHER_UUID, success=True)


def test_topology_read_and_resource_matrix(root: Path, probe: CResolverProbe) -> None:
    fixture = Fixture(root / "virtual-control")
    fixture.add_disk("virtual", 8, 32, make_gpt(), virtual=True, entry=(TARGET_UUID, 40, 47))
    _expect_both_failure(probe, fixture, fixture.roots())

    fixture, roots = _case(root, "class-devblock-alias")
    alias = fixture.root / "sys/devices/physical/alias"
    alias.mkdir()
    Fixture._attrs(alias, "gptdisk", "disk", 8, 16)
    (fixture.class_root / "gptdisk").unlink()
    Fixture._link(fixture.class_root / "gptdisk", alias)
    _expect_both_failure(probe, fixture, roots)

    fixture, roots = _case(root, "partn")
    part = fixture.root / "sys/devices/physical/gptdisk/gptdiskp1"
    (part / "uevent").write_text("MAJOR=8\nMINOR=17\nDEVNAME=gptdiskp1\nDEVTYPE=partition\nPARTN=2\n", encoding="ascii")
    _expect_both_failure(probe, fixture, roots)

    for name, attribute, value in (("start", "start", "41\n"), ("size", "size", "7\n"), ("dev", "dev", "8:99\n")):
        fixture, roots = _case(root, f"partition-{name}")
        part = fixture.root / "sys/devices/physical/gptdisk/gptdiskp1"
        (part / attribute).write_text(value, encoding="ascii")
        _expect_both_failure(probe, fixture, roots)

    fixture = Fixture(root / "partition-parent")
    fixture.add_disk("ordinary", 8, 8, b"\0" * (SECTORS * SECTOR))
    fixture.add_disk("gptdisk", 8, 16, make_gpt(), entry=(TARGET_UUID, 40, 47))
    rogue = fixture.root / "sys/devices/physical/rogue"
    rogue.mkdir()
    Fixture._attrs(rogue, "rogue", "disk", 8, 30)
    (fixture.device_root / "rogue").write_bytes(b"\0" * (SECTORS * SECTOR))
    rogue_part = rogue / "gptdiskp1"
    rogue_part.mkdir()
    Fixture._attrs(rogue_part, "gptdiskp1", "partition", 8, 17, partn=1, start=40, size=8)
    (fixture.class_root / "gptdiskp1").unlink()
    (fixture.devblock_root / "8:17").unlink()
    Fixture._link(fixture.class_root / "gptdiskp1", rogue_part)
    Fixture._link(fixture.devblock_root / "8:17", rogue_part)
    Fixture._link(fixture.devblock_root / "8:30", rogue)
    _expect_both_failure(probe, fixture, fixture.roots())

    for name, replace in (("truncated-gpt", lambda path: path.write_bytes(path.read_bytes()[:-1])),
                          ("unreadable-directory", lambda path: (path.unlink(), path.mkdir()))):
        fixture, roots = _case(root, name)
        replace(fixture.device_root / "gptdisk")
        _expect_both_failure(probe, fixture, roots)

    fixture, roots = _case(root, "invalid-sector-geometry")
    (fixture.device_root / "gptdisk").write_bytes(b"\0" * SECTOR)
    _expect_both_failure(probe, fixture, roots)

    fixture, roots = _case(root, "unsupported-entry-geometry")
    image = bytearray((fixture.device_root / "gptdisk").read_bytes())
    struct.pack_into("<I", image, SECTOR + 80, 129)
    _rewrite_header(image, 1)
    (fixture.device_root / "gptdisk").write_bytes(image)
    _expect_both_failure(probe, fixture, roots)

    fixture = Fixture(root / "candidate-cap")
    for minor in range(257):
        fixture.add_disk(f"disk{minor}", 9, minor, b"\0" * (2 * SECTOR))
    _expect_both_failure(probe, fixture, fixture.roots())

    fixture, roots = _case(root, "fd-cleanup")
    before = len(os.listdir("/proc/self/fd"))
    for _ in range(16):
        _expect_failure(lambda: gpt.resolve_partuuid(OTHER_UUID, roots))
    assert len(os.listdir("/proc/self/fd")) == before


def main() -> None:
    tests = (
        test_retained_descriptors_and_fixture_binding,
        test_uuid_and_gpt_validation_matrix,
        test_topology_read_and_resource_matrix,
    )
    with tempfile.TemporaryDirectory(dir="/var/tmp") as temporary:
        root = Path(temporary)
        probe_directory = root / "probe"
        probe_directory.mkdir()
        probe = CResolverProbe(probe_directory)
        for test in tests:
            case = root / test.__name__
            case.mkdir()
            test(case, probe)
            print(f"ok   {test.__name__}")
    print(f"SPP GPT resolver: ok ({len(tests)} tests)")


if __name__ == "__main__":
    main()
