#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Production-compiled layout binding, independent GPT and recipe checks."""
from pathlib import Path
import runpy
import struct
import subprocess
import sys
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "appliance"))
from spp_layout import entry_array, geometry, MIB, UKI_PAYLOAD_MAX
from spp_appliance import NFT_RULESET, UNIT_SGLANG, build_cmdline, build_disk_r1, build_initramfs_r1

fixtures = runpy.run_path(str(ROOT / "test/conf-proc-spp-diag-gpt-selftest.py"))


class ProductionLayout(unittest.TestCase):
    def test_production_resolver_requires_exact_selected_array(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            probe = fixtures["CResolverProbe"](root, production=True)
            fixture, _ = fixtures["_case"](root, "selected")
            target = fixtures["TARGET_UUID"]
            disk = fixture.device_root / "gptdisk"
            expected = fixture.root / "spp-gpt-array.bin"
            original = disk.read_bytes()[1024:1024+16384]
            for bad in (None, original[:-1], original + b"x", bytes(16384)):
                if bad is None:
                    expected.unlink(missing_ok=True)
                else:
                    expected.write_bytes(bad)
                probe.run(fixture.root, target, success=False)
            expected.write_bytes(original)
            probe.run(fixture.root, target, success=True)
            # An unrelated, fully valid GPT disk is allowed.
            fixture.add_disk("duplicate", 8, 24,
                             fixtures["make_gpt"](((fixtures["OTHER_UUID"], 40, 47),)),
                             entry=(fixtures["OTHER_UUID"], 40, 47))
            probe.run(fixture.root, target, success=True)
            # Both GPT copies and CRCs are valid; only the pinned layout differs.
            disk.write_bytes(fixtures["make_gpt"](((target, 40, 47), (fixtures["OTHER_UUID"], 50, 57))))
            probe.run(fixture.root, target, success=False)
            disk.write_bytes(fixtures["make_gpt"]())
            (fixture.device_root / "duplicate").write_bytes(fixtures["make_gpt"]())
            probe.run(fixture.root, target, success=False)

    def test_entries_match_independent_sgdisk_and_geometry(self):
        identities = {name: str(uuid.uuid5(uuid.NAMESPACE_URL, name)) for name in ("esp", "root", "verity", "binding")}
        expected = entry_array(MIB+1, MIB, identities)
        self.assertEqual(entry_array(MIB+2, MIB, identities), expected)
        self.assertNotEqual(entry_array(2*MIB+1, MIB, identities), expected)
        with tempfile.TemporaryDirectory() as temp:
            disk = Path(temp) / "test.raw"
            with disk.open("wb") as handle:
                handle.truncate(128*MIB)
            command = ["/usr/sbin/sgdisk", "--clear"]
            # Independent fixed fixture geometry: 64/2/1/1 MiB after first MiB.
            for i, (name, start, length, code) in enumerate([
                ("esp",1,64,"ef00"),("root",65,2,"8300"),
                ("verity",67,1,"8300"),("binding",68,1,"8300")], 1):
                command += [f"--new={i}:{start*2048}:{(start+length)*2048-1}",
                            f"--typecode={i}:{code}", f"--partition-guid={i}:{identities[name]}",
                            f"--change-name={i}:SPP-{name.upper()}"]
            subprocess.run([*command, str(disk)], check=True, capture_output=True, timeout=30)
            with disk.open("rb") as handle:
                handle.seek(1024)
                self.assertEqual(handle.read(16384), expected)
                handle.seek(128*MIB - 512 - 16384)
                self.assertEqual(handle.read(16384), expected)
            self.assertEqual(expected[4*128:], bytes(124*128))

    def test_oversized_uki_fails_before_disk_creation(self):
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp)
            uki, root, verity = (work / name for name in ("uki", "root", "verity"))
            with uki.open("wb") as handle:
                handle.truncate(UKI_PAYLOAD_MAX + 1)
            root.write_bytes(b"root")
            verity.write_bytes(b"verity")
            with self.assertRaisesRegex(ValueError, "payload budget"):
                build_disk_r1(work, uki, root, verity, b"", {}, "unused", mtools_root=work,
                              run_id="fixture", expected_gpt=bytes(16384))
            self.assertFalse((work / "diagnostic.raw").exists())

    def test_signed_flags_expected_initramfs_and_ceiling(self):
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp)
            for stage in ("prod", "prodtrace"):
                cmdline = build_cmdline(work, "a", "b", "c", "d", stage=stage).read_text()
                self.assertEqual(cmdline.split().count("systemd.gpt_auto=0"), 1)
                self.assertEqual(cmdline.split().count("systemd.swap=0"), 1)
            init = work / "init"
            init.write_bytes(b"native")
            for name in ("dm-bufio.ko", "dm-verity.ko"):
                (work / name).write_bytes(b"module")
            expected = work / "array"
            expected.write_bytes(bytes(16384))
            cpio = build_initramfs_r1(work, init, {"MODULE_DIR": work}, expected_gpt=expected)
            raw = cpio.read_bytes()
            offset = 0
            entries = {}
            while offset < len(raw):
                header = raw[offset:offset+110]
                size = int(header[54:62], 16)
                namesize = int(header[94:102], 16)
                name = raw[offset+110:offset+110+namesize-1].decode()
                body = (offset+110+namesize+3) & ~3
                entries[name] = raw[body:body+size]
                offset = (body+size+3) & ~3
            self.assertEqual(entries["spp-gpt-array.bin"], expected.read_bytes())
        self.assertIn('"min_pixels":65536,"max_pixels":3686400', UNIT_SGLANG)
        self.assertIn("--enable-cache-report", UNIT_SGLANG)

    def test_firewall_order(self):
        output = NFT_RULESET.split("chain output", 1)[1]
        self.assertLess(output.index('tcp dport { 9100, 9443 } drop'), output.index('oif "lo" accept'))
        self.assertLess(output.index('"sppcontent.slice" drop'), output.index('ct state established,related accept'))
        incoming = NFT_RULESET.split("chain input", 1)[1].split("chain output", 1)[0]
        self.assertIn("policy drop", incoming)
        self.assertIn("tcp dport 9443 accept", incoming)
        # IPv4 TCP carrying IP options never reaches the handshake (CVE-2026-98432).
        self.assertLess(incoming.index("ip protocol tcp ip hdrlength > 5 drop"),
                        incoming.index("tcp dport 9443 accept"))
        self.assertNotIn("tcp dport 8000 accept", incoming)


if __name__ == "__main__":
    unittest.main()
