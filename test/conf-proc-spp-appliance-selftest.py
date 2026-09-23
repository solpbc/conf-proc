#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Unit and contract tests for SPP appliance build recipe and components."""

from __future__ import annotations

import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
BUILD_DIR = REPO / "appliance"
if str(BUILD_DIR) not in sys.path:
    sys.path.insert(0, str(BUILD_DIR))

import spp_disk
from spp_appliance import (
    JOURNALD_DROPIN,
    NFT_RULESET,
    PARAKEET_SHA,
    SYSCTL_DROPIN,
    build_cmdline,
    install_prod_hardening,
    require_clean_repo,
    unit_asr,
    unit_sglang,
    verify_inputs,
    write_historical_report,
)
from populate_manifest import populate
from spp_appliance import COLLECTOR_SH, build_initramfs_r1, copy_tracked_source, generate_signer, required_inputs, unit_gateway
from spp_image_sbom import generate_image_sbom
from spp_image_sbom_check import check_image_sbom


class ApplianceCmdlineTest(unittest.TestCase):
    def test_cmdline_stage_differences(self) -> None:
        with tempfile.TemporaryDirectory(dir="/var/tmp") as tmpdir:
            work = Path(tmpdir)
            p_root = "00000000-0000-0000-0000-000000000001"
            p_verity = "00000000-0000-0000-0000-000000000002"
            p_binding = "00000000-0000-0000-0000-000000000003"
            rhash = "a" * 64

            f_2h = build_cmdline(work, p_root, p_verity, p_binding, rhash, stage="2h")
            text_2h = f_2h.read_text()
            self.assertIn("console=ttyS0", text_2h)

            f_1b = build_cmdline(work, p_root, p_verity, p_binding, rhash, stage="1b")
            text_1b = f_1b.read_text()
            self.assertEqual(text_1b, text_2h)

            f_prod = build_cmdline(work, p_root, p_verity, p_binding, rhash, stage="prod")
            text_prod = f_prod.read_text()
            self.assertNotIn("console=", text_prod)
            self.assertIn("ip=off spp_diag.root_data=", text_prod)


def fake_nft_pkg(root: Path) -> Path:
    (root / "etc").mkdir(exist_ok=True)
    pkg = root / "nft-pkg"
    (pkg / "usr/sbin").mkdir(parents=True)
    (pkg / "usr/sbin/nft").write_text("#!/bin/sh\n")
    lib = pkg / "usr/lib/x86_64-linux-gnu"
    lib.mkdir(parents=True)
    (lib / "libnftables.so.1.1.0").write_bytes(b"\x7fELF")
    (lib / "libnftables.so.1").symlink_to("libnftables.so.1.1.0")
    return pkg


class ApplianceHardeningTest(unittest.TestCase):
    def test_historical_report_writes(self) -> None:
        with tempfile.TemporaryDirectory(dir="/var/tmp") as tmpdir:
            tree = Path(tmpdir)
            write_historical_report(tree)
            self.assertTrue((tree / "etc/systemd/system/spp-r1-report.service").exists())
            report_sh = tree / "opt/spp/r1-report.sh"
            self.assertTrue(report_sh.exists())
            self.assertTrue(os.access(report_sh, os.X_OK))
            wants_link = tree / "etc/systemd/system/multi-user.target.wants/spp-r1-report.service"
            self.assertTrue(wants_link.is_symlink())

    def test_prod_hardening_writes_and_checks(self) -> None:
        with tempfile.TemporaryDirectory(dir="/var/tmp") as tmpdir:
            tree = Path(tmpdir)
            (tree / "var/log/journal").mkdir(parents=True)
            (tree / "usr/lib/x86_64-linux-gnu").mkdir(parents=True)
            (tree / "etc").mkdir()

            with tempfile.TemporaryDirectory(dir="/var/tmp") as pkgdir:
                install_prod_hardening(tree, fake_nft_pkg(Path(pkgdir)))

            self.assertTrue((tree / "usr/sbin/nft").exists())
            self.assertTrue((tree / "usr/lib/x86_64-linux-gnu/libnftables.so.1").is_symlink())

            self.assertFalse((tree / "etc/systemd/system/spp-r1-report.service").exists())
            self.assertFalse((tree / "opt/spp/r1-report.sh").exists())
            self.assertFalse((tree / "etc/spp/entitlement-authorizer").exists())
            self.assertFalse((tree / "var/log/journal").exists())

            egress_unit = tree / "etc/systemd/system/spp-egress.service"
            self.assertTrue(egress_unit.exists())
            egress_text = egress_unit.read_text()
            self.assertIn("Before=network-pre.target spp-gateway.service spp-asr.service sglang.service", egress_text)
            self.assertIn("Requires=sppcontent.slice sppgateway.slice", egress_text)
            for name in ("sppcontent.slice", "sppgateway.slice"):
                self.assertTrue((tree / "etc/systemd/system" / name).exists())

            wants_link = tree / "etc/systemd/system/multi-user.target.wants/spp-egress.service"
            self.assertTrue(wants_link.is_symlink())

            journald = tree / "etc/systemd/journald.conf.d/spp.conf"
            self.assertTrue(journald.exists())
            jtext = journald.read_text()
            self.assertIn("Storage=volatile", jtext)
            self.assertIn("ForwardToConsole=no", jtext)
            self.assertIn("ForwardToSyslog=no", jtext)
            self.assertIn("RuntimeMaxUse=16M", jtext)

            sysctl = tree / "etc/sysctl.d/spp.conf"
            self.assertTrue(sysctl.exists())
            self.assertEqual(sysctl.read_text(), "kernel.core_pattern=|/bin/false\n")

            # Ruleset checks
            ruleset = tree / "etc/nftables.d/spp-egress.nft"
            self.assertTrue(ruleset.exists())
            rtext = ruleset.read_text()
            # nft resolves a hostname when the rules load, before the network is up, and the
            # whole ruleset then fails to load: no hostnames, ever.
            self.assertNotIn("solstone.app", rtext)
            self.assertNotIn("amd.com", rtext)
            self.assertIn('oif "lo" accept', rtext)
            self.assertIn('socket cgroupv2 level 1 "sppcontent.slice" drop', rtext)
            self.assertIn('socket cgroupv2 level 1 "sppgateway.slice" tcp dport 443 accept', rtext)
            self.assertIn("ip daddr 168.63.129.16 udp dport 53 accept", rtext)
            self.assertIn("policy drop", rtext)

    def test_prod_hardening_rejects_forbidden_files(self) -> None:
        with tempfile.TemporaryDirectory(dir="/var/tmp") as tmpdir:
            tree = Path(tmpdir)
            cdump = tree / "usr/bin/systemd-coredump"
            cdump.parent.mkdir(parents=True)
            cdump.touch()
            with self.assertRaises(SystemExit):
                install_prod_hardening(tree, fake_nft_pkg(tree))

        with tempfile.TemporaryDirectory(dir="/var/tmp") as tmpdir:
            tree = Path(tmpdir)
            fstab = tree / "etc/fstab"
            fstab.parent.mkdir(parents=True)
            fstab.write_text("/dev/sda2 none swap sw 0 0\n")
            with self.assertRaises(SystemExit):
                install_prod_hardening(tree, fake_nft_pkg(tree))


class ApplianceUnitsTest(unittest.TestCase):
    def test_unit_user_site_flags(self) -> None:
        prod_sglang = unit_sglang("prod")
        prod_asr = unit_asr("prod")
        self.assertIn("Environment=PYTHONNOUSERSITE=1\n", prod_sglang)
        self.assertIn("Environment=PYTHONNOUSERSITE=1\n", prod_asr)

        for stg in ("1b", "2h"):
            self.assertNotIn("PYTHONNOUSERSITE", unit_sglang(stg))
            self.assertNotIn("PYTHONNOUSERSITE", unit_asr(stg))

        self.assertEqual(unit_sglang("1b"), unit_sglang("2h"))
        self.assertEqual(unit_asr("1b"), unit_asr("2h"))

    def test_python_no_user_site_behavior(self) -> None:
        with tempfile.TemporaryDirectory(dir="/var/tmp") as tmpdir:
            fake_home = Path(tmpdir)
            user_site = fake_home / ".local/lib/python3/site-packages"
            user_site.mkdir(parents=True)
            (user_site / "test_hook.pth").write_text("/tmp/should-not-be-in-path\n")

            env = dict(os.environ)
            env["HOME"] = str(fake_home)
            env["PYTHONNOUSERSITE"] = "1"

            cmd = [
                sys.executable,
                "-c",
                "import sys; print('/tmp/should-not-be-in-path' in sys.path)",
            ]
            res = subprocess.run(cmd, env=env, capture_output=True, text=True, check=True)
            self.assertEqual(res.stdout.strip(), "False")


class ApplianceManifestTest(unittest.TestCase):
    def test_template_manifest_structure(self) -> None:
        repo_manifest = Path(__file__).resolve().parents[1] / "appliance/input-manifest.json"
        self.assertTrue(repo_manifest.exists())
        data = json.loads(repo_manifest.read_text())
        self.assertEqual(data.get("status"), "unpopulated")
        inputs = data.get("inputs", {})
        for name, entry in inputs.items():
            if name == "PARAKEET":
                self.assertEqual(entry["sha256"], PARAKEET_SHA)
            else:
                self.assertIsNone(entry["sha256"])

    def test_verify_inputs_success_and_failures(self) -> None:
        with tempfile.TemporaryDirectory(dir="/var/tmp") as tmpdir:
            ws = Path(tmpdir)
            # Create valid fixture files for stage 1a
            kb = ws / "kernel/vmlinuz"
            kb.parent.mkdir(parents=True)
            kb.write_bytes(b"vmlinuz-content")
            kb_sha = spp_disk.sha256_file(kb)

            stub = ws / "stub/linuxx64.efi.stub"
            stub.parent.mkdir(parents=True)
            stub.write_bytes(b"stub-content")
            stub_sha = spp_disk.sha256_file(stub)

            ukify = ws / "tools/ukify.py"
            ukify.parent.mkdir(parents=True)
            ukify.write_bytes(b"ukify-content")
            ukify_sha = spp_disk.sha256_file(ukify)

            pefile = ws / "pkg/python3-pefile.deb"
            pefile.parent.mkdir(parents=True)
            pefile.write_bytes(b"pefile-content")
            pefile_sha = spp_disk.sha256_file(pefile)

            mod_dir = ws / "modules"
            mod_dir.mkdir(parents=True)
            (mod_dir / "dm-verity.ko").write_bytes(b"dm-verity")
            mod_files = [
                {
                    "path": "dm-verity.ko",
                    "sha256": spp_disk.sha256_bytes(b"dm-verity"),
                    "size_bytes": len(b"dm-verity"),
                }
            ]
            mod_sha = spp_disk.sha256_bytes(
                json.dumps(mod_files, sort_keys=True, separators=(",", ":")).encode()
            )

            mtools = ws / "mtools"
            mtools.mkdir(parents=True)
            (mtools / "mcopy").write_bytes(b"mcopy")
            mtools_files = [
                {
                    "path": "mcopy",
                    "sha256": spp_disk.sha256_bytes(b"mcopy"),
                    "size_bytes": len(b"mcopy"),
                }
            ]
            mtools_sha = spp_disk.sha256_bytes(
                json.dumps(mtools_files, sort_keys=True, separators=(",", ":")).encode()
            )

            manifest = {
                "inputs": {
                    "KERNEL_BZIMAGE": {
                        "path": "kernel/vmlinuz",
                        "sha256": kb_sha,
                        "size_bytes": len(b"vmlinuz-content"),
                    },
                    "MODULE_DIR": {
                        "path": "modules",
                        "sha256": mod_sha,
                        "size_bytes": len(b"dm-verity"),
                        "files": mod_files,
                    },
                    "STUB": {
                        "path": "stub/linuxx64.efi.stub",
                        "sha256": stub_sha,
                        "size_bytes": len(b"stub-content"),
                    },
                    "UKIFY": {
                        "path": "tools/ukify.py",
                        "sha256": ukify_sha,
                        "size_bytes": len(b"ukify-content"),
                    },
                    "PEFILE_DEB": {
                        "path": "pkg/python3-pefile.deb",
                        "sha256": pefile_sha,
                        "size_bytes": len(b"pefile-content"),
                    },
                    "MTOOLS_ROOT": {
                        "path": "mtools",
                        "sha256": mtools_sha,
                        "size_bytes": len(b"mcopy"),
                        "files": mtools_files,
                    },
                }
            }

            paths = verify_inputs(manifest, "1a", ws)
            self.assertEqual(len(paths), 6)

            # Test corrupted directory file sha256 asserting bad file path in error
            bad_manifest_dir = json.loads(json.dumps(manifest))
            bad_manifest_dir["inputs"]["MODULE_DIR"]["files"][0]["sha256"] = "0" * 64
            with self.assertRaises(SystemExit) as ctx:
                verify_inputs(bad_manifest_dir, "1a", ws)
            self.assertIn("dm-verity.ko", str(ctx.exception))

            # Test corrupted file sha256
            bad_manifest = json.loads(json.dumps(manifest))
            bad_manifest["inputs"]["KERNEL_BZIMAGE"]["sha256"] = "0" * 64
            with self.assertRaises(SystemExit):
                verify_inputs(bad_manifest, "1a", ws)

            # Test null sha256
            bad_manifest2 = json.loads(json.dumps(manifest))
            bad_manifest2["inputs"]["KERNEL_BZIMAGE"]["sha256"] = None
            with self.assertRaises(SystemExit):
                verify_inputs(bad_manifest2, "1a", ws)

            # Test unpopulated directory files=null
            bad_manifest3 = json.loads(json.dumps(manifest))
            bad_manifest3["inputs"]["MODULE_DIR"]["files"] = None
            with self.assertRaises(SystemExit):
                verify_inputs(bad_manifest3, "1a", ws)

            # Test unlisted file on disk in directory
            extra_file = mod_dir / "extra.ko"
            extra_file.write_bytes(b"extra")
            with self.assertRaises(SystemExit) as ctx:
                verify_inputs(manifest, "1a", ws)
            self.assertIn("extra.ko", str(ctx.exception))
            extra_file.unlink()


class ApplianceProdUnitsTest(unittest.TestCase):
    def test_prod_services_fail_closed_on_firewall_and_live_in_their_slices(self) -> None:
        for text in (unit_sglang("prod"), unit_asr("prod")):
            self.assertIn("Requires=spp-egress.service spp-gpu-bringup.service", text)
            self.assertIn("Slice=sppcontent.slice", text)
            self.assertIn("PYTHONNOUSERSITE=1", text)
        gw = unit_gateway("prod")
        self.assertIn("Requires=spp-egress.service", gw)
        self.assertIn("Slice=sppgateway.slice", gw)
        self.assertNotIn("secret", gw.lower())  # the gateway is handed no credential of any kind
        self.assertNotIn("Slice=", unit_sglang("2h"))
        for text in (unit_sglang("prod"), unit_asr("prod"), gw):
            self.assertIn("Restart=on-failure", text)
        self.assertIn("Restart=no", unit_gateway("2h"))

    def test_prod_collector_is_the_sealed_one(self) -> None:
        gw = unit_gateway("prod")
        self.assertIn("--collector-command /opt/spp/run-collector.sh", gw)
        self.assertIn("--collector-command /opt/conf-proc/run-collector.sh", unit_gateway("2h"))
        self.assertIn("COLLECTOR_SITE", required_inputs("prod"))
        self.assertNotIn("sudo", COLLECTOR_SH)  # the gateway is root; the image carries no sudo
        self.assertIn("cd /run/gw/collector", COLLECTOR_SH)  # the vendor verifier logs to its cwd
        self.assertIn("SPP_VCEK_CACHE_DIR=/run/gw/", COLLECTOR_SH)  # /var/tmp is read-only
        # The quote carries the fourteen registers the owner appraises, 11-14 included.
        self.assertIn("SPP_PCR_LIST=sha256:0,2,4,7,8,9,11,12,13,14,15,16,22,23", COLLECTOR_SH)

    def test_signer_directory_is_required(self) -> None:
        with tempfile.TemporaryDirectory(dir="/var/tmp") as tmpdir:
            with self.assertRaises(SystemExit):
                generate_signer(Path(tmpdir))


class ApplianceManifestRoundTripTest(unittest.TestCase):
    def test_populate_then_verify_and_a_retargeted_symlink_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(dir="/var/tmp") as tmpdir:
            ws = Path(tmpdir)
            files = {"KERNEL_BZIMAGE": "k/vmlinuz", "STUB": "s/stub", "UKIFY": "t/ukify.py", "PEFILE_DEB": "p/pefile.deb"}
            for rel in files.values():
                (ws / rel).parent.mkdir(parents=True, exist_ok=True)
                (ws / rel).write_bytes(rel.encode())
            (ws / "m").mkdir()
            (ws / "m/dm-verity.ko").write_bytes(b"verity")
            (ws / "m/dm-bufio.ko").write_bytes(b"bufio")
            (ws / "m/current.ko").symlink_to("dm-verity.ko")
            (ws / "mt").mkdir()
            (ws / "mt/mformat").write_bytes(b"mformat")
            manifest = {"inputs": {k: {"path": v} for k, v in files.items()}}
            manifest["inputs"]["MODULE_DIR"] = {"path": "m"}
            manifest["inputs"]["MTOOLS_ROOT"] = {"path": "mt"}
            populate(manifest, ws)
            self.assertEqual(verify_inputs(manifest, "1a", ws)["MODULE_DIR"], ws / "m")
            (ws / "m/current.ko").unlink()
            (ws / "m/current.ko").symlink_to("dm-bufio.ko")
            with self.assertRaises(SystemExit):
                verify_inputs(manifest, "1a", ws)

    def test_compact_manifest_verifies_by_tree_digest(self) -> None:
        with tempfile.TemporaryDirectory(dir="/var/tmp") as tmpdir:
            ws = Path(tmpdir)
            for rel in ("k/vmlinuz", "s/stub", "t/ukify.py", "p/pefile.deb", "mt/mformat"):
                (ws / rel).parent.mkdir(parents=True, exist_ok=True)
                (ws / rel).write_bytes(rel.encode())
            (ws / "m").mkdir()
            (ws / "m/dm-verity.ko").write_bytes(b"verity")
            manifest = {"inputs": {"KERNEL_BZIMAGE": {"path": "k/vmlinuz"}, "STUB": {"path": "s/stub"},
                                   "UKIFY": {"path": "t/ukify.py"}, "PEFILE_DEB": {"path": "p/pefile.deb"},
                                   "MODULE_DIR": {"path": "m"}, "MTOOLS_ROOT": {"path": "mt"}}}
            populate(manifest, ws)
            for entry in manifest["inputs"].values():
                entry.pop("files", None)
            verify_inputs(manifest, "1a", ws)
            (ws / "m/extra.ko").write_bytes(b"planted")
            with self.assertRaises(SystemExit):
                verify_inputs(manifest, "1a", ws)


class ApplianceInitramfsTest(unittest.TestCase):
    def test_initramfs_carries_every_path_the_init_opens(self) -> None:
        import re

        source = (REPO / "spp-diag-runtime-src/spp_diag_handoff.c").read_text()
        wanted = set(re.findall(r'spp_r1_load_module\("/([^"]+)"\)', source))
        wanted |= {m.lstrip("/") for m in re.findall(r'"(/(?:proc|sys|dev))"', source)}
        wanted.add(re.search(r'SPP_DIAG_ROOT_MOUNTPOINT "/([^"]+)"', source).group(1))
        self.assertIn("modules/dm-verity.ko", wanted)
        with tempfile.TemporaryDirectory(dir="/var/tmp") as tmpdir:
            work = Path(tmpdir)
            (work / "md").mkdir()
            for mod in ("dm-bufio.ko", "dm-verity.ko"):
                (work / "md" / mod).write_bytes(b"ko")
            init = work / "init"
            init.write_bytes(b"\x7fELF")
            cpio = build_initramfs_r1(work, init, {"MODULE_DIR": work / "md"})
            listing = subprocess.run(["cpio", "-it"], stdin=cpio.open("rb"), capture_output=True,
                                     check=True).stdout.decode().split()
        self.assertTrue(wanted <= set(listing), sorted(wanted - set(listing)))
        self.assertIn("spp-diag-handoff", listing)


class ApplianceGitTest(unittest.TestCase):
    def test_clean_repo_check(self) -> None:
        with tempfile.TemporaryDirectory(dir="/var/tmp") as tmpdir:
            repo = Path(tmpdir)
            subprocess.run(["git", "init", str(repo)], check=True, capture_output=True)
            subprocess.run(
                ["git", "-C", str(repo), "config", "user.email", "test@solstone.app"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(repo), "config", "user.name", "Test User"],
                check=True,
            )
            (repo / "file.txt").write_text("hello")
            subprocess.run(["git", "-C", str(repo), "add", "file.txt"], check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-m", "init"], check=True)

            head = require_clean_repo(repo)
            self.assertEqual(len(head), 40)

            # Untracked file makes porcelain dirty
            (repo / "untracked.txt").write_text("untracked")
            with self.assertRaises(SystemExit):
                require_clean_repo(repo)

    def test_image_source_is_what_head_tracks(self) -> None:
        with tempfile.TemporaryDirectory(dir="/var/tmp") as tmpdir:
            repo, dest = Path(tmpdir) / "repo", Path(tmpdir) / "dest"
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            (repo / ".gitignore").write_text("build/\n")
            (repo / "tool.sh").write_text("#!/bin/sh\n")
            (repo / "tool.sh").chmod(0o700)
            (repo / "lib.py").write_text("x = 1\n")
            (repo / "test").mkdir()
            (repo / "test/case.py").write_text("")
            subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
            subprocess.run(["git", "-C", str(repo), "-c", "user.email=t@solstone.app", "-c",
                            "user.name=T", "commit", "-qm", "init"], check=True)
            (repo / "build").mkdir()  # what `make ci` leaves behind: ignored, so porcelain stays clean
            (repo / "build/out.o").write_text("")
            require_clean_repo(repo)
            copy_tracked_source(repo, dest)
            self.assertEqual(sorted(p.relative_to(dest).as_posix() for p in dest.rglob("*") if p.is_file()),
                             [".gitignore", "lib.py", "tool.sh"])
            self.assertEqual((dest / "tool.sh").stat().st_mode & 0o777, 0o755)
            self.assertEqual((dest / "lib.py").stat().st_mode & 0o777, 0o644)


class ApplianceDiskFormulasTest(unittest.TestCase):
    def test_pure_formulas_for_2h_run_id(self) -> None:
        run_id = "spp-r1-260906-2h"
        expected_salt = "5582da6726460e26b67d1ec0858f9c88a4e13359e8ffcbe20da7c0150c160409"
        expected_uuid = "a491798c-8006-52e7-be21-a5e4f135d342"

        self.assertEqual(spp_disk.verity_salt(run_id), expected_salt)
        self.assertEqual(spp_disk.verity_uuid(run_id), expected_uuid)

        footer = spp_disk.vhd_footer(4096, run_id=run_id)
        self.assertEqual(len(footer), 512)
        timestamp = struct.unpack_from(">I", footer, 24)[0]
        self.assertEqual(timestamp, 841968000)

        fixed_uuid = spp_disk.fixed_vhd_uuid(run_id)
        self.assertEqual(fixed_uuid.bytes.hex(), "d70c8847067b525aaab8615987639fe6")
        self.assertIn(fixed_uuid.bytes, footer)


class ApplianceSBOMTest(unittest.TestCase):
    def test_sbom_generation_and_check(self) -> None:
        # Assert checker does not import or contain spp_image_sbom
        checker_path = (
            Path(__file__).resolve().parents[1] / "appliance/spp_image_sbom_check.py"
        )
        self.assertNotIn("spp_image_sbom", checker_path.read_text())

        with tempfile.TemporaryDirectory(dir="/var/tmp") as tmpdir:
            tree = Path(tmpdir) / "rootfs"
            tree.mkdir()

            bin_file = tree / "usr/bin/tool"
            bin_file.parent.mkdir(parents=True)
            bin_file.write_bytes(b"binary-tool")
            bin_file.chmod(0o755)

            py_file = tree / "opt/app/script.py"
            py_file.parent.mkdir(parents=True)
            py_file.write_bytes(b"print('hello')\n")

            origins = [
                {
                    "kind": "recipe",
                    "name": "custom-tools",
                    "version": "1.0",
                    "sha256": "",
                    "files": ["usr/bin/tool", "opt/app/script.py"],
                }
            ]

            boot = {
                "stub": bin_file,
                "kernel_bzimage": bin_file,
                "initrd": bin_file,
                "kernel_release": "6.8.0-test",
                "ukify": py_file,
            }

            doc = generate_image_sbom(tree, origins, boot, build_epoch=1788652800)
            self.assertEqual(doc["creationInfo"]["created"], "2026-09-06T00:00:00Z")

            # Check passes on unmodified tree
            check_image_sbom(tree, doc)

            # Flip byte in py_file -> digest diff fail
            py_file.write_bytes(b"print('modified')\n")
            with self.assertRaises(SystemExit) as ctx:
                check_image_sbom(tree, doc)
            self.assertIn("opt/app/script.py", str(ctx.exception))

            # Restore py_file
            py_file.write_bytes(b"print('hello')\n")
            check_image_sbom(tree, doc)

            # Add unlisted 0o755 file -> coverage diff fail
            unlisted = tree / "usr/bin/extra"
            unlisted.write_bytes(b"extra")
            unlisted.chmod(0o755)
            with self.assertRaises(SystemExit) as ctx:
                check_image_sbom(tree, doc)
            self.assertIn("usr/bin/extra", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
