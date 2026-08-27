#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Selftests for AC10 prohibited-class rejection: one fixture per
prohibited class, each naming the specific path/unit/content marker that
must turn the suite red."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import conf_proc_prohibited as prohibited  # noqa: E402
from conf_proc_reasons import ApplianceError  # noqa: E402


class ProhibitedPathTests(unittest.TestCase):
    def test_accepts_ordinary_path(self) -> None:
        prohibited.check_prohibited_path("/usr/bin/spp-systemd-stub")

    def test_reject_shim_bootloader(self) -> None:
        with self.assertRaises(ApplianceError) as ctx:
            prohibited.check_prohibited_path("/boot/efi/EFI/BOOT/shimx64.efi")
        self.assertEqual(ctx.exception.reason_code, "CP_TREE_UNEXPECTED")

    def test_reject_mok_manager(self) -> None:
        with self.assertRaises(ApplianceError):
            prohibited.check_prohibited_path("/boot/efi/EFI/BOOT/MokManager.efi")

    def test_reject_sshd_binary(self) -> None:
        with self.assertRaises(ApplianceError):
            prohibited.check_prohibited_path("/usr/sbin/sshd")

    def test_reject_ssh_host_key_path(self) -> None:
        with self.assertRaises(ApplianceError):
            prohibited.check_prohibited_path("/etc/ssh/ssh_host_rsa_key")

    def test_reject_azure_agent(self) -> None:
        with self.assertRaises(ApplianceError):
            prohibited.check_prohibited_path("/usr/sbin/waagent")

    def test_reject_cloud_init(self) -> None:
        with self.assertRaises(ApplianceError):
            prohibited.check_prohibited_path("/usr/bin/cloud-init")

    def test_reject_container_management_socket(self) -> None:
        with self.assertRaises(ApplianceError):
            prohibited.check_prohibited_path("/var/run/docker.sock")

    def test_reject_kdump_tool(self) -> None:
        with self.assertRaises(ApplianceError):
            prohibited.check_prohibited_path("/usr/sbin/kdump")

    def test_reject_persistent_journal(self) -> None:
        with self.assertRaises(ApplianceError):
            prohibited.check_prohibited_path("/var/log/journal/some-machine-id/system.journal")

    def test_reject_swapfile(self) -> None:
        with self.assertRaises(ApplianceError):
            prohibited.check_prohibited_path("/swapfile")

    def test_reject_runtime_fetch_tool(self) -> None:
        for path in ("/usr/bin/curl", "/usr/bin/wget", "/usr/bin/apt-get"):
            with self.assertRaises(ApplianceError):
                prohibited.check_prohibited_path(path)


class ProhibitedUnitTests(unittest.TestCase):
    def test_accepts_ordinary_unit(self) -> None:
        prohibited.check_prohibited_unit("conf-proc-final.service")

    def test_reject_getty(self) -> None:
        with self.assertRaises(ApplianceError) as ctx:
            prohibited.check_prohibited_unit("getty@.service")
        self.assertEqual(ctx.exception.reason_code, "CP_TREE_UNEXPECTED")

    def test_reject_rescue_and_emergency(self) -> None:
        with self.assertRaises(ApplianceError):
            prohibited.check_prohibited_unit("rescue.service")
        with self.assertRaises(ApplianceError):
            prohibited.check_prohibited_unit("emergency.service")

    def test_reject_docker_units(self) -> None:
        with self.assertRaises(ApplianceError):
            prohibited.check_prohibited_unit("docker.service")
        with self.assertRaises(ApplianceError):
            prohibited.check_prohibited_unit("docker.socket")

    def test_reject_cloud_init_units(self) -> None:
        with self.assertRaises(ApplianceError):
            prohibited.check_prohibited_unit("cloud-init.service")

    def test_reject_coredump_socket(self) -> None:
        with self.assertRaises(ApplianceError):
            prohibited.check_prohibited_unit("systemd-coredump.socket")

    def test_reject_sshd_unit(self) -> None:
        with self.assertRaises(ApplianceError):
            prohibited.check_prohibited_unit("sshd.service")


class ContentMarkerTests(unittest.TestCase):
    def test_accepts_ordinary_content(self) -> None:
        prohibited.check_content_markers("/etc/spp.conf", b"fixture configuration\n")

    def test_reject_embedded_private_key(self) -> None:
        with self.assertRaises(ApplianceError) as ctx:
            prohibited.check_content_markers("/opt/leak.txt", b"-----BEGIN PRIVATE KEY-----\nMII\n-----END PRIVATE KEY-----\n")
        self.assertEqual(ctx.exception.reason_code, "CP_TREE_UNEXPECTED")

    def test_reject_embedded_ssh_public_key(self) -> None:
        with self.assertRaises(ApplianceError):
            prohibited.check_content_markers("/opt/leak.txt", b"ssh-rsa AAAAB3NzaC1yc2EA fixture@host\n")


class FutureCmdlineTests(unittest.TestCase):
    def test_accepts_ordinary_cmdline(self) -> None:
        prohibited.check_future_cmdline("console=ttyS0")

    def test_reject_hibernation_resume_param(self) -> None:
        with self.assertRaises(ApplianceError) as ctx:
            prohibited.check_future_cmdline("console=ttyS0 resume=/dev/sda2")
        self.assertEqual(ctx.exception.reason_code, "CP_LOCK_SCHEMA")


if __name__ == "__main__":
    unittest.main(verbosity=2)
