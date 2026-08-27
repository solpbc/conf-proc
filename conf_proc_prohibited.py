#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Prohibited-class detection for AC10.

Pure predicates over already-obtained paths/bytes -- not tree-walking --
so both builder and inspector share them (analogous to
conf_proc_tree_rules.py). A large part of AC10 is already closed by
construction elsewhere in this subsystem and is not re-checked here:

- Every declared mount must be read-only squashfs (conf_proc_policy.py's
  MountPolicy schema has no writable or non-squashfs representation at
  all), which structurally rules out persistent owner-content sinks,
  writable executable state, executable tmpfs, and swap-as-a-mount.
- Every process node's network_scope must be exactly "none" or
  "loopback" (conf_proc_policy.py), which structurally rules out
  undeclared egress and arbitrary IP/DNS endpoints.

What remains, and what this module checks, is content and naming that
the schema alone cannot rule out: prohibited binaries/paths, prohibited
service units, hibernation kernel parameters, and credential/key/SSH/
machine-identity markers physically present in locked input bytes.
"""

from __future__ import annotations

import re
from typing import Final

from conf_proc_reasons import CP_LOCK_SCHEMA, CP_TREE_UNEXPECTED, ApplianceError


_PROHIBITED_PATH_SUBSTRINGS: Final = (
    "/shimx64.efi", "/shimia32.efi", "/shimaa64.efi", "/mmx64.efi", "/mokmanager",
    "/usr/sbin/sshd", "/etc/ssh/sshd_config", "/etc/ssh/ssh_host_",
    "/usr/sbin/waagent", "/var/lib/waagent", "walinuxagent",
    "/usr/bin/cloud-init", "/etc/cloud/cloud.cfg",
    "/var/run/docker.sock", "/run/docker.sock", "/usr/bin/dockerd", "/usr/bin/containerd",
    "/usr/sbin/kdump", "/usr/sbin/kexec", "kdump-tools", "kexec-tools",
    "/var/log/journal/",
    "/swapfile", "swap.img",
    "/usr/bin/apt", "/usr/bin/apt-get", "/usr/bin/yum", "/usr/bin/dnf",
    "/usr/bin/curl", "/usr/bin/wget",
)

_PROHIBITED_UNIT_BASENAMES: Final = (
    "getty@.service", "serial-getty@.service", "console-getty.service",
    "rescue.service", "rescue.target", "emergency.service", "emergency.target",
    "debug-shell.service",
    "docker.service", "docker.socket", "containerd.service",
    "cloud-init.service", "cloud-init-local.service", "cloud-config.service", "cloud-final.service",
    "systemd-coredump.socket", "systemd-coredump@.service",
    "kdump.service", "kdump-tools.service",
    "sshd.service", "ssh.service", "ssh.socket",
)

_CONTENT_MARKERS: Final = (
    b"-----BEGIN ", b"ssh-rsa ", b"ssh-ed25519 ", b"ssh-dss ", b"ssh-ecdsa ",
)

_HIBERNATION_CMDLINE_RE: Final = re.compile(r"\bresume=")


def check_prohibited_path(path: str) -> None:
    """Reject a placement path matching a known prohibited class."""

    lowered = path.lower()
    for marker in _PROHIBITED_PATH_SUBSTRINGS:
        if marker in lowered:
            raise ApplianceError(CP_TREE_UNEXPECTED, f"{path}: matches a prohibited class marker {marker!r}")


def check_prohibited_unit(basename: str) -> None:
    """Reject a unit basename that is interactive/recovery/management/container/cloud-init/coredump/kdump/SSH."""

    if basename in _PROHIBITED_UNIT_BASENAMES:
        raise ApplianceError(CP_TREE_UNEXPECTED, f"{basename}: prohibited unit class")


def check_content_markers(path: str, data: bytes) -> None:
    """Reject file bytes containing a credential/key/SSH-material marker."""

    for marker in _CONTENT_MARKERS:
        if marker in data:
            raise ApplianceError(CP_TREE_UNEXPECTED, f"{path}: content contains a credential/key/SSH-material marker {marker!r}")


def check_future_cmdline(future_cmdline: str) -> None:
    """Reject a hibernation-enabling kernel command line."""

    if _HIBERNATION_CMDLINE_RE.search(future_cmdline):
        raise ApplianceError(CP_LOCK_SCHEMA, "future_cmdline declares resume= (hibernation is prohibited)")
