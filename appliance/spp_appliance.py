#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Public SPP sealed appliance build recipe."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
from typing import Final

BUILD_DIR: Final = Path(__file__).resolve().parent
REPO: Final = BUILD_DIR.parent
if str(BUILD_DIR) not in sys.path:
    sys.path.insert(0, str(BUILD_DIR))

import spp_disk
from spp_image_sbom import generate_image_sbom
from spp_image_sbom_check import check_image_sbom

BUILD_EPOCH: Final = spp_disk.BUILD_EPOCH
KERNEL_RELEASE: Final = "6.8.0-1058-azure-fde"
R1_MODULES: Final = ("dm-bufio.ko", "dm-verity.ko")
PARAKEET_SHA: Final = "3cbdc85877e668ca7b82d0d56770eb1fac76691f55d6b97545e8d61ca588d10d"

NFT_RULESET: Final = """table inet spp_filter {
    chain output {
        type filter hook output priority 0; policy drop;
        oif "lo" accept
        ct state established,related accept
        socket cgroupv2 level 1 "sppcontent.slice" drop
        udp sport 68 udp dport 67 accept
        ip daddr 168.63.129.16 udp dport 53 accept
        ip daddr 168.63.129.16 tcp dport 53 accept
        socket cgroupv2 level 1 "sppgateway.slice" tcp dport 443 accept
    }
}
"""

UNIT_EGRESS: Final = """[Unit]
Description=SPP egress nftables filter
DefaultDependencies=no
# The rules match these slices by cgroup, which nft resolves at load: start them first so their
# (empty) cgroups exist. SGLang and ASR run in sppcontent.slice; the gateway in sppgateway.slice.
Requires=sppcontent.slice sppgateway.slice
After=local-fs.target systemd-modules-load.service sppcontent.slice sppgateway.slice
Wants=network-pre.target
Before=network-pre.target spp-gateway.service spp-asr.service sglang.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/nftables.d/spp-egress.nft
[Install]
WantedBy=multi-user.target
"""

JOURNALD_DROPIN: Final = """[Journal]
Storage=volatile
ForwardToConsole=no
ForwardToSyslog=no
RuntimeMaxUse=16M
"""

SYSCTL_DROPIN: Final = """kernel.core_pattern=|/bin/false
"""

UNIT_GATEWAY: Final = """[Unit]
Description=SPP RA-TLS gateway (:9443)
After=network.target
[Service]
Environment=PYTHONPATH=/opt/conf-proc:/opt/spp/pydeps
RuntimeDirectory=gw
Environment=TMPDIR=/run/gw
ExecStart=/usr/bin/python3 /opt/conf-proc/ratls_gateway.py --listen-host 0.0.0.0 --listen-port 9443 --upstream-host 127.0.0.1 --upstream-port 8000 --audio-upstream-host 127.0.0.1 --audio-upstream-port 8100 --collector-command /opt/conf-proc/run-collector.sh --entitlement-url https://services.solstone.app/spp/authorize --entitlement-timeout 10
Restart=no
[Install]
WantedBy=multi-user.target
"""

# The sealed appliance's evidence collector. The gateway already runs as root, so no sudo; the
# collector's pinned dependencies sit in their own tree, ahead of the SGLang base's; the vendor
# GPU verifier opens verifier.log in its working directory, which must therefore be tmpfs; and the
# quote carries the fourteen-register selection the owner appraises, not the running engine's ten.
COLLECTOR_SH: Final = """#!/bin/sh
set -eu
mkdir -p /run/gw/collector
cd /run/gw/collector
exec env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin TMPDIR=/run/gw \\
  PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/opt/spp/collector-site \\
  SPP_NVIDIA_VERIFIER_SRC=/opt/spp/collector-site SPP_VCEK_CACHE_DIR=/run/gw/vcek-cache \\
  SPP_PCR_LIST=sha256:0,2,4,7,8,9,11,12,13,14,15,16,22,23 \\
  /usr/bin/python3 /opt/conf-proc/ratls_collector.py
"""

UNIT_REPORT: Final = """[Unit]
Description=SPP R1 stage-1b boot report
After=multi-user.target
[Service]
# Type=simple: systemd marks the service started the instant it forks, so the
# boot transaction completes and systemd does NOT paint a per-second job-running
# spinner to the serial console for the report's whole (minutes-long) runtime.
# On the H100 boot that spinner produced ~144 KB and truncated the evidence.
Type=simple
ExecStart=/opt/spp/r1-report.sh
[Install]
WantedBy=multi-user.target
"""

REPORT_SH: Final = """#!/bin/bash
# SPP R1 stage-1b boot proof: sample the sealed appliance's service states, then power off.
exec >/dev/ttyS0 2>&1
sleep 35
echo
echo "==== SPP-R1-1B-REPORT ===="
echo "systemd: $(systemctl is-system-running 2>&1)"
echo "default target: $(systemctl get-default 2>&1)"
for u in spp-gateway spp-asr sglang; do
  echo "unit ${u}: active=$(systemctl is-active ${u}.service 2>&1) result=$(systemctl show -p Result --value ${u}.service 2>&1)"
done
echo "-- listening sockets --"; ss -ltnp 2>/dev/null | grep -E ':9443|:8100|:8000' || echo "(none of 9443/8100/8000 listening)"
echo "-- gateway last log --"; journalctl -u spp-gateway.service --no-pager -n 6 2>/dev/null | tail -6
echo "-- asr last log (expect CC-gate fail-closed) --"; journalctl -u spp-asr.service --no-pager -n 4 2>/dev/null | tail -4
echo "-- operator doors --"; echo "sshd present: $([ -e /usr/sbin/sshd ] && echo YES || echo no)"; echo "root fs rw: $(awk '$2=="/"{print $4}' /proc/mounts | head -1)"
echo "==== SPP-R1-1B-DONE, powering off ===="
sync
systemctl poweroff -f
"""

STAGE_MODEL_SH: Final = """#!/bin/bash
# Stage the sealed model from the (verity-measured, read-only) squashfs into tmpfs
# before SGLang starts. The confidential VM disk is latency-bound at queue depth 1, so
# copy every file CONCURRENTLY to raise queue depth and use the disk's burst IOPS; the
# larger squashfs block size (-b 1M) cuts the per-MB I/O count. SGLang then mmaps from RAM.
set -u
echo SPP-STAGE-COPY-BEGIN
mkdir -p /dev/shm/qwen
for f in /opt/models/qwen/*; do cp -a "$f" /dev/shm/qwen/ & done
wait
echo "SPP-STAGE-COPY-DONE files=$(ls /dev/shm/qwen | wc -l) bytes=$(du -sb /dev/shm/qwen | cut -f1)"
"""

UNIT_GPU_BRINGUP: Final = """[Unit]
Description=SPP confidential-GPU bring-up (load nvidia CC modules, set ready)
After=basic.target
Before=sglang.service spp-asr.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/opt/spp/gpu-bringup.sh
[Install]
WantedBy=multi-user.target
"""

UNIT_SGLANG: Final = """[Unit]
Description=SPP SGLang inference server (:8000)
After=network.target spp-gpu-bringup.service
[Service]
WorkingDirectory=/opt/sglang
Environment=LD_LIBRARY_PATH=/usr/local/cuda-13.0/lib64:/usr/local/cuda-13.0/targets/x86_64-linux/lib:/usr/lib/x86_64-linux-gnu:/usr/local/lib/python3.12/dist-packages/torch/lib
Environment=CUDA_HOME=/usr/local/cuda-13.0
Environment=PATH=/usr/local/cuda-13.0/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
RuntimeDirectory=sglang
Environment=HF_HUB_OFFLINE=1
Environment=TRANSFORMERS_OFFLINE=1
Environment=HOME=/run/sglang
Environment=TMPDIR=/run/sglang
Environment=XDG_CACHE_HOME=/run/sglang/.cache
Environment=HF_HOME=/run/sglang/hf
Environment=TORCHINDUCTOR_CACHE_DIR=/run/sglang/inductor
Environment=TRITON_CACHE_DIR=/run/sglang/triton
Environment=OUTLINES_CACHE_DIR=/run/sglang/outlines
TimeoutStartSec=2400
ExecStartPre=/opt/spp/stage-model.sh
ExecStart=/usr/bin/python3 -m sglang.launch_server --model-path /dev/shm/qwen --served-model-name Qwen/Qwen3.5-4B --host 127.0.0.1 --port 8000 --mem-fraction-static 0.80 --context-length 16384 --trust-remote-code
Restart=no
[Install]
WantedBy=multi-user.target
"""

UNIT_ASR: Final = """[Unit]
Description=SPP ASR sidecar (parakeet, loopback 8100)
After=network.target
[Service]
Environment=PYTHONPATH=/opt/asr-site-packages
Environment=LD_LIBRARY_PATH=/opt/asr-libs
Environment=HF_HUB_OFFLINE=1
Environment=TRANSFORMERS_OFFLINE=1
RuntimeDirectory=asr
Environment=HOME=/run/asr
Environment=TMPDIR=/run/asr
Environment=HF_HOME=/run/asr/hf
Environment=XDG_CACHE_HOME=/run/asr/.cache
ExecStart=/opt/asr-root/usr/bin/python3.10 /opt/conf-proc/asr_shim.py --host 127.0.0.1 --port 8100 --model-path /opt/spp-asr/parakeet-tdt-0.6b-v3.nemo --model-sha256 %s
Restart=no
[Install]
WantedBy=multi-user.target
""" % PARAKEET_SHA


def canonical_dumps(value: object) -> str:
    return json.dumps(value, indent=1, sort_keys=True) + "\n"


def _require(unit: str, deps: str, slice_name: str) -> str:
    # prod only: the serving units come back after a crash (same measured code), where the
    # qualification stages kept Restart=no so a failure stayed visible in their report.
    unit = unit.replace("[Unit]\n", f"[Unit]\nRequires={deps}\nAfter={deps}\n", 1)
    unit = unit.replace("Restart=no\n", "Restart=on-failure\nRestartSec=5\n", 1)
    return unit.replace("[Service]\n", f"[Service]\nSlice={slice_name}\n", 1)


SLICE_UNITS: Final = {
    "sppcontent.slice": "[Unit]\nDescription=SPP content-handling services (no egress beyond loopback)\n",
    "sppgateway.slice": "[Unit]\nDescription=SPP RA-TLS gateway (the only service allowed out on 443)\n",
}


def unit_sglang(stage: str) -> str:
    if stage == "prod":
        unit = UNIT_SGLANG.replace("[Service]\n", "[Service]\nEnvironment=PYTHONNOUSERSITE=1\n", 1)
        return _require(unit, "spp-egress.service spp-gpu-bringup.service", "sppcontent.slice")
    return UNIT_SGLANG


def unit_asr(stage: str) -> str:
    if stage == "prod":
        unit = UNIT_ASR.replace("[Service]\n", "[Service]\nEnvironment=PYTHONNOUSERSITE=1\n", 1)
        return _require(unit, "spp-egress.service spp-gpu-bringup.service", "sppcontent.slice")
    return UNIT_ASR


def unit_gateway(stage: str) -> str:
    if stage != "prod":
        return UNIT_GATEWAY
    unit = UNIT_GATEWAY.replace("--collector-command /opt/conf-proc/run-collector.sh",
                                "--collector-command /opt/spp/run-collector.sh")
    return _require(unit, "spp-egress.service", "sppgateway.slice")


def offline(argv: list[str]) -> list[str]:
    # Every build step after input verification runs with no network: its own empty network
    # namespace, same filesystem. bwrap does this unprivileged where `unshare --net` cannot
    # (Ubuntu 24.04 restricts unprivileged user namespaces).
    return ["bwrap", "--bind", "/", "/", "--dev", "/dev", "--proc", "/proc",
            "--unshare-net", "--die-with-parent", "--", *argv]


def require_clean_repo(repo: Path) -> str:
    res_head = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True
    )
    if res_head.returncode != 0:
        raise SystemExit(f"git rev-parse HEAD failed on {repo}")
    head_sha = res_head.stdout.decode("utf-8").strip()
    res_status = subprocess.run(
        ["git", "-C", str(repo), "status", "--porcelain"], capture_output=True
    )
    if res_status.returncode != 0:
        raise SystemExit(f"git status --porcelain failed on {repo}")
    status_output = res_status.stdout.decode("utf-8").strip()
    if status_output:
        raise SystemExit(f"git working tree at {repo} is dirty:\n{status_output}")
    return head_sha


def required_inputs(stage: str) -> list[str]:
    required_ids = [
        "KERNEL_BZIMAGE",
        "MODULE_DIR",
        "STUB",
        "UKIFY",
        "PEFILE_DEB",
        "MTOOLS_ROOT",
    ]
    if stage in ("1b", "2h", "prod"):
        required_ids.extend(
            [
                "SGLANG_ROOTFS",
                "ASR_OS_ROOT",
                "ASR_SITE",
                "QWEN",
                "PARAKEET",
                "DRIVER_DEBS",
                "PYDEPS",
            ]
        )
    if stage in ("2h", "prod"):
        required_ids.extend(["A24_PKG", "STOCK_MODULES_DEB", "NV_MODULES_DEB", "NV_FIRMWARE_DEB"])
    if stage == "2h":
        required_ids.extend(["CUDA_PROBE", "H100_NVML", "H100_REPORT"])
    if stage == "prod":
        required_ids.extend(["NFT_PKG", "COLLECTOR_SITE"])
    return required_ids


def verify_inputs(
    manifest_data: dict, stage: str, workspace: Path
) -> dict[str, Path]:
    inputs = manifest_data.get("inputs")
    if not isinstance(inputs, dict):
        raise SystemExit("manifest missing 'inputs' object")

    required_ids = required_inputs(stage)
    paths: dict[str, Path] = {}
    for input_id in required_ids:
        if input_id not in inputs:
            raise SystemExit(f"manifest missing required input {input_id!r}")
        entry = inputs[input_id]
        if not isinstance(entry, dict):
            raise SystemExit(f"input {input_id!r} is not an object")

        expected_sha = entry.get("sha256")
        if not expected_sha or not isinstance(expected_sha, str):
            raise SystemExit(f"input {input_id!r} has null or empty sha256")

        rel_path = entry.get("path")
        if not rel_path or not isinstance(rel_path, str):
            raise SystemExit(f"input {input_id!r} missing path")

        target_path = workspace / rel_path
        if not target_path.exists():
            raise SystemExit(f"input {input_id!r} path {target_path} does not exist")

        if target_path.is_dir() and "files" not in entry:
            # Compact entry: only the tree digest is pinned. Recompute the file list the way the
            # manifest was populated and compare digests (full lists ship beside the manifest).
            from populate_manifest import tree_digest, tree_entries

            got = tree_digest(tree_entries(target_path))
            if got != expected_sha:
                raise SystemExit(f"directory {input_id!r} sha256 mismatch: expected {expected_sha}, got {got}")
        elif "files" in entry:
            # Directory entry
            expected_files = entry.get("files")
            if not isinstance(expected_files, list):
                raise SystemExit(f"directory input {input_id!r} has null or non-list files")

            # Collect on-disk regular files and symlinks; a symlink entry pins its target.
            on_disk_map: dict[str, Path] = {}
            for p in target_path.rglob("*"):
                if p.is_symlink() or p.is_file():
                    rel_p = p.relative_to(target_path).as_posix()
                    on_disk_map[rel_p] = p

            manifest_file_map: dict[str, dict[str, object]] = {}
            for f_item in expected_files:
                if not isinstance(f_item, dict) or "path" not in f_item:
                    raise SystemExit(f"directory input {input_id!r} contains invalid file entry")
                fpath = str(f_item["path"])
                if fpath in manifest_file_map:
                    raise SystemExit(f"directory input {input_id!r} duplicate file path: {fpath}")
                manifest_file_map[fpath] = f_item

            on_disk_paths = set(on_disk_map.keys())
            manifest_paths = set(manifest_file_map.keys())

            missing_on_disk = manifest_paths - on_disk_paths
            if missing_on_disk:
                raise SystemExit(f"missing file on disk: {sorted(missing_on_disk)[0]}")

            extra_on_disk = on_disk_paths - manifest_paths
            if extra_on_disk:
                raise SystemExit(f"unlisted file on disk: {sorted(extra_on_disk)[0]}")

            total_size = 0
            for fpath in sorted(manifest_paths):
                f_item = manifest_file_map[fpath]
                f_disk_path = on_disk_map[fpath]
                if f_disk_path.is_symlink() or "symlink" in f_item:
                    target = os.readlink(f_disk_path) if f_disk_path.is_symlink() else None
                    if target is None or f_item.get("symlink") != target:
                        raise SystemExit(f"symlink mismatch for {fpath}: expected {f_item.get('symlink')!r}, got {target!r}")
                    continue
                disk_size = f_disk_path.stat().st_size
                exp_file_size = f_item.get("size_bytes")
                if not isinstance(exp_file_size, int) or exp_file_size != disk_size:
                    raise SystemExit(f"file size mismatch for {fpath}: expected {exp_file_size}, got {disk_size}")
                total_size += disk_size

                exp_file_sha = f_item.get("sha256")
                disk_sha = spp_disk.sha256_file(f_disk_path)
                if not exp_file_sha or exp_file_sha != disk_sha:
                    raise SystemExit(f"file sha256 mismatch for {fpath}: expected {exp_file_sha}, got {disk_sha}")

            exp_dir_size = entry.get("size_bytes")
            if not isinstance(exp_dir_size, int) or exp_dir_size != total_size:
                raise SystemExit(f"directory {input_id!r} size mismatch: expected {exp_dir_size}, got {total_size}")

            sorted_files = sorted(expected_files, key=lambda item: str(item.get("path", "")))
            dir_sha = spp_disk.sha256_bytes(
                json.dumps(sorted_files, sort_keys=True, separators=(",", ":")).encode("utf-8")
            )
            if dir_sha != expected_sha:
                raise SystemExit(f"directory {input_id!r} sha256 mismatch: expected {expected_sha}, got {dir_sha}")
        else:
            # File entry
            actual_size = target_path.stat().st_size
            exp_file_size = entry.get("size_bytes")
            if not isinstance(exp_file_size, int) or exp_file_size != actual_size:
                raise SystemExit(f"file {input_id!r} size mismatch: expected {exp_file_size}, got {actual_size}")

            actual_sha = spp_disk.sha256_file(target_path)
            if actual_sha != expected_sha:
                raise SystemExit(f"file {input_id!r} sha256 mismatch: expected {expected_sha}, got {actual_sha}")

        paths[input_id] = target_path

    return paths


def write_historical_report(tree: Path) -> None:
    unit_dst = tree / "etc/systemd/system/spp-r1-report.service"
    unit_dst.parent.mkdir(parents=True, exist_ok=True)
    unit_dst.write_text(UNIT_REPORT)
    report_sh = tree / "opt/spp/r1-report.sh"
    report_sh.parent.mkdir(parents=True, exist_ok=True)
    report_sh.write_text(REPORT_SH)
    report_sh.chmod(0o755)
    wants = tree / "etc/systemd/system/multi-user.target.wants"
    wants.mkdir(parents=True, exist_ok=True)
    symlink = wants / "spp-r1-report.service"
    if not symlink.exists():
        symlink.symlink_to("/etc/systemd/system/spp-r1-report.service")



def install_prod_hardening(tree: Path, nft_pkg: Path) -> None:
    # Build-time checks
    for p in tree.rglob("*"):
        if p.name == "systemd-coredump":
            raise SystemExit(f"prohibited coredump binary found: {p}")
        if p.name == "kdump" or p.name.startswith(("kdump-", "kdump.", "kdumpctl")):
            raise SystemExit(f"prohibited kdump file found: {p}")
        if p.name == "swapfile" and p.is_file():
            raise SystemExit(f"prohibited swapfile found: {p}")
        if p.name == "fstab" and p.is_file():
            content = p.read_text(encoding="utf-8", errors="ignore")
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split()
                    if len(parts) >= 3 and parts[2] == "swap":
                        raise SystemExit(f"prohibited swap fstab entry found in {p}: {line}")

    for rel in ("usr/sbin/nft",):
        dst = tree / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.unlink(missing_ok=True)
        shutil.copy2(nft_pkg / rel, dst)
    lib_src = nft_pkg / "usr/lib/x86_64-linux-gnu"
    for lib in sorted(lib_src.iterdir()):
        dst = tree / "usr/lib/x86_64-linux-gnu" / lib.name
        if lib.is_symlink():
            if dst.exists() or dst.is_symlink():
                dst.unlink()
            dst.symlink_to(lib.readlink())
        else:
            dst.unlink(missing_ok=True)
            shutil.copy2(lib, dst)
    spp_disk.run(["/sbin/ldconfig", "-r", str(tree)], cwd=tree)
    (tree / "var/cache/ldconfig/aux-cache").unlink(missing_ok=True)

    nft_file = tree / "etc/nftables.d/spp-egress.nft"
    nft_file.parent.mkdir(parents=True, exist_ok=True)
    nft_file.write_text(NFT_RULESET)

    (tree / "etc/systemd/system").mkdir(parents=True, exist_ok=True)
    for name, text in SLICE_UNITS.items():
        (tree / "etc/systemd/system" / name).write_text(text)

    egress_unit = tree / "etc/systemd/system/spp-egress.service"
    egress_unit.parent.mkdir(parents=True, exist_ok=True)
    egress_unit.write_text(UNIT_EGRESS)

    wants = tree / "etc/systemd/system/multi-user.target.wants"
    wants.mkdir(parents=True, exist_ok=True)
    symlink = wants / "spp-egress.service"
    if not symlink.exists():
        symlink.symlink_to("/etc/systemd/system/spp-egress.service")

    journal_conf = tree / "etc/systemd/journald.conf.d/spp.conf"
    journal_conf.parent.mkdir(parents=True, exist_ok=True)
    journal_conf.write_text(JOURNALD_DROPIN)

    journal_dir = tree / "var/log/journal"
    if journal_dir.exists():
        if journal_dir.is_dir() and not journal_dir.is_symlink():
            shutil.rmtree(journal_dir)
        else:
            journal_dir.unlink()

    sysctl_conf = tree / "etc/sysctl.d/spp.conf"
    sysctl_conf.parent.mkdir(parents=True, exist_ok=True)
    sysctl_conf.write_text(SYSCTL_DROPIN)



def build_cmdline(
    work: Path,
    root_partuuid: str,
    verity_partuuid: str,
    binding_partuuid: str,
    root_hash: str,
    *,
    stage: str,
) -> Path:
    _ = binding_partuuid
    cmdline_file = work / "cmdline.txt"
    cmdline = (
        "ro rdinit=/spp-diag-handoff root=/dev/mapper/spp-diag-root rootfstype=squashfs "
        "ip=off " + ("" if stage == "prod" else "console=ttyS0 ")
        + f"spp_diag.root_data=PARTUUID={root_partuuid} "
        f"spp_diag.root_hash=PARTUUID={verity_partuuid} "
        f"spp_diag.roothash={root_hash}"
    )
    spp_disk.write_bytes(cmdline_file, cmdline.encode("ascii"), 0o644)
    return cmdline_file


def build_disk_r1(
    work: Path,
    diagnostic: Path,
    rootfs: Path,
    verity: Path,
    binding: bytes,
    partuuids: dict[str, str],
    disk_guid: str,
    *,
    mtools_root: Path,
    run_id: str,
    build_epoch: int = BUILD_EPOCH,
    command_prefix: list[str] | tuple[str, ...] = (),
) -> tuple[Path, dict[str, object]]:
    mib = 1024 * 1024
    gib = 1024 * 1024 * 1024
    sizes = {
        "esp": max(64 * mib, spp_disk.align(diagnostic.stat().st_size + 8 * mib, mib)),
        "root": spp_disk.align(rootfs.stat().st_size, mib),
        "verity": spp_disk.align(verity.stat().st_size, mib),
        "binding": mib,
    }
    starts: dict[str, int] = {}
    cursor = mib
    for name in ("esp", "root", "verity", "binding"):
        starts[name] = cursor
        cursor += sizes[name]

    virtual_size = max(gib, spp_disk.align(cursor + 8 * mib, gib))
    raw = work / "diagnostic.raw"
    with raw.open("xb") as handle:
        handle.truncate(virtual_size)

    command = ["/usr/sbin/sgdisk", "--clear", f"--disk-guid={disk_guid}"]
    typecodes = {"esp": "ef00", "root": "8300", "verity": "8300", "binding": "8300"}
    labels = {
        "esp": "SPP-ESP",
        "root": "SPP-ROOT",
        "verity": "SPP-VERITY",
        "binding": "SPP-BINDING",
    }
    for index, name in enumerate(("esp", "root", "verity", "binding"), start=1):
        start_lba = starts[name] // 512
        end_lba = (starts[name] + sizes[name]) // 512 - 1
        command.extend(
            [
                f"--new={index}:{start_lba}:{end_lba}",
                f"--typecode={index}:{typecodes[name]}",
                f"--partition-guid={index}:{partuuids[name]}",
                f"--change-name={index}:{labels[name]}",
            ]
        )
    command.append(str(raw))
    spp_disk.run(command, cwd=work, command_prefix=command_prefix)
    verify = spp_disk.run(
        ["/usr/sbin/sgdisk", "--verify", "--print", str(raw)],
        cwd=work,
        command_prefix=command_prefix,
    )
    (work / "generated").mkdir(exist_ok=True)
    (work / "generated/sgdisk-verify.txt").write_bytes(verify.stdout + verify.stderr)

    fat = work / "esp.fat"
    with fat.open("xb") as handle:
        handle.truncate(sizes["esp"])
    env = {
        "PATH": str(mtools_root) + ":/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "MTOOLS_SKIP_CHECK": "1",
    }
    spp_disk.run(
        [str(mtools_root / "mformat"), "-i", str(fat), "-F", "-v", "SPPR1", "::"],
        cwd=work,
        env=env,
        command_prefix=command_prefix,
    )
    spp_disk.run(
        [str(mtools_root / "mmd"), "-i", str(fat), "::/EFI", "::/EFI/BOOT"],
        cwd=work,
        env=env,
        command_prefix=command_prefix,
    )
    spp_disk.run(
        [
            str(mtools_root / "mcopy"),
            "-i",
            str(fat),
            str(diagnostic),
            "::/EFI/BOOT/BOOTX64.EFI",
        ],
        cwd=work,
        env=env,
        command_prefix=command_prefix,
    )

    with raw.open("r+b") as handle:
        for name, source in (("esp", fat), ("root", rootfs), ("verity", verity)):
            handle.seek(starts[name])
            with source.open("rb") as input_handle:
                shutil.copyfileobj(input_handle, handle, 1024 * 1024)
        handle.seek(starts["binding"])
        handle.write(binding)
        handle.flush()
        os.fsync(handle.fileno())

    footer = spp_disk.vhd_footer(virtual_size, build_epoch=build_epoch, run_id=run_id)
    vhd = work / "diagnostic.vhd"
    with raw.open("rb") as source, vhd.open("xb") as destination:
        shutil.copyfileobj(source, destination, 1024 * 1024)
        destination.write(footer)
        destination.flush()
        os.fsync(destination.fileno())
    vhd.chmod(0o444)

    layout = {
        "virtual_size_bytes": virtual_size,
        "vhd_size_bytes": vhd.stat().st_size,
        "footer_sha256": spp_disk.sha256_bytes(footer),
        "disk_guid": disk_guid,
        "partitions": {
            name: {
                "offset": starts[name],
                "size_bytes": sizes[name],
                "partuuid": partuuids[name],
            }
            for name in ("esp", "root", "verity", "binding")
        },
    }
    return vhd, layout


def build_squashfs_1b(
    work: Path,
    tree: Path,
    *,
    build_epoch: int = BUILD_EPOCH,
    resume: bool = False,
    command_prefix: list[str] | tuple[str, ...] = (),
) -> Path:
    rootfs = work / "rootfs.img"
    if resume and rootfs.exists():
        return rootfs
    spp_disk.run(
        [
            "/usr/bin/mksquashfs",
            str(tree),
            str(rootfs),
            "-noappend",
            "-reproducible",
            "-all-root",
            "-no-xattrs",
            "-no-exports",
            "-no-progress",
            "-comp",
            "zstd",
            "-b",
            "1M",
            "-mkfs-time",
            str(build_epoch),
            "-all-time",
            str(build_epoch),
            "-root-mode",
            "0755",
        ],
        cwd=work,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC"},
        command_prefix=command_prefix,
    )
    if rootfs.stat().st_size % 4096:
        with rootfs.open("ab") as handle:
            handle.write(b"\0" * (-rootfs.stat().st_size % 4096))
    rootfs.chmod(0o444)
    return rootfs


def _inventory_files(tree: Path) -> set[str]:
    files = set()
    for p in tree.rglob("*"):
        if p.is_file() and not p.is_symlink():
            files.add(p.relative_to(tree).as_posix())
    return files


# What the image runs from this repository: the gateway, its collector, the ASR sidecar and the
# AMD roots they check against. Nothing else of the repo reaches the image, so a change to the
# recipe or the docs does not move the roothash, and the image carries no unused code.
RUNTIME_SOURCE: Final = ("LICENSE", "asr_shim.py", "ratls_collector.py", "ratls_contract.py",
                         "ratls_gateway.py", "roots/amd/", "strict_wav.py", "verifier.py")


def copy_tracked_source(repo: Path, dest: Path, allow: tuple[str, ...] = RUNTIME_SOURCE) -> None:
    # Only what HEAD tracks and the runtime needs: an ignored build/ or cache left behind by
    # `make ci` never reaches the image, and two clean clones at one commit give one tree.
    # File modes come from the index, not from the checkout's umask.
    listing = subprocess.run(["git", "-C", str(repo), "ls-files", "-s", "-z"],
                             capture_output=True, check=True).stdout
    for entry in listing.split(b"\0"):
        if not entry:
            continue
        meta, raw_path = entry.split(b"\t", 1)
        rel = raw_path.decode("utf-8")
        if not any(rel == a or (a.endswith("/") and rel.startswith(a)) for a in allow):
            continue
        mode = meta.split()[0]
        src, dst = repo / rel, dest / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        if mode == b"120000":
            dst.symlink_to(os.readlink(src))
        elif mode in (b"100644", b"100755"):
            shutil.copyfile(src, dst)
            dst.chmod(0o755 if mode == b"100755" else 0o644)
        else:
            raise SystemExit(f"unsupported tracked entry {rel} (mode {mode.decode()})")


def assemble_serving_rootfs(
    work: Path, stage: str, paths: dict[str, Path]
) -> tuple[Path, list[dict[str, object]]]:
    tree = work / "rootfs-tree"
    tree.mkdir(parents=True, exist_ok=True)
    origins: list[dict[str, object]] = []

    def _sh(cmd: str) -> subprocess.CompletedProcess[bytes]:
        return spp_disk.run(["/bin/bash", "-euo", "pipefail", "-c", cmd], cwd=work)

    # Base SGLang rootfs copy
    sglang_rootfs = paths["SGLANG_ROOTFS"]
    _sh(f"cp -al {sglang_rootfs}/. {tree}/")
    _sh(f"rm -f {tree}/usr/sbin/sshd {tree}/usr/bin/ssh")
    _sh(
        f"rm -f {tree}/etc/systemd/system/default.target && ln -s /usr/lib/systemd/system/multi-user.target {tree}/etc/systemd/system/default.target"
    )
    for g in ("serial-getty@.service", "getty@.service", "console-getty.service", "getty.target"):
        _sh(f"ln -sf /dev/null {tree}/etc/systemd/system/{g}")
    _sh(f"rm -f {tree}/etc/systemd/system/getty.target.wants/* 2>/dev/null || true")
    # The tree shares inodes with the SGLang input (cp -al): replace, never write through.
    (tree / "etc/machine-id").unlink(missing_ok=True)
    (tree / "etc/machine-id").write_text("00000000000000000000000000000001\n")
    sglang_files = _inventory_files(tree)
    origins.append(
        {
            "kind": "tree",
            "name": "sglang-base-rootfs",
            "version": "base",
            "sha256": spp_disk.sha256_file(paths["SGLANG_ROOTFS"])
            if paths["SGLANG_ROOTFS"].is_file()
            else "",
            "revision": "",
            "files": sorted(sglang_files),
        }
    )

    # Driver debs
    driver_debs = paths["DRIVER_DEBS"]
    driver_extract = work / "driver-extract"
    driver_extract.mkdir(parents=True, exist_ok=True)
    for deb in sorted(driver_debs.glob("*.deb")):
        _sh(f"dpkg-deb -x {deb} {driver_extract}")
        deb_info = subprocess.run(["dpkg-deb", "-f", str(deb)], capture_output=True)
        deb_pkg = deb.stem
        deb_ver = "unversioned"
        for line in deb_info.stdout.decode("utf-8", errors="ignore").splitlines():
            if line.startswith("Package:"):
                deb_pkg = line.split(":", 1)[1].strip()
            elif line.startswith("Version:"):
                deb_ver = line.split(":", 1)[1].strip()
        origins.append(
            {
                "kind": "deb",
                "name": deb_pkg,
                "version": deb_ver,
                "sha256": spp_disk.sha256_file(deb),
                "revision": "",
                "files": [],
            }
        )

    before_driver = _inventory_files(tree)
    _sh(f"cp -a --remove-destination {driver_extract}/usr/lib/x86_64-linux-gnu/. {tree}/usr/lib/x86_64-linux-gnu/")
    _sh(f"cp -a --remove-destination {driver_extract}/usr/bin/. {tree}/usr/bin/")
    _sh(f"/sbin/ldconfig -r {tree}")
    _sh(f"rm -f {tree}/var/cache/ldconfig/aux-cache")
    driver_added = _inventory_files(tree) - before_driver
    # Associate driver files with the driver debs
    if origins and origins[-1]["kind"] == "deb":
        origins[-1]["files"] = sorted(driver_added)

    # Runtime directories
    for d in (
        "opt/asr-root",
        "opt/asr-site-packages",
        "opt/models/qwen",
        "opt/spp-asr",
        "opt/conf-proc",
        "opt/spp/pydeps",
        "opt/spp/collector-site",
        "opt/sglang",
        "etc/spp",
    ):
        (tree / d).mkdir(parents=True, exist_ok=True)

    # ASR Runtime
    asr_os_root = paths["ASR_OS_ROOT"]
    before_asr = _inventory_files(tree)
    _sh(f"cp -al {asr_os_root}/. {tree}/opt/asr-root/")
    origins.append(
        {
            "kind": "tree",
            "name": "asr-os-root",
            "version": "runtime",
            "sha256": "",
            "revision": "",
            "files": sorted(_inventory_files(tree) - before_asr),
        }
    )

    # ASR site-packages
    asr_site = paths["ASR_SITE"]
    before_site = _inventory_files(tree)
    _sh(f"cp -al {asr_site}/. {tree}/opt/asr-site-packages/")
    origins.append(
        {
            "kind": "tree",
            "name": "asr-site-packages",
            "version": "site-packages",
            "sha256": "",
            "revision": "",
            "files": sorted(_inventory_files(tree) - before_site),
        }
    )

    # libmpdec gap bridge
    libmpdec_dir = tree / "opt/asr-libs"
    libmpdec_dir.mkdir(parents=True, exist_ok=True)
    for src in (tree / "usr/lib/x86_64-linux-gnu").glob("libmpdec*.so.2*"):
        _sh(f"cp -a {src} {libmpdec_dir}/")
    for src in libmpdec_dir.glob("libmpdec.so.2*"):
        _sh(f"ln -sf {src.name} {libmpdec_dir}/libmpdec.so.3")
    for src in libmpdec_dir.glob("libmpdec++.so.2*"):
        _sh(f"ln -sf {src.name} {libmpdec_dir}/libmpdec++.so.3")

    # Qwen model
    qwen = paths["QWEN"]
    before_qwen = _inventory_files(tree)
    _sh(f"cp -al {qwen}/. {tree}/opt/models/qwen/")
    origins.append(
        {
            "kind": "model",
            "name": "Qwen3.5-4B",
            "version": "model",
            "sha256": "",
            "revision": "qwen",
            "files": sorted(_inventory_files(tree) - before_qwen),
        }
    )

    # Parakeet model
    parakeet = paths["PARAKEET"]
    before_parakeet = _inventory_files(tree)
    _sh(f"cp -a {parakeet} {tree}/opt/spp-asr/parakeet-tdt-0.6b-v3.nemo")
    origins.append(
        {
            "kind": "model",
            "name": "parakeet-tdt-0.6b-v3",
            "version": "0.6b",
            "sha256": PARAKEET_SHA,
            "revision": PARAKEET_SHA,
            "files": sorted(_inventory_files(tree) - before_parakeet),
        }
    )

    # conf-proc source sync
    before_conf = _inventory_files(tree)
    head_rev = require_clean_repo(REPO)
    copy_tracked_source(REPO, tree / "opt/conf-proc")
    origins.append(
        {
            "kind": "git",
            "name": "conf-proc",
            "version": head_rev[:12],
            "sha256": "",
            "revision": head_rev,
            "files": sorted(_inventory_files(tree) - before_conf),
        }
    )

    # pyOpenSSL pydeps
    pydeps = paths["PYDEPS"]
    before_pydeps = _inventory_files(tree)
    _sh(f"cp -a {pydeps}/. {tree}/opt/spp/pydeps/")
    origins.append(
        {
            "kind": "tree",
            "name": "pydeps",
            "version": "pydeps",
            "sha256": "",
            "revision": "",
            "files": sorted(_inventory_files(tree) - before_pydeps),
        }
    )

    # Base units & scripts
    (tree / "etc/systemd/system/spp-gateway.service").write_text(unit_gateway(stage))
    (tree / "etc/systemd/system/spp-asr.service").write_text(unit_asr(stage))
    (tree / "etc/systemd/system/sglang.service").write_text(unit_sglang(stage))
    stage_model = tree / "opt/spp/stage-model.sh"
    stage_model.parent.mkdir(parents=True, exist_ok=True)
    stage_model.write_text(STAGE_MODEL_SH)
    stage_model.chmod(0o755)

    wants = tree / "etc/systemd/system/multi-user.target.wants"
    wants.mkdir(parents=True, exist_ok=True)
    for u in ("spp-gateway.service", "spp-asr.service", "sglang.service"):
        symlink = wants / u
        if not symlink.exists():
            symlink.symlink_to(f"/etc/systemd/system/{u}")

    if stage == "prod":
        before_collector = _inventory_files(tree)
        _sh(f"cp -a {paths['COLLECTOR_SITE']}/. {tree}/opt/spp/collector-site/")
        collector_sh = tree / "opt/spp/run-collector.sh"
        collector_sh.write_text(COLLECTOR_SH)
        collector_sh.chmod(0o755)
        origins.append(
            {
                "kind": "tree",
                "name": "collector-site",
                "version": "nv-local-gpu-verifier-2.3.0",
                "sha256": "",
                "revision": "",
                "files": sorted(_inventory_files(tree) - before_collector),
            }
        )

    # Stage-specific artifacts
    if stage in ("1b", "2h"):
        write_historical_report(tree)

    return tree, origins


def bake_gpu(
    work: Path,
    tree: Path,
    paths: dict[str, Path],
    kernel_release: str = KERNEL_RELEASE,
) -> list[dict[str, object]]:
    origins: list[dict[str, object]] = []

    def _sh(cmd: str) -> subprocess.CompletedProcess[bytes]:
        return spp_disk.run(["/bin/bash", "-euo", "pipefail", "-c", cmd], cwd=work)

    stock_deb = paths["STOCK_MODULES_DEB"]
    nv_deb = paths["NV_MODULES_DEB"]
    nv_fw_deb = paths["NV_FIRMWARE_DEB"]
    a24_pkg = paths["A24_PKG"]
    gpu_bringup = REPO / "appliance/gpu-bringup.sh"

    extract_dir = work / "gpu-deb-extract"
    extract_dir.mkdir(parents=True, exist_ok=True)
    _sh(f"dpkg-deb -x {stock_deb} {extract_dir}")
    _sh(f"dpkg-deb -x {nv_deb} {extract_dir}")
    _sh(f"dpkg-deb -x {nv_fw_deb} {extract_dir}")

    for deb in (stock_deb, nv_deb, nv_fw_deb):
        deb_info = subprocess.run(["dpkg-deb", "-f", str(deb)], capture_output=True)
        deb_pkg = deb.stem
        deb_ver = "unversioned"
        for line in deb_info.stdout.decode("utf-8", errors="ignore").splitlines():
            if line.startswith("Package:"):
                deb_pkg = line.split(":", 1)[1].strip()
            elif line.startswith("Version:"):
                deb_ver = line.split(":", 1)[1].strip()
        origins.append(
            {
                "kind": "deb",
                "name": deb_pkg,
                "version": deb_ver,
                "sha256": spp_disk.sha256_file(deb),
                "revision": "",
                "files": [],
            }
        )

    before_copy = _inventory_files(tree)
    # Both destinations must exist first, or cp makes lib/modules a copy of the kernel's own dir.
    _sh(f"mkdir -p {tree}/lib/modules {tree}/lib/firmware")
    _sh(f"cp -a --remove-destination {extract_dir}/lib/modules/{kernel_release} {tree}/lib/modules/")
    _sh(f"cp -a --remove-destination {extract_dir}/lib/firmware/. {tree}/lib/firmware/")
    modprobe_src = a24_pkg / "usr/bin/nvidia-modprobe"
    if modprobe_src.exists():
        _sh(f"cp -a --remove-destination {modprobe_src} {tree}/usr/bin/")
        (tree / "usr/bin/nvidia-modprobe").chmod(0o4755)
    _sh(f"/sbin/depmod -b {tree} {kernel_release}")

    gpu_sh_dst = tree / "opt/spp/gpu-bringup.sh"
    gpu_sh_dst.parent.mkdir(parents=True, exist_ok=True)
    _sh(f"cp -a {gpu_bringup} {gpu_sh_dst}")
    gpu_sh_dst.chmod(0o755)

    (tree / "etc/systemd/system/spp-gpu-bringup.service").write_text(UNIT_GPU_BRINGUP)
    wants = tree / "etc/systemd/system/multi-user.target.wants"
    wants.mkdir(parents=True, exist_ok=True)
    symlink = wants / "spp-gpu-bringup.service"
    if not symlink.exists():
        symlink.symlink_to("/etc/systemd/system/spp-gpu-bringup.service")

    gpu_added = _inventory_files(tree) - before_copy
    if origins:
        origins[-1]["files"] = sorted(gpu_added)
    return origins


def install_h100_stack(
    work: Path,
    tree: Path,
    paths: dict[str, Path],
    *,
    overwrite_report: bool,
) -> list[dict[str, object]]:
    origins: list[dict[str, object]] = []

    def _sh(cmd: str) -> subprocess.CompletedProcess[bytes]:
        return spp_disk.run(["/bin/bash", "-euo", "pipefail", "-c", cmd], cwd=work)

    a24_pkg = paths["A24_PKG"]

    before_tpm = _inventory_files(tree)
    _sh(f"cp -a --remove-destination {a24_pkg}/usr/bin/tpm2* {tree}/usr/bin/ 2>/dev/null || true")
    _sh(f"cp -a --remove-destination {a24_pkg}/usr/lib/x86_64-linux-gnu/libtss2* {tree}/usr/lib/x86_64-linux-gnu/ 2>/dev/null || true")
    _sh(f"/sbin/ldconfig -r {tree}")
    _sh(f"rm -f {tree}/var/cache/ldconfig/aux-cache")
    tpm_added = _inventory_files(tree) - before_tpm
    if tpm_added:
        origins.append(
            {
                "kind": "tree",
                "name": "a24-tpm2-stack",
                "version": "tpm2",
                "sha256": "",
                "revision": "",
                "files": sorted(tpm_added),
            }
        )

    if not overwrite_report:
        # prod: the CUDA probe and NVML attest script only ever fed the serial report.
        return origins + bake_gpu(work, tree, paths)

    cuda_probe = paths["CUDA_PROBE"]
    h100_nvml = paths["H100_NVML"]
    before_diag = _inventory_files(tree)
    probe_dst = tree / "opt/spp/spp-diag-cuda-driver"
    probe_dst.parent.mkdir(parents=True, exist_ok=True)
    _sh(f"cp -a {cuda_probe} {probe_dst}")
    probe_dst.chmod(0o755)

    nvml_dst = tree / "opt/spp/h100-nvml-attest.py"
    _sh(f"cp -a {h100_nvml} {nvml_dst}")

    if overwrite_report:
        h100_report = paths["H100_REPORT"]
        report_sh = tree / "opt/spp/r1-report.sh"
        report_sh.write_text(h100_report.read_text())
        report_sh.chmod(0o755)

    diag_added = _inventory_files(tree) - before_diag
    if diag_added:
        origins.append(
            {
                "kind": "recipe",
                "name": "h100-diagnostics",
                "version": "1.0",
                "sha256": "",
                "revision": "",
                "files": sorted(diag_added),
            }
        )

    gpu_origins = bake_gpu(work, tree, paths)
    origins.extend(gpu_origins)
    return origins


def assemble_rootfs_1b(work: Path, paths: dict[str, Path]) -> Path:
    tree, _ = assemble_serving_rootfs(work, "1b", paths)
    return tree


def assemble_rootfs_2h(work: Path, paths: dict[str, Path]) -> Path:
    tree, _ = assemble_serving_rootfs(work, "2h", paths)
    install_h100_stack(work, tree, paths, overwrite_report=True)
    return tree


def assemble_rootfs_prod(
    work: Path, paths: dict[str, Path]
) -> tuple[Path, list[dict[str, object]]]:
    tree, origins = assemble_serving_rootfs(work, "prod", paths)
    stack_origins = install_h100_stack(work, tree, paths, overwrite_report=False)
    origins.extend(stack_origins)

    before_harden = _inventory_files(tree)
    install_prod_hardening(tree, paths["NFT_PKG"])
    harden_added = _inventory_files(tree) - before_harden
    if harden_added:
        origins.append(
            {
                "kind": "recipe",
                "name": "prod-hardening",
                "version": "1.0",
                "sha256": "",
                "revision": "",
                "files": sorted(harden_added),
            }
        )

    # Ensure all files currently in tree are accounted for
    all_current = _inventory_files(tree)
    claimed: set[str] = set()
    for o in origins:
        claimed.update(o.get("files", []))
    unclaimed = all_current - claimed
    if unclaimed:
        origins.append(
            {
                "kind": "recipe",
                "name": "rootfs-base-files",
                "version": "1.0",
                "sha256": "",
                "revision": "",
                "files": sorted(unclaimed),
            }
        )
    return tree, origins


def compile_r1_init(work: Path) -> Path:
    # The flags the qualified boots' init was built with.
    out = work / "spp-diag-handoff"
    spp_disk.run(
        [
            "/usr/bin/gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
            "-DSPP_R1_SYSTEMD_INIT", "-static", "-Os",
            str(REPO / "spp-diag-runtime-src/spp_diag_handoff.c"),
            "-o", str(out),
        ],
        cwd=work,
    )
    out.chmod(0o555)
    return out


def compile_marker(work: Path) -> Path:
    marker_c = work / "marker.c"
    marker_c.write_text(
        """#include <fcntl.h>
#include <unistd.h>
int main(void) {
    int fd = open("/dev/ttyS0", O_WRONLY);
    if (fd >= 0) {
        write(fd, "SPP-R1-1A-MARKER-OK\\n", 20);
        close(fd);
    }
    return 0;
}
"""
    )
    out = work / "spp-r1-marker"
    spp_disk.run(
        ["/usr/bin/gcc", "-O2", "-static", str(marker_c), "-o", str(out)],
        cwd=work,
    )
    spp_disk.run(["/usr/bin/strip", str(out)], cwd=work)
    return out


def build_rootfs_tree(work: Path, marker: Path) -> Path:
    tree = work / "rootfs-tree"
    tree.mkdir(parents=True, exist_ok=True)
    for d in ("bin", "sbin", "usr/bin", "usr/sbin", "etc", "dev", "proc", "sys", "run"):
        (tree / d).mkdir(parents=True, exist_ok=True)
    shutil.copy2(marker, tree / "bin/spp-r1-marker")
    (tree / "bin/spp-r1-marker").chmod(0o755)
    (tree / "etc/spp-r1-marker").write_text("spp-r1-1a-marker\n")
    return tree


def build_initramfs_r1(
    work: Path,
    init_bin: Path,
    paths: dict[str, Path],
    *,
    build_epoch: int = BUILD_EPOCH,
) -> Path:
    # The layout the init expects: it mounts proc/sys/devtmpfs onto /proc, /sys and /dev, opens
    # the verity root at /mnt/spp-diag-root, and loads /modules/dm-bufio.ko and dm-verity.ko.
    directories = (".", "dev", "dev/mapper", "mnt", "mnt/spp-diag-root", "modules", "proc", "sys")
    files = {"spp-diag-handoff": (init_bin, stat.S_IFREG | 0o555)}
    for mod_name in R1_MODULES:
        mod_path = paths["MODULE_DIR"] / mod_name
        if not mod_path.exists():
            raise SystemExit(f"required module {mod_name} not found in {paths['MODULE_DIR']}")
        files[f"modules/{mod_name}"] = (mod_path, stat.S_IFREG | 0o444)
    entries: list[bytes] = []
    ino = 1
    for directory in sorted(directories, key=lambda v: (v.count("/"), v)):
        entries.append(spp_disk.newc_entry(directory, stat.S_IFDIR | 0o755, b"", ino, build_epoch=build_epoch))
        ino += 1
    for name, (source, mode) in sorted(files.items()):
        entries.append(spp_disk.newc_entry(name, mode, source.read_bytes(), ino, build_epoch=build_epoch))
        ino += 1
    entries.append(spp_disk.newc_entry("TRAILER!!!", stat.S_IFREG, b"", ino, build_epoch=build_epoch))
    initramfs_cpio = work / "initramfs.cpio"
    spp_disk.write_bytes(initramfs_cpio, b"".join(entries), 0o444)
    return initramfs_cpio


def generate_signer(
    work: Path, *, ephemeral: bool = False, signer_dir: Path | None = None
) -> tuple[Path, Path, Path]:
    if ephemeral:
        key = work / "spp-ephemeral.key"
        cert = work / "spp-ephemeral-cert.pem"
        spp_disk.run(
            [
                "/usr/bin/openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                str(key),
                "-out",
                str(cert),
                "-days",
                "3650",
                "-nodes",
                "-subj",
                "/CN=sol pbc SPP R1 diagnostic signer/O=sol pbc",
            ],
            cwd=work,
        )
        return key, cert, Path("/dev/null")

    if signer_dir is None:
        raise SystemExit("--signer-dir is required unless --ephemeral-signer is given")
    enc_key = signer_dir / "spp-secureboot-1.key"
    pass_file = signer_dir / "spp-secureboot-1.pass"
    cert = signer_dir / "spp-secureboot-1-cert.pem"
    if not (enc_key.exists() and pass_file.exists() and cert.exists()):
        raise SystemExit(f"signer files missing in {signer_dir}")
    # sbsign cannot prompt: decrypt into the work dir (0600); main() deletes it after signing.
    key = work / "signer.key"
    key.unlink(missing_ok=True)
    spp_disk.run(["/usr/bin/openssl", "pkey", "-in", str(enc_key), "-passin", f"file:{pass_file}",
                  "-out", str(key)], cwd=work)
    key.chmod(0o600)
    return key, cert, pass_file


def build_uki(
    work: Path,
    cmdline: Path,
    initramfs: Path,
    key: Path,
    cert_pem: Path,
    paths: dict[str, Path],
    *,
    build_epoch: int = BUILD_EPOCH,
    kernel_release: str = KERNEL_RELEASE,
) -> Path:
    initramfs_gz = work / "initramfs.cpio.gz"
    res = spp_disk.run(
        offline(["gzip", "-9", "-n", "-c", str(initramfs)]),
        cwd=work,
        env={"PATH": "/usr/bin:/bin"},
    )
    initramfs_gz.write_bytes(res.stdout)
    initramfs = initramfs_gz

    pefile_root = work / "pefile-root"
    spp_disk.run(
        offline(["dpkg-deb", "-x", str(paths["PEFILE_DEB"]), str(pefile_root)]),
        cwd=work,
    )

    os_release = work / "os-release"
    os_release.write_text("ID=spp-r1\nNAME=SPP R1 sealed image\nVERSION_ID=1\n")

    unsigned = work / "r1-unsigned.efi"
    signed = work / "r1.efi"
    env = {
        "PATH": "/usr/bin:/usr/sbin:/bin:/sbin",
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "PYTHONPATH": str(pefile_root / "usr/lib/python3/dist-packages"),
        "SOURCE_DATE_EPOCH": str(build_epoch),
    }

    spp_disk.run(
        offline(
            [
                sys.executable,
                str(paths["UKIFY"]),
                "build",
                "--linux",
                str(paths["KERNEL_BZIMAGE"]),
                "--initrd",
                str(initramfs),
                "--cmdline",
                "@" + str(cmdline),
                "--os-release",
                "@" + str(os_release),
                "--uname",
                kernel_release,
                "--stub",
                str(paths["STUB"]),
                "--output",
                str(unsigned),
            ]
        ),
        cwd=work,
        env=env,
    )

    spp_disk.run(
        offline(
            [
                "/usr/bin/sbsign",
                "--key",
                str(key),
                "--cert",
                str(cert_pem),
                "--output",
                str(signed),
                str(unsigned),
            ]
        ),
        cwd=work,
        env={"PATH": "/usr/bin:/bin"},
    )
    spp_disk.run(
        offline(["/usr/bin/sbverify", "--cert", str(cert_pem), str(signed)]),
        cwd=work,
    )
    signed.chmod(0o444)
    return signed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SPP sealed appliance build recipe")
    parser.add_argument(
        "--stage",
        choices=("1a", "1b", "2h", "prod"),
        default="1a",
        help="Appliance stage to build",
    )
    parser.add_argument(
        "--workspace",
        type=Path,
        default=None,
        help="Path to workspace with staged inputs",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=None,
        help="Path to input manifest JSON (defaults to appliance/input-manifest.json)",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Reuse existing rootfs.img if present",
    )
    parser.add_argument(
        "--signer-dir",
        type=Path,
        default=None,
        help="Directory holding the Secure Boot signer (key, passphrase, certificate)",
    )
    parser.add_argument(
        "--work",
        type=Path,
        default=None,
        help="Build output directory (default WORKSPACE/r1-build/work-STAGE)",
    )
    parser.add_argument(
        "--ephemeral-signer",
        action="store_true",
        help="Use ephemeral RSA key instead of vault signer",
    )
    args = parser.parse_args(argv)
    # Directory and file modes in the image must not depend on the builder's umask.
    os.umask(0o022)

    stage = args.stage
    ws = (
        args.workspace
        or (Path(os.environ["SPP_APPLIANCE_WORKSPACE"]) if "SPP_APPLIANCE_WORKSPACE" in os.environ else None)
        or (Path.cwd() / "spp-appliance-workspace")
    )
    manifest_path = args.manifest or (REPO / "appliance/input-manifest.json")
    work = args.work or (ws / "r1-build" / f"work-{stage}")
    work.mkdir(parents=True, exist_ok=True)
    (work / "generated").mkdir(parents=True, exist_ok=True)
    (work / "evidence").mkdir(parents=True, exist_ok=True)

    run_id = f"spp-r1-260906-{stage}"
    cmd_prefix = offline([])

    # Verify input manifest
    if not manifest_path.exists():
        raise SystemExit(f"manifest {manifest_path} does not exist")
    manifest_raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    paths = verify_inputs(manifest_raw, stage, ws)

    # Write verified input manifest
    manifest_raw["status"] = "verified"
    (work / "input-manifest.json").write_text(canonical_dumps(manifest_raw))

    # Verify clean git repo
    git_head = require_clean_repo(REPO)

    if not args.ephemeral_signer and args.signer_dir is None:
        raise SystemExit("--signer-dir is required unless --ephemeral-signer is given")

    # Compile handoff init
    init_bin = compile_r1_init(work)

    # Assemble Rootfs
    origins: list[dict[str, object]] = []
    if stage == "1a":
        marker_bin = compile_marker(work)
        tree = build_rootfs_tree(work, marker_bin)
        rootfs = spp_disk.build_rootfs(work, tree, build_epoch=BUILD_EPOCH, command_prefix=cmd_prefix)
    elif stage == "1b":
        tree = assemble_rootfs_1b(work, paths)
        rootfs = build_squashfs_1b(work, tree, build_epoch=BUILD_EPOCH, resume=args.resume, command_prefix=cmd_prefix)
    elif stage == "2h":
        tree = assemble_rootfs_2h(work, paths)
        rootfs = build_squashfs_1b(work, tree, build_epoch=BUILD_EPOCH, resume=args.resume, command_prefix=cmd_prefix)
    elif stage == "prod":
        tree, origins = assemble_rootfs_prod(work, paths)
        rootfs = build_squashfs_1b(work, tree, build_epoch=BUILD_EPOCH, resume=args.resume, command_prefix=cmd_prefix)
    else:
        raise SystemExit(f"unknown stage {stage}")

    # Verity
    verity, _, root_hash = spp_disk.build_verity(work, rootfs, run_id=run_id, command_prefix=cmd_prefix)

    # Initramfs
    initramfs = build_initramfs_r1(work, init_bin, paths, build_epoch=BUILD_EPOCH)

    # For prod stage: emit origins & SBOM outside rootfs
    if stage == "prod":
        (work / "image-origins.json").write_text(canonical_dumps(origins))
        boot_meta = {
            "stub": paths["STUB"],
            "kernel_bzimage": paths["KERNEL_BZIMAGE"],
            "initrd": initramfs,
            "kernel_release": KERNEL_RELEASE,
            "ukify": paths["UKIFY"],
        }
        sbom_doc = generate_image_sbom(tree, origins, boot_meta, build_epoch=BUILD_EPOCH)
        (work / "image-sbom.json").write_text(canonical_dumps(sbom_doc))
        check_image_sbom(tree, sbom_doc)

    # UUIDs
    import uuid

    partuuids = {
        name: str(uuid.uuid5(uuid.NAMESPACE_URL, f"{run_id}:{name}"))
        for name in ("esp", "root", "verity", "binding")
    }
    disk_guid = str(uuid.uuid5(uuid.NAMESPACE_URL, f"{run_id}:disk"))

    # Cmdline & UKI
    cmdline = build_cmdline(
        work,
        partuuids["root"],
        partuuids["verity"],
        partuuids["binding"],
        root_hash,
        stage=stage,
    )
    # The decrypted production key exists only for the signing step, whatever happens in it.
    key, cert_pem, _ = generate_signer(work, ephemeral=args.ephemeral_signer, signer_dir=args.signer_dir)
    try:
        uki = build_uki(
            work,
            cmdline,
            initramfs,
            key,
            cert_pem,
            paths,
            build_epoch=BUILD_EPOCH,
            kernel_release=KERNEL_RELEASE,
        )
    finally:
        if not args.ephemeral_signer:
            key.unlink(missing_ok=True)

    # Synthetic binding
    binding = (
        b"SPP-R1-BINDING-V1\0"
        + bytes.fromhex(root_hash)
        + bytes.fromhex(spp_disk.sha256_file(uki))
    )
    binding += b"\0" * (1024 * 1024 - len(binding))

    # Assemble Disk
    if stage == "1a":
        vhd, layout = spp_disk.build_disk(
            work,
            uki,
            rootfs,
            verity,
            binding,
            partuuids,
            disk_guid,
            mtools_root=paths["MTOOLS_ROOT"],
            run_id=run_id,
            build_epoch=BUILD_EPOCH,
            command_prefix=cmd_prefix,
        )
    else:
        vhd, layout = build_disk_r1(
            work,
            uki,
            rootfs,
            verity,
            binding,
            partuuids,
            disk_guid,
            mtools_root=paths["MTOOLS_ROOT"],
            run_id=run_id,
            build_epoch=BUILD_EPOCH,
            command_prefix=cmd_prefix,
        )

    # Certificate DER sha256
    cert_res = subprocess.run(
        ["/usr/bin/openssl", "x509", "-in", str(cert_pem), "-outform", "DER"],
        capture_output=True,
        check=True,
    )
    cert_der_sha = spp_disk.sha256_bytes(cert_res.stdout)

    manifest = {
        "schema": "sol-spp-r1-build/v1",
        "stage": stage,
        "run_id": run_id,
        "git_head": git_head,
        "git_status_porcelain": "",
        "kernel_release": KERNEL_RELEASE,
        "kernel_bzimage_sha256": spp_disk.sha256_file(paths["KERNEL_BZIMAGE"]),
        "artifact_state": "diagnostic_unqualified",
        "root_hash": root_hash,
        "cmdline": cmdline.read_text(encoding="ascii").strip(),
        "cmdline_sha256": spp_disk.sha256_file(cmdline),
        "signer_cert_der_sha256": cert_der_sha,
        "uki_sha256": spp_disk.sha256_file(uki),
        "uki_size": uki.stat().st_size,
        "rootfs_sha256": spp_disk.sha256_file(rootfs),
        "verity_sha256": spp_disk.sha256_file(verity),
        "initramfs_sha256": spp_disk.sha256_file(initramfs),
        "vhd": {
            "path": str(vhd.relative_to(ws)),
            "virtual_size_bytes": layout["virtual_size_bytes"],
            "vhd_size_bytes": layout["vhd_size_bytes"],
            "footer_sha256": layout["footer_sha256"],
            "disk_guid": layout["disk_guid"],
            "partitions": layout["partitions"],
        },
        "partuuids": partuuids,
    }

    manifest_file = work / "build-manifest.json"
    manifest_file.write_text(canonical_dumps(manifest))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
