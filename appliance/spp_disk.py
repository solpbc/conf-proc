#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Low-level disk, filesystem, and image helpers for SPP appliance recipes."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import uuid
from typing import Final

BUILD_EPOCH: Final = 1788652800


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def write_bytes(path: Path, data: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        handle.write(data)
    path.chmod(mode)


def run(
    argv: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
    command_prefix: list[str] | tuple[str, ...] = (),
) -> subprocess.CompletedProcess[bytes]:
    full_argv = list(command_prefix) + argv
    completed = subprocess.run(full_argv, cwd=cwd, env=env, capture_output=True)
    if completed.returncode != 0:
        raise RuntimeError(
            f"command failed (status {completed.returncode}): {full_argv!r}\n"
            f"stdout:\n{completed.stdout.decode('utf-8', errors='replace')}\n"
            f"stderr:\n{completed.stderr.decode('utf-8', errors='replace')}"
        )
    return completed


def align(value: int, quantum: int) -> int:
    return (value + quantum - 1) // quantum * quantum


def vhd_geometry(size_bytes: int) -> tuple[int, int, int]:
    total = min(size_bytes // 512, 65535 * 16 * 255)
    if total >= 65535 * 16 * 63:
        sectors, heads, cylinder_heads = 255, 16, total // 255
    else:
        sectors = 17
        cylinder_heads = total // sectors
        heads = max(4, (cylinder_heads + 1023) // 1024)
        if cylinder_heads >= heads * 1024 or heads > 16:
            sectors, heads, cylinder_heads = 31, 16, total // 31
        if cylinder_heads >= heads * 1024:
            sectors, heads, cylinder_heads = 63, 16, total // 63
    return cylinder_heads // heads, heads, sectors


def verity_salt(run_id: str) -> str:
    return sha256_bytes(b"sol-spp-phase1b-verity-salt-v1\0" + run_id.encode("ascii"))


def verity_uuid(run_id: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, run_id + ":verity"))


def fixed_vhd_uuid(run_id: str) -> uuid.UUID:
    return uuid.uuid5(uuid.NAMESPACE_URL, run_id + ":fixed-vhd")


def vhd_footer(
    size_bytes: int, *, build_epoch: int = BUILD_EPOCH, run_id: str
) -> bytes:
    cylinders, heads, sectors = vhd_geometry(size_bytes)
    footer = bytearray(512)
    footer[0:8] = b"conectix"
    struct.pack_into(">I", footer, 8, 2)
    struct.pack_into(">I", footer, 12, 0x00010000)
    struct.pack_into(">Q", footer, 16, 0xFFFFFFFFFFFFFFFF)
    struct.pack_into(">I", footer, 24, build_epoch - 946684800)
    footer[28:32] = b"solp"
    struct.pack_into(">I", footer, 32, 0x00010000)
    footer[36:40] = b"Wi2k"
    struct.pack_into(">Q", footer, 40, size_bytes)
    struct.pack_into(">Q", footer, 48, size_bytes)
    struct.pack_into(">HBB", footer, 56, cylinders, heads, sectors)
    struct.pack_into(">I", footer, 60, 2)
    footer[68:84] = fixed_vhd_uuid(run_id).bytes
    footer[84] = 0
    struct.pack_into(">I", footer, 64, (~sum(footer)) & 0xFFFFFFFF)
    return bytes(footer)


def newc_entry(
    name: str, mode: int, data: bytes, ino: int, *, build_epoch: int = BUILD_EPOCH
) -> bytes:
    name_bytes = name.encode("utf-8") + b"\0"
    fields = (
        ino,
        mode,
        0,
        0,
        2 if stat.S_ISDIR(mode) else 1,
        build_epoch,
        len(data),
        0,
        0,
        0,
        0,
        len(name_bytes),
        0,
    )
    header = b"070701" + b"".join(f"{field:08x}".encode("ascii") for field in fields)
    body = header + name_bytes
    body += b"\0" * (-len(body) % 4)
    body += data
    body += b"\0" * (-len(body) % 4)
    return body


def build_rootfs(
    work: Path,
    runtime_root: Path,
    *,
    build_epoch: int = BUILD_EPOCH,
    command_prefix: list[str] | tuple[str, ...] = (),
) -> Path:
    rootfs = work / "rootfs.img"
    sort_file = work / "generated/squashfs.sort"
    lines = [
        f"{path.relative_to(runtime_root).as_posix()} 0"
        for path in sorted(runtime_root.rglob("*"), key=lambda item: item.as_posix())
        if path.is_file()
    ]
    write_bytes(sort_file, ("\n".join(lines) + "\n").encode("utf-8"))
    run(
        [
            "/usr/bin/mksquashfs",
            str(runtime_root),
            str(rootfs),
            "-noappend",
            "-reproducible",
            "-all-root",
            "-no-xattrs",
            "-no-exports",
            "-no-progress",
            "-comp",
            "zstd",
            "-mkfs-time",
            str(build_epoch),
            "-all-time",
            str(build_epoch),
            "-root-mode",
            "0755",
            "-sort",
            str(sort_file),
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


def build_verity(
    work: Path,
    rootfs: Path,
    *,
    run_id: str,
    command_prefix: list[str] | tuple[str, ...] = (),
) -> tuple[Path, Path, str]:
    verity = work / "rootfs.verity"
    hash_text = work / "generated/verity-root-hash.txt"
    salt = verity_salt(run_id)
    vuuid = verity_uuid(run_id)
    run(
        [
            "/usr/sbin/veritysetup",
            "format",
            str(rootfs),
            str(verity),
            "--hash=sha256",
            "--data-block-size=4096",
            "--hash-block-size=4096",
            f"--salt={salt}",
            f"--uuid={vuuid}",
            f"--root-hash-file={hash_text}",
        ],
        cwd=work,
        env={"PATH": "/usr/bin:/usr/sbin:/bin:/sbin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC"},
        command_prefix=command_prefix,
    )
    root_hash_hex = hash_text.read_text(encoding="ascii").strip()
    if len(root_hash_hex) != 64 or any(
        char not in "0123456789abcdef" for char in root_hash_hex
    ):
        raise RuntimeError("verity root hash is invalid")
    root_hash_bin = work / "verity-root-hash.bin"
    write_bytes(root_hash_bin, bytes.fromhex(root_hash_hex), 0o444)
    verity.chmod(0o444)
    run(
        [
            "/usr/sbin/veritysetup",
            "verify",
            str(rootfs),
            str(verity),
            root_hash_hex,
            "--hash=sha256",
            "--data-block-size=4096",
            "--hash-block-size=4096",
        ],
        cwd=work,
        env={"PATH": "/usr/bin:/usr/sbin:/bin:/sbin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC"},
        command_prefix=command_prefix,
    )
    return verity, root_hash_bin, root_hash_hex


def build_disk(
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
    sizes = {
        "esp": max(64 * mib, align(diagnostic.stat().st_size + 8 * mib, mib)),
        "root": align(rootfs.stat().st_size, mib),
        "verity": align(verity.stat().st_size, mib),
        "binding": mib,
    }
    starts: dict[str, int] = {}
    cursor = mib
    for name in ("esp", "root", "verity", "binding"):
        starts[name] = cursor
        cursor += sizes[name]
    virtual_size = max(1024 * mib, align(cursor + 8 * mib, mib))
    raw = work / "diagnostic.raw"
    with raw.open("xb") as handle:
        handle.truncate(virtual_size)
    command = ["/usr/sbin/sgdisk", "--clear", f"--disk-guid={disk_guid}"]
    typecodes = {"esp": "ef00", "root": "8300", "verity": "8300", "binding": "8300"}
    labels = {
        "esp": "SPP-DIAG-ESP",
        "root": "SPP-DIAG-ROOT",
        "verity": "SPP-DIAG-VERITY",
        "binding": "SPP-DIAG-BINDING",
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
    run(command, cwd=work, command_prefix=command_prefix)
    verify = run(["/usr/sbin/sgdisk", "--verify", "--print", str(raw)], cwd=work, command_prefix=command_prefix)
    write_bytes(work / "evidence/sgdisk-verify.txt", verify.stdout + verify.stderr)
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
    run(
        [str(mtools_root / "mformat"), "-i", str(fat), "-F", "-v", "SPPDIAG", "::"],
        cwd=work,
        env=env,
        command_prefix=command_prefix,
    )
    run(
        [str(mtools_root / "mmd"), "-i", str(fat), "::/EFI", "::/EFI/BOOT"],
        cwd=work,
        env=env,
        command_prefix=command_prefix,
    )
    run(
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
    footer = vhd_footer(virtual_size, build_epoch=build_epoch, run_id=run_id)
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
        "footer_sha256": sha256_bytes(footer),
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
