#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Fetch a raw SEV-SNP attestation report via /dev/sev-guest (stdlib only).

This is the in-TEE attester half of the ACI Confidential Containers path: the
UVM runs unparavisored at VMPL0 with the native sev-guest ioctl — no vTPM, no
HCL blob (journal/2026-07-04.md). It binds a verifier-supplied nonce (or 64
fresh random bytes) into REPORT_DATA, writes the 1184-byte report, and prints
the fields a verifier appraises plus the whole report as base64 (the practical
extraction channel when the only output path is container logs or a copied
terminal).

Appraise off-TEE with `verifier.py appraise-raw` against pinned AMD roots;
certificates come from THIM (169.254.169.254/metadata/THIM/amd/certification)
or the AMD KDS using CHIP_ID + reported TCB. See the README's ACI section.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import fcntl
import os
import struct
import sys

# _IOWR('S', 0x0, struct snp_guest_request_ioctl) — 32-byte struct
SNP_GET_REPORT = 0xC0205300
REPORT_SIZE = 1184

OFF_REPORT_DATA = 0x050
OFF_MEASUREMENT = 0x090
OFF_HOST_DATA = 0x0C0
OFF_CHIP_ID = 0x1A0


class SnpReportReq(ctypes.Structure):
    _fields_ = [
        ("user_data", ctypes.c_ubyte * 64),
        ("vmpl", ctypes.c_uint32),
        ("rsvd", ctypes.c_ubyte * 28),
    ]


class SnpReportResp(ctypes.Structure):
    _fields_ = [("data", ctypes.c_ubyte * 4000)]


class SnpGuestRequest(ctypes.Structure):
    _fields_ = [
        ("msg_version", ctypes.c_uint8),
        ("req_data", ctypes.c_uint64),
        ("resp_data", ctypes.c_uint64),
        ("fw_err", ctypes.c_uint64),
    ]


def fetch_report(nonce: bytes, vmpl: int, device: str) -> bytes:
    req = SnpReportReq(vmpl=vmpl)
    ctypes.memmove(req.user_data, nonce, 64)
    resp = SnpReportResp()
    greq = SnpGuestRequest(
        msg_version=1,
        req_data=ctypes.addressof(req),
        resp_data=ctypes.addressof(resp),
        fw_err=0,
    )
    fd = os.open(device, os.O_RDWR)
    try:
        fcntl.ioctl(fd, SNP_GET_REPORT, greq)
    finally:
        os.close(fd)
    status, size = struct.unpack_from("<II", bytes(resp.data), 0)
    if status != 0 or size != REPORT_SIZE:
        raise RuntimeError(
            f"SNP_GET_REPORT failed: status={status} size={size} fw_err={greq.fw_err:#x}"
        )
    return bytes(resp.data)[32 : 32 + REPORT_SIZE]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--nonce-hex",
        help="verifier nonce for REPORT_DATA (32 or 64 bytes hex; default: 64 random bytes)",
    )
    parser.add_argument("--vmpl", type=int, default=0)
    parser.add_argument("--device", default="/dev/sev-guest")
    parser.add_argument("--out", default="report.bin", help="where to write the raw report")
    args = parser.parse_args(argv)

    if args.nonce_hex:
        nonce = bytes.fromhex("".join(args.nonce_hex.split()))
        if len(nonce) == 32:
            nonce += b"\x00" * 32
        elif len(nonce) != 64:
            print(f"nonce is {len(nonce)} bytes, expected 32 or 64", file=sys.stderr)
            return 1
    else:
        nonce = os.urandom(64)

    try:
        report = fetch_report(nonce, args.vmpl, args.device)
    except (OSError, RuntimeError) as exc:
        print(f"report fetch failed: {exc}", file=sys.stderr)
        print(
            "expected environment: ACI Confidential Containers "
            "(sku Confidential) exposing /dev/sev-guest",
            file=sys.stderr,
        )
        return 1

    if report[OFF_REPORT_DATA : OFF_REPORT_DATA + 64] != nonce:
        print("REPORT_DATA does not echo the nonce", file=sys.stderr)
        return 1

    with open(args.out, "wb") as fh:
        fh.write(report)

    print(f"NONCE:       {nonce.hex()}")
    print(f"MEASUREMENT: {report[OFF_MEASUREMENT:OFF_HOST_DATA].hex()}")
    print(f"HOST_DATA:   {report[OFF_HOST_DATA:OFF_HOST_DATA + 32].hex()}")
    print(f"CHIP_ID:     {report[OFF_CHIP_ID:OFF_CHIP_ID + 64].hex()}")
    print(f"wrote {args.out} ({REPORT_SIZE} bytes)")
    print(base64.b64encode(report).decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
