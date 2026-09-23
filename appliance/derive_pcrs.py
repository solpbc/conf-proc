#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Derive the SPP appliance's application PCRs from its published build outputs.

Nothing here reads a running machine. From the signed UKI (and the machine-id the recipe bakes)
this computes the SHA-256 bank values of the registers the image itself determines, and, given a
quote's PCR file, prints them beside the quoted values:

  PCR 4   firmware: "Calling EFI Application from Boot Option", separator, the UKI's Authenticode
          digest (a second candidate adds the embedded kernel's, for a stub that LoadImage()s it)
  PCR 9   the Linux EFI stub: its LoadOptions (the command line as NUL-terminated UTF-16LE), then
          the initrd (tagged event "Linux initrd")
  PCR 11  systemd-stub's UKI section measurements plus systemd-pcrphase's boot-phase words,
          computed by systemd-measure for each phase the quote could have been taken in
  PCR 12, 13, 14   zero: no credentials, system extensions or shim
  PCR 15  systemd-pcrmachine's "machine-id:<id>"

PCRs 0, 2 and 7 are the platform's (firmware, option ROMs, Secure Boot policy): vendor-vouched,
not recomputable from the image, and reported only as quoted. 8, 16 and 23 are expected zero and
22 all-FF.

Usage:
  derive_pcrs.py quote QUOTE_PCRS                     print a quote's registers as JSON
  derive_pcrs.py derive --uki UKI --pefile-path DIR [--machine-id ID] [--quote QUOTE_PCRS]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ZERO = bytes(32)
SEPARATOR = hashlib.sha256(b"\0\0\0\0").digest()
CALLING_EFI_APP = hashlib.sha256(b"Calling EFI Application from Boot Option").digest()
MACHINE_ID = "00000000000000000000000000000001"
# systemd-measure --phase takes one phase path; these are the points a quote can be taken at once
# the rootfs's systemd is running (the initrd here is not systemd's, so it measures no phases).
PHASE_PATHS = ("", "sysinit", "sysinit:ready")


def extend(value: bytes, digest: bytes) -> bytes:
    return hashlib.sha256(value + digest).digest()


def chain(*digests: bytes) -> bytes:
    value = ZERO
    for digest in digests:
        value = extend(value, digest)
    return value


def parse_quote_pcrs(data: bytes) -> dict[int, str]:
    """tpm2_quote -o: a fixed 8-slot TPML_PCR_SELECTION, then 8-slot TPML_DIGEST lists."""
    off = 0

    def take(n: int) -> bytes:
        nonlocal off
        if off + n > len(data):
            raise SystemExit("truncated PCR file")
        chunk = data[off:off + n]
        off += n
        return chunk

    count = struct.unpack("<I", take(4))[0]
    selected: list[int] = []
    for slot in range(8):
        alg, size = struct.unpack("<HB", take(3))
        select = take(8)
        take(5)
        if slot >= count:
            continue
        if alg != 0x000B:
            raise SystemExit("PCR file is not the SHA-256 bank")
        for byte_index in range(size):
            for bit in range(8):
                if select[byte_index] >> bit & 1:
                    selected.append(byte_index * 8 + bit)
    digests: list[bytes] = []
    for _ in range(struct.unpack("<I", take(4))[0]):
        n = struct.unpack("<I", take(4))[0]
        for index in range(8):
            size = struct.unpack("<H", take(2))[0]
            buffer = take(64)
            if index < n:
                digests.append(buffer[:size])
    if off != len(data) or len(digests) != len(selected):
        raise SystemExit("PCR file does not parse cleanly")
    return {pcr: digest.hex() for pcr, digest in zip(sorted(selected), digests)}


def authenticode(pe_bytes: bytes, pefile) -> bytes:
    pe = pefile.PE(data=pe_bytes, fast_load=True)
    checksum_off = pe.OPTIONAL_HEADER.get_file_offset() + 64
    security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
    security_dir_off = security.get_file_offset()
    header_end = pe.OPTIONAL_HEADER.SizeOfHeaders
    h = hashlib.sha256()
    h.update(pe_bytes[:checksum_off])
    h.update(pe_bytes[checksum_off + 4:security_dir_off])
    h.update(pe_bytes[security_dir_off + 8:header_end])
    hashed = header_end
    for section in sorted(pe.sections, key=lambda s: s.PointerToRawData):
        if section.SizeOfRawData == 0:
            continue
        start = section.PointerToRawData
        h.update(pe_bytes[start:start + section.SizeOfRawData])
        hashed = max(hashed, start + section.SizeOfRawData)
    cert_off, cert_size = security.VirtualAddress, security.Size
    tail_end = cert_off if cert_size else len(pe_bytes)
    if tail_end > hashed:
        h.update(pe_bytes[hashed:tail_end])
    return h.digest()


def uki_sections(uki: bytes, pefile) -> dict[str, bytes]:
    pe = pefile.PE(data=uki, fast_load=True)
    out = {}
    for section in pe.sections:
        name = section.Name.rstrip(b"\0").decode("ascii")
        out[name] = section.get_data()[: section.Misc_VirtualSize]
    return out


def pcr11(sections: dict[str, bytes]) -> dict[str, str]:
    flags = {".linux": "linux", ".osrel": "osrel", ".cmdline": "cmdline", ".initrd": "initrd",
             ".uname": "uname", ".sbat": "sbat", ".splash": "splash", ".dtb": "dtb",
             ".pcrpkey": "pcrpkey"}
    values = {}
    with tempfile.TemporaryDirectory() as temp:
        args = []
        for name, flag in flags.items():
            if name in sections:
                path = Path(temp) / flag
                path.write_bytes(sections[name])
                args.append(f"--{flag}={path}")
        for phase in PHASE_PATHS:
            cmd = ["/usr/lib/systemd/systemd-measure", "calculate", "--bank=sha256", "--json=short", *args]
            if phase:
                cmd.append(f"--phase={phase}")
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            entries = json.loads(result.stdout)["sha256"]
            values[phase or "(no phase)"] = next(e["hash"] for e in entries if e["pcr"] == 11)
    return values


def derive(uki_path: Path, pefile, machine_id: str) -> dict[str, object]:
    uki = uki_path.read_bytes()
    sections = uki_sections(uki, pefile)
    kernel = sections[".linux"]
    initrd = sections[".initrd"]
    cmdline = sections[".cmdline"].rstrip(b"\0").decode("ascii")
    uki_hash = authenticode(uki, pefile)
    kernel_hash = authenticode(kernel, pefile)
    initrd_tag = hashlib.sha256(initrd).digest()
    utf16 = cmdline.encode("utf-16-le")
    candidates: dict[str, dict[str, str]] = {
        "4": {
            "uki": chain(CALLING_EFI_APP, SEPARATOR, uki_hash).hex(),
            "uki+kernel": chain(CALLING_EFI_APP, SEPARATOR, uki_hash, kernel_hash).hex(),
        },
        "9": {
            "initrd": chain(initrd_tag).hex(),
            "initrd+options": chain(initrd_tag, hashlib.sha256(utf16).digest()).hex(),
            "initrd+options-nul": chain(initrd_tag, hashlib.sha256(utf16 + b"\0\0").digest()).hex(),
            "options+initrd": chain(hashlib.sha256(utf16).digest(), initrd_tag).hex(),
            "options-nul+initrd": chain(hashlib.sha256(utf16 + b"\0\0").digest(), initrd_tag).hex(),
        },
        "11": pcr11(sections),
        "12": {"zero": ZERO.hex()},
        "13": {"zero": ZERO.hex()},
        "14": {"zero": ZERO.hex()},
        "15": {"machine-id": chain(hashlib.sha256(f"machine-id:{machine_id}".encode()).digest()).hex()},
    }
    # One expected value per register: the measurement conventions the qualification H100 exhibits
    # (firmware measures the UKI alone; the kernel measures its NUL-terminated UTF-16 load options
    # before the initrd; quotes are taken at sysinit:ready). The other candidates stay for
    # diagnosing a platform or stub that measures differently.
    expected = {"4": candidates["4"]["uki"], "9": candidates["9"]["options-nul+initrd"],
                "11": candidates["11"]["sysinit:ready"], "12": ZERO.hex(), "13": ZERO.hex(),
                "14": ZERO.hex(), "15": candidates["15"]["machine-id"]}
    return {
        "expected": expected,
        "uki_sha256": hashlib.sha256(uki).hexdigest(),
        "uki_authenticode_sha256": uki_hash.hex(),
        "kernel_authenticode_sha256": kernel_hash.hex(),
        "initrd_sha256": initrd_tag.hex(),
        "cmdline": cmdline,
        "candidates": candidates,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)
    q = sub.add_parser("quote")
    q.add_argument("quote_pcrs", type=Path)
    d = sub.add_parser("derive")
    d.add_argument("--uki", type=Path, required=True)
    d.add_argument("--pefile-path", type=Path, required=True,
                   help="directory holding the pefile package (the recipe's pinned python3-pefile deb)")
    d.add_argument("--machine-id", default=MACHINE_ID)
    d.add_argument("--quote", type=Path, help="a quote's PCR file (tpm2_quote -o) to compare against")
    a = ap.parse_args(argv)
    if a.command == "quote":
        print(json.dumps(parse_quote_pcrs(a.quote_pcrs.read_bytes()), indent=1, sort_keys=True))
        return 0
    sys.path.insert(0, str(a.pefile_path))
    import pefile  # noqa: E402

    result = derive(a.uki, pefile, a.machine_id)
    if a.quote:
        quoted = parse_quote_pcrs(a.quote.read_bytes())
        table = {}
        for pcr in sorted(quoted):
            want = result["expected"].get(str(pcr))
            if want is None:
                kind = "unused (zero or all-FF expected)" if pcr in (8, 16, 22, 23) else "platform (vendor-vouched)"
                table[pcr] = {"quoted": quoted[pcr], "derived": kind}
                continue
            other = [label for label, value in result["candidates"][str(pcr)].items() if value == quoted[pcr]]
            table[pcr] = {"quoted": quoted[pcr], "expected": want, "match": want == quoted[pcr],
                          "candidate_matching": other[0] if other else None}
        result["match"] = table
        result["all_derived_match"] = all(r.get("match") for r in table.values() if "expected" in r)
    print(json.dumps(result, indent=1, sort_keys=True))
    return 0 if result.get("all_derived_match", True) else 1


if __name__ == "__main__":
    raise SystemExit(main())
