#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""AC5 parser for IPv4/IPv6 adapter network facts and red bypass paths."""

from __future__ import annotations

import struct
import subprocess
import sys


def network_payloads(raw: bytes) -> list[bytes]:
    offset, values = 4 + 4 + 192, []
    while offset < len(raw):
        size = int.from_bytes(raw[offset:offset + 4], "big")
        frame = raw[offset + 4:offset + 4 + size]
        event = struct.unpack(">H", frame[:2])[0]
        if event == 0x103:
            values.append(frame[44:])
        offset += 4 + size
    return values


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: runtime-network-oracle-selftest.py FIXTURE")
    fixture = sys.argv[1]
    values = network_payloads(subprocess.check_output([fixture]))
    if len(values) != 2:
        print(f"FAIL expected IPv4 connect and IPv6 sendmsg, got {len(values)}")
        return 1
    connect, sendmsg = values
    if struct.unpack(">HHHH", connect[:8]) != (1, 1, 1, 1):
        print("FAIL IPv4 connect policy shape")
        return 1
    if struct.unpack(">HHHH", sendmsg[:8]) != (2, 2, 2, 1):
        print("FAIL IPv6 explicit sendmsg policy shape")
        return 1
    if int.from_bytes(sendmsg[16:20], "big") != 0xFFFFFFF3:
        print("FAIL sendmsg errno lost its raw two's-complement bits")
        return 1
    if int.from_bytes(sendmsg[24:28], "big") != 0x7FFFFFFF:
        print("FAIL INT_MAX sendmsg size boundary")
        return 1
    if int.from_bytes(sendmsg[40:44], "big") != 0x55667788 or int.from_bytes(sendmsg[44:48], "big") != 0x11223344:
        print("FAIL IPv6 scope/flow byte order")
        return 1
    for mode, kind, family, port, address in (
        ("--tcp4", 1, 2, 443, bytes(12) + bytes((127, 0, 0, 1))),
        ("--tcp6", 2, 10, 53, bytes.fromhex("20010db8000000000000000000000001")),
    ):
        rows = network_payloads(subprocess.check_output([fixture, mode]))
        assert len(rows) == 1
        payload = rows[0]
        assert struct.unpack(">HHHHHHHH", payload[:16]) == (2, 1, kind, 2, 1, 6, family, 0)
        assert int.from_bytes(payload[20:24], "big") == 0x40
        assert int.from_bytes(payload[24:28], "big") == 7
        assert int.from_bytes(payload[28:36], "big") == 1
        assert int.from_bytes(payload[36:38], "big") == port
        assert payload[48:64] == address
    for mode in ("--unsupported", "--connect-unsupported", "--connected",
                 "--oversized", "--bad-family", "--bad-length",
                 "--peer-fail", "--peer-short", "--peer-lost-after-check"):
        red = subprocess.run([fixture, mode], check=False)
        if red.returncode != 42:
            print(f"FAIL {mode} red path exit={red.returncode}")
            return 1
    print("ok   adapter IPv4/IPv6 network facts, INT_MAX, and unsupported bypass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
