# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Production partition entries known before the UKI is signed."""
import struct
import uuid

MIB = 1024 * 1024
ESP_BYTES = 64 * MIB
UKI_PAYLOAD_MAX = 56 * MIB
NAMES = ("esp", "root", "verity", "binding")


def geometry(root_bytes: int, verity_bytes: int) -> tuple[dict, dict]:
    if root_bytes <= 0 or verity_bytes <= 0:
        raise ValueError("empty production partition")
    sizes = {"esp": ESP_BYTES, "root": ((root_bytes + MIB - 1) // MIB) * MIB,
             "verity": ((verity_bytes + MIB - 1) // MIB) * MIB, "binding": MIB}
    starts = {}
    cursor = MIB
    for name in NAMES:
        starts[name] = cursor
        cursor += sizes[name]
    return sizes, starts


def entry_array(root_bytes: int, verity_bytes: int, partuuids: dict[str, str]) -> bytes:
    sizes, starts = geometry(root_bytes, verity_bytes)
    entries = bytearray(128 * 128)
    for index, name in enumerate(NAMES):
        type_id = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b" if name == "esp" else "0fc63daf-8483-4772-8e79-3d69d8477de4"
        entry = struct.pack("<16s16sQQQ72s", uuid.UUID(type_id).bytes_le,
                            uuid.UUID(partuuids[name]).bytes_le, starts[name] // 512,
                            (starts[name] + sizes[name]) // 512 - 1, 0,
                            ("SPP-" + name.upper()).encode("utf-16le"))
        entries[index * 128:(index + 1) * 128] = entry
    return bytes(entries)
