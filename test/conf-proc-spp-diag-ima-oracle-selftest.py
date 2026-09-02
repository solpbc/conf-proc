# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc

"""Independent literal oracle for canonical IMA/PCR10 frozen measurements."""

import ast
import hashlib
from pathlib import Path

from conf_proc_spp_diag_ima_fixture import MEASUREMENTS_HEX


ENTRY_OFFSETS = (0, 101, 470, 602, 973, 1072, 1444)
ARITIES = (2, 3, 3, 3, 2, 3)
ENTRY_PCR_INDEXES = (10, 10, 10, 10, 8, 10)
ENTRY_TEMPLATE_NAMES = (
    b"ima-ng",
    b"ima-buf",
    b"ima-buf",
    b"ima-buf",
    b"ima-ng",
    b"ima-buf",
)
ENTRY_TEMPLATE_DATA_SHA1 = (
    "9483456e2b964a400d81afb44af71ef006bac4c2",
    "34dde991603b58af6b72539d922eb4e0298a817d",
    "e3d02dbc6e07a10179ba4e7511ebc21f60ef688e",
    "23ee0205a73148bdfea17036b3001f466c7a8f68",
    "54c9ce5a0b34b4e767e89ae479db1e05715c2896",
    "bb702a8e823e96f5c245e526386e95be546276ba",
)
ENTRY_TEMPLATE_DATA_SHA256 = (
    "d114f6756a02c9b43463e615af5fd0cb83e264cefcd666dd830bd389390a5603",
    "38d0550647e1888da3aa1a7b3508fdb67bc21a2ec21ed590fc41220ff08059e0",
    "51c97a37a61ce09ab11ab0da513335c5f82496d73ef71e697ae74033adea6e87",
    "8d4d423cccf785a93c3eceaf599b53bbe9fc3b23abeae1b3a55942c6f51baf71",
    "8514127d84ab224ffc6fccba2de7b8dda95a07e7b17032de7615fedcf86928e0",
    "7e62b6562262a3881e4b52d29c4df8abbc0168a40a438b8570414bb103c8f3d2",
)
IMA_BUF_BUF_SHA256 = (
    "be41bcdc76b1e0bedfd2d0bbd473650003d919029d4b57123482c1665357e5a6",
    "a0cfdba84584684dd0f2e6ef81fb6c9775547704691788767cc39ec4f89b095d",
    "c6c62fefb6ed72b5f6ba5b9fd3934aad846a831a5583e063d2db4c3fac90f993",
    "0b7427b0c010420f4eae58369ee85641bff45f156f64fe622510d547c5e5b94d",
)
CHECKPOINT_EVENT_NAMES = (
    b"sol-spp-diag-ready-v1",
    b"sol-spp-diag-release-v1",
    b"sol-spp-diag-terminal-v1",
)
CHECKPOINT_ENTRY_INDEXES = (1, 3, 5)
CHECKPOINT_RECORD_HEX = (
    "535050494d4131000001000100000100000200010001000091a8e826012fbb1c7f5cb2a326c08b13e390f469101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f00000000000000030000000000000174f55fef3952cbb08d09d7638b1b443a153a2cae96070a3dcc14563e7b2b3ac1a3000000000000ffff00000000000000010000000000000000000000000000000000000000",
    "535050494d4131000001000200000100000200010002000091a8e826012fbb1c7f5cb2a326c08b13e390f469101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f000000000000000400000000000001b4116bb4e027092b063e76c123a086b988a99292f0143ebde85700156169f5c44b000000000000ffff00000000000000010000000000000000000000000000000000000000",
    "535050494d4131000001000300000100000200010003000091a8e826012fbb1c7f5cb2a326c08b13e390f469101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f0000000000000007000000000000026af44a36acfd9093ce3be4050a52da2137a4f2d1af8a33d9d021f263f4938139d9000000000000ffff00000000000000010000000000000001000000000000000000000000",
)
PCR10_STEPS = (
    (
        "boot_aggregate",
        "d114f6756a02c9b43463e615af5fd0cb83e264cefcd666dd830bd389390a5603",
        "78ac647afcd4814b94b229a2e69e98147ab678cbb9de9e18c3d75c78c80d1158",
    ),
    (
        "spp_ready",
        "38d0550647e1888da3aa1a7b3508fdb67bc21a2ec21ed590fc41220ff08059e0",
        "de83b7264d697e89bae3055cf75f273824b3972810b593d366ddfaebc5324e7c",
    ),
    (
        "other_critical",
        "51c97a37a61ce09ab11ab0da513335c5f82496d73ef71e697ae74033adea6e87",
        "93e7dd1e06798778ef1fe1257310889df3b6d3616ca0d83de5174fa77f927021",
    ),
    (
        "spp_release",
        "8d4d423cccf785a93c3eceaf599b53bbe9fc3b23abeae1b3a55942c6f51baf71",
        "a1bac83997a955dfdb3ebe370f68d16c92c9e9e9a2c44e19d3934455026189ef",
    ),
    (
        "spp_terminal",
        "7e62b6562262a3881e4b52d29c4df8abbc0168a40a438b8570414bb103c8f3d2",
        "58968e73503de06451b84da4e3da33d0df32bebde105e74e4ce5341fbde00e4e",
    ),
)
FINAL_PCR10_SHA256 = "58968e73503de06451b84da4e3da33d0df32bebde105e74e4ce5341fbde00e4e"
MEASUREMENTS_SHA256 = "2a0141be84e886a488303fef8d1882df10ab9b67f15d7d0d0c5eb1894d076045"


def _u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def _fields(data: bytes) -> tuple[bytes, ...]:
    fields = []
    offset = 0
    while offset < len(data):
        size = _u32(data, offset)
        offset += 4
        fields.append(data[offset : offset + size])
        offset += size
    return tuple(fields)


def _parse_entries(raw: bytes):
    entries = []
    offset = 0
    while offset < len(raw):
        start = offset
        pcr_index = _u32(raw, offset)
        offset += 4
        stored = raw[offset : offset + 20]
        offset += 20
        name_length = _u32(raw, offset)
        offset += 4
        name = raw[offset : offset + name_length]
        offset += name_length
        data_length = _u32(raw, offset)
        offset += 4
        data = raw[offset : offset + data_length]
        offset += data_length
        entries.append((start, offset, pcr_index, stored, name, data))
    return entries, offset


def _static_independence() -> None:
    here = Path(__file__)
    source = here.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = set()
    fixture_names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.add(node.module or "")
            if node.module == "conf_proc_spp_diag_ima_fixture":
                fixture_names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in {
                "__import__",
                "eval",
                "exec",
                "open",
            }:
                raise AssertionError("dynamic or write-capable oracle call")
            if isinstance(node.func, ast.Attribute) and node.func.attr in {
                "open",
                "read_bytes",
                "write_bytes",
                "write_text",
                "glob",
                "rglob",
                "iterdir",
            }:
                raise AssertionError("write-capable oracle call")
    if imports != {
        "ast",
        "hashlib",
        "pathlib",
        "conf_proc_spp_diag_ima_fixture",
    }:
        raise AssertionError(f"oracle import set changed: {sorted(imports)!r}")
    if fixture_names != {"MEASUREMENTS_HEX"}:
        raise AssertionError(f"oracle fixture names changed: {sorted(fixture_names)!r}")
    forbidden = (
        "sub" + "process",
        "ct" + "ypes",
        "conf_proc_spp_diag_ima" + ".py",
        "conf_proc_spp_diag_ima_" + "reasons",
        "replay_spp_diag_" + "ima_pcr10",
        "SppDiagIma" + "Error",
        "SppDiagIma" + "Replay",
    )
    if any(token in source for token in forbidden):
        raise AssertionError("oracle reached forbidden authority")

    fixture_path = here.with_name("conf_proc_spp_diag_ima_fixture.py")
    fixture_source = fixture_path.read_text(encoding="utf-8")
    fixture_tree = ast.parse(fixture_source)
    if any(
        isinstance(node, (ast.Import, ast.ImportFrom, ast.Call))
        for node in ast.walk(fixture_tree)
    ):
        raise AssertionError("fixture authority is not literal-only")


def _check_entries(raw: bytes) -> None:
    entries, end = _parse_entries(raw)
    assert end == len(raw) == 1444
    assert tuple(item[0] for item in entries) + (end,) == ENTRY_OFFSETS
    assert len(entries) == 6
    buf_hashes = []
    checkpoints = []
    pcr = bytes(32)
    steps = []
    for index, (start, stop, pcr_index, stored, name, data) in enumerate(entries):
        assert start == ENTRY_OFFSETS[index]
        assert stop == ENTRY_OFFSETS[index + 1]
        assert pcr_index == ENTRY_PCR_INDEXES[index]
        assert name == ENTRY_TEMPLATE_NAMES[index]
        assert stored.hex() == ENTRY_TEMPLATE_DATA_SHA1[index]
        assert hashlib.sha1(data).hexdigest() == ENTRY_TEMPLATE_DATA_SHA1[index]
        assert hashlib.sha256(data).hexdigest() == ENTRY_TEMPLATE_DATA_SHA256[index]
        fields = _fields(data)
        assert len(fields) == ARITIES[index]
        if name == b"ima-buf":
            buf_hashes.append(hashlib.sha256(fields[2]).hexdigest())
            event_name = fields[1][:-1]
            if event_name in CHECKPOINT_EVENT_NAMES:
                checkpoints.append((event_name, fields[2], index))
        event_digest = hashlib.sha256(data).digest()
        if pcr_index == 10:
            pcr = hashlib.sha256(pcr + event_digest).digest()
            steps.append((event_digest.hex(), pcr.hex()))
        else:
            assert index == 4 and pcr_index == 8
    assert tuple(buf_hashes) == IMA_BUF_BUF_SHA256
    assert tuple(item[0] for item in checkpoints) == CHECKPOINT_EVENT_NAMES
    assert tuple(item[2] for item in checkpoints) == CHECKPOINT_ENTRY_INDEXES
    assert tuple(item[1].hex() for item in checkpoints) == CHECKPOINT_RECORD_HEX
    assert len(steps) == 5
    for computed, expected in zip(steps, PCR10_STEPS):
        assert computed[0] == expected[1]
        assert computed[1] == expected[2]
    assert pcr.hex() == FINAL_PCR10_SHA256
    # Criterion 1: every expected value above is a literal in this file and is
    # recomputed from MEASUREMENTS_HEX only; other fixture names are not imported.


def main() -> None:
    _static_independence()
    raw = bytes.fromhex(MEASUREMENTS_HEX)
    assert len(raw) == 1444
    assert hashlib.sha256(raw).hexdigest() == MEASUREMENTS_SHA256
    _check_entries(raw)
    flipped = bytearray(raw)
    flipped[4] ^= 1
    assert hashlib.sha256(flipped).hexdigest() != MEASUREMENTS_SHA256
    truncated = raw[:-1]
    assert hashlib.sha256(truncated).hexdigest() != MEASUREMENTS_SHA256
    mutated_data = bytearray(raw)
    mutated_data[ENTRY_OFFSETS[0] + 38] ^= 1
    first = bytes(mutated_data[ENTRY_OFFSETS[0] + 38 : ENTRY_OFFSETS[1]])
    event = hashlib.sha256(first).digest()
    step = hashlib.sha256(bytes(32) + event).hexdigest()
    assert event.hex() != PCR10_STEPS[0][1]
    assert step != PCR10_STEPS[0][2]
    print("spp diagnostic canonical IMA/PCR10 frozen oracle: ok")


if __name__ == "__main__":
    main()
