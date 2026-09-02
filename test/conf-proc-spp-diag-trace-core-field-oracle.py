#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Independent Cartesian field oracle for the SPP diagnostic kernel trace core."""

from __future__ import annotations

import hashlib
import itertools
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


SOURCE_COMMIT = bytes.fromhex("91a8e826012fbb1c7f5cb2a326c08b13e390f469")
HEADER_DOMAIN = b"sol-spp-diag-trace-header/v1"
FRAME_DOMAIN = b"sol-spp-diag-trace-frame/v1"
WIRE_OK = 0

EVENT_PRE_RELEASE = 2
EVENT_IMA_READY = 3
EVENT_USERSPACE_RELEASE = 4
EVENT_EXEC_ATTEMPT = 5
EVENT_EXEC_COMMIT = 6
EVENT_TASK_ALLOC = 7
EVENT_TASK_CREATED = 8
EVENT_PHASE_MARKER = 9
EVENT_TERMINAL = 10
EVENT_FILE_OPEN = 0x0100
EVENT_FILE_POLICY = 0x0101
EVENT_MAPPING = 0x0102
EVENT_NETWORK = 0x0103
EVENT_OP_RETURN = 0x0104
EVENT_TASK_EXIT = 0x0105

PHASE_PRE_RELEASE = 0
PHASE_INIT = 1
PHASE_COLD_START = 2
PHASE_JIT_CACHE = 13
PHASE_EVIDENCE_FINALIZE = 14
PHASE_SEALED = 15

ACCESS = (1, 2, 3, 4)
MOD_MASK = 0x3F
POLICY_ALLOW = 1
POLICY_DENY = 2
OBJECT_KIND = (1, 2, 3, 4)
MAP_MMAP = 1
MAP_MPROTECT = 2
BACKING = (1, 2, 3, 4)
BACKING_ANON = 1
BACKING_MEMFD = 3
MODE = (1, 2)
PROT_READ = 1
PROT_WRITE = 2
PROT_EXEC = 4
NET_CONNECT = 1
NET_SENDMSG = 2
NET_KIND = (1, 2, 3, 4, 5)
NET_IPV4 = 1
NET_IPV6 = 2
NET_UNSUPPORTED = 3
NET_MALFORMED = 4
NET_UNRESOLVED = 5
NET_EXPLICIT = 1
NET_CONNECTED = 2
NET_FAMILY_INET = 2
NET_FAMILY_INET6 = 10
OP_KIND = (1, 2, 3, 4, 5, 6)

HIGH32 = 0x80000000
ONES32 = 0xFFFFFFFF
HIGH64 = 1 << 63
ONES64 = (1 << 64) - 1


def be(value: int, width: int) -> bytes:
    if value < 0 or value >= 1 << (8 * width):
        raise AssertionError(f"integer {value} does not fit {width} bytes")
    return value.to_bytes(width, "big")


def u16(value: int) -> bytes:
    return be(value, 2)


def u32(value: int) -> bytes:
    return be(value, 4)


def u64(value: int) -> bytes:
    return be(value, 8)


def header(challenge: bytes, run: bytes, control: bytes, cmdline: bytes) -> bytes:
    raw = b"".join(
        (
            b"SPPTRC1\x00",
            be(1, 2),
            be(192, 2),
            be(2, 2),
            be(1, 2),
            be(524288, 4),
            be(268435456, 8),
            be(1088, 4),
            SOURCE_COMMIT,
            challenge,
            run,
            control,
            cmdline,
            be(0xFFFF, 8),
            bytes(4),
        )
    )
    if len(raw) != 192:
        raise AssertionError(f"oracle header is {len(raw)} bytes")
    return raw


def frame(
    event: int,
    flags: int,
    sequence: int,
    task: int,
    parent: int,
    operation: int,
    phase: int,
    payload: bytes,
) -> bytes:
    raw = b"".join(
        (
            be(event, 2),
            be(flags, 2),
            be(len(payload), 4),
            be(sequence, 8),
            be(task, 8),
            be(parent, 8),
            be(operation, 8),
            be(phase, 2),
            bytes(2),
            payload,
        )
    )
    if len(raw) != 44 + len(payload):
        raise AssertionError(f"oracle frame is {len(raw)} bytes")
    return raw


def header_chain_of(encoded_header: bytes) -> bytes:
    return hashlib.sha256(HEADER_DOMAIN + be(192, 4) + encoded_header).digest()


def roll_frame(previous: bytes, encoded_frame: bytes) -> bytes:
    return hashlib.sha256(
        FRAME_DOMAIN + previous + be(len(encoded_frame), 4) + encoded_frame
    ).digest()


def frame_tuple(cell: "Cell") -> str:
    return (
        be(cell.event, 2)
        + be(cell.flags, 2)
        + be(cell.task, 8)
        + be(cell.parent, 8)
        + be(cell.operation, 8)
        + be(cell.phase, 2)
        + cell.payload
    ).hex()


def classify_line(cell: "Cell") -> str:
    payload_hex = cell.payload.hex() if cell.payload else "-"
    return (
        f"{cell.event} {cell.flags} {cell.task} {cell.parent} "
        f"{cell.operation} {cell.phase} {payload_hex}"
    )


def patch(payload: bytes, offset: int, raw: bytes) -> bytes:
    buf = bytearray(payload)
    buf[offset : offset + len(raw)] = raw
    return bytes(buf)


@dataclass
class Cell:
    event: int
    flags: int
    task: int
    parent: int
    operation: int
    phase: int
    payload: bytes
    coords: dict[str, object]
    origin: str = "class"


def make_cell(
    event: int,
    *,
    flags: int = 0,
    task: int = 0,
    parent: int = 0,
    operation: int = 0,
    phase: int = 0,
    payload: bytes = b"",
    **coords: object,
) -> Cell:
    base = {
        "event": event,
        "flags": flags,
        "task": task,
        "parent": parent,
        "operation": operation,
        "phase": phase,
    }
    base.update(coords)
    return Cell(
        event=event,
        flags=flags,
        task=task,
        parent=parent,
        operation=operation,
        phase=phase,
        payload=payload,
        coords=base,
    )


def derive_twin(cell: Cell, coord: str, value: object, **wire: object) -> Cell:
    twin = Cell(
        event=int(wire.get("event", cell.event)),
        flags=int(wire.get("flags", cell.flags)),
        task=int(wire.get("task", cell.task)),
        parent=int(wire.get("parent", cell.parent)),
        operation=int(wire.get("operation", cell.operation)),
        phase=int(wire.get("phase", cell.phase)),
        payload=bytes(wire.get("payload", cell.payload)),
        coords=dict(cell.coords),
        origin="twin",
    )
    twin.coords[coord] = value
    return twin


def coord_diffs(left: Cell, right: Cell) -> list[str]:
    keys = set(left.coords) | set(right.coords)
    return sorted(key for key in keys if left.coords.get(key) != right.coords.get(key))


def payload_pre_release(path: bytes) -> bytes:
    return u16(13) + u16(len(path)) + u32(1) + u32(1) + bytes(8) + path


def payload_exec_attempt(path: bytes) -> bytes:
    return u32(1) + u16(len(path)) + u16(0) + u32(1) + u32(1) + path


def payload_exec_commit() -> bytes:
    return u32(1) + u32(1) + u32(1) + u32(0)


def payload_pid_tgid() -> bytes:
    return u32(1) + u32(1) + bytes(8)


def payload_phase_marker(prev: int) -> bytes:
    return u16(prev) + u16(prev + 1) + u32(0)


def payload_file_open(access: int, modifiers: int, dirfd: int, path: bytes) -> bytes:
    return (
        u16(1)
        + u16(len(path))
        + u16(access)
        + u16(modifiers)
        + u32(dirfd)
        + u32(0)
        + path
    )


def payload_file_policy(
    access: int,
    modifiers: int,
    decision: int,
    kind: int,
    result: int,
    inode: int,
    mount: int,
    observed: int,
) -> bytes:
    return (
        u16(access)
        + u16(modifiers)
        + u16(decision)
        + u16(kind)
        + u32(result)
        + u32(0)
        + u32(0)
        + u32(0)
        + u64(inode)
        + u64(mount)
        + u64(observed)
    )


def payload_mapping(
    operation: int,
    decision: int,
    backing: int,
    mode: int,
    requested: int,
    effective: int,
    prior: int,
    result: int,
    seals: int,
    inode: int,
    mount: int,
    observed: int,
) -> bytes:
    return (
        u16(operation)
        + u16(decision)
        + u16(backing)
        + u16(mode)
        + u32(requested)
        + u32(effective)
        + u32(prior)
        + u32(result)
        + u32(0)
        + u32(0)
        + u32(0)
        + u32(seals)
        + u64(inode)
        + u64(mount)
        + u64(observed)
    )


def network_addr(kind: int) -> bytes:
    if kind == NET_IPV4:
        return bytes(12) + bytes([10, 0, 0, 1])
    if kind == NET_IPV6:
        return bytes([0x20]) + bytes(15)
    return bytes(16)


def payload_network(
    operation: int,
    decision: int,
    kind: int,
    source: int,
    family: int,
    addrlen: int,
    result: int,
    *,
    protocol: int = 0,
    flags: int = 0,
    size: int = 0,
    cookie: int = 1,
    port: int | None = None,
    reserved: int = 0,
    scope: int | None = None,
    flow: int | None = None,
    addr: bytes | None = None,
    socket_kind: int = 1,
) -> bytes:
    if kind == NET_IPV4:
        use_port = 1 if port is None else port
        use_scope = 0 if scope is None else scope
        use_flow = 0 if flow is None else flow
    elif kind == NET_IPV6:
        use_port = 1 if port is None else port
        use_scope = 1 if scope is None else scope
        use_flow = 1 if flow is None else flow
    else:
        use_port = 0 if port is None else port
        use_scope = 0 if scope is None else scope
        use_flow = 0 if flow is None else flow
    use_addr = network_addr(kind) if addr is None else addr
    if len(use_addr) != 16:
        raise AssertionError("network address region must be 16 bytes")
    return (
        u16(operation)
        + u16(decision)
        + u16(kind)
        + u16(source)
        + u16(socket_kind)
        + u16(protocol)
        + u16(family)
        + u16(addrlen)
        + u32(result)
        + u32(flags)
        + u32(size)
        + u64(cookie)
        + u16(use_port)
        + u16(reserved)
        + u32(use_scope)
        + u32(use_flow)
        + use_addr
    )


def payload_op_return(kind: int, raw: int) -> bytes:
    return u16(kind) + u16(0) + u32(0) + u64(raw)


def payload_task_exit(code: int) -> bytes:
    return u32(code) + u32(0)


def policy_result(decision: int) -> int:
    return 0 if decision == POLICY_ALLOW else HIGH32


def mapping_ids(backing: int) -> tuple[int, int, int]:
    if backing == BACKING_ANON:
        return 0, 0, 0
    return 1, 1, 0


def build_class_cells() -> list[Cell]:
    cells: list[Cell] = []

    for task, path in itertools.product((0, 1), (b"/", b"a" * 1024)):
        cells.append(
            make_cell(
                EVENT_PRE_RELEASE,
                task=task,
                operation=1,
                phase=PHASE_PRE_RELEASE,
                payload=payload_pre_release(path),
                path_len=len(path),
            )
        )

    for blob in (bytes(8), be(HIGH64, 8), be(ONES64, 8)):
        cells.append(
            make_cell(
                EVENT_IMA_READY,
                phase=PHASE_PRE_RELEASE,
                payload=blob,
                ima_bits=int.from_bytes(blob, "big"),
            )
        )

    cells.append(
        make_cell(
            EVENT_USERSPACE_RELEASE,
            task=1,
            phase=PHASE_PRE_RELEASE,
            payload=payload_pid_tgid(),
        )
    )

    exec_attempt_grid = (
        (0, PHASE_INIT, b"/"),
        (0, PHASE_EVIDENCE_FINALIZE, b"b" * 1024),
        (1, PHASE_PRE_RELEASE, b"/"),
    )
    for flags, phase, path in exec_attempt_grid:
        cells.append(
            make_cell(
                EVENT_EXEC_ATTEMPT,
                flags=flags,
                task=1,
                operation=1,
                phase=phase,
                payload=payload_exec_attempt(path),
                path_len=len(path),
            )
        )

    cells.append(
        make_cell(
            EVENT_EXEC_COMMIT,
            task=1,
            operation=1,
            phase=PHASE_INIT,
            payload=payload_exec_commit(),
        )
    )
    cells.append(
        make_cell(
            EVENT_TASK_ALLOC,
            task=2,
            parent=1,
            operation=1,
            phase=PHASE_INIT,
            payload=bytes(8),
        )
    )
    cells.append(
        make_cell(
            EVENT_TASK_CREATED,
            task=2,
            parent=1,
            operation=1,
            phase=PHASE_INIT,
            payload=payload_pid_tgid(),
        )
    )
    for prev in (PHASE_INIT, PHASE_JIT_CACHE):
        cells.append(
            make_cell(
                EVENT_PHASE_MARKER,
                task=1,
                phase=prev + 1,
                payload=payload_phase_marker(prev),
                prev_phase=prev,
            )
        )
    cells.append(
        make_cell(EVENT_TERMINAL, phase=PHASE_SEALED, payload=b"")
    )

    for access, modifiers, path, dirfd in itertools.product(
        ACCESS,
        (0, MOD_MASK, 0x0010),
        (b"/", b"c" * 1024),
        (0, HIGH32, ONES32),
    ):
        cells.append(
            make_cell(
                EVENT_FILE_OPEN,
                task=2,
                operation=1,
                phase=PHASE_INIT,
                payload=payload_file_open(access, modifiers, dirfd, path),
                access=access,
                modifiers=modifiers,
                path_len=len(path),
                dirfd=dirfd,
            )
        )

    for access, modifiers, decision, kind, observed in itertools.product(
        ACCESS,
        (0, MOD_MASK),
        (POLICY_ALLOW, POLICY_DENY),
        OBJECT_KIND,
        (0, HIGH64, ONES64),
    ):
        result = policy_result(decision)
        cells.append(
            make_cell(
                EVENT_FILE_POLICY,
                task=2,
                operation=1,
                phase=PHASE_INIT,
                payload=payload_file_policy(
                    access, modifiers, decision, kind, result, 1, 1, observed
                ),
                access=access,
                modifiers=modifiers,
                decision=decision,
                object_kind=kind,
                inode=1,
                mount=1,
                observed_size=observed,
            )
        )

    prot_grid = (
        PROT_EXEC,
        PROT_READ | PROT_EXEC,
        PROT_WRITE | PROT_EXEC,
        PROT_READ | PROT_WRITE | PROT_EXEC,
    )
    for operation, decision, backing, mode, prot in itertools.product(
        (MAP_MMAP, MAP_MPROTECT),
        (POLICY_ALLOW, POLICY_DENY),
        BACKING,
        MODE,
        prot_grid,
    ):
        prior = 0 if operation == MAP_MMAP else PROT_READ
        inode, mount, observed = mapping_ids(backing)
        seals = 0
        cells.append(
            make_cell(
                EVENT_MAPPING,
                task=2,
                operation=1,
                phase=PHASE_INIT,
                payload=payload_mapping(
                    operation,
                    decision,
                    backing,
                    mode,
                    prot,
                    prot,
                    prior,
                    policy_result(decision),
                    seals,
                    inode,
                    mount,
                    observed,
                ),
                map_operation=operation,
                decision=decision,
                backing=backing,
                mode=mode,
                requested=prot,
                effective=prot,
                prior=prior,
                seals=seals,
                inode=inode,
                mount=mount,
                observed_size=observed,
            )
        )
    cells.append(
        make_cell(
            EVENT_MAPPING,
            task=2,
            operation=1,
            phase=PHASE_INIT,
            payload=payload_mapping(
                MAP_MMAP,
                POLICY_ALLOW,
                BACKING_MEMFD,
                2,
                PROT_EXEC,
                PROT_EXEC,
                0,
                0,
                1,
                1,
                1,
                0,
            ),
            map_operation=MAP_MMAP,
            decision=POLICY_ALLOW,
            backing=BACKING_MEMFD,
            mode=2,
            requested=PROT_EXEC,
            effective=PROT_EXEC,
            prior=0,
            seals=1,
            inode=1,
            mount=1,
            observed_size=0,
        )
    )

    families = (0, NET_FAMILY_INET, NET_FAMILY_INET6, 17)
    addr_lens = (0, 1, 8, 16, 20, 28, 64, 129)
    for operation, kind, source, family, addrlen, decision in itertools.product(
        (NET_CONNECT, NET_SENDMSG),
        NET_KIND,
        (NET_EXPLICIT, NET_CONNECTED),
        families,
        addr_lens,
        (POLICY_ALLOW, POLICY_DENY),
    ):
        flags = 0
        size = 0 if operation == NET_CONNECT else 16
        cells.append(
            make_cell(
                EVENT_NETWORK,
                task=2,
                operation=1,
                phase=PHASE_INIT,
                payload=payload_network(
                    operation,
                    decision,
                    kind,
                    source,
                    family,
                    addrlen,
                    policy_result(decision),
                    flags=flags,
                    size=size,
                    protocol=0,
                    cookie=1,
                ),
                net_operation=operation,
                decision=decision,
                endpoint_kind=kind,
                source=source,
                family=family,
                addrlen=addrlen,
                protocol=0,
                cookie=1,
                flags=flags,
                size=size,
            )
        )
    for protocol in (0x8000, 0xFFFF):
        cells.append(
            make_cell(
                EVENT_NETWORK,
                task=2,
                operation=1,
                phase=PHASE_INIT,
                payload=payload_network(
                    NET_CONNECT,
                    POLICY_ALLOW,
                    NET_IPV4,
                    NET_EXPLICIT,
                    NET_FAMILY_INET,
                    16,
                    0,
                    protocol=protocol,
                    cookie=1,
                ),
                net_operation=NET_CONNECT,
                decision=POLICY_ALLOW,
                endpoint_kind=NET_IPV4,
                source=NET_EXPLICIT,
                family=NET_FAMILY_INET,
                addrlen=16,
                protocol=protocol,
                cookie=1,
                flags=0,
                size=0,
            )
        )

    for kind, raw in itertools.product(OP_KIND, (0, HIGH64, ONES64)):
        cells.append(
            make_cell(
                EVENT_OP_RETURN,
                task=2,
                operation=1,
                phase=PHASE_INIT,
                payload=payload_op_return(kind, raw),
                op_kind=kind,
                raw=raw,
            )
        )

    for code in (0, HIGH32, ONES32):
        cells.append(
            make_cell(
                EVENT_TASK_EXIT,
                task=2,
                parent=1,
                operation=0,
                phase=PHASE_INIT,
                payload=payload_task_exit(code),
                exit_code=code,
            )
        )
    return cells


def default_twin(cell: Cell) -> Cell:
    event = cell.event
    if event == EVENT_PRE_RELEASE:
        return derive_twin(cell, "operation", 0, operation=0)
    if event == EVENT_IMA_READY:
        return derive_twin(cell, "phase", PHASE_SEALED, phase=PHASE_SEALED)
    if event == EVENT_USERSPACE_RELEASE:
        return derive_twin(cell, "task", 0, task=0)
    if event == EVENT_EXEC_ATTEMPT:
        if cell.flags == 1:
            return derive_twin(cell, "phase", PHASE_INIT, phase=PHASE_INIT)
        return derive_twin(cell, "flags", 2, flags=2)
    if event == EVENT_EXEC_COMMIT:
        return derive_twin(cell, "operation", 0, operation=0)
    if event in (EVENT_TASK_ALLOC, EVENT_TASK_CREATED):
        return derive_twin(cell, "parent", cell.task, parent=cell.task)
    if event == EVENT_PHASE_MARKER:
        return derive_twin(cell, "flags", 1, flags=1)
    if event == EVENT_TERMINAL:
        return derive_twin(cell, "phase", PHASE_PRE_RELEASE, phase=PHASE_PRE_RELEASE)
    if event == EVENT_FILE_OPEN:
        return derive_twin(
            cell, "access", 0, payload=patch(cell.payload, 4, u16(0))
        )
    if event == EVENT_FILE_POLICY:
        return derive_twin(
            cell, "object_kind", 0, payload=patch(cell.payload, 6, u16(0))
        )
    if event == EVENT_MAPPING:
        return derive_twin(
            cell, "backing", 0, payload=patch(cell.payload, 4, u16(0))
        )
    if event == EVENT_NETWORK:
        return derive_twin(
            cell, "cookie", 0, payload=patch(cell.payload, 28, u64(0))
        )
    if event == EVENT_OP_RETURN:
        return derive_twin(
            cell, "op_kind", 0, payload=patch(cell.payload, 0, u16(0))
        )
    if event == EVENT_TASK_EXIT:
        return derive_twin(cell, "parent", cell.task, parent=cell.task)
    raise AssertionError(f"no default twin for event {event}")


def first_green(greens: list[Cell], event: int, pred=None) -> Cell:
    for cell in greens:
        if cell.event != event:
            continue
        if pred is None or pred(cell):
            return cell
    raise AssertionError(f"missing green baseline for event {event}")


def isolating_twins(greens: list[Cell]) -> list[Cell]:
    twins: list[Cell] = []

    open_green = first_green(greens, EVENT_FILE_OPEN)
    twins.append(
        derive_twin(open_green, "action", 0, payload=patch(open_green.payload, 0, u16(0)))
    )
    twins.append(
        derive_twin(
            open_green,
            "modifiers",
            MOD_MASK + 1,
            payload=patch(open_green.payload, 6, u16(MOD_MASK + 1)),
        )
    )
    twins.append(
        derive_twin(
            open_green, "path_len", 0, payload=patch(open_green.payload, 2, u16(0))
        )
    )
    twins.append(
        derive_twin(
            open_green,
            "reserved",
            1,
            payload=patch(open_green.payload, 12, u32(1)),
        )
    )
    twins.append(
        derive_twin(
            open_green,
            "path_nul",
            1,
            payload=patch(open_green.payload, 16, b"\x00"),
        )
    )

    policy = first_green(greens, EVENT_FILE_POLICY)
    twins.append(
        derive_twin(policy, "access", 0, payload=patch(policy.payload, 0, u16(0)))
    )
    twins.append(
        derive_twin(
            policy,
            "modifiers",
            MOD_MASK + 1,
            payload=patch(policy.payload, 2, u16(MOD_MASK + 1)),
        )
    )
    twins.append(
        derive_twin(policy, "decision", 0, payload=patch(policy.payload, 4, u16(0)))
    )
    twins.append(
        derive_twin(policy, "inode", 0, payload=patch(policy.payload, 24, u64(0)))
    )
    twins.append(
        derive_twin(policy, "mount", 0, payload=patch(policy.payload, 32, u64(0)))
    )
    allow = first_green(
        greens, EVENT_FILE_POLICY, lambda cell: cell.coords["decision"] == POLICY_ALLOW
    )
    twins.append(
        derive_twin(allow, "result", 1, payload=patch(allow.payload, 8, u32(1)))
    )

    mapping = first_green(greens, EVENT_MAPPING)
    twins.append(
        derive_twin(
            mapping, "map_operation", 0, payload=patch(mapping.payload, 0, u16(0))
        )
    )
    twins.append(
        derive_twin(mapping, "decision", 0, payload=patch(mapping.payload, 2, u16(0)))
    )
    twins.append(
        derive_twin(mapping, "mode", 0, payload=patch(mapping.payload, 6, u16(0)))
    )
    twins.append(
        derive_twin(
            mapping,
            "requested",
            PROT_EXEC | 8,
            payload=patch(mapping.payload, 8, u32(PROT_EXEC | 8)),
        )
    )
    twins.append(
        derive_twin(
            mapping,
            "effective",
            PROT_READ,
            payload=patch(mapping.payload, 12, u32(PROT_READ)),
        )
    )
    mmap_green = first_green(
        greens,
        EVENT_MAPPING,
        lambda cell: cell.coords["map_operation"] == MAP_MMAP,
    )
    twins.append(
        derive_twin(
            mmap_green,
            "prior",
            PROT_READ,
            payload=patch(mmap_green.payload, 16, u32(PROT_READ)),
        )
    )
    anon = first_green(
        greens,
        EVENT_MAPPING,
        lambda cell: cell.coords["backing"] == BACKING_ANON,
    )
    twins.append(
        derive_twin(anon, "inode", 1, payload=patch(anon.payload, 40, u64(1)))
    )
    non_memfd = first_green(
        greens,
        EVENT_MAPPING,
        lambda cell: cell.coords["backing"] != BACKING_MEMFD,
    )
    twins.append(
        derive_twin(
            non_memfd, "seals", 1, payload=patch(non_memfd.payload, 36, u32(1))
        )
    )

    net = first_green(greens, EVENT_NETWORK)
    twins.append(
        derive_twin(
            net, "net_operation", 0, payload=patch(net.payload, 0, u16(0))
        )
    )
    twins.append(
        derive_twin(net, "decision", 0, payload=patch(net.payload, 2, u16(0)))
    )
    twins.append(
        derive_twin(net, "endpoint_kind", 0, payload=patch(net.payload, 4, u16(0)))
    )
    twins.append(
        derive_twin(net, "source", 0, payload=patch(net.payload, 6, u16(0)))
    )
    twins.append(
        derive_twin(net, "socket_kind", 0, payload=patch(net.payload, 8, u16(0)))
    )
    twins.append(
        derive_twin(net, "reserved", 1, payload=patch(net.payload, 38, u16(1)))
    )
    ipv4 = first_green(
        greens, EVENT_NETWORK, lambda cell: cell.coords["endpoint_kind"] == NET_IPV4
    )
    twins.append(
        derive_twin(ipv4, "scope", 1, payload=patch(ipv4.payload, 40, u32(1)))
    )
    connect = first_green(
        greens,
        EVENT_NETWORK,
        lambda cell: cell.coords["net_operation"] == NET_CONNECT
        and cell.coords.get("source") == NET_EXPLICIT
        and cell.coords.get("endpoint_kind") == NET_IPV4
        and cell.coords.get("family") == NET_FAMILY_INET
        and cell.coords.get("addrlen") == 16,
    )
    twins.append(
        derive_twin(connect, "flags", 1, payload=patch(connect.payload, 20, u32(1)))
    )
    twins.append(
        derive_twin(
            connect,
            "source",
            NET_CONNECTED,
            payload=patch(connect.payload, 6, u16(NET_CONNECTED)),
        )
    )
    allow_net = first_green(
        greens,
        EVENT_NETWORK,
        lambda cell: cell.coords["decision"] == POLICY_ALLOW
        and cell.coords.get("endpoint_kind") == NET_IPV4
        and cell.coords.get("source") == NET_EXPLICIT
        and cell.coords.get("family") == NET_FAMILY_INET
        and cell.coords.get("addrlen") == 16,
    )
    twins.append(
        derive_twin(allow_net, "result", 1, payload=patch(allow_net.payload, 16, u32(1)))
    )

    op_ret = first_green(greens, EVENT_OP_RETURN)
    twins.append(
        derive_twin(
            op_ret, "reserved16", 1, payload=patch(op_ret.payload, 2, u16(1))
        )
    )
    twins.append(
        derive_twin(
            op_ret, "reserved32", 1, payload=patch(op_ret.payload, 4, u32(1))
        )
    )

    exit_green = first_green(greens, EVENT_TASK_EXIT)
    twins.append(derive_twin(exit_green, "parent", 0, parent=0))
    twins.append(
        derive_twin(
            exit_green,
            "reserved32",
            1,
            payload=patch(exit_green.payload, 4, u32(1)),
        )
    )
    return twins


class LineProc:
    def __init__(self, args: list[str]) -> None:
        self.proc = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        if self.proc.stdin is None or self.proc.stdout is None:
            raise AssertionError("failed to open harness pipes")

    def send(self, line: str) -> str:
        assert self.proc.stdin is not None
        assert self.proc.stdout is not None
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()
        reply = self.proc.stdout.readline()
        if reply == "":
            err = self.proc.stderr.read() if self.proc.stderr else ""
            raise AssertionError(f"harness closed stdout: {err}")
        return reply.rstrip("\n")

    def close(self) -> None:
        if self.proc.stdin is not None:
            self.proc.stdin.close()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)
        if self.proc.returncode not in (0, None):
            err = ""
            if self.proc.stderr is not None:
                err = self.proc.stderr.read()
            if self.proc.returncode != 0:
                raise AssertionError(
                    f"harness exit {self.proc.returncode}: {err.strip()}"
                )


def parse_classifier(reply: str) -> tuple[int, str]:
    parts = reply.split("\t")
    if not parts or parts[0] == "":
        raise AssertionError(f"classifier empty reply: {reply!r}")
    code = int(parts[0])
    encoded = parts[1] if code == WIRE_OK and len(parts) > 1 else ""
    return code, encoded


def parse_harness(reply: str) -> list[str]:
    if not reply:
        raise AssertionError("gpl harness empty reply")
    return reply.split("\t")


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit(
            "usage: conf-proc-spp-diag-trace-core-field-oracle.py CLASSIFIER HARNESS"
        )
    classifier_path = Path(sys.argv[1]).resolve()
    harness_path = Path(sys.argv[2]).resolve()
    challenge = bytes(range(0, 32))
    run = bytes(range(32, 64))
    control = bytes(range(64, 96))
    cmdline = bytes(range(96, 128))

    class_cells = build_class_cells()
    cartesian_classes = len(class_cells)
    classifier = LineProc([str(classifier_path), "batch"])
    class_verdicts: list[int] = []
    try:
        for cell in class_cells:
            code, _encoded = parse_classifier(classifier.send(classify_line(cell)))
            class_verdicts.append(code)
        greens = [
            cell
            for cell, code in zip(class_cells, class_verdicts)
            if code == WIRE_OK
        ]
        if not greens:
            raise AssertionError("classifier accepted no class cells")
        pairs: list[tuple[Cell, Cell]] = []
        twins: list[Cell] = []
        for cell in greens:
            twin = default_twin(cell)
            diffs = coord_diffs(cell, twin)
            if len(diffs) != 1:
                raise AssertionError(
                    f"default twin coordinate mismatch {diffs} for event {cell.event}"
                )
            twins.append(twin)
            pairs.append((cell, twin))
        extra = isolating_twins(greens)
        for twin in extra:
            parent = None
            for green in greens:
                diffs = coord_diffs(green, twin)
                if len(diffs) == 1:
                    parent = green
                    pairs.append((green, twin))
                    break
            if parent is None:
                raise AssertionError(
                    f"isolating twin does not differ by one coordinate: {twin.coords}"
                )
            twins.append(twin)
        twin_verdicts: list[int] = []
        for twin in twins:
            code, _encoded = parse_classifier(classifier.send(classify_line(twin)))
            twin_verdicts.append(code)
            if code == WIRE_OK:
                raise AssertionError(
                    f"classifier accepted twin event={twin.event} coords={twin.coords}"
                )
    finally:
        classifier.close()

    green_n = sum(1 for code in class_verdicts if code == WIRE_OK)
    negative_n = sum(1 for code in class_verdicts if code != WIRE_OK) + len(twins)
    candidates = class_cells + twins
    expected = class_verdicts + twin_verdicts
    if cartesian_classes + len(twins) != len(candidates):
        raise AssertionError("candidate assembly mismatch")

    events_seen = {cell.event for cell in greens}
    if len(events_seen) != 15:
        raise AssertionError(
            f"green baselines cover {sorted(hex(e) if e > 10 else e for e in events_seen)}"
        )

    encoded_header = header(challenge, run, control, cmdline)
    core_init = frame(1, 0, 0, 0, 0, 0, 0, b"")
    header_chain = header_chain_of(encoded_header)
    chain_after_init = roll_frame(header_chain, core_init)

    harness = LineProc(
        [
            str(harness_path),
            "batch",
            challenge.hex(),
            run.hex(),
            control.hex(),
            cmdline.hex(),
        ]
    )
    accepted = 0
    rejected = 0
    try:
        for cell, want in zip(candidates, expected):
            actual = parse_harness(harness.send(frame_tuple(cell)))
            got = int(actual[0])
            want_ok = want == WIRE_OK
            got_ok = got == WIRE_OK
            if want_ok != got_ok:
                raise AssertionError(
                    f"verdict mismatch event={cell.event} origin={cell.origin} "
                    f"classifier={want} gpl={got} coords={cell.coords}"
                )
            if got_ok:
                accepted += 1
                published = frame(
                    cell.event,
                    cell.flags,
                    1,
                    cell.task,
                    cell.parent,
                    cell.operation,
                    cell.phase,
                    cell.payload,
                )
                chain = roll_frame(chain_after_init, published)
                if actual[4] != "2":
                    raise AssertionError(f"accepted frame_count {actual[4]}")
                if actual[7] != encoded_header.hex():
                    raise AssertionError("accepted header mismatch")
                if actual[8] != core_init.hex():
                    raise AssertionError("accepted CORE_INIT mismatch")
                if actual[9] != header_chain.hex():
                    raise AssertionError("accepted header chain mismatch")
                if actual[10] != chain.hex():
                    raise AssertionError("accepted frame chain mismatch")
                if actual[-1] != published.hex():
                    raise AssertionError("accepted published frame mismatch")
            else:
                rejected += 1
                if actual[4] != "1":
                    raise AssertionError(
                        f"rejected append published a frame: count={actual[4]}"
                    )
    finally:
        harness.close()

    candidate_n = len(candidates)
    if candidate_n != green_n + negative_n or candidate_n != accepted + rejected:
        raise AssertionError(
            "denominator mismatch "
            f"C={candidate_n} G={green_n} K={negative_n} A={accepted} R={rejected}"
        )
    if min(15, cartesian_classes, green_n, negative_n, candidate_n, accepted, rejected) == 0:
        raise AssertionError("a required denominator was zero")

    print(f"events=15")
    print(f"cartesian_classes={cartesian_classes}")
    print(f"green={green_n}")
    print(f"negative={negative_n}")
    print(f"candidates={candidate_n}")
    print(f"accepted={accepted}")
    print(f"rejected={rejected}")
    print("ok   spp-diag-trace-core-field-oracle")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
