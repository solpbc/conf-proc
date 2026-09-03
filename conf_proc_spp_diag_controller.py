#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""PID-1 diagnostic controller: drives the trace phase choreography and evidence collection.

Runs as the process execve'd by /spp-diag-handoff, inheriting fds 3 (trace control,
write-only), 4 (trace stream, read-only), and 5 (serial/UART, read-write). Imports only
shared protocol constants (conf_proc_spp_diag_pcr, conf_proc_spp_diagbundle_protocol,
conf_proc_spp_diag_failure_terminal_reasons) and never any production-appraiser module
(conf_proc_spp_diag_trace_semantics, conf_proc_spp_diag_attest, conf_proc_spp_diagbundle,
conf_proc_spp_diag_trace_checkpoints, conf_proc_spp_diag_ima). All privileged and
kernel-facing operations are routed through a ControllerOps object so that a scripted
fake can drive the exact same choreography logic under test.

PHASE_NAMES/PLAN_KEYS below are an intentional literal mirror of
conf_proc_spp_diag_trace_semantics.py's fixed constants of the same values, not an
import -- the producer and appraiser must never share appraisal code, only the two
named shared-protocol modules.
"""

from __future__ import annotations

import ctypes
import mmap as mmap_module
import os
import socket
import struct
import time
from dataclasses import dataclass
from typing import Callable, Final

from conf_proc_spp_diag_failure_terminal_reasons import (
    ALL_SPPFLR1_REASONS,
    SPPFLR1_CANARY_EXEC,
    SPPFLR1_CHILD_SUPERVISION,
    SPPFLR1_CONTROL_WRITE,
    SPPFLR1_DEADLINE,
    SPPFLR1_NETWORK_DENIAL,
    encode_failure_terminal,
)


PHASE_NAMES: Final = (
    "init",
    "cold_start",
    "synthetic_inference",
    "poison_import",
    "poison_module",
    "poison_library",
    "remote_package",
    "remote_model",
    "remote_plugin",
    "writable_exec",
    "attached_disk_exec",
    "remote_code",
    "jit_cache",
    "evidence_finalize",
)

_CMD_MAGIC: Final = b"SPPCMD1\x00"
_CMD_WIRE_VERSION: Final = 1
_CMD_ADVANCE_PHASE: Final = 1
_CMD_SEAL: Final = 2
_CMD_SEAL_PHASE: Final = 15
_CMD_SIZE: Final = 128

# Fixed absolute canary paths for the direct-execve denial phases (senior-engineer
# decision -- these literal paths are not given by any upstream spec and are private
# to this appliance's own diagnostic probes).
_WRITABLE_EXEC_CANARY: Final = "/tmp/spp-diag-writable-exec-canary"
_ATTACHED_DISK_EXEC_CANARY: Final = "/mnt/spp-diag-attached-disk-canary"
_REMOTE_CODE_EXEC_CANARY: Final = "/var/spp-diag-remote-code-canary"

# Fixed poison targets (phases 4-6): a nonexistent Python module, a nonexistent
# absolute shared-object path, and a nonexistent bare SONAME -- all expected to fail
# with a plain absent-file error, never an AppArmor denial.
_POISON_IMPORT_MODULE: Final = "spp_diag_poison_module_absent"
_POISON_MODULE_PATH: Final = "/usr/local/libexec/solstone/spp-diag-poison-module.so"
_POISON_LIBRARY_SONAME: Final = "libspp-diag-poison.so.1"

# Fixed network-denial endpoints (phases 7-9): TEST-NET-3 / documentation ranges,
# never routable, so any non-AppArmor failure would be ambiguous with a real network
# failure -- production deployments rely on the AppArmor profile actually denying
# these before any packet is sent.
_REMOTE_PACKAGE_ENDPOINT: Final = ("203.0.113.10", 443)
_REMOTE_MODEL_ENDPOINT: Final = ("2001:db8::1", 443)
_REMOTE_PLUGIN_ENDPOINT: Final = ("203.0.113.20", 53)


def encode_command(kind: int, requested_phase: int, challenge: bytes, run_identity: bytes, control_plan_address: bytes) -> bytes:
    """Encode the 128-byte spp_diag_trace_command wire struct, big-endian, per conf_proc_spp_diag_trace.c."""

    if len(challenge) != 32 or len(run_identity) != 32 or len(control_plan_address) != 32:
        raise ValueError("challenge/run_identity/control_plan_address must each be 32 bytes")
    reserved = b"\x00" * 14
    packed = struct.pack(
        ">8sHHI32s32s32sH14s",
        _CMD_MAGIC,
        _CMD_WIRE_VERSION,
        kind,
        _CMD_SIZE,
        challenge,
        run_identity,
        control_plan_address,
        requested_phase,
        reserved,
    )
    assert len(packed) == _CMD_SIZE
    return packed


@dataclass(frozen=True)
class ControllerIdentity:
    challenge: bytes
    run_identity: bytes
    control_plan_address: bytes


@dataclass
class ControllerOps:
    write_control: Callable[[bytes], None]
    read_stream: Callable[[int], bytes]
    monotonic: Callable[[], float]
    import_probe: Callable[[str], bool]
    cdll_probe: Callable[[str], bool]
    connect_probe: Callable[[str, tuple], bool]
    exec_probe: Callable[[str], bool]
    jit_probe: Callable[[], bool]
    request_poweroff: Callable[[bytes], None]


class ControllerTerminated(Exception):
    def __init__(self, reason_code: str, phase: int):
        super().__init__(reason_code)
        self.reason_code = reason_code
        self.phase = phase


_PHASE_DEADLINE_SECONDS: Final = 30.0


def _terminate(ops: ControllerOps, reason_code: str, phase: int) -> None:
    assert reason_code in ALL_SPPFLR1_REASONS
    record = encode_failure_terminal(reason_code, phase)
    ops.request_poweroff(record)
    raise ControllerTerminated(reason_code, phase)


def _advance(ops: ControllerOps, identity: ControllerIdentity, phase_number: int, deadline: float) -> None:
    if ops.monotonic() > deadline:
        _terminate(ops, SPPFLR1_DEADLINE, phase_number)
    command = encode_command(_CMD_ADVANCE_PHASE, phase_number, identity.challenge, identity.run_identity, identity.control_plan_address)
    try:
        ops.write_control(command)
    except Exception:
        _terminate(ops, SPPFLR1_CONTROL_WRITE, phase_number)


def _run_poison_phases(ops: ControllerOps, identity: ControllerIdentity, deadline: float) -> None:
    _advance(ops, identity, 4, deadline)
    if not ops.import_probe(_POISON_IMPORT_MODULE):
        _terminate(ops, SPPFLR1_CHILD_SUPERVISION, 4)
    _advance(ops, identity, 5, deadline)
    if not ops.cdll_probe(_POISON_MODULE_PATH):
        _terminate(ops, SPPFLR1_CHILD_SUPERVISION, 5)
    _advance(ops, identity, 6, deadline)
    if not ops.cdll_probe(_POISON_LIBRARY_SONAME):
        _terminate(ops, SPPFLR1_CHILD_SUPERVISION, 6)


def _run_network_phases(ops: ControllerOps, identity: ControllerIdentity, deadline: float) -> None:
    _advance(ops, identity, 7, deadline)
    if not ops.connect_probe("ipv4", _REMOTE_PACKAGE_ENDPOINT):
        _terminate(ops, SPPFLR1_NETWORK_DENIAL, 7)
    _advance(ops, identity, 8, deadline)
    if not ops.connect_probe("ipv6", _REMOTE_MODEL_ENDPOINT):
        _terminate(ops, SPPFLR1_NETWORK_DENIAL, 8)
    _advance(ops, identity, 9, deadline)
    if not ops.connect_probe("udp", _REMOTE_PLUGIN_ENDPOINT):
        _terminate(ops, SPPFLR1_NETWORK_DENIAL, 9)


def _run_exec_phases(ops: ControllerOps, identity: ControllerIdentity, deadline: float) -> None:
    _advance(ops, identity, 10, deadline)
    if not ops.exec_probe(_WRITABLE_EXEC_CANARY):
        _terminate(ops, SPPFLR1_CANARY_EXEC, 10)
    _advance(ops, identity, 11, deadline)
    if not ops.exec_probe(_ATTACHED_DISK_EXEC_CANARY):
        _terminate(ops, SPPFLR1_CANARY_EXEC, 11)
    _advance(ops, identity, 12, deadline)
    if not ops.exec_probe(_REMOTE_CODE_EXEC_CANARY):
        _terminate(ops, SPPFLR1_CANARY_EXEC, 12)


def run_controller(ops: ControllerOps, identity: ControllerIdentity) -> bytes:
    """Drive phases 2-14 then SEAL(15); returns the post-seal stream bytes.

    Never reads the stream before writing SEAL -- evidence collection is only valid
    on a sealed trace.
    """

    deadline = ops.monotonic() + _PHASE_DEADLINE_SECONDS

    _advance(ops, identity, 2, deadline)  # cold_start
    _advance(ops, identity, 3, deadline)  # synthetic_inference

    _run_poison_phases(ops, identity, deadline)
    _run_network_phases(ops, identity, deadline)
    _run_exec_phases(ops, identity, deadline)

    _advance(ops, identity, 13, deadline)  # jit_cache
    if not ops.jit_probe():
        _terminate(ops, SPPFLR1_CHILD_SUPERVISION, 13)

    _advance(ops, identity, 14, deadline)  # evidence_finalize

    if ops.monotonic() > deadline:
        _terminate(ops, SPPFLR1_DEADLINE, _CMD_SEAL_PHASE)
    seal_command = encode_command(_CMD_SEAL, _CMD_SEAL_PHASE, identity.challenge, identity.run_identity, identity.control_plan_address)
    try:
        ops.write_control(seal_command)
    except Exception:
        _terminate(ops, SPPFLR1_CONTROL_WRITE, _CMD_SEAL_PHASE)

    return ops.read_stream(64 * 1024 * 1024)


def real_monotonic() -> float:
    return time.monotonic()


# --------------------------------------------------------------------
# Real production ops -- each probe forks a disposable child so a probe
# that unexpectedly succeeds (e.g. an exec that should have been denied)
# never runs its consequences inside the controller's own PID-1 process.
# --------------------------------------------------------------------


def _real_import_probe(module_name: str) -> bool:
    pid = os.fork()
    if pid == 0:
        try:
            __import__(module_name)
            os._exit(0)
        except ImportError:
            os._exit(1)
        except Exception:
            os._exit(2)
    _, status = os.waitpid(pid, 0)
    return os.WIFEXITED(status) and os.WEXITSTATUS(status) == 1


def _real_cdll_probe(path: str) -> bool:
    pid = os.fork()
    if pid == 0:
        try:
            ctypes.CDLL(path)
            os._exit(0)
        except OSError:
            os._exit(1)
        except Exception:
            os._exit(2)
    _, status = os.waitpid(pid, 0)
    return os.WIFEXITED(status) and os.WEXITSTATUS(status) == 1


def _real_connect_probe(family: str, endpoint: tuple) -> bool:
    pid = os.fork()
    if pid == 0:
        try:
            if family == "ipv4":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2.0)
                sock.connect(endpoint)
            elif family == "ipv6":
                sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                sock.settimeout(2.0)
                sock.connect(endpoint)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(b"", endpoint)
            os._exit(0)
        except PermissionError:
            os._exit(1)
        except Exception:
            os._exit(2)
    _, status = os.waitpid(pid, 0)
    return os.WIFEXITED(status) and os.WEXITSTATUS(status) == 1


def _real_exec_probe(path: str) -> bool:
    pid = os.fork()
    if pid == 0:
        try:
            os.execve(path, [path], {})
        except PermissionError:
            os._exit(1)
        except Exception:
            os._exit(2)
        os._exit(0)
    _, status = os.waitpid(pid, 0)
    return os.WIFEXITED(status) and os.WEXITSTATUS(status) == 1


def _real_jit_probe() -> bool:
    try:
        size = mmap_module.PAGESIZE
        region = mmap_module.mmap(-1, size, prot=mmap_module.PROT_READ | mmap_module.PROT_WRITE)
        region.write(b"\xc3" + b"\x00" * (size - 1))
        region.mprotect(mmap_module.PROT_READ | mmap_module.PROT_EXEC)
        region.close()
        return True
    except Exception:
        return False


def _real_request_poweroff(record: bytes) -> None:
    """Placeholder integration point: the UART export module (a later batch) owns
    writing this failure-terminal record to serial and triggering reboot(2)
    RB_POWER_OFF. The controller's own contract only guarantees this callback
    receives the exact encoded failure-terminal bytes."""


def real_controller_ops(control_fd: int = 3, stream_fd: int = 4) -> ControllerOps:
    def write_control(data: bytes) -> None:
        os.write(control_fd, data)

    def read_stream(max_bytes: int) -> bytes:
        chunks: list[bytes] = []
        total = 0
        while total < max_bytes:
            chunk = os.read(stream_fd, min(1024 * 1024, max_bytes - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        return b"".join(chunks)

    return ControllerOps(
        write_control=write_control,
        read_stream=read_stream,
        monotonic=real_monotonic,
        import_probe=_real_import_probe,
        cdll_probe=_real_cdll_probe,
        connect_probe=_real_connect_probe,
        exec_probe=_real_exec_probe,
        jit_probe=_real_jit_probe,
        request_poweroff=_real_request_poweroff,
    )
