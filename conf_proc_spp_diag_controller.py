#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Fixed-purpose SPP diagnostic PID-1 controller.

The controller owns appliance policy and syscall choreography.  It imports only the
shared producer codecs needed to emit evidence; trace appraisal stays independent.
``ControllerOps`` is the local syscall/clock seam used by production and recording
selftests--there is no environment-selected fake path.
"""

from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import mmap
import os
import re
import select
import signal
import socket
import stat
import struct
import termios
import time
from dataclasses import dataclass
from typing import Callable, Final

from conf_proc_json import canonical_dumps, canonical_loads
from conf_proc_spp_diag_export import ExportOps, build_export_stream, export_and_poweroff
from conf_proc_spp_diag_failure_terminal_reasons import (
    SPPFLR1_BINDING, SPPFLR1_CHILD, SPPFLR1_EXPORT, SPPFLR1_GPU, SPPFLR1_IMA,
    SPPFLR1_INPUT, SPPFLR1_POLICY, SPPFLR1_TPM, SPPFLR1_TRACE, encode_failure_terminal,
)
from conf_proc_spp_diag_quote import QuoteOps, build_quote_invocation, run_quote
from conf_proc_spp_diagbundle_protocol import DOMAIN_CONTROL_PLAN, inner_receipt_digest


TARGET_PROFILE: Final = "azure:centralus:3:Standard_NCC40ads_H100_v5:ConfidentialVM:v1"
CONTROLLER_PATH: Final = "/usr/lib/spp/spp-diag-controller"
CONTROL_FD: Final = 3
STREAM_FD: Final = 4
UART_FD: Final = 5
UART_PATH: Final = "/dev/ttyS0"
UART_MAJOR: Final = 4
UART_MINOR: Final = 64
BINDING_PATH_PREFIX: Final = "/dev/disk/by-partuuid/"
BINDING_SIZE: Final = 4096
BINDING_MAGIC: Final = b"SPPBND1\0"
BINDING_VERSION: Final = 1
BINDING_DOMAIN: Final = b"sol-spp-diag-runtime-late-binding/v1\0"
MAX_PLAN_BYTES: Final = 131_072
MAX_STREAM_BYTES: Final = 8 * 1024 * 1024
_CHILD_CAPTURE_BYTES: Final = 1_048_576
_FAILURE_UART_SECONDS: Final = 5.0
_PHASE_DEADLINE_SECONDS: Final = 300.0
_TERM_GRACE: Final = 0.250
_POST_KILL: Final = 1.0
_LINUX_REBOOT_CMD_POWER_OFF: Final = 0x4321FEDC

PHASE_NAMES: Final = (
    "init", "cold_start", "synthetic_inference", "poison_import", "poison_module",
    "poison_library", "remote_package", "remote_model", "remote_plugin", "writable_exec",
    "attached_disk_exec", "remote_code", "jit_cache", "evidence_finalize",
)
_CMD_MAGIC: Final = b"SPPCMD1\0"
_CMD_SIZE: Final = 128
_ADVANCE: Final = 1
_SEAL: Final = 2
_SEAL_PHASE: Final = 15
_PARTUUID: Final = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")

# Literal producer-side plan schema copied from the contract, never imported from an
# appraiser.  Parsed plans constrain only these fixed probes and cannot select IDs.
_PLAN_SCHEMA: Final = "sol-spp-diag-trace-control-plan-v1"
_PLAN_KEYS: Final = frozenset((
    "attached_disk_exec", "cold_start", "jit_cache", "phase_order", "poison_import",
    "poison_library", "poison_module", "pre_release", "remote_code", "remote_model",
    "remote_package", "remote_plugin", "schema", "synthetic_inference", "writable_exec",
))
_CUDA: Final = "/opt/solstone/bin/synthetic-runtime"
_MODEL: Final = "/opt/solstone/models/synthetic-fixture-v1.bin"
_JIT: Final = "/var/cache/solstone/jit/synthetic-fixture-v1.so"
_POISONS: Final = (
    "/var/lib/solstone/poison/import.py",
    "/var/lib/solstone/poison/module.so",
    "/var/lib/solstone/poison/libinject.so",
)
_NETWORKS: Final = (
    (socket.AF_INET, socket.SOCK_STREAM, "198.51.100.7", 443, "connect"),
    (socket.AF_INET6, socket.SOCK_STREAM, "2001:db8::8", 443, "connect"),
    (socket.AF_INET, socket.SOCK_DGRAM, "203.0.113.9", 443, "sendmsg"),
)
_EXEC_DENIALS: Final = (
    "/var/tmp/solstone-writable-exec",
    "/mnt/solstone-attached/foreign-exec",
    "/run/solstone/remote-code/foreign-exec",
)
_PARSER: Final = "/usr/sbin/apparmor_parser"
_PROFILE_FILE: Final = "/etc/apparmor.d/usr.local.libexec.solstone.spp-diag-controller"
_PROFILE_NAME: Final = "/usr/lib/spp/spp-diag-controller"
_GPU_HELPER: Final = "/opt/solstone/bin/spp-diag-gpu-helper"
_TPM_QUOTE: Final = "/usr/bin/tpm2_quote"
_TPM_PCR_LIST: Final = "sha256:0,2,4,7,8,9,10,11,12,13,14,15,16,22,23"
_AK_PEM: Final = "/run/spp-diag/ak-public.pem"
_AK_TPMT: Final = "/run/spp-diag/ak-tpmt-public.bin"
_HCLA: Final = "/run/spp-diag/hcla.bin"
_FIRMWARE: Final = "/sys/kernel/security/tpm0/binary_bios_measurements"
_IMA: Final = "/sys/kernel/security/ima/ascii_runtime_measurements"
_SCRATCH: Final = "/run/spp-diag/scratch"
_MODEL_FIXTURE_SHA256: Final = "1ae959386fcd1dff3db63e50a9ebba5376d5d83f08ef98a2e584e7b0f878d6c8"


def encode_command(kind: int, phase: int, challenge: bytes, run_identity: bytes, control_plan_address: bytes) -> bytes:
    """Encode the complete 128-byte trace command, including zero reserved bytes."""

    if kind not in (_ADVANCE, _SEAL) or not 0 <= phase <= 0xffff:
        raise ValueError("invalid trace command")
    if any(type(x) is not bytes or len(x) != 32 for x in (challenge, run_identity, control_plan_address)):
        raise ValueError("trace identities must be 32 bytes")
    result = struct.pack(
        ">8sHHI32s32s32sH14s", _CMD_MAGIC, 1, kind, _CMD_SIZE, challenge, run_identity,
        control_plan_address, phase, b"\0" * 14,
    )
    assert len(result) == _CMD_SIZE
    return result


@dataclass(frozen=True)
class ControllerIdentity:
    challenge: bytes
    run_identity: bytes
    control_plan_address: bytes
    signed_image_binding_address: str = ""


@dataclass(frozen=True)
class ChildResult:
    returncode: int
    stdout: bytes = b""
    stderr: bytes = b""


@dataclass
class ControllerOps:
    """The complete injected surface for the controller's one production core."""

    write_control: Callable[[bytes], None]
    read_stream: Callable[[int], bytes]
    monotonic: Callable[[], float]
    run_child: Callable[[str, tuple[str, ...], float, int], ChildResult]
    direct_operation: Callable[[str, object], bool]
    read_file: Callable[[str, int], bytes]
    write_file: Callable[[str, bytes], None]
    write_uart: Callable[[bytes, float], None]
    request_poweroff: Callable[[], None]
    verify_pid_fds: Callable[[], None]
    configure_uart: Callable[[], None]
    mount_scratch: Callable[[], None]
    preflight_fixture: Callable[["BootInputs", bytes], None]


class ControllerFault(RuntimeError):
    """Controller-local failure carrying one public reason and last entered phase."""

    def __init__(self, reason: str, phase: int) -> None:
        self.reason_code = reason
        self.phase = phase
        super().__init__(f"{reason}:{phase}")


def _fail(reason: str, phase: int) -> None:
    raise ControllerFault(reason, phase)


def _require_deadline(ops: ControllerOps, deadline: float, phase: int) -> None:
    # Inclusive deadline: reaching the deadline itself is too late.
    if ops.monotonic() >= deadline:
        _fail(SPPFLR1_CHILD, phase)


def _advance(ops: ControllerOps, identity: ControllerIdentity, phase: int, deadline: float) -> None:
    _require_deadline(ops, deadline, phase)
    try:
        ops.write_control(encode_command(_ADVANCE, phase, identity.challenge, identity.run_identity, identity.control_plan_address))
    except Exception:
        _fail(SPPFLR1_TRACE, phase)


def _child(
    ops: ControllerOps, name: str, argv: tuple[str, ...], deadline: float, cap: int, phase: int, reason: str,
) -> ChildResult:
    _require_deadline(ops, deadline, phase)
    try:
        result = ops.run_child(name, argv, deadline, cap)
    except Exception:
        _fail(SPPFLR1_CHILD, phase)
    _require_deadline(ops, deadline, phase)
    if result.returncode != 0 or len(result.stdout) > cap or len(result.stderr) > cap:
        _fail(reason, phase)
    return result


def _direct(ops: ControllerOps, action: str, value: object, phase: int, reason: str, deadline: float) -> None:
    _require_deadline(ops, deadline, phase)
    try:
        accepted = ops.direct_operation(action, value)
    except Exception:
        accepted = False
    if not accepted:
        _fail(reason, phase)


def _output_oracle(model: bytes, challenge: bytes, run_identity: bytes) -> bytes:
    if type(model) is not bytes or not 1 <= len(model) <= MAX_STREAM_BYTES:
        raise ValueError("fixture model outside fixed bounds")
    output = bytearray(_seed(challenge, run_identity))
    for index, value in enumerate(model):
        output[index % 32] ^= value
    return struct.pack(">8sHHI32s", b"SPPGPUO1", 1, 1, 32, bytes(output))


def _seed(challenge: bytes, run_identity: bytes) -> bytes:
    return hashlib.sha256(b"sol-spp-diag-input-seed-v1\0" + challenge + run_identity).digest()


def run_controller(ops: ControllerOps, identity: ControllerIdentity, *, model_bytes: bytes) -> tuple[bytes, bytes]:
    """Execute literal phases 2--14, SEAL(15), then its first stream read."""

    if any(type(x) is not bytes or len(x) != 32 for x in (identity.challenge, identity.run_identity, identity.control_plan_address)):
        _fail(SPPFLR1_INPUT, 1)
    deadline = ops.monotonic() + _PHASE_DEADLINE_SECONDS

    _advance(ops, identity, 2, deadline)
    cold = _child(ops, "cuda-cold", (_CUDA, "cold"), min(deadline, ops.monotonic() + 120.0), _CHILD_CAPTURE_BYTES, 2, SPPFLR1_CHILD)
    if cold.stdout or cold.stderr:
        _fail(SPPFLR1_GPU, 2)

    _advance(ops, identity, 3, deadline)
    expected_output = _output_oracle(model_bytes, identity.challenge, identity.run_identity)
    infer = _child(
        ops, "cuda-infer", (_CUDA, "infer", _seed(identity.challenge, identity.run_identity).hex()), min(deadline, ops.monotonic() + 300.0),
        _CHILD_CAPTURE_BYTES, 3, SPPFLR1_GPU,
    )
    if infer.stdout != expected_output or infer.stderr:
        _fail(SPPFLR1_GPU, 3)

    for phase, action, value, reason in (
        (4, "poison-open", _POISONS[0], SPPFLR1_TRACE), (5, "poison-open", _POISONS[1], SPPFLR1_TRACE), (6, "poison-open", _POISONS[2], SPPFLR1_TRACE),
        (7, "network", _NETWORKS[0], SPPFLR1_POLICY), (8, "network", _NETWORKS[1], SPPFLR1_POLICY), (9, "network", _NETWORKS[2], SPPFLR1_POLICY),
        (10, "exec-denial", _EXEC_DENIALS[0], SPPFLR1_POLICY), (11, "exec-denial", _EXEC_DENIALS[1], SPPFLR1_POLICY), (12, "exec-denial", _EXEC_DENIALS[2], SPPFLR1_POLICY),
    ):
        _advance(ops, identity, phase, deadline)
        _direct(ops, action, value, phase, reason, deadline)
    _advance(ops, identity, 13, deadline)
    _direct(ops, "jit", _JIT, 13, SPPFLR1_TRACE, deadline)
    _advance(ops, identity, 14, deadline)
    _require_deadline(ops, deadline, _SEAL_PHASE)
    try:
        ops.write_control(encode_command(_SEAL, _SEAL_PHASE, identity.challenge, identity.run_identity, identity.control_plan_address))
        stream = ops.read_stream(MAX_STREAM_BYTES)
    except Exception:
        _fail(SPPFLR1_TRACE, _SEAL_PHASE)
    if type(stream) is not bytes or len(stream) > MAX_STREAM_BYTES:
        _fail(SPPFLR1_TRACE, _SEAL_PHASE)
    return stream, expected_output


_CMDLINE: Final = re.compile(
    r"\Aro rdinit=/spp-diag-handoff init=/usr/lib/spp/spp-diag-controller root=/dev/mapper/spp-diag-root "
    r"rootfstype=squashfs ip=off ima_policy=critical_data spp_diag.root_data=PARTUUID=([0-9a-f-]{36}) "
    r"spp_diag.root_hash=PARTUUID=([0-9a-f-]{36}) spp_diag.roothash=([0-9a-f]{64}) "
    r"sol_spp_diag.challenge=([0-9a-f]{64}) sol_spp_diag.run=([0-9a-f]{64}) "
    r"sol_spp_diag.control_plan=([0-9a-f]{64}) -- sol_spp_diag.target_profile=" + re.escape(TARGET_PROFILE) +
    r" sol_spp_diag.binding_partuuid=([0-9a-f-]{36})\Z"
)


@dataclass(frozen=True)
class BootInputs:
    root_data_partuuid: str
    root_hash_partuuid: str
    root_hash: str
    binding_partuuid: str
    identity: ControllerIdentity


def parse_boot_inputs(argv: list[str], cmdline: bytes) -> BootInputs:
    """Independently validate handoff argv and byte-identical cmdline grammar."""

    if len(argv) != 3 or argv[0] != CONTROLLER_PATH or argv[1] != f"sol_spp_diag.target_profile={TARGET_PROFILE}":
        _fail(SPPFLR1_INPUT, 1)
    try:
        text = cmdline.decode("ascii")
    except UnicodeDecodeError:
        _fail(SPPFLR1_INPUT, 1)
    match = _CMDLINE.fullmatch(text)
    if match is None:
        _fail(SPPFLR1_INPUT, 1)
    data_uuid, hash_uuid, root_hash, challenge, run, plan, binding_uuid = match.groups()
    expected = (
        "ro rdinit=/spp-diag-handoff init=/usr/lib/spp/spp-diag-controller root=/dev/mapper/spp-diag-root "
        f"rootfstype=squashfs ip=off ima_policy=critical_data spp_diag.root_data=PARTUUID={data_uuid} "
        f"spp_diag.root_hash=PARTUUID={hash_uuid} spp_diag.roothash={root_hash} sol_spp_diag.challenge={challenge} "
        f"sol_spp_diag.run={run} sol_spp_diag.control_plan={plan} -- sol_spp_diag.target_profile={TARGET_PROFILE} "
        f"sol_spp_diag.binding_partuuid={binding_uuid}"
    )
    if (
        text != expected
        or argv[2] != f"sol_spp_diag.binding_partuuid={binding_uuid}"
        or len({data_uuid, hash_uuid, binding_uuid}) != 3
        or any(_PARTUUID.fullmatch(value) is None for value in (data_uuid, hash_uuid, binding_uuid))
    ):
        _fail(SPPFLR1_INPUT, 1)
    return BootInputs(data_uuid, hash_uuid, root_hash, binding_uuid, ControllerIdentity(bytes.fromhex(challenge), bytes.fromhex(run), bytes.fromhex(plan)))


def parse_binding_record(data: bytes, boot: BootInputs) -> ControllerIdentity:
    """Validate SPPBND1: header, seven-key canonical JSON, domain digest and zero tail."""

    if type(data) is not bytes or len(data) != BINDING_SIZE:
        _fail(SPPFLR1_BINDING, 1)
    try:
        magic, version, reserved, length = struct.unpack(">8sHHI", data[:16])
    except struct.error:
        _fail(SPPFLR1_BINDING, 1)
    end = 16 + length
    if magic != BINDING_MAGIC or version != BINDING_VERSION or reserved != 0 or not 2 <= length <= BINDING_SIZE - 48:
        _fail(SPPFLR1_BINDING, 1)
    prefix, digest = data[:end], data[end:end + 32]
    if digest != hashlib.sha256(BINDING_DOMAIN + prefix).digest() or any(data[end + 32:]):
        _fail(SPPFLR1_BINDING, 1)
    try:
        record = canonical_loads(data[16:end])
    except Exception:
        _fail(SPPFLR1_BINDING, 1)
    keys = {"challenge", "control_plan_address", "image_binding_address", "input_closure_address", "run_identity", "schema", "target_profile_id"}
    if type(record) is not dict or set(record) != keys or record["schema"] != "sol-spp-diag-runtime-late-binding/v1" or record["target_profile_id"] != TARGET_PROFILE:
        _fail(SPPFLR1_BINDING, 1)
    if record["challenge"] != boot.identity.challenge.hex() or record["run_identity"] != boot.identity.run_identity.hex() or record["control_plan_address"] != boot.identity.control_plan_address.hex():
        _fail(SPPFLR1_BINDING, 1)
    if any(type(record[name]) is not str or re.fullmatch(r"[0-9a-f]{64}", record[name]) is None for name in ("image_binding_address", "input_closure_address")):
        _fail(SPPFLR1_BINDING, 1)
    return ControllerIdentity(boot.identity.challenge, boot.identity.run_identity, boot.identity.control_plan_address, record["image_binding_address"])


def parse_control_plan(data: bytes, expected_address: bytes) -> dict:
    if type(data) is not bytes or len(data) > MAX_PLAN_BYTES:
        _fail(SPPFLR1_INPUT, 1)
    if hashlib.sha256(DOMAIN_CONTROL_PLAN + data).digest() != expected_address:
        _fail(SPPFLR1_BINDING, 1)
    try:
        plan = canonical_loads(data)
    except Exception:
        _fail(SPPFLR1_INPUT, 1)
    if type(plan) is not dict or frozenset(plan) != _PLAN_KEYS or plan.get("schema") != _PLAN_SCHEMA or tuple(plan.get("phase_order", ())) != PHASE_NAMES:
        _fail(SPPFLR1_INPUT, 1)
    fixed = {
        "pre_release": {"denied_exec_path_hex": "/usr/local/libexec/solstone/pre-release-denied".encode().hex()},
        "cold_start": {"exec_path_hex": _CUDA.encode().hex()},
        "poison_import": {"path_hex": _POISONS[0].encode().hex()},
        "poison_module": {"path_hex": _POISONS[1].encode().hex()},
        "poison_library": {"path_hex": _POISONS[2].encode().hex()},
        "writable_exec": {"path_hex": _EXEC_DENIALS[0].encode().hex()},
        "attached_disk_exec": {"path_hex": _EXEC_DENIALS[1].encode().hex()},
        "remote_code": {"exec_path_hex": _EXEC_DENIALS[2].encode().hex()},
    }
    if any(plan.get(key) != value for key, value in fixed.items()):
        _fail(SPPFLR1_POLICY, 1)
    synthetic = plan.get("synthetic_inference")
    jit = plan.get("jit_cache")
    endpoints = (
        ("remote_package", _NETWORKS[0]), ("remote_model", _NETWORKS[1]), ("remote_plugin", _NETWORKS[2]),
    )
    if (
        type(synthetic) is not dict
        or set(synthetic) != {"gpu_witness_policy_address", "model_path_hex", "model_sha256", "output_oracle_address"}
        or synthetic["model_path_hex"] != _MODEL.encode().hex()
        or synthetic["model_sha256"] != _MODEL_FIXTURE_SHA256
        or any(type(synthetic[key]) is not str or re.fullmatch(r"[0-9a-f]{64}", synthetic[key]) is None for key in ("gpu_witness_policy_address", "output_oracle_address"))
        or type(jit) is not dict
        or set(jit) != {"object_sha256", "path_hex"}
        or jit["path_hex"] != _JIT.encode().hex()
        or type(jit["object_sha256"]) is not str
        or re.fullmatch(r"[0-9a-f]{64}", jit["object_sha256"]) is None
    ):
        _fail(SPPFLR1_POLICY, 1)
    for key, (family, _kind, host, port, operation) in endpoints:
        endpoint = plan.get(key)
        if (
            type(endpoint) is not dict
            or set(endpoint) != {"address_hex", "family", "operation", "port"}
            or endpoint["family"] != family
            or endpoint["operation"] != operation
            or endpoint["port"] != port
            or endpoint["address_hex"] != socket.inet_pton(family, host).hex()
        ):
            _fail(SPPFLR1_POLICY, 1)
    return plan


def _read_regular(path: str, cap: int) -> bytes:
    node = os.lstat(path)
    if not stat.S_ISREG(node.st_mode) or stat.S_ISLNK(node.st_mode) or node.st_nlink != 1 or node.st_size > cap:
        raise OSError("not a bounded regular file")
    if hasattr(os, "listxattr") and os.listxattr(path, follow_symlinks=False):
        raise OSError("unexpected file capability/xattr")
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (node.st_dev, node.st_ino):
            raise OSError("file changed")
        parts, total = [], 0
        while total <= cap:
            chunk = os.read(fd, min(65536, cap + 1 - total))
            if not chunk:
                return b"".join(parts)
            parts.append(chunk)
            total += len(chunk)
        raise OSError("file cap")
    finally:
        os.close(fd)


def _read_fd(fd: int, cap: int) -> bytes:
    """Perform the one bounded post-SEAL stream read from the inherited fd."""

    if cap < 0:
        raise ValueError("negative stream cap")
    return os.read(fd, cap)


def _collect_and_export(ops: ControllerOps, identity: ControllerIdentity, trace: bytes, output: bytes) -> None:
    """Post-seal order is fixed; no raw child stdout is evidence except helper TLV."""

    deadline = ops.monotonic() + _PHASE_DEADLINE_SECONDS
    gpu = _child(ops, "gpu-helper", (_GPU_HELPER, identity.challenge.hex(), identity.run_identity.hex()), deadline, _CHILD_CAPTURE_BYTES, 15, SPPFLR1_GPU).stdout
    try:
        ak_pem = ops.read_file(_AK_PEM, _CHILD_CAPTURE_BYTES)
        ak_tpmt = ops.read_file(_AK_TPMT, _CHILD_CAPTURE_BYTES)
        hcla = ops.read_file(_HCLA, _CHILD_CAPTURE_BYTES)
        firmware = ops.read_file(_FIRMWARE, _CHILD_CAPTURE_BYTES)
        ima_before = ops.read_file(_IMA, _CHILD_CAPTURE_BYTES)
    except Exception:
        _fail(SPPFLR1_IMA, 15)
    inner_rows = {
        "ak-tpmt-public.bin": ak_tpmt,
        "firmware-event-log.sha256": hashlib.sha256(firmware).digest(),
        "gpu-evidence.sha256": hashlib.sha256(gpu).digest(),
        "ima-measurements.sha256": hashlib.sha256(ima_before).digest(),
        "manifest.json": canonical_dumps({"schema": "sol-spp-diag-inner-receipt/v1", "terminal": "last"}),
        "synthetic-output.bin": output,
        "terminal-frame.bin": trace[-128:],
    }
    inventory = [{"name": name, "sha256": hashlib.sha256(inner_rows[name]).hexdigest()} for name in sorted(inner_rows)]
    receipt = canonical_dumps({"schema": "sol-spp-diag-inner-receipt/v1", "rows": inventory})
    receipt_digest = inner_receipt_digest(
        schema="sol-spp-diag-inner-receipt/v1", node_kind="diagnostic_receipt", artifact_state="sealed",
        challenge=identity.challenge.hex(), run_identity=identity.run_identity.hex(),
        signed_image_binding_address=identity.signed_image_binding_address, target_profile_id=TARGET_PROFILE,
        control_plan_address=identity.control_plan_address.hex(), inventory=inventory,
    )
    invocation = build_quote_invocation(
        challenge=identity.challenge, run_identity=identity.run_identity, inner_receipt_digest=receipt_digest,
        signed_image_binding_address=identity.signed_image_binding_address, target_profile_id=TARGET_PROFILE,
        control_plan_address=identity.control_plan_address.hex(),
    )
    try:
        run_quote(QuoteOps(run_tool=lambda argv, _env, seconds, cap: ops.run_child("tpm-quote", argv, ops.monotonic() + seconds, cap)), invocation)
        quote_msg = ops.read_file("/run/spp-diag/quote.msg", _CHILD_CAPTURE_BYTES)
        quote_sig = ops.read_file("/run/spp-diag/quote.sig", _CHILD_CAPTURE_BYTES)
        quote_pcrs = ops.read_file("/run/spp-diag/quote.pcrs", _CHILD_CAPTURE_BYTES)
        ima_after = ops.read_file(_IMA, _CHILD_CAPTURE_BYTES)
    except Exception:
        _fail(SPPFLR1_TPM, 15)
    if ima_after != ima_before:
        _fail(SPPFLR1_IMA, 15)
    members = {
        "ak-public.pem": ak_pem, "firmware-event-log.bin": firmware, "gpu-evidence.tlv": gpu, "hcla.bin": hcla,
        "ima-measurements.bin": ima_after, "inner-receipt/ak-tpmt-public.bin": inner_rows["ak-tpmt-public.bin"],
        "inner-receipt/firmware-event-log.sha256": inner_rows["firmware-event-log.sha256"],
        "inner-receipt/gpu-evidence.sha256": inner_rows["gpu-evidence.sha256"],
        "inner-receipt/ima-measurements.sha256": inner_rows["ima-measurements.sha256"],
        "inner-receipt/manifest.json": receipt, "inner-receipt/synthetic-output.bin": output,
        "inner-receipt/terminal-frame.bin": inner_rows["terminal-frame.bin"], "inner-receipt/trace.bin": trace,
        "quote.msg": quote_msg, "quote.pcrs": quote_pcrs, "quote.sig": quote_sig,
    }
    try:
        stream = build_export_stream(members=members, challenge=identity.challenge, run_identity=identity.run_identity)
        export_and_poweroff(ExportOps(
            write_serial=lambda data: _uart_once(ops, data), wait_writable=lambda end: ops.monotonic() < end,
            serial_queue_bytes=lambda: 0, monotonic=ops.monotonic, request_poweroff_hardware=ops.request_poweroff,
        ), stream)
    except Exception:
        _fail(SPPFLR1_EXPORT, 15)


def _uart_once(ops: ControllerOps, data: bytes) -> int:
    ops.write_uart(data, ops.monotonic() + _FAILURE_UART_SECONDS)
    return len(data)


def _verify_pid_fds() -> None:
    if os.getpid() != 1:
        _fail(SPPFLR1_INPUT, 1)
    status = _read_regular("/proc/self/status", 65536)
    if re.search(br"^Tgid:\s*1$", status, re.MULTILINE) is None:
        _fail(SPPFLR1_INPUT, 1)
    if {int(name) for name in os.listdir("/proc/self/fd") if name.isdecimal()} != {0, 1, 2, 3, 4, 5}:
        _fail(SPPFLR1_INPUT, 1)
    for fd, access in ((CONTROL_FD, os.O_WRONLY), (STREAM_FD, os.O_RDONLY), (UART_FD, os.O_WRONLY)):
        if fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE != access:
            _fail(SPPFLR1_INPUT, 1)
        fcntl.fcntl(fd, fcntl.F_SETFD, 0)
        if fcntl.fcntl(fd, fcntl.F_GETFD) != 0:
            _fail(SPPFLR1_INPUT, 1)


def _configure_uart() -> None:
    inherited, node = os.fstat(UART_FD), os.stat(UART_PATH)
    flags = fcntl.fcntl(UART_FD, fcntl.F_GETFL)
    if (not stat.S_ISCHR(inherited.st_mode) or (os.major(inherited.st_rdev), os.minor(inherited.st_rdev)) != (UART_MAJOR, UART_MINOR)
            or (inherited.st_dev, inherited.st_ino) != (node.st_dev, node.st_ino)
            or flags & os.O_ACCMODE != os.O_WRONLY or not flags & os.O_NONBLOCK):
        _fail(SPPFLR1_INPUT, 1)
    attrs = termios.tcgetattr(UART_FD)
    attrs[0], attrs[1], attrs[2], attrs[3] = 0, 0, termios.CLOCAL | termios.CREAD | termios.CS8, 0
    attrs[4], attrs[5] = termios.B115200, termios.B115200
    attrs[6][termios.VMIN], attrs[6][termios.VTIME] = 1, 0
    termios.tcsetattr(UART_FD, termios.TCSANOW, attrs)
    actual = termios.tcgetattr(UART_FD)
    if actual[0] != 0 or actual[1] != 0 or actual[2] != attrs[2] or actual[3] != 0 or actual[4] != termios.B115200 or actual[5] != termios.B115200 or actual[6][termios.VMIN] != 1 or actual[6][termios.VTIME] != 0:
        _fail(SPPFLR1_INPUT, 1)


def _real_direct(action: str, value: object) -> bool:
    try:
        if action == "poison-open":
            fd = os.open(str(value), os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
            os.close(fd)
            return False
        if action == "network":
            family, kind, host, port, operation = value  # type: ignore[misc]
            sock = socket.socket(family, kind)
            try:
                if operation == "connect": sock.connect((host, port))
                else: sock.sendmsg([b""], [], 0, (host, port))
            finally: sock.close()
            return False
        if action == "exec-denial":
            try:
                os.execve(str(value), [str(value)], {})
            except OSError as exc:
                return exc.errno in (errno.EACCES, errno.EPERM)
            return False
        if action == "jit":
            fd = os.open(str(value), os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
            try:
                region = mmap.mmap(fd, os.fstat(fd).st_size, flags=mmap.MAP_PRIVATE, prot=mmap.PROT_READ)
                try:
                    region.mprotect(mmap.PROT_READ | mmap.PROT_EXEC)
                finally:
                    region.close()
            finally:
                os.close(fd)
            return True
    except OSError as exc:
        return action in ("poison-open", "network") and exc.errno in (errno.EACCES, errno.EPERM, errno.ENOENT)
    return False


def _reap_adopted(deadline: float) -> None:
    # PID 1 must reap direct and adopted descendants after each fixed child.
    while time.monotonic() < deadline:
        active = False
        while True:
            try:
                pid, _status = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                return
            if pid == 0:
                active = True
                break
        if active:
            time.sleep(0.002)


def _drain_child_pipes(open_fds: set[int], captures: dict[int, bytearray], cap: int) -> bool:
    """Drain bounded child output while it is running, preventing pipe deadlock."""

    if not open_fds:
        return True
    readable, _writable, _errors = select.select(list(open_fds), [], [], 0)
    for descriptor in readable:
        while True:
            try:
                chunk = os.read(descriptor, 65536)
            except BlockingIOError:
                break
            if not chunk:
                open_fds.remove(descriptor)
                os.close(descriptor)
                break
            captures[descriptor].extend(chunk)
            if len(captures[descriptor]) > cap:
                return False
    return True


def _run_fixed_child(name: str, argv: tuple[str, ...], deadline: float, cap: int) -> ChildResult:
    if name == "apparmor":
        valid = argv == (_PARSER, "-r", "-K", "--abort-on-error", _PROFILE_FILE)
    elif name == "cuda-cold":
        valid = argv == (_CUDA, "cold")
    elif name == "cuda-infer":
        valid = len(argv) == 3 and argv[:2] == (_CUDA, "infer") and re.fullmatch(r"[0-9a-f]{64}", argv[2]) is not None
    elif name == "gpu-helper":
        valid = (
            len(argv) == 3
            and argv[0] == _GPU_HELPER
            and all(re.fullmatch(r"[0-9a-f]{64}", value) is not None for value in argv[1:])
        )
    elif name == "tpm-quote":
        valid = (
            len(argv) == 17
            and argv[:6] == (_TPM_QUOTE, "-c", "0x81000003", "-l", _TPM_PCR_LIST, "-q")
            and re.fullmatch(r"[0-9a-f]{64}", argv[6]) is not None
            and argv[7:] == (
                "-g", "sha256", "--scheme", "rsassa", "-m", "/run/spp-diag/quote.msg",
                "-s", "/run/spp-diag/quote.sig", "-o", "/run/spp-diag/quote.pcrs",
            )
        )
    else:
        valid = False
    if not valid:
        raise OSError("undeclared child")
    out_r, out_w = os.pipe2(os.O_CLOEXEC); err_r, err_w = os.pipe2(os.O_CLOEXEC)
    pid = os.fork()
    if pid == 0:
        try:
            os.setsid()
            null = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
            os.dup2(null, 0); os.dup2(out_w, 1); os.dup2(err_w, 2)
            for fd in (out_r, out_w, err_r, err_w, null):
                if fd > 2: os.close(fd)
            for fd in (CONTROL_FD, STREAM_FD, UART_FD):
                try:
                    os.close(fd)
                except OSError:
                    pass
            os.execve(argv[0], list(argv), {"LANG": "C", "LC_ALL": "C", "TZ": "UTC"})
        except BaseException: os._exit(127)
    os.close(out_w); os.close(err_w)
    os.set_blocking(out_r, False)
    os.set_blocking(err_r, False)
    captures = {out_r: bytearray(), err_r: bytearray()}
    open_fds = {out_r, err_r}
    status: int | None = None
    timed_out = False
    overflow = False
    term_deadline: float | None = None
    kill_deadline: float | None = None
    try:
        while status is None or open_fds:
            if status is None:
                waited, candidate = os.waitpid(pid, os.WNOHANG)
                if waited == pid:
                    status = candidate
            if not _drain_child_pipes(open_fds, captures, cap):
                overflow = True
            now = time.monotonic()
            if status is None and (overflow or now >= deadline) and term_deadline is None:
                timed_out = timed_out or now >= deadline
                try:
                    os.killpg(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                term_deadline = now + _TERM_GRACE
            if status is None and term_deadline is not None and now >= term_deadline and kill_deadline is None:
                try:
                    os.killpg(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                kill_deadline = now + _POST_KILL
            if status is None and kill_deadline is not None and now >= kill_deadline:
                raise OSError("child not reaped after SIGKILL")
            if status is not None and not open_fds:
                break
            time.sleep(0.002)
        stdout, stderr = bytes(captures[out_r]), bytes(captures[err_r])
    finally:
        for descriptor in tuple(open_fds):
            os.close(descriptor)
        _reap_adopted(time.monotonic() + _POST_KILL)
    if status is None or timed_out or overflow or not os.WIFEXITED(status):
        return ChildResult(255)
    return ChildResult(os.WEXITSTATUS(status), stdout, stderr)


def _write_all(fd: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        count = os.write(fd, data[offset:])
        if count <= 0: raise OSError("short write")
        offset += count


def _write_path(path: str, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CLOEXEC)
    try: _write_all(fd, data)
    finally: os.close(fd)


def _mount_scratch_once() -> None:
    """Mount the controller's sole scratch tmpfs and read it back from mountinfo."""

    try:
        os.mkdir(_SCRATCH, 0o700)
    except FileExistsError:
        _fail(SPPFLR1_INPUT, 1)
    libc = ctypes.CDLL(None, use_errno=True)
    # MS_NOSUID | MS_NODEV | MS_NOEXEC.  The controller never mounts anything else.
    flags = 0x2 | 0x4 | 0x8
    if libc.mount(b"tmpfs", os.fsencode(_SCRATCH), b"tmpfs", flags, b"size=16777216,mode=0700") != 0:
        _fail(SPPFLR1_INPUT, 1)
    try:
        mountinfo = _read_regular("/proc/self/mountinfo", 1_048_576).decode("ascii")
    except Exception:
        _fail(SPPFLR1_INPUT, 1)
    if not any(f" {_SCRATCH} " in line and " - tmpfs tmpfs " in line for line in mountinfo.splitlines()):
        _fail(SPPFLR1_INPUT, 1)


def _preflight_fixture_contract(boot: BootInputs, model: bytes) -> None:
    """Keep fixed root fixture and poison/canary identities out of signed plan choice."""

    if len({boot.root_data_partuuid, boot.root_hash_partuuid, boot.binding_partuuid}) != 3:
        _fail(SPPFLR1_INPUT, 1)
    try:
        blocks = tuple(
            os.stat(BINDING_PATH_PREFIX + value)
            for value in (boot.root_data_partuuid, boot.root_hash_partuuid, boot.binding_partuuid)
        )
    except Exception:
        _fail(SPPFLR1_INPUT, 1)
    if (
        any(not stat.S_ISBLK(node.st_mode) for node in blocks)
        or len({node.st_rdev for node in blocks}) != 3
        or hashlib.sha256(model).hexdigest() != _MODEL_FIXTURE_SHA256
    ):
        _fail(SPPFLR1_INPUT, 1)
    # JIT is an immutable fixture; poison targets and execution canaries must remain
    # absent/known paths until their literal direct operations enter phases 4--13.
    if not stat.S_ISREG(os.stat(_JIT).st_mode) or any(os.path.lexists(path) for path in _POISONS + _EXEC_DENIALS):
        _fail(SPPFLR1_POLICY, 1)


def _poweroff() -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.reboot.argtypes = [ctypes.c_int]
    libc.reboot.restype = ctypes.c_int
    if libc.reboot(_LINUX_REBOOT_CMD_POWER_OFF) != 0:
        raise OSError(ctypes.get_errno(), "poweroff failed")
    raise OSError("poweroff returned")


def real_controller_ops() -> ControllerOps:
    def uart(data: bytes, deadline: float) -> None:
        offset = 0
        while offset < len(data):
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([], [UART_FD], [], remaining)[1]: raise OSError("UART deadline")
            count = os.write(UART_FD, data[offset:])
            if count <= 0: raise OSError("UART write")
            offset += count
    return ControllerOps(
        write_control=lambda data: _write_all(CONTROL_FD, data), read_stream=lambda cap: _read_fd(STREAM_FD, cap),
        monotonic=time.monotonic, run_child=_run_fixed_child, direct_operation=_real_direct, read_file=_read_regular,
        write_file=_write_path, write_uart=uart, request_poweroff=_poweroff,
        verify_pid_fds=_verify_pid_fds, configure_uart=_configure_uart, mount_scratch=_mount_scratch_once,
        preflight_fixture=_preflight_fixture_contract,
    )


def _preflight(ops: ControllerOps, boot: BootInputs) -> tuple[ControllerIdentity, bytes]:
    try:
        binding = ops.read_file(BINDING_PATH_PREFIX + boot.binding_partuuid, BINDING_SIZE)
    except Exception:
        _fail(SPPFLR1_BINDING, 1)
    identity = parse_binding_record(binding, boot)
    try:
        plan = ops.read_file("/usr/share/spp-diag/control-plan.json", MAX_PLAN_BYTES)
    except Exception:
        _fail(SPPFLR1_INPUT, 1)
    parse_control_plan(plan, identity.control_plan_address)
    try:
        model = ops.read_file(_MODEL, MAX_STREAM_BYTES)
    except Exception:
        _fail(SPPFLR1_INPUT, 1)
    try:
        _output_oracle(model, identity.challenge, identity.run_identity)  # hold and derive before phase 3; never reopen.
    except Exception:
        _fail(SPPFLR1_INPUT, 1)
    try:
        ops.preflight_fixture(boot, model)
        ops.mount_scratch()
    except ControllerFault:
        raise
    except Exception:
        _fail(SPPFLR1_INPUT, 1)
    _child(ops, "apparmor", (_PARSER, "-r", "-K", "--abort-on-error", _PROFILE_FILE), ops.monotonic() + 30.0, _CHILD_CAPTURE_BYTES, 1, SPPFLR1_POLICY)
    try:
        ops.write_file("/proc/self/attr/current", ("changeprofile " + _PROFILE_NAME).encode())
    except Exception:
        _fail(SPPFLR1_POLICY, 1)
    return identity, model


def _fail_stop(ops: ControllerOps, fault: ControllerFault, identity: ControllerIdentity | None, uart_usable: bool, production: bool) -> int:
    """Emit at most one identity-bound terminal, then request non-returning poweroff."""

    if identity is not None and uart_usable:
        try:
            record = encode_failure_terminal(fault.reason_code, fault.phase, identity.challenge, identity.run_identity)
            ops.write_uart(record, ops.monotonic() + _FAILURE_UART_SECONDS)
        except Exception:
            pass
    try:
        ops.request_poweroff()
    except Exception:
        pass
    if production:
        os._exit(1)
    return 1


def main(argv: list[str] | None = None, ops: ControllerOps | None = None) -> int:
    """Real entrypoint: returned poweroff is fail-stop and emits no second record."""

    production = ops is None
    ops = real_controller_ops() if ops is None else ops
    identity: ControllerIdentity | None = None
    uart_usable = False
    try:
        boot = parse_boot_inputs(list(os.sys.argv if argv is None else argv), ops.read_file("/proc/cmdline", 4096))
        identity = boot.identity
        ops.verify_pid_fds()
        ops.configure_uart()  # setup failure is poweroff-only: UART is not usable yet.
        uart_usable = True
        identity, model = _preflight(ops, boot)
        trace, output = run_controller(ops, identity, model_bytes=model)
        _collect_and_export(ops, identity, trace, output)
        _fail(SPPFLR1_EXPORT, 15)
    except ControllerFault as fault:
        return _fail_stop(ops, fault, identity, uart_usable, production)
    except Exception:
        reason = SPPFLR1_INPUT if identity is None else SPPFLR1_EXPORT
        return _fail_stop(ops, ControllerFault(reason, 1), identity, uart_usable, production)


if __name__ == "__main__":
    raise SystemExit(main())
