#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Focused unit tests for the isolated SPP PID-1 controller core.

These use recording operations.  They deliberately do not claim a live kernel,
AppArmor, UART, or multiprocess-appliance integration environment.
"""

from __future__ import annotations

import ast
import errno
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from conf_proc_spp_diag_controller import (  # noqa: E402
    BINDING_DOMAIN, BINDING_MAGIC, CONTROLLER_PATH, ChildResult, ControllerFault, ControllerIdentity,
    ControllerOps, TARGET_PROFILE, _CUDA, _EXEC_DENIALS, _JIT, _MODEL, _MODEL_FIXTURE_SHA256,
    _POISONS, _output_oracle, encode_command, parse_binding_record, parse_boot_inputs, parse_control_plan,
    main as controller_main, run_controller,
)
from conf_proc_json import canonical_dumps  # noqa: E402
from conf_proc_spp_diagbundle_protocol import DOMAIN_CONTROL_PLAN  # noqa: E402
from conf_proc_spp_diag_failure_terminal_reasons import (  # noqa: E402
    SPPFLR1_BINDING, SPPFLR1_CHILD, SPPFLR1_GPU, SPPFLR1_IMA, SPPFLR1_INPUT, SPPFLR1_POLICY, SPPFLR1_TRACE,
    parse_failure_terminal,
)


IDENTITY = ControllerIdentity(b"\x01" * 32, b"\x02" * 32, b"\x03" * 32, "ab" * 32)
MODEL = b"sol-spp-semantic-fixture-model-v1"


class Recorder:
    def __init__(self) -> None:
        self.clock = 1000.0
        self.writes: list[bytes] = []
        self.children: list[tuple[str, tuple[str, ...]]] = []
        self.direct: list[tuple[str, object]] = []
        self.reads = 0
        self.fail_child: str | None = None
        self.fail_direct: str | None = None
        self.fail_write_at: int | None = None
        self.files: dict[str, bytes] = {}
        self.fail_reads: set[str] = set()
        self.read_errnos: dict[str, int] = {}
        self.bootstrap: list[str] = []
        self.uart: list[bytes] = []
        self.poweroffs = 0

    def monotonic(self) -> float:
        self.clock += 0.001
        return self.clock

    def write_control(self, data: bytes) -> None:
        if self.fail_write_at == len(self.writes):
            raise OSError("forced trace write failure")
        self.writes.append(data)

    def read_stream(self, cap: int) -> bytes:
        self.reads += 1
        assert cap == 8 * 1024 * 1024
        return b"sealed trace"

    def run_child(self, name: str, argv: tuple[str, ...], _deadline: float, _cap: int) -> ChildResult:
        self.children.append((name, argv))
        if name == self.fail_child:
            return ChildResult(1)
        if name == "cuda-infer":
            seed = bytes.fromhex(argv[2])
            output = bytearray(seed)
            for index, value in enumerate(self.files.get(_MODEL, MODEL)):
                output[index % 32] ^= value
            return ChildResult(0, struct.pack(">8sHHI32s", b"SPPGPUO1", 1, 1, 32, bytes(output)))
        if name == "gpu-helper":
            return ChildResult(0, b"SPPGPU1\0record")
        return ChildResult(0)

    def direct_operation(self, action: str, value: object) -> bool:
        self.direct.append((action, value))
        return action != self.fail_direct

    def read_file(self, path: str, _cap: int) -> bytes:
        if path in self.read_errnos:
            raise OSError(self.read_errnos[path], path)
        if path in self.fail_reads:
            raise OSError(path)
        return self.files[path]

    def write_uart(self, data: bytes, _deadline: float) -> None:
        self.uart.append(data)

    def poweroff(self) -> None:
        self.poweroffs += 1

    def ops(self) -> ControllerOps:
        return ControllerOps(
            write_control=self.write_control, read_stream=self.read_stream, monotonic=self.monotonic,
            run_child=self.run_child, direct_operation=self.direct_operation,
            read_file=self.read_file, write_file=lambda _path, _data: self.bootstrap.append("changeprofile"),
            write_uart=self.write_uart, request_poweroff=self.poweroff,
            verify_pid_fds=lambda: self.bootstrap.append("fds"),
            configure_uart=lambda: self.bootstrap.append("uart"),
            mount_scratch=lambda: self.bootstrap.append("scratch"),
            preflight_fixture=lambda _boot, _model: self.bootstrap.append("fixtures"),
        )


def _expect(reason: str, callback) -> None:
    try:
        callback()
    except ControllerFault as exc:
        assert exc.reason_code == reason
    else:
        raise AssertionError(f"expected {reason}")


def test_command_wire() -> None:
    data = encode_command(1, 2, IDENTITY.challenge, IDENTITY.run_identity, IDENTITY.control_plan_address)
    assert len(data) == 128 and data[:8] == b"SPPCMD1\0"
    assert int.from_bytes(data[10:12], "big") == 1
    assert int.from_bytes(data[112:114], "big") == 2
    assert data[114:] == b"\0" * 14


def test_fixed_choreography_and_seal_before_read() -> None:
    recorder = Recorder()
    trace, output = run_controller(recorder.ops(), IDENTITY, model_bytes=MODEL)
    assert trace == b"sealed trace" and output == _output_oracle(MODEL, IDENTITY.challenge, IDENTITY.run_identity)
    assert [int.from_bytes(data[112:114], "big") for data in recorder.writes] == list(range(2, 16))
    assert [int.from_bytes(data[10:12], "big") for data in recorder.writes] == [1] * 13 + [2]
    assert recorder.reads == 1
    assert [name for name, _argv in recorder.children] == ["cuda-cold", "cuda-infer"]
    assert recorder.children[0][1] == (_CUDA, "cold")
    assert [name for name, _value in recorder.direct] == [
        "poison-open", "poison-open", "poison-open", "network", "network", "network",
        "exec-denial", "exec-denial", "exec-denial", "jit",
    ]


def test_rejecting_twins_map_to_closed_reasons() -> None:
    child = Recorder(); child.fail_child = "cuda-cold"
    _expect(SPPFLR1_CHILD, lambda: run_controller(child.ops(), IDENTITY, model_bytes=MODEL))
    gpu = Recorder()
    original = gpu.run_child
    gpu.run_child = lambda name, argv, deadline, cap: ChildResult(0, b"wrong") if name == "cuda-infer" else original(name, argv, deadline, cap)
    _expect(SPPFLR1_GPU, lambda: run_controller(gpu.ops(), IDENTITY, model_bytes=MODEL))
    policy = Recorder(); policy.fail_direct = "network"
    _expect(SPPFLR1_POLICY, lambda: run_controller(policy.ops(), IDENTITY, model_bytes=MODEL))
    poison = Recorder(); poison.fail_direct = "poison-open"
    _expect(SPPFLR1_TRACE, lambda: run_controller(poison.ops(), IDENTITY, model_bytes=MODEL))
    trace = Recorder(); trace.fail_write_at = 4
    _expect(SPPFLR1_TRACE, lambda: run_controller(trace.ops(), IDENTITY, model_bytes=MODEL))


def _plan() -> bytes:
    return canonical_dumps({
        "schema": "sol-spp-diag-trace-control-plan-v1",
        "phase_order": ["init", "cold_start", "synthetic_inference", "poison_import", "poison_module", "poison_library", "remote_package", "remote_model", "remote_plugin", "writable_exec", "attached_disk_exec", "remote_code", "jit_cache", "evidence_finalize"],
        "pre_release": {"denied_exec_path_hex": "/usr/local/libexec/solstone/pre-release-denied".encode().hex()},
        "cold_start": {"exec_path_hex": _CUDA.encode().hex()},
        "synthetic_inference": {"gpu_witness_policy_address": "44" * 32, "model_path_hex": _MODEL.encode().hex(), "model_sha256": _MODEL_FIXTURE_SHA256, "output_oracle_address": "55" * 32},
        "poison_import": {"path_hex": _POISONS[0].encode().hex()},
        "poison_module": {"path_hex": _POISONS[1].encode().hex()},
        "poison_library": {"path_hex": _POISONS[2].encode().hex()},
        "remote_package": {"address_hex": socket.inet_pton(socket.AF_INET, "198.51.100.7").hex(), "family": int(socket.AF_INET), "operation": "connect", "port": 443},
        "remote_model": {"address_hex": socket.inet_pton(socket.AF_INET6, "2001:db8::8").hex(), "family": int(socket.AF_INET6), "operation": "connect", "port": 443},
        "remote_plugin": {"address_hex": socket.inet_pton(socket.AF_INET, "203.0.113.9").hex(), "family": int(socket.AF_INET), "operation": "sendmsg", "port": 443},
        "writable_exec": {"path_hex": _EXEC_DENIALS[0].encode().hex()},
        "attached_disk_exec": {"path_hex": _EXEC_DENIALS[1].encode().hex()},
        "remote_code": {"exec_path_hex": _EXEC_DENIALS[2].encode().hex()},
        "jit_cache": {"object_sha256": "66" * 32, "path_hex": _JIT.encode().hex()},
    })


def test_cmdline_plan_and_4096_binding_reject_twins() -> None:
    data_uuid = "11111111-1111-4111-8111-111111111111"
    hash_uuid = "22222222-2222-4222-8222-222222222222"
    binding_uuid = "33333333-3333-4333-8333-333333333333"
    plan = _plan()
    address = hashlib.sha256(DOMAIN_CONTROL_PLAN + plan).hexdigest()
    cmdline = (
        f"ro rdinit=/spp-diag-handoff init=/usr/lib/spp/spp-diag-controller root=/dev/mapper/spp-diag-root rootfstype=squashfs ip=off ima_policy=critical_data spp_diag.root_data=PARTUUID={data_uuid} spp_diag.root_hash=PARTUUID={hash_uuid} spp_diag.roothash={'aa' * 32} sol_spp_diag.challenge={'11' * 32} sol_spp_diag.run={'22' * 32} sol_spp_diag.control_plan={address} -- sol_spp_diag.target_profile={TARGET_PROFILE} sol_spp_diag.binding_partuuid={binding_uuid}"
    ).encode()
    boot = parse_boot_inputs([CONTROLLER_PATH, f"sol_spp_diag.target_profile={TARGET_PROFILE}", f"sol_spp_diag.binding_partuuid={binding_uuid}"], cmdline)
    record_json = canonical_dumps({
        "challenge": "11" * 32, "control_plan_address": address, "image_binding_address": "77" * 32,
        "input_closure_address": "88" * 32, "run_identity": "22" * 32,
        "schema": "sol-spp-diag-runtime-late-binding/v1", "target_profile_id": TARGET_PROFILE,
    })
    prefix = struct.pack(">8sHHI", BINDING_MAGIC, 1, 0, len(record_json)) + record_json
    record = prefix + hashlib.sha256(BINDING_DOMAIN + prefix).digest()
    record += b"\0" * (4096 - len(record))
    identity = parse_binding_record(record, boot)
    assert identity.signed_image_binding_address == "77" * 32
    assert parse_control_plan(plan, identity.control_plan_address)["schema"] == "sol-spp-diag-trace-control-plan-v1"
    broken = bytearray(record); broken[-1] = 1
    _expect(SPPFLR1_BINDING, lambda: parse_binding_record(bytes(broken), boot))
    mutated_value = json.loads(plan)
    mutated_value["remote_package"]["address_hex"] = "00" * 4
    mutated = canonical_dumps(mutated_value)
    _expect(SPPFLR1_POLICY, lambda: parse_control_plan(mutated, hashlib.sha256(DOMAIN_CONTROL_PLAN + mutated).digest()))


def _main_fixture(recorder: Recorder) -> list[str]:
    data_uuid = "11111111-1111-4111-8111-111111111111"
    hash_uuid = "22222222-2222-4222-8222-222222222222"
    binding_uuid = "33333333-3333-4333-8333-333333333333"
    plan = _plan()
    address = hashlib.sha256(DOMAIN_CONTROL_PLAN + plan).hexdigest()
    command_line = (
        f"ro rdinit=/spp-diag-handoff init=/usr/lib/spp/spp-diag-controller root=/dev/mapper/spp-diag-root rootfstype=squashfs ip=off ima_policy=critical_data spp_diag.root_data=PARTUUID={data_uuid} spp_diag.root_hash=PARTUUID={hash_uuid} spp_diag.roothash={'aa' * 32} sol_spp_diag.challenge={'11' * 32} sol_spp_diag.run={'22' * 32} sol_spp_diag.control_plan={address} -- sol_spp_diag.target_profile={TARGET_PROFILE} sol_spp_diag.binding_partuuid={binding_uuid}"
    ).encode()
    binding_json = canonical_dumps({
        "challenge": "11" * 32, "control_plan_address": address, "image_binding_address": "77" * 32,
        "input_closure_address": "88" * 32, "run_identity": "22" * 32,
        "schema": "sol-spp-diag-runtime-late-binding/v1", "target_profile_id": TARGET_PROFILE,
    })
    prefix = struct.pack(">8sHHI", BINDING_MAGIC, 1, 0, len(binding_json)) + binding_json
    binding = prefix + hashlib.sha256(BINDING_DOMAIN + prefix).digest()
    binding += b"\0" * (4096 - len(binding))
    recorder.files = {
        "/proc/cmdline": command_line,
        f"/dev/disk/by-partuuid/{binding_uuid}": binding,
        "/usr/share/spp-diag/control-plan.json": plan,
        _MODEL: MODEL,
        "/run/spp-diag/ak-public.pem": b"AK PEM\n",
        "/run/spp-diag/ak-tpmt-public.bin": b"AKTPMT",
        "/run/spp-diag/hcla.bin": b"HCLA",
        "/sys/kernel/security/tpm0/binary_bios_measurements": b"FIRMWARE",
        "/sys/kernel/security/ima/ascii_runtime_measurements": b"IMA",
        "/run/spp-diag/quote.msg": b"MSG",
        "/run/spp-diag/quote.sig": b"SIG",
        "/run/spp-diag/quote.pcrs": b"PCRS",
    }
    return [CONTROLLER_PATH, f"sol_spp_diag.target_profile={TARGET_PROFILE}", f"sol_spp_diag.binding_partuuid={binding_uuid}"]


def test_main_uses_the_same_injected_production_core_and_one_failure_record() -> None:
    recorder = Recorder()
    assert controller_main(_main_fixture(recorder), recorder.ops()) == 1
    assert recorder.bootstrap == ["fds", "uart", "fixtures", "scratch", "changeprofile"]
    terminals = [data for data in recorder.uart if len(data) == 112 and data.startswith(b"SPPFLR1\0")]
    assert len(terminals) == 1
    assert parse_failure_terminal(terminals[0]).reason_code == 10  # returned poweroff is EXPORT
    assert recorder.poweroffs == 2


def test_uart_setup_and_collector_failures_fail_stop_without_second_record() -> None:
    uart = Recorder()
    argv = _main_fixture(uart)
    broken_ops = uart.ops()
    broken_ops.configure_uart = lambda: (_ for _ in ()).throw(ControllerFault(SPPFLR1_INPUT, 1))
    assert controller_main(argv, broken_ops) == 1
    assert not uart.uart and uart.poweroffs == 1

    collector = Recorder()
    argv = _main_fixture(collector)
    collector.read_errnos["/sys/kernel/security/tpm0/binary_bios_measurements"] = errno.ENOSPC
    assert controller_main(argv, collector.ops()) == 1
    terminals = [data for data in collector.uart if len(data) == 112 and data.startswith(b"SPPFLR1\0")]
    assert len(terminals) == 1
    assert parse_failure_terminal(terminals[0]).reason_code == 9  # IMA


def test_fd_uart_and_runner_source_contract() -> None:
    source = (ROOT / "conf_proc_spp_diag_controller.py").read_text(encoding="utf-8")
    for required in (
        "{0, 1, 2, 3, 4, 5}", "fcntl.F_SETFD", "fcntl.F_GETFD", "termios.B115200",
        "termios.VMIN", "termios.VTIME", "os.setsid()", "_TERM_GRACE", "_POST_KILL",
        "_drain_child_pipes", "os.killpg(pid, signal.SIGTERM)", "os.killpg(pid, signal.SIGKILL)",
        "read_stream=lambda cap: _read_fd(STREAM_FD, cap)", "return os.read(fd, cap)",
        "_LINUX_REBOOT_CMD_POWER_OFF", "libc.reboot(_LINUX_REBOOT_CMD_POWER_OFF)",
    ):
        assert required in source


def test_source_has_a_real_entrypoint_and_no_appraiser_import() -> None:
    source = (ROOT / "conf_proc_spp_diag_controller.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
        elif isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
    forbidden = {"conf_proc_spp_diag_trace_semantics", "conf_proc_spp_diag_attest", "conf_proc_spp_diag_gpu_evidence", "conf_proc_spp_diag_ima"}
    assert not imported & forbidden
    assert 'if __name__ == "__main__":' in source
    assert "raise SystemExit(main())" in source
    assert '"-r", "-K", "--abort-on-error"' in source
    assert "-Q" not in source
    for required in ("os.setsid", "os.waitpid(-1", "signal.SIGTERM", "signal.SIGKILL", "os.execve(str(value), [str(value)], {})"):
        assert required in source


def test_shipped_entrypoint_exact_eight_module_import_graph() -> None:
    """Source/reachability assertion for the extensionless installed controller."""

    expected = {
        "conf_proc_reasons.py", "conf_proc_json.py", "conf_proc_spp_diag_failure_terminal_reasons.py",
        "conf_proc_spp_diag_export.py", "conf_proc_spp_diag_export_reasons.py", "conf_proc_spp_diag_quote.py",
        "conf_proc_spp_diag_pcr.py", "conf_proc_spp_diagbundle_protocol.py",
    }
    pending = ["conf_proc_spp_diag_controller.py"]
    seen: set[str] = set()
    while pending:
        filename = pending.pop()
        if filename in seen:
            continue
        seen.add(filename)
        tree = ast.parse((ROOT / filename).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("conf_proc_"):
                candidate = node.module + ".py"
                if candidate in expected:
                    pending.append(candidate)
                else:
                    raise AssertionError(f"unexpected staged producer import: {candidate}")
    assert seen - {"conf_proc_spp_diag_controller.py"} == expected


TESTS = (
    test_command_wire,
    test_fixed_choreography_and_seal_before_read,
    test_rejecting_twins_map_to_closed_reasons,
    test_cmdline_plan_and_4096_binding_reject_twins,
    test_main_uses_the_same_injected_production_core_and_one_failure_record,
    test_uart_setup_and_collector_failures_fail_stop_without_second_record,
    test_fd_uart_and_runner_source_contract,
    test_source_has_a_real_entrypoint_and_no_appraiser_import,
    test_shipped_entrypoint_exact_eight_module_import_graph,
)


def main() -> int:
    for test in TESTS:
        test()
        print(f"ok   {test.__name__}")
    print(f"SPP diagnostic controller: ok ({len(TESTS)} tests)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
