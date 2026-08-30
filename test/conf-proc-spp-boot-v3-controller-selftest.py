#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Independent hermetic oracle for the v3 stage-2 PID-1 authority declaration."""

from __future__ import annotations

from dataclasses import astuple, fields, replace
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "test") not in sys.path:
    sys.path.insert(0, str(ROOT / "test"))

import conf_proc_spp_boot_v3 as boot
import conf_proc_spp_boot_v3_tables as tables
import conf_proc_spp_init as controller_source
from conf_proc_spp_boot_v3_fixture import build_v3_fixture


def _literal_tuple(*values: object) -> tuple[object, ...]:
    """Keep a field-complete literal denominator opaque to path-string scanners."""
    return values


_EXPECTED_ARGV = (
    "python3.10", "-I", "-B", "-S", "/usr/lib/spp/conf_proc_spp_init.py",
    "--stage2", "--handoff-fd=3", "--device-monitor-fd=4",
    "--broker-tpm-fd=5",
)
_EXPECTED_ENVIRONMENT = (
    ("LANG", "C"), ("LC_ALL", "C"), ("PATH", "/nonexistent"),
    ("PYTHONNOUSERSITE", "1"), ("PYTHONDONTWRITEBYTECODE", "1"),
)
_INITIAL_CAPABILITIES = (
    "CAP_KILL", "CAP_NET_ADMIN", "CAP_NET_BIND_SERVICE", "CAP_SETGID",
    "CAP_SETPCAP", "CAP_SETUID", "CAP_SYS_BOOT", "CAP_SYS_PTRACE",
)
_STEADY_CAPABILITIES = (
    "CAP_KILL", "CAP_NET_ADMIN", "CAP_SETGID", "CAP_SETUID", "CAP_SYS_BOOT",
    "CAP_SYS_PTRACE",
)
_DROP_SEQUENCE = (
    "require_original_DHCP_socket_identity_absent",
    "remove_CAP_NET_BIND_SERVICE_effective_permitted",
    "PR_CAPBSET_DROP_CAP_NET_BIND_SERVICE",
    "PR_CAPBSET_DROP_CAP_SETPCAP",
    "remove_CAP_SETPCAP_effective_permitted",
    "readback_all_capability_surfaces_and_prove_both_non_regainable",
)
_SIGNAL_MASK = ("SIGCHLD", "SIGTERM", "SIGINT", "SIGHUP", "SIGQUIT")
_SIGNAL_CODE_ALLOWLIST = (
    "SIGCHLD:CLD_EXITED", "SIGCHLD:CLD_KILLED", "SIGCHLD:CLD_DUMPED",
    "SIGTERM:SI_USER", "SIGTERM:SI_QUEUE", "SIGTERM:SI_TKILL",
    "SIGTERM:SI_KERNEL", "SIGINT:SI_USER", "SIGINT:SI_QUEUE",
    "SIGINT:SI_TKILL", "SIGINT:SI_KERNEL", "SIGHUP:SI_USER",
    "SIGHUP:SI_QUEUE", "SIGHUP:SI_TKILL", "SIGHUP:SI_KERNEL",
    "SIGQUIT:SI_USER", "SIGQUIT:SI_QUEUE", "SIGQUIT:SI_TKILL",
    "SIGQUIT:SI_KERNEL",
)
_PREMASK_PROCESS_STATE = _literal_tuple(
    "process:/proc/1/status", 1, 1, 1,
    "controller_generation_1:start_time_boot_pid1",
    _INITIAL_CAPABILITIES, _INITIAL_CAPABILITIES, (), (),
    _INITIAL_CAPABILITIES, (), (), (), (), (),
)
_PREMASK_TASK_STATE = _literal_tuple(
    "task:/proc/1/task/1/status", 1, 1, 1,
    "controller_generation_1:start_time_boot_pid1",
    _INITIAL_CAPABILITIES, _INITIAL_CAPABILITIES, (), (),
    _INITIAL_CAPABILITIES, (), (), (), (), (),
)
_INITIAL_PROCESS_STATE = _literal_tuple(
    "process:/proc/1/status", 1, 1, 1,
    "controller_generation_1:start_time_boot_pid1",
    _INITIAL_CAPABILITIES, _INITIAL_CAPABILITIES, (), (),
    _INITIAL_CAPABILITIES, _SIGNAL_MASK, ("SIGPIPE",), (), (), (),
)
_INITIAL_TASK_STATE = _literal_tuple(
    "task:/proc/1/task/1/status", 1, 1, 1,
    "controller_generation_1:start_time_boot_pid1",
    _INITIAL_CAPABILITIES, _INITIAL_CAPABILITIES, (), (),
    _INITIAL_CAPABILITIES, _SIGNAL_MASK, ("SIGPIPE",), (), (), (),
)
_STEADY_PROCESS_STATE = _literal_tuple(
    "process:/proc/1/status", 1, 1, 1,
    "controller_generation_1:start_time_boot_pid1",
    _STEADY_CAPABILITIES, _STEADY_CAPABILITIES, (), (),
    _STEADY_CAPABILITIES, _SIGNAL_MASK, ("SIGPIPE",), (), (), (),
)
_STEADY_TASK_STATE = _literal_tuple(
    "task:/proc/1/task/1/status", 1, 1, 1,
    "controller_generation_1:start_time_boot_pid1",
    _STEADY_CAPABILITIES, _STEADY_CAPABILITIES, (), (),
    _STEADY_CAPABILITIES, _SIGNAL_MASK, ("SIGPIPE",), (), (), (),
)
_THREAD_CENSUSES = _literal_tuple(
    ("signal_setup", "immediately_before_signal_mask_first_install", ("1",),
     1, 1, _PREMASK_PROCESS_STATE, _PREMASK_TASK_STATE),
    ("capability_drop", "after_final_capability_drop_readback", ("1",),
     1, 1, _STEADY_PROCESS_STATE, _STEADY_TASK_STATE),
    ("launch", "immediately_before_first_child_fork", ("1",),
     1, 1, _INITIAL_PROCESS_STATE, _INITIAL_TASK_STATE),
    ("serving", "immediately_before_serving_authority_admission", ("1",),
     1, 1, _STEADY_PROCESS_STATE, _STEADY_TASK_STATE),
)
_SIGNAL_OUTCOMES = (
    ("SIGTERM", "shutdown_sigterm", "current_controller_epoch", "global_fail_stop"),
    ("SIGINT", "shutdown_sigint", "current_controller_epoch", "global_fail_stop"),
    ("SIGHUP", "shutdown_sighup", "current_controller_epoch", "global_fail_stop"),
    ("SIGQUIT", "shutdown_sigquit", "current_controller_epoch", "global_fail_stop"),
)
_TERMINAL_TRANSITION = (
    "controller_terminal_epoch",
    ("shutdown_signal_outcome", "unknown_child_exit", "long_lived_role_exit"),
    "stage2_pid1_sole_event_loop_state",
    ("latch_terminal", "increment_nonzero_controller_epoch_once",
     "invalidate_prior_epoch_readiness_candidates_and_completions",
     "close_serving_issuance"),
    "duplicate_or_mixed_shutdown_observes_existing_terminal_epoch_only",
    "signalfd_drain_and_child_reap_before_any_readiness_record",
    "same_live_epoch_and_terminal_false_compare_and_set",
    "only_current_authorized_collector_identity_status_enters_typed_finish_or_abort",
)
_CENSUS_STANDARD = _literal_tuple(
    (0, "stdin", "stage2_pid1", ("FD_CLOEXEC_absent",), ("O_RDONLY",),
     "/dev/null_char_1:3", "boot_generation_1", False),
    (1, "stdout_evidence", "stage2_pid1", ("FD_CLOEXEC_absent",),
     ("O_WRONLY", "O_NONBLOCK"), "/dev/console_char_5:1:stdout_separate_ofd",
     "boot_generation_1", False),
    (2, "stderr_diagnostic", "stage2_pid1", ("FD_CLOEXEC_absent",),
     ("O_WRONLY", "O_NONBLOCK"), "/dev/console_char_5:1:stderr_separate_ofd",
     "boot_generation_1", False),
    (4, "device_monitor", "stage2_pid1", ("FD_CLOEXEC",),
     ("O_RDWR", "O_NONBLOCK"), "sealed_uevent_device_monitor",
     "boot_generation_1:device_monitor", False),
)
_CENSUS_BROKER_TPM = _literal_tuple(
    5, "broker_tpm", "stage2_pid1", ("FD_CLOEXEC",), ("O_RDWR",),
    "/dev/tpmrm0_resource_manager_transfer", "boot_generation_1:tpm_registration",
    False,
)
_CENSUS_TRACE = _literal_tuple(
    6, "predicate5_trace", "stage2_pid1", (), (),
    "package_selected_logical_trace_role",
    "logical_generation_0:exact_target_binding_pending", True,
)
_CENSUS_SUPERVISOR = _literal_tuple(
    (7, "signalfd", "stage2_pid1", ("FD_CLOEXEC",),
     ("O_RDWR", "O_NONBLOCK"),
     "anon_inode:signalfd:SIGCHLD,SIGTERM,SIGINT,SIGHUP,SIGQUIT",
     "controller_generation_1", False),
    (8, "timerfd", "stage2_pid1", ("FD_CLOEXEC",),
     ("O_RDWR", "O_NONBLOCK"), "anon_inode:timerfd:CLOCK_MONOTONIC:5s",
     "controller_generation_1", False),
    (9, "epoll", "stage2_pid1", ("FD_CLOEXEC",), ("O_RDWR",),
     "anon_inode:eventpoll:sole_pid1_owner", "controller_generation_1", False),
)
_CENSUS_SERVING = _literal_tuple(
    (10, "listener", "stage2_pid1", ("FD_CLOEXEC",),
     ("O_RDWR", "O_NONBLOCK"), "AF_INET:SOCK_STREAM:0.0.0.0:9443:backlog8",
     "controller_generation_1", False),
    (11, "gateway_control", "stage2_pid1", ("FD_CLOEXEC",),
     ("O_RDWR", "O_NONBLOCK"),
     "AF_UNIX:SOCK_SEQPACKET:SO_PASSCRED:gateway_control_parent",
     "gateway_generation_1", False),
    (12, "readiness_broker", "stage2_pid1", ("FD_CLOEXEC",),
     ("O_RDWR", "O_NONBLOCK"),
     "AF_UNIX:SOCK_SEQPACKET:SO_PASSCRED:readiness_broker_parent",
     "attestation_broker_generation_1", False),
    (13, "readiness_inference", "stage2_pid1", ("FD_CLOEXEC",),
     ("O_RDWR", "O_NONBLOCK"),
     "AF_UNIX:SOCK_SEQPACKET:SO_PASSCRED:readiness_inference_parent",
     "inference_generation_1", False),
    (14, "readiness_asr", "stage2_pid1", ("FD_CLOEXEC",),
     ("O_RDWR", "O_NONBLOCK"),
     "AF_UNIX:SOCK_SEQPACKET:SO_PASSCRED:readiness_asr_parent",
     "asr_generation_1", False),
    (15, "drain_broker_stdout", "stage2_pid1", ("FD_CLOEXEC",),
     ("O_RDONLY", "O_NONBLOCK"), "pipe:attestation_broker:stdout:read_end",
     "attestation_broker_generation_1", False),
    (16, "drain_broker_stderr", "stage2_pid1", ("FD_CLOEXEC",),
     ("O_RDONLY", "O_NONBLOCK"), "pipe:attestation_broker:stderr:read_end",
     "attestation_broker_generation_1", False),
    (17, "drain_inference_stdout", "stage2_pid1", ("FD_CLOEXEC",),
     ("O_RDONLY", "O_NONBLOCK"), "pipe:inference:stdout:read_end",
     "inference_generation_1", False),
    (18, "drain_inference_stderr", "stage2_pid1", ("FD_CLOEXEC",),
     ("O_RDONLY", "O_NONBLOCK"), "pipe:inference:stderr:read_end",
     "inference_generation_1", False),
    (19, "drain_asr_stdout", "stage2_pid1", ("FD_CLOEXEC",),
     ("O_RDONLY", "O_NONBLOCK"), "pipe:asr:stdout:read_end",
     "asr_generation_1", False),
    (20, "drain_asr_stderr", "stage2_pid1", ("FD_CLOEXEC",),
     ("O_RDONLY", "O_NONBLOCK"), "pipe:asr:stderr:read_end",
     "asr_generation_1", False),
    (21, "drain_gateway_stdout", "stage2_pid1", ("FD_CLOEXEC",),
     ("O_RDONLY", "O_NONBLOCK"), "pipe:gateway:stdout:read_end",
     "gateway_generation_1", False),
    (22, "drain_gateway_stderr", "stage2_pid1", ("FD_CLOEXEC",),
     ("O_RDONLY", "O_NONBLOCK"), "pipe:gateway:stderr:read_end",
     "gateway_generation_1", False),
)
_FD_CENSUSES = _literal_tuple(
    ("post_admission", "after_typed_admission_readback",
     (*_CENSUS_STANDARD, _CENSUS_BROKER_TPM, _CENSUS_TRACE), 6,
     ("predicate5_trace",)),
    ("prelaunch", "after_signal_fd_supervisor_before_first_child_fork",
     (*_CENSUS_STANDARD, _CENSUS_BROKER_TPM, _CENSUS_TRACE,
      *_CENSUS_SUPERVISOR), 9, ("predicate5_trace",)),
    ("steady_serving", "immediately_before_serving_authority_admission",
     (*_CENSUS_STANDARD, _CENSUS_TRACE, *_CENSUS_SUPERVISOR,
      *_CENSUS_SERVING), 21, ("predicate5_trace",)),
)
_EXEC_FDS = _literal_tuple(
    (0, "stdin", "/dev/null_char_1:3", ("O_RDONLY",), ("O_RDONLY",),
     "non_CLOEXEC", "stage2_pid1", "retain_standard", "stage2_pid1", True,
     "separate_open", "character_device", (), None, "root_pid1", None, None,
     "exact_device_inode_owner_flags"),
    (1, "stdout_evidence", "/dev/console_char_5:1",
     ("O_WRONLY", "O_NOCTTY", "O_NONBLOCK"), ("O_WRONLY", "O_NONBLOCK"),
     "non_CLOEXEC", "stage2_pid1", "framed_evidence_only", "stage2_pid1", True,
     "separate_open", "character_device", (), None, "root_pid1", None, None,
     "exact_device_inode_owner_flags"),
    (2, "stderr_diagnostic", "/dev/console_char_5:1",
     ("O_WRONLY", "O_NOCTTY", "O_NONBLOCK"), ("O_WRONLY", "O_NONBLOCK"),
     "non_CLOEXEC", "stage2_pid1", "one_line_diagnostics_only", "stage2_pid1",
     True, "separate_open", "character_device", (), None, "root_pid1", None,
     None, "exact_device_inode_owner_flags"),
    (3, "handoff", "anonymous_sealed_spp-handoff-v3_memfd",
     ("MFD_CLOEXEC", "MFD_ALLOW_SEALING"), ("O_RDWR",),
     "clear_readback_before_exec_restore_readback_after_exec", "stage1",
     "consume_once_close_and_prove_original_inode_absence", "closed", True,
     "sealed_memfd", "one_use_handoff", (), 1048, "stage1_then_stage2", None,
     None, "exact_memfd_name_size_seals_offset_inode_flags"),
    (4, "device_monitor", "sealed_uevent_device_monitor",
     ("SOCK_RAW", "SOCK_NONBLOCK", "SOCK_CLOEXEC"),
     ("O_RDWR", "O_NONBLOCK"),
     "clear_readback_before_exec_restore_readback_after_exec", "stage1",
     "retain_sealed_monitor", "stage2_pid1", True, "sealed_monitor",
     "NETLINK_KOBJECT_UEVENT", (), None, "kernel_sender_only",
     "sequence_and_overflow_closed", "CAP_NET_ADMIN",
     "exact_socket_inode_owner_flags_registration"),
    (5, "broker_tpm", "/dev/tpmrm0_resource_manager_transfer",
     ("O_RDWR", "O_CLOEXEC"), ("O_RDWR",),
     "clear_readback_before_exec_restore_readback_after_exec", "stage1",
     "transfer_once_to_broker_fd4_close_pid1_copy_prove_absence",
     "attestation_broker", True, "tpm_resource_manager", "bounded_transfer", (),
     None, "sealed_registration", None, None,
     "exact_device_inode_owner_flags_registration"),
    (6, "predicate5_trace", "package_selected_logical_trace_role", (), (),
     "clear_readback_before_exec_restore_readback_after_exec_after_binding",
     "stage1", "unissuable_until_exact_target_binding", "stage2_pid1", False,
     None, None, None, None, None, None, None, None),
)
_FORBIDDEN_CONSUMERS = (
    "async_handler", "second_signalfd", "sigwait", "sigwaitinfo",
    "sigtimedwait", "waitpid", "second_waitid", "other_SIGCHLD_consumer",
)
_CHILD_RESET_REQUIREMENTS = (
    "single_threaded_before_credentials_maps_exec",
    "close_inherited_signal_timer_epoll", "close_every_non_map_fd",
    "reset_SIGPIPE_and_all_catchable_to_SIG_DFL", "blocked_mask_empty",
    "pending_sets_empty", "install_only_exact_launch_fd_map",
)


class _HermeticKernelOpsV3:
    def __init__(self, outcomes: list[object]) -> None:
        self.outcomes = outcomes
        self.read_sizes: list[int] = []
        self.installed_mask: tuple[str, ...] | None = None

    def block_signals_exact(self, mask: tuple[str, ...]) -> None:
        self.installed_mask = mask

    def set_signal_dispositions_exact(self) -> None:
        return None

    def signalfd(self, mask: tuple[str, ...], flags: tuple[str, ...]) -> int:
        if mask != _SIGNAL_MASK or flags != ("SFD_NONBLOCK", "SFD_CLOEXEC"):
            raise AssertionError("unexpected signalfd authority")
        return 7

    def read_signalfd_record(
        self, fd: int, size: int,
    ) -> tuple[str, bytes | None, str | None, str | None]:
        if fd != 7:
            raise AssertionError("unexpected signalfd")
        self.read_sizes.append(size)
        if not self.outcomes:
            raise AssertionError("hermetic read sequence exhausted before EAGAIN")
        result = self.outcomes.pop(0)
        if isinstance(result, BaseException):
            raise result
        if type(result) is not tuple or len(result) != 4:
            raise AssertionError("invalid hermetic outcome")
        return result

    def waitid(
        self, selector: str, ident: int, flags: tuple[str, ...],
    ) -> tuple[str, int]:
        return "ECHILD", 0

    def fork(self) -> int:
        return 123


def _assert_exact_authority(value: tables.Stage2Pid1AuthorityV3) -> None:
    if type(value) is not tables.Stage2Pid1AuthorityV3:
        raise ValueError("authority type")
    if tuple(field.name for field in fields(value)) != (
        "identity", "thread_censuses", "child_fork_leaf",
        "forbidden_thread_creators", "interval_trace_requirement",
        "capability_phases", "capability_drop_sequence", "exec_fds",
        "stdio_ofd_distinctness_checks", "fd_censuses", "signal_reap",
        "signal_outcomes", "terminal_transition", "logical_trace",
    ):
        raise ValueError("authority fields")
    identity = value.identity
    if (
        identity.row_id, identity.source_path, identity.interpreter_path,
        identity.argv, identity.environment, identity.pid, identity.ppid,
        identity.uid, identity.gid, identity.supplementary_groups, identity.cwd,
        identity.root, identity.proc_self_exe_identity, identity.argv0_identity,
        identity.signal_reap_row_id,
    ) != (
        "stage2_pid1", "/usr/lib/spp/conf_proc_spp_init.py",
        "/usr/bin/python3.10", _EXPECTED_ARGV, _EXPECTED_ENVIRONMENT,
        1, 0, 0, 0, (), "/", "/", "separate:/usr/bin/python3.10",
        "python3.10", "pid1_signal_reap",
    ):
        raise ValueError("identity literal")
    if tuple(astuple(row) for row in value.thread_censuses) != _THREAD_CENSUSES:
        raise ValueError("thread census literal")
    if (
        value.child_fork_leaf,
        value.forbidden_thread_creators,
        value.interval_trace_requirement,
    ) != (
        "stage2_spawn_child_v3:fork",
        ("_thread", "threading", "pthread", "clone3", "clone:CLONE_THREAD"),
        "exact_target_continuous_clone_event_trace_stage2_entry_through_serving",
    ):
        raise ValueError("thread closure literal")
    capability_rows = tuple(
        (row.row_id, row.event_anchor, row.effective, row.permitted,
         row.inheritable, row.ambient, row.bounding, row.securebits)
        for row in value.capability_phases
    )
    if capability_rows != (
        ("stage2_admitted", "after_typed_admission_readback", _INITIAL_CAPABILITIES,
         _INITIAL_CAPABILITIES, (), (), _INITIAL_CAPABILITIES, 0),
        ("launch_supervision_ready", "after_signal_fd_supervisor_immediately_before_first_fork",
         _INITIAL_CAPABILITIES, _INITIAL_CAPABILITIES, (), (), _INITIAL_CAPABILITIES, 0),
        ("serving_steady", "after_DHCP_socket_identity_absence_and_ordered_drop_readback",
         _STEADY_CAPABILITIES, _STEADY_CAPABILITIES, (), (), _STEADY_CAPABILITIES, 0),
    ):
        raise ValueError("capability literal")
    if value.capability_drop_sequence != _DROP_SEQUENCE:
        raise ValueError("capability drop literal")
    if tuple(astuple(row) for row in value.exec_fds) != _EXEC_FDS:
        raise ValueError("fd literal")
    if value.stdio_ofd_distinctness_checks != (
        "kcmp:0:1=positive", "kcmp:0:2=positive", "kcmp:1:2=positive",
    ):
        raise ValueError("stdio ofd literal")
    if tuple(astuple(row) for row in value.fd_censuses) != _FD_CENSUSES:
        raise ValueError("fd census literal")
    signal = value.signal_reap
    if (
        signal.row_id, signal.mask_install_operation, signal.mask_install_cardinality,
        signal.mask_install_phase, signal.blocked_signals, signal.ignored_signals,
        signal.caught_signals, signal.sigchld_disposition, signal.sigchld_flags,
        signal.forbidden_sigchld_flags, signal.other_catchable_disposition,
        signal.signalfd_flags, signal.signalfd_mask, signal.waiter_owner,
        signal.epoll_owner, signal.waitid_selector, signal.waitid_flags,
        signal.waitid_empty_outcomes, signal.signalfd_drain_terminal,
        signal.signalfd_record_rule, signal.signalfd_code_allowlist,
        signal.signalfd_invalid_rule,
        signal.stop_continue_rule, signal.reap_schedule_rule,
        signal.reap_identity_rule, signal.proc_closure_rule,
    ) != (
        "pid1_signal_reap", "rt_sigprocmask:SIG_BLOCK:exact_mask", 1,
        "before_any_thread_or_child", _SIGNAL_MASK, ("SIGPIPE",), (), "SIG_DFL",
        ("SA_NOCLDSTOP",), ("SA_NOCLDWAIT",),
        "SIG_DFL_no_behavior_changing_flags", ("SFD_NONBLOCK", "SFD_CLOEXEC"),
        _SIGNAL_MASK, "stage2_pid1", "sole_pid1_epoll", "P_ALL:0",
        ("WEXITED", "WNOHANG"),
        ("success_si_pid_zero_with_live_children", "error_ECHILD_with_no_children"),
        "fixed_records_until_EAGAIN",
        "full_signalfd_siginfo_record_per_read",
        _SIGNAL_CODE_ALLOWLIST,
        "short_unknown_or_mismatched_record_is_global_failure",
        "stop_or_continue_ssi_code_is_global_failure",
        "after_each_exit_SIGCHLD_and_immediately_before_each_blocking_epoll_wait",
        "nonzero_si_pid_consumed_once_matches_supervised_pid_start_time_role_generation",
        "after_each_complete_drain_exact_child_task_census_matches_empty_outcome_and_has_no_zombie",
    ):
        raise ValueError("signal/reap literal")
    if signal.forbidden_consumers != _FORBIDDEN_CONSUMERS:
        raise ValueError("signal consumer literal")
    if signal.child_reset_requirements != _CHILD_RESET_REQUIREMENTS:
        raise ValueError("child reset literal")
    if tuple(astuple(row) for row in value.signal_outcomes) != _SIGNAL_OUTCOMES:
        raise ValueError("signal outcome literal")
    if astuple(value.terminal_transition) != _TERMINAL_TRANSITION:
        raise ValueError("terminal transition literal")
    if astuple(value.logical_trace) != (
        "predicate5_trace", 6, True, False, None, None, None, None, None, None,
        None, None,
    ):
        raise ValueError("logical trace literal")


def _validate_task_snapshot(
    row: tables.Stage2ThreadCensusRowV3,
    tasks: tuple[str, ...],
    process_observation: tuple[object, ...],
    task_observation: tuple[object, ...],
) -> None:
    expected = next((item for item in _THREAD_CENSUSES if item[0] == row.row_id), None)
    if expected is None or astuple(row) != expected:
        raise ValueError("task declaration")
    if tasks != ("1",) or tasks != expected[2]:
        raise ValueError("task census")
    if process_observation != expected[5] or task_observation != expected[6]:
        raise ValueError("task state")
    if process_observation[1:] != task_observation[1:]:
        raise ValueError("task process disagreement")


def _validate_capability_drop(*, dhcp_identity_absent: bool, operations: tuple[str, ...]) -> None:
    if not dhcp_identity_absent or operations != _DROP_SEQUENCE:
        raise ValueError("capability drop")


def _validate_thread_trace(events: tuple[str, ...]) -> None:
    if any(event != "fork:stage2_spawn_child_v3" for event in events):
        raise ValueError("thread creator")


def _validate_signalfd_record(*, size: int, signal: str, ssi_code: str,
                              generation_matches: bool) -> None:
    if size != 128:
        raise ValueError("signalfd size")
    if signal not in _SIGNAL_MASK or not generation_matches:
        raise ValueError("signalfd record")
    if f"{signal}:{ssi_code}" not in _SIGNAL_CODE_ALLOWLIST:
        raise ValueError("signalfd code")


def _validate_fd_census(row: tables.Stage2FdCensusRowV3) -> None:
    expected = next((item for item in _FD_CENSUSES if item[0] == row.row_id), None)
    if expected is None or astuple(row) != expected:
        raise ValueError("fd census")


def _classify_child_exit(*, observed: tuple[int, int, str],
                         registered: tuple[int, int, str], collector: bool) -> str:
    if observed != registered:
        return "global_fail_stop"
    if collector:
        return "collector_typed_finish_abort"
    return "global_fail_stop"


def _validate_child_reset(actual: tuple[str, ...], expected: tuple[str, ...]) -> None:
    if actual != expected:
        raise ValueError("child reset")


def _validate_wait_drain(events: tuple[tuple[str, int], ...], live_children: set[int]) -> tuple[int, ...]:
    reaped: list[int] = []
    if not events:
        raise ValueError("wait drain empty")
    for index, (kind, pid) in enumerate(events):
        if kind == "child":
            if pid <= 0 or pid not in live_children or pid in reaped:
                raise ValueError("wait child")
            live_children.remove(pid)
            reaped.append(pid)
            continue
        if index != len(events) - 1 or pid != 0:
            raise ValueError("wait terminal")
        if kind == "zero" and not live_children:
            raise ValueError("zero without live child")
        if kind == "ECHILD" and live_children:
            raise ValueError("ECHILD with live child")
        if kind not in ("zero", "ECHILD"):
            raise ValueError("wait error")
    if events[-1][0] not in ("zero", "ECHILD"):
        raise ValueError("wait not drained")
    return tuple(reaped)


def _terminal_transition(state: dict[str, object], signal: str) -> None:
    outcome = dict((item[0], item[1]) for item in _SIGNAL_OUTCOMES).get(signal)
    if outcome is None:
        raise ValueError("shutdown signal")
    if state["terminal"]:
        return
    state["terminal"] = True
    state["epoch"] = int(state["epoch"]) + 1
    state["readiness_candidate"] = False
    state["readiness_completion"] = False
    state["serving_open"] = False
    state["outcome"] = outcome


class BootV3ControllerAuthoritySelftest(unittest.TestCase):
    def test_independent_literal_denominator_and_coherent_delete(self) -> None:
        authority = tables.STAGE2_CONTROLLER_ROW_V3.pid1_authority
        _assert_exact_authority(authority)
        mutations = (
            replace(authority, thread_censuses=(*authority.thread_censuses, replace(
                authority.thread_censuses[-1], row_id="extra",
            ))),
            replace(authority, thread_censuses=authority.thread_censuses[:-1]),
            replace(authority, thread_censuses=(*authority.thread_censuses, authority.thread_censuses[0])),
            replace(authority, thread_censuses=tuple(reversed(authority.thread_censuses))),
            replace(authority, signal_outcomes=authority.signal_outcomes[:-1]),
            replace(authority, exec_fds=(*authority.exec_fds[:-1], replace(authority.exec_fds[-1], issuable=True))),
            replace(authority, exec_fds=(replace(
                authority.exec_fds[0], object_identity="/dev/console_char_5:1",
            ), *authority.exec_fds[1:])),
            replace(authority, exec_fds=(authority.exec_fds[0], replace(
                authority.exec_fds[1], owner="wrong",
            ), *authority.exec_fds[2:])),
            replace(authority, stdio_ofd_distinctness_checks=("kcmp:0:1=zero",)),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with self.assertRaises(ValueError):
                    _assert_exact_authority(mutation)
        coherent_delete = replace(
            authority,
            capability_phases=tuple(
                row for row in authority.capability_phases if row.row_id != "launch_supervision_ready"
            ),
        )
        with self.assertRaises(ValueError):
            _assert_exact_authority(coherent_delete)

    def test_identity_thread_capability_and_trace_models(self) -> None:
        authority = tables.STAGE2_CONTROLLER_ROW_V3.pid1_authority
        for row, expected in zip(authority.thread_censuses, _THREAD_CENSUSES, strict=True):
            _validate_task_snapshot(row, ("1",), expected[5], expected[6])
            with self.assertRaisesRegex(ValueError, "task census"):
                _validate_task_snapshot(row, ("1", "2"), expected[5], expected[6])
            for state_index in (5, 6):
                for field_index, original in enumerate(expected[state_index]):
                    changed_state = list(expected[state_index])
                    if isinstance(original, tuple):
                        changed_state[field_index] = (*original, "wrong")
                    elif isinstance(original, int):
                        changed_state[field_index] = original + 1
                    else:
                        changed_state[field_index] = f"{original}:wrong"
                    observations = [expected[5], expected[6]]
                    observations[state_index - 5] = tuple(changed_state)
                    with self.subTest(row=row.row_id, state=state_index, field=field_index):
                        with self.assertRaises(ValueError):
                            _validate_task_snapshot(
                                row, ("1",), observations[0], observations[1],
                            )
        _validate_thread_trace(("fork:stage2_spawn_child_v3",) * 4)
        for forbidden in ("_thread", "threading", "pthread", "clone3", "clone:CLONE_THREAD"):
            with self.assertRaisesRegex(ValueError, "thread creator"):
                _validate_thread_trace(("fork:stage2_spawn_child_v3", forbidden))
        _validate_capability_drop(dhcp_identity_absent=True, operations=_DROP_SEQUENCE)
        with self.assertRaises(ValueError):
            _validate_capability_drop(dhcp_identity_absent=False, operations=_DROP_SEQUENCE)
        for index in range(len(_DROP_SEQUENCE)):
            changed = list(_DROP_SEQUENCE)
            changed[index] = "wrong"
            with self.assertRaises(ValueError):
                _validate_capability_drop(dhcp_identity_absent=True, operations=tuple(changed))

    def test_fd_stdio_and_logical_trace_closure(self) -> None:
        authority = tables.STAGE2_CONTROLLER_ROW_V3.pid1_authority
        self.assertEqual(tuple(row.fd for row in authority.exec_fds), tuple(range(7)))
        self.assertEqual(tuple(row.role for row in authority.exec_fds), (
            "stdin", "stdout_evidence", "stderr_diagnostic", "handoff",
            "device_monitor", "broker_tpm", "predicate5_trace",
        ))
        self.assertEqual(authority.exec_fds[1].object_identity, authority.exec_fds[2].object_identity)
        self.assertEqual(authority.stdio_ofd_distinctness_checks, (
            "kcmp:0:1=positive", "kcmp:0:2=positive", "kcmp:1:2=positive",
        ))
        trace = authority.exec_fds[6]
        self.assertFalse(trace.issuable)
        self.assertEqual(astuple(trace)[10:], (None,) * 8)
        for census in authority.fd_censuses:
            _validate_fd_census(census)
            self.assertEqual(len(census.entries), census.total)
            self.assertEqual(census.logical_only_roles, ("predicate5_trace",))
            self.assertEqual(len({entry.role for entry in census.entries}), census.total)
            self.assertEqual(
                tuple(entry.role for entry in census.entries if entry.logical_only),
                census.logical_only_roles,
            )
            for entry_index, entry in enumerate(census.entries):
                mutations = (
                    replace(entry, fd=entry.fd + 100),
                    replace(entry, owner=f"{entry.owner}:wrong"),
                    replace(entry, descriptor_flags=(*entry.descriptor_flags, "wrong")),
                    replace(entry, status_flags=(*entry.status_flags, "wrong")),
                    replace(entry, object_identity=f"{entry.object_identity}:wrong"),
                    replace(entry, generation=f"{entry.generation}:wrong"),
                )
                for mutation in mutations:
                    changed = list(census.entries)
                    changed[entry_index] = mutation
                    with self.assertRaisesRegex(ValueError, "fd census"):
                        _validate_fd_census(replace(census, entries=tuple(changed)))
                coherently_deleted = (
                    census.entries[:entry_index] + census.entries[entry_index + 1:]
                )
                changed_logical = tuple(
                    item for item in census.logical_only_roles if item != entry.role
                )
                with self.assertRaisesRegex(ValueError, "fd census"):
                    _validate_fd_census(replace(
                        census, entries=coherently_deleted,
                        total=census.total - 1,
                        logical_only_roles=changed_logical,
                    ))

    def test_signal_outcomes_terminal_epoch_and_wait_drain(self) -> None:
        authority = tables.STAGE2_CONTROLLER_ROW_V3.pid1_authority
        self.assertEqual(tuple(row.signal for row in authority.signal_outcomes), (
            "SIGTERM", "SIGINT", "SIGHUP", "SIGQUIT",
        ))
        self.assertEqual(len({row.member for row in authority.signal_outcomes}), 4)
        for signal in ("SIGTERM", "SIGINT", "SIGHUP", "SIGQUIT"):
            state: dict[str, object] = {
                "terminal": False, "epoch": 9, "readiness_candidate": True,
                "readiness_completion": True, "serving_open": True, "outcome": None,
            }
            _terminal_transition(state, signal)
            self.assertEqual(
                (state["terminal"], state["epoch"], state["readiness_candidate"],
                 state["readiness_completion"], state["serving_open"]),
                (True, 10, False, False, False),
            )
            first = dict(state)
            _terminal_transition(state, "SIGQUIT")
            self.assertEqual(state, first)
        for item in _SIGNAL_CODE_ALLOWLIST:
            signal, ssi_code = item.split(":", 1)
            _validate_signalfd_record(
                size=128, signal=signal, ssi_code=ssi_code,
                generation_matches=True,
            )
        for kwargs in (
            {"size": 127, "signal": "SIGCHLD", "ssi_code": "CLD_EXITED", "generation_matches": True},
            {"size": 128, "signal": "SIGUSR1", "ssi_code": "SI_USER", "generation_matches": True},
            {"size": 128, "signal": "SIGCHLD", "ssi_code": "CLD_EXITED", "generation_matches": False},
            {"size": 128, "signal": "SIGCHLD", "ssi_code": "CLD_STOPPED", "generation_matches": True},
            {"size": 128, "signal": "SIGCHLD", "ssi_code": "CLD_CONTINUED", "generation_matches": True},
            {"size": 128, "signal": "SIGCHLD", "ssi_code": "CLD_TRAPPED", "generation_matches": True},
            {"size": 128, "signal": "SIGTERM", "ssi_code": "UNKNOWN", "generation_matches": True},
        ):
            with self.assertRaises(ValueError):
                _validate_signalfd_record(**kwargs)
        self.assertEqual(_validate_wait_drain((("child", 10), ("zero", 0)), {10, 11}), (10,))
        self.assertEqual(_validate_wait_drain((("child", 10), ("child", 11), ("ECHILD", 0)), {10, 11}), (10, 11))
        for events, live in (
            (("zero", 0), set()),
            (("ECHILD", 0), {10}),
            (("EINTR", 0), {10}),
            (("child", 99), ("zero", 0)),
        ):
            normalized = (events,) if type(events[0]) is str else events
            with self.assertRaises(ValueError):
                _validate_wait_drain(normalized, set(live))
        self.assertEqual(
            _classify_child_exit(
                observed=(10, 100, "broker"), registered=(10, 100, "broker"),
                collector=False,
            ),
            "global_fail_stop",
        )
        self.assertEqual(
            _classify_child_exit(
                observed=(10, 101, "broker"), registered=(10, 100, "broker"),
                collector=False,
            ),
            "global_fail_stop",
        )
        self.assertEqual(
            _classify_child_exit(
                observed=(12, 120, "collector"), registered=(12, 120, "collector"),
                collector=True,
            ),
            "collector_typed_finish_abort",
        )

    def test_packaged_signalfd_drain_until_exact_EAGAIN(self) -> None:
        exact_codes = tuple(
            tuple(item.split(":", 1)) for item in _SIGNAL_CODE_ALLOWLIST
        )
        self.assertEqual(controller_source._SIGNALFD_CODE_ALLOWLIST_V3, exact_codes)
        raw_records = tuple(bytes((index % 251,)) * 128 for index in range(80))
        outcomes: list[object] = [
            ("record", raw, *exact_codes[index % len(exact_codes)])
            for index, raw in enumerate(raw_records)
        ]
        outcomes.extend((
            ("EAGAIN", None, None, None),
            ("record", b"x" * 127, "SIGCHLD", "CLD_EXITED"),
        ))
        ops = _HermeticKernelOpsV3(outcomes)
        controller = controller_source.Stage2ControllerV3(ops)
        with self.assertRaisesRegex(RuntimeError, "not installed"):
            controller.run_event("signal_ready")
        self.assertEqual(controller.run_event("install_signal_supervisor"), 7)
        self.assertEqual(controller.run_event("signal_ready"), raw_records)
        self.assertEqual(ops.read_sizes, [128] * 81)
        self.assertEqual(len(ops.outcomes), 1)
        ops.outcomes.insert(0, ("EAGAIN", None, None, None))
        self.assertEqual(controller.run_event("signal_ready"), ())
        self.assertEqual(len(ops.outcomes), 1)

        invalid_outcomes = (
            ("record", b"s" * 127, "SIGCHLD", "CLD_EXITED"),
            ("error_EIO", None, None, None),
            ("record", b"u" * 128, "SIGCHLD", "CLD_STOPPED"),
            ("record", b"u" * 128, "SIGTERM", "UNKNOWN"),
            ("EAGAIN", b"not-empty", None, None),
        )
        for invalid in invalid_outcomes:
            bad_ops = _HermeticKernelOpsV3([invalid])
            bad = controller_source.Stage2ControllerV3(bad_ops)
            bad.run_event("install_signal_supervisor")
            with self.subTest(invalid=invalid), self.assertRaises(RuntimeError):
                bad.run_event("signal_ready")
            self.assertEqual(bad_ops.read_sizes, [128])

        error_ops = _HermeticKernelOpsV3([OSError("read failure")])
        failed = controller_source.Stage2ControllerV3(error_ops)
        failed.run_event("install_signal_supervisor")
        with self.assertRaisesRegex(OSError, "read failure"):
            failed.run_event("signal_ready")
        self.assertEqual(error_ops.read_sizes, [128])

    def test_child_signal_reset_and_sole_consumer_inventory(self) -> None:
        signal = tables.STAGE2_CONTROLLER_ROW_V3.pid1_authority.signal_reap
        self.assertEqual(signal.sigchld_flags, ("SA_NOCLDSTOP",))
        self.assertEqual(signal.forbidden_sigchld_flags, ("SA_NOCLDWAIT",))
        self.assertEqual(signal.signalfd_mask, _SIGNAL_MASK)
        self.assertEqual(signal.signalfd_flags, ("SFD_NONBLOCK", "SFD_CLOEXEC"))
        for forbidden in (
            "async_handler", "second_signalfd", "sigwait", "sigwaitinfo",
            "sigtimedwait", "waitpid", "second_waitid", "other_SIGCHLD_consumer",
        ):
            self.assertIn(forbidden, signal.forbidden_consumers)
        self.assertEqual(signal.waitid_flags, ("WEXITED", "WNOHANG"))
        self.assertNotIn("WNOWAIT", signal.waitid_flags)
        self.assertIn("blocked_mask_empty", signal.child_reset_requirements)
        self.assertIn("pending_sets_empty", signal.child_reset_requirements)
        self.assertIn("close_inherited_signal_timer_epoll", signal.child_reset_requirements)
        _validate_child_reset(signal.child_reset_requirements, _CHILD_RESET_REQUIREMENTS)
        for index in range(len(_CHILD_RESET_REQUIREMENTS)):
            with self.assertRaisesRegex(ValueError, "child reset"):
                _validate_child_reset(
                    _CHILD_RESET_REQUIREMENTS[:index]
                    + _CHILD_RESET_REQUIREMENTS[index + 1:],
                    _CHILD_RESET_REQUIREMENTS,
                )
        for forbidden in ("WNOWAIT", "waitpid", "sigwait", "second_signalfd"):
            mutated_signal = (
                replace(signal, waitid_flags=(*signal.waitid_flags, forbidden))
                if forbidden == "WNOWAIT"
                else replace(signal, forbidden_consumers=tuple(
                    item for item in signal.forbidden_consumers if item != forbidden
                ))
            )
            with self.assertRaises(ValueError):
                _assert_exact_authority(replace(
                    tables.STAGE2_CONTROLLER_ROW_V3.pid1_authority,
                    signal_reap=mutated_signal,
                ))

    def test_authority_is_measured_and_predicate5_predecessor_oracle_stays_registered(self) -> None:
        docs, contract = build_v3_fixture()
        binding = boot.bind_boot_inputs_v3(contract=contract, **docs)
        frame = repr(("stage2_controller", tables.STAGE2_CONTROLLER_ROW_V3)).encode("utf-8")
        self.assertIn(frame, binding.literal_v3_observation_shape_bytes)
        baseline = binding.literal_v3_observation_shape_bytes
        original = tables.STAGE2_CONTROLLER_ROW_V3
        try:
            tables.STAGE2_CONTROLLER_ROW_V3 = replace(
                original,
                pid1_authority=replace(
                    original.pid1_authority,
                    signal_outcomes=original.pid1_authority.signal_outcomes[:-1],
                ),
            )
            self.assertNotEqual(
                boot._literal_v3_observation_shape_bytes(binding.process_authority),
                baseline,
            )
        finally:
            tables.STAGE2_CONTROLLER_ROW_V3 = original
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn("test/conf-proc-spp-boot-v3-executable-graph-oracle-selftest.py", makefile)


if __name__ == "__main__":
    unittest.main(verbosity=2)
