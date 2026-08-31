#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Handwritten A3.1b oracle: no production imports, fixtures, or serializers."""

LAUNCH_FIELD_NAMES = (
    "role", "source_path", "process_kind", "interpreter_path", "argv",
    "expected_network_scope", "expected_process_capabilities",
    "expected_capability_bounding_set", "expected_ambient_capabilities",
    "expected_no_new_privileges", "uid", "gid", "supplementary_groups",
    "environment", "cwd", "root", "namespace_requirements", "cardinality",
    "child_fork_policy", "restart_policy", "fd_surface", "pipe_census",
    "listener_policy", "upstream_policy", "admission_policy", "readiness",
)

_ENVIRONMENT = (
    ("LANG", "C"),
    ("LC_ALL", "C"),
    ("PATH", "/nonexistent"),
    ("PYTHONNOUSERSITE", "1"),
    ("PYTHONDONTWRITEBYTECODE", "1"),
)
_NAMESPACES = (
    "same_initial_user_namespace_as_stage2_pid1",
    "same_initial_pid_namespace_as_stage2_pid1",
    "same_initial_mount_namespace_as_stage2_pid1",
    "same_initial_network_namespace_as_stage2_pid1",
)
_COMMON_PIPES = (
    (1, "stdout", 65536, 65536, 65536, 1, "pid1_epoll_immediate_discard"),
    (2, "stderr", 65536, 65536, 65536, 1, "pid1_epoll_immediate_discard"),
)
_COMMON_FDS = (
    (0, "/dev/null", "pid1", "inherited", "exact"),
    (1, "bounded_content_discard_pipe", "pid1", "inherited", "65536_plus_detection"),
    (2, "bounded_content_discard_pipe", "pid1", "inherited", "65536_plus_detection"),
)


def _argv(role):
    return (
        "/usr/bin/python3.10", "-I", "-B", "-S",
        "/usr/lib/spp/conf_proc_spp_role_bootstrap.py", "--role=" + role,
    )


def _readiness(role_id):
    return (
        "AF_UNIX SOCK_SEQPACKET root_owned", b"SPPRDQ3\0", b"SPPRDR3\0",
        32, 80, role_id, "CLOCK_MONOTONIC", "nanoseconds",
        "one_matching_SCM_CREDENTIALS", "no_ancillary_fd", 4,
    )


def _row(
    role, source_path, network, uid, cardinality, fd_surface, pipe_census,
    listener, upstream, admission, readiness,
):
    return {
        "role": role,
        "source_path": source_path,
        "process_kind": "interpreter",
        "interpreter_path": "/usr/bin/python3.10",
        "argv": _argv(role),
        "expected_network_scope": network,
        "expected_process_capabilities": (),
        "expected_capability_bounding_set": (),
        "expected_ambient_capabilities": (),
        "expected_no_new_privileges": True,
        "uid": uid,
        "gid": uid,
        "supplementary_groups": (),
        "environment": _ENVIRONMENT,
        "cwd": "/",
        "root": "/",
        "namespace_requirements": _NAMESPACES,
        "cardinality": cardinality,
        "child_fork_policy": "none",
        "restart_policy": "never",
        "fd_surface": fd_surface,
        "pipe_census": pipe_census,
        "listener_policy": listener,
        "upstream_policy": upstream,
        "admission_policy": admission,
        "readiness": readiness,
    }


LAUNCH_ROWS = (
    _row(
        "attestation-broker", "/usr/lib/spp/conf_proc_spp_attestation_broker.py",
        "none", 61100, "one_long_lived",
        _COMMON_FDS + (
            (3, "root_owned_broker_SOCK_SEQPACKET", "pid1", "inherited", "sole_control_endpoint"),
            (4, "/dev/tpmrm0_resource_manager", "stage1", "fd5_transfer", "sole_pinned_tpm_handle"),
        ),
        _COMMON_PIPES, "no_listener", "no_network", "none", _readiness(1),
    ),
    _row(
        "inference", "/usr/lib/spp/conf_proc_spp_inference.py", "loopback",
        61101, "one_long_lived",
        _COMMON_FDS + (
            (3, "loopback_listener_127.0.0.1:8000", "pid1", "inherited", "sole_listener"),
            (4, "root_owned_readiness_SOCK_SEQPACKET", "pid1", "inherited", "sole_readiness_endpoint"),
        ),
        _COMMON_PIPES, "one_pid1_created_loopback_listener_127.0.0.1:8000",
        "none", "none", _readiness(2),
    ),
    _row(
        "asr", "/usr/lib/spp/asr_shim.py", "loopback", 61102,
        "one_long_lived",
        _COMMON_FDS + (
            (3, "loopback_listener_127.0.0.1:8100", "pid1", "inherited", "sole_listener"),
            (4, "root_owned_readiness_SOCK_SEQPACKET", "pid1", "inherited", "sole_readiness_endpoint"),
        ),
        _COMMON_PIPES, "one_pid1_created_loopback_listener_127.0.0.1:8100",
        "none", "none", _readiness(3),
    ),
    _row(
        "gateway", "/usr/lib/spp/ratls_gateway.py", "loopback", 61103,
        "one_long_lived",
        _COMMON_FDS + (
            (3, "pid1_created_gateway_control_endpoint", "pid1", "inherited", "sole_control_endpoint"),
        ),
        _COMMON_PIPES, "no_listener",
        "connect_only_loopback_127.0.0.1:8000_and_127.0.0.1:8100_after_work_permit",
        "pid1_admitted_connected_fds_and_pid1_entitlement_fd_only", None,
    ),
    _row(
        "collector", "/usr/lib/spp/ratls_collector.py", "none", 61104,
        "zero_or_one_transient",
        (
            (0, "one_request_stdin_pipe", "pid1", "inherited", "exact_one_request"),
            (1, "bounded_stdout_pipe", "pid1", "inherited", "8388608_plus_detection"),
            (2, "bounded_stderr_pipe", "pid1", "inherited", "65536_plus_detection"),
        ),
        (
            (1, "stdout", 8388608, 8388608, 8388608, 1, "collector_result_only"),
            (2, "stderr", 65536, 65536, 65536, 1, "immediate_discard"),
        ),
        "no_listener", "no_network",
        "pid1_spawned_reaped_one_bounded_request_response", None,
    ),
)

READINESS_LAYOUT_FIELD_NAMES = ("offset", "width", "name", "encoding", "constraint")
READINESS_LAYOUT_ROW_FIELD_NAMES = (
    "row_id", "transport", "total_bytes", "fields", "credential_rule", "fd_rule",
    "trailing_rule",
)
READINESS_BARRIER_FIELD_NAMES = (
    "row_id", "role_order", "generation", "census_cardinality", "deadline_clock",
    "deadline_delta_ns", "states", "terminal_event_order", "completion_rule",
    "consume_rule", "retry_rule",
)


READINESS_LAYOUTS = (
    (
        "role_probe", "AF_UNIX SOCK_SEQPACKET root_owned", 32,
        ((0, 8, "magic", "bytes", "SPPRDQ3_then_NUL"),
         (8, 2, "version", "u16_be", "3"),
         (10, 2, "role_id", "u16_be", "1_to_3_exact_role"),
         (12, 4, "flags", "u32_be", "zero"),
         (16, 8, "generation", "u64_be", "shared_exact_1"),
         (24, 8, "deadline", "u64_be", "shared_absolute_CLOCK_MONOTONIC_ns")),
        "one_matching_SCM_CREDENTIALS", "no_ancillary_fd", "no_trailing_bytes",
    ),
    (
        "role_result", "AF_UNIX SOCK_SEQPACKET root_owned", 80,
        ((0, 8, "magic", "bytes", "SPPRDR3_then_NUL"),
         (8, 2, "version", "u16_be", "3"),
         (10, 2, "role_id", "u16_be", "1_to_3_exact_role"),
         (12, 4, "flags", "u32_be", "exactly_1_ready"),
         (16, 8, "generation", "u64_be", "echo_shared_exact_1"),
         (24, 8, "deadline", "u64_be", "echo_shared_absolute_deadline"),
         (32, 4, "pid", "u32_be", "exact_supervised_child"),
         (36, 4, "uid", "u32_be", "exact_role_uid"),
         (40, 4, "gid", "u32_be", "exact_role_gid"),
         (44, 4, "reserved", "u32_be", "zero"),
         (48, 32, "executable_sha256", "bytes", "exact_measured_source_digest")),
        "one_matching_SCM_CREDENTIALS", "no_ancillary_fd", "no_trailing_bytes",
    ),
    (
        "gateway_probe", "serving_wire_v3", 88,
        ((0, 72, "serving_wire_header", "bytes", "type_22_zero_session_single_chunk_no_fd"),
         (72, 8, "generation", "u64_be", "shared_exact_1"),
         (80, 8, "deadline", "u64_be", "shared_absolute_CLOCK_MONOTONIC_ns")),
        "authenticated_supervised_sender", "no_ancillary_fd", "no_trailing_bytes",
    ),
    (
        "gateway_result", "serving_wire_v3", 128,
        ((0, 72, "serving_wire_header", "bytes", "type_23_zero_session_single_chunk_no_fd"),
         (72, 8, "generation", "u64_be", "echo_shared_exact_1"),
         (80, 4, "pid", "u32_be", "exact_supervised_gateway"),
         (84, 2, "worker_count", "u16_be", "0_to_4_equals_live_session_ledger"),
         (86, 2, "flags", "u16_be", "exactly_1_control_ready"),
         (88, 32, "executable_sha256", "bytes", "exact_measured_gateway_digest"),
         (120, 8, "control_endpoint_SO_COOKIE", "u64_be", "exact_nonzero")),
        "one_matching_SCM_CREDENTIALS", "no_ancillary_fd", "no_trailing_bytes",
    ),
)

BARRIER = {
    "row_id": "all_four_generation_deadline",
    "role_order": ("attestation-broker", "inference", "asr", "gateway"),
    "generation": 1,
    "census_cardinality": 1,
    "deadline_clock": "CLOCK_MONOTONIC",
    "deadline_delta_ns": 4000000000,
    "states": ("unstarted", "collecting", "candidate", "complete", "consumed", "failed"),
    "terminal_event_order": "signalfd_and_reap_before_readiness_in_same_epoll_batch",
    "completion_rule": "one_compare_and_set_collecting_to_complete_same_epoch_nonterminal",
    "consume_rule": "one_exact_completion_makes_serving_eligible_then_duplicate_fails",
    "retry_rule": "failed_census_is_terminal_no_retry_or_second_census",
}
