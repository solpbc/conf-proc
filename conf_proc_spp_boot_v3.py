#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Document binding and PCR-15 measurement for SPP boot authority v3."""

from __future__ import annotations

import hashlib
import threading
import weakref
from collections import namedtuple
from dataclasses import dataclass
from enum import Enum
from typing import Final

from conf_proc_json import canonical_loads
from conf_proc_spp_boot import (
    BootEffect,
    BootObservation,
    BootTransport,
    Pcr15ExtendOutcome,
    StateEffectPostcondition,
    _claim_extend_transport,
    _record_extend_outcome,
    _record_extend_transport_closed,
)
from conf_proc_spp_boot_v3_resource import ServingAuthorityWrapperV3
from conf_proc_spp_boot_v3_semantics import (
    ControlInventorySnapshotV3,
    ExecutionClosureV3,
    KernelIdentitySnapshotV3,
    LaunchProjectionV3,
    ModuleAuthoritySnapshotV3,
    Predicate5SnapshotV3,
    SourceDigestsV3,
    Stage2ControllerSnapshotV3,
    StorageSnapshotV3,
    parse_execution_closure_v3,
    validate_execution_mode_v3,
    validate_semantic_conjunction_v3,
)
import conf_proc_spp_boot_v3_tables as tables
from conf_proc_spp_reasons_v3 import (
    ApplianceErrorV3,
    CP_BOOT_V3_BINDING,
    CP_BOOT_V3_CONTROL,
    CP_BOOT_V3_DEVICE_MONITOR,
    CP_BOOT_V3_DEV_TREE,
    CP_BOOT_V3_FAILURE_PROTOCOL,
    CP_BOOT_V3_LATCH,
    CP_BOOT_V3_LAUNCH_SUPERVISION,
    CP_BOOT_V3_MODULE_AUTHORITY,
    CP_BOOT_V3_MOUNT_CENSUS,
    CP_BOOT_V3_NETWORK_POLICY,
    CP_BOOT_V3_PCR,
    CP_BOOT_V3_PID1_IDENTITY,
    CP_BOOT_V3_ROOT_TRANSITION,
    CP_BOOT_V3_SCHEMA,
)


BOOT_CONTRACT_V3_SCHEMA: Final = "conf-proc-spp-boot-contract/v3"
_SHA_CHARS_V3: Final = frozenset("0123456789abcdef")
_HASH_REFERENCE_FIELDS_V3: Final = (
    "root_lock_sha256",
    "runtime_closure_sha256",
    "verity_rules_sha256",
    "tcb_identity_sha256",
    "builder_source_sha256",
    "policy_sha256",
    "accepted_manifest_sha256",
    "kernel_feature_contract_sha256",
    "trusted_certificate_bundle_sha256",
    "gpt_layout_rules_sha256",
)
_InputReferenceV3 = namedtuple("_InputReferenceV3", "input_name reference_name")
_INPUT_TO_REFERENCE_V3: Final = (
    _InputReferenceV3("root_lock_bytes", "root_lock_sha256"),
    _InputReferenceV3("runtime_closure_bytes", "runtime_closure_sha256"),
    _InputReferenceV3("verity_rules_bytes", "verity_rules_sha256"),
    _InputReferenceV3("tcb_identity_bytes", "tcb_identity_sha256"),
    _InputReferenceV3("builder_source_bytes", "builder_source_sha256"),
    _InputReferenceV3("policy_bytes", "policy_sha256"),
    _InputReferenceV3("accepted_manifest_bytes", "accepted_manifest_sha256"),
    _InputReferenceV3("kernel_feature_contract_bytes", "kernel_feature_contract_sha256"),
    _InputReferenceV3("trusted_certificate_bundle_bytes", "trusted_certificate_bundle_sha256"),
    _InputReferenceV3("gpt_layout_rules_bytes", "gpt_layout_rules_sha256"),
)


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise ApplianceErrorV3(code, message)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha(value: object) -> bool:
    return type(value) is str and len(value) == 64 and set(value) <= _SHA_CHARS_V3


def _load_contract_document(data: bytes) -> object:
    try:
        return canonical_loads(data)
    except Exception:
        raise ApplianceErrorV3(CP_BOOT_V3_SCHEMA, "v3 boot contract is not canonical JSON") from None


@dataclass(frozen=True)
class BootContractV3:
    schema: str
    contract_version: int
    root_lock_sha256: str
    runtime_closure_sha256: str
    verity_rules_sha256: str
    tcb_identity_sha256: str
    builder_source_sha256: str
    policy_sha256: str
    accepted_manifest_sha256: str
    kernel_feature_contract_sha256: str
    trusted_certificate_bundle_sha256: str
    gpt_layout_rules_sha256: str
    execution_closure: ExecutionClosureV3
    execution_mode: str
    cache_policy: str


def parse_boot_contract_v3(data: bytes) -> BootContractV3:
    """Parse the v3 document itself; other authority bytes bind separately."""

    raw = _load_contract_document(data)
    expected = {
        "schema", "contract_version", *_HASH_REFERENCE_FIELDS_V3,
        "execution_closure", "execution_mode", "cache_policy",
    }
    _require(type(raw) is dict and set(raw) == expected, CP_BOOT_V3_SCHEMA, "v3 boot contract fields are invalid")
    _require(
        raw["schema"] == BOOT_CONTRACT_V3_SCHEMA and raw["contract_version"] == 3,
        CP_BOOT_V3_SCHEMA,
        "v3 boot contract schema is invalid",
    )
    _require(
        all(_sha(raw[field]) for field in _HASH_REFERENCE_FIELDS_V3),
        CP_BOOT_V3_SCHEMA,
        "v3 boot contract hash references are invalid",
    )
    closure = parse_execution_closure_v3(raw["execution_closure"])
    validate_execution_mode_v3(raw["execution_mode"], raw["cache_policy"], closure)
    return BootContractV3(
        raw["schema"], raw["contract_version"],
        *[raw[field] for field in _HASH_REFERENCE_FIELDS_V3],
        closure, raw["execution_mode"], raw["cache_policy"],
    )


@dataclass(frozen=True)
class BootBindingV3:
    root_lock_bytes: bytes
    runtime_closure_bytes: bytes
    verity_rules_bytes: bytes
    tcb_identity_bytes: bytes
    builder_source_bytes: bytes
    policy_bytes: bytes
    accepted_manifest_bytes: bytes
    kernel_feature_contract_bytes: bytes
    trusted_certificate_bundle_bytes: bytes
    boot_contract_bytes: bytes
    module_plan_bytes: bytes
    gpt_layout_rules_bytes: bytes
    literal_v3_observation_shape_bytes: bytes
    boot_contract: BootContractV3
    source_digests: SourceDigestsV3
    storage: StorageSnapshotV3
    kernel_identity: KernelIdentitySnapshotV3
    module_authority: ModuleAuthoritySnapshotV3
    control_inventory: ControlInventorySnapshotV3
    launch_projection: LaunchProjectionV3
    stage2_controller: Stage2ControllerSnapshotV3
    predicate5: Predicate5SnapshotV3

    @property
    def boot_contract_sha256(self) -> str:
        return hashlib.sha256(self.boot_contract_bytes).hexdigest()


_ISSUED_BOOT_BINDINGS_V3: Final = weakref.WeakValueDictionary[int, BootBindingV3]()
_ISSUED_BOOT_BINDINGS_V3_LOCK: Final = threading.Lock()


def _register_boot_binding_v3(binding: BootBindingV3) -> BootBindingV3:
    with _ISSUED_BOOT_BINDINGS_V3_LOCK:
        _ISSUED_BOOT_BINDINGS_V3[id(binding)] = binding
    return binding


def is_issued_boot_binding_v3(binding: object) -> bool:
    return type(binding) is BootBindingV3 and _ISSUED_BOOT_BINDINGS_V3.get(id(binding)) is binding


def _literal_v3_observation_shape_bytes() -> bytes:
    """Serialize every v3-owned closed inventory in a stable, ordered form."""

    shape = (
        ("schema", "conf-proc-spp-boot-observation-shape/v3"),
        ("bootstrap_mounts", tables.BOOTSTRAP_MOUNTS_V3),
        (
            "early_modules",
            tables.EARLY_MODULE_TARGET_KERNEL_RELEASE_V3,
            tables.EARLY_MODULE_TARGET_CONFIG_SHA256_V3,
            tables.EARLY_MODULE_SIGNER_V3,
            tables.EARLY_MODULE_SIGNATURE_KEY_ID_V3,
            tables.EARLY_MODULE_RELEASE_ROOT_V3,
            tables.EARLY_MODULE_ROWS_V3,
            tables.EARLY_MODULE_BUILTIN_DEPENDENCIES_V3,
        ),
        ("kernel_config_binding", tables.KERNEL_CONFIG_BINDING_ROWS_V3),
        ("control_inventory", tables.CONTROL_INVENTORY_ROWS_V3),
        (
            "dev_tree",
            tables.DEV_TREE_DIRECTORY_ROWS_V3,
            tables.DEV_TREE_ROWS_V3,
            tables.DEV_TREE_FORBIDDEN_PATH_PATTERNS_V3,
            tables.DEV_TREE_FORBIDDEN_NODE_KINDS_V3,
        ),
        (
            "failure_inventory",
            tables.FAILURE_DIAGNOSTIC_TOKENS_V3,
            tables.FAILURE_LATE_CODES_V3,
            tables.FAILURE_STAGES_V3,
        ),
        ("launch_roles", tables.LAUNCH_ROLE_ROWS_V3),
        ("stage2_controller", tables.STAGE2_CONTROLLER_ROW_V3),
        (
            "wire_message_authority",
            tables.WIRE_HEADER_FIELDS_V3,
            tables.WIRE_HEADER_BYTES_V3,
            tables.WIRE_SEQUENCE_RULE_V3,
            tables.WIRE_HAS_FD_TYPE_IDS_V3,
            tables.WIRE_SESSION_COORDINATE_RULES_V3,
            tables.WIRE_ROUTE_ENUM_ROWS_V3,
            tables.WIRE_COLLECTOR_GENERATION_ENUM_ROWS_V3,
            tables.WIRE_COLLECTOR_RESULT_ENUM_ROWS_V3,
            tables.WIRE_COLLECTOR_ABORT_REASON_ENUM_ROWS_V3,
            tables.WIRE_INVALID_COLLECTOR_ACK_REASON_ENUM_ROWS_V3,
            tables.WIRE_INVALID_COLLECTOR_ACK_ABORT_MAPPING_V3,
            tables.WIRE_COLLECTOR_CANCEL_REASON_ENUM_ROWS_V3,
            tables.WIRE_REQUEST_REJECT_REASON_ENUM_ROWS_V3,
            tables.WIRE_WORK_FINISH_OUTCOME_ENUM_ROWS_V3,
            tables.WIRE_REQUEST_RELEASE_STATE_ENUM_ROWS_V3,
            tables.WIRE_SESSION_RELEASE_HELD_BITS_V3,
            tables.WIRE_SESSION_RELEASE_REASON_ENUM_ROWS_V3,
            tables.WIRE_PRE_REQUEST_REJECT_REASON_ENUM_ROWS_V3,
            tables.WIRE_GLOBAL_FAULT_REASON_ENUM_ROWS_V3,
            tables.WIRE_ENTITLEMENT_CONNECT_REJECT_REASON_ENUM_ROWS_V3,
            tables.WIRE_CONDITIONAL_SHAPE_ROWS_V3,
            tables.WIRE_MESSAGE_AUTHORITY_ROWS_V3,
        ),
        ("resource_actions", tables.RESOURCE_ACTION_ROWS_V3),
        (
            "resource_capacities",
            tables.LISTEN_BACKLOG_V3,
            tables.SOMAXCONN_MINIMUM_V3,
            tables.MAX_LIVE_SESSIONS_V3,
            tables.COLLECTOR_OPERATION_PERMITS_V3,
            tables.COLLECTOR_OPERATION_BOUND_SECONDS_V3,
            tables.COLLECTOR_OUTPUT_CAPACITY_BYTES_V3,
            tables.ROUTE_WORK_PERMITS_TOTAL_V3,
            tables.STREAM_BUFFER_BYTES_V3,
            tables.AGGREGATE_BUFFER_BYTES_V3,
            tables.REQUEST_HEAD_CAPACITY_BYTES_V3,
            tables.RELAY_COPY_CHUNK_BYTES_V3,
        ),
        ("wire_message_types", tables.WIRE_MESSAGE_TYPE_ROWS_V3),
    )
    return repr(shape).encode("utf-8")


def bind_boot_inputs_v3(
    *,
    contract: BootContractV3,
    root_lock_bytes: bytes,
    runtime_closure_bytes: bytes,
    verity_rules_bytes: bytes,
    tcb_identity_bytes: bytes,
    builder_source_bytes: bytes,
    policy_bytes: bytes,
    accepted_manifest_bytes: bytes,
    kernel_feature_contract_bytes: bytes,
    trusted_certificate_bundle_bytes: bytes,
    module_plan_bytes: bytes,
    gpt_layout_rules_bytes: bytes,
    boot_contract_bytes: bytes,
) -> BootBindingV3:
    """Cross-bind v3 component bytes to the parsed contract references."""

    _require(type(contract) is BootContractV3, CP_BOOT_V3_BINDING, "v3 contract is invalid")
    supplied = {
        "root_lock_bytes": root_lock_bytes,
        "runtime_closure_bytes": runtime_closure_bytes,
        "verity_rules_bytes": verity_rules_bytes,
        "tcb_identity_bytes": tcb_identity_bytes,
        "builder_source_bytes": builder_source_bytes,
        "policy_bytes": policy_bytes,
        "accepted_manifest_bytes": accepted_manifest_bytes,
        "kernel_feature_contract_bytes": kernel_feature_contract_bytes,
        "trusted_certificate_bundle_bytes": trusted_certificate_bundle_bytes,
        "module_plan_bytes": module_plan_bytes,
        "gpt_layout_rules_bytes": gpt_layout_rules_bytes,
        "boot_contract_bytes": boot_contract_bytes,
    }
    _require(all(type(value) is bytes for value in supplied.values()), CP_BOOT_V3_BINDING, "all v3 boot authority inputs must be bytes")
    _require(
        parse_boot_contract_v3(boot_contract_bytes) == contract,
        CP_BOOT_V3_BINDING,
        "v3 contract bytes disagree with parsed contract",
    )
    snapshots = validate_semantic_conjunction_v3(
        contract=contract,
        boot_contract_bytes=boot_contract_bytes,
        root_lock_bytes=root_lock_bytes,
        runtime_closure_bytes=runtime_closure_bytes,
        verity_rules_bytes=verity_rules_bytes,
        tcb_identity_bytes=tcb_identity_bytes,
        builder_source_bytes=builder_source_bytes,
        policy_bytes=policy_bytes,
        accepted_manifest_bytes=accepted_manifest_bytes,
        kernel_feature_contract_bytes=kernel_feature_contract_bytes,
        trusted_certificate_bundle_bytes=trusted_certificate_bundle_bytes,
        module_plan_bytes=module_plan_bytes,
        gpt_layout_rules_bytes=gpt_layout_rules_bytes,
    )
    return _register_boot_binding_v3(
        BootBindingV3(
            root_lock_bytes,
            runtime_closure_bytes,
            verity_rules_bytes,
            tcb_identity_bytes,
            builder_source_bytes,
            policy_bytes,
            accepted_manifest_bytes,
            kernel_feature_contract_bytes,
            trusted_certificate_bundle_bytes,
            boot_contract_bytes,
            module_plan_bytes,
            gpt_layout_rules_bytes,
            _literal_v3_observation_shape_bytes(),
            contract,
            snapshots.source_digests,
            snapshots.storage,
            snapshots.kernel_identity,
            snapshots.module_authority,
            snapshots.control_inventory,
            snapshots.launch_projection,
            snapshots.stage2_controller,
            snapshots.predicate5,
        )
    )


class BootTransitionEngineV3:
    """The sealed v3 causal chain and its PCR-15 authority calculation."""

    def __init__(self, binding: BootBindingV3) -> None:
        if not is_issued_boot_binding_v3(binding):
            raise ApplianceErrorV3(CP_BOOT_V3_BINDING, "binding was not issued")
        self.binding = binding
        self.state = BootTransitionStateV3.PID1_IDENTITY_ESTABLISHED
        self._pending: AuthorityStepEffectV3 | None = None
        self._extend_transport: BootTransport | None = None
        self._extend_request_issued = False
        self._serving_effect_completed = False
        self._serving_authority: ServingAuthorityWrapperV3 | None = None
        self.failure_diagnostic_token: str | None = None

    @property
    def contract_sha256(self) -> str:
        return _sha256(self.binding.boot_contract_bytes)

    @property
    def pcr15_measurement_v3(self) -> bytes:
        frame = lambda value: len(value).to_bytes(8, "big") + value
        material = (
            b"sol-spp-appliance-manifest-v3" + b"\0"
            + frame(self.binding.root_lock_bytes)
            + frame(self.binding.runtime_closure_bytes)
            + frame(self.binding.verity_rules_bytes)
            + frame(self.binding.tcb_identity_bytes)
            + frame(self.binding.builder_source_bytes)
            + frame(self.binding.policy_bytes)
            + frame(self.binding.accepted_manifest_bytes)
            + frame(self.binding.kernel_feature_contract_bytes)
            + frame(self.binding.trusted_certificate_bundle_bytes)
            + frame(self.binding.boot_contract_bytes)
            + frame(self.binding.module_plan_bytes)
            + frame(self.binding.gpt_layout_rules_bytes)
            + frame(self.binding.literal_v3_observation_shape_bytes)
        )
        return hashlib.sha256(material).digest()

    @property
    def predicted_pcr15_v3(self) -> bytes:
        return hashlib.sha256(b"\0" * 32 + self.pcr15_measurement_v3).digest()

    def next_effect(self) -> AuthorityStepEffectV3 | None:
        if self._pending is not None:
            return self._pending
        if self.state is BootTransitionStateV3.FAILED_NON_SERVING:
            return None
        if self.state is BootTransitionStateV3.SERVING_AVAILABLE and self._serving_effect_completed:
            return None
        step = _STEP_BY_STATE_V3[self.state]
        if self.state is BootTransitionStateV3.PCR15_EXTENDED:
            if not _claim_extend_transport():
                self._fail(CP_BOOT_V3_LATCH, "a PCR15 extend transport was already claimed for this process")
            self._extend_request_issued = True
            expected: object = self.pcr15_measurement_v3
        else:
            expected = step.expected
        self._pending = AuthorityStepEffectV3(self.contract_sha256, self.state, step.action, expected)
        return self._pending

    def advance(self, transport: BootTransport) -> BootTransitionStateV3:
        effect = self.next_effect()
        if effect is None:
            self._fail(_reason_for_state_v3(self.state), "v3 boot transition has no further normal effect")
        if self.state is BootTransitionStateV3.PCR15_EXTENDED:
            if self._extend_transport is None:
                self._extend_transport = transport
            elif transport is not self._extend_transport:
                self._pending = None
                self._fail(CP_BOOT_V3_LATCH, "PCR15 extend requires its claimed transport")
        elif self.state is BootTransitionStateV3.TPM_BOOT_TRANSPORT_CLOSED and transport is not self._extend_transport:
            self._pending = None
            self._fail(CP_BOOT_V3_LATCH, "PCR15 transport closure requires the claimed transport")
        try:
            observation = transport.execute(effect)
        except Exception:
            if self.state is BootTransitionStateV3.PCR15_EXTENDED:
                return self.accept(
                    AuthorityStepReadbackV3(
                        self.contract_sha256,
                        self.state,
                        effect.action,
                        Pcr15ExtendOutcome.ERROR,
                    )
                )
            self._pending = None
            self._fail(_reason_for_state_v3(self.state), "typed v3 boot transport failed")
        return self.accept(observation)

    def accept(self, observation: BootObservation) -> BootTransitionStateV3:
        """Accept one typed step readback for deterministic reducer tests."""

        state = self.state
        step = _STEP_BY_STATE_V3.get(state)
        if step is None:
            self._fail(_reason_for_state_v3(state), "v3 observation is unavailable in this state")
        effect = self._pending
        if (
            effect is None
            or type(observation) is not AuthorityStepReadbackV3
            or observation.contract_sha256 != self.contract_sha256
            or observation.state is not state
            or observation.action != step.action
            or observation.accepted is not True
        ):
            self._fail(_reason_for_state_v3(state), "v3 observation is stale, unordered, or malformed")
        self._pending = None
        if state is BootTransitionStateV3.PCR15_EXTENDED:
            if not self._extend_request_issued or self._extend_transport is None or type(observation.observed) is not Pcr15ExtendOutcome:
                self._fail(CP_BOOT_V3_LATCH, "v3 PCR extend has no shared-latch transport")
            _record_extend_outcome(observation.observed)
        elif state is BootTransitionStateV3.TPM_BOOT_TRANSPORT_CLOSED:
            if self._extend_transport is None:
                self._fail(CP_BOOT_V3_LATCH, "v3 PCR transport closure has no claimed transport")
            if observation.observed is None:
                self._fail(CP_BOOT_V3_LATCH, "v3 PCR transport closure readback is invalid")
            _record_extend_transport_closed()
            self._extend_transport = None
        elif step.expected is None:
            if observation.observed is None:
                self._fail(_reason_for_state_v3(state), "v3 step observation is absent")
        elif observation.observed != step.expected:
            self._fail(_reason_for_state_v3(state), "v3 step observation disagrees with authority")
        self.state = _NEXT_STATE_V3[state]
        if state is BootTransitionStateV3.SERVING_AVAILABLE:
            self._serving_effect_completed = True
        return self.state

    def _fail(self, reason_code: str, message: str) -> None:
        if self.state is not BootTransitionStateV3.FAILED_NON_SERVING:
            self.failure_diagnostic_token = DIAGNOSTIC_TOKEN_FOR_STATE_V3[self.state]
            self.state = BootTransitionStateV3.FAILED_NON_SERVING
        self._pending = None
        raise ApplianceErrorV3(reason_code, message)

    def admit_serving_authority(self) -> ServingAuthorityWrapperV3:
        if self.state is not BootTransitionStateV3.SERVING_AVAILABLE:
            self._fail(
                CP_BOOT_V3_LAUNCH_SUPERVISION,
                "v3 serving authority is not available before SERVING_AVAILABLE",
            )
        # Wrapper admission has no transport argument; its later per-session
        # open_session boundary owns session transport identity and freshness.
        if self._serving_authority is None:
            self._serving_authority = ServingAuthorityWrapperV3(
                on_global_fault=self._on_wrapper_global_fault
            )
        return self._serving_authority

    def _on_wrapper_global_fault(self) -> None:
        if self.state is BootTransitionStateV3.FAILED_NON_SERVING:
            return
        try:
            self._fail(
                CP_BOOT_V3_LAUNCH_SUPERVISION,
                "v3 serving authority reported a global fault",
            )
        except ApplianceErrorV3:
            # The wrapper must continue directly to resource revocation after
            # the outer engine enters its terminal failure state.
            return


class BootTransitionStateV3(Enum):
    PID1_IDENTITY_ESTABLISHED = "pid1_identity_established"
    ADAPTER_CONSTRUCTED = "adapter_constructed"
    BOOTSTRAP_MOUNTED = "bootstrap_mounted"
    NETWORK_PREFLIGHT_STARTED = "network_preflight_started"
    NIC_CENSUS_ESTABLISHED = "nic_census_established"
    EARLY_MODULES_LOADED = "early_modules_loaded"
    NIC_CENSUS_REVALIDATED = "nic_census_revalidated"
    NETWORK_DENY_INSTALLED = "network_deny_installed"
    CMDLINE_SEALED = "cmdline_sealed"
    PCR15_ZERO_CONFIRMED = "pcr15_zero_confirmed"
    DISK_IDENTIFIED = "disk_identified"
    ROOT_MODEL_VERITY_MAPPED = "root_model_verity_mapped"
    ROOT_MODEL_MOUNTED = "root_model_mounted"
    C1_CENSUS_ESTABLISHED = "c1_census_established"
    FINAL_RUN_CREATED = "final_run_created"
    C2_CENSUS_ESTABLISHED = "c2_census_established"
    LATER_MODULES_LOADED = "later_modules_loaded"
    MODULES_DISABLED = "modules_disabled"
    MUTABLE_CONTROLS_ENFORCED = "mutable_controls_enforced"
    PCR15_EXTENDED = "pcr15_extended"
    TPM_BOOT_TRANSPORT_CLOSED = "tpm_boot_transport_closed"
    DEVICE_MONITOR_SEALED = "device_monitor_sealed"
    DEV_TREE_PRUNED = "dev_tree_pruned"
    DEVICE_MONITOR_RECONCILED = "device_monitor_reconciled"
    SECURITYFS_UNMOUNTED = "securityfs_unmounted"
    KERNEL_INTERFACES_MOVED = "kernel_interfaces_moved"
    C3_CENSUS_ESTABLISHED = "c3_census_established"
    HANDOFF_SEALED = "handoff_sealed"
    SWITCH_ROOT_COMPLETED = "switch_root_completed"
    STAGE2_ADMITTED = "stage2_admitted"
    POST_ROOT_RUNTIME_SEALED = "post_root_runtime_sealed"
    LAUNCH_SUPERVISION_READY = "launch_supervision_ready"
    SERVING_AVAILABLE = "serving_available"
    FAILED_NON_SERVING = "failed_non_serving"


@dataclass(frozen=True)
class AuthorityStepEffectV3(BootEffect):
    state: BootTransitionStateV3
    action: str
    expected: object


@dataclass(frozen=True)
class AuthorityStepReadbackV3(BootObservation):
    state: BootTransitionStateV3
    action: str
    observed: object
    accepted: bool = True


@dataclass(frozen=True)
class _StepSpecV3:
    state: BootTransitionStateV3
    action: str
    expected: object


_NETWORK_CENSUS_REQUIREMENTS_V3: Final = (
    "interfaces_down",
    "interfaces_unaddressed",
    "interfaces_unrouted",
    "listener_count=0",
    "af_packet_count=0",
    "monitor_family=AF_NETLINK",
    "monitor_protocol=NETLINK_ROUTE",
)
_NORMAL_STATES_V3: Final = tuple(
    state for state in BootTransitionStateV3 if state is not BootTransitionStateV3.FAILED_NON_SERVING
)
_EARLY_MODULE_EXPECTED_V3: Final = (
    tables.EARLY_MODULE_ROWS_V3,
    tables.EARLY_MODULE_TARGET_KERNEL_RELEASE_V3,
    tables.EARLY_MODULE_TARGET_CONFIG_SHA256_V3,
    tables.EARLY_MODULE_SIGNER_V3,
    tables.EARLY_MODULE_SIGNATURE_KEY_ID_V3,
    tables.EARLY_MODULE_RELEASE_ROOT_V3,
    tables.EARLY_MODULE_BUILTIN_DEPENDENCIES_V3,
)
_DEV_TREE_EXPECTED_V3: Final = (
    tables.DEV_TREE_DIRECTORY_ROWS_V3,
    tables.DEV_TREE_ROWS_V3,
    tables.DEV_TREE_FORBIDDEN_PATH_PATTERNS_V3,
    tables.DEV_TREE_FORBIDDEN_NODE_KINDS_V3,
)
_STEP_EXPECTED_V3: Final = {
    BootTransitionStateV3.BOOTSTRAP_MOUNTED: tables.BOOTSTRAP_MOUNTS_V3,
    BootTransitionStateV3.NETWORK_PREFLIGHT_STARTED: _NETWORK_CENSUS_REQUIREMENTS_V3,
    BootTransitionStateV3.NIC_CENSUS_ESTABLISHED: _NETWORK_CENSUS_REQUIREMENTS_V3,
    BootTransitionStateV3.EARLY_MODULES_LOADED: _EARLY_MODULE_EXPECTED_V3,
    BootTransitionStateV3.NIC_CENSUS_REVALIDATED: _NETWORK_CENSUS_REQUIREMENTS_V3,
    BootTransitionStateV3.NETWORK_DENY_INSTALLED: _NETWORK_CENSUS_REQUIREMENTS_V3,
    BootTransitionStateV3.PCR15_ZERO_CONFIRMED: b"\0" * 32,
    BootTransitionStateV3.MUTABLE_CONTROLS_ENFORCED: tables.CONTROL_INVENTORY_ROWS_V3,
    BootTransitionStateV3.DEV_TREE_PRUNED: _DEV_TREE_EXPECTED_V3,
    BootTransitionStateV3.LAUNCH_SUPERVISION_READY: tables.LAUNCH_ROLE_ROWS_V3,
    BootTransitionStateV3.SERVING_AVAILABLE: tables.LAUNCH_ROLE_ROWS_V3,
}
BOOT_TRANSITION_STEPS_V3: Final = tuple(
    _StepSpecV3(state, state.value, _STEP_EXPECTED_V3.get(state)) for state in _NORMAL_STATES_V3
)
_STEP_BY_STATE_V3: Final = {step.state: step for step in BOOT_TRANSITION_STEPS_V3}
_NEXT_STATE_V3: Final = {
    state: _NORMAL_STATES_V3[index + 1]
    for index, state in enumerate(_NORMAL_STATES_V3[:-1])
}
_NEXT_STATE_V3[BootTransitionStateV3.SERVING_AVAILABLE] = BootTransitionStateV3.SERVING_AVAILABLE
STATE_EFFECT_POSTCONDITIONS_V3: Final = tuple(
    StateEffectPostcondition(step.state, "AuthorityStepEffectV3", step.action)
    for step in BOOT_TRANSITION_STEPS_V3
)

DIAGNOSTIC_TOKEN_FOR_STATE_V3: Final = {
    BootTransitionStateV3.PID1_IDENTITY_ESTABLISHED: "pid1",
    BootTransitionStateV3.ADAPTER_CONSTRUCTED: "adapter",
    BootTransitionStateV3.BOOTSTRAP_MOUNTED: "runtime_authority",
    BootTransitionStateV3.NETWORK_PREFLIGHT_STARTED: "runtime_authority",
    BootTransitionStateV3.NIC_CENSUS_ESTABLISHED: "runtime_authority",
    BootTransitionStateV3.EARLY_MODULES_LOADED: "runtime_authority",
    BootTransitionStateV3.NIC_CENSUS_REVALIDATED: "runtime_authority",
    BootTransitionStateV3.NETWORK_DENY_INSTALLED: "runtime_authority",
    BootTransitionStateV3.CMDLINE_SEALED: "runtime_authority",
    BootTransitionStateV3.PCR15_ZERO_CONFIRMED: "runtime_authority",
    BootTransitionStateV3.DISK_IDENTIFIED: "runtime_authority",
    BootTransitionStateV3.ROOT_MODEL_VERITY_MAPPED: "root_transition",
    BootTransitionStateV3.ROOT_MODEL_MOUNTED: "root_transition",
    BootTransitionStateV3.C1_CENSUS_ESTABLISHED: "root_transition",
    BootTransitionStateV3.FINAL_RUN_CREATED: "root_transition",
    BootTransitionStateV3.C2_CENSUS_ESTABLISHED: "root_transition",
    BootTransitionStateV3.LATER_MODULES_LOADED: "root_transition",
    BootTransitionStateV3.MODULES_DISABLED: "root_transition",
    BootTransitionStateV3.MUTABLE_CONTROLS_ENFORCED: "root_transition",
    BootTransitionStateV3.PCR15_EXTENDED: "root_transition",
    BootTransitionStateV3.TPM_BOOT_TRANSPORT_CLOSED: "root_transition",
    BootTransitionStateV3.DEVICE_MONITOR_SEALED: "root_transition",
    BootTransitionStateV3.DEV_TREE_PRUNED: "root_transition",
    BootTransitionStateV3.DEVICE_MONITOR_RECONCILED: "root_transition",
    BootTransitionStateV3.SECURITYFS_UNMOUNTED: "root_transition",
    BootTransitionStateV3.KERNEL_INTERFACES_MOVED: "root_transition",
    BootTransitionStateV3.C3_CENSUS_ESTABLISHED: "root_transition",
    BootTransitionStateV3.HANDOFF_SEALED: "root_transition",
    BootTransitionStateV3.SWITCH_ROOT_COMPLETED: "root_transition",
    BootTransitionStateV3.STAGE2_ADMITTED: "root_transition",
    BootTransitionStateV3.POST_ROOT_RUNTIME_SEALED: "runtime_authority",
    BootTransitionStateV3.LAUNCH_SUPERVISION_READY: "serving_integrity",
    BootTransitionStateV3.SERVING_AVAILABLE: "serving_integrity",
}
assert set(DIAGNOSTIC_TOKEN_FOR_STATE_V3) == set(_NORMAL_STATES_V3)
assert set(DIAGNOSTIC_TOKEN_FOR_STATE_V3.values()) <= set(tables.FAILURE_DIAGNOSTIC_TOKENS_V3)


def _reason_for_state_v3(state: BootTransitionStateV3) -> str:
    if state in (
        BootTransitionStateV3.PID1_IDENTITY_ESTABLISHED,
        BootTransitionStateV3.ADAPTER_CONSTRUCTED,
    ):
        return CP_BOOT_V3_PID1_IDENTITY
    if state in (
        BootTransitionStateV3.BOOTSTRAP_MOUNTED,
        BootTransitionStateV3.C1_CENSUS_ESTABLISHED,
        BootTransitionStateV3.FINAL_RUN_CREATED,
        BootTransitionStateV3.C2_CENSUS_ESTABLISHED,
        BootTransitionStateV3.C3_CENSUS_ESTABLISHED,
    ):
        return CP_BOOT_V3_MOUNT_CENSUS
    if state in (
        BootTransitionStateV3.NETWORK_PREFLIGHT_STARTED,
        BootTransitionStateV3.NIC_CENSUS_ESTABLISHED,
        BootTransitionStateV3.NIC_CENSUS_REVALIDATED,
        BootTransitionStateV3.NETWORK_DENY_INSTALLED,
    ):
        return CP_BOOT_V3_NETWORK_POLICY
    if state in (
        BootTransitionStateV3.EARLY_MODULES_LOADED,
        BootTransitionStateV3.LATER_MODULES_LOADED,
    ):
        return CP_BOOT_V3_MODULE_AUTHORITY
    if state in (
        BootTransitionStateV3.PCR15_ZERO_CONFIRMED,
        BootTransitionStateV3.PCR15_EXTENDED,
    ):
        return CP_BOOT_V3_PCR
    if state is BootTransitionStateV3.TPM_BOOT_TRANSPORT_CLOSED:
        return CP_BOOT_V3_LATCH
    if state in (
        BootTransitionStateV3.MUTABLE_CONTROLS_ENFORCED,
        BootTransitionStateV3.MODULES_DISABLED,
        BootTransitionStateV3.SECURITYFS_UNMOUNTED,
        BootTransitionStateV3.KERNEL_INTERFACES_MOVED,
        BootTransitionStateV3.POST_ROOT_RUNTIME_SEALED,
    ):
        return CP_BOOT_V3_CONTROL
    if state is BootTransitionStateV3.DEV_TREE_PRUNED:
        return CP_BOOT_V3_DEV_TREE
    if state in (
        BootTransitionStateV3.DEVICE_MONITOR_SEALED,
        BootTransitionStateV3.DEVICE_MONITOR_RECONCILED,
    ):
        return CP_BOOT_V3_DEVICE_MONITOR
    if state in (
        BootTransitionStateV3.LAUNCH_SUPERVISION_READY,
        BootTransitionStateV3.SERVING_AVAILABLE,
    ):
        return CP_BOOT_V3_LAUNCH_SUPERVISION
    return CP_BOOT_V3_ROOT_TRANSITION


class FailureStageV3(Enum):
    DIAGNOSTIC = "diagnostic"
    CLOSE_SERVING_NETWORK = "close_serving_network"
    POWEROFF_REQUESTED = "poweroff_requested"
    FAIL_STOP = "fail_stop"


assert tuple(stage.value for stage in FailureStageV3) == tables.FAILURE_STAGES_V3


class PoweroffAckedV3(BaseException):
    """Harness-only sentinel for a non-returning poweroff dispatch."""


@dataclass(frozen=True)
class FailureControllerEffectV3(BootEffect):
    action: str


@dataclass(frozen=True)
class FailureControllerReadbackV3(BootObservation):
    action: str
    confirmed: bool


class FailureControllerV3:
    """Fail-closed diagnostic, bounded closure, and poweroff controller."""

    def __init__(self, diagnostic_token: str) -> None:
        if diagnostic_token not in tables.FAILURE_DIAGNOSTIC_TOKENS_V3:
            raise ApplianceErrorV3(CP_BOOT_V3_FAILURE_PROTOCOL, "unknown diagnostic token")
        self.diagnostic_token = diagnostic_token
        self.stage = FailureStageV3.DIAGNOSTIC
        self._diagnostic_rendered = False
        self._network_close_attempts = 0
        self._network_close_confirmed = False
        self._poweroff_requested = False
        self.late_code: str | None = None

    def _set_late_code(self, code: str) -> None:
        if not self._diagnostic_rendered:
            raise ApplianceErrorV3(CP_BOOT_V3_FAILURE_PROTOCOL, "late code precedes diagnostic")
        if code not in tables.FAILURE_LATE_CODES_V3:
            raise ApplianceErrorV3(CP_BOOT_V3_FAILURE_PROTOCOL, "unknown late failure code")
        self.late_code = code

    def render_diagnostic(self) -> str:
        if self.stage is not FailureStageV3.DIAGNOSTIC or self._diagnostic_rendered:
            raise ApplianceErrorV3(CP_BOOT_V3_FAILURE_PROTOCOL, "diagnostic is unavailable")
        self._diagnostic_rendered = True
        self.stage = FailureStageV3.CLOSE_SERVING_NETWORK
        return f"conf-proc-spp-boot-v3: {self.diagnostic_token}"

    @staticmethod
    def _confirmed_readback(observation: object, action: str) -> bool:
        return (
            type(observation) is FailureControllerReadbackV3
            and observation.contract_sha256 == "failure-controller/v3"
            and observation.action == action
            and observation.confirmed is True
        )

    def _best_effort(self, transport: BootTransport, action: str) -> bool:
        try:
            observation = transport.execute(FailureControllerEffectV3("failure-controller/v3", action))
        except BaseException:
            return False
        return self._confirmed_readback(observation, action)

    def attempt_network_close(self, transport: BootTransport) -> bool:
        if self.stage is not FailureStageV3.CLOSE_SERVING_NETWORK:
            raise ApplianceErrorV3(CP_BOOT_V3_FAILURE_PROTOCOL, "network close is unavailable")
        if self._network_close_attempts >= 3:
            raise ApplianceErrorV3(CP_BOOT_V3_FAILURE_PROTOCOL, "network close attempts are exhausted")
        self._network_close_attempts += 1
        confirmed = self._best_effort(transport, "close_serving_network")
        self._network_close_confirmed = self._network_close_confirmed or confirmed
        if not confirmed:
            self._set_late_code("network_close")
        if self._network_close_attempts == 3:
            self.stage = FailureStageV3.POWEROFF_REQUESTED
        return confirmed

    def _dispatch_poweroff_attempt(self, transport: BootTransport) -> None:
        self._poweroff_requested = True
        try:
            transport.execute(FailureControllerEffectV3("failure-controller/v3", "poweroff"))
        except PoweroffAckedV3:
            raise
        except BaseException:
            self._set_late_code("poweroff_returned")
            self.stage = FailureStageV3.FAIL_STOP
            return
        self._set_late_code("poweroff_returned")
        self.stage = FailureStageV3.FAIL_STOP

    def dispatch_poweroff(self, transport: BootTransport) -> None:
        if self.stage is not FailureStageV3.POWEROFF_REQUESTED:
            raise ApplianceErrorV3(CP_BOOT_V3_FAILURE_PROTOCOL, "poweroff dispatch is unavailable")
        self._dispatch_poweroff_attempt(transport)

    def fail_stop_cycle(
        self,
        *,
        close_transport: BootTransport,
        deny_all_transport: BootTransport,
        poweroff_transport: BootTransport,
    ) -> None:
        if self.stage is not FailureStageV3.FAIL_STOP:
            raise ApplianceErrorV3(CP_BOOT_V3_FAILURE_PROTOCOL, "fail-stop cycle is unavailable")
        self._best_effort(close_transport, "close_serving_network")
        self._best_effort(deny_all_transport, "deny_all")
        self._dispatch_poweroff_attempt(poweroff_transport)
        self.stage = FailureStageV3.FAIL_STOP
