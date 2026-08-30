#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Independent AST/reachability oracle for the packaged stage-2 controller."""

from __future__ import annotations

import ast
import hashlib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "conf_proc_spp_init.py"

_EXPECTED_SIZE = 4604
_EXPECTED_SHA256 = "32b7c8f5b6772f52433adcca11051ad1e883bb59aa4f7c66116e43a379bd1dd3"
_ROOT = "Stage2ControllerV3.run_event"
_REACHABLE = frozenset({
    "Stage2ControllerV3.run_event",
    "Stage2ControllerV3._install_signal_supervisor",
    "Stage2ControllerV3._spawn_child",
    "Stage2ControllerV3._drain_signalfd",
    "Stage2ControllerV3._drain_children",
})
_CONTROLLER_METHODS = _REACHABLE | {"Stage2ControllerV3.__init__"}
_PROTOCOL_METHODS = frozenset({
    "block_signals_exact", "set_signal_dispositions_exact", "signalfd",
    "read_signalfd_record", "waitid", "fork",
})
_EXACT_IMPORTS = (
    ("__future__", 0, (("annotations", None),)),
    ("typing", 0, (("Final", None), ("Protocol", None))),
)
_EXACT_CONSTANTS = {
    "_SIGNAL_MASK_V3": ("SIGCHLD", "SIGTERM", "SIGINT", "SIGHUP", "SIGQUIT"),
    "_SIGNALFD_FLAGS_V3": ("SFD_NONBLOCK", "SFD_CLOEXEC"),
    "_WAITID_FLAGS_V3": ("WEXITED", "WNOHANG"),
    "_SIGNALFD_CODE_ALLOWLIST_V3": (
        ("SIGCHLD", "CLD_EXITED"),
        ("SIGCHLD", "CLD_KILLED"),
        ("SIGCHLD", "CLD_DUMPED"),
        ("SIGTERM", "SI_USER"),
        ("SIGTERM", "SI_QUEUE"),
        ("SIGTERM", "SI_TKILL"),
        ("SIGTERM", "SI_KERNEL"),
        ("SIGINT", "SI_USER"),
        ("SIGINT", "SI_QUEUE"),
        ("SIGINT", "SI_TKILL"),
        ("SIGINT", "SI_KERNEL"),
        ("SIGHUP", "SI_USER"),
        ("SIGHUP", "SI_QUEUE"),
        ("SIGHUP", "SI_TKILL"),
        ("SIGHUP", "SI_KERNEL"),
        ("SIGQUIT", "SI_USER"),
        ("SIGQUIT", "SI_QUEUE"),
        ("SIGQUIT", "SI_TKILL"),
        ("SIGQUIT", "SI_KERNEL"),
    ),
}


def _constant(value: object) -> tuple[str, str, object]:
    return "constant", type(value).__name__, value


def _name(value: str) -> tuple[str, str]:
    return "name", value


def _attribute(value: str) -> tuple[str, str]:
    return "attribute", value


_EXACT_CALLS = {
    "Stage2ControllerV3.__init__": (),
    "Stage2ControllerV3.run_event": (
        ("self._install_signal_supervisor", (), ()),
        ("self._spawn_child", (), ()),
        ("self._drain_signalfd", (), ()),
        ("self._drain_children", (), ()),
        ("ValueError", (_constant("unregistered controller event"),), ()),
    ),
    "Stage2ControllerV3._install_signal_supervisor": (
        ("RuntimeError", (_constant("signal supervisor already installed"),), ()),
        ("self._ops.block_signals_exact", (_name("_SIGNAL_MASK_V3"),), ()),
        ("self._ops.set_signal_dispositions_exact", (), ()),
        (
            "self._ops.signalfd",
            (_name("_SIGNAL_MASK_V3"), _name("_SIGNALFD_FLAGS_V3")),
            (),
        ),
    ),
    "Stage2ControllerV3._spawn_child": (
        ("self._ops.fork", (), ()),
    ),
    "Stage2ControllerV3._drain_signalfd": (
        ("RuntimeError", (_constant("signal supervisor is not installed"),), ()),
        (
            "self._ops.read_signalfd_record",
            (_attribute("self._signalfd"), _constant(128)),
            (),
        ),
        ("tuple", (_name("records"),), ()),
        ("RuntimeError", (_constant("malformed signalfd EAGAIN outcome"),), ()),
        ("type", (_name("raw"),), ()),
        ("type", (_name("signal_name"),), ()),
        ("type", (_name("signal_code"),), ()),
        ("RuntimeError", (_constant("invalid signalfd read outcome"),), ()),
        ("len", (_name("raw"),), ()),
        ("RuntimeError", (_constant("short signalfd record"),), ()),
        ("RuntimeError", (_constant("unknown signalfd signal code"),), ()),
        ("records.append", (_name("raw"),), ()),
    ),
    "Stage2ControllerV3._drain_children": (
        (
            "self._ops.waitid",
            (_constant("P_ALL"), _constant(0), _name("_WAITID_FLAGS_V3")),
            (),
        ),
        ("reaped.append", (_name("pid"),), ()),
        ("tuple", (_name("reaped"),), ()),
        ("RuntimeError", (_constant("invalid waitid outcome"),), ()),
    ),
}

_EXACT_PROTOCOL_HEADERS = {
    "block_signals_exact": "def block_signals_exact(self, mask: tuple[str, ...]) -> None: ...",
    "set_signal_dispositions_exact": "def set_signal_dispositions_exact(self) -> None: ...",
    "signalfd": "def signalfd(self, mask: tuple[str, ...], flags: tuple[str, ...]) -> int: ...",
    "read_signalfd_record": (
        "def read_signalfd_record(self, fd: int, size: int) "
        "-> tuple[str, bytes | None, str | None, str | None]: ..."
    ),
    "waitid": (
        "def waitid(self, selector: str, ident: int, flags: tuple[str, ...]) "
        "-> tuple[str, int]: ..."
    ),
    "fork": "def fork(self) -> int: ...",
}
_EXACT_CONTROLLER_HEADERS = {
    "__init__": "def __init__(self, ops: Stage2KernelOpsV3) -> None: ...",
    "run_event": (
        "def run_event(self, event: str) "
        "-> int | tuple[int, ...] | tuple[bytes, ...]: ..."
    ),
    "_install_signal_supervisor": "def _install_signal_supervisor(self) -> int: ...",
    "_spawn_child": "def _spawn_child(self) -> int: ...",
    "_drain_signalfd": "def _drain_signalfd(self) -> tuple[bytes, ...]: ...",
    "_drain_children": "def _drain_children(self) -> tuple[int, ...]: ...",
}


def _attribute_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        owner = _attribute_name(node.value)
        return None if owner is None else owner + "." + node.attr
    return None


def _argument_key(node: ast.expr) -> tuple[object, ...]:
    if isinstance(node, ast.Constant):
        return _constant(node.value)
    if isinstance(node, ast.Name):
        return _name(node.id)
    if isinstance(node, ast.Attribute):
        value = _attribute_name(node)
        if value is not None:
            return _attribute(value)
    raise ValueError("dynamic controller call argument")


def _call_key(node: ast.Call) -> tuple[object, ...]:
    target = _attribute_name(node.func)
    if target is None:
        raise ValueError("dynamic controller call target")
    if any(keyword.arg is None for keyword in node.keywords):
        raise ValueError("expanded controller call argument")
    return (
        target,
        tuple(_argument_key(argument) for argument in node.args),
        tuple((keyword.arg, _argument_key(keyword.value)) for keyword in node.keywords),
    )


class _CallCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.calls: list[ast.Call] = []

    def visit_Call(self, node: ast.Call) -> None:
        self.calls.append(node)
        self.generic_visit(node)


def _expression_dump(source: str) -> str:
    return ast.dump(ast.parse(source, mode="eval").body, include_attributes=False)


def _statement_dump(source: str) -> str:
    statements = ast.parse(source).body
    if len(statements) != 1:
        raise ValueError("expected one oracle statement")
    return ast.dump(statements[0], include_attributes=False)


def _function_header_key(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[object, ...]:
    return (
        type(node).__name__,
        node.name,
        ast.dump(node.args, include_attributes=False),
        None if node.returns is None else ast.dump(node.returns, include_attributes=False),
        tuple(ast.dump(item, include_attributes=False) for item in node.decorator_list),
        node.type_comment,
        tuple(ast.dump(item, include_attributes=False) for item in getattr(node, "type_params", ())),
    )


def _validate_function_header(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    expected_source: str,
) -> None:
    expected = ast.parse(expected_source).body[0]
    if not isinstance(expected, ast.FunctionDef) or _function_header_key(node) != _function_header_key(expected):
        raise ValueError(f"controller function declaration:{node.name}")


def _validate_init_shape(method: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
    expected = (
        "self._ops = ops",
        "self._signalfd: int | None = None",
    )
    if tuple(ast.dump(node, include_attributes=False) for node in method.body) != tuple(
        _statement_dump(source) for source in expected
    ):
        raise ValueError("controller initialization shape")


def _validate_install_shape(method: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
    if tuple(type(node) for node in method.body) != (
        ast.If, ast.Expr, ast.Expr, ast.Assign, ast.Assign, ast.Return,
    ):
        raise ValueError("signal supervisor installation outer shape")
    guard = method.body[0]
    assert isinstance(guard, ast.If)
    if (
        ast.dump(guard.test, include_attributes=False)
        != _expression_dump("self._signalfd is not None")
        or len(guard.body) != 1
        or ast.dump(guard.body[0], include_attributes=False)
        != _statement_dump("raise RuntimeError('signal supervisor already installed')")
        or guard.orelse
    ):
        raise ValueError("signal supervisor installation guard shape")
    expected = (
        "self._ops.block_signals_exact(_SIGNAL_MASK_V3)",
        "self._ops.set_signal_dispositions_exact()",
        "fd = self._ops.signalfd(_SIGNAL_MASK_V3, _SIGNALFD_FLAGS_V3)",
        "self._signalfd = fd",
        "return fd",
    )
    if tuple(ast.dump(node, include_attributes=False) for node in method.body[1:]) != tuple(
        _statement_dump(source) for source in expected
    ):
        raise ValueError("signal supervisor installation operation shape")


def _validate_spawn_shape(method: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
    if tuple(ast.dump(node, include_attributes=False) for node in method.body) != (
        _statement_dump("return self._ops.fork()"),
    ):
        raise ValueError("child spawn shape")


def _validate_event_dispatch_shape(
    method: ast.FunctionDef | ast.AsyncFunctionDef,
) -> None:
    if tuple(type(node) for node in method.body) != (
        ast.If, ast.If, ast.If, ast.If, ast.Raise,
    ):
        raise ValueError("controller event dispatch outer shape")
    branches = method.body[:-1]
    expected = (
        ("event == 'install_signal_supervisor'", "self._install_signal_supervisor()"),
        ("event == 'launch_child'", "self._spawn_child()"),
        ("event == 'signal_ready'", "self._drain_signalfd()"),
        (
            "event in ('child_exit', 'before_blocking_epoll_wait')",
            "self._drain_children()",
        ),
    )
    for branch, (predicate, returned) in zip(branches, expected, strict=True):
        assert isinstance(branch, ast.If)
        if (
            ast.dump(branch.test, include_attributes=False)
            != _expression_dump(predicate)
            or len(branch.body) != 1
            or not isinstance(branch.body[0], ast.Return)
            or branch.body[0].value is None
            or ast.dump(branch.body[0].value, include_attributes=False)
            != _expression_dump(returned)
            or branch.orelse
        ):
            raise ValueError("controller event dispatch decision shape")
    if ast.dump(method.body[-1], include_attributes=False) != _statement_dump(
        "raise ValueError('unregistered controller event')"
    ):
        raise ValueError("controller event dispatch terminal shape")


def _validate_signalfd_drain_shape(
    method: ast.FunctionDef | ast.AsyncFunctionDef,
) -> None:
    if tuple(type(node) for node in method.body) != (
        ast.If, ast.AnnAssign, ast.While,
    ):
        raise ValueError("signalfd drain outer shape")
    guard, records, drain = method.body
    assert isinstance(guard, ast.If)
    assert isinstance(records, ast.AnnAssign)
    assert isinstance(drain, ast.While)
    if (
        _expression_dump("self._signalfd is None")
        != ast.dump(guard.test, include_attributes=False)
        or len(guard.body) != 1
        or ast.dump(guard.body[0], include_attributes=False)
        != _statement_dump("raise RuntimeError('signal supervisor is not installed')")
        or guard.orelse
        or ast.dump(records, include_attributes=False)
        != _statement_dump("records: list[bytes] = []")
        or ast.dump(drain.test, include_attributes=False)
        != _expression_dump("True")
        or drain.orelse
        or tuple(type(node) for node in drain.body)
        != (ast.Assign, ast.If, ast.If, ast.If, ast.If, ast.Expr)
    ):
        raise ValueError("signalfd drain loop shape")
    read, eagain, outcome, short, code, append = drain.body
    assert isinstance(read, ast.Assign)
    assert isinstance(eagain, ast.If)
    assert isinstance(outcome, ast.If)
    assert isinstance(short, ast.If)
    assert isinstance(code, ast.If)
    assert isinstance(append, ast.Expr)
    if (
        len(read.targets) != 1
        or ast.dump(read.targets[0], include_attributes=False)
        != ast.dump(
            ast.parse("outcome, raw, signal_name, signal_code = value").body[0].targets[0],
            include_attributes=False,
        )
        or ast.dump(read.value, include_attributes=False)
        != _expression_dump("self._ops.read_signalfd_record(self._signalfd, 128)")
        or ast.dump(eagain.test, include_attributes=False)
        != _expression_dump("outcome == 'EAGAIN'")
        or ast.dump(outcome.test, include_attributes=False)
        != _expression_dump(
            "outcome != 'record' or type(raw) is not bytes or "
            "type(signal_name) is not str or type(signal_code) is not str"
        )
        or ast.dump(short.test, include_attributes=False)
        != _expression_dump("len(raw) != 128")
        or ast.dump(code.test, include_attributes=False)
        != _expression_dump(
            "(signal_name, signal_code) not in _SIGNALFD_CODE_ALLOWLIST_V3"
        )
        or len(outcome.body) != 1
        or ast.dump(outcome.body[0], include_attributes=False)
        != _statement_dump("raise RuntimeError('invalid signalfd read outcome')")
        or outcome.orelse
        or len(short.body) != 1
        or ast.dump(short.body[0], include_attributes=False)
        != _statement_dump("raise RuntimeError('short signalfd record')")
        or short.orelse
        or len(code.body) != 1
        or ast.dump(code.body[0], include_attributes=False)
        != _statement_dump("raise RuntimeError('unknown signalfd signal code')")
        or code.orelse
        or ast.dump(append, include_attributes=False)
        != _statement_dump("records.append(raw)")
        or tuple(type(node) for node in eagain.body) != (ast.If, ast.Raise)
        or ast.dump(eagain.body[1], include_attributes=False)
        != _statement_dump("raise RuntimeError('malformed signalfd EAGAIN outcome')")
        or eagain.orelse
    ):
        raise ValueError("signalfd drain decision shape")
    eagain_exact = eagain.body[0]
    assert isinstance(eagain_exact, ast.If)
    eagain_return = eagain_exact.body[0] if eagain_exact.body else None
    if (
        ast.dump(eagain_exact.test, include_attributes=False)
        != _expression_dump(
            "raw is None and signal_name is None and signal_code is None"
        )
        or len(eagain_exact.body) != 1
        or not isinstance(eagain_return, ast.Return)
        or eagain_return.value is None
        or ast.dump(eagain_return.value, include_attributes=False)
        != _expression_dump("tuple(records)")
        or eagain_exact.orelse
    ):
        raise ValueError("signalfd EAGAIN shape")


def _validate_child_drain_shape(
    method: ast.FunctionDef | ast.AsyncFunctionDef,
) -> None:
    if tuple(type(node) for node in method.body) != (ast.AnnAssign, ast.While):
        raise ValueError("child drain outer shape")
    reaped, drain = method.body
    assert isinstance(reaped, ast.AnnAssign)
    assert isinstance(drain, ast.While)
    if (
        ast.dump(reaped, include_attributes=False)
        != _statement_dump("reaped: list[int] = []")
        or ast.dump(drain.test, include_attributes=False) != _expression_dump("True")
        or drain.orelse
        or tuple(type(node) for node in drain.body)
        != (ast.Assign, ast.If, ast.If, ast.Raise)
    ):
        raise ValueError("child drain loop shape")
    wait, child, terminal, failure = drain.body
    assert isinstance(wait, ast.Assign)
    assert isinstance(child, ast.If)
    assert isinstance(terminal, ast.If)
    assert isinstance(failure, ast.Raise)
    expected_target = ast.parse("kind, pid = value").body[0]
    assert isinstance(expected_target, ast.Assign)
    if (
        len(wait.targets) != 1
        or ast.dump(wait.targets[0], include_attributes=False)
        != ast.dump(expected_target.targets[0], include_attributes=False)
        or ast.dump(wait.value, include_attributes=False)
        != _expression_dump("self._ops.waitid('P_ALL', 0, _WAITID_FLAGS_V3)")
        or ast.dump(child.test, include_attributes=False)
        != _expression_dump("kind == 'child'")
        or tuple(type(node) for node in child.body) != (ast.Expr, ast.Continue)
        or ast.dump(child.body[0], include_attributes=False)
        != _statement_dump("reaped.append(pid)")
        or ast.dump(child.body[1], include_attributes=False)
        != _statement_dump("continue")
        or child.orelse
        or ast.dump(terminal.test, include_attributes=False)
        != _expression_dump("kind in ('zero', 'ECHILD') and pid == 0")
        or len(terminal.body) != 1
        or not isinstance(terminal.body[0], ast.Return)
        or terminal.body[0].value is None
        or ast.dump(terminal.body[0].value, include_attributes=False)
        != _expression_dump("tuple(reaped)")
        or terminal.orelse
        or ast.dump(failure, include_attributes=False)
        != _statement_dump("raise RuntimeError('invalid waitid outcome')")
    ):
        raise ValueError("child drain decision shape")


def _analyze(raw: bytes, *, enforce_pin: bool = True) -> None:
    if enforce_pin and (
        len(raw) != _EXPECTED_SIZE
        or hashlib.sha256(raw).hexdigest() != _EXPECTED_SHA256
    ):
        raise ValueError("controller source pin")
    tree = ast.parse(raw, filename="conf_proc_spp_init.py")
    imports = tuple(
        (
            node.module,
            node.level,
            tuple((alias.name, alias.asname) for alias in node.names),
        )
        if isinstance(node, ast.ImportFrom)
        else (None, 0, tuple((alias.name, alias.asname) for alias in node.names))
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
    )
    if imports != _EXACT_IMPORTS:
        raise ValueError("controller import closure")
    constants = {
        node.target.id: ast.literal_eval(node.value)
        for node in tree.body
        if isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name)
        and node.value is not None
    }
    if constants != _EXACT_CONSTANTS:
        raise ValueError("controller operation constants")

    if tuple(type(node) for node in tree.body) != (
        ast.Expr,
        ast.ImportFrom,
        ast.ImportFrom,
        ast.AnnAssign,
        ast.AnnAssign,
        ast.AnnAssign,
        ast.AnnAssign,
        ast.ClassDef,
        ast.ClassDef,
    ):
        raise ValueError("controller module declaration closure")
    classes = {node.name: node for node in tree.body if isinstance(node, ast.ClassDef)}
    if set(classes) != {"Stage2KernelOpsV3", "Stage2ControllerV3"}:
        raise ValueError("controller class closure")
    protocol_class = classes["Stage2KernelOpsV3"]
    controller_class = classes["Stage2ControllerV3"]
    if (
        tuple(ast.dump(base, include_attributes=False) for base in protocol_class.bases)
        != (_expression_dump("Protocol"),)
        or protocol_class.keywords
        or protocol_class.decorator_list
        or getattr(protocol_class, "type_params", ())
        or controller_class.bases
        or controller_class.keywords
        or controller_class.decorator_list
        or getattr(controller_class, "type_params", ())
    ):
        raise ValueError("controller class declaration closure")
    if (
        tuple(type(node) for node in protocol_class.body)
        != (ast.Expr, *(ast.FunctionDef for _ in range(len(_EXACT_PROTOCOL_HEADERS))))
        or tuple(type(node) for node in controller_class.body)
        != (ast.Expr, ast.Assign, *(ast.FunctionDef for _ in range(len(_EXACT_CONTROLLER_HEADERS))))
        or ast.dump(controller_class.body[1], include_attributes=False)
        != _statement_dump('__slots__ = ("_ops", "_signalfd")')
    ):
        raise ValueError("controller class body declaration closure")
    if any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) for node in tree.body):
        raise ValueError("top-level callable closure")
    protocol_methods = {
        member.name: member for member in protocol_class.body
        if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    if set(protocol_methods) != _PROTOCOL_METHODS:
        raise ValueError("operation protocol closure")
    for name, expected_source in _EXACT_PROTOCOL_HEADERS.items():
        method = protocol_methods[name]
        _validate_function_header(method, expected_source)
        if len(method.body) != 1 or not isinstance(method.body[0], ast.Expr):
            raise ValueError(f"operation protocol body:{name}")
        value = method.body[0].value
        if not isinstance(value, ast.Constant) or value.value is not Ellipsis:
            raise ValueError(f"operation protocol body:{name}")

    methods: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for node in tree.body:
        if not isinstance(node, ast.ClassDef) or node.name != "Stage2ControllerV3":
            continue
        for member in node.body:
            if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                methods[f"{node.name}.{member.name}"] = member
    if set(methods) != _CONTROLLER_METHODS:
        raise ValueError("controller method closure")
    for name, expected_source in _EXACT_CONTROLLER_HEADERS.items():
        _validate_function_header(methods[f"Stage2ControllerV3.{name}"], expected_source)
    _validate_init_shape(methods["Stage2ControllerV3.__init__"])
    _validate_install_shape(methods["Stage2ControllerV3._install_signal_supervisor"])
    _validate_spawn_shape(methods["Stage2ControllerV3._spawn_child"])
    _validate_event_dispatch_shape(methods["Stage2ControllerV3.run_event"])
    _validate_signalfd_drain_shape(methods["Stage2ControllerV3._drain_signalfd"])
    _validate_child_drain_shape(methods["Stage2ControllerV3._drain_children"])

    edges: dict[str, set[str]] = {name: set() for name in methods}
    owned_call_ids: set[int] = set()
    for owner, method in methods.items():
        class_name = owner.partition(".")[0]
        collector = _CallCollector()
        for statement in method.body:
            collector.visit(statement)
        actual_calls = tuple(_call_key(node) for node in collector.calls)
        if actual_calls != _EXACT_CALLS[owner]:
            raise ValueError(f"controller call closure:{owner}")
        owned_call_ids.update(id(node) for node in collector.calls)
        for target, _arguments, _keywords in actual_calls:
            if target.startswith("self.") and not target.startswith("self._ops."):
                candidate = f"{class_name}.{target.removeprefix('self.')}"
                if candidate in methods:
                    edges[owner].add(candidate)
    if {id(node) for node in ast.walk(tree) if isinstance(node, ast.Call)} != owned_call_ids:
        raise ValueError("controller call outside reachable methods")

    reachable: set[str] = set()
    pending = [_ROOT]
    while pending:
        current = pending.pop()
        if current in reachable:
            continue
        reachable.add(current)
        pending.extend(edges[current] - reachable)
    if frozenset(reachable) != _REACHABLE:
        raise ValueError("controller reachable closure")


class ControllerSourceOracleSelftest(unittest.TestCase):
    def test_packaged_controller_source_has_exact_reachable_authority(self) -> None:
        raw = SOURCE.read_bytes()
        _analyze(raw)
        pin = f'{len(raw)}, "{hashlib.sha256(raw).hexdigest()}"'
        producer = (ROOT / "conf_proc_spp_boot_payload_v3.py").read_text(encoding="utf-8")
        inspector = (ROOT / "conf_proc_spp_boot_payload_v3_inspect.py").read_text(encoding="utf-8")
        independent = (ROOT / "test/conf-proc-spp-boot-payload-v3-independent-selftest.py").read_text(encoding="utf-8")
        self.assertIn(f'"/usr/lib/spp/conf_proc_spp_init.py", "engine", 0o444, {pin}', producer)
        self.assertIn(f'"/usr/lib/spp/conf_proc_spp_init.py", "engine", 0o444, {pin}', inspector)
        self.assertIn(f'"conf_proc_spp_init.py", {pin}', independent)

    def test_forbidden_or_second_authority_consumers_fail(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        mutations = {
            "async_event_dispatch": source.replace(
                "    def run_event(\n",
                "    async def run_event(\n",
            ),
            "staticmethod_event_dispatch": source.replace(
                "    def run_event(\n",
                "    @staticmethod\n    def run_event(\n",
            ),
            "controller_inherits_protocol": source.replace(
                "class Stage2ControllerV3:",
                "class Stage2ControllerV3(Stage2KernelOpsV3):",
            ),
            "kernel_ops_not_protocol": source.replace(
                "class Stage2KernelOpsV3(Protocol):",
                "class Stage2KernelOpsV3:",
            ),
            "kernel_ops_signature_drift": source.replace(
                "def fork(self) -> int: ...",
                "def fork(self, injected: int = 0) -> int: ...",
            ),
            "waitid_WNOWAIT": source.replace(
                '("WEXITED", "WNOHANG")', '("WEXITED", "WNOHANG", "WNOWAIT")',
            ),
            "wrong_signal_mask": source.replace(
                '"SIGCHLD", "SIGTERM", "SIGINT", "SIGHUP", "SIGQUIT",',
                '"SIGCHLD", "SIGTERM", "SIGINT", "SIGHUP", "SIGUSR1",',
            ),
            "missing_SFD_CLOEXEC": source.replace(
                '("SFD_NONBLOCK", "SFD_CLOEXEC")', '("SFD_NONBLOCK",)',
            ),
            "short_signalfd_read": source.replace(
                "self._ops.read_signalfd_record(self._signalfd, 128)",
                "self._ops.read_signalfd_record(self._signalfd, 64)",
            ),
            "dead_signalfd_read": source.replace(
                "self._ops.read_signalfd_record(self._signalfd, 128)",
                "self._ops.read_signalfd_record(self._signalfd, 128) "
                "if False else ('EAGAIN', None, None, None)",
            ),
            "single_pass_instead_of_drain": source.replace(
                "        while True:\n", "        if True:\n",
            ),
            "wrong_EAGAIN_branch": source.replace(
                '            if outcome == "EAGAIN":',
                '            if outcome != "EAGAIN":',
            ),
            "drop_drained_records_at_EAGAIN": source.replace(
                "                    return tuple(records)",
                "                    return tuple(records) if False else ()",
            ),
            "replace_drained_records_at_EAGAIN": source.replace(
                "                    return tuple(records)",
                "                    return (tuple(records), None)[1]",
            ),
            "wrong_signal_ready_dispatch": source.replace(
                '        if event == "signal_ready":',
                '        if event != "signal_ready":',
            ),
            "wrong_child_outcome_branch": source.replace(
                '            if kind == "child":',
                '            if kind != "child":',
            ),
            "wrong_reap_terminal_predicate": source.replace(
                '            if kind in ("zero", "ECHILD") and pid == 0:',
                '            if kind in ("zero", "ECHILD") or pid == 0:',
            ),
            "accept_short_record": source.replace(
                "            if len(raw) != 128:",
                "            if len(raw) == 128:",
            ),
            "accept_error_outcome": source.replace(
                '                outcome != "record"',
                '                outcome == "record"',
            ),
            "construct_instead_of_raise_invalid_outcome": source.replace(
                '                raise RuntimeError("invalid signalfd read outcome")',
                '                RuntimeError("invalid signalfd read outcome")',
            ),
            "construct_instead_of_raise_short_record": source.replace(
                '                raise RuntimeError("short signalfd record")',
                '                RuntimeError("short signalfd record")',
            ),
            "construct_instead_of_raise_unknown_code": source.replace(
                '                raise RuntimeError("unknown signalfd signal code")',
                '                RuntimeError("unknown signalfd signal code")',
            ),
            "invert_code_allowlist": source.replace(
                "not in _SIGNALFD_CODE_ALLOWLIST_V3",
                "in _SIGNALFD_CODE_ALLOWLIST_V3",
            ),
            "drop_signalfd_record_append": source.replace(
                "            records.append(raw)",
                "            records.append(raw) if False else None",
            ),
            "dead_waitid": source.replace(
                'self._ops.waitid("P_ALL", 0, _WAITID_FLAGS_V3)',
                'self._ops.waitid("P_ALL", 0, _WAITID_FLAGS_V3) '
                "if False else ('ECHILD', 0)",
            ),
            "drop_reaped_pid_append": source.replace(
                "                reaped.append(pid)",
                "                reaped.append(pid) if False else None",
            ),
            "dead_signal_mask_install": source.replace(
                "        self._ops.block_signals_exact(_SIGNAL_MASK_V3)",
                "        self._ops.block_signals_exact(_SIGNAL_MASK_V3) if False else None",
            ),
            "discard_installed_signalfd": source.replace(
                "        self._signalfd = fd",
                "        self._signalfd = 0",
            ),
            "discard_spawned_child_pid": source.replace(
                "        return self._ops.fork()",
                "        self._ops.fork()\n        return 0",
            ),
            "waitpid": source.replace(
                "return self._ops.fork()", "self._ops.waitpid()\n        return self._ops.fork()",
            ),
            "second_waitid": source.replace(
                "return self._ops.fork()", "self._ops.waitid(\"P_ALL\", 0, ())\n        return self._ops.fork()",
            ),
            "second_signalfd": source.replace(
                "return self._ops.fork()", "self._ops.signalfd((), ())\n        return self._ops.fork()",
            ),
            "sigwait": source.replace(
                "return self._ops.fork()", "self._ops.sigwait(())\n        return self._ops.fork()",
            ),
            "thread": source.replace(
                "return self._ops.fork()", "self._ops.start_new_thread()\n        return self._ops.fork()",
            ),
            "clone3": source.replace(
                "return self._ops.fork()", "self._ops.clone3()\n        return self._ops.fork()",
            ),
            "clone_thread": source.replace(
                "return self._ops.fork()", "self._ops.clone(\"CLONE_THREAD\")\n        return self._ops.fork()",
            ),
            "unknown_ops_reaper": source.replace(
                'kind, pid = self._ops.waitid("P_ALL", 0, _WAITID_FLAGS_V3)',
                'self._ops.reap_unregistered()\n            '
                'kind, pid = self._ops.waitid("P_ALL", 0, _WAITID_FLAGS_V3)',
            ),
            "dynamic_getattr_waitid": source.replace(
                'self._ops.waitid("P_ALL", 0, _WAITID_FLAGS_V3)',
                'getattr(self._ops, "waitid")("P_ALL", 0, _WAITID_FLAGS_V3)',
            ),
            "second_signalfd_in_authorized_caller": source.replace(
                "        self._signalfd = fd",
                "        self._ops.signalfd(_SIGNAL_MASK_V3, _SIGNALFD_FLAGS_V3)\n"
                "        self._signalfd = fd",
            ),
            "second_fork_in_authorized_leaf": source.replace(
                "        return self._ops.fork()",
                "        self._ops.fork()\n        return self._ops.fork()",
            ),
            "subprocess_import_and_call": source.replace(
                "from typing import Final, Protocol",
                "import subprocess\nfrom typing import Final, Protocol",
            ).replace(
                "        return self._ops.fork()",
                '        subprocess.run(("true",), check=True)\n'
                "        return self._ops.fork()",
            ),
            "hidden_consumer": source + "\ndef hidden_waiter(ops):\n    return ops.waitid(\"P_ALL\", 0, ())\n",
            "removed_signalfd_guard": source.replace(
                "        if self._signalfd is not None:\n"
                "            raise RuntimeError(\"signal supervisor already installed\")\n",
                "",
            ),
        }
        for label, changed in mutations.items():
            with self.subTest(label=label), self.assertRaises(ValueError):
                _analyze(changed.encode("utf-8"), enforce_pin=False)

    def test_reachable_coherent_rename_and_pin_mutation_fail(self) -> None:
        raw = SOURCE.read_bytes()
        changed = raw.replace(b"_drain_children", b"_drain_children_deleted")
        with self.assertRaisesRegex(ValueError, "closure"):
            _analyze(changed, enforce_pin=False)
        with self.assertRaisesRegex(ValueError, "source pin"):
            _analyze(raw + b"\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
