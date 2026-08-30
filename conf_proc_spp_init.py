#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Measured stage-2 controller source closure for the sealed SPP appliance.

This wave freezes the controller's reachable operation graph without supplying
the exact-target syscall provider.  The physical adapter must bind that sealed
provider before this source is issuable.
"""

from __future__ import annotations

from typing import Final, Protocol


_SIGNAL_MASK_V3: Final = (
    "SIGCHLD", "SIGTERM", "SIGINT", "SIGHUP", "SIGQUIT",
)
_SIGNALFD_FLAGS_V3: Final = ("SFD_NONBLOCK", "SFD_CLOEXEC")
_WAITID_FLAGS_V3: Final = ("WEXITED", "WNOHANG")
_SIGNALFD_CODE_ALLOWLIST_V3: Final = (
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
)


class Stage2KernelOpsV3(Protocol):
    """Exact-target operations supplied only by the later physical adapter."""

    def block_signals_exact(self, mask: tuple[str, ...]) -> None: ...

    def set_signal_dispositions_exact(self) -> None: ...

    def signalfd(self, mask: tuple[str, ...], flags: tuple[str, ...]) -> int: ...

    def read_signalfd_record(
        self, fd: int, size: int,
    ) -> tuple[str, bytes | None, str | None, str | None]: ...

    def waitid(self, selector: str, ident: int,
               flags: tuple[str, ...]) -> tuple[str, int]: ...

    def fork(self) -> int: ...


class Stage2ControllerV3:
    """Single-threaded controller with one source-level owner per authority."""

    __slots__ = ("_ops", "_signalfd")

    def __init__(self, ops: Stage2KernelOpsV3) -> None:
        self._ops = ops
        self._signalfd: int | None = None

    def run_event(
        self, event: str,
    ) -> int | tuple[int, ...] | tuple[bytes, ...]:
        if event == "install_signal_supervisor":
            return self._install_signal_supervisor()
        if event == "launch_child":
            return self._spawn_child()
        if event == "signal_ready":
            return self._drain_signalfd()
        if event in ("child_exit", "before_blocking_epoll_wait"):
            return self._drain_children()
        raise ValueError("unregistered controller event")

    def _install_signal_supervisor(self) -> int:
        if self._signalfd is not None:
            raise RuntimeError("signal supervisor already installed")
        self._ops.block_signals_exact(_SIGNAL_MASK_V3)
        self._ops.set_signal_dispositions_exact()
        fd = self._ops.signalfd(_SIGNAL_MASK_V3, _SIGNALFD_FLAGS_V3)
        self._signalfd = fd
        return fd

    def _spawn_child(self) -> int:
        return self._ops.fork()

    def _drain_signalfd(self) -> tuple[bytes, ...]:
        if self._signalfd is None:
            raise RuntimeError("signal supervisor is not installed")
        records: list[bytes] = []
        while True:
            outcome, raw, signal_name, signal_code = (
                self._ops.read_signalfd_record(self._signalfd, 128)
            )
            if outcome == "EAGAIN":
                if raw is None and signal_name is None and signal_code is None:
                    return tuple(records)
                raise RuntimeError("malformed signalfd EAGAIN outcome")
            if (
                outcome != "record"
                or type(raw) is not bytes
                or type(signal_name) is not str
                or type(signal_code) is not str
            ):
                raise RuntimeError("invalid signalfd read outcome")
            if len(raw) != 128:
                raise RuntimeError("short signalfd record")
            if (signal_name, signal_code) not in _SIGNALFD_CODE_ALLOWLIST_V3:
                raise RuntimeError("unknown signalfd signal code")
            records.append(raw)

    def _drain_children(self) -> tuple[int, ...]:
        reaped: list[int] = []
        while True:
            kind, pid = self._ops.waitid("P_ALL", 0, _WAITID_FLAGS_V3)
            if kind == "child":
                reaped.append(pid)
                continue
            if kind in ("zero", "ECHILD") and pid == 0:
                return tuple(reaped)
            raise RuntimeError("invalid waitid outcome")
