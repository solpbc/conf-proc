#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Exercise native signal ABI and actual reap through the existing controller."""
import os
from pathlib import Path
import select
import signal
import sys
import time
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from conf_proc_spp_candidate_controller import make_signal_supervisor

old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
numbers = (signal.SIGCHLD, signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT, signal.SIGPIPE)
old_handlers = {n: signal.getsignal(n) for n in numbers}
ops = None
try:
    controller, ops, fd = make_signal_supervisor()
    assert not os.get_blocking(fd) and not os.get_inheritable(fd)
    assert controller.run_event('signal_ready') == ()
    pid = controller.run_event('launch_child')
    if pid == 0:
        os._exit(17)
    ready, _, _ = select.select([fd], [], [], 2)
    assert ready == [fd]
    events = controller.run_event('signal_ready')
    assert len(events) == 1 and len(events[0]) == 128
    assert controller.run_event('child_exit') == (pid,)
    assert ops.take_exit(pid) == (os.CLD_EXITED, 17)
    assert controller.run_event('before_blocking_epoll_wait') == ()
    try:
        ops.read_signalfd_record(fd, 127)
    except RuntimeError:
        pass
    else:
        raise AssertionError('incorrect signalfd record size accepted')
    print('ok actual child exit, native signalfd ABI, nonblocking drain and waitid status')
finally:
    if ops is not None:
        ops.close()
    for n, handler in old_handlers.items():
        signal.signal(n, handler)
    signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)

# A native signal read failure must reach global socket/grant revocation,
# even before the caller can handle the exception. Substitute only the failed
# read and namespace-wide kill; exercise the real controller and socket owner.
import socket
from unittest.mock import patch
from conf_proc_spp_candidate_controller import CandidateController
from conf_proc_spp_candidate_session import CandidateSessionOwner
from conf_proc_spp_boot_v3_resource import ServingResourceReducerV3
controller = CandidateController.__new__(CandidateController)
controller.failed = False
controller.ledger = ServingResourceReducerV3()
controller.sessions = CandidateSessionOwner(controller.ledger)
controller.signals, controller.kernel, fd = make_signal_supervisor()
controller.children = {}
controller.results = {}
client, peer = socket.socketpair()
try:
    token = controller.ledger.session_acquire()
    controller.sessions.adopt(token, client, time.monotonic_ns()+1_000_000_000)
    with patch.object(controller.kernel, 'waitid', side_effect=OSError('native reap failed')), \
            patch('conf_proc_spp_candidate_controller.os.kill') as kill:
        try:
            controller.step()
        except OSError:
            pass
        else:
            raise AssertionError('native failure accepted')
        assert controller.failed and controller.ledger.revoked
        kill.assert_called_once_with(-1, signal.SIGKILL)
    peer.settimeout(1)
    assert peer.recv(1) == b''
    print('ok native controller fault revokes actual sockets and grants')
finally:
    client.close(); peer.close()
    controller.sessions.close(); controller.kernel.close()
    for n, handler in old_handlers.items():
        signal.signal(n, handler)
    signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
