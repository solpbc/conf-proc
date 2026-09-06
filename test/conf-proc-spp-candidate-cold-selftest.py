#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Native PID1 pipes, signalfd/waitid and rejecting cold-workload outcomes."""
from pathlib import Path
import os
import signal
import subprocess
import sys
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import conf_proc_spp_candidate_cold as cold
from conf_proc_json import canonical_dumps
from conf_proc_spp_candidate_controller import CandidateController

GOOD = {'inference': ['12', '4'], 'asr': [
    'The quick brown fox jumps over the lazy dog.', 'Seven plus five equals twelve.']}


class ResourceLeaves:
    # The actual cgroup filesystem/placement has separate native tests. These
    # leaves record that the real reap path required its role to be empty.
    def __init__(self):
        self.empty = []

    def check(self):
        pass

    def require_empty(self, role):
        self.empty.append(role)


def child_case(case):
    assert os.getpid() == 1
    controller = CandidateController()
    controller.cgroups = ResourceLeaves()
    runner = cold.CandidateColdWorkloads(controller)
    launched = []

    def launch(c, role, mode, result_fd):
        assert c is controller and mode == 'cold'
        pid = c.signals.run_event('launch_child')
        if pid == 0:
            try:
                signal.pthread_sigmask(signal.SIG_SETMASK, set())
                data = canonical_dumps({'role': role, 'outputs': GOOD[role]})
                if case == 'wrong-output':
                    data = canonical_dumps({'role': role, 'outputs': ['12', '12']})
                elif case == 'wrong-role':
                    data = canonical_dumps({'role': 'asr', 'outputs': GOOD[role]})
                elif case == 'extra-key':
                    data = canonical_dumps({'role': role, 'outputs': GOOD[role], 'accepted': True})
                elif case == 'duplicate-key':
                    data = b'{"outputs":["12","4"],"role":"inference","role":"inference"}'
                elif case == 'oversize':
                    data = b'x' * 4097
                elif case == 'empty':
                    data = b''
                elif case == 'truncated':
                    data = data[:-1]
                if case == 'partial-writes':
                    for part in (data[:5], data[5:]):
                        assert os.write(result_fd, part) == len(part)
                        time.sleep(0.02)
                elif data:
                    assert os.write(result_fd, data) == len(data)
                os.close(result_fd)
                if case == 'valid-but-alive':
                    time.sleep(20)
                if case == 'valid-but-signaled':
                    os.kill(os.getpid(), signal.SIGKILL)
                os._exit(17 if case == 'valid-but-failed' else 0)
            except BaseException:
                os._exit(126)
        c.register_child(pid, 'cold-' + role)
        launched.append(pid)
        return pid

    positive = case in ('good', 'partial-writes', 'repeat', 'wrong-order')
    try:
        with patch.object(cold, 'launch_workload', launch), \
                patch.object(cold, 'COLD_BUDGET_NS', 2_000_000_000):
            if case == 'wrong-order':
                try:
                    runner.run('asr')
                except RuntimeError:
                    assert controller.failed and not launched
                    return
                raise AssertionError('wrong order accepted')
            try:
                result = runner.run('inference')
            except Exception:
                if positive:
                    raise
                assert controller.failed and controller.ledger.revoked and not runner.results
                return
            assert positive, 'rejecting case accepted: ' + case
            assert result.pid == launched[0] and result.outputs == ('12', '4')
            assert controller.results['cold-inference'] == (os.CLD_EXITED, 0)
            assert controller.cgroups.empty.count('cold-inference') >= 2
            assert not controller.children and not controller.ledger.sessions
            assert not Path('/proc/self/task/1/children').read_text().strip()
            assert not controller.failed
            if case == 'repeat':
                try:
                    runner.run('inference')
                except RuntimeError:
                    assert controller.failed and len(launched) == 1
                    return
                raise AssertionError('cold workload rerun accepted')
            result = runner.run('asr')
            assert result.pid == launched[1] and result.outputs == tuple(GOOD['asr'])
            assert [x.role for x in runner.results] == ['inference', 'asr']
            assert not controller.children and not controller.ledger.sessions
    finally:
        controller.sessions.close()
        controller.kernel.close()


if len(sys.argv) == 2:
    child_case(sys.argv[1])
else:
    cases = ('good', 'partial-writes', 'repeat', 'wrong-order', 'wrong-output',
             'wrong-role', 'extra-key', 'duplicate-key', 'oversize', 'empty',
             'truncated', 'valid-but-alive', 'valid-but-failed', 'valid-but-signaled')
    for case in cases:
        subprocess.run(['/usr/bin/bwrap', '--unshare-all', '--as-pid-1', '--die-with-parent',
            '--uid', '0', '--gid', '0',
            '--ro-bind', '/', '/', '--proc', '/proc', '--dev', '/dev', '--',
            sys.executable, str(Path(__file__).resolve()), case], check=True, timeout=15)
        print('ok native cold collection', case, flush=True)
