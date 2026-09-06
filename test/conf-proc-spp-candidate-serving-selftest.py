#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Native PID1 readiness transport, live process census and rejecting twins."""
from pathlib import Path
import ctypes
import hashlib
import os
import signal
import socket
import subprocess
import sys
import time
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import conf_proc_spp_candidate_serving as serving
from conf_proc_spp_candidate_controller import CandidateController
from conf_proc_spp_candidate_launch import _drop_bounding_set
from conf_proc_spp_boot_v3_wire import (decode_standalone_readiness_probe_v3,
    StandaloneReadinessResultV3, encode_standalone_readiness_result_v3)


class ResourceLeaves:
    def check(self): pass
    def require_empty(self, role): pass


def drop_caps():
    libc = ctypes.CDLL(None, use_errno=True)
    assert libc.prctl(38, 1, 0, 0, 0) == 0
    _drop_bounding_set()
    header = (ctypes.c_uint * 2)(0x20080522, 0)
    data = (ctypes.c_uint * 6)()
    assert libc.capset(ctypes.byref(header), ctypes.byref(data)) == 0


def child_case(case):
    assert os.getpid() == 1
    from conf_proc_spp_candidate_isolation import restrict_pid1_capabilities
    restrict_pid1_capabilities()
    c = CandidateController()
    c.cgroups = ResourceLeaves()
    c.results.update({'cold-inference': (os.CLD_EXITED, 0), 'cold-asr': (os.CLD_EXITED, 0)})
    expected = hashlib.sha256(Path('/proc/self/exe').read_bytes()).digest()
    if case == 'forged-executable': expected = b'z'*32
    runner = serving.CandidateServingWorkloads(c, {'inference': expected, 'asr': expected})
    launched = []
    native_read = serving._read

    def read_leaf(path, cap):
        if path.endswith('/cgroup'):
            pid = int(path.split('/')[2])
            role = 'other' if case == 'wrong-cgroup' else c.children[pid]
            return f'0::/spp/{role}\n'.encode()
        return native_read(path, cap)

    def launch(controller, role, mode, listener, readiness):
        assert controller is c and mode == 'serve'
        pid = c.signals.run_event('launch_child')
        if pid == 0:
            try:
                signal.pthread_sigmask(signal.SIG_SETMASK, set())
                channel = socket.socket(fileno=os.dup(readiness))
                probe = decode_standalone_readiness_probe_v3(channel.recv(33))
                if case != 'retained-capabilities': drop_caps()
                if case == 'timeout': time.sleep(10)
                result = StandaloneReadinessResultV3(probe.role_id, 1, probe.census_generation,
                    probe.absolute_monotonic_deadline_ns, os.getpid(), 0, 0, expected)
                from dataclasses import replace
                changes = {
                    'wrong-role': {'role_id': 3}, 'wrong-pid': {'supervised_child_pid': os.getpid()+1},
                    'wrong-uid': {'role_uid': 1}, 'wrong-generation': {'census_generation': 2},
                    'wrong-deadline': {'absolute_monotonic_deadline_ns': probe.absolute_monotonic_deadline_ns+1},
                    'wrong-executable': {'executable_sha256': b'z'*32},
                }
                if case in changes: result = replace(result, **changes[case])
                raw = encode_standalone_readiness_result_v3(result)
                if case == 'short': raw = raw[:-1]
                if case == 'oversize': raw += b'xx'
                if case == 'rights':
                    import array
                    channel.sendmsg([raw], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [listener]))])
                elif case == 'wrong-sender':
                    if os.fork() == 0:
                        channel.send(raw)
                        os._exit(0)
                else: channel.send(raw)
                if case == 'duplicate': channel.send(raw)
                if case == 'dies': os._exit(17)
                time.sleep(20)
                os._exit(0)
            except BaseException:
                import traceback
                traceback.print_exc()
                os._exit(126)
        c.register_child(pid, role)
        launched.append(pid)
        return pid

    positive = case in ('good', 'repeat', 'cohort-death', 'revoke-error')
    try:
        with patch.object(serving, 'launch_workload', launch), \
                patch.object(serving, 'runtime', return_value=SimpleNamespace(uid=0)), \
                patch.object(serving, '_read', read_leaf), \
                patch.object(serving, 'STARTUP_NS', 2_000_000_000):
            try:
                first = runner.start('inference')
                runner.check()
            except Exception:
                if positive: raise
                assert c.failed and c.ledger.revoked
                return
            assert positive, 'rejecting readiness accepted: '+case
            assert first.pid == launched[0] and first.executable_sha256 == expected
            assert c.children[first.pid] == 'inference'
            if case == 'repeat':
                try: runner.start('inference')
                except RuntimeError:
                    assert c.failed and c.ledger.revoked
                    return
                raise AssertionError('repeated cohort accepted')
            second = runner.start('asr')
            assert second.pid == launched[1] and second.pid != first.pid
            runner.check()
            assert len(runner.identities) == 2 and not c.ledger.sessions
            if case == 'revoke-error':
                sockets = (*runner.listeners.values(), *runner.channels.values())
                original_stop = c.fail_stop
                def broken_stop():
                    original_stop()
                    raise RuntimeError('injected revocation failure')
                os.kill(first.pid, signal.SIGKILL)
                time.sleep(0.05)
                with patch.object(c, 'fail_stop', broken_stop):
                    try: runner.check()
                    except RuntimeError:
                        assert c.failed and c.ledger.revoked
                        assert not runner.listeners and not runner.channels
                        assert all(item.fileno() == -1 for item in sockets)
                        return
                    raise AssertionError('revocation fault retained serving resources')
            if case == 'cohort-death':
                os.kill(first.pid, signal.SIGKILL)
                time.sleep(0.05)
                try: runner.check()
                except Exception:
                    assert c.failed and c.ledger.revoked and not runner.listeners
                    return
                raise AssertionError('dead cohort remained ready')
    finally:
        c.fail_stop()
        runner.close()
        c.sessions.close()
        c.kernel.close()


if len(sys.argv) == 2:
    child_case(sys.argv[1])
else:
    cases = ('good','repeat','cohort-death','wrong-role','wrong-pid','wrong-uid',
             'wrong-generation','wrong-deadline','wrong-executable','short','oversize',
             'rights','wrong-sender','duplicate','dies','timeout',
             'forged-executable','wrong-cgroup','retained-capabilities','revoke-error')
    for case in cases:
        subprocess.run(['/usr/bin/bwrap','--unshare-all','--as-pid-1','--die-with-parent',
            '--uid','0','--gid','0','--cap-add','ALL','--ro-bind','/','/','--proc','/proc','--dev','/dev',
            '--',sys.executable,str(Path(__file__).resolve()),case],check=True,timeout=15)
        print('ok native serving readiness',case,flush=True)
