#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Native cold children and file IO with a substitutable kernel control leaf."""
from pathlib import Path
import errno
import hashlib
import os
import signal
import subprocess
import sys
import time
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import conf_proc_spp_candidate_finite as finite
import conf_proc_spp_candidate_cold as cold
from conf_proc_spp_candidate_controller import CandidateController
from conf_proc_spp_diag_controller import ControllerIdentity

class Limits:
    def check(self):pass
    def require_empty(self,role):pass

def inside(case):
    Path('/tmp/control').write_bytes(b'')
    expected=b'actual read-only kernel stream leaf'
    if case=='empty':expected=b''
    if case=='oversize':expected=b'x'*1025
    Path('/tmp/stream').write_bytes(expected)
    fd=os.open('/tmp/control',os.O_WRONLY|os.O_CLOEXEC)
    os.dup2(fd,6,inheritable=False)
    if fd!=6:os.close(fd)
    c=CandidateController();c.cgroups=Limits()
    identity=ControllerIdentity(b'c'*32,b'r'*32,b'p'*32)
    commands=[];controls=[]
    original_open=os.open;original_stat=os.stat;original_write=os.write;original_read=os.read
    current_phase=1
    stream_fd=None
    def open_leaf(path,*args,**kwargs):
        nonlocal stream_fd
        if path==finite.STREAM:
            assert current_phase==15,'stream opened before SEAL'
            if case=='read-error':raise OSError(errno.EIO,'injected unavailable trace')
            path='/tmp/stream'
            stream_fd=original_open(path,*args,**kwargs)
            return stream_fd
        return original_open(path,*args,**kwargs)
    def stat_leaf(path,*args,**kwargs):
        if path==finite.CONTROL:path='/tmp/stream' if case=='wrong-descriptor' else '/tmp/control'
        elif path==finite.STREAM:path='/tmp/stream'
        return original_stat(path,*args,**kwargs)
    def write_leaf(fd,data):
        nonlocal current_phase
        if fd==6:
            # Independent fixed byte offsets from SPPCMD1, not encode_command.
            assert len(data)==128 and data[:8]==b'SPPCMD1\0'
            phase=int.from_bytes(data[112:114],'big')
            if case=='short-write' and phase==3:return 127
            if case=='kernel-denial' and phase==3:raise OSError(errno.EIO,'kernel rejected transition')
            commands.append(data);current_phase=phase
        return original_write(fd,data)
    def launch(controller,role,mode,output):
        assert controller is c and mode=='cold'
        pid=c.signals.run_event('launch_child')
        if pid==0:
            signal.pthread_sigmask(signal.SIG_SETMASK,set())
            raw=(b'{"outputs":["12","4"],"role":"inference"}' if role=='inference' else
                 b'{"outputs":["The quick brown fox jumps over the lazy dog.","Seven plus five equals twelve."],"role":"asr"}')
            if case=='wrong-output':raw=b'{"outputs":["12","12"],"role":"inference"}'
            os.write(output,raw)
            if case=='unreaped':time.sleep(10)
            os._exit(0)
        c.register_child(pid,'cold-'+role)
        return pid
    def direct(action,value):
        controls.append((current_phase,action,value))
        assert 4<=current_phase<=13
        assert not c.children
        return case!='negative-failed'
    positive=case in ('good','repeat')
    try:
        with patch.object(os,'open',open_leaf),patch.object(os,'stat',stat_leaf),patch.object(os,'write',write_leaf), \
             patch.object(cold,'launch_workload',launch),patch.object(cold,'COLD_BUDGET_NS',1_500_000_000), \
             patch.object(finite,'_real_direct',direct),patch.object(finite,'MAX_STREAM_BYTES',1024):
            try:
                runner=finite.CandidateFiniteInterval(c,identity)
                native_quiescent=runner.cold._quiescent
                def quiescent():
                    assert current_phase in (1,2,3,15),'extra census polluted a control/final phase'
                    native_quiescent()
                with patch.object(runner.cold,'_quiescent',quiescent):
                    result=runner.run()
            except Exception:
                if positive:raise
                # Constructor rejection precedes controller ownership; run failures revoke.
                if case!='wrong-descriptor':assert c.failed and c.ledger.revoked
                return
            assert positive,'rejecting finite interval accepted: '+case
            assert result.stream==expected and result.stream_sha256==hashlib.sha256(expected).digest()
            assert [x.role for x in result.cold]==['inference','asr'] and not c.children
            assert [int.from_bytes(x[112:114],'big') for x in commands]==list(range(2,16))
            assert len(controls)==10 and not c.ledger.sessions
            if case=='repeat':
                try:runner.run()
                except RuntimeError:assert c.failed and c.ledger.revoked
                else:raise AssertionError('repeated finite interval accepted')
    finally:
        c.fail_stop();c.sessions.close();c.kernel.close()
        try:os.close(6)
        except OSError:pass

if len(sys.argv)==2:inside(sys.argv[1])
else:
    cases=('good','repeat','wrong-output','unreaped','negative-failed','short-write','kernel-denial','wrong-descriptor','empty','oversize','read-error')
    for case in cases:
        subprocess.run(['/usr/bin/bwrap','--unshare-all','--as-pid-1','--die-with-parent','--uid','0','--gid','0',
            '--ro-bind','/','/','--proc','/proc','--dev','/dev','--tmpfs','/tmp','--',sys.executable,str(Path(__file__).resolve()),case],check=True,timeout=12)
        print('ok native finite interval',case,flush=True)
