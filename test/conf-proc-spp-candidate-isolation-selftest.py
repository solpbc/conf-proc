#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Actual network namespace, retained-socket and privilege-transition tests."""
from pathlib import Path
import ctypes,errno,json,os,socket,threading,subprocess,sys
ROOT=Path(__file__).resolve().parents[1]
if sys.argv[1:]!=['--inside']:
 result=subprocess.run(['/usr/bin/bwrap','--die-with-parent','--unshare-all','--as-pid-1',
  '--uid','0','--gid','0','--cap-add','ALL','--ro-bind','/','/','--proc','/proc','--dev','/dev',
  '--',sys.executable,str(Path(__file__).resolve()),'--inside'],capture_output=True,timeout=15)
 assert result.returncode==0,result.stderr.decode()
 report=json.loads(result.stdout)
 assert len(report)==6 and all(value is True for value in report.values()),report
 print(result.stdout.decode(),end='')
 raise SystemExit(0)
sys.path.insert(0,str(ROOT))
import conf_proc_spp_candidate_isolation as m
assert os.getpid()==1
# Reject a live sibling thread before any namespace mutation.
ready=threading.Event();release=threading.Event()
thread=threading.Thread(target=lambda:(ready.set(),release.wait(2)))
thread.start();assert ready.wait(1)
try:
 try:m.enter_workload_network()
 except RuntimeError:pass
 else:raise AssertionError('network transition accepted another live thread')
finally:release.set();thread.join()
# A child may still hold the old namespace even without a second PID1 thread.
read_fd,write_fd=os.pipe();child=os.fork()
if child==0:
 os.close(write_fd);os.read(read_fd,1);os._exit(0)
os.close(read_fd)
try:
 try:m.enter_workload_network()
 except RuntimeError:pass
 else:raise AssertionError('network transition accepted a live child')
finally:os.close(write_fd);assert os.waitpid(child,0)==(child,0)
m._loopback_up()
listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1)
original_port=listener.getsockname()[1]
client=socket.socket();client.connect(('127.0.0.1',original_port))
old=m._netns();new=m.enter_workload_network();assert old!=new
server,_=listener.accept()
# Retained connected/listener sockets continue in the original network namespace.
client.sendall(b'fixed-retained-channel');assert server.recv(64)==b'fixed-retained-channel'
# A newly opened socket cannot reach the old namespace's listening endpoint.
with socket.socket() as disconnected:
 disconnected.settimeout(0.2)
 try:disconnected.connect(('127.0.0.1',original_port))
 except OSError as e:assert e.errno==errno.ECONNREFUSED
 else:raise AssertionError('new socket reached original namespace')
m.restrict_pid1_capabilities();m.freeze_namespace_transitions()
libc=ctypes.CDLL(None,use_errno=True)
assert libc.unshare(0x10000000)==-1 and ctypes.get_errno()==errno.EPERM
assert libc.unshare(m.CLONE_NEWNET)==-1 and ctypes.get_errno()==errno.EPERM
assert libc.setns(-1,0)==-1 and ctypes.get_errno()==errno.EPERM
assert libc.syscall(435,0,0)==-1 and ctypes.get_errno()==errno.ENOSYS
for namespace in (0x10000000,0x40000000,0x00020000):
 child=libc.syscall(56,namespace|17,0,0,0,0)
 if child==0:os._exit(99)
 if child>0:os.kill(child,9);os.waitpid(child,0)
 assert child==-1 and ctypes.get_errno()==errno.EPERM
with socket.socket() as external:
 external.settimeout(0.2)
 try:external.connect(('192.0.2.1',443))
 except OSError as error:assert error.errno==errno.ENETUNREACH
 else:raise AssertionError('isolated process acquired external egress')
# Ordinary thread/fork remains available for fixed serving libraries.
result=[];t=threading.Thread(target=lambda:result.append('thread'));t.start();t.join();assert result==['thread']
pid=os.fork()
if pid==0:os._exit(0)
assert os.waitpid(pid,0)==(pid,0)
m.require_loopback_only(new)
client.sendall(b'still-fixed');assert server.recv(64)==b'still-fixed'
print(json.dumps({'namespace_changed':True,'new_socket_cannot_reach_original_namespace':True,'retained_channel_works':True,'namespace_transitions_denied':True,'thread_and_fork_work':True,'pid1_capability_census_exact':True}))
