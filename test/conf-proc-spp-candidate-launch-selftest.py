#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Exercise descriptor handoff on an actual child, including colliding slots."""
import fcntl
import json
import os
from pathlib import Path
import select
import socket
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from conf_proc_spp_candidate_launch import _install_fds

read_fd,write_fd=os.pipe2(os.O_CLOEXEC)
a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
pid=os.fork()
if pid==0:
    try:
        # Pin sources, then deliberately put them in each other's destinations.
        out=fcntl.fcntl(write_fd,fcntl.F_DUPFD_CLOEXEC,64)
        ready=fcntl.fcntl(a.fileno(),fcntl.F_DUPFD_CLOEXEC,64)
        os.dup2(out,4);os.dup2(ready,3)
        null=os.open('/dev/null',os.O_RDWR|os.O_CLOEXEC)
        _install_fds(null,4,3)
        held=[]
        for name in os.listdir('/proc/self/fd'):
            try:os.fstat(int(name))
            except OSError:continue
            held.append(int(name))
        assert sorted(held)==[0,1,2,3,4]
        assert all(os.get_inheritable(fd) for fd in held)
        channel=socket.socket(fileno=4)
        channel.send(b'correct-readiness-channel')
        os.write(3,json.dumps({'fds':held,'null_input':os.read(0,1)==b''}).encode())
        os._exit(0)
    except BaseException:
        os._exit(1)
os.close(write_fd);a.close()
try:
    assert select.select([read_fd],[],[],2)[0]==[read_fd]
    result=json.loads(os.read(read_fd,4096))
    assert result['null_input'] and sorted(result['fds'])==[0,1,2,3,4]
    b.settimeout(2);assert b.recv(64)==b'correct-readiness-channel'
    waited,status=os.waitpid(pid,0);assert waited==pid and status==0
    print('ok native child FD remapping preserves swapped sources and closes ambient descriptors')
finally:
    os.close(read_fd);b.close()
