#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Exercise resource readback failures and actual child release/capability leaves."""
import copy
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import conf_proc_spp_candidate_cgroups as c
from conf_proc_spp_candidate_launch import _await_parent_release


class Tests(unittest.TestCase):
    def setUp(self):
        self.role='inference';self.pid=234
        self.obj=c.CandidateCgroups.__new__(c.CandidateCgroups)
        self.obj.groups={self.role:9};self.obj.placed={}
        self.files={'memory.max':str(32*1024**3),'memory.swap.max':'0',
                    'memory.oom.group':'1','pids.max':'128','cgroup.type':'domain',
                    'cgroup.procs':'','cgroup.events':'populated 0\nfrozen 0',
                    'memory.events':'low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0',
                    'pids.events':'max 0'}

    def read(self,fd,name):
        self.assertEqual(fd,9);return self.files[name]

    def write(self,fd,name,value):
        self.assertEqual((fd,name,value),(9,'cgroup.procs',str(self.pid)))
        self.files[name]=value;self.files['cgroup.events']='populated 1\nfrozen 0'

    def place(self,write=None,membership=None):
        with patch.object(c,'_read',self.read),patch.object(c,'_write',write or self.write), \
             patch.object(c.Path,'read_text',return_value=membership or f'0::/spp/{self.role}\n'):
            self.obj.place(self.role,self.pid)

    def test_correct_placement_and_replay_denial(self):
        self.place();self.assertEqual(self.obj.placed,{self.role:self.pid})
        with self.assertRaises(RuntimeError):self.place()

    def test_each_wrong_limit_and_missing_or_nonzero_pressure_denies(self):
        original=copy.deepcopy(self.files)
        mutants={'memory.max':'max','memory.swap.max':'1','memory.oom.group':'0',
                 'pids.max':'max','cgroup.type':'threaded','memory.events':'oom 0',
                 'pids.events':'max 1','cgroup.procs':'99','cgroup.events':'populated 1\nfrozen 1'}
        for key,value in mutants.items():
            with self.subTest(key=key):
                self.files=original|{key:value}
                with self.assertRaises(RuntimeError):self.place()
                self.assertEqual(self.obj.placed,{})
        self.files=original|{'memory.events':original['memory.events'].replace('oom_kill 0','oom_kill 1')}
        with self.assertRaises(RuntimeError):self.place()

    def test_stale_write_wrong_process_and_wrong_hierarchy_deny(self):
        for writer in (lambda *args:None, lambda fd,name,value:self.files.update({'cgroup.procs':'235'})):
            with self.assertRaises(RuntimeError):self.place(write=writer)
            self.files['cgroup.procs']=''
        with self.assertRaises(RuntimeError):self.place(membership='0::/spp/asr\n')
        self.assertEqual(self.obj.placed,{})

    def test_later_pressure_and_surviving_descendant_fail(self):
        self.place()
        with patch.object(c,'_read',self.read):
            self.obj.check()
            with self.assertRaises(RuntimeError):self.obj.require_empty(self.role)
            self.files['cgroup.procs']='';self.files['cgroup.events']='populated 0\nfrozen 0'
            self.obj.require_empty(self.role)
            self.files['pids.events']='max 1'
            with self.assertRaises(RuntimeError):self.obj.check()

    def test_real_regular_filesystem_and_symlink_are_not_cgroup_limits(self):
        # Vary the filesystem while retaining root ownership as the control.
        fd=c._directory(-100,'/sys/fs/cgroup')
        try:
            self.assertIsInstance(c._read(fd,'cgroup.controllers'),str)
        finally:os.close(fd)
        with self.assertRaises(RuntimeError):c._directory(-100,'/')
        with tempfile.TemporaryDirectory() as root:
            path=Path(root);(path/'link').symlink_to(path,target_is_directory=True)
            for target in (path,path/'link'):
                with self.assertRaises((RuntimeError,OSError)):c._directory(-100,str(target))

    def test_real_child_cannot_proceed_until_parent_releases(self):
        read,write=os.pipe2(os.O_CLOEXEC);out,reply=os.pipe2(os.O_CLOEXEC)
        pid=os.fork()
        if pid==0:
            try:
                os.close(write);os.close(out);_await_parent_release(read)
                os.write(reply,b'executed');os._exit(0)
            except BaseException:os._exit(1)
        os.close(read);os.close(reply)
        try:
            self.assertFalse(select.select([out],[],[],0.1)[0])
            os.write(write,b'R');os.close(write);write=None
            self.assertTrue(select.select([out],[],[],2)[0])
            self.assertEqual(os.read(out,64),b'executed')
            self.assertEqual(os.waitpid(pid,0),(pid,0))
        finally:
            if write is not None:os.close(write)
            os.close(out)

    def test_real_release_pipe_eof_and_malformed_fail(self):
        for payload in (b'',b'X',b'RR'):
            read,write=os.pipe2(os.O_CLOEXEC)
            os.write(write,payload);os.close(write)
            with self.assertRaises(RuntimeError):_await_parent_release(read)

    def test_real_bounding_set_removed_in_disposable_namespace(self):
        code=("import sys;sys.path.insert(0,"+repr(str(ROOT))+");"
              "from conf_proc_spp_candidate_launch import _drop_bounding_set;"
              "from pathlib import Path;_drop_bounding_set();"
              "s=dict(x.split(':',1) for x in Path('/proc/self/status').read_text().splitlines() if ':' in x);"
              "assert int(s['CapBnd'].strip(),16)==0;print('bounding-set-empty')")
        result=subprocess.run(['/usr/bin/bwrap','--unshare-all','--uid','0','--gid','0',
            '--cap-add','CAP_SETPCAP','--ro-bind','/','/','--dev','/dev','--proc','/proc','--',sys.executable,'-c',code],
            capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertEqual(result.stdout,b'bounding-set-empty\n')


if __name__=='__main__':unittest.main()
