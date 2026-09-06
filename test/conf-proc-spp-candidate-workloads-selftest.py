#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Independent interpreter and synthetic output rejection cases."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from conf_proc_spp_candidate_workloads import (
    appraise_asr_outputs, appraise_inference_outputs, fixed_environment,
    launch_argv, validate_interpreter,
)

class WorkloadTests(unittest.TestCase):
    def test_distinct_actual_launch_interpreters(self):
        self.assertEqual(launch_argv('inference','cold')[:4], ('/usr/bin/python3.12','-I','-B','-S'))
        self.assertEqual(launch_argv('asr','serve')[:4], ('/usr/bin/python3.10','-I','-B','-S'))
        for role, version in [('inference',(3,12)), ('asr',(3,10))]:
            path=f'/usr/lib/python{version[0]}.{version[1]}'
            exe=f'/usr/bin/python{version[0]}.{version[1]}'
            validate_interpreter(role,version,exe,(path,path+'/lib-dynload'))
            for bad in (('/tmp',), ('',), (path,'/opt/other-runtime'), ('/usr/lib/python3.11',)):
                with self.assertRaises(RuntimeError):validate_interpreter(role,version,exe,bad)
            with self.assertRaises(RuntimeError):validate_interpreter(role,(3,11),exe,(path,))
            with self.assertRaises(RuntimeError):validate_interpreter(role,version,'/usr/bin/python', (path,))
        for role in ('inference','asr'):
            with self.assertRaises(ValueError):launch_argv(role,'arbitrary')
        with self.assertRaises(ValueError):launch_argv('plugin','cold')

    def test_asr_fixed_inputs_and_numbers(self):
        fox='The quick brown fox jumps over the lazy dog.'
        for arithmetic in ('Seven plus five equals twelve.', '7 plus 5 equals 12.'):
            appraise_asr_outputs([fox,arithmetic])
        for outputs in ([],[fox],['',''],[fox,fox],['7 plus 5 equals 12.',fox],
                        [fox,'7 plus 6 equals 12'],[fox,'7 plus 5 equals 13'],
                        [fox,'plus equals'],[fox,'twelve'],[fox,'7 plus 5 equals 12. 999']):
            with self.assertRaises(ValueError):appraise_asr_outputs(outputs)

    def test_inference_requires_distinct_correct_work(self):
        appraise_inference_outputs(['12','4'])
        for outputs in (['',''],['12','12'],['4','12'],['12','5'],['unrelated','4'],['12'],['12','4','extra']):
            with self.assertRaises(ValueError):appraise_inference_outputs(outputs)

    def test_asr_adopts_existing_listener_without_binding_again(self):
        import socket
        from asr_shim import AsrServer, Metrics
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0))
            listener.listen(1)
            address=listener.getsockname()
            with AsrServer(address, None, Metrics(), 1.0, inherited_socket=listener) as server:
                self.assertNotEqual(server.socket.fileno(),listener.fileno())
                self.assertEqual(server.socket.getsockname(),address)
                with socket.create_connection(address,timeout=1) as client:
                    accepted,_=server.socket.accept()
                    with accepted:
                        client.sendall(b'actual-inherited-fd')
                        self.assertEqual(accepted.recv(64),b'actual-inherited-fd')
            self.assertGreaterEqual(listener.fileno(),0)
            with self.assertRaises(ValueError):
                AsrServer(('127.0.0.1',address[1]+1), None, Metrics(),1.0,inherited_socket=listener)

    def test_environment_closes_ambient_paths_and_plugins(self):
        env=fixed_environment('inference')
        self.assertNotIn('PYTHONPATH',env)
        self.assertNotIn('LD_PRELOAD',env)
        self.assertEqual(env['HF_HUB_OFFLINE'],'1')
        # The pinned SGLang loader treats a truthy comma as an empty allowed set;
        # an empty string instead means unrestricted discovery.
        self.assertTrue(env['SGLANG_PLUGINS'])
        self.assertEqual({s.strip() for s in env['SGLANG_PLUGINS'].split(',') if s.strip()},set())

if __name__=='__main__':unittest.main()
