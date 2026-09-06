#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Fixed cold/serving entry for the isolated candidate workload roots."""
from __future__ import annotations

import importlib.util
import os
import sys


def _bootstrap(role: str):
    name = 'conf_proc_spp_candidate_workloads'
    path = '/usr/lib/spp/' + name + '.py'
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError('candidate bootstrap unavailable')
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    module.install_import_paths(role)
    if dict(os.environ) != module.fixed_environment(role):
        raise RuntimeError('candidate environment differs')
    if os.getuid() != module.runtime(role).uid or os.getgid() != module.runtime(role).uid:
        raise RuntimeError('candidate role credentials differ')
    return module


def _readiness(role: str, executable_hash: bytes) -> None:
    import socket
    import struct
    import time
    from conf_proc_spp_boot_v3_wire import (
        StandaloneReadinessResultV3, decode_standalone_readiness_probe_v3,
        encode_standalone_readiness_result_v3,
    )
    channel = socket.socket(fileno=4)
    sent = False
    try:
        if (channel.family != socket.AF_UNIX
                or channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_SEQPACKET):
            raise RuntimeError('candidate readiness channel differs')
        channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        channel.settimeout(30)
        data, ancillary, flags, _address = channel.recvmsg(33, socket.CMSG_SPACE(12))
        if (flags or len(ancillary) != 1 or ancillary[0][:2] != (socket.SOL_SOCKET, socket.SCM_CREDENTIALS)
                or len(ancillary[0][2]) != 12 or struct.unpack('3i', ancillary[0][2]) != (1,0,0)):
            raise RuntimeError('candidate readiness sender differs')
        probe = decode_standalone_readiness_probe_v3(data)
        role_id = {'inference': 2, 'asr': 3}[role]
        if probe.role_id != role_id or time.monotonic_ns() >= probe.absolute_monotonic_deadline_ns:
            raise RuntimeError('candidate readiness probe expired or mismatched')
        result = StandaloneReadinessResultV3(role_id, 1, probe.census_generation,
            probe.absolute_monotonic_deadline_ns, os.getpid(), os.getuid(), os.getgid(), executable_hash)
        wire = encode_standalone_readiness_result_v3(result)
        if channel.send(wire) != len(wire):
            raise RuntimeError('candidate readiness send incomplete')
        sent = True
    finally:
        if sent:
            channel.detach()  # Preserve the inspected role FD census while serving.
        else:
            channel.close()


def _sglang_ports() -> None:
    """Select fixed loopback TCP IPC, which the existing trace format records."""
    from sglang.srt.server_args import PortArgs
    def fixed_ports(args, dp_rank=None, worker_ports=None):
        if (args.tp_size != 1 or args.nnodes != 1 or args.tokenizer_worker_num != 1
                or args.enable_dp_attention or dp_rank is not None or worker_ports is not None):
            raise RuntimeError('candidate SGLang topology differs')
        return PortArgs(tokenizer_ipc_name='tcp://127.0.0.1:7001',
            scheduler_input_ipc_name='tcp://127.0.0.1:7002',
            detokenizer_ipc_name='tcp://127.0.0.1:7003', nccl_port=7000,
            rpc_ipc_name='tcp://127.0.0.1:7004', metrics_ipc_name='tcp://127.0.0.1:7005',
            tokenizer_worker_ipc_name=None, instance_id='spp-candidate')
    PortArgs.init_new = staticmethod(fixed_ports)


def _serve_asr(workload) -> None:
    import socket
    from asr_shim import AsrServer, BatchWorker, Metrics, NemoTranscriber, check_cc_production
    check_cc_production()
    workload.verify_weights('asr')
    listener = socket.socket(fileno=3)
    metrics = Metrics()
    worker = BatchWorker(lambda: NemoTranscriber('/models/parakeet-tdt-0.6b-v3.nemo', True),
                         metrics, 1, 0.01, 1)
    with AsrServer(('127.0.0.1',8100), worker, metrics, 60.0, inherited_socket=listener) as server:
        listener.close()
        worker.start()
        if not worker.ready.wait(600):
            raise TimeoutError('candidate ASR startup expired')
        _readiness('asr', bytes.fromhex(workload.file_sha256('/proc/self/exe')))
        server.serve_forever(poll_interval=0.1)


def _serve_inference(workload) -> None:
    import socket
    import uvicorn
    from sglang.srt.server_args import ServerArgs
    from sglang.srt.entrypoints import http_server
    workload.verify_weights('inference')
    listener = socket.socket(fileno=3)
    if (listener.family != socket.AF_INET or listener.getsockname() != ('127.0.0.1',8000)
            or listener.getsockopt(socket.SOL_SOCKET,socket.SO_ACCEPTCONN) != 1):
        raise RuntimeError('candidate inference listener differs')
    listener.detach()  # Uvicorn duplicates fd3; PID1 retains revocation ownership.
    run_uvicorn = uvicorn.run
    def inherited_run(app, **kwargs):
        if app is not http_server.app or kwargs.get('host') != '127.0.0.1' or kwargs.get('port') != 8000:
            raise RuntimeError('unexpected candidate HTTP server')
        kwargs.pop('host'); kwargs.pop('port')
        return run_uvicorn(app, fd=3, access_log=False, **kwargs)
    uvicorn.run = inherited_run
    args = ServerArgs(**workload.inference_arguments())
    try:
        http_server.launch_server(args, launch_callback=lambda: _readiness('inference',
            bytes.fromhex(workload.file_sha256('/proc/self/exe'))))
    finally:
        uvicorn.run = run_uvicorn


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] not in ('asr','inference') or sys.argv[2] not in ('cold','serve'):
        raise ValueError('candidate workload argv differs')
    role, mode = sys.argv[1:]
    workload = _bootstrap(role)
    os.set_inheritable(3, False)
    if mode == 'serve':
        os.set_inheritable(4, False)
    if role == 'inference':
        _sglang_ports()
    if mode == 'cold':
        import json
        result = workload.cold_asr() if role == 'asr' else workload.cold_inference()
        data = json.dumps(result, sort_keys=True, separators=(',',':')).encode('ascii')
        if len(data) > 4096 or os.write(3, data) != len(data):
            raise RuntimeError('candidate cold result incomplete')
        return 0
    if role == 'asr':
        _serve_asr(workload)
    else:
        _serve_inference(workload)
    raise RuntimeError('candidate serving cohort returned')


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception:
        # Content and vendor exceptions belong only to bounded cold evidence;
        # serving failures must not print request data or leave worker children.
        os._exit(1)
