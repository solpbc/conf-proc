#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Prepare fixed synthetic CUDA work; this supplies no attestation or lease."""
from __future__ import annotations
import ctypes as ct
import json
import os
import sys

LIBRARY = '/usr/lib/x86_64-linux-gnu/libnvidia-ml.so.595.71.05'


class _Settings(ct.Structure):
    _fields_ = [(name, ct.c_uint) for name in (
        'version', 'environment', 'cc', 'devtools', 'multigpu')]


class _Caps(ct.Structure):
    _fields_ = [('cpu', ct.c_uint), ('gpu', ct.c_uint)]


class _Nvml:
    def __init__(self) -> None:
        self.lib = ct.CDLL(LIBRARY, mode=os.RTLD_NOW | os.RTLD_LOCAL)

    def call(self, name: str, *arguments: object) -> None:
        fn = getattr(self.lib, name)
        fn.restype = ct.c_int
        fn.argtypes = [type(arg) for arg in arguments]
        result = fn(*arguments)
        if result != 0:
            raise RuntimeError(f'{name} failed ({result})')


def _identity(api: _Nvml) -> ct.c_void_p:
    count = ct.c_uint()
    api.call('nvmlDeviceGetCount_v2', ct.pointer(count))
    if count.value != 1:
        raise RuntimeError('synthetic GPU bootstrap requires exactly one device')
    device = ct.c_void_p()
    api.call('nvmlDeviceGetHandleByIndex_v2', ct.c_uint(0), ct.pointer(device))
    if not device.value:
        raise RuntimeError('GPU handle is absent')
    name = ct.create_string_buffer(96)
    api.call('nvmlDeviceGetName', device, name, ct.c_uint(len(name)))
    if name.value != b'NVIDIA H100 NVL':
        raise RuntimeError('GPU model differs')
    settings = _Settings(version=(1 << 24) | ct.sizeof(_Settings))
    api.call('nvmlSystemGetConfComputeSettings', ct.pointer(settings))
    if (settings.environment, settings.cc, settings.devtools, settings.multigpu) != (2, 1, 0, 0):
        raise RuntimeError('GPU requires production CC-on without devtools or multi-GPU mode')
    caps = _Caps()
    api.call('nvmlSystemGetConfComputeCapabilities', ct.pointer(caps))
    if caps.cpu not in (3, 4) or caps.gpu != 1:
        raise RuntimeError('GPU platform is not SNP confidential-compute capable')
    return device


def prepare_synthetic_gpu() -> dict[str, object]:
    """Run as a bounded bootstrap child before confinement and any ingress.

    Kernel persistence retains the SPDM device state between helper processes.
    The Ready bit enables only CUDA execution; the independent fresh composite
    appraiser must still authorize every later secret-bearing session.
    """
    if os.geteuid() != 0:
        raise RuntimeError('GPU bootstrap requires root')
    api = _Nvml()
    api.call('nvmlInit_v2')
    try:
        device = _identity(api)
        api.call('nvmlDeviceSetPersistenceMode', device, ct.c_uint(1))
        persistent = ct.c_uint()
        api.call('nvmlDeviceGetPersistenceMode', device, ct.pointer(persistent))
        if persistent.value != 1:
            raise RuntimeError('GPU persistence readback differs')
        api.call('nvmlSystemSetConfComputeGpusReadyState', ct.c_uint(1))
        ready = ct.c_uint()
        api.call('nvmlSystemGetConfComputeGpusReadyState', ct.pointer(ready))
        if ready.value != 1:
            raise RuntimeError('GPU Ready readback differs')
        _identity(api)
    finally:
        api.call('nvmlShutdown')
    # A separate library initialization must see the state after all prior
    # client references have closed. Never treat a setter's return as readback.
    api.call('nvmlInit_v2')
    try:
        device = _identity(api)
        persistent = ct.c_uint(); ready = ct.c_uint()
        api.call('nvmlDeviceGetPersistenceMode', device, ct.pointer(persistent))
        api.call('nvmlSystemGetConfComputeGpusReadyState', ct.pointer(ready))
        if (persistent.value, ready.value) != (1, 1):
            raise RuntimeError('GPU bootstrap state did not survive client shutdown')
    finally:
        api.call('nvmlShutdown')
    return {'gpu': 'NVIDIA H100 NVL', 'cc_on': True, 'devtools': False,
            'persistence': True, 'cuda_ready': True, 'session_authorized': False}


if __name__ == '__main__':
    if len(sys.argv) != 1:
        raise SystemExit('GPU bootstrap takes no arguments')
    print(json.dumps(prepare_synthetic_gpu(), sort_keys=True, separators=(',', ':')))
