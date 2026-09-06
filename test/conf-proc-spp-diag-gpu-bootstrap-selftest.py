#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
import ctypes as ct
from unittest.mock import patch
import conf_proc_spp_diag_gpu_bootstrap as gpu


class Fake:
    def __init__(self, change=None, fail=0):
        self.change = change; self.fail = fail; self.calls = []; self.init = 0

    def call(self, name, *args):
        self.calls.append(name)
        if len(self.calls) == self.fail:
            raise RuntimeError('injected native failure')
        if name == 'nvmlInit_v2': self.init += 1
        elif name == 'nvmlDeviceGetCount_v2': args[0].contents.value = 2 if self.change == 'count' else 1
        elif name == 'nvmlDeviceGetHandleByIndex_v2': args[1].contents.value = 0 if self.change == 'handle' else 7
        elif name == 'nvmlDeviceGetName': args[1].value = b'other' if self.change == 'model' else b'NVIDIA H100 NVL'
        elif name == 'nvmlSystemGetConfComputeSettings':
            x = args[0].contents
            x.environment = 1 if self.change == 'simulation' else 2
            x.cc = 0 if self.change == 'cc_off' or (self.change == 'lost_cc' and self.init == 2) else 1
            x.devtools = int(self.change == 'devtools')
            x.multigpu = int(self.change == 'multigpu')
        elif name == 'nvmlSystemGetConfComputeCapabilities':
            args[0].contents.cpu = 1 if self.change == 'cpu' else 3
            args[0].contents.gpu = 0 if self.change == 'gpu' else 1
        elif name == 'nvmlDeviceGetPersistenceMode':
            args[1].contents.value = int(self.change != 'persistence' and not (self.change == 'lost_persistence' and self.init == 2))
        elif name == 'nvmlSystemGetConfComputeGpusReadyState':
            args[0].contents.value = int(self.change != 'ready' and not (self.change == 'lost_ready' and self.init == 2))


def run(api):
    with patch.object(gpu, '_Nvml', return_value=api), patch.object(gpu.os, 'geteuid', return_value=0):
        return gpu.prepare_synthetic_gpu()


positive = Fake()
assert run(positive) == {'gpu': 'NVIDIA H100 NVL', 'cc_on': True, 'devtools': False,
                         'persistence': True, 'cuda_ready': True, 'session_authorized': False}
assert positive.calls.count('nvmlInit_v2') == positive.calls.count('nvmlShutdown') == 2
assert positive.calls.index('nvmlDeviceGetPersistenceMode') < positive.calls.index('nvmlSystemSetConfComputeGpusReadyState')
for change in ('count', 'handle', 'model', 'simulation', 'cc_off', 'devtools', 'multigpu', 'cpu', 'gpu',
               'persistence', 'ready', 'lost_persistence', 'lost_ready', 'lost_cc'):
    api = Fake(change)
    try: run(api)
    except RuntimeError: pass
    else: raise AssertionError(change)
    if change in ('count', 'handle', 'model', 'simulation', 'cc_off', 'devtools', 'multigpu', 'cpu', 'gpu'):
        assert not any(name.startswith(('nvmlDeviceSet', 'nvmlSystemSet')) for name in api.calls)
for call in range(1, len(positive.calls) + 1):
    try: run(Fake(fail=call))
    except RuntimeError: pass
    else: raise AssertionError(('native failure accepted', call))
assert ct.sizeof(gpu._Settings) == 20 and ct.sizeof(gpu._Caps) == 8
print('PASS fixed GPU identity, CC/devtools gating, persistence/readiness readbacks, client-shutdown continuity and every native failure')

with patch.object(gpu.os, 'geteuid', return_value=61101), patch.object(gpu, '_Nvml', side_effect=AssertionError('non-root loaded native library')):
    try:
        gpu.prepare_synthetic_gpu()
    except RuntimeError:
        pass
    else:
        raise AssertionError('non-root GPU mutation accepted')
