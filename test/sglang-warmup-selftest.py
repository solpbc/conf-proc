#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Exercise the pinned server warmup against the installed namespace guard."""
import argparse
import ast
import asyncio
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace as N

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from appliance.sglang_patches import OPENAI_PATH, PATCHES, replace_pinned


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--serving-root', type=Path, required=True)
    args = parser.parse_args()
    directory = args.serving_root / OPENAI_PATH
    warmup_patch = next(p for p in PATCHES if p[0] == '../http_server.py')
    adapter_patch = next(p for p in PATCHES if p[0] == 'serving_chat.py')
    server = (directory / warmup_patch[0]).read_bytes()
    adapter = replace_pinned((directory / adapter_patch[0]).read_bytes(), *adapter_patch[1:])
    patched = replace_pinned(server, *warmup_patch[1:])
    serving_base = (directory / 'serving_base.py').read_bytes()
    method = next(n for n in ast.walk(ast.parse(adapter))
        if isinstance(n, ast.FunctionDef) and n.name == '_convert_to_internal_request')
    guard = ast.FunctionDef(name='namespace', args=ast.arguments(posonlyargs=[],
        args=[ast.arg(arg='raw_request')], kwonlyargs=[], kw_defaults=[], defaults=[]),
        body=copy.deepcopy(method.body[:3]) + [ast.Return(value=ast.Name(id='cache_namespace', ctx=ast.Load()))],
        decorator_list=[])
    namespace = {}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[guard], type_ignores=[])), 'adapter-guard', 'exec'), namespace)
    def request(headers):
        return N(headers=N(getlist=lambda key: [value for name, value in headers if name.lower() == key]))
    for headers in ([], [('x-sol-device', 'a')], [('x-sol-device', 'g' * 64)],
                    [('x-sol-device', 'a' * 64), ('x-sol-device', 'b' * 64)]):
        try: namespace['namespace'](request(headers))
        except ValueError: pass
        else: raise AssertionError('invalid journal namespace accepted')
    assert len({namespace['namespace'](request([('x-sol-device', label * 64)]))
                for label in ('0', 'a', 'b')}) == 3
    handler = next(n for n in ast.walk(ast.parse(serving_base))
        if isinstance(n, ast.AsyncFunctionDef) and n.name == 'handle_request')
    handler.returns = None
    for arg in handler.args.args:
        arg.annotation = None
    handler_scope = {'monotonic_time': lambda: 0, 'GenerateReqInput': type('GenerateReqInput', (), {}),
        'EmbeddingReqInput': type('EmbeddingReqInput', (), {}), 'HTTPException': type('HTTPException', (Exception,), {}),
        'DS32EncodingError': type('DS32EncodingError', (Exception,), {})}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[handler], type_ignores=[])), 'serving-handler', 'exec'), handler_scope)
    class Serving:
        tokenizer_manager = N(request_logger=N(log_requests=False))
        def _validate_request(self, body): return None
        def _convert_to_internal_request(self, body, raw): return namespace['namespace'](raw), body
        async def _handle_non_streaming_request(self, *args): return N(status_code=200, text='')
        def create_error_response(self, message, err_type='BadRequestError', status_code=400):
            return N(status_code=status_code, text=message)
    results = []
    for label, source, expected in (('original-warmup', server, False), ('patched-warmup', patched, True)):
        function = next(n for n in ast.parse(source).body
            if isinstance(n, ast.FunctionDef) and n.name == '_execute_server_warmup')
        calls, killed = [], []
        def post(url, *, json, headers, **kwargs):
            raw = request(list(headers.items()))
            response = asyncio.run(handler_scope['handle_request'](Serving(), N(stream=False), raw))
            key = namespace['namespace'](raw) if response.status_code == 200 else None
            calls.append({'path': url.removeprefix('http://127.0.0.1:8000'),
                'namespace': key, 'status': response.status_code})
            return response
        scope = {'ServerArgs': object, 'requests': N(get=lambda *a, **kw: N(status_code=200,
            json=lambda: {'has_image_understanding': True, 'is_generation': True}), post=post,
            exceptions=N(RequestException=RuntimeError)), 'time': N(sleep=lambda _: None),
            'is_mps': lambda: False, '_global_state': N(tokenizer_manager=N(served_model_name='Qwen/Qwen3.5-4B')),
            'MINIMUM_PNG_PICTURE_BASE64': 'synthetic-image', 'envs': N(SGLANG_WARMUP_TIMEOUT=N(get=lambda: 0)),
            'logger': N(error=lambda *a: None, info=lambda *a: None),
            'get_exception_traceback': lambda: 'synthetic HTTP seam',
            'kill_process_tree': lambda pid: killed.append(pid), 'os': os, 'ServerStatus': N(Up='up')}
        exec(compile(ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[])), 'server-warmup', 'exec'), scope)
        server_args = N(api_key=None, url=lambda: 'http://127.0.0.1:8000', ssl_verify=lambda: True,
            skip_tokenizer_init=False, disaggregation_mode='null', debug_tensor_dump_input_file=None, dp_size=1)
        observed = scope['_execute_server_warmup'](server_args)
        assert observed is expected and bool(killed) is (not expected)
        assert len(calls) == 1 and calls[0]['path'] == '/v1/chat/completions'
        results.append({'variant': label, 'success': observed, 'termination_requested': bool(killed), 'calls': calls})
    print(json.dumps({'passed': True, 'http_server_input_sha256': hashlib.sha256(server).hexdigest(),
        'http_server_output_sha256': hashlib.sha256(patched).hexdigest(),
        'serving_base_sha256': hashlib.sha256(serving_base).hexdigest(), 'controls': results,
        'scope': 'Actual pinned warmup, request handler and adapter guard, with HTTP/model/termination seams replaced; no hardware claim.'}))


if __name__ == '__main__':
    main()
