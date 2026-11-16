#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Run the pinned SGLang media loaders, unpatched and patched, against URL, path and inline inputs."""
import argparse
import ast
import base64
import json
import os
from pathlib import Path
import sys
import types
from urllib.parse import unquote, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from appliance.sglang_patches import OPENAI_PATH, PATCHES, replace_pinned

FUNCTIONS = ('_inline_media_only', 'load_audio', 'load_image', 'get_image_bytes', '_normalize_video_input')
INLINE = 'data:image/png;base64,' + base64.b64encode(b'synthetic').decode()
REFUSED = ('http://127.0.0.1:8100/v1/models', 'https://example.invalid/a.png', 'file:///etc/passwd',
           '/etc/passwd', '/opt/conf-proc/a.png', base64.b64encode(b'synthetic').decode())


class Reached(BaseException):
    """Raised by a stub when a loader reaches a fetch, open or decode."""


def loaders(source):
    tree = ast.parse(source)
    picked = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in FUNCTIONS]
    for function in picked:
        function.returns = None
        for arg in function.args.args:
            arg.annotation = None
    events = []

    def reach(kind):
        def stub(*args, **kwargs):
            events.append(kind)
            raise Reached(kind)
        return stub

    class ImageData:
        url = None

    decoders = types.ModuleType('torchcodec.decoders')
    decoders.AudioDecoder = reach('audio-decode')
    sys.modules.setdefault('torchcodec', types.ModuleType('torchcodec'))
    sys.modules['torchcodec.decoders'] = decoders
    scope = {
        'get_mm_http_session': reach('fetch'), 'open': reach('open'), '_load_image': reach('image-decode'),
        'pybase64': types.SimpleNamespace(b64decode=lambda data, validate: events.append('inline-decode') or b''),
        'unquote': unquote, 'urlparse': urlparse, 'os': os, 'Image': types.SimpleNamespace(Image=type('Image', (), {})),
        'ImageData': ImageData, 'image_extension_names': ('.png', '.jpg', '.jpeg', '.webp', '.gif'),
        '_BACKEND': 'torchcodec', 'Union': None, 'Optional': None, 'np': None,
    }
    exec(compile(ast.fix_missing_locations(ast.Module(body=picked, type_ignores=[])), 'pinned-loaders', 'exec'), scope)
    return scope, events


def outcome(scope, events, name, value):
    events.clear()
    try:
        scope[name](value)
    except ValueError as error:
        return {'refused': True, 'reached': list(events), 'message': str(error)}
    except Reached:
        pass
    return {'refused': False, 'reached': list(events)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--serving-root', type=Path, required=True)
    args = parser.parse_args()
    patch = next(p for p in PATCHES if p[0] == '../../utils/common.py')
    original = (args.serving_root / OPENAI_PATH / patch[0]).read_bytes()
    patched = replace_pinned(original, *patch[1:])
    results = {}
    for label, source in (('original', original), ('patched', patched)):
        scope, events = loaders(source)
        rows = {}
        for name in ('load_audio', 'load_image', 'get_image_bytes', '_normalize_video_input'):
            rows[name] = {value: outcome(scope, events, name, value) for value in (INLINE, *REFUSED)}
        results[label] = rows
    patched_rows, original_rows = results['patched'], results['original']
    for name, rows in patched_rows.items():
        assert not rows[INLINE]['refused'], (name, 'inline media refused')
        for value in REFUSED:
            row = rows[value]
            assert row['refused'] and row['reached'] == [], (name, value, row)
    # Control: the unpatched loaders reach a fetch or an open for the remote and file forms.
    assert original_rows['load_audio']['http://127.0.0.1:8100/v1/models']['reached'] == ['fetch']
    assert original_rows['get_image_bytes']['file:///etc/passwd']['reached'] == ['open']
    assert original_rows['_normalize_video_input']['https://example.invalid/a.png']['reached'] == ['fetch']
    assert not original_rows['load_image']['file:///etc/passwd']['refused']
    print(json.dumps({'passed': True, 'results': results}, indent=1, sort_keys=True))


if __name__ == '__main__':
    main()
