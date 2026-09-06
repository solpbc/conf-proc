#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Fixed interpreter and workload identities for the isolated sealed candidate."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import sys
from dataclasses import dataclass

ASR_MODEL_SHA256 = '3cbdc85877e668ca7b82d0d56770eb1fac76691f55d6b97545e8d61ca588d10d'
QWEN_WEIGHTS = (
    ('model-00001-of-00002.safetensors', '26a93f066e1916adb13453dae5a0c707c0fbc71299ed98779571a907b8e74c61'),
    ('model-00002-of-00002.safetensors', 'cb544bd9bfae93dc59b0f22b292f5933573854a7f9b97835c67060d7d910e188'),
)
BOOTSTRAP = '/usr/lib/spp/conf_proc_spp_candidate_workload_entry.py'


@dataclass(frozen=True)
class Runtime:
    root: str
    interpreter: str
    python: tuple[int, int]
    uid: int
    imports: tuple[str, ...]


INFERENCE = Runtime('/runtimes/inference', '/usr/bin/python3.12', (3, 12), 61101,
    ('/usr/lib/spp', '/usr/local/lib/python3.12/dist-packages',
     '/usr/lib/python3/dist-packages', '/sgl-workspace/sglang/python'))
ASR = Runtime('/runtimes/asr', '/usr/bin/python3.10', (3, 10), 61102,
    ('/usr/lib/spp', '/opt/asr'))


def runtime(role: str) -> Runtime:
    if role == 'inference':
        return INFERENCE
    if role == 'asr':
        return ASR
    raise ValueError('unknown candidate workload')


def launch_argv(role: str, mode: str) -> tuple[str, ...]:
    if mode not in ('cold', 'serve'):
        raise ValueError('unknown candidate workload mode')
    return (runtime(role).interpreter, '-I', '-B', '-S', BOOTSTRAP, role, mode)


def fixed_environment(role: str) -> dict[str, str]:
    runtime(role)
    return {
        'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC', 'HOME': '/tmp',
        'PATH': '/usr/bin:/bin', 'TMPDIR': '/tmp', 'PWD': '/',
        'USER': 'spp-' + role,
        'HF_HUB_OFFLINE': '1', 'TRANSFORMERS_OFFLINE': '1',
        'HF_DATASETS_OFFLINE': '1', 'HF_HUB_DISABLE_TELEMETRY': '1',
        'TORCHINDUCTOR_CACHE_DIR': '/tmp/torchinductor',
        'TRITON_CACHE_DIR': '/tmp/triton', 'CUDA_CACHE_PATH': '/tmp/cuda',
        'CUDA_VISIBLE_DEVICES': '0', 'OMP_NUM_THREADS': '4',
        'SGLANG_PLUGINS': ',',
    }


def validate_interpreter(role: str, version: tuple[int, int], executable: str,
                         paths: tuple[str, ...]) -> None:
    spec = runtime(role)
    standard = f'/usr/lib/python{spec.python[0]}.{spec.python[1]}'
    allowed = {standard, standard + '/lib-dynload',
               f'/usr/lib/python{spec.python[0]}{spec.python[1]}.zip'}
    if version != spec.python or executable != spec.interpreter:
        raise RuntimeError('candidate interpreter identity differs')
    if not paths or any(path not in allowed for path in paths):
        raise RuntimeError('candidate ambient or cross-root import path')


def install_import_paths(role: str) -> None:
    if not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode):
        raise RuntimeError('candidate requires isolated immutable Python startup')
    validate_interpreter(role, sys.version_info[:2], sys.executable, tuple(sys.path))
    # The fixed bootstrap is loaded explicitly, then this function adds only the
    # role's measured imports. No site processing, .pth execution or entrypoints.
    sys.path[:0] = runtime(role).imports


def file_sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def verify_weights(role: str) -> None:
    runtime(role)
    rows = (('parakeet-tdt-0.6b-v3.nemo', ASR_MODEL_SHA256),) if role == 'asr' else QWEN_WEIGHTS
    for name, expected in rows:
        if file_sha256('/models/' + name) != expected:
            raise RuntimeError('candidate model identity differs')


def transcript_tokens(text: str) -> tuple[str, ...]:
    if type(text) is not str or len(text) > 4096 or not text.isascii():
        raise ValueError('invalid synthetic transcript')
    numbers = {'seven': '7', 'five': '5', 'twelve': '12'}
    return tuple(numbers.get(word, word) for word in re.findall(r'[a-z]+|[0-9]+', text.lower()))


def appraise_asr_outputs(outputs: list[str]) -> None:
    expected = ('The quick brown fox jumps over the lazy dog.', 'Seven plus five equals twelve.')
    if type(outputs) is not list or len(outputs) != len(expected):
        raise ValueError('incomplete synthetic ASR output')
    for actual, wanted in zip(outputs, expected):
        if transcript_tokens(actual) != transcript_tokens(wanted):
            raise ValueError('synthetic ASR output differs')


def cold_asr() -> dict:
    """Use the actual NeMo interface and independently specified WAV inputs."""
    import torch
    from nemo.collections.asr.models import ASRModel
    if not torch.cuda.is_available():
        raise RuntimeError('candidate cold workload requires CUDA')
    verify_weights('asr')
    for name, digest in (
        ('fox.wav', '1f59d686905e0118e46401e52455d3d3f31d5dae0762dd4962117617cad306ad'),
        ('arithmetic.wav', '66514a30feda55cb3160b1ac3716b57ae7693c7602e068360ccfa27d3ceb2052'),
    ):
        if file_sha256('/fixtures/' + name) != digest:
            raise RuntimeError('candidate synthetic input identity differs')
    torch.set_num_threads(4)
    model = ASRModel.restore_from('/models/parakeet-tdt-0.6b-v3.nemo', map_location='cuda')
    model.eval()
    with torch.inference_mode():
        results = model.transcribe(['/fixtures/fox.wav', '/fixtures/arithmetic.wav'],
                                   batch_size=1, num_workers=0, verbose=False)
    outputs = [result if isinstance(result, str) else result.text for result in results]
    appraise_asr_outputs(outputs)
    torch.cuda.synchronize()
    return {'role': 'asr', 'outputs': outputs}


def inference_arguments() -> dict:
    return dict(model_path='/models', device='cuda', host='127.0.0.1', port=8000,
        trust_remote_code=False, tp_size=1, context_length=4096,
        mem_fraction_static=0.50, max_running_requests=1, tokenizer_worker_num=1,
        log_level='error', log_level_http='error', enable_metrics=False)


def cold_inference() -> dict:
    """Run the exact SGLang/Qwen model on two distinct arithmetic prompts."""
    import torch
    from sglang import Engine
    if not torch.cuda.is_available():
        raise RuntimeError('candidate cold workload requires CUDA')
    verify_weights('inference')
    engine = Engine(**inference_arguments())
    try:
        tokenizer = engine.tokenizer_manager.tokenizer
        outputs = []
        for question in ('What is seven plus five?', 'What is nine minus five?'):
            prompt = tokenizer.apply_chat_template(
                [{'role': 'user', 'content': question + ' Answer with only the number.'}],
                tokenize=False, add_generation_prompt=True, enable_thinking=False)
            result = engine.generate(prompt, {'temperature': 0, 'max_new_tokens': 16})
            outputs.append(result['text'])
        appraise_inference_outputs(outputs)
        torch.cuda.synchronize()
        return {'role': 'inference', 'outputs': outputs}
    finally:
        engine.shutdown()


def appraise_inference_outputs(outputs: list[str]) -> None:
    if (type(outputs) is not list or len(outputs) != 2
            or any(type(item) is not str or len(item) > 128 for item in outputs)
            or tuple(item.strip() for item in outputs) != ('12', '4')):
        raise ValueError('synthetic inference output differs')
