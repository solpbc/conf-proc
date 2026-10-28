# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Small, preimage-checked changes to the pinned serving input."""
from __future__ import annotations

import hashlib
from pathlib import Path

OPENAI_PATH = "sgl-workspace/sglang/python/sglang/srt/entrypoints/openai"
PATCHES = (
    ("protocol.py", "4f4e9714c27509b845f0389528c431ff296de9cfec796fcf91b6e4e77f00a7bc",
     'class PromptTokensDetails(BaseModel):\n    """Details about prompt tokens."""\n\n    cached_tokens: int = 0',
     'class PromptTokensDetails(BaseModel):\n    """Details about prompt tokens."""\n\n    cached_tokens: Optional[int] = None'),
    ("usage_processor.py", "883c4c3ba95eb52fa57d5bf732d128063bac0b032f484776331220f61b7498a5",
     '"""Return PromptTokensDetails only when count > 0 (keeps JSON slim)."""\n        return PromptTokensDetails(cached_tokens=count) if count > 0 else None',
     '"""Return an explicit measurement, including a measured zero."""\n        return PromptTokensDetails(cached_tokens=count)'),
    ("serving_chat.py", "3217a5a23dd0388c9506b80f343c584a9261210c0e0571f7071d6f7e3ee58278",
     ('        reasoning_effort = (', '            extra_key=self._compute_extra_key(request),'),
     ('        cache_labels = raw_request.headers.getlist("x-sol-device") if raw_request is not None else []\n'
      '        if len(cache_labels) != 1 or len(cache_labels[0]) != 64 or any(c not in "0123456789abcdef" for c in cache_labels[0]):\n'
      '            raise ValueError("canonical journal namespace required")\n'
      '        cache_namespace = "spp:" + cache_labels[0]\n'
      '        reasoning_effort = (', '            extra_key=cache_namespace,')),
)


def replace_pinned(data: bytes, digest: str, before: str | tuple[str, ...], after: str | tuple[str, ...]) -> bytes:
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("serving patch input digest mismatch")
    pairs = [(before, after)] if isinstance(before, str) else list(zip(before, after, strict=True))
    for old_text, new_text in pairs:
        old = old_text.encode()
        if data.count(old) != 1:
            raise ValueError("serving patch input must match exactly once")
        data = data.replace(old, new_text.encode(), 1)
    return data


def apply(root: Path) -> list[dict[str, str]]:
    records = []
    for name, digest, before, after in PATCHES:
        path = root / OPENAI_PATH / name
        patched = replace_pinned(path.read_bytes(), digest, before, after)
        mode = path.stat().st_mode & 0o777
        # Rootfs inputs are hardlinked. Never modify their shared inode.
        path.unlink()
        path.write_bytes(patched)
        path.chmod(mode)
        records.append({"path": str(path.relative_to(root)), "input_sha256": digest,
                        "output_sha256": hashlib.sha256(patched).hexdigest()})
    return records
