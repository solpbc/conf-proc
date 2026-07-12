#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Strict canonical-WAV intake parser — the minimal-parser-surface boundary.

Accepts EXACTLY one wire format and rejects everything else:
  RIFF/WAVE container, fmt chunk with PCM (format tag 1), 1 channel (mono),
  16,000 Hz sample rate, 16 bits per sample, followed by a data chunk.

Pure stdlib (struct only). No ffmpeg, no libsndfile, no C decoder — this is
the ONLY code on the hosted system that touches wire audio bytes, under the
locked journal-side-normalization constraint (reject-don't-convert).

Returns raw little-endian PCM16 bytes; numeric conversion happens at the
model boundary, keeping this module dependency-free and fully testable.
"""

from __future__ import annotations

import struct

CANONICAL_SAMPLE_RATE = 16000
CANONICAL_CHANNELS = 1
CANONICAL_BITS = 16
MAX_AUDIO_SECONDS = 330  # observer contract is <=300s; small tolerance
MAX_PAYLOAD_BYTES = (
    12 + 8 + 40 + 8 + (CANONICAL_SAMPLE_RATE * 2 * MAX_AUDIO_SECONDS) + 1024
)


class WavReject(ValueError):
    """Raised for any payload that is not canonical PCM16/16k/mono WAV."""


def parse_canonical_wav(payload: bytes) -> tuple[bytes, int]:
    """Parse a canonical WAV payload, or reject.

    Returns ``(pcm_data, sample_count)`` where ``pcm_data`` is the raw
    little-endian int16 mono sample bytes at 16 kHz.
    """
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise WavReject("payload exceeds maximum size")
    if len(payload) < 44:
        raise WavReject("payload too small to be a WAV file")
    if payload[0:4] != b"RIFF":
        raise WavReject("not a RIFF container")
    if payload[8:12] != b"WAVE":
        raise WavReject("not a WAVE file")

    pos = 12
    fmt_seen = False
    data: bytes | None = None
    while pos + 8 <= len(payload):
        chunk_id = payload[pos : pos + 4]
        (chunk_size,) = struct.unpack_from("<I", payload, pos + 4)
        body_start = pos + 8
        body_end = body_start + chunk_size
        if body_end > len(payload):
            raise WavReject("truncated chunk")
        if chunk_id == b"fmt ":
            if chunk_size < 16:
                raise WavReject("fmt chunk too small")
            fmt_tag, channels, rate, _byte_rate, _align, bits = struct.unpack_from(
                "<HHIIHH", payload, body_start
            )
            if fmt_tag != 1:
                raise WavReject(f"format tag {fmt_tag} is not PCM")
            if channels != CANONICAL_CHANNELS:
                raise WavReject(f"{channels} channels; canonical is mono")
            if rate != CANONICAL_SAMPLE_RATE:
                raise WavReject(f"sample rate {rate}; canonical is 16000")
            if bits != CANONICAL_BITS:
                raise WavReject(f"{bits} bits/sample; canonical is 16")
            fmt_seen = True
        elif chunk_id == b"data":
            if not fmt_seen:
                raise WavReject("data chunk before fmt chunk")
            data = payload[body_start:body_end]
        # any other chunk id is skipped without interpretation
        pos = body_end + (chunk_size & 1)  # chunks are word-aligned

    if not fmt_seen:
        raise WavReject("missing fmt chunk")
    if data is None:
        raise WavReject("missing data chunk")
    if len(data) % 2 != 0:
        raise WavReject("odd data length for 16-bit samples")
    n_samples = len(data) // 2
    if n_samples == 0:
        raise WavReject("empty audio")
    if n_samples > CANONICAL_SAMPLE_RATE * MAX_AUDIO_SECONDS:
        raise WavReject("audio exceeds maximum duration")

    return data, n_samples


def build_canonical_wav(pcm_data: bytes) -> bytes:
    """Assemble a canonical WAV around raw PCM16 mono/16k bytes (test/smoke aid)."""
    if len(pcm_data) % 2 != 0:
        raise ValueError("pcm data must be an even number of bytes")
    byte_rate = CANONICAL_SAMPLE_RATE * 2
    header = (
        b"RIFF"
        + struct.pack("<I", 36 + len(pcm_data))
        + b"WAVE"
        + b"fmt "
        + struct.pack(
            "<IHHIIHH", 16, 1, CANONICAL_CHANNELS, CANONICAL_SAMPLE_RATE,
            byte_rate, 2, CANONICAL_BITS,
        )
        + b"data"
        + struct.pack("<I", len(pcm_data))
    )
    return header + pcm_data
