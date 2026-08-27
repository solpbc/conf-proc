#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Strict canonical JSON codec for the integer-only conf-proc artifact subset."""

from __future__ import annotations

import json
from typing import Final

from conf_proc_reasons import (
    CP_JSON_DUPLICATE_KEY,
    CP_JSON_INVALID,
    CP_JSON_INVALID_UTF8,
    CP_JSON_NONCANONICAL,
    CP_JSON_UNSUPPORTED_NUMBER,
    CP_JSON_UNSUPPORTED_TYPE,
    ApplianceError,
)


JSON_SAFE_INTEGER_MIN: Final = -(2**53 - 1)
JSON_SAFE_INTEGER_MAX: Final = 2**53 - 1


def canonical_dumps(value: object) -> bytes:
    """Encode a strict RFC 8785-compatible integer-only JSON value."""

    return _encode_value(value).encode("utf-8")


def canonical_loads(data: bytes) -> object:
    """Decode only bytes that already equal their canonical JSON rendering."""

    if type(data) is not bytes:
        raise ApplianceError(CP_JSON_UNSUPPORTED_TYPE, "canonical JSON input must be bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ApplianceError(CP_JSON_INVALID_UTF8, "JSON is not valid UTF-8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_object_without_duplicates,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except ApplianceError:
        raise
    except (json.JSONDecodeError, ValueError) as exc:
        raise ApplianceError(CP_JSON_INVALID, "invalid JSON") from exc
    if canonical_dumps(value) != data:
        raise ApplianceError(CP_JSON_NONCANONICAL, "JSON is not canonically encoded")
    return value


def _object_without_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ApplianceError(CP_JSON_DUPLICATE_KEY, f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def _reject_float(value: str) -> object:
    raise ApplianceError(CP_JSON_UNSUPPORTED_NUMBER, f"floating-point JSON number: {value}")


def _reject_constant(value: str) -> object:
    raise ApplianceError(CP_JSON_UNSUPPORTED_NUMBER, f"unsupported JSON number constant: {value}")


def _encode_value(value: object) -> str:
    value_type = type(value)
    if value_type is dict:
        return _encode_object(value)
    if value_type is list:
        return "[" + ",".join(_encode_value(item) for item in value) + "]"
    if value_type is str:
        return _encode_string(value)
    if value_type is bool:
        return "true" if value else "false"
    if value is None:
        return "null"
    if value_type is int:
        if not JSON_SAFE_INTEGER_MIN <= value <= JSON_SAFE_INTEGER_MAX:
            raise ApplianceError(CP_JSON_UNSUPPORTED_NUMBER, "integer is outside the safe range")
        return str(value)
    raise ApplianceError(CP_JSON_UNSUPPORTED_TYPE, f"unsupported JSON value type: {value_type.__name__}")


def _encode_object(value: dict[object, object]) -> str:
    keys = list(value)
    if any(type(key) is not str for key in keys):
        raise ApplianceError(CP_JSON_UNSUPPORTED_TYPE, "JSON object keys must be strings")
    if len(keys) != len(set(keys)):
        raise ApplianceError(CP_JSON_DUPLICATE_KEY, "duplicate JSON object key")
    ordered = sorted(keys, key=_utf16_sort_key)
    return "{" + ",".join(f"{_encode_string(key)}:{_encode_value(value[key])}" for key in ordered) + "}"


def _utf16_sort_key(value: str) -> bytes:
    _validate_unicode_scalar_values(value)
    return value.encode("utf-16-be")


def _encode_string(value: str) -> str:
    _validate_unicode_scalar_values(value)
    parts = ['"']
    short_escapes = {
        "\b": "\\b",
        "\t": "\\t",
        "\n": "\\n",
        "\f": "\\f",
        "\r": "\\r",
        '"': '\\"',
        "\\": "\\\\",
    }
    for character in value:
        if character in short_escapes:
            parts.append(short_escapes[character])
        elif ord(character) <= 0x1F:
            parts.append(f"\\u{ord(character):04x}")
        else:
            parts.append(character)
    parts.append('"')
    return "".join(parts)


def _validate_unicode_scalar_values(value: str) -> None:
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise ApplianceError(CP_JSON_UNSUPPORTED_TYPE, "string contains an unpaired surrogate")
