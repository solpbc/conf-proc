#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Command-line inspector for a diagnostic-bundle graph root."""

from __future__ import annotations

import argparse
import sys

from conf_proc_json import canonical_dumps
from conf_proc_spp_diagbundle import inspect_diagnostic_bundle
from conf_proc_spp_diagbundle_reasons import (
    CP_DIAGBUNDLE_INTERNAL,
    DiagBundleError,
    NODE_ARTIFACT_STATE,
    recovery_for,
)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise DiagBundleError(CP_DIAGBUNDLE_INTERNAL, "invalid inspector arguments")


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description=__doc__)
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--expectations", required=True)
    try:
        args = parser.parse_args(argv)
        addresses = inspect_diagnostic_bundle(args.bundle, args.expectations)
        result = {
            "accepted": True,
            "artifact_state": NODE_ARTIFACT_STATE,
            "result": "codec_valid",
            **addresses,
        }
        sys.stdout.buffer.write(canonical_dumps(result) + b"\n")
        return 0
    except DiagBundleError as exc:
        recovery_class, safe_next_action = recovery_for(exc.reason_code)
        return _emit_failure(exc.reason_code, recovery_class, safe_next_action)
    except Exception:
        recovery_class, safe_next_action = recovery_for(CP_DIAGBUNDLE_INTERNAL)
        return _emit_failure(CP_DIAGBUNDLE_INTERNAL, recovery_class, safe_next_action)


def _emit_failure(reason_code: str, recovery_class: str, safe_next_action: str) -> int:
    output = {
        "accepted": False,
        "artifact_state": NODE_ARTIFACT_STATE,
        "reason_code": reason_code,
        "recovery_class": recovery_class,
        "result": "not_codec_valid",
        "safe_next_action": safe_next_action,
    }
    try:
        sys.stdout.buffer.write(canonical_dumps(output) + b"\n")
    except Exception:
        sys.stdout.write(
            '{"accepted":false,"artifact_state":"diagnostic_unqualified",'
            f'"reason_code":"{reason_code}","recovery_class":"{recovery_class}",'
            f'"result":"not_codec_valid","safe_next_action":"{safe_next_action}"}}\n'
        )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
