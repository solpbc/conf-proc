#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
set -euo pipefail
exec python3 "$(dirname "$(realpath "$0")")/check_egress_ruleset.py" "$@"
