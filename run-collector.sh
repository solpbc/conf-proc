#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc

set -euo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

exec sudo env \
  SPP_NVIDIA_VERIFIER_SRC=/usr/local/lib/local_gpu_verifier/src \
  SPP_VCEK_CACHE_DIR=/var/tmp/spp-vcek-cache \
  /usr/local/lib/local_gpu_verifier/.venv/bin/python \
  "$repo_dir/ratls_collector.py"
