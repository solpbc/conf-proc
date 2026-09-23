#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
#
# SPP confidential-GPU bring-up. Loads the Canonical-signed NVIDIA open modules baked into the
# measured root, creates the device nodes the driver userspace expects, confirms the GPU is in
# confidential-compute mode, and marks it ready for CC workloads. Ordered before SGLang and the
# ASR sidecar. Output goes to this unit's stdout (the volatile journal) and nowhere else.
set -u

echo "SPP-GPU-BRINGUP begin"
modprobe nvidia || { echo "SPP-GPU-BRINGUP modprobe nvidia failed"; exit 1; }
modprobe nvidia_uvm || { echo "SPP-GPU-BRINGUP modprobe nvidia_uvm failed"; exit 1; }

nv=$(awk '$2=="nvidia-frontend" || $2=="nvidia" {print $1; exit}' /proc/devices)
uvm=$(awk '$2=="nvidia-uvm" {print $1; exit}' /proc/devices)
if [ -z "$nv" ] || [ -z "$uvm" ]; then
  echo "SPP-GPU-BRINGUP device majors missing nvidia=${nv:-none} uvm=${uvm:-none}"
  exit 1
fi
echo "SPP-GPU-BRINGUP majors nvidia=$nv uvm=$uvm"

[ -e /dev/nvidiactl ]        || mknod -m 666 /dev/nvidiactl c "$nv" 255
[ -e /dev/nvidia0 ]          || mknod -m 666 /dev/nvidia0 c "$nv" 0
[ -e /dev/nvidia-uvm ]       || mknod -m 666 /dev/nvidia-uvm c "$uvm" 0
[ -e /dev/nvidia-uvm-tools ] || mknod -m 666 /dev/nvidia-uvm-tools c "$uvm" 1

# Refuse to continue unless the GPU reports confidential compute ON.
cc=$(nvidia-smi conf-compute -f 2>&1)
echo "SPP-GPU-BRINGUP $cc"
case "$cc" in
  *"CC status: ON"*) ;;
  *) echo "SPP-GPU-BRINGUP confidential compute is not on; refusing"; exit 1 ;;
esac

nvidia-smi conf-compute -srs 1 >/dev/null 2>&1 || { echo "SPP-GPU-BRINGUP set-ready failed"; exit 1; }
echo "SPP-GPU-BRINGUP ready $(nvidia-smi --query-gpu=name,driver_version --format=csv,noheader 2>&1)"
