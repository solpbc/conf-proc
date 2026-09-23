#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Acquire the SPP appliance's boot, driver and build-tool inputs, every byte pinned by SHA-256.

Complements the serving-input acquisition (models, SGLang OCI image, ASR runtime). Downloads
each pinned artifact, refuses on any size or digest mismatch, and lays it out under the
workspace in the paths the appliance recipe reads. Network is used here and nowhere after:
the build itself runs offline against what this script verified.

Usage: acquire_boot_inputs.py --workspace DIR [--packages DIR]
  --packages: an already-verified directory of the recipe's 46 pinned Ubuntu packages
              (tpm2-tools, libtss2, nvidia-modprobe, mtools, pefile, ...); default WORKSPACE/packages.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

UBU = "http://archive.ubuntu.com/ubuntu/"
LP = "https://launchpad.net/ubuntu/+archive/primary/+files/"
PYPI = "https://files.pythonhosted.org/packages/"

# (workspace-relative destination, url, sha256, size). Kernel/driver debs are jammy
# 6.8.0-1058.65~22.04.1 + NVIDIA 595.71.05 — the pair qualified on the confidential H100.
PINS = [
    ("stock-kernel/debs/kernel-fde-1058/linux-image-6.8.0-1058-azure-fde_6.8.0-1058.65~22.04.1_amd64.deb",
     UBU + "pool/main/l/linux-signed-azure-fde-6.8/linux-image-6.8.0-1058-azure-fde_6.8.0-1058.65~22.04.1_amd64.deb",
     "99d817a1e226c62c8fb281b4560d5e409eadb4eaf7e8d6f6561a17c869e61c0e", 51195136),
    ("stock-kernel/debs/kernel-fde-1058/linux-modules-6.8.0-1058-azure-fde_6.8.0-1058.65~22.04.1_amd64.deb",
     UBU + "pool/main/l/linux-azure-fde-6.8/linux-modules-6.8.0-1058-azure-fde_6.8.0-1058.65~22.04.1_amd64.deb",
     "64350ba17e95e02796291dac6072b8b7fb29addbda0be6f8023da16764c99037", 23500102),
    ("stock-kernel/debs/nvidia-modules-fde-1058/linux-modules-nvidia-595-server-open-6.8.0-1058-azure-fde_6.8.0-1058.65~22.04.1_amd64.deb",
     UBU + "pool/restricted/l/linux-restricted-signatures-azure-fde-6.8/linux-modules-nvidia-595-server-open-6.8.0-1058-azure-fde_6.8.0-1058.65~22.04.1_amd64.deb",
     "194779828374b36e53ee7293415d44023f3dc7399fc852874a16852d6a8e897c", 8165906),
    ("stock-kernel/debs/nvidia-userspace-595-server/nvidia-firmware-595-server-595.71.05_595.71.05-0ubuntu0.22.04.1_amd64.deb",
     UBU + "pool/multiverse/n/nvidia-graphics-drivers-595-server/nvidia-firmware-595-server-595.71.05_595.71.05-0ubuntu0.22.04.1_amd64.deb",
     "740636b37668ac78a5f392dee3139b78f534561b01a6152db74c8380b00ec1f9", None),
    ("stock-kernel/debs/nvidia-userspace-595-server/libnvidia-compute-595-server_595.71.05-0ubuntu0.22.04.1_amd64.deb",
     LP + "libnvidia-compute-595-server_595.71.05-0ubuntu0.22.04.1_amd64.deb",
     "7fe71bab8a0d93af0b4da1845b33e61a7af116a90979423e244ddf41a3224a2f", 86732312),
    ("stock-kernel/debs/nvidia-userspace-595-server/nvidia-utils-595-server_595.71.05-0ubuntu0.22.04.1_amd64.deb",
     LP + "nvidia-utils-595-server_595.71.05-0ubuntu0.22.04.1_amd64.deb",
     "aa45cc940578e412673bb6ae0629217d7be94a60f791f9f271203c7bd39b830b", 618300),
    ("stock-kernel/debs/nvidia-userspace-595-server/libnvidia-cfg1-595-server_595.71.05-0ubuntu0.22.04.1_amd64.deb",
     LP + "libnvidia-cfg1-595-server_595.71.05-0ubuntu0.22.04.1_amd64.deb",
     "2669f15b5d7ac7d22f81b901c9929dccd3e4d122f36dca0a0079608752eceaba", 161506),
    # systemd 255 (noble): the stub implements the LoadFile2 initrd protocol the 6.8 EFI stub expects;
    # ukify from the same release.
    ("stock-kernel/debs/systemd-boot-efi_255.4-1ubuntu8.17_amd64.deb",
     UBU + "pool/universe/s/systemd/systemd-boot-efi_255.4-1ubuntu8.17_amd64.deb",
     "4bd54ad65e5c4baf4b14d98db2eedabedfb97ecf65327f686284989b01046044", 155688),
    ("stock-kernel/debs/systemd-ukify_255.4-1ubuntu8.17_all.deb",
     UBU + "pool/universe/s/systemd/systemd-ukify_255.4-1ubuntu8.17_all.deb",
     "c98d0d8472b2711ed1a6bed44481186ea6da7c834d69fce2b8937daa06fcb7f4", 29814),
    # nftables for the prod egress policy (jammy; the SGLang base lacks nft and these libs).
    ("stock-kernel/debs/nftables/nftables_1.0.2-1ubuntu3.1_amd64.deb",
     UBU + "pool/main/n/nftables/nftables_1.0.2-1ubuntu3.1_amd64.deb",
     "a18cd9b477bc0277dc6a5190ca84131e0e0ff809283049e3c8f2e4e735d83f28", None),
    ("stock-kernel/debs/nftables/libnftables1_1.0.2-1ubuntu3.1_amd64.deb",
     UBU + "pool/main/n/nftables/libnftables1_1.0.2-1ubuntu3.1_amd64.deb",
     "c23880032dcf0a6f7afd12c599230d226240ff829153cc2e5b4b09ce7f6080b3", None),
    ("stock-kernel/debs/nftables/libnftnl11_1.2.1-1build1_amd64.deb",
     UBU + "pool/main/libn/libnftnl/libnftnl11_1.2.1-1build1_amd64.deb",
     "a2c19952be8ca65e3464773009490701a0a49e1ef984d9140158371f909f2606", 65544),
    ("stock-kernel/debs/nftables/libmnl0_1.0.4-3build2_amd64.deb",
     UBU + "pool/main/libm/libmnl/libmnl0_1.0.4-3build2_amd64.deb",
     "e0ed2e88526830896a9efcef75a3d019b40cdac5a56d6605c426296979708f4a", 13216),
    ("stock-kernel/debs/nftables/libxtables12_1.8.7-1ubuntu5.2_amd64.deb",
     UBU + "pool/main/i/iptables/libxtables12_1.8.7-1ubuntu5.2_amd64.deb",
     "c2e99be5d2f06ce776883c3d11dbe58f1c735e2ad9acd9ea2faa584829eddb16", None),
    # The gateway's TLS stack on the SGLang rootfs's CPython 3.12, at the versions
    # conf-proc/requirements-lock.txt pins for the running engine.
    ("wheels/cryptography-46.0.7-cp311-abi3-manylinux_2_28_x86_64.whl",
     PYPI + "cryptography-46.0.7-cp311-abi3-manylinux_2_28_x86_64.whl",
     "420b1e4109cc95f0e5700eed79908cef9268265c773d3a66f7af1eef53d409ef", 4459985),
    ("wheels/pyopenssl-26.2.0-py3-none-any.whl", PYPI + "pyopenssl-26.2.0-py3-none-any.whl",
     "4f9d971bc5298b8bc1fab282803da04bf000c755d4ad9d99b52de2569ca19a70", 55823),
    ("wheels/cffi-2.1.0-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.whl",
     PYPI + "cffi-2.1.0-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.whl",
     "1e9f50d192a3e525b15a75ab5114e442d83d657b7ec29182a991bc9a88fd3a66", 221844),
    ("wheels/pycparser-3.0-py3-none-any.whl", PYPI + "pycparser-3.0-py3-none-any.whl",
     "b727414169a36b7d524c1c3e31839a521725078d7b2ff038656844266160a992", 48172),
    ("wheels/typing_extensions-4.16.0-py3-none-any.whl", PYPI + "typing_extensions-4.16.0-py3-none-any.whl",
     "481caa481374e813c1b176ada14e97f1f67a4539ce9cfeb3f350d78d6370c2e8", 45571),
]

# Expected digest of the kernel image extracted from the linux-image deb (the value the
# R1 SBOM recorded, so this also proves the deb is the one the qualified image used).
BZIMAGE_SHA256 = "78d4c293142d78588d7b31a2fd9272109e2d305d93c8685abeb6cbcb60c39609"

# From the pinned package set: what the recipe copies tpm2-tools, libtss2 and nvidia-modprobe from.
A24_PACKAGES = ("tpm2-tools.deb", "libtss2-esys.deb", "libtss2-mu.deb", "libtss2-rc.deb",
                "libtss2-sys.deb", "libtss2-tcti-device.deb", "libtss2-tctildr.deb",
                "nvidia-modprobe_595.71.05-1ubuntu1_amd64.deb", "kmod_29-1ubuntu1.1_amd64.deb")


def fetch(ws: Path, rel: str, url: str, sha: str, size: int | None) -> dict:
    dest = ws / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not dest.exists():
        # PyPI files live under a content-hash path; resolve it from the JSON index when needed.
        if url.startswith(PYPI) and "/" not in url[len(PYPI):]:
            url = _pypi_url(url[len(PYPI):], sha)
        with urllib.request.urlopen(url, timeout=300) as r:
            data = r.read()
        part = dest.with_name(dest.name + ".part")
        part.write_bytes(data)
        part.rename(dest)
    data = dest.read_bytes()
    got = hashlib.sha256(data).hexdigest()
    if got != sha or (size is not None and len(data) != size):
        dest.unlink()
        raise SystemExit(f"digest/size mismatch for {rel}: {got} {len(data)}")
    return {"path": rel, "url": url, "sha256": sha, "size_bytes": len(data)}


def _pypi_url(filename: str, sha: str) -> str:
    name, version = filename.split("-")[0], filename.split("-")[1]
    with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/{version}/json", timeout=60) as r:
        meta = json.load(r)
    for u in meta["urls"]:
        if u["filename"] == filename and u["digests"]["sha256"] == sha:
            return u["url"]
    raise SystemExit(f"PyPI has no {filename} with sha256 {sha}")


def sh(*argv: str) -> None:
    subprocess.run(argv, check=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", required=True, type=Path)
    ap.add_argument("--packages", type=Path)
    a = ap.parse_args()
    ws = a.workspace.resolve()
    pkgs = (a.packages or ws / "packages").resolve()

    rows = [fetch(ws, *pin) for pin in PINS]

    ext = ws / "stock-kernel/extract"
    vmlinuz = ext / "boot/vmlinuz-6.8.0-1058-azure-fde"
    if not vmlinuz.exists():
        ext.mkdir(parents=True, exist_ok=True)
        for rel, *_ in PINS[:2]:
            sh("dpkg-deb", "-x", str(ws / rel), str(ext))
        # The azure-fde image package ships Canonical's own signed UKI, not a bare vmlinuz.
        # The kernel we embed is that UKI's .linux section: Canonical's signed bzImage, byte-exact.
        sh("objcopy", "-O", "binary", "--only-section=.linux",
           str(ext / "usr/lib/linux/efi/kernel.efi-6.8.0-1058-azure-fde"), str(vmlinuz))
    if hashlib.sha256(vmlinuz.read_bytes()).hexdigest() != BZIMAGE_SHA256:
        raise SystemExit("extracted vmlinuz does not match the qualified kernel image")

    stub = ws / "stock-kernel/stub-noble"
    if not stub.exists():
        sh("dpkg-deb", "-x", str(ws / "stock-kernel/debs/systemd-boot-efi_255.4-1ubuntu8.17_amd64.deb"), str(stub))

    tools = ws / "build-tools-recovered"
    if not (tools / "ukify.py").exists():
        tmp = ws / "stock-kernel/ukify-extract"
        sh("dpkg-deb", "-x", str(ws / "stock-kernel/debs/systemd-ukify_255.4-1ubuntu8.17_all.deb"), str(tmp))
        tools.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(tmp / "usr/lib/systemd/ukify", tools / "ukify.py")
        shutil.rmtree(tmp)
    if not (tools / "usr/bin/mformat").exists():
        shutil.copytree(pkgs / "mtools-root/usr/bin", tools / "usr/bin", dirs_exist_ok=True)

    root = ws / "appliance-a24/package-root"
    if not root.exists():
        root.mkdir(parents=True)
        for name in A24_PACKAGES:
            sh("dpkg-deb", "-x", str(pkgs / name), str(root))

    nft_root = ws / "nftables/package-root"
    if not nft_root.exists():
        nft_root.mkdir(parents=True)
        for rel, *_ in PINS:
            if rel.startswith("stock-kernel/debs/nftables/"):
                sh("dpkg-deb", "-x", str(ws / rel), str(nft_root))

    target = ws / "r1-build/pydeps/target"
    if not target.exists():
        target.mkdir(parents=True)
        wheels = sorted(str(ws / rel) for rel, *_ in PINS if rel.startswith("wheels/"))
        sh("uv", "pip", "install", "--no-index", "--no-deps", "--no-cache", "--python", "3.12",
           "--python-platform", "x86_64-manylinux_2_28", "--target", str(target), *wheels)
        # Console scripts carry the build host's interpreter path in their shebang and nothing in
        # the image runs them; the gateway only imports these packages.
        shutil.rmtree(target / "bin", ignore_errors=True)

    (ws / "boot-inputs-verified.json").write_text(json.dumps(rows, indent=2) + "\n")
    print(f"{len(rows)} pinned boot/driver/tool inputs verified; vmlinuz matches {BZIMAGE_SHA256[:12]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
