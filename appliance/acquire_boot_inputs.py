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
# 6.8.0-1071.78~22.04.1 + NVIDIA 595.91.07: the fixed kernel for CVE-2026-98432 and the driver
# Canonical signs its NVIDIA modules from for that kernel.
PINS = [
    ("stock-kernel/debs/kernel-fde-1071/linux-image-6.8.0-1071-azure-fde_6.8.0-1071.78~22.04.1_amd64.deb",
     UBU + "pool/main/l/linux-signed-azure-fde-6.8/linux-image-6.8.0-1071-azure-fde_6.8.0-1071.78~22.04.1_amd64.deb",
     "294ffe6fbc874db51b05ebbcfe3e8ae318f1c801c607843c7ec97f4f75d6e66d", 52427186),
    ("stock-kernel/debs/kernel-fde-1071/linux-modules-6.8.0-1071-azure-fde_6.8.0-1071.78~22.04.1_amd64.deb",
     UBU + "pool/main/l/linux-azure-fde-6.8/linux-modules-6.8.0-1071-azure-fde_6.8.0-1071.78~22.04.1_amd64.deb",
     "c8d28188053d275307cda9dbcc902f8f8dc38fe0f2d45b114b2f4a13ffeed0af", 25203236),
    ("stock-kernel/debs/nvidia-modules-fde-1071/linux-modules-nvidia-595-server-open-6.8.0-1071-azure-fde_6.8.0-1071.78~22.04.1_amd64.deb",
     UBU + "pool/restricted/l/linux-restricted-signatures-azure-fde-6.8/linux-modules-nvidia-595-server-open-6.8.0-1071-azure-fde_6.8.0-1071.78~22.04.1_amd64.deb",
     "43b2715ce9ad0b2e33f1b343464a5c4791fa5636d41ef27184092e2ab80713f6", 8172178),
    ("stock-kernel/debs/nvidia-userspace-595-server/nvidia-firmware-595-server-595.91.07_595.91.07-0ubuntu0.22.04.1_amd64.deb",
     UBU + "pool/multiverse/n/nvidia-graphics-drivers-595-server/nvidia-firmware-595-server-595.91.07_595.91.07-0ubuntu0.22.04.1_amd64.deb",
     "87f0daec92a5a1002017060f3cd8ab53b54197f61ed35cba732835fbdcc4ba6e", 75004038),
    ("stock-kernel/debs/nvidia-userspace-595-server/libnvidia-compute-595-server_595.91.07-0ubuntu0.22.04.1_amd64.deb",
     UBU + "pool/multiverse/n/nvidia-graphics-drivers-595-server/libnvidia-compute-595-server_595.91.07-0ubuntu0.22.04.1_amd64.deb",
     "9dc881896e1d705d45ee4c7f5f80749eac4bb329197e556bb287edd01cd1a847", 86704668),
    ("stock-kernel/debs/nvidia-userspace-595-server/nvidia-utils-595-server_595.91.07-0ubuntu0.22.04.1_amd64.deb",
     UBU + "pool/multiverse/n/nvidia-graphics-drivers-595-server/nvidia-utils-595-server_595.91.07-0ubuntu0.22.04.1_amd64.deb",
     "759a56835779f36f56c8fb7bee680e7a1db2c4aabf29cb5ab7bde010a6308fcd", 618488),
    ("stock-kernel/debs/nvidia-userspace-595-server/libnvidia-cfg1-595-server_595.91.07-0ubuntu0.22.04.1_amd64.deb",
     UBU + "pool/multiverse/n/nvidia-graphics-drivers-595-server/libnvidia-cfg1-595-server_595.91.07-0ubuntu0.22.04.1_amd64.deb",
     "c99461297940b647f2659d725002e4deaf74f3107eb056ca2a9b1dd9fa305e80", 161544),
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

# The evidence collector's GPU leg: NVIDIA's local GPU verifier 2.3.0 and its closure, at the
# versions the running engine's collector uses. Installed apart from the gateway's pydeps: the
# two pin different cryptography releases.
COLLECTOR_PINS = [
    ("collector-wheels/certifi-2026.5.20-py3-none-any.whl",
     PYPI + "certifi-2026.5.20-py3-none-any.whl",
     "3c52e209ba0a4ad7aebe60436a4ab349c39e1e602e8c134221e546902ad25897", 134134),
    ("collector-wheels/cffi-2.0.0-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.whl",
     PYPI + "cffi-2.0.0-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.whl",
     "3e17ed538242334bf70832644a32a7aae3d83b57567f9fd60a26257e992b79ba", 219572),
    ("collector-wheels/charset_normalizer-3.4.7-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl",
     PYPI + "charset_normalizer-3.4.7-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl",
     "5649fd1c7bade02f320a462fdefd0b4bd3ce036065836d4f42e0de958038e116", 216589),
    ("collector-wheels/cryptography-43.0.1-cp39-abi3-manylinux_2_28_x86_64.whl",
     PYPI + "cryptography-43.0.1-cp39-abi3-manylinux_2_28_x86_64.whl",
     "511f4273808ab590912a93ddb4e3914dfd8a388fed883361b02dea3791f292e1", 3993152),
    ("collector-wheels/ecdsa-0.18.0-py2.py3-none-any.whl",
     PYPI + "ecdsa-0.18.0-py2.py3-none-any.whl",
     "80600258e7ed2f16b9aa1d7c295bd70194109ad5a30fdee0eaeefef1d4c559dd", 142915),
    ("collector-wheels/elementpath-4.8.0-py3-none-any.whl",
     PYPI + "elementpath-4.8.0-py3-none-any.whl",
     "5393191f84969bcf8033b05ec4593ef940e58622ea13cefe60ecefbbf09d58d9", 243271),
    ("collector-wheels/idna-3.18-py3-none-any.whl",
     PYPI + "idna-3.18-py3-none-any.whl",
     "7f952cbe720b688055e3f87de14f5c3e5fdaa8bc3928985c4077ca689de849a2", 65455),
    ("collector-wheels/lxml-4.9.4-cp312-cp312-manylinux_2_28_x86_64.whl",
     PYPI + "lxml-4.9.4-cp312-cp312-manylinux_2_28_x86_64.whl",
     "e8f9f93a23634cfafbad6e46ad7d09e0f4a25a2400e4a64b1b7b7c0fbaa06d9d", 8026189),
    ("collector-wheels/nv_local_gpu_verifier-2.3.0-py3-none-any.whl",
     PYPI + "nv_local_gpu_verifier-2.3.0-py3-none-any.whl",
     "ebee7d44453a19d2c550cbb259f76c7af53343c8878fc33fcabaabb283c4253d", 207213),
    ("collector-wheels/nvidia_ml_py-12.550.52-py3-none-any.whl",
     PYPI + "nvidia_ml_py-12.550.52-py3-none-any.whl",
     "b78a1175f299f702dea17fc468676443f3fefade880202da8d0997df15dc11e2", 39295),
    ("collector-wheels/pycparser-3.0-py3-none-any.whl",
     PYPI + "pycparser-3.0-py3-none-any.whl",
     "b727414169a36b7d524c1c3e31839a521725078d7b2ff038656844266160a992", 48172),
    ("collector-wheels/PyJWT-2.7.0-py3-none-any.whl",
     PYPI + "PyJWT-2.7.0-py3-none-any.whl",
     "ba2b425b15ad5ef12f200dc67dd56af4e26de2331f965c5439994dad075876e1", 22366),
    ("collector-wheels/pyOpenSSL-24.2.1-py3-none-any.whl",
     PYPI + "pyOpenSSL-24.2.1-py3-none-any.whl",
     "967d5719b12b243588573f39b0c677637145c7a1ffedcd495a487e58177fbb8d", 58390),
    ("collector-wheels/requests-2.32.3-py3-none-any.whl",
     PYPI + "requests-2.32.3-py3-none-any.whl",
     "70761cfe03c773ceb22aa2f671b4757976145175cdfca038c02654d061d6dcc6", 64928),
    ("collector-wheels/signxml-3.2.0-py3-none-any.whl",
     PYPI + "signxml-3.2.0-py3-none-any.whl",
     "0ee07e3e8fcba8fa0975f5bf9e205e557ea3f0b34ea95b4fde1c897e75c4812c", 57867),
    ("collector-wheels/six-1.17.0-py2.py3-none-any.whl",
     PYPI + "six-1.17.0-py2.py3-none-any.whl",
     "4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274", 11050),
    ("collector-wheels/urllib3-2.7.0-py3-none-any.whl",
     PYPI + "urllib3-2.7.0-py3-none-any.whl",
     "9fb4c81ebbb1ce9531cce37674bbc6f1360472bc18ca9a553ede278ef7276897", 131087),
    ("collector-wheels/xmlschema-2.2.3-py3-none-any.whl",
     PYPI + "xmlschema-2.2.3-py3-none-any.whl",
     "7d971045eeeb8de183b56bc7530eb8f3d8276072d08017a962c2c34e93bfdd26", 355468),
]

# Expected digest of the kernel image extracted from the linux-image deb: the .linux section of
# Canonical's signed UKI, so this also proves the deb is the pinned one.
BZIMAGE_SHA256 = "3068f996183680ca0be1d2c80f4026b2e22c1d58fd2caae7d539d9bf66125a89"

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

    rows = [fetch(ws, *pin) for pin in PINS + COLLECTOR_PINS]

    ext = ws / "stock-kernel/extract"
    vmlinuz = ext / "boot/vmlinuz-6.8.0-1071-azure-fde"
    if not vmlinuz.exists():
        ext.mkdir(parents=True, exist_ok=True)
        for rel, *_ in PINS[:2]:
            sh("dpkg-deb", "-x", str(ws / rel), str(ext))
        # The azure-fde image package ships Canonical's own signed UKI, not a bare vmlinuz.
        # The kernel we embed is that UKI's .linux section: Canonical's signed bzImage, byte-exact.
        sh("objcopy", "-O", "binary", "--only-section=.linux",
           str(ext / "usr/lib/linux/efi/kernel.efi-6.8.0-1071-azure-fde"), str(vmlinuz))
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

    collector = ws / "r1-build/collector-site/target"
    if not collector.exists():
        collector.mkdir(parents=True)
        wheels = sorted(str(ws / rel) for rel, *_ in COLLECTOR_PINS)
        sh("uv", "pip", "install", "--no-index", "--no-deps", "--no-cache", "--python", "3.12",
           "--python-platform", "x86_64-manylinux_2_28", "--target", str(collector), *wheels)
        shutil.rmtree(collector / "bin", ignore_errors=True)

    from normalize_wheels import normalize
    normalize(target)
    normalize(collector)

    (ws / "boot-inputs-verified.json").write_text(json.dumps(rows, indent=2) + "\n")
    print(f"{len(rows)} pinned boot/driver/tool inputs verified; vmlinuz matches {BZIMAGE_SHA256[:12]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
