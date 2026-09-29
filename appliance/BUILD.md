# Building the sealed appliance

Use an x86-64 Linux host with Python 3.12, bubblewrap, dpkg-deb, objcopy (binutils), curl, gpgv, the Ubuntu archive
keyring, uv, skopeo and umoci. Acquisition needs network access and enough space for the unpacked
serving stack and build outputs. The image build uses a separate, hash-pinned toolchain root.

All acquisition commands below take `--workspace DIR`, where DIR is an absolute path to a fresh
directory. Run them with `python3 appliance/SCRIPT` from this repository:

1. `acquire-packages.py` fetches the base package set and extracts the boot tools.
2. `acquire-model-inputs.py` fetches the pinned Qwen and Parakeet models.
3. `acquire-asr-packages.py` fetches the ASR wheels and source archives.
4. `build-asr-source-wheels.py` builds the four pure-Python source distributions offline.
5. `stage-asr-packages.py` installs the ASR wheels into the input tree.
6. `acquire-asr-native-gap.py` verifies and fetches the additional native dependency.
7. `build_asr_os_root.py` assembles the ASR interpreter and native libraries.
8. `acquire-sglang-image.py` verifies the pinned OCI image and unpacks it without executing it.
9. `acquire_boot_inputs.py` fetches and extracts the kernel, driver, boot tools and attestation dependencies.

`acquire-synthetic-speech-tool.py` separately extracts the tools used to generate synthetic audio
fixtures. It is not required to build the image.

Installer paths, timestamps and unused console scripts are removed from the import-only wheel
trees. The image recipe checks every resulting input against `input-manifest-prod.json`.
Do not regenerate that manifest to make a failed input check pass.

Prepare a toolchain root using the committed package lock:

```sh
python3 appliance/toolchain.py prepare --root /build/toolchain --cache /build/debs
```

Build from a clean clone, mounting the directory that contains the input workspace as `/workspace`:

```sh
python3 appliance/toolchain.py run --root /build/toolchain \
  --workspace /build --source /path/to/clean/conf-proc --signer /path/to/signer \
  -- python3 /src/appliance/spp_appliance.py --stage prod \
  --workspace /workspace/inputs --manifest /src/appliance/input-manifest-prod.json \
  --signer-dir /signer
```

In this example, acquisition used `/build/inputs`. The signer directory contains the encrypted
Secure Boot key, passphrase and certificate expected by the recipe. An independent test build
can use `--ephemeral-signer` instead of the recipe's `--signer-dir /signer`; the outer mount still
needs an existing directory. Its signature and measurements will differ from a release build.

Use a fresh output directory for each build. The output manifest records the source commit,
artifact hashes and actual tool binaries. `prodtrace` adds diagnostic serial output for hardware
testing and must never be used as the serving release.
