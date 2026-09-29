#!/usr/bin/env python3
"""Extract hash-pinned speech-fixture tools without a host package installation."""
import json
import subprocess
from acquisition_common import arguments, DATA
from toolchain import acquire

workspace, evidence = arguments()
output = workspace / "synthetic-speech-tool"
output.mkdir(exist_ok=False)
rows = json.loads((DATA / "speech-tool.json").read_text())
for row in rows:
    archive = acquire(row, output)
    subprocess.run(["dpkg-deb", "-x", str(archive), str(output / "root")], check=True)
(evidence / "synthetic-speech-tool.json").write_text(json.dumps(rows, indent=2) + "\n")
print("Speech fixture tools acquired and verified against pinned hashes.")
