#!/usr/bin/env python3
"""Restore hash-pinned public build inputs into this run's owned scratch root."""
import concurrent.futures
import hashlib
import json
from pathlib import Path
import subprocess
import urllib.request

from acquisition_common import arguments, DATA
ROOT, E = arguments()
DEST = ROOT / 'packages'
manifest = json.loads((DATA / 'packages.json').read_text())
DEST.mkdir(mode=0o700, exist_ok=True)

def acquire(item):
    name = item['filename']
    assert Path(name).name == name
    target = DEST / name
    local = Path(item['reusable_local_file']) if item.get('reusable_local_file') else None
    if target.exists():
        payload = target.read_bytes()
    elif local and local.is_file():
        payload = local.read_bytes()
    else:
        with urllib.request.urlopen(item['url'], timeout=120) as response:
            payload = response.read(item['size_bytes'] + 1)
    if len(payload) != item['size_bytes'] or hashlib.sha256(payload).hexdigest() != item['sha256']:
        raise ValueError('input bytes mismatch: ' + name)
    if not target.exists():
        with target.open('xb') as handle:
            handle.write(payload)
    return {'filename': name, 'sha256': item['sha256'], 'size_bytes': len(payload)}

with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
    rows = list(pool.map(acquire, manifest['packages']))
for name, directory in [('python3-pefile.deb', 'pefile-root'), ('mtools_4.0.43-1build1_amd64.deb', 'mtools-root')]:
    subprocess.run(['dpkg-deb', '-x', str(DEST / name), str(DEST / directory)], check=True)
(E / 'packages-verified.json').write_text(json.dumps(rows, indent=2) + '\n')
print('All manifest packages verified and build tools extracted.')
