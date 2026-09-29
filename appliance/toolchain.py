#!/usr/bin/env python3
"""Assemble and run the appliance builder using hash-pinned Debian packages."""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request

HERE = Path(__file__).resolve().parent


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def acquire(row: dict, cache: Path) -> Path:
    name = row['filename']
    if Path(name).name != name:
        raise ValueError('package filename must be a basename')
    dest = cache / name
    if not dest.exists():
        fd, temporary = tempfile.mkstemp(prefix=name + '.', suffix='.part', dir=cache)
        part = Path(temporary)
        try:
            with os.fdopen(fd, 'wb') as out, urllib.request.urlopen(row['url'], timeout=120) as source:
                while block := source.read(1024 * 1024):
                    out.write(block)
            if part.stat().st_size != row['size_bytes'] or digest(part) != row['sha256']:
                raise ValueError(f'package digest mismatch: {name}')
            part.replace(dest)
        finally:
            part.unlink(missing_ok=True)
    if dest.stat().st_size != row['size_bytes'] or digest(dest) != row['sha256']:
        raise ValueError(f'package digest mismatch: {name}')
    return dest


def prepare(root: Path, cache: Path, manifest: Path) -> None:
    rows = json.loads(manifest.read_text())['packages']
    if not rows or len({r['filename'] for r in rows}) != len(rows):
        raise ValueError('empty or duplicate package closure')
    cache.mkdir(parents=True, exist_ok=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        debs = list(pool.map(lambda row: acquire(row, cache), rows))
    root.mkdir(parents=True, exist_ok=False)
    info = root / 'var/lib/dpkg/info'
    info.mkdir(parents=True)
    status = []
    for row, deb in zip(rows, debs):
        subprocess.run(['dpkg-deb', '-x', str(deb), str(root)], check=True)
        control = subprocess.run(['dpkg-deb', '-f', str(deb)], capture_output=True, text=True, check=True).stdout
        status.append(control.rstrip() + '\nStatus: install ok installed\n')
        listing = subprocess.Popen(['dpkg-deb', '--fsys-tarfile', str(deb)], stdout=subprocess.PIPE)
        assert listing.stdout is not None
        try:
            with tarfile.open(fileobj=listing.stdout, mode='r|') as archive:
                names = ['/' + member.name.removeprefix('./').rstrip('/') for member in archive]
        finally:
            listing.stdout.close()
        if listing.wait() != 0:
            raise RuntimeError(f'cannot list package {deb.name}')
        package = row['package'] + (':' + row['architecture'] if 'Multi-Arch: same' in control else '')
        (info / (package + '.list')).write_text('\n'.join(names) + '\n')
    (root / 'var/lib/dpkg/status').write_text('\n'.join(status))
    # Format 1 enables architecture-qualified .list filenames for Multi-Arch
    # packages. Without it dpkg-query silently searches the legacy names.
    (info / 'format').write_text('1\n')
    # Package archives straddle the merged-/usr transition. Merge their legacy
    # directories explicitly; no maintainer script or host library participates.
    for name in ('bin', 'sbin', 'lib', 'lib64'):
        old, dest = root / name, root / 'usr' / name
        dest.mkdir(parents=True, exist_ok=True)
        if old.is_dir() and not old.is_symlink():
            shutil.copytree(old, dest, dirs_exist_ok=True, symlinks=True)
            shutil.rmtree(old)
        if old.is_symlink():
            old.unlink()
        old.symlink_to('usr/' + name)
    # Archive extraction does not run the shell-alternative maintainer scripts.
    # Supply /bin/sh explicitly from the pinned bash package for Debian wrappers.
    (root / 'usr/bin/sh').symlink_to('bash')
    for directory in ('proc', 'dev', 'tmp', 'run', 'workspace', 'src', 'signer'):
        (root / directory).mkdir(parents=True, exist_ok=True)
    (root / 'etc/passwd').write_text('root:x:0:0:root:/root:/bin/bash\n')
    (root / 'etc/group').write_text('root:x:0:\n')
    (root / 'toolchain-manifest.json').write_bytes(manifest.read_bytes())
    print(f'assembled {len(rows)} pinned packages at {root}', flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, default=HERE / 'toolchain-manifest.json')
    sub = parser.add_subparsers(dest='action', required=True)
    prep = sub.add_parser('prepare')
    prep.add_argument('--root', type=Path, required=True)
    prep.add_argument('--cache', type=Path, required=True)
    run = sub.add_parser('run')
    run.add_argument('--root', type=Path, required=True)
    run.add_argument('--workspace', type=Path, required=True)
    run.add_argument('--source', type=Path, required=True)
    run.add_argument('--signer', type=Path, required=True)
    run.add_argument('args', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.action == 'prepare':
        prepare(args.root.resolve(), args.cache.resolve(), args.manifest.resolve())
        return
    root = args.root.resolve()
    if (root / 'toolchain-manifest.json').read_bytes() != args.manifest.read_bytes():
        raise ValueError('toolchain manifest mismatch')
    command = args.args
    if command[:1] == ['--']:
        command = command[1:]
    if not command:
        parser.error('run requires a command after --')
    os.execvp('bwrap', ['bwrap', '--ro-bind', str(root), '/', '--proc', '/proc', '--dev', '/dev',
              '--tmpfs', '/tmp', '--tmpfs', '/run', '--bind', str(args.workspace.resolve()), '/workspace',
              '--ro-bind', str(args.source.resolve()), '/src', '--ro-bind', str(args.signer.resolve()), '/signer',
              '--unshare-net', '--die-with-parent', '--clearenv', '--setenv', 'PATH', '/usr/sbin:/usr/bin:/sbin:/bin',
              '--setenv', 'HOME', '/tmp', '--setenv', 'LANG', 'C.UTF-8', '--setenv', 'PYTHONDONTWRITEBYTECODE', '1',
              '--setenv', 'SOURCE_DATE_EPOCH', '1788652800', '--chdir', '/src', '--', *command])


if __name__ == '__main__':
    main()
