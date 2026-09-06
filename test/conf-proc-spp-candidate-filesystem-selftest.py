#!/usr/bin/env python3
"""Native mount identity, readonly bind, bounded scratch and stale-target tests."""
from pathlib import Path
import importlib.util,json,os,subprocess,sys
R=Path(__file__).resolve().parents[1]
if sys.argv[1:]!=['--inside']:
 args=['bwrap','--unshare-all','--as-pid-1','--die-with-parent','--uid','0','--gid','0','--cap-add','ALL','--ro-bind','/','/','--proc','/proc','--dev','/dev','--tmpfs','/tmp','--',sys.executable,str(Path(__file__).resolve()),'--inside']
 p=subprocess.run(args,capture_output=True,timeout=20)
 assert p.returncode==0,(p.returncode,p.stderr.decode())
 print(p.stdout.decode(),end='');raise SystemExit(0)
sys.path.insert(0,str(R))
spec=importlib.util.spec_from_file_location('fs',R/'conf_proc_spp_candidate_filesystem.py');m=importlib.util.module_from_spec(spec);sys.modules['fs']=m;spec.loader.exec_module(m)
for path in ('/tmp/source','/tmp/target','/tmp/scratch','/tmp/missing'):
 os.mkdir(path)
(Path('/tmp/source')/'sentinel').write_bytes(b'readonly-control')
m._readonly_bind('/tmp/source','/tmp/target',m.TMPFS_MAGIC)
assert Path('/tmp/target/sentinel').read_bytes()==b'readonly-control'
try:Path('/tmp/target/sentinel').write_bytes(b'changed')
except OSError as error:assert error.errno==30
else:raise AssertionError('readonly mount writable')
try:m._readonly_bind('/tmp/source','/tmp/target',m.TMPFS_MAGIC)
except RuntimeError:pass
else:raise AssertionError('stale mount accepted')
m._tmpfs('/tmp/scratch',16777216,4096,0o700,0)
Path('/tmp/scratch/writable').write_bytes(b'ram-only')
from unittest.mock import patch
with patch.object(m,'_mount',return_value=None):
 try:m._tmpfs('/tmp/missing',16777216,4096,0o700,0)
 except RuntimeError:pass
 else:raise AssertionError('missing native mount accepted')
try:m.prepare_filesystems()
except RuntimeError:pass
else:raise AssertionError('non-verity outer root accepted')
print(json.dumps({'readonly_bind_identity':True,'write_denied':True,'scratch_limits_read_back':True,'stale_mount_denied':True,'missing_mount_denied':True,'non_verity_root_denied':True}))
