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
# Exercise actual private tmpfs retirement with substituted device stat leaves;
# a target-kernel boot separately exercises native character-device metadata.
m._mount('tmpfs','/dev','tmpfs',m.MS_NOSUID|m.MS_NOEXEC,'size=1048576,nr_inodes=128,mode=755')
import stat
Path('/dev/tpmrm0').touch(mode=0o600)
Path('/tmp/tpm-original').touch(mode=0o600)
Path('/tmp/tpm-wrong').touch(mode=0o600)
# Host user namespaces prohibit mknod. Substitute only character-device stat
# leaves here; tmpfs remount, unlink, readback and retained-fd IO remain native.
from types import SimpleNamespace
native_stat=os.stat;native_fstat=os.fstat
tpm_inode=native_stat('/tmp/tpm-original').st_ino
def node_stat(path,*args,**kwargs):
 value=native_stat(path,*args,**kwargs)
 if str(path)=='/dev/tpmrm0':return SimpleNamespace(st_mode=stat.S_IFCHR|0o600,st_uid=0,st_gid=0,st_rdev=123,st_dev=value.st_dev,st_ino=value.st_ino)
 return value
def fd_stat(fd):
 value=native_fstat(fd)
 if fd==5:return SimpleNamespace(st_mode=stat.S_IFCHR|0o600,st_rdev=123 if value.st_ino==tpm_inode else 456,st_dev=value.st_dev,st_ino=value.st_ino)
 return value
stat_patch=patch.object(os,'stat',node_stat);fd_patch=patch.object(os,'fstat',fd_stat)
stat_patch.start();fd_patch.start()
m._mount(None,'/dev',None,m.MS_REMOUNT|m.MS_RDONLY|m.MS_NOSUID|m.MS_NOEXEC)
fd=os.open('/tmp/tpm-wrong',os.O_RDONLY|os.O_CLOEXEC);os.dup2(fd,5,inheritable=False)
if fd!=5:os.close(fd)
try:m.retire_controller_tpm_device(5)
except RuntimeError:pass
else:raise AssertionError('wrong TPM transport retired')
assert Path('/dev/tpmrm0').exists();os.close(5)
fd=os.open('/tmp/tpm-original',os.O_RDONLY|os.O_CLOEXEC);os.dup2(fd,5,inheritable=False)
if fd!=5:os.close(fd)
original=m._mount
with patch.object(m,'_mount',side_effect=lambda source,target,kind,flags,data=None: None if not flags&m.MS_RDONLY else original(source,target,kind,flags,data)):
 try:m.retire_controller_tpm_device(5)
 except RuntimeError:pass
 else:raise AssertionError('false writable remount accepted')
assert Path('/dev/tpmrm0').exists()
m.retire_controller_tpm_device(5)
assert not Path('/dev/tpmrm0').exists() and os.read(5,1)==b''
try:Path('/dev/late-node').write_bytes(b'x')
except OSError as error:assert error.errno==30
else:raise AssertionError('retired device directory remained writable')
os.close(5)
stat_patch.stop();fd_patch.stop()
print('ok native controller TPM path retirement, retained transport, wrong-object and false-remount denial')
print(json.dumps({'readonly_bind_identity':True,'write_denied':True,'scratch_limits_read_back':True,'stale_mount_denied':True,'missing_mount_denied':True,'non_verity_root_denied':True}))
