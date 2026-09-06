#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Fixed native mount projections for the candidate's one verity volume."""
from __future__ import annotations
import ctypes
import os
from pathlib import Path
import resource
import stat
from dataclasses import dataclass

MS_RDONLY=1
MS_NOSUID=2
MS_NODEV=4
MS_NOEXEC=8
MS_REMOUNT=32
MS_BIND=4096
MS_PRIVATE=1<<18
MS_REC=16384
SQUASHFS_MAGIC=0x73717368
TMPFS_MAGIC=0x01021994
PROC_MAGIC=0x9fa0
SYSFS_MAGIC=0x62656572
CGROUP2_MAGIC=0x63677270


class _StatFs(ctypes.Structure):
    _fields_=[('type',ctypes.c_long),('bsize',ctypes.c_long),
              ('blocks',ctypes.c_ulong),('bfree',ctypes.c_ulong),('bavail',ctypes.c_ulong),
              ('files',ctypes.c_ulong),('ffree',ctypes.c_ulong),('fsid',ctypes.c_int*2),
              ('namelen',ctypes.c_long),('frsize',ctypes.c_long),('flags',ctypes.c_long),
              ('spare',ctypes.c_long*4)]


def _filesystem(fd: int) -> _StatFs:
    if ctypes.sizeof(_StatFs)!=120 or os.uname().machine!='x86_64':
        raise RuntimeError('candidate filesystem ABI differs')
    result=_StatFs();libc=ctypes.CDLL(None,use_errno=True)
    if libc.fstatfs(fd,ctypes.byref(result)):
        raise OSError(ctypes.get_errno(),'candidate filesystem readback')
    return result


def _directory(path: str) -> int:
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    node=os.fstat(fd)
    if not stat.S_ISDIR(node.st_mode) or (node.st_uid,node.st_gid)!=(0,0):
        os.close(fd);raise RuntimeError('candidate mount directory identity differs')
    return fd


def _mount(source: str|None,target: str,kind: str|None,flags: int,data: str|None=None) -> None:
    libc=ctypes.CDLL(None,use_errno=True)
    libc.mount.argtypes=(ctypes.c_char_p,ctypes.c_char_p,ctypes.c_char_p,ctypes.c_ulong,ctypes.c_char_p)
    def raw(value):return None if value is None else value.encode()
    if libc.mount(raw(source),raw(target),raw(kind),flags,raw(data)):
        raise OSError(ctypes.get_errno(),'candidate mount operation')


def _observe(path: str,magic: int,required_flags: int) -> tuple[int,int]:
    fd=_directory(path)
    try:
        fs=_filesystem(fd);node=os.fstat(fd)
        if fs.type!=magic or fs.flags&required_flags!=required_flags:
            raise RuntimeError('candidate mount readback differs')
        return node.st_dev,node.st_ino
    finally:os.close(fd)


def _require_unmounted(path: str) -> None:
    with open('/proc/self/mountinfo','r') as source:
        raw=source.read(262145)
    if len(raw)>262144:
        raise RuntimeError('candidate mount census exceeds bound')
    for row in raw.splitlines():
        fields=row.split()
        if len(fields)<10 or ' - ' not in row:
            raise RuntimeError('candidate mount census is malformed')
        if fields[4]==path:
            raise RuntimeError('candidate target is already a mountpoint')


def _readonly_bind(source: str,target: str,magic: int,extra_flags: int=0) -> None:
    # Parents come from the already verified, readonly image; a sole PID1 owns
    # all mounts. Reopen after mounting so the readback observes the mounted
    # object, not the directory descriptor hidden beneath it.
    _require_unmounted(target)
    before=_directory(target);os.close(before)
    source_fd=_directory(source)
    try:
        identity=os.fstat(source_fd)
        _mount('/proc/self/fd/'+str(source_fd),target,None,MS_BIND)
        _mount(None,target,None,MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|extra_flags)
        if _observe(target,magic,MS_RDONLY|MS_NOSUID|extra_flags)!=(identity.st_dev,identity.st_ino):
            raise RuntimeError('candidate bind mounted the wrong source')
    finally:os.close(source_fd)


def _tmpfs(path: str,size: int,inodes: int,mode: int,uid: int,*,executable: bool=False,devices: bool=False) -> None:
    _require_unmounted(path)
    fd=_directory(path);os.close(fd)
    flags=MS_NOSUID | (0 if executable else MS_NOEXEC) | (0 if devices else MS_NODEV)
    options=f'size={size},nr_inodes={inodes},mode={mode:o},uid={uid},gid={uid}'
    _mount('tmpfs',path,'tmpfs',flags,options)
    # Scratch roots are workload-owned, so use direct no-follow open here.
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        fs=_filesystem(fd);node=os.fstat(fd)
        if (fs.type!=TMPFS_MAGIC or fs.flags&flags!=flags or fs.flags&MS_RDONLY
                or fs.blocks*fs.bsize!=size or fs.files!=inodes
                or stat.S_IMODE(node.st_mode)!=mode or (node.st_uid,node.st_gid)!=(uid,uid)):
            raise RuntimeError('candidate scratch mount limits or ownership differ')
    finally:os.close(fd)


def _device_nodes(root: str,uid: int,*,controller: bool) -> tuple[tuple[str,int],...]:
    _tmpfs(root+'/dev',1048576,128,0o755,0,devices=True)
    names=['null','zero','random','urandom','nvidia0','nvidiactl','nvidia-uvm']
    if controller:names+=['tpmrm0']
    cap_root=Path('/dev/nvidia-caps')
    try:
        cap_stat=cap_root.lstat()
    except FileNotFoundError:
        caps=[]
    else:
        if not stat.S_ISDIR(cap_stat.st_mode) or (cap_stat.st_uid,cap_stat.st_gid)!=(0,0):
            raise RuntimeError('candidate GPU capability directory differs')
        caps=sorted(cap_root.iterdir())
    for entry in caps:
        if not entry.name.startswith('nvidia-cap') or not entry.name[len('nvidia-cap'):].isdigit():
            raise RuntimeError('candidate unexpected GPU capability node')
        names.append('nvidia-caps/'+entry.name)
    os.mkdir(root+'/dev/nvidia-caps',0o755)
    rows=[]
    for name in names:
        source=os.stat('/dev/'+name,follow_symlinks=False)
        if not stat.S_ISCHR(source.st_mode):
            raise RuntimeError('candidate device source is not a character node')
        target=root+'/dev/'+name
        os.mknod(target,stat.S_IFCHR|0o600,source.st_rdev);os.chown(target,uid,uid)
        got=os.stat(target,follow_symlinks=False)
        if not stat.S_ISCHR(got.st_mode) or got.st_rdev!=source.st_rdev or (got.st_uid,got.st_gid)!=(uid,uid) or stat.S_IMODE(got.st_mode)!=0o600:
            raise RuntimeError('candidate projected device differs')
        rows.append((name,source.st_rdev))
    # RAM-backed shared memory has a separate bounded child mount. Seal the
    # containing device directory after creating its mountpoint.
    os.mkdir(root+'/dev/shm',0o755)
    _mount(None,root+'/dev',None,MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NOEXEC)
    _observe(root+'/dev',TMPFS_MAGIC,MS_RDONLY|MS_NOSUID|MS_NOEXEC)
    _tmpfs(root+'/dev/shm',1073741824,8192,0o700,uid)
    return tuple(rows)


def _set_sysctl(path: str,value: str) -> None:
    target='/proc/sys/'+path
    with open(target,'w') as output:
        if output.write(value+'\n')!=len(value)+1:
            raise RuntimeError('candidate kernel setting write was partial')
    if Path(target).read_text().strip()!=value:
        raise RuntimeError('candidate kernel setting readback differs')


@dataclass(frozen=True)
class PreparedFilesystems:
    outer_root: tuple[int,int]
    controller_root: tuple[int,int]
    workload_roots: tuple[tuple[str,int,int],...]
    devices: tuple[tuple[str,tuple[tuple[str,int],...]],...]


def prepare_filesystems() -> PreparedFilesystems:
    """Run after fixed driver/network setup, before any child or PCR15 measure.

    All models and runtimes reside inside the same dm-verity-backed SquashFS.
    The nested controller root is a distinct chroot within that measured volume.
    No block device or old-root descriptor survives the later handoff.
    """
    from conf_proc_spp_candidate_isolation import _require_singleton_pid1
    _require_singleton_pid1()
    outer=_observe('/',SQUASHFS_MAGIC,MS_RDONLY)
    device=Path('/sys/dev/block')/f'{os.major(outer[0])}:{os.minor(outer[0])}'
    if (device/'dm/name').read_text().strip()!='spp-diag-root' or (device/'ro').read_text().strip()!='1':
        raise RuntimeError('candidate root is not the readonly verified mapping')
    controller=_observe('/candidate',SQUASHFS_MAGIC,MS_RDONLY)
    if controller[0]!=outer[0] or controller[1]==outer[1]:
        raise RuntimeError('candidate controller root is not a distinct verified directory')
    rows=Path('/proc/swaps').read_text().splitlines()
    if len(rows)!=1 or rows[0].split()!=['Filename','Type','Size','Used','Priority']:
        raise RuntimeError('candidate persistent swap is active')
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    if resource.getrlimit(resource.RLIMIT_CORE)!=(0,0):
        raise RuntimeError('candidate core-dump limit differs')
    for path,value in (('kernel/core_pattern','core'),('kernel/sysrq','0'),
            ('kernel/kexec_load_disabled','1'),('kernel/modules_disabled','1'),
            ('kernel/dmesg_restrict','1'),('kernel/kptr_restrict','2'),
            ('kernel/perf_event_paranoid','3'),('kernel/unprivileged_bpf_disabled','1')):
        _set_sysctl(path,value)
    _mount(None,'/',None,MS_REC|MS_PRIVATE)
    _require_unmounted('/sys/fs/cgroup')
    _mount('cgroup2','/sys/fs/cgroup','cgroup2',MS_NOSUID|MS_NODEV|MS_NOEXEC)
    _observe('/sys/fs/cgroup',CGROUP2_MAGIC,MS_NOSUID|MS_NODEV|MS_NOEXEC)
    # PID1 retains the actual kernel control files inside its new root.
    for source in ('/proc','/sys'):
        _require_unmounted('/candidate'+source)
        _mount(source,'/candidate'+source,None,MS_BIND|MS_REC)
        if _observe('/candidate'+source,PROC_MAGIC if source=='/proc' else SYSFS_MAGIC,0)!=_observe(source,PROC_MAGIC if source=='/proc' else SYSFS_MAGIC,0):
            raise RuntimeError('candidate controller kernel mount differs')
    _tmpfs('/candidate/run',16777216,4096,0o700,0)
    _tmpfs('/candidate/tmp',16777216,4096,0o700,0)
    devices=[('controller',_device_nodes('/candidate',0,controller=True))]
    roots=[]
    for role,uid in (('inference',61101),('asr',61102)):
        root='/candidate/runtimes/'+role
        identity=_observe(root,SQUASHFS_MAGIC,MS_RDONLY)
        if identity[0]!=outer[0]:
            raise RuntimeError('candidate runtime is outside verified volume')
        roots.append((role,*identity))
        _require_unmounted(root+'/proc')
        _mount('proc',root+'/proc','proc',MS_NOSUID|MS_NODEV|MS_NOEXEC,'hidepid=2')
        _observe(root+'/proc',PROC_MAGIC,MS_NOSUID|MS_NODEV|MS_NOEXEC)
        _readonly_bind('/sys',root+'/sys',SYSFS_MAGIC,MS_NODEV|MS_NOEXEC)
        _tmpfs(root+'/tmp',4294967296 if role=='asr' else 2147483648,65536,0o700,uid,executable=True)
        _tmpfs(root+'/run',16777216,4096,0o700,uid)
        devices.append((role,_device_nodes(root,uid,controller=False)))
    return PreparedFilesystems(outer,controller,tuple(roots),tuple(devices))


def retire_controller_tpm_device(fd: int) -> None:
    """After S2, remove PID1's TPM path before final capability/namespace lock.

    The inherited fd5 remains available for its one transfer to the fixed
    attestation broker. No child or session may exist during this operation.
    The caller must close PID1's fd after that transfer and verify its census.
    """
    from conf_proc_spp_candidate_isolation import _require_singleton_pid1
    _require_singleton_pid1()
    if fd != 5 or os.get_inheritable(fd):
        raise RuntimeError('candidate TPM retirement descriptor differs')
    actual = os.fstat(fd)
    path = '/dev/tpmrm0'
    node = os.stat(path, follow_symlinks=False)
    if (not stat.S_ISCHR(node.st_mode) or not stat.S_ISCHR(actual.st_mode)
            or (node.st_dev,node.st_ino)==(actual.st_dev,actual.st_ino)
            or node.st_rdev != actual.st_rdev or (node.st_uid,node.st_gid)!=(0,0)
            or stat.S_IMODE(node.st_mode)!=0o600):
        raise RuntimeError('candidate TPM retirement device differs')
    flags = MS_NOSUID | MS_NOEXEC
    identity = _observe('/dev', TMPFS_MAGIC, flags | MS_RDONLY)
    try:
        _mount(None, '/dev', None, MS_REMOUNT | flags)
        check = _directory('/dev')
        try:
            fs = _filesystem(check)
            if fs.flags & MS_RDONLY:
                raise RuntimeError('candidate TPM retirement remount did not apply')
        finally:
            os.close(check)
        os.unlink(path)
    finally:
        _mount(None, '/dev', None, MS_REMOUNT | flags | MS_RDONLY)
        if _observe('/dev', TMPFS_MAGIC, flags | MS_RDONLY) != identity:
            raise RuntimeError('candidate retired device mount identity differs')
    if os.path.lexists(path) or os.fstat(fd).st_rdev != actual.st_rdev:
        raise RuntimeError('candidate TPM retirement did not preserve sole transport')
