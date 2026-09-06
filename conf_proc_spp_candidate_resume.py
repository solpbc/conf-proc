#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Physical, one-use cross-root handoff using the existing PCR16 formulas."""
from __future__ import annotations

from dataclasses import dataclass
import fcntl
import hashlib
import os
from pathlib import Path
import stat
import struct

from conf_proc_spp_candidate_tpm import NativeTpm, PCR15_READ, parse_pcr15_read, parse_extend_ack, _response

FRAME_SIZE = 1048
MAGIC = b'SPPRESUME-V3\0\0\0\0'
READ16 = bytes.fromhex('8001000000140000017e00000001000b03000001')
EXTEND16 = bytes.fromhex('80020000004100000182000000100000000940000009000000000000000001000b')
SEALS = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
_TRANSPORT = struct.Struct('>IIQIIIIQQ32s')


def _h(raw: bytes) -> bytes:
    return hashlib.sha256(raw).digest()


def _digest(value: bytes) -> bytes:
    if type(value) is not bytes or len(value) != 32:
        raise ValueError('candidate resume SHA256 field differs')
    return value


@dataclass(frozen=True)
class ResumeBinding:
    issued_binding: bytes
    measurement: bytes
    pcr15: bytes
    authorities: tuple[bytes, ...]

    def encode(self) -> bytes:
        if type(self.authorities) is not tuple or len(self.authorities) != 13:
            raise ValueError('candidate resume authority census differs')
        return b''.join(_digest(x) for x in (
            self.issued_binding, self.measurement, self.pcr15, *self.authorities))


@dataclass(frozen=True)
class ResumeFrame:
    nonce: bytes
    binding: ResumeBinding
    namespaces: tuple[int, ...]
    transport: bytes

    def encode(self) -> bytes:
        if (type(self.namespaces) is not tuple or len(self.namespaces) != 4
                or any(type(x) is not int or not 0 < x < 2**64 for x in self.namespaces)
                or type(self.transport) is not bytes or len(self.transport) != _TRANSPORT.size):
            raise ValueError('candidate resume physical identity differs')
        body = (_digest(self.nonce) + self.binding.encode()
                + struct.pack('>4Q', *self.namespaces) + self.transport)
        raw = struct.pack('>16sHIH', MAGIC, 3, FRAME_SIZE, 0) + body
        return raw + bytes(FRAME_SIZE - len(raw))


def decode_frame(raw: bytes, expected: ResumeBinding) -> ResumeFrame:
    if (type(raw) is not bytes or len(raw) != FRAME_SIZE
            or raw[:24] != struct.pack('>16sHIH', MAGIC, 3, FRAME_SIZE, 0)):
        raise ValueError('candidate resume frame header differs')
    # Fixed internal layout completes the formerly declaration-only 1048-byte
    # handoff. It is not part of the owner RA-TLS envelope.
    binding = expected.encode()
    if raw[56:568] != binding:
        raise ValueError('candidate resume independently supplied binding differs')
    end = 600 + _TRANSPORT.size
    if any(raw[end:]):
        raise ValueError('candidate resume reserved bytes differ')
    frame = ResumeFrame(raw[24:56], expected, struct.unpack('>4Q', raw[568:600]), raw[600:end])
    if frame.encode() != raw:
        raise ValueError('candidate resume frame is not canonical')
    return frame


@dataclass(frozen=True)
class ResumeStates:
    nonce_commitment: bytes
    transport_identity: bytes
    lineage: bytes
    frame_sha256: bytes
    d1: bytes
    s1: bytes
    d2: bytes
    s2: bytes


def resume_states(frame: ResumeFrame, raw: bytes | None = None) -> ResumeStates:
    encoded = frame.encode()
    if raw is not None and raw != encoded:
        raise ValueError('candidate resume bytes differ from parsed frame')
    nonce = _h(b'sol-pbc/spp/handoff-nonce-v3\0' + frame.nonce)
    transport = _h(b'sol-pbc/spp/tpmrm-transport-v3\0' + frame.transport)
    lineage = _h(b'sol-pbc/spp/boot-lineage-v3\0' + frame.binding.encode()
                 + struct.pack('>4Q', *frame.namespaces) + transport + nonce)
    digest = _h(encoded)
    d1 = _h(b'sol-pbc/spp/resume-anchor-v3/staged\0' + struct.pack('>HI', 3, FRAME_SIZE)
            + digest + lineage + nonce)
    s1 = _h(bytes(32) + d1)
    d2 = _h(b'sol-pbc/spp/resume-anchor-v3/consumed\0' + struct.pack('>H', 3)
            + s1 + d1 + digest + lineage + nonce)
    return ResumeStates(nonce, transport, lineage, digest, d1, s1, d2, _h(s1 + d2))


def parse_read16(raw: bytes) -> bytes:
    body = _response(raw, 0x8001)
    if (len(body) != 52
            or body[4:20] != bytes.fromhex('00000001000b03000001000000010020')):
        raise ValueError('candidate PCR16 response selection or size differs')
    return body[20:]


def namespaces() -> tuple[int, ...]:
    return tuple(os.stat('/proc/self/ns/' + name).st_ino for name in ('mnt', 'user', 'pid', 'net'))


def transport_bytes(fd: int, registration_digest: bytes) -> bytes:
    info = os.fstat(fd)
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    fdflags = fcntl.fcntl(fd, fcntl.F_GETFD)
    if (not stat.S_ISCHR(info.st_mode) or flags & os.O_ACCMODE != os.O_RDWR
            or not flags & os.O_NONBLOCK or fdflags != fcntl.FD_CLOEXEC):
        raise RuntimeError('candidate resume TPM descriptor flags or type differ')
    metadata = dict(line.split(':', 1) for line in Path('/proc/self/fdinfo/' + str(fd)).read_text().splitlines())
    if int(metadata['ino']) != info.st_ino:
        raise RuntimeError('candidate TPM descriptor inode readback differs')
    # O_NONBLOCK is required for a physical five-second budget: this kernel's
    # tpm_common_write otherwise blocks inside tpm_dev_transmit before poll.
    return _TRANSPORT.pack(os.major(info.st_dev), os.minor(info.st_dev), info.st_ino,
        os.major(info.st_rdev), os.minor(info.st_rdev), flags & ~os.O_CLOEXEC, fdflags,
        int(metadata['mnt_id']), int(metadata['ino']), _digest(registration_digest))


def _references(device: int, inode: int) -> list[int]:
    found = []
    for name in os.listdir('/proc/self/fd'):
        try:
            node = os.fstat(int(name))
        except OSError:
            # Only listdir's already-closed descriptor may disappear here.
            if Path('/proc/self/fd/' + name).exists():
                raise
            continue
        if (node.st_dev, node.st_ino) == (device, inode):
            found.append(int(name))
    return found


def inspect_memfd(fd: int, offset: int = 0) -> tuple[int, int]:
    node = os.fstat(fd)
    if (not stat.S_ISREG(node.st_mode) or node.st_size != FRAME_SIZE or node.st_nlink != 0
            or os.readlink('/proc/self/fd/' + str(fd)) != '/memfd:spp-handoff-v3 (deleted)'
            or fcntl.fcntl(fd, fcntl.F_GET_SEALS) != SEALS
            or os.lseek(fd, 0, os.SEEK_CUR) != offset
            or _references(node.st_dev, node.st_ino) != [fd]):
        raise RuntimeError('candidate sealed handoff descriptor census differs')
    return node.st_dev, node.st_ino


def create_memfd(frame: bytes) -> int:
    if type(frame) is not bytes or len(frame) != FRAME_SIZE:
        raise ValueError('candidate handoff frame length differs')
    fd = os.memfd_create('spp-handoff-v3', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        if os.write(fd, frame) != FRAME_SIZE:
            raise RuntimeError('candidate handoff frame write incomplete')
        os.lseek(fd, 0, os.SEEK_SET)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, SEALS)
        inspect_memfd(fd)
        return fd
    except BaseException:
        os.close(fd)
        raise


def consume_memfd(fd: int) -> bytes:
    device, inode = inspect_memfd(fd)
    try:
        raw = os.read(fd, FRAME_SIZE + 1)
        if len(raw) != FRAME_SIZE:
            raise RuntimeError('candidate handoff advancing read incomplete')
        inspect_memfd(fd, FRAME_SIZE)
    finally:
        os.close(fd)
    if _references(device, inode):
        raise RuntimeError('candidate consumed handoff inode remains open')
    return raw


def _singleton_pid1() -> None:
    if (os.getpid() != 1 or os.getresuid() != (0, 0, 0) or os.getresgid() != (0, 0, 0)
            or os.listdir('/proc/self/task') != ['1']
            or Path('/proc/self/task/1/children').read_text().strip()):
        raise RuntimeError('candidate resume requires sole-thread PID1 without children')


def _closed_slot(fd: int) -> None:
    try:
        os.fstat(fd)
    except OSError as exc:
        if exc.errno == 9:
            return
        raise
    raise RuntimeError('candidate resume fixed descriptor slot is occupied')


def require_fd_census(expected: set[int]) -> None:
    actual = set()
    for name in os.listdir('/proc/self/fd'):
        try:
            os.fstat(int(name))
        except OSError:
            if Path('/proc/self/fd/' + name).exists():
                raise
            continue
        actual.add(int(name))
    if actual != expected:
        raise RuntimeError('candidate resume has missing or ambient descriptors')


def _tpm_matches_device(fd: int) -> None:
    node = os.stat('/dev/tpmrm0', follow_symlinks=False)
    actual = os.fstat(fd)
    if not stat.S_ISCHR(node.st_mode) or not stat.S_ISCHR(actual.st_mode) or actual.st_rdev != node.st_rdev:
        raise RuntimeError('candidate resume transport is not the fixed TPM resource manager')
    matches = []
    for name in os.listdir('/proc/self/fd'):
        try:
            item = os.fstat(int(name))
        except OSError:
            if Path('/proc/self/fd/' + name).exists():
                raise
            continue
        if stat.S_ISCHR(item.st_mode) and item.st_rdev == actual.st_rdev:
            matches.append(int(name))
    if matches != [fd]:
        raise RuntimeError('candidate TPM transport is not solely owned')


@dataclass
class PreparedResume:
    frame: ResumeFrame
    states: ResumeStates
    tpm: NativeTpm
    _exec_attempted: bool = False

    def exec_stage2(self, root_fd: int) -> None:
        """One fixed exec after the boot entry has appraised the readonly root."""
        if self._exec_attempted:
            raise RuntimeError('candidate stage2 exec cannot be retried')
        self._exec_attempted = True
        _singleton_pid1()
        node = os.fstat(root_fd)
        if (root_fd in range(7) or not stat.S_ISDIR(node.st_mode)
                or (node.st_uid, node.st_gid) != (0, 0)
                or not os.fstatvfs(root_fd).f_flag & os.ST_RDONLY):
            raise RuntimeError('candidate stage2 root descriptor differs')
        require_fd_census(set(range(7)) | {root_fd})
        inspect_memfd(3)
        if os.pread(3, FRAME_SIZE + 1, 0) != self.frame.encode():
            raise RuntimeError('candidate pre-exec sealed frame differs')
        _tpm_matches_device(5)
        if (namespaces() != self.frame.namespaces
                or transport_bytes(5, self.frame.transport[-32:]) != self.frame.transport):
            raise RuntimeError('candidate pre-exec namespace or transport drift')
        # fd4 is the already sealed device monitor, fd6 the actual trace handle.
        # Their state-specific readbacks belong to the boot entry; require their
        # presence and exec flags here without inventing replacement evidence.
        for fd in (3, 4, 5, 6):
            if os.get_inheritable(fd):
                raise RuntimeError('candidate inherited descriptor armed prematurely')
        os.fchdir(root_fd)
        os.chroot('.')
        os.chdir('/')
        os.close(root_fd)
        _singleton_pid1()
        require_fd_census(set(range(7)))
        inspect_memfd(3)
        for fd in (3, 4, 5, 6):
            os.set_inheritable(fd, True)
            if not os.get_inheritable(fd):
                raise RuntimeError('candidate exec descriptor flag readback differs')
        argv = ('/usr/bin/python3.10', '-I', '-B', '-S',
                '/usr/lib/spp/conf_proc_spp_candidate_entry.py', '--stage2')
        os.execve(argv[0], argv, {'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC', 'LD_BIND_NOW': '1'})


def prepare_stage1(expected: ResumeBinding, registration_digest: bytes) -> PreparedResume:
    """Open the resume transport only after the boot TPM owner has closed."""
    _singleton_pid1()
    expected.encode()
    _digest(registration_digest)
    _closed_slot(3)
    _closed_slot(5)
    tpm = NativeTpm()
    memfd = None
    try:
        if tpm.fd != 5:
            os.dup2(tpm.fd, 5, inheritable=False)
            os.close(tpm.fd)
            tpm.fd = 5
        _tpm_matches_device(5)
        if parse_pcr15_read(tpm.exchange(PCR15_READ)) != expected.pcr15:
            raise RuntimeError('candidate stage1 PCR15 binding differs')
        frame = ResumeFrame(os.getrandom(32), expected, namespaces(), transport_bytes(5, registration_digest))
        memfd = create_memfd(frame.encode())
        if memfd != 3:
            os.dup2(memfd, 3, inheritable=False)
            os.close(memfd)
            memfd = 3
        states = ResumeAnchor(tpm).stage1(frame, memfd)
        _singleton_pid1()
        return PreparedResume(frame, states, tpm)
    except BaseException:
        if memfd is not None:
            os.close(memfd)
        tpm.close()
        raise


def resume_stage2(expected: ResumeBinding, registration_digest: bytes) -> tuple[NativeTpm, ResumeStates]:
    """First stage2 operation; no controller or serving construction precedes it."""
    _singleton_pid1()
    require_fd_census(set(range(7)))
    for fd in (3, 4, 5, 6):
        if not os.get_inheritable(fd):
            raise RuntimeError('candidate stage2 descriptor did not cross fixed exec')
        os.set_inheritable(fd, False)
        if os.get_inheritable(fd):
            raise RuntimeError('candidate stage2 CLOEXEC restoration failed')
    _tpm_matches_device(5)
    tpm = NativeTpm.__new__(NativeTpm)
    tpm.fd = 5  # Preserve the inherited open file description; never reopen.
    try:
        states = ResumeAnchor(tpm).stage2(expected, registration_digest)
        _singleton_pid1()
        require_fd_census({0, 1, 2, 4, 5, 6})
        return tpm, states
    except BaseException:
        tpm.close()
        raise


class ResumeAnchor:
    """No retry after any TPM ambiguity; stage2 authority follows S2 readback.

    The boot entry owns the fixed fd3/fd5 exec transfer and immutable binding
    appraisal. Only physical leaf operations are replaceable in tests.
    """

    def __init__(self, tpm: NativeTpm) -> None:
        self.tpm = tpm
        self._attempted = False

    def stage1(self, frame: ResumeFrame, fd: int) -> ResumeStates:
        if self._attempted:
            raise RuntimeError('candidate resume operation cannot be retried')
        self._attempted = True
        inspect_memfd(fd)
        if os.pread(fd, FRAME_SIZE + 1, 0) != frame.encode():
            raise RuntimeError('candidate handoff sealed bytes differ')
        states = resume_states(frame)
        if parse_read16(self.tpm.exchange(READ16)) != bytes(32):
            raise RuntimeError('candidate PCR16 was not initially zero')
        parse_extend_ack(self.tpm.exchange(EXTEND16 + states.d1))
        if parse_read16(self.tpm.exchange(READ16)) != states.s1:
            raise RuntimeError('candidate staged PCR16 readback differs')
        inspect_memfd(fd)
        return states

    def stage2(self, expected: ResumeBinding, registration_digest: bytes, fd: int = 3) -> ResumeStates:
        if self._attempted:
            raise RuntimeError('candidate resume operation cannot be retried')
        self._attempted = True
        # Read S1 before consuming any content. Expected S1 is reconstructed
        # from the sealed frame plus independent post-exec binding, never from
        # this observed PCR. No authority is returned until both compares pass.
        inspect_memfd(fd)
        observed = parse_read16(self.tpm.exchange(READ16))
        frame = decode_frame(consume_memfd(fd), expected)
        if frame.namespaces != namespaces() or frame.transport != transport_bytes(self.tpm.fd, registration_digest):
            raise RuntimeError('candidate cross-root physical identity differs')
        states = resume_states(frame)
        if observed != states.s1:
            raise RuntimeError('candidate resumed PCR16 differs from staged frame')
        parse_extend_ack(self.tpm.exchange(EXTEND16 + states.d2))
        if parse_read16(self.tpm.exchange(READ16)) != states.s2:
            raise RuntimeError('candidate consumed PCR16 readback differs')
        if parse_pcr15_read(self.tpm.exchange(PCR15_READ)) != expected.pcr15:
            raise RuntimeError('candidate post-exec PCR15 binding differs')
        return states
