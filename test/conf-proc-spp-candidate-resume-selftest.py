#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Native sealed-FD consumption and independent PCR16 formula/packet oracle."""
from dataclasses import astuple, replace
import fcntl
import os
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import conf_proc_spp_candidate_resume as r
import conf_proc_spp_boot_v3_resume_oracle as oracle

V = oracle.vector_inputs()
BINDING = r.ResumeBinding(V.binding, V.measurement, V.pcr15, V.authority_inputs)
TRANSPORT = struct.pack('>IIQIIIIQQ32s', *astuple(V.transport))
FRAME = r.ResumeFrame(V.nonce, BINDING, V.namespaces, TRANSPORT)
STATES = oracle.calculate(replace(V, frame=FRAME.encode()))
ACK = bytes.fromhex('80020000001300000000000000000000010000')


class Tpm:
    fd = 99

    def __init__(self, responses):
        self.responses = list(responses)
        self.commands = []

    def exchange(self, raw):
        self.commands.append(raw)
        value = self.responses.pop(0)
        if isinstance(value, BaseException):
            raise value
        return value


def replies():
    return [oracle.read_response(bytes(32), 1), ACK, oracle.read_response(STATES.s1, 2),
            oracle.read_response(STATES.s1, 2), ACK, oracle.read_response(STATES.s2, 3),
            bytes.fromhex('80010000003e000000000000000300000001000b03008000000000010020') + V.pcr15]


class Tests(unittest.TestCase):
    def test_actual_extra_old_root_descriptor_rejects_closed_exec_census(self):
        held = set()
        for name in os.listdir('/proc/self/fd'):
            try: os.fstat(int(name))
            except OSError: continue
            held.add(int(name))
        r.require_fd_census(held)
        old_root = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            with self.assertRaises(RuntimeError): r.require_fd_census(held)
            r.require_fd_census(held | {old_root})
        finally: os.close(old_root)
        r.require_fd_census(held)

    def test_all_formulas_match_existing_independent_oracle(self):
        self.assertEqual(astuple(r.resume_states(FRAME)), astuple(STATES))
        self.assertEqual(r.decode_frame(FRAME.encode(), BINDING), FRAME)
        changed = replace(FRAME, nonce=b'x' * 32)
        self.assertNotEqual(r.resume_states(changed).s2, STATES.s2)

    def test_frame_rejects_altered_binding_header_padding_or_length(self):
        raw = FRAME.encode()
        for offset in (0, 17, 23, 60, 1047):
            value = bytearray(raw); value[offset] ^= 1
            with self.assertRaises(ValueError): r.decode_frame(bytes(value), BINDING)
        with self.assertRaises(ValueError): r.decode_frame(raw[:-1], BINDING)
        with self.assertRaises(ValueError):
            r.decode_frame(raw, replace(BINDING, pcr15=b'\0' * 32))

    def test_actual_memfd_seals_duplicates_offset_and_consumption(self):
        fd = r.create_memfd(FRAME.encode())
        original = os.fstat(fd)
        twin = os.dup(fd)
        with self.assertRaises(RuntimeError): r.inspect_memfd(fd)
        os.close(twin)
        with self.assertRaises(OSError): os.write(fd, b'changed')
        self.assertEqual(r.consume_memfd(fd), FRAME.encode())
        with self.assertRaises(OSError): os.fstat(fd)
        self.assertEqual(r._references(original.st_dev, original.st_ino), [])
        fd = r.create_memfd(FRAME.encode())
        try:
            os.read(fd, 1)
            with self.assertRaises(RuntimeError): r.consume_memfd(fd)
        finally: os.close(fd)

    def test_unsealed_or_wrong_name_rejected(self):
        fd = os.memfd_create('wrong', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            os.write(fd, FRAME.encode()); os.lseek(fd, 0, os.SEEK_SET)
            with self.assertRaises(RuntimeError): r.inspect_memfd(fd)
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, r.SEALS)
            with self.assertRaises(RuntimeError): r.inspect_memfd(fd)
        finally: os.close(fd)

    def execute(self, responses, *, physical_transport=TRANSPORT):
        tpm = Tpm(responses)
        fd = r.create_memfd(FRAME.encode())
        first, second = r.ResumeAnchor(tpm), r.ResumeAnchor(tpm)
        try:
            first.stage1(FRAME, fd)
            with patch.object(r, 'namespaces', return_value=V.namespaces), \
                    patch.object(r, 'transport_bytes', return_value=physical_transport):
                second.stage2(BINDING, V.transport.registration_identity, fd)
            return tpm, first, second
        finally:
            try: os.close(fd)
            except OSError: pass

    def test_six_ordered_operations_then_independent_pcr15(self):
        tpm, first, second = self.execute(replies())
        self.assertEqual(tpm.commands, [oracle.READ_REQUEST, oracle.extend_request(STATES.d1),
            oracle.READ_REQUEST, oracle.READ_REQUEST, oracle.extend_request(STATES.d2),
            oracle.READ_REQUEST, r.PCR15_READ])
        with self.assertRaises(RuntimeError): first.stage1(FRAME, -1)
        with self.assertRaises(RuntimeError): second.stage2(BINDING, V.transport.registration_identity, -1)
        self.assertEqual(len(tpm.commands), 7)

    def test_every_missing_or_ambiguous_operation_stops_without_retry(self):
        for index in range(7):
            for failure in (b'', OSError('TPM unavailable'), TimeoutError('deadline')):
                values = replies(); values[index] = failure
                tpm = Tpm(values)
                fd = r.create_memfd(FRAME.encode())
                first, second = r.ResumeAnchor(tpm), r.ResumeAnchor(tpm)
                active = first
                try:
                    with patch.object(r, 'namespaces', return_value=V.namespaces), \
                            patch.object(r, 'transport_bytes', return_value=TRANSPORT):
                        with self.assertRaises((ValueError, OSError)):
                            first.stage1(FRAME, fd)
                            active = second
                            second.stage2(BINDING, V.transport.registration_identity, fd)
                    self.assertEqual(len(tpm.commands), index + 1)
                    with self.assertRaises(RuntimeError): active.stage1(FRAME, fd)
                    self.assertEqual(len(tpm.commands), index + 1)
                finally:
                    try: os.close(fd)
                    except OSError: pass

    def test_wrong_pcr_states_and_cross_root_transport_reject(self):
        for index in (0, 2, 3, 5):
            values = replies(); values[index] = oracle.read_response(b'x' * 32, 7)
            with self.assertRaises(RuntimeError): self.execute(values)
        with self.assertRaises(RuntimeError):
            self.execute(replies(), physical_transport=b'x' * len(TRANSPORT))
        values = replies(); values[-1] = values[-1][:-32] + bytes(32)
        with self.assertRaises(RuntimeError): self.execute(values)


if __name__ == '__main__': unittest.main()
