#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Independently encoded TPM packets exercise one acknowledged manifest extend."""
import hashlib
from pathlib import Path
import struct
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from conf_proc_spp_candidate_tpm import ManifestPcr15, PCR15_READ, pcr15_extend_command, parse_pcr15_read

DIGEST=bytes(range(32))
EXPECTED=hashlib.sha256(bytes(32)+DIGEST).digest()
ACK=bytes.fromhex('80020000001300000000000000000000010000')

def read_reply(digest):
    return bytes.fromhex('80010000003e000000000000000100000001000b03008000000000010020')+digest

class Transport:
    def __init__(self,responses):self.responses=list(responses);self.commands=[]
    def exchange(self,command):
        self.commands.append(command)
        item=self.responses.pop(0)
        if isinstance(item,BaseException):raise item
        return item

class Tests(unittest.TestCase):
    def test_packets_and_real_digest_conjunction(self):
        self.assertEqual(PCR15_READ.hex(),'8001000000140000017e00000001000b03008000')
        self.assertEqual(pcr15_extend_command(DIGEST),bytes.fromhex('800200000041000001820000000f0000000940000009000000000000000001000b')+DIGEST)
        transport=Transport([read_reply(bytes(32)),ACK,read_reply(EXPECTED)])
        measure=ManifestPcr15(transport)
        self.assertEqual(measure.measure(DIGEST),EXPECTED)
        self.assertEqual(transport.commands,[PCR15_READ,pcr15_extend_command(DIGEST),PCR15_READ])
        with self.assertRaises(RuntimeError):measure.measure(DIGEST)
        self.assertEqual(len(transport.commands),3)
    def test_nonzero_initial_never_extends(self):
        transport=Transport([read_reply(b'x'*32)])
        with self.assertRaises(RuntimeError):ManifestPcr15(transport).measure(DIGEST)
        self.assertEqual(transport.commands,[PCR15_READ])
    def test_missing_partial_and_wrong_ack_never_readback_or_retry(self):
        for bad in (b'',ACK[:-1],ACK[:6]+b'\x00\x00\x01\x01'+ACK[10:],OSError('TPM unavailable')):
            transport=Transport([read_reply(bytes(32)),bad])
            measure=ManifestPcr15(transport)
            with self.assertRaises((ValueError,OSError)):measure.measure(DIGEST)
            with self.assertRaises(RuntimeError):measure.measure(DIGEST)
            self.assertEqual(len(transport.commands),2)
    def test_readback_is_independent_not_learned(self):
        transport=Transport([read_reply(bytes(32)),ACK,read_reply(DIGEST)])
        with self.assertRaises(RuntimeError):ManifestPcr15(transport).measure(DIGEST)
        self.assertEqual(len(transport.commands),3)
    def test_wrong_selection_and_trailing_bytes_reject(self):
        good=read_reply(bytes(32))
        for raw in (good+b'x',good[:-1],good[:22]+b'\x40'+good[23:]):
            with self.assertRaises(ValueError):parse_pcr15_read(raw)

if __name__=='__main__':unittest.main()
