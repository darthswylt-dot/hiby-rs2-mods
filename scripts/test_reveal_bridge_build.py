#!/usr/bin/env python3
"""Reproducibility and patch-scope tests for the new capture-only ELF."""

import struct
import unittest

import build_reveal_bridge_diag as d
from verify_reveal_bridge_diag import verify
from test_folderfollow_reveal_static_contract import SOURCE


class BridgeBuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SOURCE.read_bytes()
        cls.golden, _ = d.b.normalize_source(cls.source)
        cls.candidate, cls.meta = d.build(cls.source)

    def test_full_verifier_and_noninstallable_labels(self):
        report = verify(self.source, self.candidate)
        self.assertFalse(report['autoscroll'])
        self.assertTrue(report['capture_only'])
        self.assertEqual(report['hardware'], 'UNTESTED')
        self.assertGreater(report['code_bytes'], d.b.CAVE_CAPACITY)
        self.assertEqual(len(report['external_calls']), 4)

    def test_normalized_inputs_build_identical_candidate(self):
        candidate, meta = d.build(self.golden)
        self.assertEqual(candidate, self.candidate)
        self.assertEqual(meta['labels'], self.meta['labels'])
        self.assertEqual(meta['buffer'], 0xBD4000)

    def test_legacy_cave_is_untouched_and_no_old_wrapper_composition(self):
        off, size = d.b.CAVE_OFFSET, d.b.CAVE_CAPACITY
        self.assertEqual(self.candidate[off:off + size], bytes(size))
        self.assertEqual(self.candidate[off:off + size], self.golden[off:off + size])

    def test_all_declared_hooks_and_delay_slots(self):
        for kind, (pc, original) in d.HOOKS.items():
            with self.subTest(kind=kind):
                word, delay = struct.unpack_from('<2I', self.candidate, pc - d.BASE)
                self.assertEqual(word >> 26, 3 if kind in d.LINKED else 2)
                target = self.meta['labels']['playback' if kind.startswith('play_') else kind]
                self.assertEqual((word & 0x3FFFFFF) << 2, target)
                self.assertEqual(delay, original[1] if kind in d.LINKED else 0)

    def test_mutated_hook_header_code_and_undeclared_original_byte_rejected(self):
        points = (d.HOOKS['touch'][0] - d.BASE, self.meta['memsize_offset'],
                  self.meta['phdr_offset'] + 24, self.meta['code_offset'],
                  d.b.CALLBACK_HI_OFFSET, d.b.CALLBACK_LO_OFFSET, 0x500)
        for offset in points:
            with self.subTest(offset=hex(offset)):
                bad = bytearray(self.candidate)
                bad[offset] ^= 1
                with self.assertRaises(ValueError):
                    verify(self.source, bytes(bad))

    def test_wrong_source_and_length_rejected(self):
        with self.assertRaises(ValueError):
            d.build(self.candidate)
        with self.assertRaises(ValueError):
            d.build(self.source[:-1])
        for bad in (self.candidate[:-1], self.candidate + b'\0'):
            with self.assertRaises(ValueError):
                verify(self.source, bad)

    def test_capacity_can_hold_a_full_512_row_query_with_bookends(self):
        self.assertGreaterEqual(d.CAPACITY, 512 + 3)
        self.assertEqual(d.MEMORY_BYTES, d.HEADER + d.RECORD * d.CAPACITY)
        self.assertEqual(d.WRITE, 0xA5B4A0)


if __name__ == '__main__':
    unittest.main()
