#!/usr/bin/env python3
"""Structural tests for the offline passive bridge ELF layout, not a loader."""

import hashlib
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

from build_folderfollow_saved_path_rebuild import normalize_source, SOURCE_SHA256
import reveal_bridge_elf as elf


SOURCE = (Path(__file__).resolve().parents[1]
          / 'artifacts/import-20261001/hiby_player_02fd.bin')


class RevealBridgeElfTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SOURCE.read_bytes()
        cls.golden, _ = normalize_source(cls.source)
        if hashlib.sha256(cls.golden).hexdigest() != SOURCE_SHA256:
            raise AssertionError('reference did not normalize to pinned golden')

    def headers(self, image):
        return [struct.unpack_from('<8I', image, 52 + 32 * i)
                for i in range(10)]

    def test_plan_exact_addresses(self):
        self.assertEqual(elf.plan_layout(self.golden, 0x10000), {
            'buffer': 0xBD4000,
            'memsize_offset': 0xA8,
            'memsize': 0x178000,
            'code_base': 0xBF0000,
            'code_offset': 0x6D0000,
            'phdr_offset': 0x154,
        })

    def test_one_byte_and_alignment_boundary_memory_requests(self):
        for requested, code_base in ((1, 0xBE0000), (0xC000, 0xBE0000),
                                     (0xC001, 0xBF0000)):
            with self.subTest(requested=requested):
                result = elf.plan_layout(self.golden, requested)
                self.assertEqual(result['code_base'], code_base)
                self.assertEqual(result['memsize'],
                                 0xBD4000 + requested - 0xA6C000)

    def test_only_two_original_header_areas_change(self):
        before = self.golden
        code = bytes.fromhex('0800e00300000000')
        output, meta = elf.install_layout(before, code, 0x20000)
        original_copy = bytearray(output[:len(before)])
        for start, length in ((0xA8, 4), (0x154, 32)):
            original_copy[start:start + length] = before[start:start + length]
        self.assertEqual(bytes(original_copy), before)
        self.assertEqual(hashlib.sha256(before).hexdigest(), SOURCE_SHA256)
        self.assertEqual(output[len(before):meta['code_offset']],
                         b'\0' * (meta['code_offset'] - len(before)))
        self.assertEqual(output[meta['code_offset']:], code)
        self.assertEqual(meta['code_bytes'], len(code))
        self.assertEqual(meta['output_size'], len(output))
        self.assertEqual(len(output), meta['code_offset'] + len(code))

    def test_old_phdrs_and_permissions_are_preserved(self):
        output, meta = elf.install_layout(self.golden, b'\0' * 16, 0x40000)
        original_headers = self.headers(self.golden)
        new_headers = self.headers(output)
        for index in range(9):
            expected = list(original_headers[index])
            if index == 3:
                expected[5] = meta['memsize']
            self.assertEqual(new_headers[index], tuple(expected))
        self.assertEqual(new_headers[9], (
            1, meta['code_offset'], meta['code_base'], meta['code_base'],
            16, 16, 5, 0x10000))
        # Existing GNU_STACK flags are deliberately not rewritten. All LOADs,
        # including the new code, must be non-W+X.
        for header in new_headers:
            if header[0] == 1:
                self.assertNotEqual(header[6] & 3, 3)

    def test_private_memory_zero_fill_and_load_ranges_do_not_overlap(self):
        output, meta = elf.install_layout(self.golden, b'\0' * 12, 0x54321)
        loads = [h for h in self.headers(output) if h[0] == 1]
        for previous, current in zip(loads, loads[1:]):
            self.assertLessEqual(previous[2] + previous[5], current[2])
            self.assertLessEqual(previous[1] + previous[4], current[1])
        rw = loads[1]
        self.assertLess(rw[2] + rw[4], meta['buffer'])
        self.assertEqual(rw[2] + rw[5], meta['buffer'] + 0x54321)
        for load in loads:
            self.assertEqual(load[1] % load[7], load[2] % load[7])
            self.assertLess(load[2] + load[5], elf.J_REGION_END)

    def test_deterministic_and_supports_maximum_bounded_sizes(self):
        code = b'\0' * elf.MAX_CODE_BYTES
        one = elf.install_layout(self.golden, code, elf.MAX_MEMORY_BYTES)
        two = elf.install_layout(self.golden, code, elf.MAX_MEMORY_BYTES)
        self.assertEqual(one, two)
        self.assertLess(one[1]['code_base'] + len(code), elf.J_REGION_END)

    def test_invalid_memory_dimensions_fail_closed(self):
        for size in (0, -1, True, False, None, 1.0, '8',
                     elf.MAX_MEMORY_BYTES + 1, 1 << 32):
            with self.subTest(size=size), self.assertRaises(ValueError):
                elf.plan_layout(self.golden, size)

    def test_invalid_code_dimensions_fail_closed(self):
        for code in (b'', b'\0', b'\0' * 3, b'\0' * 5,
                     bytearray(4), None, 'code',
                     b'\0' * (elf.MAX_CODE_BYTES + 4)):
            with self.subTest(size=None if code is None else len(code)):
                with self.assertRaises(ValueError):
                    elf.install_layout(self.golden, code, 4)

    def test_input_must_be_exact_immutable_normalized_golden(self):
        candidates = (self.source, bytearray(self.golden), b'',
                      self.golden[:-1], self.golden + b'\0')
        for index, candidate in enumerate(candidates):
            with self.subTest(index=index), self.assertRaises(ValueError):
                elf.plan_layout(candidate, 4)

    def test_arbitrary_content_and_header_tampering_is_rejected(self):
        for offset in (0, 16, 28, 42, 44, 0xA8, 0xAC, 0x154,
                       0x16C, 0x41F970 - 0x400000, len(self.golden) - 1):
            image = bytearray(self.golden)
            image[offset] ^= 1
            with self.subTest(offset=hex(offset)), self.assertRaises(ValueError):
                elf.plan_layout(bytes(image), 4)

    def test_reapplying_layout_is_rejected(self):
        output, _ = elf.install_layout(self.golden, b'\0' * 4, 4)
        with self.assertRaises(ValueError):
            elf.install_layout(output, b'\0' * 4, 4)

    def test_structural_guards_even_if_digest_gate_is_bypassed(self):
        # Test-only digest substitution exercises independent structural
        # checks; there is no production option to waive the pinned digest.
        for offset, value, fmt in ((28, 64, '<I'), (44, 9, '<H'),
                                   (0x154, 1, '<I'), (0xAC, 7, '<I'),
                                   (0x90, 0x1000, '<I')):
            image = bytearray(self.golden)
            struct.pack_into(fmt, image, offset, value)
            image = bytes(image)
            with self.subTest(offset=hex(offset)):
                with patch.object(elf, 'SOURCE_SHA256',
                                  hashlib.sha256(image).hexdigest()):
                    with self.assertRaises(ValueError):
                        elf.plan_layout(image, 4)

    def test_jump_region_boundary_is_checked_for_memory_and_code(self):
        with patch.object(elf, 'J_REGION_END', 0xBE0000):
            with self.assertRaisesRegex(ValueError, 'code base'):
                elf.plan_layout(self.golden, 1)
        with patch.object(elf, 'J_REGION_END', 0xBE0004):
            with self.assertRaisesRegex(ValueError, 'code leaves'):
                elf.install_layout(self.golden, b'\0' * 8, 1)


if __name__ == '__main__':
    unittest.main()
