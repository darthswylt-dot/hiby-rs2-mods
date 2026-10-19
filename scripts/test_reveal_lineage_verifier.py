"""Saved-image acceptance/rejection checks; no deployment."""
import unittest

import build_reveal_lineage_stage as stage
from verify_reveal_lineage_stage import verify
from test_folderfollow_reveal_static_contract import SOURCE


class LineageVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SOURCE.read_bytes()
        cls.image, cls.meta = stage.build(cls.source)

    def test_exact_image_and_normalized_reference(self):
        result = verify(self.source, self.image)
        golden, _ = stage.normalize_source(self.source)
        self.assertEqual(verify(golden, self.image)['sha256'], result['sha256'])
        self.assertEqual(result['external_calls'], [0x6F7CA0])
        self.assertFalse(result['autoscroll'])
        self.assertEqual(result['memory_bytes'], 16 + 64 * 1024)

    def test_corruption_at_every_distinct_patch_class_is_rejected(self):
        offsets = (0x500, self.meta['memsize_offset'], self.meta['phdr_offset'],
                   0x490758 - stage.BASE, 0x48F3BC - stage.BASE,
                   0x48F1B4 - stage.BASE, len(self.source), self.meta['code_offset'])
        for offset in offsets:
            with self.subTest(offset=hex(offset)):
                corrupted = bytearray(self.image)
                corrupted[offset] ^= 1
                with self.assertRaises(ValueError):
                    verify(self.source, bytes(corrupted))

    def test_truncated_extended_and_unknown_source_are_rejected(self):
        for candidate in (self.image[:-1], self.image + b'\0'):
            with self.assertRaises(ValueError):
                verify(self.source, candidate)
        wrong_source = bytearray(self.source)
        wrong_source[0x400] ^= 1
        with self.assertRaises(ValueError):
            verify(bytes(wrong_source), self.image)

    def test_capacity_is_part_of_the_exact_image_contract(self):
        tiny, _ = stage.build(self.source, capacity=4)
        self.assertEqual(verify(self.source, tiny, capacity=4)['capacity'], 4)
        with self.assertRaises(ValueError):
            verify(self.source, tiny)
        for value in (True, 0, -1, None):
            with self.subTest(capacity=value), self.assertRaises(ValueError):
                stage.build(self.source, capacity=value)


if __name__ == '__main__':
    unittest.main()
