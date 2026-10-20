"""Saved-image checks for the separate raw row-journal build, no player."""
import hashlib
import unittest

import build_reveal_lineage_rows_stage as stage
from verify_reveal_lineage_rows_stage import verify
from test_folderfollow_reveal_static_contract import SOURCE


class LineageRowsVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SOURCE.read_bytes()
        cls.image, cls.meta = stage.build(cls.source)

    def test_exact_reference_and_normalized_source(self):
        result = verify(self.source, self.image)
        golden, _ = stage.normalize_source(self.source)
        self.assertEqual(verify(golden, self.image)['sha256'], result['sha256'])
        self.assertEqual(sorted(result['external_calls']), [0x5C31C0, 0x6F7CA0])
        self.assertEqual(len(result['indirect_append_calls']), 1)
        self.assertFalse(result['autoscroll'])
        self.assertEqual(result['row_buffer'], result['buffer'] + result['lineage_bytes'])

    def test_all_patch_and_payload_classes_are_exact(self):
        offsets = (0x300, self.meta['memsize_offset'], self.meta['phdr_offset'],
                   0x6ED6E8 - stage.BASE, 0x6ED704 - stage.BASE, 0x6ED7D4 - stage.BASE,
                   0x48F3BC - stage.BASE, 0x48F1B4 - stage.BASE, len(self.source),
                   self.meta['code_offset'], len(self.image) - 1)
        for offset in offsets:
            with self.subTest(offset=hex(offset)):
                changed = bytearray(self.image)
                changed[offset] ^= 1
                with self.assertRaises(ValueError):
                    verify(self.source, bytes(changed))
        for changed in (self.image[:-1], self.image + b'\0'):
            with self.assertRaises(ValueError):
                verify(self.source, changed)

    def test_both_capacities_are_bound_into_saved_image(self):
        tiny, _ = stage.build(self.source, capacity=4, row_capacity=7)
        self.assertEqual(verify(self.source, tiny, capacity=4, row_capacity=7)['row_capacity'], 7)
        for kwargs in ({}, {'capacity': 4}, {'row_capacity': 7}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                verify(self.source, tiny, **kwargs)

    def test_unknown_sources_active_modes_and_bad_bounds_are_refused(self):
        source = bytearray(self.source)
        source[0x400] ^= 1
        for bad in (bytes(source), self.image, self.source[:-1]):
            with self.assertRaises(ValueError):
                stage.build(bad)
        for flag in (True, 1, 0, None, 'yes'):
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                stage.build(self.source, enable_reveal=flag)
        for value in (True, 0, -1, None):
            for name in ('capacity', 'row_capacity'):
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    stage.build(self.source, **{name: value})

    def test_previous_lineage_only_build_is_unchanged(self):
        previous, _ = stage.lineage.build(self.source)
        self.assertEqual(hashlib.sha256(previous).hexdigest(),
                         'f31239aa544c55959e9f75686a421489c8ea6d91e1ef6d30b01955d8c75ec139')


if __name__ == '__main__':
    unittest.main()
