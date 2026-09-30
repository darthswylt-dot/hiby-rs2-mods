"""Read-only captured-run report checks; no hardware simulation or deployment."""
import tempfile
import unittest
from pathlib import Path

import diagnose_move_diag_reboot as d


ROOT = Path(__file__).resolve().parents[1] / 'artifacts'
AVAILABLE = all((ROOT / name).exists() for _, name, _ in d.CAPTURES)


class Tests(unittest.TestCase):
    @unittest.skipUnless(AVAILABLE, 'recorded captures not available')
    def test_recorded_run_and_copy_footprint(self):
        report = d.analyze(ROOT)
        self.assertTrue(report['all_checkpoints_are_exact_byte_prefixes'])
        self.assertEqual([r['events'] for r in report['checkpoints']], [0, 5, 21, 21, 21])
        self.assertEqual(report['final_status']['reserved'], 21)
        self.assertEqual(report['final_status']['drained'], 21)
        self.assertEqual(report['stationary_tail']['samples'], 468)
        self.assertEqual(report['stationary_tail']['cue_brackets'], [4, 4])
        self.assertEqual(report['stationary_tail']['scroll_y'], 0)
        self.assertAlmostEqual(report['stationary_tail']['duration_seconds'], 59.744035839)
        self.assertEqual(report['checkpoint_copy_footprint_if_retained']['logical_bytes'], 21543680)
        self.assertEqual(report['checkpoint_copy_footprint_if_retained']['rounded_bytes_assuming_4k_pages'], 21553152)
        self.assertEqual(report['largest_snapshot_gap']['from_tick'], 47)
        self.assertEqual(report['largest_snapshot_gap']['to_tick'], 48)
        self.assertTrue(all(0.127 < n < 0.129 for n in report['last_ten_snapshot_intervals_seconds']))

    def test_hash_gate(self):
        # Temporary fixture only; real captures are never changed.
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'fixture.bin'
            path.write_bytes(b'not a recorded capture')
            with self.assertRaises(ValueError):
                d.checked_bytes(path, d.CAPTURES[-1][2])

    def test_timestamp_rejects_invalid_nanos(self):
        with self.assertRaises(ValueError):
            d.ns({'time': (1, 1_000_000_000)})
        self.assertEqual(d.ns({'time': (1, 7)}), 1_000_000_007)


if __name__ == '__main__':
    unittest.main()
