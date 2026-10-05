"""Local compatibility-run tests; all ADB calls are replaced with canned data."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import check_legacy_adb_transport as compatibility


NONCE = '0123456789abcdef0123456789abcdef'
PID = 116
ALL_BYTES = bytes(range(256)) + b'\0\r\n\xffA\nB\r\nZ'


def process_stat(start=349):
    fields = ['S'] + ['0'] * 18 + [str(start)]
    return f'{PID} (system main) ' + ' '.join(fields)


def stock_state(reference, nonce=NONCE):
    digest = hashlib.sha256(reference).hexdigest()
    return {
        'boot': 'd20f9fb3-9038-445a-961b-02f1cd17f03b',
        'stat': process_stat(),
        'exe': f'{compatibility.STOCK}  /proc/{PID}/exe',
        'flag': 'absent',
        'installed': 'a' * 64 + '  /ui_data/player\n' + 'b' * 64 + '  /data/hiby_player_sortfix',
        'closed_log': digest + '  ' + compatibility.CLOSED_LOG,
        'log_identity': f'142 -rwxr-xr-x 1 0 0 {len(reference)} Sep 30 12:00 {compatibility.CLOSED_LOG}',
        'meminfo': 'MemTotal: 58308 kB\nMemFree: 904 kB',
        'status': f'Name:\tsystem_main_thr\nPid:\t{PID}\nVmRSS:\t19088 kB',
        'done_' + nonce: '0',
    }


def state_bytes(state):
    return ''.join(f'\r\r\n@@{key}@@\r\r\n{value}\r\r\n' for key, value in state.items()).encode('ascii')


def result(data=b'', **overrides):
    value = dict(returncode=0, host_returncode=0, timed_out=False, overlong=False,
                 stderr_overlong=False, reader_errors=[], bytes=len(data),
                 encoding_valid=True, remote_returncode=0)
    value.update(overrides)
    return value


class CannedAdb:
    def __init__(self, reference):
        self.reference = reference
        self.probes = []
        self.streams = []
        self.states = {'before': stock_state(reference), 'after': stock_state(reference)}
        self.probe_overrides = {}
        self.stream_overrides = {}
        self.stream_data = {}
        self.probe_exceptions = {}
        self.stream_exceptions = {}

    def probe(self, script, output, timeout):
        label = output.stem
        self.probes.append((label, script, timeout))
        if label in self.probe_exceptions:
            raise self.probe_exceptions[label]
        state = self.states[label]
        data = state if isinstance(state, bytes) else state_bytes(state)
        output.write_bytes(data)
        return result(data, **self.probe_overrides.get(label, {}))

    def stream(self, script, output, size, timeout):
        label = output.stem
        self.streams.append((label, script, size, timeout))
        if label in self.stream_exceptions:
            raise self.stream_exceptions[label]
        data = self.stream_data.get(label, {
            'all_bytes': ALL_BYTES, 'remote_failure': b'',
            'closed_prefix': self.reference[:65536],
        }[label])
        output.write_bytes(data)
        override = {'returncode': 37, 'remote_returncode': 37} if label == 'remote_failure' else {}
        override.update(self.stream_overrides.get(label, {}))
        return result(data, **override)


class Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='legacy-compatibility-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.reference = bytes(range(256)) * 260 + b'closed reference tail'
        self.reference_path = self.root / 'reference.bin'
        self.reference_path.write_bytes(self.reference)
        self.fake = CannedAdb(self.reference)
        self.factory = self.enterContext(patch.object(compatibility, 'LegacyAdb', return_value=self.fake))
        self.enterContext(patch.object(compatibility, 'REFERENCE', hashlib.sha256(self.reference).hexdigest()))
        self.enterContext(patch.object(compatibility.secrets, 'token_hex', return_value=NONCE))
        self.count = 0

    def run_check(self):
        self.count += 1
        output = self.root / f'evidence-{self.count}'
        report = compatibility.check('unused-adb', 'HiBy RS2', PID, self.reference_path, output)
        self.assertEqual(json.loads((output / 'report.json').read_text()), report)
        return report, output

    def assert_failed_preserved(self, report, output):
        self.assertFalse(report['compatibility_passed'])
        self.assertFalse(report['live_move_validated'])
        self.assertTrue(report['errors'])
        self.assertTrue((output / 'after.txt').exists())
        self.assertEqual(self.fake.probes[-1][0], 'after')

    def test_exact_controls_and_stable_stock_pass_without_live_claim(self):
        report, output = self.run_check()
        self.assertTrue(report['compatibility_passed'])
        self.assertTrue(report['stock_state_preserved'])
        self.assertFalse(report['live_move_validated'])
        self.assertEqual(report['errors'], [])
        self.factory.assert_called_once_with('unused-adb', 'HiBy RS2', NONCE)
        self.assertEqual([p[0] for p in self.fake.probes], ['before', 'after'])
        self.assertEqual([s[0] for s in self.fake.streams], ['all_bytes', 'remote_failure', 'closed_prefix'])
        self.assertEqual([s[2] for s in self.fake.streams], [len(ALL_BYTES), 0, 65536])
        self.assertEqual((output / 'all_bytes.bin').read_bytes(), ALL_BYTES)
        self.assertEqual((output / 'closed_prefix.bin').read_bytes(), self.reference[:65536])
        self.assertEqual(report['remote_failure']['remote_returncode'], 37)
        self.assertEqual(report['closed_prefix_sha256'], hashlib.sha256(self.reference[:65536]).hexdigest())
        for _, script, _, _ in self.fake.streams:
            self.assertIn(f'@@{NONCE}:BEGIN@@', script)
            self.assertIn(f'@@{NONCE}:END:%s@@', script)

    def test_bad_reference_does_not_create_output_or_transport(self):
        self.reference_path.write_bytes(b'wrong reference')
        output = self.root / 'never-created'
        with self.assertRaisesRegex(ValueError, 'wrong local reference'):
            compatibility.check('unused-adb', 'HiBy RS2', PID, self.reference_path, output)
        self.factory.assert_not_called()
        self.assertFalse(output.exists())

    def test_existing_output_is_not_overwritten_or_contacted(self):
        output = self.root / 'existing'
        output.mkdir()
        sentinel = output / 'report.json'
        sentinel.write_bytes(b'existing evidence')
        with self.assertRaises(FileExistsError):
            compatibility.check('unused-adb', 'HiBy RS2', PID, self.reference_path, output)
        self.factory.assert_not_called()
        self.assertEqual(sentinel.read_bytes(), b'existing evidence')

    def test_stream_safety_flags_fail_even_with_correct_bytes_and_zero_rc(self):
        cases = [dict(timed_out=True), dict(overlong=True), dict(stderr_overlong=True),
                 dict(reader_errors=['pipe failure']), dict(encoding_valid=False),
                 dict(bytes=len(ALL_BYTES) - 1), dict(returncode=1), dict(remote_returncode=1)]
        for change in cases:
            with self.subTest(change=change):
                self.fake.stream_overrides = {'all_bytes': change}
                report, output = self.run_check()
                self.assert_failed_preserved(report, output)
                self.assertEqual((output / 'all_bytes.bin').read_bytes(), ALL_BYTES)

    def test_wrong_bytes_fail_and_remain_on_host(self):
        self.fake.stream_data['all_bytes'] = b'\xff' + ALL_BYTES[1:]
        report, output = self.run_check()
        self.assert_failed_preserved(report, output)
        self.assertEqual((output / 'all_bytes.bin').read_bytes(), b'\xff' + ALL_BYTES[1:])

    def test_remote_failure_control_requires_effective_error_and_exact_status(self):
        for change in ({'returncode': 0}, {'returncode': 1}, {'remote_returncode': 0},
                       {'remote_returncode': 36}, {'remote_returncode': None},
                       {'host_returncode': 1}, {'host_returncode': None}):
            with self.subTest(change=change):
                self.fake.stream_overrides = {'remote_failure': change}
                report, output = self.run_check()
                self.assert_failed_preserved(report, output)
                self.assertIn('nonzero remote status', report['errors'][0])

    def test_before_transport_flags_fail_and_still_capture_after(self):
        for change in (dict(timed_out=True), dict(overlong=True), dict(stderr_overlong=True),
                       dict(reader_errors=['failure']), dict(returncode=1)):
            with self.subTest(change=change):
                self.fake.probe_overrides = {'before': change}
                report, output = self.run_check()
                self.assert_failed_preserved(report, output)
                self.assertFalse(report['stock_state_preserved'])

    def test_malformed_before_metadata_fails_closed(self):
        original = state_bytes(stock_state(self.reference))
        cases = [original.replace(f'@@done_{NONCE}@@'.encode(), b'@@unknown@@'),
                 original + b'\n@@boot@@\nrepeated\n',
                 original.replace(b'349', b'bad', 1),
                 original.replace(b'absent', b'present', 1),
                 original.replace(compatibility.STOCK.encode(), b'0' * 64, 1),
                 original.replace(hashlib.sha256(self.reference).hexdigest().encode(), b'0' * 64, 1),
                 original.replace(b'\r\r\n@@stat@@', b'\r\r\n@@missing_stat@@', 1),
                 b'\xff' + original]
        for data in cases:
            with self.subTest(data=data[:100]):
                self.fake.states['before'] = data
                report, output = self.run_check()
                self.assert_failed_preserved(report, output)
                self.assertEqual((output / 'before.txt').read_bytes(), data)

    def test_changed_stable_state_is_rejected(self):
        changes = {'boot': '12345678-1234-1234-1234-123456789abc', 'stat': process_stat(350),
                   'installed': 'c' * 64 + '  /ui_data/player\n' + 'b' * 64 + '  /data/hiby_player_sortfix',
                   'log_identity': stock_state(self.reference)['log_identity'].replace('142 ', '143 ', 1)}
        for key, value in changes.items():
            with self.subTest(key=key):
                self.fake.states['after'] = stock_state(self.reference)
                self.fake.states['after'][key] = value
                report, output = self.run_check()
                self.assert_failed_preserved(report, output)
                self.assertFalse(report['stock_state_preserved'])

    def test_identically_malformed_evidence_cannot_count_as_stable(self):
        changes = {'boot': '', 'installed': 'invalid hash evidence',
                   'meminfo': 'MemFree: 904 kB', 'status': 'Pid: 117'}
        for key, value in changes.items():
            with self.subTest(key=key):
                self.fake.states = {'before': stock_state(self.reference), 'after': stock_state(self.reference)}
                self.fake.states['before'][key] = value
                self.fake.states['after'][key] = value
                report, output = self.run_check()
                self.assert_failed_preserved(report, output)

    def test_extra_and_missing_sections_fail_closed(self):
        for missing in (True, False):
            with self.subTest(missing=missing):
                self.fake.states['before'] = stock_state(self.reference)
                if missing:
                    del self.fake.states['before']['meminfo']
                else:
                    self.fake.states['before']['unexpected'] = 'value'
                report, output = self.run_check()
                self.assert_failed_preserved(report, output)

    def test_installed_hash_evidence_requires_exact_two_ordered_paths(self):
        first = 'a' * 64 + '  /ui_data/player'
        second = 'b' * 64 + '  /data/hiby_player_sortfix'
        for installed in (second + '\n' + first, first, first + '\n' + second + '\n' + first,
                          first + '\n' + second.replace('/data/', '/other/'),
                          first.replace('a', 'g', 1) + '\n' + second):
            with self.subTest(installed=installed):
                self.fake.states['before']['installed'] = installed
                report, output = self.run_check()
                self.assert_failed_preserved(report, output)

    def test_volatile_memory_and_stat_fields_may_change(self):
        self.fake.states['after']['meminfo'] = 'MemTotal: 58308 kB\nMemFree: 800 kB'
        self.fake.states['after']['status'] = f'Name:\tsystem_main_thr\nPid:\t{PID}\nVmRSS:\t20000 kB'
        self.fake.states['after']['stat'] = process_stat().replace(') S ', ') R ', 1)
        report, _ = self.run_check()
        self.assertTrue(report['compatibility_passed'])

    def test_stream_exception_preserves_report_and_after_state(self):
        self.fake.stream_exceptions['closed_prefix'] = OSError('simulated transfer exception')
        report, output = self.run_check()
        self.assert_failed_preserved(report, output)
        self.assertIn('simulated transfer exception', report['errors'][0])
        self.assertTrue((output / 'all_bytes.bin').exists())

    def test_after_failure_cannot_pass_and_report_is_written(self):
        self.fake.probe_overrides['after'] = dict(timed_out=True)
        report, output = self.run_check()
        self.assert_failed_preserved(report, output)
        self.assertIn('after state:', report['errors'][0])

    def test_closed_log_size_mismatch_prevents_prefix_read(self):
        self.fake.states['before']['log_identity'] = self.fake.states['before']['log_identity'].replace(
            str(len(self.reference)), str(len(self.reference) + 1), 1)
        report, output = self.run_check()
        self.assert_failed_preserved(report, output)
        self.assertIn('closed log size mismatch', report['errors'][0])
        self.assertNotIn('closed_prefix', [s[0] for s in self.fake.streams])


if __name__ == '__main__':
    unittest.main()
