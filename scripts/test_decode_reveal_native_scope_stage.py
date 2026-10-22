#!/usr/bin/env python3
"""Independent combined-format checks using executed integration snapshots.

Native function bodies are harness stubs. No copied history, including a
quiet scope table, establishes coherent native capture, ownership or UI
permission. Capacities are an explicit out-of-band format contract.
"""

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
import struct
import unittest
from unittest.mock import patch

import decode_reveal_native_scope_stage as decoder
import decode_reveal_native_scope as scope
import test_reveal_native_scope_stage as integration


CAPACITIES = dict(capacity=16, row_capacity=16, operation_capacity=16,
                  scope_capacity=16)


def word(data, offset, value):
    changed = bytearray(data)
    struct.pack_into('<I', changed, offset, value)
    return bytes(changed)


class DecodeRevealNativeScopeStageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Reuse fixture helpers without inheriting/rerunning their TestCase.
        fixture_class = integration.RevealNativeScopeStageTests
        fixture_class.setUpClass()
        cls.fixture = fixture_class('test_fresh_closed_scope_then_sequence_is_only_historical_evidence')
        machine, _, _ = cls.fixture.sequence()
        cls.fresh = machine.snapshot()
        cls.scope_offset = machine.meta['scope_buffer'] - machine.meta['buffer']
        cls.row_offset = machine.meta['row_buffer'] - machine.meta['buffer']
        cls.revision_offset = (machine.meta['contents_revision_buffer']
                               - machine.meta['buffer'])
        cls.operation_offset = machine.meta['operation_buffer'] - machine.meta['buffer']

    def decode(self, data=None, **capacities):
        options = dict(CAPACITIES)
        options.update(capacities)
        return decoder.decode(self.fresh if data is None else data, **options)

    def assert_no_authority(self, result):
        for field in scope.AUTHORITY_FLAGS:
            self.assertIs(result[field], False, field)

    def open_snapshot(self):
        machine, _, _ = self.fixture.sequence()
        self.fixture.begin(machine)
        return machine.snapshot()

    def scope_word(self, data, field, value, *, ticket=1):
        offset = (self.scope_offset + scope.HEADER + (ticket - 1) * scope.RECORD
                  + scope.FIELDS.index(field) * 4)
        return word(data, offset, value)

    def test_fresh_executed_sequence_is_quiet_historical_not_live_authority(self):
        result = self.decode()
        self.assertEqual(result['format'], 'lineage-rows-native-scope-v1')
        self.assertEqual(result['format'], decoder.FORMAT)
        self.assertTrue(result['scope_quiet'])
        self.assertTrue(result['native_scope']['scope_quiet'])
        self.assertEqual(result['native_scope']['issued'], 0)
        operation, window = result['operations'][0], result['windows'][0]
        self.assertTrue(operation['original_frontier_matches'])
        self.assertTrue(operation['observed_callback_sequence_complete_before_scope'])
        self.assertTrue(operation['observed_callback_sequence_complete'])
        self.assertTrue(operation['observed_row_window_complete'])
        self.assertTrue(window['observed_window_complete'])
        self.assertFalse(window['complete_before_scope'])
        self.assertFalse(window['complete'])
        self.assertIn('known-contents-boundary', window['reasons'])
        for output in (result, result['native_scope'], operation, window):
            self.assert_no_authority(output)
        for forbidden in ('CompletedRows', 'ready_rows', 'owner_lease', 'scope_success'):
            self.assertNotIn(forbidden, result)

    def test_closed_native_reset_then_new_sequence_is_not_promoted_to_success(self):
        machine = self.fixture.machine()
        self.fixture.begin(machine)
        self.fixture.end(machine, result=0xFFFFFFFF)
        machine, _, _ = self.fixture.sequence(machine)
        result = self.decode(machine.snapshot())
        self.assertTrue(result['scope_quiet'])
        self.assertEqual(result['native_scope']['closed_count'], 1)
        self.assertEqual(result['native_scope']['records'][0]['actual_result_signed'], -1)
        self.assertTrue(result['operations'][0]['observed_callback_sequence_complete'])
        self.assertFalse(result['windows'][0]['complete'])
        self.assert_no_authority(result)

    def test_open_scope_narrows_both_operation_completeness_fields(self):
        result = self.decode(self.open_snapshot())
        operation, window = result['operations'][0], result['windows'][0]
        self.assertFalse(result['scope_quiet'])
        self.assertEqual(result['native_scope']['open_count'], 1)
        self.assertTrue(operation['observed_callback_sequence_complete_before_scope'])
        self.assertTrue(operation['observed_row_window_complete_before_scope'])
        self.assertFalse(operation['observed_callback_sequence_complete'])
        self.assertFalse(operation['observed_row_window_complete'])
        self.assertFalse(window['complete'])
        self.assertTrue(window['observed_window_complete'])
        self.assertIn('native-scope-not-quiet', operation['reasons'])
        self.assertIn('native-scope-not-quiet', window['reasons'])
        self.assert_no_authority(result)

    def test_issued_unpublished_gap_is_not_mistaken_for_empty_guard(self):
        for active in (0, 1):
            with self.subTest(active=active):
                data = word(self.fresh, self.scope_offset, 1 | active << 16)
                # This may be a partially filled reservation, not a valid
                # published kind/frame/status. Unknown words remain unknown.
                data = self.scope_word(data, 'kind', 99)
                data = self.scope_word(data, 'frame', 3)
                data = self.scope_word(data, 'status', 99)
                result = self.decode(data)
                self.assertFalse(result['scope_quiet'])
                self.assertEqual(result['native_scope']['unpublished_count'], 1)
                self.assertIn('native-scope-unpublished', result['native_scope']['reasons'])
                self.assertFalse(result['operations'][0]['observed_callback_sequence_complete'])

    def test_midclose_result_and_published_closed_count_lag_are_incomplete(self):
        data = self.open_snapshot()
        closing = self.scope_word(data, 'status', scope.CLOSING)
        closing = self.scope_word(closing, 'actual_result', 0x87654321)
        result = self.decode(closing)
        self.assertEqual(result['native_scope']['closing_count'], 1)
        self.assertFalse(result['scope_quiet'])
        self.assertIn('native-scope-closing', result['native_scope']['reasons'])
        closed = self.scope_word(closing, 'status', scope.CLOSED)
        result = self.decode(closed)
        self.assertFalse(result['native_scope']['counter_matches_records'])
        self.assertFalse(result['scope_quiet'])
        self.assertIn('native-scope-count-mismatch', result['native_scope']['reasons'])

    def test_fault_highbit_reserved_and_unissued_data_are_rejected(self):
        candidates = [word(self.fresh, self.scope_offset, state)
                      for state in (scope.FAULT, 0x80000000, 0x80000001)]
        candidates += [word(self.fresh, self.scope_offset + offset, 1)
                       for offset in (4, 8, 12)]
        candidates += [self.scope_word(self.fresh, field, 1, ticket=16)
                       for field in scope.FIELDS]
        for data in candidates:
            with self.subTest(tail=data[self.scope_offset:self.scope_offset + 16]), \
                    self.assertRaises(ValueError):
                self.decode(data)

    def test_published_scope_corruption_preserves_strict_validation(self):
        data = self.open_snapshot()
        for field, value in (('magic', 1), ('kind', 0), ('ticket', 2),
                             ('frame', 3), ('status', 4), ('actual_result', 1)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.decode(self.scope_word(data, field, value))

    def test_base_prefix_corruption_is_not_masked_by_quiet_scope(self):
        candidates = [word(self.fresh, 0, 0xFFFFFFFF),
                      word(self.fresh, 16, 0),
                      word(self.fresh, self.row_offset, 0xFFFFFFFF),
                      word(self.fresh, self.row_offset + 16, 0),
                      word(self.fresh, self.revision_offset, 0xFFFFFFFF),
                      word(self.fresh, self.operation_offset + 16, 0)]
        for data in candidates:
            with self.assertRaises(ValueError):
                self.decode(data)

    def test_exact_bytes_bytearray_memoryview_and_input_immutability(self):
        expected = self.decode()
        for kind in (bytes, bytearray, memoryview):
            with self.subTest(kind=kind):
                owned = bytearray(self.fresh)
                before = bytes(owned)
                result = self.decode(kind(owned))
                self.assertEqual(result, expected)
                result['native_scope']['limitations'].append('output only')
                result['operations'][0]['reasons'].append('output only')
                result['windows'][0]['rows'][0]['path'] = 'output only'
                self.assertEqual(bytes(owned), before)
                self.assertNotIn('output only', self.decode()['limitations'])

    def test_sizes_and_nonbuffer_types_are_refused(self):
        for data in (self.fresh[:-1], self.fresh + b'\0', self.fresh[:self.scope_offset],
                     b'', '', 1, [], None):
            with self.subTest(kind=type(data)), self.assertRaises(ValueError):
                decoder.decode(data, **CAPACITIES)

    def test_individually_mismatched_and_invalid_capacities_are_refused(self):
        for field in CAPACITIES:
            for value in (15, 17, 0, -1, True, False, 1.5, None):
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    self.decode(**{field: value})
        with self.assertRaises(ValueError):
            self.decode(scope_capacity=65536)

    def test_previous_origin_frontier_format_refuses_the_extended_buffer(self):
        options = {key: value for key, value in CAPACITIES.items() if key != 'scope_capacity'}
        with self.assertRaises(ValueError):
            decoder.previous.decode(self.fresh, **options)
        prefix = self.fresh[:self.scope_offset]
        previous = decoder.previous.decode(prefix, **options)
        self.assertTrue(previous['operations'][0]['observed_callback_sequence_complete'])
        with self.assertRaises(ValueError):
            self.decode(prefix)

    def test_quiet_scope_never_repairs_prior_frontier_rejection(self):
        # A zero original-entry mark remains unknown even with fully observed
        # callbacks and a quiet scope table. No new native reads are needed.
        data = word(self.fresh, 16 + 60, 0)
        result = self.decode(data)
        operation, window = result['operations'][0], result['windows'][0]
        self.assertTrue(result['scope_quiet'])
        self.assertFalse(operation['original_frontier_matches'])
        self.assertFalse(operation['observed_callback_sequence_complete_before_scope'])
        self.assertFalse(operation['observed_callback_sequence_complete'])
        self.assertFalse(window['complete_before_scope'])
        self.assertFalse(window['complete'])
        self.assertIn('original-entry-frontier-mismatch', operation['reasons'])
        self.assertIn('known-contents-boundary', window['reasons'])
        self.assert_no_authority(result)

    def test_actual_report_retains_scope_limits_and_no_positive_authority_flags(self):
        result = self.decode()
        text = ' '.join(result['limitations'])
        for limitation in ('diagnostic exclusion', 'complete writer coverage',
                           'function return', 'capture coherence', 'UI/playback request'):
            self.assertIn(limitation, text)
        for output in (result, result['native_scope'], *result['operations'], *result['windows']):
            self.assert_no_authority(output)

    def test_cli_decodes_only_supplied_local_owned_bytes(self):
        args = ['snapshot.bin']
        for key, value in CAPACITIES.items():
            args.extend(['--' + key.replace('_', '-'), str(value)])
        output = StringIO()
        with patch.object(decoder.Path, 'read_bytes', return_value=self.fresh) as reader:
            with redirect_stdout(output):
                decoder.main(args)
            reader.assert_called_once_with()
        result = json.loads(output.getvalue())
        self.assertEqual(result['format'], decoder.FORMAT)
        self.assertTrue(result['scope_quiet'])
        self.assert_no_authority(result)
        for failure in (b'bad', OSError('unavailable')):
            kwargs = dict(side_effect=failure) if isinstance(failure, OSError) else dict(return_value=failure)
            with patch.object(decoder.Path, 'read_bytes', **kwargs):
                with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as error:
                    decoder.main(args)
                self.assertEqual(error.exception.code, 2)


if __name__ == '__main__':
    unittest.main()
