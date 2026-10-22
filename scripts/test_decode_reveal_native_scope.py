#!/usr/bin/env python3
"""Private scope exclusion fixtures; no quiet state grants UI authority."""

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from io import StringIO
import json
import struct
import unittest
from unittest.mock import patch

import decode_reveal_native_scope as decoder
import decode_reveal_origin_frontier as frontier
import test_decode_reveal_origin_frontier as fixtures


CAPACITY = 8


def scope(*, kind=decoder.RESET, ticket=1, frame=0x7FFF1000,
          rawarg0=0x90000000, rawarg1=0x90002000,
          status=decoder.CLOSED, actual_result=0, magic=decoder.MAGIC):
    return dict(magic=magic, kind=kind, ticket=ticket, frame=frame,
                rawarg0=rawarg0, rawarg1=rawarg1, status=status,
                actual_result=actual_result)


def snapshot(records=(), *, issued=None, active=None, state=None, capacity=CAPACITY):
    if issued is None:
        issued = len(records)
    if active is None:
        active = sum(item['status'] in (decoder.OPEN, decoder.CLOSING) for item in records)
    if state is None:
        state = issued | active << 16
    data = bytearray(decoder.memory_bytes(capacity))
    struct.pack_into('<I', data, 0, state)
    for index, item in enumerate(records):
        struct.pack_into('<8I', data, decoder.HEADER + index * decoder.RECORD,
                         *(item[field] for field in decoder.FIELDS))
    return bytes(data)


def word(data, offset, value):
    changed = bytearray(data)
    struct.pack_into('<I', changed, offset, value)
    return bytes(changed)


def record_word(data, ticket, field, value):
    return word(data, decoder.HEADER + (ticket - 1) * decoder.RECORD
                + decoder.FIELDS.index(field) * 4, value)


def decode(data=None):
    return decoder.decode_snapshot(snapshot() if data is None else data, capacity=CAPACITY)


def prior_frontier(**kwargs):
    return frontier.decode(fixtures.snapshot(**kwargs), capacity=fixtures.CAPACITY,
                           row_capacity=fixtures.ROW_CAPACITY,
                           operation_capacity=fixtures.OPERATION_CAPACITY)


class DecodeRevealNativeScopeTests(unittest.TestCase):
    def assert_no_authority(self, result):
        for field in decoder.AUTHORITY_FLAGS:
            self.assertIs(result[field], False, field)

    def test_empty_guard_is_only_diagnostic_quiet(self):
        result = decode()
        self.assertEqual(result['format'], 'native-scope-observation-v1')
        self.assertTrue(result['scope_quiet'])
        self.assertEqual(result['records'], [])
        self.assertEqual(result['reasons'], [])
        self.assertTrue(result['counter_matches_records'])
        self.assert_no_authority(result)
        self.assertIn('complete writer coverage', ' '.join(result['limitations']))
        self.assertIn('empty guard', ' '.join(result['limitations']))

    def test_both_closed_kinds_and_arbitrary_returns_are_not_success_claims(self):
        records = [scope(actual_result=0xFFFFFFFF),
                   scope(kind=decoder.RECONCILE, ticket=2, actual_result=0x90002000)]
        result = decode(snapshot(records))
        self.assertTrue(result['scope_quiet'])
        self.assertEqual(result['closed_count'], 2)
        self.assertEqual(result['published_count'], 2)
        self.assertEqual(result['records'][0]['actual_result'], 0xFFFFFFFF)
        self.assertEqual(result['records'][0]['actual_result_signed'], -1)
        self.assert_no_authority(result)
        self.assertNotIn('success', result)

    def test_open_scope_stays_nonquiet_even_with_matching_count(self):
        result = decode(snapshot([scope(status=decoder.OPEN)]))
        self.assertFalse(result['scope_quiet'])
        self.assertTrue(result['counter_matches_records'])
        self.assertEqual(result['open_count'], 1)
        self.assertIn('native-scope-active', result['reasons'])
        self.assert_no_authority(result)

    def test_closing_is_incomplete_with_zero_or_actual_midclose_result(self):
        for actual in (0, 1, 0xFFFFFFFF, 0x90002000):
            with self.subTest(actual=actual):
                result = decode(snapshot([scope(status=decoder.CLOSING,
                                                actual_result=actual)]))
                self.assertFalse(result['scope_quiet'])
                self.assertEqual(result['closing_count'], 1)
                self.assertTrue(result['counter_matches_records'])
                self.assertIn('native-scope-closing', result['reasons'])

    def test_unpublished_issued_slots_never_disappear_from_guard(self):
        for active in (0, 1):
            for transient in (scope(magic=0),
                              dict(zip(decoder.FIELDS, (0, 99, 0xFFFFFFFF, 3,
                                                       0xFFFFFFFF, 7, 99, 8)))):
                with self.subTest(active=active, transient=transient):
                    result = decode(snapshot([transient], active=active))
                    self.assertFalse(result['scope_quiet'])
                    self.assertEqual(result['unpublished_count'], 1)
                    self.assertEqual(result['records'], [dict(ticket=1, published=False)])
                    self.assertIn('native-scope-unpublished', result['reasons'])
        zero = decode(snapshot(issued=1, active=1))
        self.assertEqual(zero['unpublished_count'], 1)
        self.assertFalse(zero['scope_quiet'])

    def test_published_after_an_unpublished_gap_is_retained_but_incomplete(self):
        result = decode(snapshot([scope(magic=0), scope(ticket=2)]))
        self.assertEqual(result['records'][1]['ticket'], 2)
        self.assertEqual(result['closed_count'], 1)
        self.assertFalse(result['scope_quiet'])

    def test_closed_before_counter_decrement_is_incomplete_not_malformed(self):
        result = decode(snapshot([scope()], active=1))
        self.assertEqual(result['closed_count'], 1)
        self.assertFalse(result['counter_matches_records'])
        self.assertFalse(result['scope_quiet'])
        self.assertIn('native-scope-count-mismatch', result['reasons'])

    def test_all_count_disagreements_are_conservative_incomplete(self):
        candidates = [snapshot([scope(status=decoder.OPEN)], active=0),
                      snapshot([scope(status=decoder.CLOSING)], active=0),
                      snapshot(active=1), snapshot([scope()], active=0x7FFF)]
        for data in candidates:
            with self.subTest(state=struct.unpack_from('<I', data)[0]):
                result = decode(data)
                self.assertFalse(result['counter_matches_records'])
                self.assertFalse(result['scope_quiet'])
                self.assertIn('native-scope-count-mismatch', result['reasons'])

    def test_nested_and_overlapping_records_do_not_alias_raw_addresses(self):
        records = [scope(ticket=1), scope(ticket=2, status=decoder.OPEN),
                   scope(ticket=3, kind=decoder.RECONCILE)]
        result = decode(snapshot(records))
        self.assertEqual([item['ticket'] for item in result['records']], [1, 2, 3])
        self.assertEqual(result['closed_count'], 2)
        self.assertEqual(result['open_count'], 1)
        self.assertFalse(result['scope_quiet'])

    def test_malformed_published_identity_and_status_are_rejected(self):
        data = snapshot([scope()])
        for field, values in [('magic', (1, 0xFFFFFFFF)), ('kind', (0, 3, 0xFFFFFFFF)),
                              ('ticket', (0, 2, 0xFFFFFFFF)),
                              ('frame', (0, 1, 2, 3, 0xFFFFFFFF)),
                              ('status', (0, 4, 0xFFFFFFFF))]:
            for value in values:
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    decode(record_word(data, 1, field, value))
        with self.assertRaisesRegex(ValueError, 'result in an open'):
            decode(snapshot([scope(status=decoder.OPEN, actual_result=1)]))

    def test_terminal_fault_and_other_highbit_states_are_rejected(self):
        for state in (0xFFFFFFFF, 0x80000000, 0x80000001, 0xFFFE0001):
            with self.subTest(state=state), self.assertRaises(ValueError):
                decode(snapshot(state=state))

    def test_reserved_header_and_nonzero_unissued_tails_are_rejected(self):
        data = snapshot([scope()])
        for offset in (4, 8, 12):
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                decode(word(data, offset, 1))
        for ticket in (2, CAPACITY):
            for field in decoder.FIELDS:
                with self.subTest(ticket=ticket, field=field), self.assertRaises(ValueError):
                    decode(record_word(data, ticket, field, 1))

    def test_exact_buffers_capacities_and_issued_bounds_are_required(self):
        for data in (b'', snapshot()[:-1], snapshot() + b'\0', '', 1, [], None):
            with self.subTest(data_type=type(data)), self.assertRaises(ValueError):
                decoder.decode_snapshot(data, capacity=CAPACITY)
        for capacity in (True, False, 0, -1, 1.0, '1', 65536, 1 << 32):
            with self.subTest(capacity=capacity), self.assertRaises(ValueError):
                decoder.decode_snapshot(snapshot(), capacity=capacity)
        with self.assertRaisesRegex(ValueError, 'exceeds capacity'):
            decode(snapshot(issued=CAPACITY + 1, active=0))
        self.assertEqual(decoder.memory_bytes(65535), 16 + 32 * 65535)
        self.assertTrue(decoder.decode_snapshot(snapshot(capacity=1), capacity=1)['scope_quiet'])

    def test_input_and_decoded_record_mutation_are_independent(self):
        original = bytearray(snapshot([scope()]))
        before = bytes(original)
        result = decoder.decode_snapshot(memoryview(original), capacity=CAPACITY)
        result['records'][0]['rawarg0'] = 0
        result['limitations'].append('output only')
        self.assertEqual(bytes(original), before)
        self.assertNotIn('output only', decode()['limitations'])

    def test_annotation_narrows_operations_and_windows_without_repair(self):
        prior = prior_frontier()
        guard = decode(snapshot([scope(status=decoder.OPEN)]))
        narrowed = decoder.annotate_frontier_snapshot(prior, guard)
        operation, window = narrowed['operations'][0], narrowed['windows'][0]
        self.assertTrue(operation['observed_callback_sequence_complete_before_scope'])
        self.assertTrue(operation['observed_row_window_complete_before_scope'])
        self.assertFalse(operation['observed_callback_sequence_complete'])
        self.assertFalse(operation['observed_row_window_complete'])
        self.assertFalse(window['complete_before_scope'])
        self.assertFalse(window['complete'])
        self.assertTrue(window['observed_window_complete'])
        self.assertIn('known-contents-boundary', window['reasons'])
        for output in (narrowed, operation, window):
            self.assert_no_authority(output)
        self.assertIn('native-scope-not-quiet', operation['reasons'])
        self.assertIn('native-scope-not-quiet', window['reasons'])
        self.assertEqual(narrowed['native_scope'], guard)
        self.assertTrue(prior['operations'][0]['observed_callback_sequence_complete'])

    def test_quiet_annotation_does_not_repair_any_prior_rejection(self):
        prior = prior_frontier(original_entry_revision=0)
        before = deepcopy(prior)
        result = decoder.annotate_frontier_snapshot(prior, decode())
        operation, window = result['operations'][0], result['windows'][0]
        self.assertFalse(operation['observed_callback_sequence_complete_before_scope'])
        self.assertFalse(operation['observed_callback_sequence_complete'])
        self.assertFalse(window['complete'])
        self.assertIn('original-entry-frontier-mismatch', operation['reasons'])
        self.assertNotIn('native-scope-not-quiet', operation['reasons'])
        self.assertEqual(prior, before)
        self.assert_no_authority(result)

    def test_quiet_annotation_retains_true_historical_completeness_only(self):
        result = decoder.annotate_frontier_snapshot(prior_frontier(), decode())
        self.assertTrue(result['operations'][0]['observed_callback_sequence_complete'])
        self.assertTrue(result['scope_quiet'])
        self.assertFalse(result['windows'][0]['complete'])
        self.assert_no_authority(result['operations'][0])

    def test_annotation_deepcopies_both_inputs_and_is_idempotently_conservative(self):
        prior, guard = prior_frontier(), decode(snapshot([scope(status=decoder.OPEN)]))
        before_prior, before_guard = deepcopy(prior), deepcopy(guard)
        once = decoder.annotate_frontier_snapshot(prior, guard)
        twice = decoder.annotate_frontier_snapshot(once, guard)
        self.assertEqual(twice, once)
        once['operations'][0]['reasons'].append('output only')
        once['windows'][0]['rows'][0]['path'] = 'output only'
        once['native_scope']['records'][0]['frame'] = 0
        self.assertEqual(prior, before_prior)
        self.assertEqual(guard, before_guard)

    def test_annotation_forces_all_known_authority_flags_false(self):
        prior = prior_frontier()
        guard = decode()
        guard.update({field: True for field in decoder.AUTHORITY_FLAGS})
        for result in (prior, prior['operations'][0], prior['windows'][0]):
            result.update({field: True for field in decoder.AUTHORITY_FLAGS})
        result = decoder.annotate_frontier_snapshot(prior, guard)
        for output in (result, result['native_scope'], result['operations'][0], result['windows'][0]):
            self.assert_no_authority(output)
        self.assertTrue(guard['autoscroll_authorized'])

    def test_annotation_rejects_missing_or_nonboolean_quiet(self):
        for guard in ({}, {'scope_quiet': 1}, {'scope_quiet': None}, [], None):
            with self.subTest(guard=guard), self.assertRaises(ValueError):
                decoder.annotate_frontier_snapshot(prior_frontier(), guard)
        with self.assertRaises(ValueError):
            decoder.annotate_frontier_snapshot([], decode())

    def test_standalone_cli_uses_owned_local_bytes_and_explicit_capacity(self):
        output = StringIO()
        with patch.object(decoder.Path, 'read_bytes', return_value=snapshot()) as reader:
            with redirect_stdout(output):
                decoder.main(['owned.bin', '--capacity', str(CAPACITY)])
            reader.assert_called_once_with()
        result = json.loads(output.getvalue())
        self.assertTrue(result['scope_quiet'])
        self.assert_no_authority(result)
        for failure in (b'bad', OSError('unavailable')):
            kwargs = dict(side_effect=failure) if isinstance(failure, OSError) else dict(return_value=failure)
            with patch.object(decoder.Path, 'read_bytes', **kwargs):
                with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as error:
                    decoder.main(['owned.bin', '--capacity', str(CAPACITY)])
                self.assertEqual(error.exception.code, 2)

    def test_cli_optional_frontier_is_narrowed_only_after_strict_decode(self):
        output = StringIO()
        args = ['guard.bin', '--capacity', str(CAPACITY), '--frontier-snapshot', 'frontier.bin',
                '--lineage-capacity', str(fixtures.CAPACITY),
                '--row-capacity', str(fixtures.ROW_CAPACITY),
                '--operation-capacity', str(fixtures.OPERATION_CAPACITY)]
        raw = snapshot([scope(status=decoder.OPEN)])
        with patch.object(decoder.Path, 'read_bytes', side_effect=[raw, fixtures.snapshot()]):
            with redirect_stdout(output):
                decoder.main(args)
        result = json.loads(output.getvalue())
        self.assertFalse(result['operations'][0]['observed_callback_sequence_complete'])
        self.assert_no_authority(result)
        with patch.object(decoder.Path, 'read_bytes', side_effect=[raw, b'bad']):
            with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as error:
                decoder.main(args)
            self.assertEqual(error.exception.code, 2)


if __name__ == '__main__':
    unittest.main()
