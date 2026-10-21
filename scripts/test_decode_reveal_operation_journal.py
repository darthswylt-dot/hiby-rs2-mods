#!/usr/bin/env python3
"""Owned operation fixtures: callback history never repairs row authority."""

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
import struct
import unittest
from unittest.mock import patch

import decode_reveal_operation_journal as decoder
import reveal_operation_journal_mips as journal
import test_decode_reveal_contents_revision as revision_fixtures
import test_decode_reveal_lineage_rows as fixtures


CAPACITY, ROW_CAPACITY = fixtures.CAPACITY, fixtures.ROW_CAPACITY
OPERATION_CAPACITY = 16
PREFIX_SIZE = revision_fixtures.PREFIX_SIZE + decoder.base.STATE_BYTES


def operation_events(*, borrow=2, start=1):
    result = []
    for kind, revision in zip(decoder.EXPECTED_KINDS,
                              (start, start + 1, start + 1, start + 2, start + 3, start + 3)):
        item = dict.fromkeys(decoder.FIELDS, 0)
        item.update(magic=decoder.MAGIC, kind=kind, borrow=borrow,
                    origin=1, job=0x5000, stack=0xA770,
                    site=decoder.SITES[kind], revision=revision)
        if kind in (decoder.FILL_BEGIN, decoder.POST_TARGET):
            item['callee'] = decoder.FILL_CALLEE if kind == decoder.FILL_BEGIN else decoder.POST_CALLEE
        elif kind == decoder.BIND_BEGIN:
            item.update(panel=0x2000, dest=0x7000, view=0x1000)
        result.append(item)
    return result


def snapshot(*, events=None, records=None, row_events=None, producer_revision=2,
             current=4, stamps=None):
    prefix = revision_fixtures.snapshot(records=records, events=row_events,
                                        producer_revision=producer_revision,
                                        current=current, stamps=stamps)
    events = operation_events() if events is None else events
    journal = bytearray(decoder.memory_bytes(OPERATION_CAPACITY))
    struct.pack_into('<I', journal, 0, len(events))
    for index, event in enumerate(events):
        item = dict(event, seq=index + 1)
        struct.pack_into('<16I', journal, decoder.HEADER + index * decoder.RECORD,
                         *(item[field] & fixtures.MASK for field in decoder.FIELDS))
    return prefix + journal


def operation_word(data, sequence, field, value):
    return fixtures.mutate_word(data, PREFIX_SIZE + decoder.HEADER
                                + (sequence - 1) * decoder.RECORD
                                + decoder.FIELDS.index(field) * 4, value)


class DecodeRevealOperationJournalTests(unittest.TestCase):
    def decode(self, data=None):
        return decoder.decode(snapshot() if data is None else data,
                              capacity=CAPACITY, row_capacity=ROW_CAPACITY,
                              operation_capacity=OPERATION_CAPACITY)

    def test_literal_schema_and_return_branch_target_are_pinned(self):
        self.assertEqual((decoder.HEADER, decoder.RECORD), (16, 64))
        self.assertEqual(decoder.MAGIC.to_bytes(4, 'little'), b'LOPR')
        self.assertEqual(decoder.SITES, {1: 0x48EC48, 2: 0x48EC5C, 3: 0x48EC68,
                                         4: 0x4A0EE0, 5: 0x48F8E4,
                                         6: 0x48EC7C, 7: 0x48EDD4})
        self.assertEqual((decoder.FILL_CALLEE, decoder.POST_CALLEE), (0x48D280, 0x48F880))
        self.assertEqual(len(decoder.FIELDS), 16)
        self.assertEqual((decoder.HEADER, decoder.RECORD, decoder.MAGIC),
                         (journal.HEADER, journal.RECORD, journal.MAGIC))
        for index, name in enumerate(('MAGIC_OFFSET', 'KIND', 'BORROW', 'SEQ', 'ORIGIN',
                                      'JOB', 'STACK', 'SITE', 'RESULT', 'CALLEE',
                                      'PANEL', 'DEST', 'VIEW', 'REVISION')):
            self.assertEqual(getattr(journal, name), index * 4)
        self.assertEqual(journal.RESERVED, (56, 60))
        self.assertEqual(decoder.memory_bytes(OPERATION_CAPACITY), journal.memory_bytes(OPERATION_CAPACITY))

    def test_complete_observed_callback_history_does_not_repair_known_boundary_rows(self):
        result = self.decode()
        operation, window = result['operations'][0], result['windows'][0]
        self.assertTrue(operation['observed_callback_sequence_complete'])
        self.assertTrue(operation['row_observation_associated'])
        self.assertTrue(operation['observed_row_window_complete'])
        self.assertEqual((operation['borrow'], operation['associated_query'],
                          operation['associated_producer']), (2, 3, 4))
        self.assertEqual(operation['event_kinds'], [1, 2, 3, 4, 5, 6])
        self.assertEqual(operation['reasons'], [])
        self.assertFalse(operation['known_later_boundary'])
        self.assertTrue(window['observed_window_complete'])
        self.assertFalse(window['complete'])
        self.assertIn('known-contents-boundary', window['reasons'])
        self.assertEqual(window['producer_revision'], 2)
        self.assertEqual(result['format'], decoder.FORMAT)
        for output in (result, operation, window):
            self.assertFalse(output['contents_current'])
            self.assertFalse(output['coherent_capture'])
        self.assertFalse(result['autoscroll_authorized'])
        self.assertNotIn('CompletedRows', result)

    def test_later_boundary_does_not_erase_historical_observation_or_grant_currentness(self):
        result = self.decode(snapshot(current=9))
        operation = result['operations'][0]
        self.assertTrue(operation['observed_callback_sequence_complete'])
        self.assertTrue(operation['known_later_boundary'])
        self.assertEqual(operation['latest_observed_revision'], 4)
        self.assertEqual(operation['known_contents_revision'], 9)
        self.assertFalse(result['windows'][0]['complete'])
        limitations = ' '.join(result['limitations'])
        for premise in ('already-active writer', 'queued stale', 'statement-finalize', 'coherence'):
            self.assertIn(premise, limitations)

    def test_missing_duplicate_cross_phase_and_error_end_sequences_stay_incomplete(self):
        original = operation_events()
        cases = [[], original[:-1], original[1:], original[:3] + original[4:],
                 original[:2] + [original[1]] + original[2:], original + [original[-1]],
                 original[:3] + [original[4], original[3], original[5]]]
        error = dict(original[-1], kind=decoder.ERROR_END, site=decoder.SITES[decoder.ERROR_END], result=-1)
        cases += [[original[0], dict(original[1], result=-1), error], original + [error]]
        for events in cases:
            with self.subTest(kinds=[item['kind'] for item in events]):
                operation = self.decode(snapshot(events=events))['operations'][0]
                self.assertFalse(operation['observed_callback_sequence_complete'])
                self.assertIn('callback-event-sequence', operation['reasons'])
        empty = self.decode(snapshot(events=[]))['operations'][0]
        self.assertIsNone(empty['known_later_boundary'])
        self.assertIn('no-operation-events', empty['reasons'])

    def test_actual_fill_post_bind_and_end_values_are_not_forced_success(self):
        cases = [(0, 'callee', 0, 'fill-target'), (0, 'callee', 0x48D080, 'fill-target'),
                 (1, 'result', -1, 'fill-return-error'), (2, 'callee', 0, 'post-target'),
                 (2, 'callee', 0x1234, 'post-target'), (4, 'result', -6, 'bind-return-failed'),
                 (5, 'result', 2, 'normal-end-result'), (5, 'result', -6, 'normal-end-result')]
        for index, field, value, reason in cases:
            events = operation_events()
            events[index][field] = value
            with self.subTest(index=index, field=field, value=value):
                operation = self.decode(snapshot(events=events))['operations'][0]
                self.assertFalse(operation['observed_callback_sequence_complete'])
                self.assertIn(reason, operation['reasons'])
        # The explicit protocol rejects native fill -1, not arbitrary statuses
        # extrapolated from a different callback. Keep the copied signed value.
        events = operation_events()
        events[1]['result'] = -(1 << 31)
        result = self.decode(snapshot(events=events))
        self.assertEqual(result['operation_events'][1]['result'], -(1 << 31))
        self.assertTrue(result['operations'][0]['observed_callback_sequence_complete'])

    def test_revision_steps_and_immutable_producer_sample_must_match(self):
        for index, revision in ((1, 1), (2, 3), (3, 2), (4, 3), (5, 3)):
            events = operation_events()
            events[index]['revision'] = revision
            with self.subTest(index=index):
                operation = self.decode(snapshot(events=events))['operations'][0]
                self.assertFalse(operation['observed_callback_sequence_complete'])
                self.assertIn('revision-steps', operation['reasons'])
        operation = self.decode(snapshot(producer_revision=1))['operations'][0]
        self.assertFalse(operation['observed_callback_sequence_complete'])
        self.assertIn('producer-revision', operation['reasons'])

    def test_equal_and_extreme_valid_revision_samples_do_not_imply_ownership(self):
        for start in (0, 0x7FFFFFFC):
            result = self.decode(snapshot(events=operation_events(start=start),
                                          producer_revision=start + 1, current=start + 3))
            self.assertTrue(result['operations'][0]['observed_callback_sequence_complete'])
            self.assertFalse(result['contents_current'])
            self.assertFalse(result['autoscroll_authorized'])

    def test_bind_destination_must_match_unique_query_and_producer(self):
        events = operation_events()
        events[3]['dest'] = 0x7777
        operation = self.decode(snapshot(events=events))['operations'][0]
        self.assertFalse(operation['row_observation_associated'])
        self.assertFalse(operation['observed_callback_sequence_complete'])
        self.assertIn('row-observation-association', operation['reasons'])
        for extra in (fixtures.receipts()[2], fixtures.receipts()[3]):
            records = fixtures.receipts() + [dict(extra)]
            stamps = {4: 2, 5: 2} if extra['kind'] == fixtures.lineage.PRODUCER else {4: 2}
            operation = self.decode(snapshot(records=records, stamps=stamps))['operations'][0]
            self.assertFalse(operation['observed_callback_sequence_complete'])
            self.assertIn('query-count' if extra['kind'] == fixtures.lineage.QUERY else 'producer-count',
                          operation['reasons'])

    def test_incomplete_row_observation_is_not_fixed_by_native_callback_returns(self):
        for events in ([], fixtures.complete_events()[:-1]):
            result = self.decode(snapshot(row_events=events))
            operation = result['operations'][0]
            self.assertTrue(operation['row_observation_associated'])
            self.assertFalse(operation['observed_row_window_complete'])
            self.assertFalse(operation['observed_callback_sequence_complete'])
            self.assertIn('row-window-incomplete', operation['reasons'])
            self.assertFalse(result['windows'][0]['complete'])

    def test_every_borrow_is_reported_without_merging_identical_raw_addresses(self):
        records = fixtures.receipts()
        records += [dict(records[1]), dict(records[2], parent=5), dict(records[3], parent=6)]
        rows = fixtures.complete_events(4) + fixtures.complete_events(7)
        result = self.decode(snapshot(records=records, row_events=rows, stamps={4: 2, 7: 2}))
        first, second = result['operations']
        self.assertEqual([first['borrow'], second['borrow']], [2, 5])
        self.assertEqual([first['job'], second['job']], [0x5000, 0x5000])
        self.assertEqual([first['stack'], second['stack']], [0xA770, 0xA770])
        self.assertTrue(first['observed_callback_sequence_complete'])
        self.assertFalse(second['observed_callback_sequence_complete'])
        self.assertEqual(second['event_sequences'], [])
        self.assertEqual(second['associated_producer'], 7)
        empty = self.decode(snapshot(records=[], row_events=[], events=[]))
        self.assertEqual((empty['operations'], empty['operation_events']), ([], []))

    def test_interleaved_borrow_events_are_grouped_only_by_receipt_id(self):
        records = fixtures.receipts()
        records += [dict(records[1]), dict(records[2], parent=5), dict(records[3], parent=6)]
        rows = fixtures.complete_events(4) + fixtures.complete_events(7)
        first, second = operation_events(), operation_events(borrow=5)
        # The second incomplete invocation may have exactly the same raw
        # addresses, but its events cannot supply the first one's missing END.
        events = [item for pair in zip(first[:-1], second[:-1]) for item in pair] + [second[-1]]
        result = self.decode(snapshot(records=records, row_events=rows, events=events,
                                      stamps={4: 2, 7: 2}))
        old, other = result['operations']
        self.assertFalse(old['observed_callback_sequence_complete'])
        self.assertTrue(other['observed_callback_sequence_complete'])
        self.assertEqual(old['event_sequences'], [1, 3, 5, 7, 9])
        self.assertEqual(other['event_sequences'], [2, 4, 6, 8, 10, 11])

    def test_allocator_headers_magic_gaps_and_unused_tails_are_strict(self):
        data = snapshot()
        candidates = [fixtures.mutate_word(data, PREFIX_SIZE, 0xFFFFFFFF),
                      fixtures.mutate_word(data, PREFIX_SIZE, OPERATION_CAPACITY + 1),
                      fixtures.mutate_word(data, PREFIX_SIZE, 5),
                      fixtures.mutate_word(data, PREFIX_SIZE + 16 + 15 * 64, decoder.MAGIC)]
        candidates += [fixtures.mutate_word(data, PREFIX_SIZE + offset, 1) for offset in (4, 8, 12)]
        candidates += [operation_word(data, 2, 'magic', 0), operation_word(data, 2, 'seq', 3),
                       operation_word(data, 1, 'seq', 0)]
        for candidate in candidates:
            with self.assertRaises(ValueError):
                self.decode(candidate)

    def test_exact_size_explicit_capacities_and_owned_bytes_are_required(self):
        data = snapshot()
        for candidate in (data[:-1], data + b'\0', data[:PREFIX_SIZE], 'not bytes', 1):
            with self.assertRaises(ValueError):
                self.decode(candidate)
        for field in ('capacity', 'row_capacity', 'operation_capacity'):
            for invalid in (0, -1, True, 1.5, 1 << 32):
                args = dict(capacity=CAPACITY, row_capacity=ROW_CAPACITY,
                            operation_capacity=OPERATION_CAPACITY)
                args[field] = invalid
                with self.subTest(field=field, value=invalid), self.assertRaises(ValueError):
                    decoder.decode(data, **args)

    def test_sites_borrow_metadata_unused_fields_and_future_revisions_reject(self):
        data = snapshot()
        cases = [(1, 'kind', 8), (1, 'site', 0), (5, 'site', 0x48F8E0),
                 (1, 'borrow', 0), (1, 'borrow', 1), (1, 'borrow', 8),
                 (1, 'origin', 2), (1, 'job', 1), (1, 'stack', 1),
                 (4, 'panel', 1), (4, 'view', 1), (1, 'panel', 1),
                 (2, 'dest', 1), (3, 'view', 1), (2, 'callee', 1),
                 (4, 'callee', 1), (1, 'result', 1), (3, 'result', -1),
                 (4, 'result', 1), (1, 'reserved0', 1), (1, 'reserved1', 1),
                 (1, 'revision', 5), (1, 'revision', 0xFFFFFFFF)]
        for sequence, field, value in cases:
            with self.subTest(sequence=sequence, field=field, value=value), self.assertRaises(ValueError):
                self.decode(operation_word(data, sequence, field, value))

    def test_strict_base_decoder_checks_are_retained_without_canonicalizing_operations(self):
        data = snapshot()
        candidates = [fixtures.line_word(data, 4, 'parent', 2),
                      fixtures.row_word(data, 1, 'magic', 0),
                      fixtures.row_word(data, 1, 'reserved', 1),
                      fixtures.line_word(data, 4, 'reserved0', 5),
                      fixtures.mutate_word(data, revision_fixtures.PREFIX_SIZE + 4, 1)]
        for candidate in candidates:
            with self.assertRaises(ValueError):
                self.decode(candidate)
        row_events = fixtures.complete_events()
        row_events[0]['result'] = -1
        result = self.decode(snapshot(row_events=row_events))
        self.assertFalse(result['operations'][0]['observed_callback_sequence_complete'])
        self.assertIn('append-result-mismatch', result['windows'][0]['reasons'])
        self.assertIn('known-contents-boundary', result['windows'][0]['reasons'])

    def test_owned_copy_base_windows_and_caller_input_are_preserved(self):
        original = bytearray(snapshot())
        before = bytes(original)
        strict = decoder.base.decode
        with patch.object(decoder.base, 'decode', wraps=strict) as call:
            result = self.decode(memoryview(original))
        call.assert_called_once()
        self.assertEqual(call.call_args.args[0], before[:PREFIX_SIZE])
        expected = strict(before[:PREFIX_SIZE], capacity=CAPACITY, row_capacity=ROW_CAPACITY)
        self.assertEqual(result['windows'], expected['windows'])
        result['operation_events'][0]['job'] = 123
        result['windows'][0]['rows'][0]['path'] = 'output only'
        self.assertEqual(bytes(original), before)

    def test_cli_only_reads_explicit_snapshot_and_never_authorizes_ui(self):
        output = StringIO()
        args = ['owned.bin', '--capacity', str(CAPACITY), '--row-capacity', str(ROW_CAPACITY),
                '--operation-capacity', str(OPERATION_CAPACITY)]
        with patch.object(decoder.Path, 'read_bytes', return_value=snapshot()) as reader:
            with redirect_stdout(output):
                decoder.main(args)
            reader.assert_called_once_with()
        result = json.loads(output.getvalue())
        self.assertTrue(result['operations'][0]['observed_callback_sequence_complete'])
        self.assertFalse(result['autoscroll_authorized'])
        with patch.object(decoder.Path, 'read_bytes', return_value=b'bad'):
            with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as error:
                decoder.main(args)
            self.assertEqual(error.exception.code, 2)


if __name__ == '__main__':
    unittest.main()
