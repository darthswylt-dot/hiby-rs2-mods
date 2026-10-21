#!/usr/bin/env python3
"""Immutable original-entry fixtures; fresh starts still convey no authority."""

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
import struct
import unittest
from unittest.mock import patch

import decode_reveal_origin_frontier as decoder
import test_decode_reveal_operation_journal as operations
import test_decode_reveal_lineage_rows as fixtures


CAPACITY, ROW_CAPACITY, OPERATION_CAPACITY = (
    operations.CAPACITY, operations.ROW_CAPACITY, operations.OPERATION_CAPACITY)


def snapshot(*, original_entry_revision=1, entry_stamps=None, **kwargs):
    data = bytearray(operations.snapshot(**kwargs))
    allocated = struct.unpack_from('<I', data)[0]
    for index in range(allocated):
        start = fixtures.lineage.HEADER + index * fixtures.lineage.RECORD
        kind = struct.unpack_from('<I', data, start + fixtures.lineage.KIND)[0]
        if kind == fixtures.lineage.RENDER:
            stamp = original_entry_revision if entry_stamps is None else entry_stamps[index + 1]
            struct.pack_into('<I', data, start + decoder.ORIGINAL_ENTRY_REVISION_OFFSET, stamp)
    return bytes(data)


class DecodeRevealOriginFrontierTests(unittest.TestCase):
    def decode(self, data=None):
        return decoder.decode(snapshot() if data is None else data,
                              capacity=CAPACITY, row_capacity=ROW_CAPACITY,
                              operation_capacity=OPERATION_CAPACITY)

    def test_first_fresh_fill_preserves_observation_not_current_rows(self):
        result = self.decode()
        operation, window = result['operations'][0], result['windows'][0]
        self.assertEqual(result['format'], 'lineage-rows-origin-frontier-v1')
        self.assertTrue(operation['observed_callback_sequence_complete_before_frontier'])
        self.assertTrue(operation['original_frontier_matches'])
        self.assertTrue(operation['observed_callback_sequence_complete'])
        self.assertEqual(operation['original_entry_revision'], 1)
        self.assertEqual([item['original_entry_revision'] for item in result['receipts']], [1] * 4)
        self.assertFalse(window['complete'])
        self.assertTrue(window['observed_window_complete'])
        self.assertIn('known-contents-boundary', window['reasons'])
        for output in (result, operation, window):
            self.assertFalse(output['contents_current'])
            self.assertFalse(output['coherent_capture'])
        self.assertFalse(result['autoscroll_authorized'])
        self.assertNotIn('CompletedRows', result)

    def test_old_queued_job_starting_after_reset_keeps_its_old_original_mark(self):
        data = snapshot(original_entry_revision=1,
                        events=operations.operation_events(start=5), producer_revision=6, current=8)
        result = self.decode(data)
        operation = result['operations'][0]
        self.assertTrue(operation['observed_callback_sequence_complete_before_frontier'])
        self.assertFalse(operation['original_frontier_matches'])
        self.assertFalse(operation['observed_callback_sequence_complete'])
        self.assertEqual(operation['original_entry_revision'], 1)
        self.assertEqual(operation['starting_revision'], 5)
        self.assertIn('original-entry-frontier-mismatch', operation['reasons'])
        self.assertTrue(result['windows'][0]['observed_window_complete'])
        self.assertFalse(result['windows'][0]['complete'])

    def test_delayed_root_mint_uses_captured_entry_not_the_later_global_counter(self):
        # A entered at1; B entered at2 while A was paused before root mint.
        # A's root must still carry1, not a fresh callback-time sample of2.
        data = snapshot(original_entry_revision=1,
                        events=operations.operation_events(start=2), producer_revision=3, current=5)
        operation = self.decode(data)['operations'][0]
        self.assertTrue(operation['observed_callback_sequence_complete_before_frontier'])
        self.assertFalse(operation['original_frontier_matches'])
        self.assertEqual(operation['original_entry_revision'], 1)
        self.assertEqual(operation['starting_revision'], 2)

    def test_later_chunk_of_same_origin_is_conservatively_unadmitted(self):
        records = fixtures.receipts()
        records += [dict(records[1]), dict(records[2], parent=5), dict(records[3], parent=6)]
        row_events = fixtures.complete_events(4) + fixtures.complete_events(7)
        events = operations.operation_events() + operations.operation_events(borrow=5, start=4)
        result = self.decode(snapshot(records=records, row_events=row_events, events=events,
                                      stamps={4: 2, 7: 5}, current=7))
        first, later = result['operations']
        self.assertTrue(first['observed_callback_sequence_complete'])
        self.assertTrue(first['known_later_boundary'])
        self.assertTrue(later['observed_callback_sequence_complete_before_frontier'])
        self.assertFalse(later['original_frontier_matches'])
        self.assertFalse(later['observed_callback_sequence_complete'])
        self.assertEqual([item['original_entry_revision'] for item in result['receipts']], [1] * 7)
        self.assertTrue(all(not window['complete'] for window in result['windows']))

    def test_unknown_renderer_and_initial_roots_remain_unadmitted(self):
        for initial in (False, True):
            records = fixtures.receipts()
            if initial:
                records[0].update(kind=fixtures.lineage.INITIAL, site=0x48F40C)
            with self.subTest(initial=initial):
                result = self.decode(snapshot(records=records, original_entry_revision=0))
                operation = result['operations'][0]
                self.assertTrue(operation['observed_callback_sequence_complete_before_frontier'])
                self.assertFalse(operation['original_frontier_matches'])
                self.assertFalse(operation['observed_callback_sequence_complete'])
                self.assertEqual([item['original_entry_revision'] for item in result['receipts']], [0] * 4)
        empty = self.decode(snapshot(records=[], row_events=[], events=[]))
        self.assertEqual((empty['receipts'], empty['operations']), ([], []))

    def test_fresh_render_of_stale_request_and_prior_active_writer_are_not_excluded(self):
        # These unobserved histories produce identical valid marks. No field
        # identifies playback intent, an owner lease, or a still-active writer.
        for history in ('stale-ui-request-enters-after-reset', 'prior-writer-resumes-without-entry',
                        'raw-view-panel-addresses-recycled'):
            with self.subTest(history=history):
                result = self.decode()
                self.assertTrue(result['operations'][0]['original_frontier_matches'])
                self.assertFalse(result['contents_current'])
                self.assertFalse(result['autoscroll_authorized'])
        limitations = ' '.join(result['limitations'])
        for bound in ('stale UI', 'playback/request', 'already-active writer', 'query scope', 'capture coherence'):
            self.assertIn(bound, limitations)

    def test_maximum_nonwrapping_original_revision_remains_only_diagnostic(self):
        start = 0x7FFFFFFC
        result = self.decode(snapshot(original_entry_revision=start,
                                      events=operations.operation_events(start=start),
                                      producer_revision=start + 1, current=start + 3))
        self.assertTrue(result['operations'][0]['original_frontier_matches'])
        self.assertFalse(result['contents_current'])

    def test_impossible_original_producer_and_operation_chronology_rejects(self):
        # Future original marks and a producer preceding its origin are not
        # merely stale histories: they contradict the monotonic native clock.
        for stamp in (5, 0x80000000, 0xFFFFFFFF):
            with self.subTest(stamp=stamp), self.assertRaises(ValueError):
                self.decode(snapshot(original_entry_revision=stamp))
        with self.assertRaisesRegex(ValueError, 'producer revision predates'):
            self.decode(snapshot(original_entry_revision=3))
        data = snapshot(original_entry_revision=2,
                        events=operations.operation_events(start=2), producer_revision=3, current=5)
        with self.assertRaisesRegex(ValueError, 'operation event predates'):
            self.decode(operations.operation_word(data, 1, 'revision', 1))

    def test_only_allocated_render_byte60_is_a_known_extension(self):
        data = snapshot()
        for token in (2, 3, 4, 8):
            with self.subTest(token=token), self.assertRaises(ValueError):
                self.decode(fixtures.line_word(data, token, 'reserved1', 1))
        records = fixtures.receipts()
        records[0].update(kind=fixtures.lineage.INITIAL, site=0x48F40C)
        initial = snapshot(records=records)
        with self.assertRaises(ValueError):
            self.decode(fixtures.line_word(initial, 1, 'reserved1', 1))
        for field in ('reserved0', 'flags'):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.decode(fixtures.line_word(data, 1, field, 1))

    def test_existing_strict_checks_and_semantic_rejections_are_not_bypassed(self):
        data = snapshot()
        # The new extension is versioned, not a relaxation of the old parser.
        # Only this decoder may remove the allocated RENDER+60 word in a copy.
        with self.assertRaises(ValueError):
            decoder.base.decode(data, capacity=CAPACITY, row_capacity=ROW_CAPACITY,
                                operation_capacity=OPERATION_CAPACITY)
        candidates = [fixtures.line_word(data, 1, 'magic', 0),
                      fixtures.line_word(data, 4, 'parent', 2),
                      fixtures.row_word(data, 1, 'magic', 0),
                      fixtures.row_word(data, 1, 'reserved', 1),
                      operations.operation_word(data, 1, 'origin', 2),
                      operations.operation_word(data, 5, 'site', 0x48F8E0),
                      operations.operation_word(data, 1, 'reserved0', 1)]
        for candidate in candidates:
            with self.assertRaises(ValueError):
                self.decode(candidate)
        events = operations.operation_events()
        events[0]['callee'] = 0
        operation = self.decode(snapshot(events=events))['operations'][0]
        self.assertTrue(operation['original_frontier_matches'])
        self.assertFalse(operation['observed_callback_sequence_complete_before_frontier'])
        self.assertFalse(operation['observed_callback_sequence_complete'])
        self.assertIn('fill-target', operation['reasons'])
        result = self.decode(snapshot(row_events=[]))
        self.assertTrue(result['operations'][0]['original_frontier_matches'])
        self.assertFalse(result['operations'][0]['observed_callback_sequence_complete'])
        self.assertIn('row-window-incomplete', result['operations'][0]['reasons'])

    def test_missing_sequence_cannot_be_repaired_by_matching_root_entry(self):
        for events in ([], operations.operation_events()[:-1]):
            operation = self.decode(snapshot(events=events))['operations'][0]
            self.assertFalse(operation['observed_callback_sequence_complete_before_frontier'])
            self.assertFalse(operation['observed_callback_sequence_complete'])
            self.assertFalse(operation['original_frontier_matches'])
            self.assertIn('original-entry-frontier-mismatch', operation['reasons'])

    def test_size_capacities_faulted_counter_and_reserved_state_remain_strict(self):
        data = snapshot()
        revision_offset = operations.revision_fixtures.PREFIX_SIZE
        candidates = [data[:-1], data + b'\0', '', 123,
                      fixtures.mutate_word(data, 0, 0xFFFFFFFF),
                      fixtures.mutate_word(data, revision_offset, 0xFFFFFFFF),
                      fixtures.mutate_word(data, revision_offset, 0x80000000)]
        candidates += [fixtures.mutate_word(data, revision_offset + offset, 1) for offset in (4, 8, 12)]
        for candidate in candidates:
            with self.assertRaises(ValueError):
                self.decode(candidate)
        for field in ('capacity', 'row_capacity', 'operation_capacity'):
            for invalid in (0, -1, True, 1.5, 1 << 32):
                args = dict(capacity=CAPACITY, row_capacity=ROW_CAPACITY,
                            operation_capacity=OPERATION_CAPACITY)
                args[field] = invalid
                with self.subTest(field=field, value=invalid), self.assertRaises(ValueError):
                    decoder.decode(data, **args)

    def test_canonicalization_changes_only_root_extension_in_a_private_copy(self):
        original = bytearray(snapshot())
        before = bytes(original)
        strict = decoder.base.decode
        with patch.object(decoder.base, 'decode', wraps=strict) as call:
            result = self.decode(memoryview(original))
        call.assert_called_once()
        canonical = bytes(call.call_args.args[0])
        changed = {index for index, pair in enumerate(zip(before, canonical)) if pair[0] != pair[1]}
        allowed = set(range(16 + 60, 16 + 64))
        self.assertTrue(changed)
        self.assertLessEqual(changed, allowed)
        self.assertEqual(canonical[16 + 60:16 + 64], b'\0' * 4)
        expected = strict(canonical, capacity=CAPACITY, row_capacity=ROW_CAPACITY,
                          operation_capacity=OPERATION_CAPACITY)
        self.assertEqual(result['windows'], expected['windows'])
        self.assertEqual(result['operation_events'], expected['operation_events'])
        result['receipts'][0]['original_entry_revision'] = 99
        result['windows'][0]['rows'][0]['path'] = 'output only'
        self.assertEqual(bytes(original), before)

    def test_distinct_origin_ids_keep_their_own_immutable_entry_marks(self):
        records = fixtures.receipts()
        # A second root and BORROW can reuse every raw scalar; they must not
        # inherit the first root's entry mark from any address-based registry.
        records += [dict(records[0], origin=5), dict(records[1], origin=5, parent=5)]
        result = self.decode(snapshot(records=records, entry_stamps={1: 1, 5: 3}))
        self.assertEqual([item['original_entry_revision'] for item in result['receipts']],
                         [1, 1, 1, 1, 3, 3])
        self.assertEqual([item['original_entry_revision'] for item in result['operations']], [1, 3])
        self.assertTrue(result['operations'][0]['observed_callback_sequence_complete'])
        self.assertFalse(result['operations'][1]['observed_callback_sequence_complete'])

    def test_cli_uses_only_owned_local_bytes_and_explicit_capacities(self):
        output = StringIO()
        args = ['owned.bin', '--capacity', str(CAPACITY), '--row-capacity', str(ROW_CAPACITY),
                '--operation-capacity', str(OPERATION_CAPACITY)]
        with patch.object(decoder.Path, 'read_bytes', return_value=snapshot()) as reader:
            with redirect_stdout(output):
                decoder.main(args)
            reader.assert_called_once_with()
        result = json.loads(output.getvalue())
        self.assertTrue(result['operations'][0]['original_frontier_matches'])
        self.assertFalse(result['autoscroll_authorized'])
        with patch.object(decoder.Path, 'read_bytes', return_value=b'bad'):
            with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as error:
                decoder.main(args)
            self.assertEqual(error.exception.code, 2)


if __name__ == '__main__':
    unittest.main()
