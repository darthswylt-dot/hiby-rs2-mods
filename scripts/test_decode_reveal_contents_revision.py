#!/usr/bin/env python3
"""Owned revision fixtures: cancellation evidence is never positive authority."""

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
import struct
import unittest
from unittest.mock import patch

import decode_reveal_contents_revision as decoder
import decode_reveal_lineage_rows as base
import test_decode_reveal_lineage_rows as fixtures


CAPACITY, ROW_CAPACITY = fixtures.CAPACITY, fixtures.ROW_CAPACITY
LINEAGE_SIZE = fixtures.lineage.memory_bytes(CAPACITY)
PREFIX_SIZE = LINEAGE_SIZE + fixtures.journal.memory_bytes(ROW_CAPACITY)


def snapshot(*, producer_revision=2, current=2, records=None, events=None, stamps=None):
    data = bytearray(fixtures.snapshot(records, events))
    allocated = struct.unpack_from('<I', data)[0]
    revisions = {}
    for index in range(allocated):
        start = 16 + index * fixtures.lineage.RECORD
        if struct.unpack_from('<I', data, start + 4)[0] == fixtures.lineage.PRODUCER:
            stamp = producer_revision if stamps is None else stamps[index + 1]
            revisions[index + 1] = stamp
            struct.pack_into('<I', data, start + 56, stamp)
    allocated_events = struct.unpack_from('<I', data, LINEAGE_SIZE)[0]
    for index in range(allocated_events):
        start = LINEAGE_SIZE + 16 + index * fixtures.journal.RECORD
        producer = struct.unpack_from('<I', data, start + fixtures.journal.PRODUCER)[0]
        struct.pack_into('<I', data, start + 60, revisions[producer])
    return bytes(data) + struct.pack('<4I', current, 0, 0, 0)


class DecodeRevealContentsRevisionTests(unittest.TestCase):
    def decode(self, data=None):
        return decoder.decode(snapshot() if data is None else data,
                              capacity=CAPACITY, row_capacity=ROW_CAPACITY)

    def test_equal_revision_preserves_observed_window_but_never_authorizes_contents(self):
        result = self.decode()
        self.assertEqual(result['format'], 'lineage-rows-content-revision-v1')
        self.assertEqual(result['known_contents_revision'], 2)
        window = result['windows'][0]
        self.assertTrue(window['observed_window_complete'])
        self.assertTrue(window['known_boundary_unchanged'])
        self.assertTrue(window['complete'])
        self.assertEqual(window['producer_revision'], 2)
        for output in (result, window):
            self.assertFalse(output['contents_current'])
            self.assertFalse(output['coherent_capture'])
        self.assertFalse(result['autoscroll_authorized'])
        self.assertTrue(window['observed_window_only'])
        self.assertFalse(window['whole_folder'])

    def test_known_entry_before_rows_during_rows_or_after_end_rejects_old_stamp(self):
        # The exact crossing time is NOT encoded. These modeled histories
        # produce the same immutable producer stamp and later final counter.
        for boundary_position in ('before-first-row', 'between-row-and-terminal', 'after-end'):
            with self.subTest(history=boundary_position):
                result = self.decode(snapshot(producer_revision=2, current=3))
                window = result['windows'][0]
                self.assertTrue(window['observed_window_complete'])
                self.assertFalse(window['known_boundary_unchanged'])
                self.assertFalse(window['complete'])
                self.assertIn('known-contents-boundary', window['reasons'])
                self.assertFalse(result['contents_current'])

    def test_incomplete_window_is_not_repaired_by_equal_or_later_revision(self):
        for current in (2, 3):
            with self.subTest(current=current):
                window = self.decode(snapshot(events=[], current=current))['windows'][0]
                self.assertFalse(window['observed_window_complete'])
                self.assertFalse(window['complete'])
                self.assertIn('missing-end', window['reasons'])
                self.assertEqual(window['known_boundary_unchanged'], current == 2)

    def test_stale_job_starting_after_reset_and_already_active_writer_remain_unknown(self):
        for unobserved_history in ('queued-old-job-starts-after-reset', 'prior-writer-continues'):
            with self.subTest(history=unobserved_history):
                result = self.decode(snapshot(producer_revision=7, current=7))
                window = result['windows'][0]
                self.assertTrue(window['known_boundary_unchanged'])
                self.assertTrue(window['observed_window_complete'])
                self.assertFalse(window['contents_current'])
                self.assertFalse(result['autoscroll_authorized'])
        limitations = ' '.join(result['limitations'])
        self.assertIn('queued stale job', limitations)
        self.assertIn('already-active writer', limitations)
        self.assertIn('not per-owner', limitations)

    def test_raw_owner_job_list_aba_does_not_restore_an_old_revision(self):
        unchanged = self.decode(snapshot(producer_revision=1, current=1))
        reused = self.decode(snapshot(producer_revision=1, current=4))
        for field in ('frame', 'stmt', 'dest', 'origin', 'rows'):
            self.assertEqual(unchanged['windows'][0][field], reused['windows'][0][field])
        self.assertTrue(unchanged['windows'][0]['complete'])
        self.assertFalse(reused['windows'][0]['complete'])
        self.assertFalse(reused['contents_current'])

    def test_separate_producer_ids_keep_distinct_revisions_despite_identical_addresses(self):
        records = fixtures.receipts()
        records.append(dict(records[3]))
        first, second = fixtures.complete_events(4), fixtures.complete_events(5)
        events = [item for pair in zip(first, second) for item in pair]
        result = self.decode(snapshot(records=records, events=events,
                                      stamps={4: 1, 5: 3}, current=3))
        old, newer = result['windows']
        self.assertEqual([old['producer'], newer['producer']], [4, 5])
        self.assertEqual([old['producer_revision'], newer['producer_revision']], [1, 3])
        self.assertFalse(old['complete'])
        self.assertTrue(newer['complete'])
        self.assertFalse(old['contents_current'])
        self.assertFalse(newer['contents_current'])

    def test_zero_and_maximum_nonwrapping_revisions_are_valid_but_not_ready(self):
        for revision in (0, 0x7FFFFFFF):
            with self.subTest(revision=revision):
                result = self.decode(snapshot(producer_revision=revision, current=revision))
                self.assertTrue(result['windows'][0]['known_boundary_unchanged'])
                self.assertFalse(result['contents_current'])
                self.assertFalse(result['autoscroll_authorized'])
        result = self.decode(snapshot(records=[], events=[], current=17))
        self.assertEqual(result['windows'], [])
        self.assertFalse(result['contents_current'])

    def test_faulted_counter_reserved_state_and_wrong_size_or_capacities_reject(self):
        data = snapshot()
        candidates = [data[:-1], data + b'\0', data[:-16],
                      fixtures.mutate_word(data, PREFIX_SIZE, 0x80000000),
                      fixtures.mutate_word(data, PREFIX_SIZE, 0xFFFFFFFF)]
        candidates += [fixtures.mutate_word(data, PREFIX_SIZE + offset, 1) for offset in (4, 8, 12)]
        for candidate in candidates:
            with self.assertRaises(ValueError):
                self.decode(candidate)
        for field in ('capacity', 'row_capacity'):
            for value in (0, -1, True, 1.5, 1 << 32):
                args = dict(capacity=CAPACITY, row_capacity=ROW_CAPACITY)
                args[field] = value
                with self.assertRaises(ValueError):
                    decoder.decode(data, **args)
        with self.assertRaises(ValueError):
            self.decode('not bytes')

    def test_future_negative_encoded_or_nonproducer_stamps_reject(self):
        data = snapshot()
        for value in (3, 0x80000000, 0xFFFFFFFF):
            with self.subTest(stamp=value), self.assertRaises(ValueError):
                self.decode(fixtures.line_word(data, 4, 'reserved0', value))
        for token in (1, 2, 3):
            with self.subTest(token=token), self.assertRaises(ValueError):
                self.decode(fixtures.line_word(data, token, 'reserved0', 1))

    def test_all_event_stamps_must_mirror_the_original_producer_stamp(self):
        data = snapshot()
        for sequence in range(1, 6):
            with self.subTest(sequence=sequence), self.assertRaises(ValueError):
                self.decode(fixtures.row_word(data, sequence, 'reserved', 1))
        for producer in (0, 1, 3, 8):
            with self.subTest(producer=producer), self.assertRaises(ValueError):
                self.decode(fixtures.row_word(data, 1, 'producer', producer))

    def test_unallocated_extensions_and_all_unknown_reserved_fields_still_reject(self):
        data = snapshot()
        candidates = [fixtures.line_word(data, 8, 'reserved0', 2),
                      fixtures.row_word(data, 16, 'reserved', 2),
                      fixtures.line_word(data, 4, 'reserved1', 2),
                      fixtures.line_word(data, 4, 'flags', 2)]
        row_padding = LINEAGE_SIZE + 16 + 584
        candidates.append(fixtures.mutate_word(data, row_padding, 2))
        for candidate in candidates:
            with self.assertRaises(ValueError):
                self.decode(candidate)

    def test_base_strictness_for_magic_headers_lineage_metadata_and_paths_is_retained(self):
        data = snapshot()
        candidates = [fixtures.line_word(data, 4, 'magic', 0),
                      fixtures.line_word(data, 4, 'parent', 2),
                      fixtures.line_word(data, 4, 'site', 1),
                      fixtures.row_word(data, 1, 'magic', 0),
                      fixtures.row_word(data, 1, 'seq', 2),
                      fixtures.row_word(data, 1, 'frame', 1),
                      fixtures.row_word(data, 1, 'mode', 1),
                      fixtures.mutate_word(data, 4, 1),
                      fixtures.mutate_word(data, LINEAGE_SIZE, 0xFFFFFFFF)]
        for candidate in candidates:
            with self.assertRaises(ValueError):
                self.decode(candidate)
        events = fixtures.complete_events()
        events[0]['raw_path'] = b'x\0' * 260
        with self.assertRaises(ValueError):
            self.decode(snapshot(events=events))

    def test_semantic_base_errors_and_boundary_evidence_are_both_preserved(self):
        events = fixtures.complete_events()
        events[0]['result'] = -1
        window = self.decode(snapshot(events=events, current=3))['windows'][0]
        self.assertFalse(window['observed_window_complete'])
        self.assertFalse(window['complete'])
        self.assertIn('append-result-mismatch', window['reasons'])
        self.assertIn('known-contents-boundary', window['reasons'])

    def test_canonicalization_changes_only_two_extension_words_in_an_owned_copy(self):
        original = bytearray(snapshot())
        before = bytes(original)
        strict_decode = base.decode
        with patch.object(decoder.base, 'decode', wraps=strict_decode) as strict:
            self.decode(original)
        strict.assert_called_once()
        canonical = bytes(strict.call_args.args[0])
        allowed = set(range(16 + 3 * 64 + 56, 16 + 3 * 64 + 60))
        for index in range(5):
            start = LINEAGE_SIZE + 16 + index * fixtures.journal.RECORD + 60
            allowed.update(range(start, start + 4))
        differences = {index for index, (left, right) in
                       enumerate(zip(before[:PREFIX_SIZE], canonical)) if left != right}
        self.assertTrue(differences)
        self.assertLessEqual(differences, allowed)
        self.assertTrue(all(canonical[index] == 0 for index in allowed))
        self.assertEqual(bytes(original), before)
        result = self.decode(memoryview(original))
        result['windows'][0]['rows'][0]['path'] = 'changed output only'
        self.assertEqual(bytes(original), before)

    def test_cli_reads_explicit_local_bytes_and_never_claims_current_contents(self):
        output = StringIO()
        with patch.object(decoder.Path, 'read_bytes', return_value=snapshot()) as reader:
            with redirect_stdout(output):
                decoder.main(['owned.bin', '--capacity', str(CAPACITY),
                              '--row-capacity', str(ROW_CAPACITY)])
            reader.assert_called_once_with()
        result = json.loads(output.getvalue())
        self.assertFalse(result['contents_current'])
        self.assertFalse(result['autoscroll_authorized'])
        with patch.object(decoder.Path, 'read_bytes', return_value=b'bad'):
            with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as error:
                decoder.main(['owned.bin', '--capacity', str(CAPACITY),
                              '--row-capacity', str(ROW_CAPACITY)])
            self.assertEqual(error.exception.code, 2)


if __name__ == '__main__':
    unittest.main()
