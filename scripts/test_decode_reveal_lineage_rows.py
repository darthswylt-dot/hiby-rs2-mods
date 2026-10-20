#!/usr/bin/env python3
"""Owned byte fixtures for the strict offline lineage/row decoder."""

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
import struct
import unittest
from unittest.mock import patch

import decode_reveal_lineage_rows as decoder
import folderfollow_reveal_lineage_mips as lineage
import reveal_lineage_rows_mips as journal


CAPACITY, ROW_CAPACITY = 8, 16
MASK = 0xFFFFFFFF


def receipts():
    records = []
    for kind, parent, job, dest, stack, request, stmt in (
            (1, 0, 0x4000, 0, 0x3000, 0, 0),
            (3, 1, 0x5000, 0, 0xA770, 0, 0),
            (4, 2, 0x5000, 0x7000, 0xA730, 3, 0),
            (5, 3, 0x5000, 0x7000, 0x9000, 3, 0xA000)):
        item = dict.fromkeys(decoder.LINEAGE_FIELDS, 0)
        item.update(magic=lineage.MAGIC, kind=kind, origin=1, parent=parent,
                    view=0x1000, panel=0x2000, job=job, dest=dest,
                    site={1: 0x490758, 3: 0x48EB40, 4: 0x48D1B8, 5: 0x6ED624}[kind],
                    stack=stack, request=request, stmt=stmt)
        records.append(item)
    return records


def event(kind, ordinal, result, count, *, producer=4, path='', cue=0):
    item = dict.fromkeys(decoder.ROW_FIELDS, 0)
    item.update(magic=journal.MAGIC, kind=kind, producer=producer, frame=0x9000,
                stmt=0xA000, dest=0x7000, ordinal=ordinal, result=result,
                cue=cue, count=count, origin=1, path=path)
    return item


def complete_events(producer=4):
    return [event(1, 0, 0, 1, producer=producer, path='a:\\A\\one.flac', cue=-1),
            event(1, 1, 1, 2, producer=producer, path='b:\\B\\two.flac', cue=-(1 << 31)),
            event(2, 2, 101, 2, producer=producer),
            event(3, 2, 0, 2, producer=producer),
            event(4, 2, 2, 2, producer=producer)]


def snapshot(records=None, events=None):
    records = receipts() if records is None else records
    events = complete_events() if events is None else events
    data = bytearray(lineage.memory_bytes(CAPACITY) + journal.memory_bytes(ROW_CAPACITY))
    struct.pack_into('<I', data, 0, len(records))
    for index, item in enumerate(records):
        struct.pack_into('<16I', data, 16 + index * 64,
                         *(item[field] & MASK for field in decoder.LINEAGE_FIELDS))
    base = lineage.memory_bytes(CAPACITY)
    struct.pack_into('<I', data, base, len(events))
    for index, item in enumerate(events):
        item = dict(item, seq=index + 1)
        start = base + 16 + index * journal.RECORD
        struct.pack_into('<16I', data, start,
                         *(item[field] & MASK for field in decoder.ROW_FIELDS))
        if item['kind'] == 1:
            path = item.get('raw_path')
            if path is None:
                path = item['path'].encode('utf-16le') + b'\0\0'
            if len(path) > journal.PATH_BYTES:
                raise ValueError('test fixture path exceeds field')
            data[start + 64:start + 64 + len(path)] = path
    return bytes(data)


def mutate_word(data, offset, value):
    result = bytearray(data)
    struct.pack_into('<I', result, offset, value & MASK)
    return bytes(result)


def line_word(data, token, field, value):
    return mutate_word(data, 16 + (token - 1) * 64 + decoder.LINEAGE_FIELDS.index(field) * 4, value)


def row_word(data, sequence, field, value):
    return mutate_word(data, lineage.memory_bytes(CAPACITY) + 16
                       + (sequence - 1) * journal.RECORD + decoder.ROW_FIELDS.index(field) * 4, value)


class DecodeRevealLineageRowsTests(unittest.TestCase):
    def decode(self, data=None):
        return decoder.decode(snapshot() if data is None else data,
                              capacity=CAPACITY, row_capacity=ROW_CAPACITY)

    def window(self, records=None, events=None):
        return self.decode(snapshot(records, events))['windows'][0]

    def test_schema_matches_actual_native_journal_constants(self):
        self.assertEqual((decoder.ROW_HEADER, decoder.ROW_RECORD), (16, 592))
        for index, name in enumerate(('MAGIC_OFFSET', 'KIND', 'PRODUCER', 'SEQ', 'FRAME',
                                      'STMT', 'DEST', 'MODE', 'OFFSET', 'ORDINAL', 'RESULT',
                                      'CUE', 'TRUNCATED', 'COUNT', 'ORIGIN', 'RESERVED')):
            self.assertEqual(getattr(journal, name), index * 4)
        self.assertEqual((journal.PATH, journal.PATH_BYTES), (64, 520))

    def test_complete_window_preserves_exact_paths_signed_cues_and_no_authority(self):
        result = self.decode()
        window = result['windows'][0]
        self.assertTrue(window['complete'])
        self.assertEqual(window['reasons'], [])
        self.assertEqual(window['producer'], 4)
        self.assertEqual(window['observed_count'], 2)
        self.assertEqual([row['cue'] for row in window['rows']], [-1, -(1 << 31)])
        self.assertEqual(window['rows'][0]['result'], 0)
        self.assertEqual(window['rows'][1]['path'], 'b:\\B\\two.flac')
        # Different parents are not guessed to match an absent query scope.
        self.assertTrue(window['observed_window_only'])
        self.assertFalse(window['whole_folder'])
        self.assertFalse(result['autoscroll_authorized'])
        self.assertTrue(any('scope' in item for item in result['limitations']))
        self.assertNotIn('CompletedRows', result)

    def test_empty_window_with_zero_requested_count_is_valid(self):
        records = receipts()
        records[2]['request'] = records[3]['request'] = 0
        events = [event(2, 0, 101, 0), event(3, 0, 0, 0), event(4, 0, 0, 0)]
        window = self.window(records, events)
        self.assertTrue(window['complete'])
        self.assertEqual(window['rows'], [])

    def test_every_producer_is_reported_even_without_events(self):
        window = self.window(events=[])
        self.assertFalse(window['complete'])
        self.assertIn('no-events', window['reasons'])
        self.assertIn('missing-terminal', window['reasons'])
        self.assertIn('missing-reset', window['reasons'])
        self.assertIn('missing-end', window['reasons'])
        result = self.decode(snapshot([], []))
        self.assertEqual((result['receipts'], result['events'], result['windows']), ([], [], []))
        self.assertFalse(result['autoscroll_authorized'])

    def test_same_frame_list_and_statement_never_merge_distinct_producer_ids(self):
        records = receipts()
        records.append(dict(records[3]))
        first, second = complete_events(4), complete_events(5)
        events = [item for pair in zip(first, second) for item in pair]
        windows = self.decode(snapshot(records, events))['windows']
        self.assertEqual([window['producer'] for window in windows], [4, 5])
        self.assertTrue(all(window['complete'] for window in windows))

    def test_negative_offset_bad_requested_and_excess_rows_are_semantic_failures(self):
        for offset, request, reason in ((-1, 3, 'invalid-offset'),
                                        (0, -1, 'invalid-requested-count'),
                                        (0, 0, 'rows-exceed-requested-count')):
            with self.subTest(offset=offset, request=request):
                records, events = receipts(), complete_events()
                for record in records[2:]:
                    record.update(offset=offset, request=request)
                for item in events:
                    item['offset'] = offset
                window = self.window(records, events)
                self.assertFalse(window['complete'])
                self.assertIn(reason, window['reasons'])

    def test_exact_size_capacities_and_byte_input_are_required(self):
        data = snapshot()
        for candidate in (data[:-1], data + b'\0', '', 123):
            with self.subTest(candidate=type(candidate).__name__):
                with self.assertRaises(ValueError):
                    self.decode(candidate)
        for field in ('capacity', 'row_capacity'):
            for invalid in (0, -1, True, 1.5, 1 << 32):
                with self.subTest(field=field, invalid=invalid):
                    args = dict(capacity=CAPACITY, row_capacity=ROW_CAPACITY)
                    args[field] = invalid
                    with self.assertRaises(ValueError):
                        decoder.decode(data, **args)
        self.assertTrue(self.decode(memoryview(data))['windows'][0]['complete'])

    def test_allocator_fault_reserved_headers_and_unallocated_bytes_are_rejected(self):
        data = snapshot()
        for base, capacity, record in ((0, CAPACITY, 64),
                                       (lineage.memory_bytes(CAPACITY), ROW_CAPACITY, journal.RECORD)):
            for offset, value in ((base, 0xFFFFFFFF), (base, capacity + 1),
                                  (base + 4, 1), (base + 8, 1), (base + 12, 1),
                                  (base + 16 + (capacity - 1) * record, 1)):
                with self.subTest(base=base, offset=offset):
                    with self.assertRaises(ValueError):
                        self.decode(mutate_word(data, offset, value))

    def test_gaps_unpublished_slots_and_sequence_gaps_are_not_resynchronized(self):
        data = snapshot()
        bad = [line_word(data, 2, 'magic', 0), row_word(data, 2, 'magic', 0),
               row_word(data, 2, 'seq', 3), row_word(data, 1, 'seq', 0),
               mutate_word(data, 0, 3),
               mutate_word(data, lineage.memory_bytes(CAPACITY), 4)]
        for candidate in bad:
            with self.assertRaises(ValueError):
                self.decode(candidate)

    def test_lineage_parent_kinds_causality_originals_and_unused_fields_are_strict(self):
        data = snapshot()
        cases = [(1, 'kind', 6), (1, 'origin', 2), (1, 'parent', 1),
                 (2, 'parent', 0), (2, 'parent', 2), (3, 'parent', 1),
                 (4, 'parent', 2), (3, 'origin', 2), (2, 'view', 0x1111),
                 (4, 'panel', 0x2222), (1, 'flags', 1), (1, 'reserved0', 1),
                 (4, 'reserved1', 1), (2, 'dest', 7), (3, 'stmt', 7),
                 (3, 'job', 1), (3, 'stack', 1), (4, 'job', 1),
                 (4, 'dest', 1), (4, 'offset', 1), (4, 'request', 1),
                 (4, 'stack', 1), (1, 'site', 0), (3, 'site', 0)]
        for token, field, value in cases:
            with self.subTest(token=token, field=field):
                with self.assertRaises(ValueError):
                    self.decode(line_word(data, token, field, value))

    def test_event_receipt_and_metadata_mismatch_are_structural_errors(self):
        data = snapshot()
        cases = [('producer', 0), ('producer', 3), ('producer', 8), ('kind', 5),
                 ('frame', 1), ('stmt', 1), ('dest', 1), ('offset', 1),
                 ('origin', 2), ('mode', 1), ('reserved', 1)]
        for field, value in cases:
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    self.decode(row_word(data, 1, field, value))
        base = lineage.memory_bytes(CAPACITY) + 16
        with self.assertRaises(ValueError):
            self.decode(mutate_word(data, base + 584, 1))
        for field in ('cue', 'truncated'):
            with self.assertRaises(ValueError):
                self.decode(row_word(data, 3, field, 1))

    def test_invalid_utf16_truncation_unterminated_and_nonzero_padding_reject_capture(self):
        for raw, flag in ((b'\0\xd8\0\0', 0), (b'x\0' * 260, 0),
                          ('ok'.encode('utf-16le') + b'\0\0x\0', 0),
                          (b'\0\0', 1), (b'\0\0', 2)):
            with self.subTest(flag=flag, prefix=raw[:8]):
                events = complete_events()
                events[0].update(raw_path=raw, truncated=flag)
                with self.assertRaises(ValueError):
                    self.window(events=events)
        data = snapshot()
        base = lineage.memory_bytes(CAPACITY) + 16 + 2 * journal.RECORD
        with self.assertRaises(ValueError):
            self.decode(mutate_word(data, base + 64, 1))

    def test_supported_path_boundary_and_signed_cue_extremes(self):
        events = [event(1, index, index, index + 1,
                        path=('x' * 259 if index == 0 else f'row{index}'), cue=cue)
                  for index, cue in enumerate((-(1 << 31), -1, (1 << 31) - 1))]
        events += [event(2, 3, 101, 3), event(3, 3, 0, 3), event(4, 3, 3, 3)]
        window = self.window(events=events)
        self.assertTrue(window['complete'])
        self.assertEqual([row['cue'] for row in window['rows']], [-(1 << 31), -1, (1 << 31) - 1])

    def test_append_failures_ordinals_counts_duplicate_identities_and_empty_path_fail_window(self):
        for overrides, reason in (({'result': -1}, 'append-result-mismatch'),
                                   ({'ordinal': 1}, 'row-ordinal-mismatch'),
                                   ({'count': 0}, 'append-count-mismatch'),
                                   ({'path': ''}, 'empty-row-path')):
            with self.subTest(overrides=overrides):
                events = complete_events()
                events[0].update(overrides)
                window = self.window(events=events)
                self.assertFalse(window['complete'])
                self.assertIn(reason, window['reasons'])
        events = complete_events()
        events[1].update(path=events[0]['path'], cue=events[0]['cue'])
        self.assertIn('duplicate-row-identity', self.window(events=events)['reasons'])

    def test_missing_terminal_reset_end_and_non_success_results_fail_window(self):
        for index, result in ((2, 100), (2, -1), (3, 19), (3, -1), (4, -1), (4, 1)):
            with self.subTest(index=index, result=result):
                events = complete_events()
                events[index]['result'] = result
                self.assertFalse(self.window(events=events)['complete'])
        for index in (2, 3, 4):
            events = complete_events()
            del events[index]
            self.assertFalse(self.window(events=events)['complete'])
        # A bind-error END without SQL terminal must not synthesize success.
        self.assertFalse(self.window(events=[event(4, 0, -1, 0)])['complete'])

    def test_duplicate_out_of_order_and_after_end_events_fail_window(self):
        original = complete_events()
        cases = [original[:3] + [original[2]] + original[3:],
                 original[:4] + [original[3]] + original[4:],
                 original + [original[4]], original + [original[0]],
                 [original[3]] + original[:3] + original[4:],
                 original[:3] + [original[0]] + original[3:]]
        for events in cases:
            with self.subTest(kinds=[item['kind'] for item in events]):
                self.assertFalse(self.window(events=events)['complete'])
        for index in (2, 3, 4):
            events = complete_events()
            events[index]['count'] = 1
            self.assertFalse(self.window(events=events)['complete'])

    def test_cli_reads_only_explicit_local_bytes_and_reports_json(self):
        output = StringIO()
        with patch.object(decoder.Path, 'read_bytes', return_value=snapshot()) as reader:
            with redirect_stdout(output):
                decoder.main(['owned.bin', '--capacity', str(CAPACITY),
                              '--row-capacity', str(ROW_CAPACITY)])
            reader.assert_called_once_with()
        self.assertTrue(json.loads(output.getvalue())['windows'][0]['complete'])
        with patch.object(decoder.Path, 'read_bytes', return_value=b'bad'):
            with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as error:
                decoder.main(['owned.bin', '--capacity', str(CAPACITY),
                              '--row-capacity', str(ROW_CAPACITY)])
            self.assertEqual(error.exception.code, 2)


if __name__ == '__main__':
    unittest.main()
