#!/usr/bin/env python3
"""LQBR parser fixtures are private history, never fresh/current UI authority."""

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
import struct
import unittest
from unittest.mock import patch

import decode_reveal_queue_birth as decoder


CAPACITY = 12


def event(kind=decoder.BIRTH, *, seq=1, parent=None, origin=1,
          engine=0x90001000, input=0x7FFF4000, copy=None,
          metadata=0xFFFFFFFF, frame=0x7FFF1000, revision=10, scope=4,
          result=0, magic=decoder.MAGIC, site=None):
    if parent is None:
        parent = {decoder.BIRTH: 0, decoder.ENQUEUE_BEGIN: 1,
                  decoder.RETURN: 2}[kind]
    if copy is None:
        copy = 0 if kind == decoder.BIRTH else 0x90004000
    if site is None:
        site = decoder.SITES[kind]
    return dict(magic=magic, kind=kind, parent=parent, origin=origin,
                seq=seq, engine=engine, input=input, copy=copy,
                metadata=metadata, frame=frame, site=site, result=result,
                revision=revision, scope=scope, reserved0=0, reserved1=0)


def sequence(*, revision=10, scope=4, result=0x90005001):
    return [event(revision=revision, scope=scope),
            event(decoder.ENQUEUE_BEGIN, seq=2, revision=revision, scope=scope),
            event(decoder.RETURN, seq=3, revision=revision, scope=scope, result=result)]


def snapshot(records=(), *, counter=None, capacity=CAPACITY):
    if counter is None:
        counter = len(records)
    data = bytearray(decoder.memory_bytes(capacity))
    struct.pack_into('<I', data, 0, counter)
    for index, item in enumerate(records):
        struct.pack_into('<16I', data, decoder.HEADER + index * decoder.RECORD,
                         *(item[field] for field in decoder.FIELDS))
    return bytes(data)


def word(data, offset, value):
    changed = bytearray(data)
    struct.pack_into('<I', changed, offset, value)
    return bytes(changed)


def record_word(data, seq, field, value):
    return word(data, decoder.HEADER + (seq - 1) * decoder.RECORD
                + decoder.FIELDS.index(field) * 4, value)


def decode(data=None, *, current_revision=None):
    return decoder.decode(snapshot(sequence()) if data is None else data,
                          capacity=CAPACITY, current_revision=current_revision)


class DecodeRevealQueueBirthTests(unittest.TestCase):
    def assert_no_authority(self, output):
        for field in decoder.AUTHORITY_FLAGS:
            self.assertIs(output[field], False, field)

    def test_exact_three_event_history_is_only_an_observed_sequence(self):
        result = decode(current_revision=10)
        request = result['requests'][0]
        self.assertEqual(result['format'], 'queue-birth-observation-v1')
        self.assertEqual(result['counter'], 3)
        self.assertEqual(request['birth'], 1)
        self.assertEqual(request['origin'], 1)
        self.assertEqual(request['event_sequences'], [1, 2, 3])
        self.assertEqual(request['event_kinds'], [1, 2, 3])
        self.assertTrue(request['observed_enqueue_sequence_complete'])
        self.assertTrue(request['queue_return_observed'])
        self.assertEqual(request['append_return'], 0x90005001)
        self.assertTrue(request['append_nonzero'])
        self.assertTrue(request['known_boundary_unchanged'])
        self.assertTrue(request['observed_scopes_quiet'])
        self.assertFalse(request['born_while_known_scope_active'])
        self.assertEqual(request['reasons'], [])
        self.assert_no_authority(result)
        self.assert_no_authority(request)
        self.assertNotIn('success', request)
        self.assertNotIn('row_origins', result)

    def test_missing_current_sample_only_preserves_equal_historical_samples(self):
        result = decode()
        self.assertIsNone(result['known_contents_revision'])
        self.assertTrue(result['requests'][0]['known_boundary_unchanged'])
        self.assert_no_authority(result['requests'][0])

    def test_empty_journal_never_establishes_coverage_or_freshness(self):
        result = decode(snapshot())
        self.assertEqual(result['requests'], [])
        self.assertEqual(result['events'], [])
        self.assertFalse(result['capacity_full'])
        self.assert_no_authority(result)
        joined = ' '.join(result['limitations'])
        for text in ('coverage', 'not yet transported', 'never by',
                     'native pointer', 'capture coherence', 'opaque scalar'):
            self.assertIn(text, joined)

    def test_partial_birth_or_enqueue_does_not_grant_unchanged_or_quiet(self):
        for count in (1, 2):
            with self.subTest(count=count):
                result = decode(snapshot(sequence()[:count]), current_revision=10)
                request = result['requests'][0]
                self.assertFalse(request['observed_enqueue_sequence_complete'])
                self.assertFalse(request['queue_return_observed'])
                self.assertIsNone(request['append_return'])
                self.assertIsNone(request['append_nonzero'])
                self.assertFalse(request['known_boundary_unchanged'])
                self.assertFalse(request['observed_scopes_quiet'])
                self.assertIn('enqueue-event-sequence', request['reasons'])
                self.assert_no_authority(request)

    def test_all_actual_append_returns_remain_unsigned_opaque_scalars(self):
        for value in (0, 1, 3, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF):
            with self.subTest(value=value):
                request = decode(snapshot(sequence(result=value)))['requests'][0]
                self.assertEqual(request['append_return'], value)
                self.assertEqual(request['append_nonzero'], value != 0)
                self.assertTrue(request['observed_enqueue_sequence_complete'])
                self.assert_no_authority(request)

    def test_later_current_boundary_narrows_without_repairing_sequence(self):
        request = decode(current_revision=11)['requests'][0]
        self.assertTrue(request['observed_enqueue_sequence_complete'])
        self.assertFalse(request['known_boundary_unchanged'])
        self.assertIn('known-boundary-unchanged-not-observed', request['reasons'])
        self.assert_no_authority(request)

    def test_changed_chain_revision_narrows_unchanged_observation(self):
        records = sequence()
        records[1]['revision'] = 11
        records[2]['revision'] = 12
        request = decode(snapshot(records), current_revision=12)['requests'][0]
        self.assertTrue(request['observed_enqueue_sequence_complete'])
        self.assertFalse(request['known_boundary_unchanged'])
        self.assertEqual(request['birth_revision'], 10)
        self.assert_no_authority(request)

    def test_parent_chain_revision_regression_is_rejected(self):
        data = snapshot(sequence())
        for seq in (2, 3):
            with self.subTest(seq=seq), self.assertRaisesRegex(ValueError, 'revision regressed'):
                decode(record_word(data, seq, 'revision', 9))

    def test_scope_active_at_any_observed_point_prevents_quiet_claim(self):
        for seq in (1, 2, 3):
            with self.subTest(seq=seq):
                data = record_word(snapshot(sequence()), seq, 'scope', 4 | 1 << 16)
                request = decode(data)['requests'][0]
                self.assertFalse(request['observed_scopes_quiet'])
                self.assertEqual(request['born_while_known_scope_active'], seq == 1)
                self.assertTrue(request['observed_enqueue_sequence_complete'])
                self.assertTrue(request['known_boundary_unchanged'])
                self.assert_no_authority(request)

    def test_scope_issued_can_increase_and_active_can_close_or_reopen(self):
        records = sequence(scope=1 | 1 << 16)
        records[1]['scope'] = 2
        records[2]['scope'] = 3 | 2 << 16
        request = decode(snapshot(records))['requests'][0]
        self.assertTrue(request['born_while_known_scope_active'])
        self.assertFalse(request['observed_scopes_quiet'])
        self.assertTrue(request['observed_enqueue_sequence_complete'])

    def test_scope_issued_regression_within_exact_chain_is_rejected(self):
        data = snapshot(sequence())
        for seq in (2, 3):
            with self.subTest(seq=seq), self.assertRaisesRegex(ValueError, 'tickets regressed'):
                decode(record_word(data, seq, 'scope', 3))

    def test_scope_zero_and_maximum_nonfault_states_are_valid_samples(self):
        for state in (0, 1, 0xFFFF, 0x7FFFFFFF):
            with self.subTest(state=state):
                request = decode(snapshot(sequence(scope=state)))['requests'][0]
                self.assertEqual(request['birth_scope_state'], state)
                self.assertEqual(request['observed_scopes_quiet'], state >> 16 == 0)
                self.assert_no_authority(request)

    def test_scope_highbit_fault_or_more_active_than_issued_is_rejected(self):
        data = snapshot(sequence())
        for state in (0xFFFFFFFF, 0x80000000, 0x80000001,
                      1 << 16, 2 << 16 | 1, 0x7FFF0000):
            for seq in (1, 2, 3):
                with self.subTest(state=state, seq=seq), self.assertRaises(ValueError):
                    decode(record_word(data, seq, 'scope', state))

    def test_duplicate_begin_is_retained_but_never_a_complete_sequence(self):
        records = sequence()
        records.append(event(decoder.ENQUEUE_BEGIN, seq=4, copy=0x90009000))
        request = decode(snapshot(records))['requests'][0]
        self.assertEqual(request['event_kinds'], [1, 2, 3, 2])
        self.assertFalse(request['observed_enqueue_sequence_complete'])
        self.assertTrue(request['queue_return_observed'])
        self.assertFalse(request['known_boundary_unchanged'])
        self.assertFalse(request['observed_scopes_quiet'])

    def test_duplicate_return_does_not_select_one_as_the_append_result(self):
        records = sequence()
        records.append(event(decoder.RETURN, seq=4, result=1))
        request = decode(snapshot(records))['requests'][0]
        self.assertFalse(request['observed_enqueue_sequence_complete'])
        self.assertTrue(request['queue_return_observed'])
        self.assertIsNone(request['append_return'])
        self.assertIsNone(request['append_nonzero'])
        self.assert_no_authority(request)

    def test_distinct_birth_ids_with_reused_addresses_are_never_merged(self):
        records = sequence()
        records.extend([event(seq=4, origin=4),
                        event(decoder.ENQUEUE_BEGIN, seq=5, parent=4, origin=4),
                        event(decoder.RETURN, seq=6, parent=5, origin=4, result=3)])
        requests = decode(snapshot(records))['requests']
        self.assertEqual([request['birth'] for request in requests], [1, 4])
        self.assertEqual([request['event_sequences'] for request in requests],
                         [[1, 2, 3], [4, 5, 6]])
        self.assertTrue(all(request['observed_enqueue_sequence_complete'] for request in requests))
        for request in requests:
            self.assert_no_authority(request)

    def test_independent_reservation_order_is_not_native_chronology(self):
        records = [event(revision=20, scope=7),
                   event(seq=2, origin=2, revision=10, scope=4),
                   event(decoder.ENQUEUE_BEGIN, seq=3, parent=1, revision=20, scope=7),
                   event(decoder.ENQUEUE_BEGIN, seq=4, parent=2, origin=2, revision=10, scope=4),
                   event(decoder.RETURN, seq=5, parent=3, revision=20, scope=7),
                   event(decoder.RETURN, seq=6, parent=4, origin=2, revision=10, scope=4)]
        result = decode(snapshot(records), current_revision=20)
        self.assertEqual([request['event_sequences'] for request in result['requests']],
                         [[1, 3, 5], [2, 4, 6]])
        self.assertTrue(result['requests'][0]['known_boundary_unchanged'])
        self.assertFalse(result['requests'][1]['known_boundary_unchanged'])
        self.assertTrue(all(request['observed_enqueue_sequence_complete']
                            for request in result['requests']))

    def test_birth_ancestry_copy_and_result_words_are_strict(self):
        data = snapshot(sequence())
        for field, values in (('parent', (1, 2, 0xFFFFFFFF)),
                              ('origin', (0, 2, 0xFFFFFFFF)),
                              ('copy', (1, 0x90004000)), ('result', (1, 0xFFFFFFFF))):
            for value in values:
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    decode(record_word(data, 1, field, value))

    def test_birth_requires_positive_aligned_engine_input_and_frame_only(self):
        data = snapshot(sequence())
        for field in ('engine', 'input', 'frame'):
            for value in (0, 1, 2, 3, 0xFFFFFFFF):
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    decode(record_word(data, 1, field, value))
        records = sequence()
        for item in records:
            item.update(engine=0xFFFFFFFC, input=4, frame=8, metadata=3)
        result = decode(snapshot(records))
        self.assertEqual(result['requests'][0]['metadata'], 3)
        self.assertTrue(result['requests'][0]['observed_enqueue_sequence_complete'])

    def test_children_require_prior_published_exact_parent_kinds(self):
        data = snapshot(sequence())
        for seq, values in ((2, (0, 2, 3, 0xFFFFFFFF)), (3, (0, 1, 3, 0xFFFFFFFF))):
            for value in values:
                with self.subTest(seq=seq, parent=value), self.assertRaises(ValueError):
                    decode(record_word(data, seq, 'parent', value))

    def test_children_cannot_change_any_immutable_parent_binding(self):
        data = snapshot(sequence())
        for seq in (2, 3):
            for field in ('origin', 'engine', 'input', 'metadata', 'frame'):
                value = 2 if field == 'origin' else 0x90009000
                with self.subTest(seq=seq, field=field), self.assertRaisesRegex(ValueError, 'binding mismatch'):
                    decode(record_word(data, seq, field, value))

    def test_return_cannot_borrow_copy_of_another_enqueue(self):
        data = snapshot(sequence())
        for copy in (0, 1, 0x90009000):
            with self.subTest(copy=copy), self.assertRaisesRegex(ValueError, 'copy binding mismatch'):
                decode(record_word(data, 3, 'copy', copy))

    def test_enqueue_requires_positive_aligned_copy_and_zero_begin_result(self):
        data = snapshot(sequence())
        for value in (0, 1, 2, 3, 0xFFFFFFFF):
            with self.subTest(copy=value), self.assertRaises(ValueError):
                decode(record_word(data, 2, 'copy', value))
        for value in (1, 0xFFFFFFFF):
            with self.subTest(result=value), self.assertRaises(ValueError):
                decode(record_word(data, 2, 'result', value))

    def test_invalid_kinds_sites_sequences_magic_and_reserved_words_rejected(self):
        data = snapshot(sequence())
        for seq in (1, 2, 3):
            for field, values in (('kind', (0, 4, 0xFFFFFFFF)),
                                  ('site', (0, 0x8B4288, 0x8B42EC)),
                                  ('seq', (0, seq + 1, 0xFFFFFFFF)),
                                  ('magic', (0, 1, 0xFFFFFFFF)),
                                  ('reserved0', (1,)), ('reserved1', (0xFFFFFFFF,))):
                for value in values:
                    with self.subTest(seq=seq, field=field, value=value), self.assertRaises(ValueError):
                        decode(record_word(data, seq, field, value))
        for seq in (1, 2, 3):
            other_site = decoder.SITES[decoder.RETURN if seq != 3 else decoder.BIRTH]
            with self.subTest(seq=seq), self.assertRaisesRegex(ValueError, 'source site'):
                decode(record_word(data, seq, 'site', other_site))

    def test_allocated_unpublished_or_zero_slot_is_not_silently_omitted(self):
        for data in (snapshot(counter=1), snapshot(sequence()[:1], counter=2),
                     record_word(snapshot(sequence()), 2, 'magic', 0)):
            with self.subTest(data=data[:20]), self.assertRaisesRegex(ValueError, 'unpublished'):
                decode(data)

    def test_faulted_counter_reserved_header_and_dirty_unallocated_tail_rejected(self):
        data = snapshot(sequence())
        for counter in (decoder.FAULT, CAPACITY + 1, 0x80000000):
            with self.subTest(counter=counter), self.assertRaises(ValueError):
                decode(word(data, 0, counter))
        for offset in (4, 8, 12):
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                decode(word(data, offset, 1))
        for seq in (4, CAPACITY):
            for field in decoder.FIELDS:
                with self.subTest(seq=seq, field=field), self.assertRaisesRegex(ValueError, 'unallocated'):
                    decode(record_word(data, seq, field, 1))

    def test_full_buffer_does_not_claim_unobserved_request_coverage(self):
        records = sequence()
        result = decoder.decode(snapshot(records, capacity=3), capacity=3)
        self.assertTrue(result['capacity_full'])
        self.assertTrue(result['requests'][0]['observed_enqueue_sequence_complete'])
        self.assert_no_authority(result)
        self.assertIn('capacity-full', ' '.join(result['limitations']))

    def test_current_revision_types_bounds_and_prior_sample_rejected(self):
        for current in (True, False, -1, 1.0, '10', 0x80000000, 0xFFFFFFFF):
            with self.subTest(current=current), self.assertRaises(ValueError):
                decode(current_revision=current)
        with self.assertRaisesRegex(ValueError, 'beyond the known counter'):
            decode(current_revision=9)
        for value in (0x80000000, 0xFFFFFFFF):
            with self.subTest(event_revision=value), self.assertRaises(ValueError):
                decode(record_word(snapshot(sequence()), 1, 'revision', value))
        for value in (0, 0x7FFFFFFF):
            result = decode(snapshot(sequence(revision=value)), current_revision=value)
            self.assertTrue(result['requests'][0]['known_boundary_unchanged'])

    def test_exact_owned_buffers_and_capacity_bounds_are_required(self):
        data = snapshot(sequence())
        for raw in (b'', data[:-1], data + b'\0', '', None, 1, []):
            with self.subTest(raw_type=type(raw)), self.assertRaises(ValueError):
                decoder.decode(raw, capacity=CAPACITY)
        for capacity in (True, False, 0, -1, 1.0, '1', decoder.MAX_CAPACITY + 1, 1 << 32):
            with self.subTest(capacity=capacity), self.assertRaises(ValueError):
                decoder.decode(data, capacity=capacity)
        self.assertEqual(decoder.memory_bytes(1), 80)
        self.assertEqual(decoder.memory_bytes(decoder.MAX_CAPACITY),
                         16 + 64 * decoder.MAX_CAPACITY)

    def test_owned_bytes_and_returned_objects_are_independent(self):
        data = bytearray(snapshot(sequence()))
        original = bytes(data)
        result = decoder.decode(memoryview(data), capacity=CAPACITY)
        result['requests'][0]['input'] = 0
        result['requests'][0]['reasons'].append('output only')
        result['events'][0]['input'] = 0
        result['limitations'].append('output only')
        self.assertEqual(bytes(data), original)
        another = decode()
        self.assertNotIn('output only', another['limitations'])
        self.assertNotIn('output only', another['requests'][0]['reasons'])
        self.assertNotEqual(another['events'][0]['input'], 0)

    def test_old_and_new_births_with_same_values_never_become_freshness_proof(self):
        old = decode(snapshot(sequence(revision=5)), current_revision=10)
        new = decode(snapshot(sequence(revision=10)), current_revision=10)
        self.assertFalse(old['requests'][0]['known_boundary_unchanged'])
        self.assertTrue(new['requests'][0]['known_boundary_unchanged'])
        for output in (old, old['requests'][0], new, new['requests'][0]):
            self.assert_no_authority(output)
        self.assertEqual(old['requests'][0]['input'], new['requests'][0]['input'])
        self.assertEqual(old['requests'][0]['birth'], new['requests'][0]['birth'])

    def test_cli_decodes_owned_local_buffer_and_explicit_revision(self):
        output = StringIO()
        with patch.object(decoder.Path, 'read_bytes', return_value=snapshot(sequence())) as reader:
            with redirect_stdout(output):
                decoder.main(['owned.bin', '--capacity', str(CAPACITY), '--current-revision', '10'])
            reader.assert_called_once_with()
        result = json.loads(output.getvalue())
        self.assertTrue(result['requests'][0]['known_boundary_unchanged'])
        self.assert_no_authority(result)

    def test_cli_reports_malformed_buffers_and_read_failures(self):
        for failure in (b'bad', OSError('unavailable')):
            kwargs = dict(side_effect=failure) if isinstance(failure, OSError) else dict(return_value=failure)
            with patch.object(decoder.Path, 'read_bytes', **kwargs):
                with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as error:
                    decoder.main(['owned.bin', '--capacity', str(CAPACITY)])
                self.assertEqual(error.exception.code, 2)


if __name__ == '__main__':
    unittest.main()
