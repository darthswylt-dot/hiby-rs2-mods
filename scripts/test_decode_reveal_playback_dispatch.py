#!/usr/bin/env python3
"""Strict owned-byte LPDI parsing, never callback/UI/playback authority."""

import contextlib
import io
import json
import struct
import unittest
from unittest import mock

import decode_reveal_playback_dispatch as decoder


CAPACITY = 4


def event(seq=1, kind=decoder.FAST, **changes):
    site = decoder.SITES.get(kind, 0)
    result = dict(magic=decoder.MAGIC, kind=kind, parent=0, origin=seq,
                  seq=seq, frame=0x2002000, site=site, return_pc=site + 8,
                  target=0x12345679, context=0, descriptor=decoder.DESCRIPTOR,
                  player=decoder.PLAYER,
                  reserved0=0, reserved1=0, reserved2=0, reserved3=0)
    result.update(changes)
    return result


def snapshot(*events, capacity=CAPACITY, counter=None, header_reserved=(0, 0, 0)):
    raw = bytearray(decoder.memory_bytes(capacity))
    struct.pack_into('<4I', raw, 0, len(events) if counter is None else counter,
                     *header_reserved)
    for index, item in enumerate(events):
        struct.pack_into('<16I', raw, decoder.HEADER + index * decoder.RECORD,
                         *(item[field] for field in decoder.FIELDS))
    return bytes(raw)


class DecodeRevealPlaybackDispatchTests(unittest.TestCase):
    def decode(self, raw, *, capacity=CAPACITY):
        return decoder.decode(raw, capacity=capacity)

    def assert_deny(self, result):
        self.assertEqual(result['decision'], 'deny')
        for name in (*decoder.AUTHORITY_FLAGS, *decoder.OBSERVATION_FLAGS):
            self.assertIs(result[name], False, name)

    def assert_refused(self, *events, **options):
        with self.assertRaises(ValueError):
            self.decode(snapshot(*events, **options))

    def test_constants_pin_the_independent_64_byte_call_intent_schema(self):
        self.assertEqual((decoder.HEADER, decoder.RECORD), (16, 64))
        self.assertEqual(struct.pack('<I', decoder.MAGIC), b'LPDI')
        self.assertEqual(decoder.FIELDS,
                         ('magic', 'kind', 'parent', 'origin', 'seq', 'frame',
                          'site', 'return_pc', 'target', 'context', 'descriptor',
                          'player', 'reserved0', 'reserved1', 'reserved2', 'reserved3'))
        self.assertEqual(decoder.SITES, {1: 0x42CC0C, 2: 0x42D6A0})
        self.assertEqual((decoder.PLAYER, decoder.DESCRIPTOR), (0xADD368, 0xADD468))

    def test_capacity_is_nonempty_exact_int_and_unsigned_32_bounded(self):
        self.assertEqual(decoder.memory_bytes(1), 80)
        self.assertLessEqual(decoder.memory_bytes(decoder.MAX_CAPACITY), 0x100000000)
        for value in (True, False, 0, -1, 1.0, '4', None, decoder.MAX_CAPACITY + 1):
            with self.subTest(value=value), self.assertRaises(ValueError):
                decoder.memory_bytes(value)

    def test_empty_snapshot_is_not_complete_coverage_or_authority(self):
        result = self.decode(snapshot())
        self.assertEqual(result['format'], 'playback-dispatch-observation-v1')
        self.assertEqual((result['counter'], result['observed_call_intents']), (0, 0))
        self.assertEqual(result['events'], [])
        self.assertFalse(result['capacity_full'])
        self.assert_deny(result)

    def test_fast_and_general_records_retain_only_their_explicit_self_origins(self):
        supplied = (event(), event(2, decoder.GENERAL, context=0xBAD00001))
        result = self.decode(snapshot(*supplied))
        self.assertEqual((result['counter'], result['observed_call_intents']), (2, 2))
        self.assertEqual([item['origin'] for item in result['events']], [1, 2])
        self.assertEqual([item['parent'] for item in result['events']], [0, 0])
        for item, expected in zip(result['events'], supplied):
            for field in decoder.FIELDS[1:12]:
                self.assertEqual(item[field], expected[field], field)
            self.assertNotIn('magic', item)
            self.assertFalse(any(field.startswith('reserved') for field in item))
            self.assertEqual(item['observation'], 'CALL_INTENT-only')
            self.assert_deny(item)
        self.assert_deny(result)

    def test_already_owned_bytes_bytearray_and_memoryview_are_copied(self):
        raw = snapshot(event())
        mutable = bytearray(raw)
        expected = self.decode(raw)
        for data in (mutable, memoryview(mutable)):
            self.assertEqual(self.decode(data), expected)
        mutable[:] = bytes(len(mutable))
        self.assertEqual(expected['events'][0]['target'], 0x12345679)

    def test_no_dictionary_summary_or_other_host_object_is_decoder_input(self):
        for value in ({}, {'events': [event()]}, [], (), 'LPDI', None, 80):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.decode(value)

    def test_exact_capacity_size_rejects_prefix_truncation_suffix_and_other_journals(self):
        raw = snapshot(event())
        for data in (b'', raw[:-1], raw + b'\0', raw[16:], snapshot(event(), capacity=3)):
            with self.subTest(length=len(data)), self.assertRaises(ValueError):
                self.decode(data)

    def test_all_reserved_header_words_are_strictly_zero(self):
        for index in range(3):
            reserved = [0, 0, 0]
            reserved[index] = 1
            with self.subTest(index=index):
                self.assert_refused(header_reserved=reserved)

    def test_fault_and_counter_past_capacity_are_refused_even_with_zero_records(self):
        for counter in (decoder.FAULT, CAPACITY + 1, 0x80000000):
            with self.subTest(counter=counter):
                self.assert_refused(counter=counter)

    def test_reserved_unpublished_slot_is_not_repaired_by_a_later_valid_record(self):
        self.assert_refused(counter=1)
        self.assert_refused(event(), event(2, magic=0), event(3), counter=3)
        self.assert_refused(event(magic=0), event(2), counter=2)

    def test_any_nonzero_unallocated_slot_is_refused_including_the_last(self):
        self.assert_refused(event(), counter=0)
        raw = bytearray(snapshot(event()))
        raw[-1] = 1
        with self.assertRaises(ValueError):
            self.decode(raw)

    def test_other_magic_is_not_a_compatible_private_journal(self):
        for magic in (int.from_bytes(b'LQBR', 'little'), 1, decoder.FAULT):
            with self.subTest(magic=magic):
                self.assert_refused(event(magic=magic))

    def test_only_the_two_pinned_call_intent_kinds_are_accepted(self):
        for kind in (0, 3, 0xFFFFFFFF):
            with self.subTest(kind=kind):
                self.assert_refused(event(kind=kind))

    def test_kind_and_original_native_site_must_match_exactly(self):
        for kind in (decoder.FAST, decoder.GENERAL):
            for site in (0, decoder.SITES[3 - kind], decoder.SITES[kind] - 4):
                with self.subTest(kind=kind, site=site):
                    self.assert_refused(event(kind=kind, site=site))

    def test_return_pc_is_the_original_jalr_site_plus_eight_not_wrapper_or_callback_return(self):
        for kind in (decoder.FAST, decoder.GENERAL):
            for delta in (0, 4, 12, 0x100):
                with self.subTest(kind=kind, delta=delta):
                    self.assert_refused(event(kind=kind, return_pc=decoder.SITES[kind] + delta))

    def test_parent_is_always_zero_and_never_an_earlier_call_or_queue_birth(self):
        for parent in (1, 2, 0xFFFFFFFF):
            with self.subTest(parent=parent):
                self.assert_refused(event(), event(2, parent=parent))

    def test_each_origin_is_its_own_sequence_not_a_matching_target_or_frame_group(self):
        for origin in (0, 1, 3, 0xFFFFFFFF):
            with self.subTest(origin=origin):
                self.assert_refused(event(), event(2, origin=origin))

    def test_sequence_is_contiguous_in_physical_reservation_slots(self):
        for seq in (0, 2, 0xFFFFFFFF):
            with self.subTest(seq=seq):
                self.assert_refused(event(seq=seq))
        self.assert_refused(event(), event(seq=1))
        self.assert_refused(event(2), event(1))

    def test_frame_is_nonzero_aligned_scalar_without_any_live_frame_lease(self):
        for frame in (0, 1, 2, 0xFFFFFFFF):
            with self.subTest(frame=frame):
                self.assert_refused(event(frame=frame))
        result = self.decode(snapshot(event(frame=0xFFFFFFFC)))
        self.assertEqual(result['events'][0]['frame'], 0xFFFFFFFC)
        self.assert_deny(result['events'][0])

    def test_zero_target_is_not_a_call_intent(self):
        self.assert_refused(event(target=0))

    def test_target_is_raw_nonzero_uint32_not_required_to_be_aligned_or_mapped(self):
        for target in (1, 2, 0x12345679, 0xFFFFFFFF):
            with self.subTest(target=target):
                result = self.decode(snapshot(event(target=target)))
                self.assertEqual(result['events'][0]['target'], target)
                self.assert_deny(result['events'][0])

    def test_context_is_arbitrary_raw_uint32_including_zero_and_unaligned(self):
        for context in (0, 1, 2, 0xFFFFFFFF):
            with self.subTest(context=context):
                result = self.decode(snapshot(event(context=context)))
                self.assertEqual(result['events'][0]['context'], context)
                self.assert_deny(result['events'][0])

    def test_player_and_descriptor_are_exact_source_scalars_not_lookup_keys(self):
        for changes in ({'player': 0}, {'player': decoder.PLAYER + 4},
                        {'descriptor': 0}, {'descriptor': decoder.DESCRIPTOR + 4}):
            with self.subTest(changes=changes):
                self.assert_refused(event(**changes))

    def test_all_four_reserved_record_words_are_strictly_zero(self):
        for number in range(4):
            with self.subTest(number=number):
                self.assert_refused(event(**{'reserved' + str(number): 1}))

    def test_full_journal_does_not_become_a_completion_or_coverage_certificate(self):
        result = self.decode(snapshot(*(event(number) for number in range(1, CAPACITY + 1))))
        self.assertTrue(result['capacity_full'])
        self.assertEqual(result['observed_call_intents'], CAPACITY)
        self.assert_deny(result)
        for item in result['events']:
            self.assert_deny(item)

    def test_reused_native_addresses_do_not_group_or_adopt_parent_identity(self):
        result = self.decode(snapshot(event(), event(2), event(3, decoder.GENERAL)))
        self.assertEqual([item['target'] for item in result['events']], [0x12345679] * 3)
        self.assertEqual([item['frame'] for item in result['events']], [0x2002000] * 3)
        self.assertEqual([item['origin'] for item in result['events']], [1, 2, 3])
        self.assertEqual([item['parent'] for item in result['events']], [0, 0, 0])
        for absent in ('groups', 'requests', 'births', 'associations', 'latest_callback'):
            self.assertNotIn(absent, result)
        self.assert_deny(result)

    def test_no_revision_scope_current_publication_or_cross_journal_input_can_be_added(self):
        raw = snapshot(event())
        for field in ('revision', 'scope', 'current_revision', 'scope_issued',
                      'current_publication', 'births', 'parent_result'):
            with self.subTest(field=field), self.assertRaises(TypeError):
                decoder.decode(raw, capacity=CAPACITY, **{field: 1})
        result = self.decode(raw)
        for item in (result, *result['events']):
            self.assertFalse(any('revision' in name or 'scope' in name for name in item))

    def test_public_limitations_distinguish_intent_raw_scalars_and_unproved_cause(self):
        result = self.decode(snapshot(event()))
        caveats = '\n'.join(result['limitations'])
        for text in ('CALL_INTENT only', 'callback return', 'raw register scalars',
                     'BA0 registration', 'immutable owned media', 'queue BIRTH/UI',
                     'never associated', 'complete coverage', 'authorize autoscroll'):
            self.assertIn(text, caveats)
        self.assert_deny(result)

    def test_cli_uses_owned_bytes_and_prints_only_the_same_deny_report(self):
        raw = snapshot(event())
        output = io.StringIO()
        with mock.patch.object(decoder.Path, 'read_bytes', return_value=raw) as read:
            with contextlib.redirect_stdout(output):
                decoder.main(['fixture.lpdi', '--capacity', str(CAPACITY)])
        read.assert_called_once_with()
        self.assertEqual(json.loads(output.getvalue()), self.decode(raw))

    def test_cli_refuses_structurally_bad_bytes(self):
        with mock.patch.object(decoder.Path, 'read_bytes', return_value=b''):
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    decoder.main(['fixture.lpdi', '--capacity', str(CAPACITY)])
        self.assertEqual(raised.exception.code, 2)


if __name__ == '__main__':
    unittest.main()
