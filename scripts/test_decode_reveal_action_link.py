#!/usr/bin/env python3
"""Strict historical source-to-BIRTH transport remains deny-only."""

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
import struct
import unittest
from unittest.mock import patch

import decode_reveal_action_link as decoder
import decode_reveal_queue_birth as birth_decoder
import test_decode_reveal_queue_birth as birth_fixture


CAPACITY, BIRTH_CAPACITY = 16, 8
SOURCE_FRAME, DELIVERY_FRAME, PAINT_DELIVERY_FRAME = 0x70001000, 0x70008000, 0x71008000
WORKER, QUEUE, ACTION_RECORD = 0x90001000, 0x90002000, 0x90003000
RESOURCE, NODE, CONTROLLER, PAINT_RECORD = 0x90004000, 0x90005000, 0x90006000, 0x90007000


def sequence(*, base=0, birth_id=1, param1=0xFFFFFFFF, paint_caller=0x490A10):
    shared = dict(magic=decoder.MAGIC, origin=base + 1, worker=WORKER,
                  source_frame=SOURCE_FRAME, action=1, param1=param1, param2=0,
                  reserved0=0, reserved1=0)
    result = []
    for kind in range(1, 7):
        item = dict.fromkeys(decoder.FIELDS, 0)
        item.update(shared, kind=kind, seq=base + kind,
                    parent=0 if kind == 1 else base + kind - 1,
                    site=decoder.SITES[kind], caller=decoder.CALLERS[kind][0])
        result.append(item)
    result[0].update(queue=QUEUE, record=SOURCE_FRAME + 0x18, frame=SOURCE_FRAME)
    result[1].update(queue=QUEUE, record=ACTION_RECORD, frame=DELIVERY_FRAME)
    result[2].update(queue=QUEUE, record=ACTION_RECORD, frame=DELIVERY_FRAME - 0x40,
                     resource=RESOURCE, node=NODE)
    result[3].update(record=DELIVERY_FRAME - 0x80 + 0x18,
                     frame=DELIVERY_FRAME - 0x80, resource=RESOURCE, node=NODE,
                     controller=CONTROLLER, engine=NODE,
                     input=DELIVERY_FRAME - 0x80 + 0x58, caller=paint_caller)
    result[4].update(record=PAINT_RECORD, frame=PAINT_DELIVERY_FRAME,
                     resource=RESOURCE, node=NODE, controller=CONTROLLER,
                     engine=NODE, input=PAINT_RECORD + 0xC)
    result[5].update(record=PAINT_RECORD, frame=PAINT_DELIVERY_FRAME - 0x68,
                     resource=RESOURCE, node=NODE, controller=CONTROLLER,
                     engine=NODE, input=PAINT_RECORD + 0xC, birth=birth_id)
    return result


def births(records=None):
    if records is None:
        records = [birth_fixture.event(engine=NODE, input=PAINT_RECORD + 0xC,
                                       metadata=0, frame=PAINT_DELIVERY_FRAME - 0x68)]
    return birth_fixture.snapshot(records, capacity=BIRTH_CAPACITY)


def snapshot(records=None, *, counter=None, capacity=CAPACITY):
    records = sequence() if records is None else records
    raw = bytearray(decoder.memory_bytes(capacity))
    struct.pack_into('<I', raw, 0, len(records) if counter is None else counter)
    for index, event in enumerate(records):
        struct.pack_into('<24I', raw, decoder.HEADER + index * decoder.RECORD,
                         *(event[field] for field in decoder.FIELDS))
    return bytes(raw)


def word(data, offset, value):
    raw = bytearray(data)
    struct.pack_into('<I', raw, offset, value)
    return bytes(raw)


def record_word(data, seq, field, value):
    return word(data, decoder.HEADER + (seq - 1) * decoder.RECORD
                + decoder.FIELDS.index(field) * 4, value)


def decode(data=None, *, birth_data=None, **options):
    return decoder.decode(snapshot() if data is None else data,
                          birth_data=births() if birth_data is None else birth_data,
                          capacity=CAPACITY, birth_capacity=BIRTH_CAPACITY, **options)


class DecodeRevealActionLinkTests(unittest.TestCase):
    def assert_no_authority(self, value):
        for field in decoder.AUTHORITY_FLAGS + (
                'native_record_lease_proven', 'native_payload_coherence_proven',
                'source_playback_identity_proven', 'universal_playback_coverage_proven'):
            self.assertIs(value[field], False, field)
        self.assertEqual(value['decision'], 'deny')

    def test_exact_schema_and_private_core_agree(self):
        import reveal_action_link_mips as core
        self.assertEqual((decoder.HEADER, decoder.RECORD, decoder.MAGIC),
                         (core.HEADER, core.RECORD_BYTES, core.MAGIC))
        self.assertEqual(decoder.MAGIC.to_bytes(4, 'little'), b'LALI')
        for index, name in enumerate(('MAGIC_OFFSET', 'KIND', 'PARENT', 'ORIGIN', 'SEQ',
                                      'WORKER', 'QUEUE', 'RECORD', 'SOURCE_FRAME', 'FRAME',
                                      'SITE', 'CALLER', 'ACTION', 'PARAM1', 'PARAM2',
                                      'RESOURCE', 'NODE', 'CONTROLLER', 'ENGINE', 'INPUT',
                                      'METADATA', 'BIRTH')):
            self.assertEqual(getattr(core, name), index * 4)
        self.assertEqual(core.RESERVED, (88, 92))
        self.assertEqual(decoder.memory_bytes(CAPACITY), core.memory_bytes(CAPACITY))

    def test_exact_six_kind_chain_is_historical_only(self):
        result = decode()
        self.assertEqual(result['format'], decoder.FORMAT)
        self.assertEqual(result['counter'], 6)
        association, = result['associations']
        self.assertEqual([association[field] for field in
                          ('source', 'delivery', 'explorer', 'paint',
                           'paint_delivery', 'birth_link', 'birth')],
                         [1, 2, 3, 4, 5, 6, 1])
        self.assertEqual(association['event_sequences'], [1, 2, 3, 4, 5, 6])
        self.assertTrue(association['observed_source_to_birth_chain'])
        self.assertTrue(association['historical_source_to_birth_associated'])
        self.assertEqual(result['unassociated_sources'], [])
        self.assertEqual(result['unassociated_births'], [])
        self.assertFalse(result['complete_coverage_proven'])
        self.assert_no_authority(result)
        self.assert_no_authority(association)
        for forbidden in ('current_track', 'fresh_request', 'success', 'row_origins'):
            self.assertNotIn(forbidden, result)
            self.assertNotIn(forbidden, association)

    def test_executed_private_core_bytes_decode_without_native_mapping(self):
        import test_reveal_action_link_mips as emitted
        machine = emitted.ActionLinkMachine()
        self.assertEqual(machine.chain(), (1, 2, 3, 4, 5, 6))
        result = decoder.decode(bytes(machine.shared.regions[emitted.JOURNAL]),
                                birth_data=bytes(machine.shared.regions[emitted.BIRTH]),
                                capacity=machine.shared.capacity,
                                birth_capacity=emitted.BIRTH_CAPACITY)
        self.assertEqual(result['associations'][0]['event_sequences'], [1, 2, 3, 4, 5, 6])
        self.assert_no_authority(result)

    def test_second_native_paint_call_site_is_admitted(self):
        self.assertEqual(len(decode(snapshot(sequence(paint_caller=0x490A60)))['associations']), 1)

    def test_partial_prefixes_never_invent_the_missing_edges(self):
        for count in range(6):
            with self.subTest(count=count):
                result = decode(snapshot(sequence()[:count]))
                self.assertEqual(result['associations'], [])
                self.assertEqual(result['unassociated_sources'], [1] if count else [])
                self.assertEqual(result['unassociated_births'], [1])
                self.assert_no_authority(result)

    def test_empty_both_journals_is_unknown_not_coverage(self):
        result = decode(snapshot([]), birth_data=births([]))
        self.assertEqual(result['associations'], [])
        self.assertFalse(result['complete_coverage_proven'])
        self.assert_no_authority(result)

    def test_capacity_full_valid_prefix_has_no_extra_authority(self):
        result = decoder.decode(snapshot(sequence(), capacity=6), birth_data=births(),
                                capacity=6, birth_capacity=BIRTH_CAPACITY)
        self.assertTrue(result['capacity_full'])
        self.assert_no_authority(result)

    def test_native_address_reuse_does_not_merge_explicit_histories(self):
        records = sequence() + sequence(base=6, birth_id=2)
        first = birth_fixture.event(engine=NODE, input=PAINT_RECORD + 0xC,
                                    metadata=0, frame=PAINT_DELIVERY_FRAME - 0x68)
        second = dict(first, seq=2, origin=2)
        result = decode(snapshot(records), birth_data=births([first, second]))
        self.assertEqual([(item['source'], item['birth']) for item in result['associations']],
                         [(1, 1), (7, 2)])

    def test_interleaved_reservations_follow_ids_not_adjacent_slots(self):
        first, second = sequence(), sequence(birth_id=2)
        records = []
        for index in range(6):
            for side, chain in enumerate((first, second)):
                item = dict(chain[index], seq=2 * index + side + 1,
                            origin=side + 1,
                            parent=0 if index == 0 else 2 * (index - 1) + side + 1)
                records.append(item)
        birth = birth_fixture.event(engine=NODE, input=PAINT_RECORD + 0xC,
                                    metadata=0, frame=PAINT_DELIVERY_FRAME - 0x68)
        result = decode(snapshot(records), birth_data=births([birth, dict(birth, seq=2, origin=2)]))
        self.assertEqual([item['event_sequences'] for item in result['associations']],
                         [[1, 3, 5, 7, 9, 11], [2, 4, 6, 8, 10, 12]])

    def test_explicit_delivery_fanout_can_have_two_historical_paint_branches(self):
        records = sequence()
        branch = sequence(birth_id=2)[2:]
        for index, item in enumerate(branch, 7):
            item.update(seq=index, parent=2 if index == 7 else index - 1)
        records.extend(branch)
        birth = birth_fixture.event(engine=NODE, input=PAINT_RECORD + 0xC,
                                    metadata=0, frame=PAINT_DELIVERY_FRAME - 0x68)
        result = decode(snapshot(records), birth_data=births([birth, dict(birth, seq=2, origin=2)]))
        self.assertEqual([item['event_sequences'] for item in result['associations']],
                         [[1, 2, 3, 4, 5, 6], [1, 2, 7, 8, 9, 10]])
        self.assert_no_authority(result)

    def test_independent_numeric_id_one_is_not_sufficient_to_link(self):
        with self.assertRaisesRegex(ValueError, 'LQBR BIRTH binding'):
            decode(birth_data=births([birth_fixture.event()]))

    def test_unlinked_lqbr_births_remain_explicitly_unassociated(self):
        first = birth_fixture.event(engine=NODE, input=PAINT_RECORD + 0xC,
                                    metadata=0, frame=PAINT_DELIVERY_FRAME - 0x68)
        second = dict(first, seq=2, origin=2)
        self.assertEqual(decode(birth_data=births([first, second]))['unassociated_births'], [2])

    def test_only_explicit_parent_ids_select_the_ancestry(self):
        raw = record_word(snapshot(), 4, 'parent', 2)
        with self.assertRaisesRegex(ValueError, 'wrong parent kind'):
            decode(raw)

    def test_parent_cannot_be_self_future_missing_or_zero(self):
        for parent in (0, 2, 6, 0xFFFFFFFF):
            with self.subTest(parent=parent), self.assertRaisesRegex(ValueError, 'earlier published'):
                decode(record_word(snapshot(), 2, 'parent', parent))

    def test_source_requires_zero_parent_and_self_origin(self):
        for field, value in (('parent', 1), ('origin', 0), ('origin', 2)):
            with self.subTest(field=field, value=value), self.assertRaisesRegex(ValueError, 'SOURCE ancestry'):
                decode(record_word(snapshot(), 1, field, value))

    def test_source_requires_exact_general_action_one(self):
        for field, value in (('action', 0), ('action', 5), ('param2', 1),
                             ('source_frame', SOURCE_FRAME + 4),
                             ('record', SOURCE_FRAME + 0x1C)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                decode(record_word(snapshot(), 1, field, value))

    def test_all_common_scalar_inheritance_is_strict(self):
        for seq in range(2, 7):
            for field in ('origin', 'worker', 'source_frame', 'action', 'param1', 'param2'):
                with self.subTest(seq=seq, field=field), self.assertRaisesRegex(ValueError, 'source binding'):
                    decode(record_word(snapshot(), seq, field, sequence()[seq - 1][field] ^ 4))

    def test_queue_and_selected_record_are_bound_at_delivery_to_explorer(self):
        for seq, field in ((2, 'queue'), (3, 'queue'), (3, 'record')):
            with self.subTest(seq=seq, field=field), self.assertRaisesRegex(ValueError, 'binding'):
                decode(record_word(snapshot(), seq, field, sequence()[seq - 1][field] + 4))

    def test_delivery_can_use_a_different_native_frame_and_record(self):
        records = sequence()[:2]
        records[1].update(frame=0x12340000, record=0x56780000)
        self.assertEqual(decode(snapshot(records))['counter'], 2)

    def test_explorer_and_paint_native_frame_relations_are_exact(self):
        for seq in (3, 4):
            with self.subTest(seq=seq), self.assertRaisesRegex(ValueError, 'frame'):
                decode(record_word(snapshot(), seq, 'frame', sequence()[seq - 1]['frame'] - 4))

    def test_paint_source_rectangle_and_engine_are_not_current_state_samples(self):
        for field in ('record', 'input', 'engine'):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'PAINT frame/engine/input'):
                decode(record_word(snapshot(), 4, field, sequence()[3][field] + 4))

    def test_explorer_resource_and_node_binding_cannot_be_retargeted(self):
        for field in ('resource', 'node'):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'EXPLORER binding'):
                decode(record_word(snapshot(), 4, field, sequence()[3][field] + 4))

    def test_paint_delivery_must_bind_exact_private_paint_scalars(self):
        for field in ('resource', 'node', 'controller', 'engine', 'metadata'):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'PAINT binding'):
                decode(record_word(snapshot(), 5, field, sequence()[4][field] + 4))

    def test_paint_delivery_input_is_inline_rectangle(self):
        with self.assertRaisesRegex(ValueError, 'PAINT_DELIVERY input'):
            decode(record_word(snapshot(), 5, 'input', PAINT_RECORD + 0x10))

    def test_birth_link_must_inherit_exact_delivery(self):
        for field in ('queue', 'record', 'resource', 'node', 'controller', 'engine',
                      'input', 'metadata'):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'PAINT_DELIVERY binding'):
                decode(record_word(snapshot(), 6, field, sequence()[5][field] + 4))

    def test_birth_frame_ancestry_cannot_be_rebound(self):
        with self.assertRaisesRegex(ValueError, 'BIRTH_LINK frame'):
            decode(record_word(snapshot(), 6, 'frame', PAINT_DELIVERY_FRAME - 0x64))

    def test_external_birth_id_is_required(self):
        for token in (0, 2, 0xFFFFFFFF):
            with self.subTest(token=token), self.assertRaisesRegex(ValueError, 'missing explicit'):
                decode(record_word(snapshot(), 6, 'birth', token))

    def test_external_enqueue_id_is_not_a_birth_id(self):
        records = birth_fixture.sequence()
        with self.assertRaisesRegex(ValueError, 'not an LQBR BIRTH'):
            decode(record_word(snapshot(), 6, 'birth', 2), birth_data=births(records))

    def test_external_birth_scalar_bindings_are_all_checked(self):
        first = birth_fixture.event(engine=NODE, input=PAINT_RECORD + 0xC,
                                    metadata=0, frame=PAINT_DELIVERY_FRAME - 0x68)
        for field in ('engine', 'input', 'metadata', 'frame'):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'LQBR BIRTH binding'):
                decode(birth_data=births([dict(first, **{field: first[field] + 4})]))

    def test_duplicate_observer_for_actual_birth_is_refused(self):
        records = sequence()
        records.append(dict(records[-1], seq=7))
        with self.assertRaisesRegex(ValueError, 'duplicate observed'):
            decode(snapshot(records))

    def test_wrong_source_sites_and_original_callers_are_rejected(self):
        for seq in range(1, 7):
            for field in ('site', 'caller'):
                with self.subTest(seq=seq, field=field), self.assertRaises(ValueError):
                    decode(record_word(snapshot(), seq, field, sequence()[seq - 1][field] + 4))

    def test_unknown_kinds_are_not_forward_compatible_authority(self):
        for kind in (0, 7, 0xFFFFFFFF):
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, 'unknown kind'):
                decode(record_word(snapshot(), 1, 'kind', kind))

    def test_missing_magic_and_noncontiguous_sequence_are_rejected(self):
        for seq in range(1, 7):
            for field in ('magic', 'seq'):
                with self.subTest(seq=seq, field=field), self.assertRaises(ValueError):
                    decode(record_word(snapshot(), seq, field, 0))

    def test_reserved_header_and_record_words_are_rejected(self):
        for offset in (4, 8, 12):
            with self.subTest(offset=offset), self.assertRaisesRegex(ValueError, 'reserved header'):
                decode(word(snapshot(), offset, 1))
        for seq in range(1, 7):
            for field in ('reserved0', 'reserved1'):
                with self.subTest(seq=seq, field=field), self.assertRaisesRegex(ValueError, 'reserved record'):
                    decode(record_word(snapshot(), seq, field, 1))

    def test_fault_and_overcapacity_counter_are_rejected(self):
        for value in (decoder.FAULT, CAPACITY + 1):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'allocator'):
                decode(word(snapshot(), 0, value))

    def test_allocated_unpublished_and_dirty_unallocated_slots_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'unpublished'):
            decode(snapshot(sequence(), counter=7))
        with self.assertRaisesRegex(ValueError, 'unallocated'):
            decode(word(snapshot(), decoder.HEADER + 6 * decoder.RECORD, 1))

    def test_all_unused_kind_payload_words_must_be_zero(self):
        fields_by_kind = {
            1: ('resource', 'node', 'controller', 'engine', 'input', 'metadata', 'birth'),
            2: ('resource', 'node', 'controller', 'engine', 'input', 'metadata', 'birth'),
            3: ('controller', 'engine', 'input', 'metadata', 'birth'),
            4: ('queue', 'metadata', 'birth'), 5: ('queue', 'birth')}
        for seq, fields in fields_by_kind.items():
            for field in fields:
                with self.subTest(seq=seq, field=field), self.assertRaises(ValueError):
                    decode(record_word(snapshot(), seq, field, 4))

    def test_native_scalar_alignment_and_nonzero_checks_are_strict(self):
        for seq in range(1, 7):
            for field in ('worker', 'source_frame', 'frame', 'record'):
                for value in (0, 3):
                    with self.subTest(seq=seq, field=field, value=value), self.assertRaises(ValueError):
                        decode(record_word(snapshot(), seq, field, value))

    def test_pointer_arithmetic_does_not_wrap(self):
        records = sequence()[:1]
        records[0].update(frame=0xFFFFFFE8, source_frame=0xFFFFFFE8, record=0)
        with self.assertRaises(ValueError):
            decode(snapshot(records))
        with self.assertRaises(ValueError):
            decode(record_word(snapshot(), 5, 'record', 0xFFFFFFFC))

    def test_public_inputs_are_raw_owned_buffers_not_decoded_dicts(self):
        for invalid in ({}, [], '', None, 42):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                decoder.decode(invalid, birth_data=births(), capacity=CAPACITY,
                               birth_capacity=BIRTH_CAPACITY)
        for invalid in ({'events': []}, [], '', None, 42):
            with self.subTest(birth_data=invalid), self.assertRaises(ValueError):
                decoder.decode(snapshot(), birth_data=invalid,
                               capacity=CAPACITY, birth_capacity=BIRTH_CAPACITY)

    def test_snapshot_lengths_and_capacity_types_are_exact(self):
        for raw in (snapshot()[:-1], snapshot() + b'\0'):
            with self.subTest(length=len(raw)), self.assertRaisesRegex(ValueError, 'size'):
                decode(raw)
        for capacity in (0, -1, True, 1.0, '16', decoder.MAX_CAPACITY + 1):
            with self.subTest(capacity=capacity), self.assertRaises(ValueError):
                decoder.memory_bytes(capacity)

    def test_foreign_birth_fault_or_unpublished_slot_is_not_ignored(self):
        for raw in (word(births(), 0, 0xFFFFFFFF), word(births(), 0, 2),
                    word(births(), birth_decoder.HEADER, 0)):
            with self.subTest(raw=raw[:20]), self.assertRaises(ValueError):
                decode(birth_data=raw)

    def test_bytearray_and_memoryview_are_snapshotted_without_mutation(self):
        raw, external = bytearray(snapshot()), bytearray(births())
        before, external_before = bytes(raw), bytes(external)
        result = decode(memoryview(raw), birth_data=memoryview(external))
        self.assertEqual(bytes(raw), before)
        self.assertEqual(bytes(external), external_before)
        self.assertEqual(len(result['associations']), 1)

    def test_cli_reads_two_owned_files_and_emits_deny_only_json(self):
        with patch('pathlib.Path.read_bytes', side_effect=[snapshot(), births()]), \
                redirect_stdout(StringIO()) as output:
            decoder.main(['local.action', 'local.birth', '--capacity', str(CAPACITY),
                          '--birth-capacity', str(BIRTH_CAPACITY)])
        self.assert_no_authority(json.loads(output.getvalue()))

    def test_cli_reports_read_or_validation_error_without_traceback(self):
        with patch('pathlib.Path.read_bytes', side_effect=OSError('local read failed')), \
                redirect_stderr(StringIO()) as output, self.assertRaises(SystemExit) as exited:
            decoder.main(['local.action', 'local.birth'])
        self.assertEqual(exited.exception.code, 2)
        self.assertIn('local read failed', output.getvalue())


if __name__ == '__main__':
    unittest.main()
