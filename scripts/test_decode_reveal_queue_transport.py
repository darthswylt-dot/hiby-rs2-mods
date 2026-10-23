#!/usr/bin/env python3
"""LQTR observations use receipt IDs, never pointer registries or UI claims."""

import copy
import struct
import unittest

import decode_reveal_queue_birth as birth
import decode_reveal_queue_transport as decoder
import test_decode_reveal_queue_birth as birth_fixtures


CAPACITY = 16
ENGINE, NODE, COPY = 0x90001000, 0x90005000, 0x90004000
ENQUEUE_FRAME, BORROW_FRAME = 0x7FFF1000, 0x7FFF8000
HELPER_FRAME, CALLBACK_FRAME = BORROW_FRAME - 0xB8, BORROW_FRAME - 0xB8 - 0x38


def event(kind=decoder.INSTALL, *, seq=None, parent=None, origin=1,
          engine=ENGINE, node=NODE, copy=COPY, metadata=0xFFFFFFFF,
          frame=None, upstream=None, revision=10, scope=4, site=None):
    if seq is None:
        seq = kind
    if parent is None:
        parent = 2 if kind == decoder.INSTALL else seq - 1
    if frame is None:
        frame = {decoder.INSTALL: ENQUEUE_FRAME - 0x28,
                 decoder.BORROW: BORROW_FRAME,
                 decoder.HELPER: HELPER_FRAME,
                 decoder.CALLBACK: CALLBACK_FRAME}[kind]
    if upstream is None:
        upstream = {decoder.INSTALL: ENQUEUE_FRAME, decoder.BORROW: 0,
                    decoder.HELPER: BORROW_FRAME,
                    decoder.CALLBACK: HELPER_FRAME}[kind]
    return dict(magic=decoder.MAGIC, kind=kind, parent=parent,
                origin=origin, seq=seq, engine=engine, node=node,
                copy=copy, metadata=metadata, frame=frame,
                site=decoder.SITES[kind] if site is None else site,
                upstream=upstream, revision=revision, scope=scope,
                reserved0=0, reserved1=0)


def sequence(**options):
    return [event(kind, **options) for kind in
            (decoder.INSTALL, decoder.BORROW, decoder.HELPER, decoder.CALLBACK)]


def snapshot(records=None, *, capacity=CAPACITY, counter=None):
    if records is None:
        records = sequence()
    if counter is None:
        counter = len(records)
    result = bytearray(decoder.memory_bytes(capacity))
    struct.pack_into('<I', result, 0, counter)
    for index, item in enumerate(records):
        struct.pack_into('<16I', result, decoder.HEADER + index * decoder.RECORD,
                         *(item[field] for field in decoder.FIELDS))
    return bytes(result)


def word(data, offset, value):
    result = bytearray(data)
    struct.pack_into('<I', result, offset, value)
    return bytes(result)


def record_word(data, seq, field, value):
    return word(data, decoder.HEADER + (seq - 1) * decoder.RECORD
                + decoder.FIELDS.index(field) * 4, value)


def birth_records(*, revision=10, scope=4, result=NODE):
    return birth_fixtures.sequence(revision=revision, scope=scope, result=result)


def birth_result(records=None, *, current_revision=None):
    return birth.decode(birth_fixtures.snapshot(birth_records() if records is None else records),
                        capacity=birth_fixtures.CAPACITY, current_revision=current_revision)


def decode(data=None, births=None, **options):
    return decoder.decode(snapshot() if data is None else data,
                          birth_result() if births is None else births,
                          capacity=CAPACITY, **options)


class DecodeRevealQueueTransportTests(unittest.TestCase):
    def assert_no_authority(self, result):
        for field in decoder.AUTHORITY_FLAGS:
            self.assertIs(result[field], False, field)

    def test_schema_and_explicit_source_sites(self):
        self.assertEqual((decoder.HEADER, decoder.RECORD), (16, 64))
        self.assertEqual(decoder.MAGIC.to_bytes(4, 'little'), b'LQTR')
        self.assertEqual(decoder.FIELDS,
                         ('magic', 'kind', 'parent', 'origin', 'seq', 'engine', 'node',
                          'copy', 'metadata', 'frame', 'site', 'upstream', 'revision',
                          'scope', 'reserved0', 'reserved1'))
        self.assertEqual(decoder.SITES,
                         {1: 0x8B3CE8, 2: 0x8B4754, 3: 0x8B3FA0, 4: 0x439EC0})
        self.assertEqual(decoder.memory_bytes(1), 80)

    def test_schema_matches_the_emitted_private_core(self):
        import reveal_queue_transport_mips as core
        self.assertEqual((decoder.HEADER, decoder.RECORD, decoder.MAGIC),
                         (core.HEADER, core.RECORD, core.MAGIC))
        for index, field in enumerate(('MAGIC_OFFSET', 'KIND', 'PARENT', 'ORIGIN',
                                       'SEQ', 'ENGINE', 'NODE', 'COPY', 'METADATA',
                                       'FRAME', 'SITE', 'UPSTREAM', 'REVISION', 'SCOPE')):
            self.assertEqual(getattr(core, field), index * 4)
        self.assertEqual(core.RESERVED, (56, 60))
        self.assertEqual(decoder.memory_bytes(CAPACITY), core.memory_bytes(CAPACITY))

    def test_complete_exact_chain_is_historical_not_ui_authority(self):
        result = decode(current_revision=10, scope_issued=4)
        chain = result['chains'][0]
        self.assertEqual(result['format'], decoder.FORMAT)
        self.assertEqual(result['counter'], 4)
        self.assertEqual(chain['event_sequences'], [1, 2, 3, 4])
        self.assertEqual((chain['birth'], chain['enqueue'], chain['install'],
                          chain['borrow'], chain['helper'], chain['callback']),
                         (1, 2, 1, 2, 3, 4))
        self.assertEqual(chain['birth_event_sequences'], [1, 2, 3])
        self.assertEqual(chain['producer_return_sequences'], [3])
        self.assertTrue(chain['observed_birth_to_callback_chain'])
        self.assertTrue(chain['producer_return_observed'])
        self.assertTrue(chain['unique_producer_return_observed'])
        self.assertTrue(chain['append_return_matches_node'])
        self.assertTrue(chain['observed_enqueue_sequence_complete'])
        self.assertTrue(chain['observation_complete'])
        self.assertTrue(chain['known_boundary_unchanged'])
        self.assertTrue(chain['observed_scopes_quiet'])
        self.assertEqual(chain['reasons'], [])
        self.assertEqual(result['installs'][0]['callbacks'], [4])
        for item in (result, result['installs'][0], chain):
            self.assert_no_authority(item)
            for forbidden in ('row_origins', 'renderer', 'current_request', 'success'):
                self.assertNotIn(forbidden, item)

    def test_empty_histories_never_prove_coverage(self):
        result = decode(snapshot([]), birth_result([]))
        self.assertEqual(result['events'], [])
        self.assertEqual(result['installs'], [])
        self.assertEqual(result['chains'], [])
        self.assertFalse(result['observation_complete'])
        self.assertFalse(result['observed_birth_to_callback_chain'])
        self.assert_no_authority(result)
        limits = ' '.join(result['limitations'])
        for text in ('coverage', 'never registry keys', 'native lifetime',
                     'row/renderer association', 'not native chronology'):
            self.assertIn(text, limits)

    def test_partial_consumer_history_remains_incomplete(self):
        for count in (1, 2, 3):
            with self.subTest(count=count):
                result = decode(snapshot(sequence()[:count]))
                self.assertEqual(result['chains'], [])
                install = result['installs'][0]
                self.assertFalse(install['observed_birth_to_callback_chain'])
                self.assertFalse(install['observation_complete'])
                self.assertFalse(install['known_boundary_unchanged'])
                self.assertFalse(install['observed_scopes_quiet'])
                self.assertTrue(install['observed_enqueue_sequence_complete'])
                self.assertTrue(install['producer_return_observed'])
                self.assertIn('birth-to-callback-chain-not-observed', install['reasons'])

    def test_one_complete_chain_does_not_complete_another_known_partial_install(self):
        births = birth_records()
        births.extend([birth_fixtures.event(seq=4, origin=4),
                       birth_fixtures.event(birth.ENQUEUE_BEGIN, seq=5, parent=4, origin=4),
                       birth_fixtures.event(birth.RETURN, seq=6, parent=5, origin=4, result=NODE)])
        records = sequence() + [event(decoder.INSTALL, seq=5, parent=5, origin=4)]
        result = decode(snapshot(records), birth_result(births))
        self.assertTrue(result['chains'][0]['observation_complete'])
        self.assertTrue(result['observed_birth_to_callback_chain'])
        self.assertFalse(result['installs'][1]['observation_complete'])
        self.assertFalse(result['observation_complete'])

    def test_missing_producer_return_does_not_repair_complete_consumer_ancestry(self):
        result = decode(births=birth_result(birth_records()[:2]))
        chain = result['chains'][0]
        self.assertTrue(chain['observed_birth_to_callback_chain'])
        self.assertFalse(chain['producer_return_observed'])
        self.assertFalse(chain['unique_producer_return_observed'])
        self.assertFalse(chain['observed_enqueue_sequence_complete'])
        self.assertFalse(chain['observation_complete'])
        self.assertIsNone(chain['append_return'])
        self.assertIn('producer-return-not-observed', chain['reasons'])
        self.assert_no_authority(chain)

    def test_duplicate_explicit_parent_returns_stay_incomplete(self):
        records = birth_records()
        records.append(birth_fixtures.event(birth.RETURN, seq=4, result=NODE))
        chain = decode(births=birth_result(records))['chains'][0]
        self.assertTrue(chain['producer_return_observed'])
        self.assertFalse(chain['unique_producer_return_observed'])
        self.assertFalse(chain['observed_enqueue_sequence_complete'])
        self.assertFalse(chain['observation_complete'])
        self.assertIsNone(chain['append_return'])
        self.assertEqual(chain['producer_return_sequences'], [3, 4])
        self.assertIn('producer-return-not-unique', chain['reasons'])

    def test_later_return_can_follow_consumer_without_crossjournal_seq_order(self):
        records = birth_records()
        # This RETURN sample follows INSTALL but may follow every consumer.
        # Its separate journal seq=3 is not ordered against LQTR seq=4.
        records[2].update(revision=12, scope=6)
        chain = decode(births=birth_result(records), current_revision=12,
                       scope_issued=6)['chains'][0]
        self.assertTrue(chain['observation_complete'])
        self.assertTrue(chain['observed_scopes_quiet'])
        self.assertFalse(chain['known_boundary_unchanged'])
        self.assert_no_authority(chain)

    def test_return_before_consumer_samples_is_also_allowed(self):
        records = sequence(revision=12, scope=6)
        records[0].update(revision=10, scope=4)
        chain = decode(snapshot(records),
                       current_revision=12, scope_issued=6)['chains'][0]
        self.assertTrue(chain['observation_complete'])
        self.assertFalse(chain['known_boundary_unchanged'])

    def test_actual_return_must_match_installed_node_without_pointer_rejoin(self):
        for returned in (0, 1, NODE + 4, 0xFFFFFFFF):
            with self.subTest(returned=returned):
                chain = decode(births=birth_result(birth_records(result=returned)))['chains'][0]
                self.assertTrue(chain['producer_return_observed'])
                self.assertTrue(chain['unique_producer_return_observed'])
                self.assertTrue(chain['observed_enqueue_sequence_complete'])
                self.assertFalse(chain['append_return_matches_node'])
                self.assertFalse(chain['observation_complete'])
                self.assertIn('append-return-node-mismatch', chain['reasons'])

    def test_explicit_install_to_return_causality_cannot_regress(self):
        for field, value in (('revision', 11), ('scope', 5)):
            records = sequence()
            for item in records:
                item[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'regressed'):
                decode(snapshot(records))

    def test_callback_multiplicity_is_distinct_receipts_not_duplicate_join(self):
        records = sequence()
        records.extend([event(decoder.CALLBACK, seq=5, parent=3),
                        event(decoder.CALLBACK, seq=6, parent=3)])
        result = decode(snapshot(records))
        self.assertEqual([item['callback'] for item in result['chains']], [4, 5, 6])
        self.assertEqual([item['event_sequences'] for item in result['chains']],
                         [[1, 2, 3, 4], [1, 2, 3, 5], [1, 2, 3, 6]])
        self.assertEqual(result['installs'][0]['callbacks'], [4, 5, 6])
        self.assertTrue(all(item['observation_complete'] for item in result['chains']))

    def test_reused_engine_node_copy_metadata_and_frames_never_merge_birth_ids(self):
        births = birth_records()
        births.extend([birth_fixtures.event(seq=4, origin=4),
                       birth_fixtures.event(birth.ENQUEUE_BEGIN, seq=5, parent=4, origin=4),
                       birth_fixtures.event(birth.RETURN, seq=6, parent=5, origin=4, result=NODE)])
        records = sequence()
        records.extend([event(decoder.INSTALL, seq=5, parent=5, origin=4),
                        event(decoder.BORROW, seq=6, parent=5, origin=4),
                        event(decoder.HELPER, seq=7, parent=6, origin=4),
                        event(decoder.CALLBACK, seq=8, parent=7, origin=4)])
        result = decode(snapshot(records), birth_result(births))
        self.assertEqual([item['birth'] for item in result['chains']], [1, 4])
        self.assertEqual([item['enqueue'] for item in result['chains']], [2, 5])
        self.assertEqual([item['event_sequences'] for item in result['chains']],
                         [[1, 2, 3, 4], [5, 6, 7, 8]])
        self.assertEqual([item['producer_return_sequences'] for item in result['chains']], [[3], [6]])

    def test_other_return_with_same_node_does_not_repair_missing_explicit_parent(self):
        births = birth_records()[:2]
        births.extend([birth_fixtures.event(seq=3, origin=3),
                       birth_fixtures.event(birth.ENQUEUE_BEGIN, seq=4, parent=3, origin=3),
                       birth_fixtures.event(birth.RETURN, seq=5, parent=4, origin=3, result=NODE)])
        chain = decode(births=birth_result(births))['chains'][0]
        self.assertFalse(chain['producer_return_observed'])
        self.assertFalse(chain['observation_complete'])
        self.assertEqual(chain['producer_return_sequences'], [])

    def test_install_parent_is_external_explicit_id_not_transport_sequence(self):
        births = birth_records()
        births.extend([birth_fixtures.event(seq=4, origin=4),
                       birth_fixtures.event(birth.ENQUEUE_BEGIN, seq=5, parent=4, origin=4),
                       birth_fixtures.event(birth.RETURN, seq=6, parent=5, origin=4, result=NODE)])
        records = sequence(origin=4)
        records[0]['parent'] = 5
        chain = decode(snapshot(records), birth_result(births))['chains'][0]
        self.assertEqual(chain['enqueue'], 5)
        self.assertEqual(chain['install'], 1)
        self.assertTrue(chain['observation_complete'])

    def test_independent_reservations_may_have_regressing_revision_and_scope_samples(self):
        births = birth_records(revision=20, scope=7)
        births.extend([birth_fixtures.event(seq=4, origin=4, revision=10, scope=4),
                       birth_fixtures.event(birth.ENQUEUE_BEGIN, seq=5, parent=4,
                                            origin=4, revision=10, scope=4),
                       birth_fixtures.event(birth.RETURN, seq=6, parent=5,
                                            origin=4, revision=10, scope=4, result=NODE)])
        records = sequence(revision=20, scope=7)
        records.extend([event(decoder.INSTALL, seq=5, parent=5, origin=4),
                        event(decoder.BORROW, seq=6, parent=5, origin=4),
                        event(decoder.HELPER, seq=7, parent=6, origin=4),
                        event(decoder.CALLBACK, seq=8, parent=7, origin=4)])
        result = decode(snapshot(records), birth_result(births), current_revision=20, scope_issued=7)
        self.assertTrue(result['chains'][0]['known_boundary_unchanged'])
        self.assertFalse(result['chains'][1]['known_boundary_unchanged'])
        self.assertTrue(all(item['observation_complete'] for item in result['chains']))

    def test_install_requires_an_existing_enqueue_parent_not_birth_or_return(self):
        data = snapshot()
        for parent in (0, 1, 3, 4, 0xFFFFFFFF):
            with self.subTest(parent=parent), self.assertRaises(ValueError):
                decode(record_word(data, 1, 'parent', parent))
        with self.assertRaisesRegex(ValueError, 'parent'):
            decode(births=birth_result([]))

    def test_install_immutable_birth_bindings_are_strict(self):
        data = snapshot()
        for field, value in (('origin', 2), ('engine', ENGINE + 4),
                             ('copy', COPY + 4), ('metadata', 0)):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'binding mismatch'):
                decode(record_word(data, 1, field, value))

    def test_children_require_earlier_published_exact_previous_kind(self):
        data = snapshot()
        for seq in (2, 3, 4):
            for parent in (0, seq, seq + 1, 0xFFFFFFFF):
                with self.subTest(seq=seq, parent=parent), self.assertRaises(ValueError):
                    decode(record_word(data, seq, 'parent', parent))
        for seq, wrong in ((3, 1), (4, 1), (4, 2)):
            with self.subTest(seq=seq, wrong=wrong), self.assertRaisesRegex(ValueError, 'parent kind'):
                decode(record_word(data, seq, 'parent', wrong))

    def test_children_cannot_change_origin_or_native_scalar_bindings(self):
        data = snapshot()
        for seq in (2, 3, 4):
            for field in ('origin', 'engine', 'node', 'copy', 'metadata'):
                value = 2 if field == 'origin' else 0x90009000
                with self.subTest(seq=seq, field=field), self.assertRaisesRegex(ValueError, 'binding mismatch'):
                    decode(record_word(data, seq, field, value))

    def test_install_frame_parent_delta_and_upstream_are_exact(self):
        data = snapshot()
        for field, value in (('frame', ENQUEUE_FRAME), ('frame', ENQUEUE_FRAME - 0x2C),
                             ('upstream', 0), ('upstream', ENQUEUE_FRAME + 4)):
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                decode(record_word(data, 1, field, value))

    def test_borrow_has_no_upstream_and_helper_callback_frames_match_exact_ancestors(self):
        data = snapshot()
        for value in (4, ENQUEUE_FRAME, 0xFFFFFFFF):
            with self.subTest(borrow=value), self.assertRaisesRegex(ValueError, 'borrow upstream'):
                decode(record_word(data, 2, 'upstream', value))
        for seq in (3, 4):
            for field, value in (('frame', 0x7FFF4000), ('upstream', 0),
                                 ('upstream', 0x7FFF4000)):
                with self.subTest(seq=seq, field=field), self.assertRaisesRegex(ValueError, 'frame binding'):
                    decode(record_word(data, seq, field, value))

    def test_positive_aligned_addresses_are_required_before_any_association(self):
        data = snapshot()
        for seq in (1, 2, 3, 4):
            for field in ('engine', 'node', 'copy', 'frame'):
                for value in (0, 1, 2, 3, 0xFFFFFFFF):
                    with self.subTest(seq=seq, field=field, value=value), self.assertRaises(ValueError):
                        decode(record_word(data, seq, field, value))

    def test_native_extent_and_frame_arithmetic_may_not_wrap(self):
        data = snapshot()
        for seq in (1, 2, 3, 4):
            for field in ('engine', 'node', 'copy', 'frame'):
                with self.subTest(seq=seq, field=field), self.assertRaisesRegex(ValueError, 'nonwrapping'):
                    decode(record_word(data, seq, field, 0xFFFFFFFC))
        with self.assertRaisesRegex(ValueError, 'nonwrapping'):
            decode(record_word(data, 1, 'upstream', 0xFFFFFFFC))

    def test_metadata_remains_any_unsigned_scalar_not_a_receipt_slot(self):
        for metadata in (0, 1, 3, 0xFFFFFFFF):
            births = birth_records()
            for item in births:
                item['metadata'] = metadata
            chain = decode(snapshot(sequence(metadata=metadata)), birth_result(births))['chains'][0]
            self.assertEqual(chain['metadata'], metadata)
            self.assertTrue(chain['observation_complete'])

    def test_parent_chain_samples_must_not_regress_even_without_final_counters(self):
        data = snapshot()
        for seq in (1, 2, 3, 4):
            for field, value in (('revision', 9), ('scope', 3)):
                with self.subTest(seq=seq, field=field), self.assertRaisesRegex(ValueError, 'regressed'):
                    decode(record_word(data, seq, field, value))

    def test_active_known_scope_at_any_transport_point_prevents_quiet_claim_only(self):
        data = snapshot()
        for seq in (1, 2, 3, 4):
            with self.subTest(seq=seq):
                chain = decode(record_word(data, seq, 'scope', 4 | 1 << 16))['chains'][0]
                self.assertTrue(chain['observation_complete'])
                self.assertTrue(chain['known_boundary_unchanged'])
                self.assertFalse(chain['observed_scopes_quiet'])
                self.assertIn('known-scopes-quiet-not-observed', chain['reasons'])
                self.assert_no_authority(chain)

    def test_active_scope_in_birth_or_return_also_prevents_quiet_claim(self):
        for index in (0, 1, 2):
            records = birth_records()
            records[index]['scope'] = 4 | 1 << 16
            chain = decode(births=birth_result(records))['chains'][0]
            self.assertTrue(chain['observation_complete'])
            self.assertFalse(chain['observed_scopes_quiet'])

    def test_later_revision_narrows_without_invalidating_historical_ancestry(self):
        chain = decode(current_revision=11)['chains'][0]
        self.assertTrue(chain['observation_complete'])
        self.assertFalse(chain['known_boundary_unchanged'])
        self.assertTrue(chain['observed_scopes_quiet'])
        self.assert_no_authority(chain)

    def test_inherited_birth_counter_is_used_when_no_final_override_supplied(self):
        result = decode(births=birth_result(current_revision=11))
        self.assertEqual(result['known_contents_revision'], 11)
        self.assertFalse(result['chains'][0]['known_boundary_unchanged'])
        with self.assertRaisesRegex(ValueError, 'precedes'):
            decode(births=birth_result(current_revision=11), current_revision=10)

    def test_invalid_final_revision_and_scope_counter_types_or_bounds_rejected(self):
        for value in (True, False, -1, 1.0, '10', 0x80000000, 0xFFFFFFFF):
            with self.subTest(revision=value), self.assertRaises(ValueError):
                decode(current_revision=value)
        for value in (True, False, -1, 1.0, '4', 0x10000, 0xFFFFFFFF):
            with self.subTest(scope_issued=value), self.assertRaises(ValueError):
                decode(scope_issued=value)

    def test_future_birth_and_transport_samples_against_final_bounds_rejected(self):
        with self.assertRaisesRegex(ValueError, 'beyond the known counter'):
            decode(current_revision=9)
        with self.assertRaisesRegex(ValueError, 'birth scope sample'):
            decode(scope_issued=3)
        for field, value, kwargs in (('revision', 11, dict(current_revision=10)),
                                     ('scope', 5, dict(scope_issued=4))):
            data = record_word(snapshot(), 4, field, value)
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'beyond'):
                decode(data, **kwargs)

    def test_scope_fault_and_more_active_than_issued_rejected(self):
        data = snapshot()
        for seq in (1, 2, 3, 4):
            for state in (0xFFFFFFFF, 0x80000000, 1 << 16, 5 << 16 | 4):
                with self.subTest(seq=seq, state=state), self.assertRaises(ValueError):
                    decode(record_word(data, seq, 'scope', state))

    def test_faulted_or_invalid_event_revision_rejected(self):
        for seq in (1, 2, 3, 4):
            for value in (0x80000000, 0xFFFFFFFF):
                with self.subTest(seq=seq, value=value), self.assertRaises(ValueError):
                    decode(record_word(snapshot(), seq, 'revision', value))

    def test_magic_kind_source_sequence_and_reserved_record_words_are_strict(self):
        data = snapshot()
        for seq in (1, 2, 3, 4):
            for field, values in (('magic', (0, 1, 0xFFFFFFFF)),
                                  ('kind', (0, 5, 0xFFFFFFFF)),
                                  ('seq', (0, seq + 1, 0xFFFFFFFF)),
                                  ('site', (0, decoder.SITES[seq] + 4)),
                                  ('reserved0', (1,)), ('reserved1', (0xFFFFFFFF,))):
                for value in values:
                    with self.subTest(seq=seq, field=field, value=value), self.assertRaises(ValueError):
                        decode(record_word(data, seq, field, value))
            wrong_site = decoder.SITES[1 if seq != 1 else 2]
            with self.subTest(seq=seq), self.assertRaisesRegex(ValueError, 'source site'):
                decode(record_word(data, seq, 'site', wrong_site))

    def test_unpublished_allocated_slot_and_missing_records_are_not_ignored(self):
        for data in (snapshot([], counter=1), snapshot(sequence()[:2], counter=3),
                     record_word(snapshot(), 3, 'magic', 0)):
            with self.subTest(prefix=data[:20]), self.assertRaisesRegex(ValueError, 'unpublished'):
                decode(data)

    def test_counter_fault_reserved_header_and_nonzero_unallocated_tail_rejected(self):
        data = snapshot()
        for value in (decoder.FAULT, CAPACITY + 1, 0x80000000):
            with self.subTest(counter=value), self.assertRaises(ValueError):
                decode(word(data, 0, value))
        for offset in (4, 8, 12):
            with self.subTest(offset=offset), self.assertRaisesRegex(ValueError, 'reserved header'):
                decode(word(data, offset, 1))
        for seq in (5, CAPACITY):
            for field in decoder.FIELDS:
                with self.subTest(seq=seq, field=field), self.assertRaisesRegex(ValueError, 'unallocated'):
                    decode(record_word(data, seq, field, 1))

    def test_capacity_full_does_not_mean_coverage_or_authority(self):
        result = decoder.decode(snapshot(capacity=4), birth_result(), capacity=4)
        self.assertTrue(result['capacity_full'])
        self.assertTrue(result['observation_complete'])
        self.assert_no_authority(result)
        self.assertIn('capacity-full', ' '.join(result['limitations']))

    def test_exact_owned_buffer_and_valid_capacity_required(self):
        data = snapshot()
        for raw in (None, '', 1, [], b'', data[:-1], data + b'\0'):
            with self.subTest(raw_type=type(raw)), self.assertRaises(ValueError):
                decoder.decode(raw, birth_result(), capacity=CAPACITY)
        for capacity in (True, False, 0, -1, 1.0, '1', decoder.MAX_CAPACITY + 1):
            with self.subTest(capacity=capacity), self.assertRaises(ValueError):
                decoder.decode(data, birth_result(), capacity=capacity)
        self.assertEqual(decoder.memory_bytes(decoder.MAX_CAPACITY),
                         16 + 64 * decoder.MAX_CAPACITY)

    def test_both_inputs_and_output_objects_are_independent(self):
        data, births = bytearray(snapshot()), birth_result()
        original_data, original_births = bytes(data), copy.deepcopy(births)
        result = decode(memoryview(data), births)
        result['events'][0]['node'] = 0
        result['chains'][0]['birth_event_sequences'].append(123)
        result['chains'][0]['reasons'].append('output only')
        result['installs'][0]['callbacks'].append(123)
        result['limitations'].append('output only')
        self.assertEqual(bytes(data), original_data)
        self.assertEqual(births, original_births)
        another = decode(data, births)
        self.assertNotIn(123, another['chains'][0]['birth_event_sequences'])
        self.assertNotIn('output only', another['chains'][0]['reasons'])
        self.assertNotEqual(another['events'][0]['node'], 0)

    def test_birth_input_must_have_canonical_format_counter_and_event_schema(self):
        for invalid in (None, [], {}, dict(birth_result(), format='other'),
                        dict(birth_result(), counter=0),
                        dict(birth_result(), counter=True),
                        dict(birth_result(), capacity=0),
                        dict(birth_result(), counter=0xFFFFFFFF)):
            with self.subTest(invalid_type=type(invalid)), self.assertRaises(ValueError):
                decoder.decode(snapshot(), invalid, capacity=CAPACITY)
        for mutate in ('missing', 'extra', 'bool', 'wrong-parent', 'revision'):
            births = birth_result()
            if mutate == 'missing':
                del births['events'][0]['seq']
            elif mutate == 'extra':
                births['events'][0]['magic'] = birth.MAGIC
            elif mutate == 'bool':
                births['events'][0]['revision'] = True
            elif mutate == 'wrong-parent':
                births['events'][1]['parent'] = 2
            else:
                births['events'][1]['revision'] = 9
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                decode(births=births)

    def test_mutable_birth_request_summary_cannot_repair_missing_return(self):
        births = birth_result(birth_records()[:2])
        births['requests'] = birth_result()['requests']
        births['requests'][0].update(observed_enqueue_sequence_complete=True,
                                     queue_return_observed=True, append_return=NODE)
        chain = decode(births=births)['chains'][0]
        self.assertFalse(chain['producer_return_observed'])
        self.assertFalse(chain['observation_complete'])

    def test_all_zero_and_maximum_nonfault_sample_limits_are_supported(self):
        for revision, scope in ((0, 0), (0x7FFFFFFF, 0xFFFF),
                                (0x7FFFFFFF, 0x7FFFFFFF)):
            with self.subTest(revision=revision, scope=scope):
                chain = decode(snapshot(sequence(revision=revision, scope=scope)),
                               birth_result(birth_records(revision=revision, scope=scope)),
                               current_revision=revision, scope_issued=scope & 0xFFFF)['chains'][0]
                self.assertTrue(chain['observation_complete'])
                self.assertTrue(chain['known_boundary_unchanged'])
                self.assertEqual(chain['observed_scopes_quiet'], scope >> 16 == 0)
                self.assert_no_authority(chain)


if __name__ == '__main__':
    unittest.main()
