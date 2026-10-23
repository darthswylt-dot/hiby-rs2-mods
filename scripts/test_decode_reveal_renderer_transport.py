#!/usr/bin/env python3
"""Explicit renderer-root associations remain diagnostic and immutable."""

import copy
import struct
import unittest

import decode_reveal_lineage_rows as lineage_decoder
import decode_reveal_queue_transport as transport
import decode_reveal_renderer_transport as decoder
import folderfollow_reveal_lineage_mips as lineage
import test_decode_reveal_queue_transport as prior


CAPACITY = 12
CALLBACK_FRAME = prior.CALLBACK_FRAME
OUTER_FRAME, RENDER_FRAME = CALLBACK_FRAME - 0x200, CALLBACK_FRAME - 0x230
WIDGET, VIEW, PANEL, CONTROLLER, CACHE = (0x90002000, 0x90003000, 0x90006000,
                                         0x90007000, 0x90008000)


def event(kind=decoder.OUTER, *, seq=None, parent=None, origin=1,
          transport_id=4, lineage_id=None, frame=None, upstream=None,
          engine=prior.ENGINE, widget=WIDGET, view=None, panel=None,
          descriptor=CALLBACK_FRAME + 0x18, input=CALLBACK_FRAME + 0x90,
          controller=CONTROLLER, job=None, cache=None, revision=10, scope=4):
    if seq is None:
        seq = kind
    if parent is None:
        parent = transport_id if kind == decoder.OUTER else 1
    if frame is None:
        frame = OUTER_FRAME if kind == decoder.OUTER else RENDER_FRAME
    if upstream is None:
        upstream = CALLBACK_FRAME if kind == decoder.OUTER else OUTER_FRAME
    defaults = (0, 0, 0, 0, 0) if kind == decoder.OUTER else (1, VIEW, PANEL, VIEW + 0x38A4, CACHE)
    lineage_id = defaults[0] if lineage_id is None else lineage_id
    view, panel, job, cache = (default if value is None else value for value, default in
                               zip((view, panel, job, cache), defaults[1:]))
    return dict(magic=decoder.MAGIC, kind=kind, parent=parent, origin=origin,
                seq=seq, transport=transport_id, lineage=lineage_id,
                engine=engine, widget=widget, view=view, panel=panel,
                frame=frame, upstream=upstream, descriptor=descriptor, input=input,
                controller=controller, job=job, revision=revision, scope=scope,
                cache=cache, site=decoder.SITES[kind],
                reserved0=0, reserved1=0, reserved2=0)


def sequence(**options):
    return [event(decoder.OUTER, **options), event(decoder.RENDER, **options)]


def snapshot(records=None, *, counter=None, capacity=CAPACITY):
    records = sequence() if records is None else records
    counter = len(records) if counter is None else counter
    raw = bytearray(decoder.memory_bytes(capacity))
    struct.pack_into('<I', raw, 0, counter)
    for index, item in enumerate(records):
        struct.pack_into('<24I', raw, decoder.HEADER + index * decoder.RECORD,
                         *(item[field] for field in decoder.FIELDS))
    return bytes(raw)


def word(data, offset, value):
    raw = bytearray(data)
    struct.pack_into('<I', raw, offset, value)
    return bytes(raw)


def record_word(data, seq, field, value):
    return word(data, decoder.HEADER + (seq - 1) * decoder.RECORD
                + decoder.FIELDS.index(field) * 4, value)


def root(*, token=1, frame=RENDER_FRAME, view=VIEW, panel=PANEL,
         entry_revision=10, kind=lineage.RENDER):
    values = dict.fromkeys(lineage_decoder.LINEAGE_FIELDS, 0)
    values.update(magic=lineage.MAGIC, kind=kind, origin=token,
                  view=view, panel=panel, job=view + 0x38A4,
                  site=0x490758 if kind == lineage.RENDER else 0x48F40C,
                  stack=frame)
    return values, entry_revision


def lineage_result(roots=None, *, current_revision=10):
    roots = [root()] if roots is None else roots
    capacity = max(1, len(roots))
    raw = bytearray(lineage.memory_bytes(capacity))
    struct.pack_into('<I', raw, 0, len(roots))
    for index, (record, _) in enumerate(roots):
        struct.pack_into('<16I', raw, lineage.HEADER + index * lineage.RECORD,
                         *(record[field] & 0xFFFFFFFF for field in lineage_decoder.LINEAGE_FIELDS))
    receipts = lineage_decoder._receipts(raw, capacity)
    for receipt, (_, revision) in zip(receipts, roots):
        receipt['original_entry_revision'] = revision
    return dict(format='lineage-rows-queue-transport-v1', receipts=receipts,
                known_contents_revision=current_revision,
                windows=[dict(complete=False, reasons=['existing-rejection'])],
                operations=[dict(observed_callback_sequence_complete=False)])


def transport_result(births=None, *, records=None, current_revision=None):
    births = prior.birth_result() if births is None else births
    return transport.decode(prior.snapshot() if records is None else prior.snapshot(records),
                            births, capacity=prior.CAPACITY, current_revision=current_revision)


def decode(data=None, *, births=None, transported=None, lineaged=None, **options):
    births = prior.birth_result() if births is None else births
    transported = transport_result(births) if transported is None else transported
    lineaged = lineage_result() if lineaged is None else lineaged
    return decoder.decode(snapshot() if data is None else data, transported, lineaged,
                          birth_result=births, capacity=CAPACITY, **options)


class DecodeRevealRendererTransportTests(unittest.TestCase):
    def assert_no_authority(self, item):
        for flag in decoder.AUTHORITY_FLAGS:
            self.assertIs(item[flag], False, flag)

    def test_exact_schema_source_sites_and_memory_extent(self):
        self.assertEqual((decoder.HEADER, decoder.RECORD), (16, 96))
        self.assertEqual(decoder.MAGIC.to_bytes(4, 'little'), b'LQRD')
        self.assertEqual(decoder.SITES, {1: 0x438248, 2: 0x49076C})
        self.assertEqual(len(decoder.FIELDS), 24)
        self.assertEqual(decoder.FIELDS[19:21], ('cache', 'site'))
        self.assertEqual(decoder.memory_bytes(1), 112)

    def test_schema_matches_the_emitted_private_core(self):
        import reveal_renderer_transport_mips as core
        self.assertEqual((decoder.HEADER, decoder.RECORD, decoder.MAGIC),
                         (core.HEADER, core.RECORD, core.MAGIC))
        for index, field in enumerate(('MAGIC_OFFSET', 'KIND', 'PARENT', 'ORIGIN', 'SEQ',
                                       'TRANSPORT', 'LINEAGE', 'ENGINE', 'WIDGET', 'VIEW',
                                       'PANEL', 'FRAME', 'UPSTREAM', 'DESCRIPTOR', 'INPUT',
                                       'CONTROLLER', 'JOB', 'REVISION', 'SCOPE', 'CACHE', 'SITE')):
            self.assertEqual(getattr(core, field), index * 4)
        self.assertEqual(core.RESERVED, (84, 88, 92))
        self.assertEqual(core.memory_bytes(CAPACITY), decoder.memory_bytes(CAPACITY))

    def test_exact_ancestry_associates_existing_root_without_currentness(self):
        result = decode(current_revision=10, scope_issued=4)
        assoc = result['associations'][0]
        self.assertEqual(result['format'], decoder.FORMAT)
        self.assertEqual((assoc['birth'], assoc['callback'], assoc['outer'],
                          assoc['renderer'], assoc['lineage'], assoc['lineage_root']),
                         (1, 4, 1, 2, 1, 1))
        self.assertEqual(assoc['event_sequences'], [1, 2])
        self.assertEqual(assoc['transport_event_sequences'], [1, 2, 3, 4])
        self.assertEqual(assoc['birth_event_sequences'], [1, 2, 3])
        self.assertTrue(assoc['renderer_root_associated'])
        self.assertTrue(assoc['observed_birth_to_renderer_chain'])
        self.assertTrue(assoc['observation_complete'])
        self.assertTrue(assoc['producer_return_observed'])
        self.assertTrue(assoc['observed_enqueue_sequence_complete'])
        self.assertTrue(assoc['known_boundary_unchanged'])
        self.assertTrue(assoc['observed_scopes_quiet'])
        self.assertEqual(result['outers'][0]['lineage_roots'], [1])
        self.assertEqual(result['outers'][0]['renderer_ids'], [2])
        for item in (result, assoc, result['outers'][0]):
            self.assert_no_authority(item)
        for forbidden in ('row_origins', 'CompletedRows', 'success', 'fresh_request'):
            self.assertNotIn(forbidden, assoc)

    def test_literal_equality_is_not_exempted_for_ordinary_renderer_entry_bump(self):
        records = sequence()
        records[1]['revision'] = 11
        assoc = decode(snapshot(records), lineaged=lineage_result([root(entry_revision=11)],
                                                                 current_revision=11))['associations'][0]
        self.assertTrue(assoc['renderer_root_associated'])
        self.assertTrue(assoc['observation_complete'])
        self.assertEqual(assoc['original_entry_revision'], 11)
        self.assertEqual((assoc['birth_revision'], assoc['outer_revision'], assoc['renderer_revision']),
                         (10, 10, 11))
        self.assertFalse(assoc['known_boundary_unchanged'])
        self.assert_no_authority(assoc)

    def test_empty_or_outer_only_histories_do_not_claim_renderer_coverage(self):
        for records in ([], sequence()[:1]):
            with self.subTest(count=len(records)):
                result = decode(snapshot(records))
                self.assertEqual(result['associations'], [])
                self.assertFalse(result['renderer_root_associated'])
                self.assertFalse(result['observation_complete'])
                self.assert_no_authority(result)
                self.assertIn('coverage', ' '.join(result['limitations']))

    def test_missing_producer_return_preserves_root_association_but_not_completeness(self):
        births = prior.birth_result(prior.birth_records()[:2])
        assoc = decode(births=births)['associations'][0]
        self.assertTrue(assoc['renderer_root_associated'])
        self.assertTrue(assoc['observed_birth_to_renderer_chain'])
        self.assertFalse(assoc['producer_return_observed'])
        self.assertFalse(assoc['observed_enqueue_sequence_complete'])
        self.assertFalse(assoc['observation_complete'])
        self.assertFalse(assoc['known_boundary_unchanged'])
        self.assertIn('producer-return-not-observed', assoc['reasons'])

    def test_duplicate_return_remains_incomplete_without_selecting_a_matching_one(self):
        births = prior.birth_records()
        births.append(prior.birth_fixtures.event(prior.birth.RETURN, seq=4, result=prior.NODE))
        assoc = decode(births=prior.birth_result(births))['associations'][0]
        self.assertTrue(assoc['producer_return_observed'])
        self.assertFalse(assoc['unique_producer_return_observed'])
        self.assertFalse(assoc['observation_complete'])
        self.assertEqual(assoc['producer_return_sequences'], [3, 4])

    def test_later_return_is_not_required_to_precede_renderer_reservation(self):
        births = prior.birth_records()
        births[2].update(revision=12, scope=6)
        assoc = decode(births=prior.birth_result(births), current_revision=12,
                       scope_issued=6)['associations'][0]
        self.assertTrue(assoc['observation_complete'])
        self.assertTrue(assoc['observed_scopes_quiet'])
        self.assertFalse(assoc['known_boundary_unchanged'])

    def test_outer_requires_the_explicit_external_callback_kind_and_ticket(self):
        data = snapshot()
        for parent in (0, 1, 2, 3, 5, 0xFFFFFFFF):
            with self.subTest(parent=parent), self.assertRaises(ValueError):
                decode(record_word(data, 1, 'parent', parent))
        for field in ('transport', 'origin', 'engine'):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'CALLBACK binding'):
                decode(record_word(data, 1, field, 8 if field != 'engine' else prior.ENGINE + 4))

    def test_outer_unused_payload_must_stay_zero(self):
        data = snapshot()
        for field in ('lineage', 'view', 'panel', 'job', 'cache'):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'unused OUTER'):
                decode(record_word(data, 1, field, 4))

    def test_outer_frame_and_two_descriptors_have_exact_nonwrapping_offsets(self):
        data = snapshot()
        for field in ('frame', 'upstream', 'descriptor', 'input'):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'frame/descriptor'):
                decode(record_word(data, 1, field, sequence()[0][field] + 4))

    def test_renderer_requires_prior_outer_not_self_future_or_renderer(self):
        data = snapshot()
        for parent in (0, 2, 3, 0xFFFFFFFF):
            with self.subTest(parent=parent), self.assertRaises(ValueError):
                decode(record_word(data, 2, 'parent', parent))
        records = sequence() + [event(decoder.RENDER, seq=3, parent=2)]
        with self.assertRaisesRegex(ValueError, 'not OUTER'):
            decode(snapshot(records))

    def test_renderer_inherited_scalar_bindings_cannot_be_changed(self):
        data = snapshot()
        for field in ('transport', 'origin', 'engine', 'widget', 'descriptor', 'input', 'controller'):
            value = 8 if field in ('transport', 'origin') else 0x9000A000
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'OUTER binding'):
                decode(record_word(data, 2, field, value))

    def test_renderer_native_frame_and_job_delta_are_exact(self):
        data = snapshot()
        for field, value in (('frame', RENDER_FRAME + 4), ('upstream', OUTER_FRAME + 4),
                             ('job', VIEW + 0x38A0)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                decode(record_word(data, 2, field, value))

    def test_lineage_id_is_explicit_and_cannot_be_recovered_by_equal_addresses(self):
        data = snapshot()
        for root_id in (0, 2, 0xFFFFFFFF):
            with self.subTest(root=root_id), self.assertRaisesRegex(ValueError, 'lineage root'):
                decode(record_word(data, 2, 'lineage', root_id))
        roots = [root(), root(token=2)]
        assoc = decode(record_word(data, 2, 'lineage', 2),
                       lineaged=lineage_result(roots))['associations'][0]
        self.assertEqual(assoc['lineage'], 2)
        self.assertEqual(assoc['lineage_root'], 2)

    def test_lineage_root_kind_site_and_actual_payload_are_checked(self):
        with self.assertRaisesRegex(ValueError, 'not a RENDER root'):
            decode(lineaged=lineage_result([root(kind=lineage.INITIAL, entry_revision=0)]))
        for field in ('view', 'panel', 'job', 'stack'):
            parents = lineage_result()
            parents['receipts'][0][field] += 4
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'root binding'):
                decode(lineaged=parents)
        parents = lineage_result()
        parents['receipts'][0]['site'] += 4
        with self.assertRaisesRegex(ValueError, 'source site'):
            decode(lineaged=parents)

    def test_old_frontier_zero_is_unknown_not_replaced_with_current_revision(self):
        assoc = decode(lineaged=lineage_result([root(entry_revision=0)]))['associations'][0]
        self.assertTrue(assoc['renderer_root_associated'])
        self.assertTrue(assoc['observation_complete'])
        self.assertEqual(assoc['original_entry_revision'], 0)
        self.assertFalse(assoc['known_boundary_unchanged'])
        self.assert_no_authority(assoc)

    def test_original_entry_cannot_be_future_or_predate_observed_outer_sample(self):
        with self.assertRaisesRegex(ValueError, 'beyond'):
            decode(lineaged=lineage_result([root(entry_revision=11)]))
        with self.assertRaisesRegex(ValueError, 'entry revision order'):
            decode(lineaged=lineage_result([root(entry_revision=9)]))
        records = sequence()
        with self.assertRaisesRegex(ValueError, 'entry revision order'):
            decode(snapshot(records), lineaged=lineage_result([root(entry_revision=11)], current_revision=11))

    def test_distinct_actual_roots_under_same_outer_and_known_partial_outer_are_not_merged(self):
        records = sequence() + [event(decoder.RENDER, seq=3, lineage_id=2), event(decoder.OUTER, seq=4)]
        result = decode(snapshot(records), lineaged=lineage_result([root(), root(token=2)]))
        self.assertEqual([item['renderer'] for item in result['associations']], [2, 3])
        self.assertEqual(result['outers'][0]['renderer_ids'], [2, 3])
        self.assertTrue(result['associations'][0]['observation_complete'])
        self.assertFalse(result['outers'][1]['observation_complete'])
        self.assertFalse(result['observation_complete'])

    def test_same_existing_root_cannot_gain_duplicate_renderer_observer_receipts(self):
        for records in (sequence() + [event(decoder.RENDER, seq=3)],
                        sequence() + [event(decoder.OUTER, seq=3),
                                      event(decoder.RENDER, seq=4, parent=3)]):
            with self.subTest(count=len(records)), self.assertRaisesRegex(ValueError, 'duplicate observed lineage root'):
                decode(snapshot(records))

    def test_reused_all_native_addresses_do_not_merge_distinct_birth_and_lineage_ids(self):
        births = prior.birth_records()
        births.extend([prior.birth_fixtures.event(seq=4, origin=4),
                       prior.birth_fixtures.event(prior.birth.ENQUEUE_BEGIN, seq=5, parent=4, origin=4),
                       prior.birth_fixtures.event(prior.birth.RETURN, seq=6, parent=5, origin=4, result=prior.NODE)])
        transports = prior.sequence() + [
            prior.event(transport.INSTALL, seq=5, parent=5, origin=4),
            prior.event(transport.BORROW, seq=6, parent=5, origin=4),
            prior.event(transport.HELPER, seq=7, parent=6, origin=4),
            prior.event(transport.CALLBACK, seq=8, parent=7, origin=4)]
        records = sequence() + [event(decoder.OUTER, seq=3, parent=8, transport_id=8, origin=4),
                                event(decoder.RENDER, seq=4, parent=3, transport_id=8,
                                      lineage_id=2, origin=4)]
        births = prior.birth_result(births)
        result = decode(snapshot(records), births=births,
                        transported=transport_result(births, records=transports),
                        lineaged=lineage_result([root(), root(token=2)]))
        self.assertEqual([(item['birth'], item['callback'], item['lineage'])
                          for item in result['associations']], [(1, 4, 1), (4, 8, 2)])
        # Changing only the explicit second root ID must never attribute
        # one existing row lineage to both different prequeue births.
        records[-1]['lineage'] = 1
        with self.assertRaisesRegex(ValueError, 'duplicate observed lineage root'):
            decode(snapshot(records), births=births,
                   transported=transport_result(births, records=transports),
                   lineaged=lineage_result([root(), root(token=2)]))

    def test_unrelated_reservation_order_is_not_a_global_sample_clock(self):
        births = prior.birth_records(revision=20, scope=7)
        births.extend([prior.birth_fixtures.event(seq=4, origin=4, revision=10, scope=4),
                       prior.birth_fixtures.event(prior.birth.ENQUEUE_BEGIN, seq=5, parent=4,
                                                 origin=4, revision=10, scope=4),
                       prior.birth_fixtures.event(prior.birth.RETURN, seq=6, parent=5,
                                                 origin=4, revision=10, scope=4, result=prior.NODE)])
        transports = prior.sequence(revision=20, scope=7) + [
            prior.event(transport.INSTALL, seq=5, parent=5, origin=4),
            prior.event(transport.BORROW, seq=6, parent=5, origin=4),
            prior.event(transport.HELPER, seq=7, parent=6, origin=4),
            prior.event(transport.CALLBACK, seq=8, parent=7, origin=4)]
        records = sequence(revision=20, scope=7) + [
            event(decoder.OUTER, seq=3, parent=8, transport_id=8, origin=4),
            event(decoder.RENDER, seq=4, parent=3, transport_id=8, lineage_id=2, origin=4)]
        births = prior.birth_result(births)
        result = decode(snapshot(records), births=births,
                        transported=transport_result(births, records=transports),
                        lineaged=lineage_result([root(entry_revision=20), root(token=2)], current_revision=20),
                        current_revision=20, scope_issued=7)
        self.assertTrue(result['associations'][0]['known_boundary_unchanged'])
        self.assertFalse(result['associations'][1]['known_boundary_unchanged'])
        self.assertTrue(all(item['observation_complete'] for item in result['associations']))

    def test_parent_chain_revision_and_issued_scope_regressions_rejected(self):
        data = snapshot()
        for seq in (1, 2):
            for field, value in (('revision', 9), ('scope', 3)):
                with self.subTest(seq=seq, field=field), self.assertRaises(ValueError):
                    decode(record_word(data, seq, field, value))

    def test_active_scopes_affect_only_quiet_diagnostic_not_association(self):
        for seq in (1, 2):
            assoc = decode(record_word(snapshot(), seq, 'scope', 4 | 1 << 16))['associations'][0]
            self.assertTrue(assoc['renderer_root_associated'])
            self.assertTrue(assoc['observation_complete'])
            self.assertFalse(assoc['observed_scopes_quiet'])
            self.assert_no_authority(assoc)

    def test_all_added_addresses_require_positive_aligned_nonwrapping_extents(self):
        data = snapshot()
        for seq, fields in ((1, ('engine', 'widget', 'controller', 'frame', 'upstream', 'descriptor', 'input')),
                            (2, ('view', 'panel', 'cache'))):
            for field in fields:
                for value in (0, 1, 2, 3, 0xFFFFFFFC, 0xFFFFFFFF):
                    # A single word at FFFFFFFC is in bounds, but its
                    # required identity/frame bindings still reject it.
                    if field == 'cache' and value == 0xFFFFFFFC:
                        continue
                    with self.subTest(seq=seq, field=field, value=value), self.assertRaises(ValueError):
                        decode(record_word(data, seq, field, value))

    def test_faults_domains_magic_sites_sequences_reserved_and_dirty_tails_are_strict(self):
        data = snapshot()
        for seq in (1, 2):
            for field, values in (('magic', (0, 1, decoder.FAULT)),
                                  ('kind', (0, 3)), ('seq', (0, 3)),
                                  ('site', (0, decoder.SITES[seq] + 4)),
                                  ('revision', (0x80000000, decoder.FAULT)),
                                  ('scope', (0x80000000, 1 << 16, 5 << 16 | 4)),
                                  ('reserved0', (1,)), ('reserved1', (1,)), ('reserved2', (1,))):
                for value in values:
                    with self.subTest(seq=seq, field=field, value=value), self.assertRaises(ValueError):
                        decode(record_word(data, seq, field, value))
        for counter in (decoder.FAULT, CAPACITY + 1):
            with self.assertRaises(ValueError):
                decode(word(data, 0, counter))
        for offset in (4, 8, 12):
            with self.assertRaisesRegex(ValueError, 'reserved header'):
                decode(word(data, offset, 1))
        for field in decoder.FIELDS:
            with self.subTest(tailfield=field), self.assertRaisesRegex(ValueError, 'unallocated'):
                decode(record_word(data, CAPACITY, field, 1))
        with self.assertRaisesRegex(ValueError, 'unpublished'):
            decode(snapshot([], counter=1))

    def test_final_counter_bounds_apply_to_all_inputs_without_repair(self):
        for revision in (True, False, -1, 1.0, '10', 0x80000000, decoder.FAULT):
            with self.subTest(revision=revision), self.assertRaises(ValueError):
                decode(current_revision=revision)
        for issued in (True, False, -1, 1.0, '4', 0x10000):
            with self.subTest(issued=issued), self.assertRaises(ValueError):
                decode(scope_issued=issued)
        with self.assertRaisesRegex(ValueError, 'precedes'):
            decode(current_revision=9)
        with self.assertRaisesRegex(ValueError, 'beyond'):
            decode(scope_issued=3)
        for field, value, options in (('revision', 11, dict(current_revision=10)),
                                      ('scope', 5, dict(scope_issued=4))):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'beyond'):
                decode(record_word(snapshot(), 2, field, value), **options)

    def test_parent_mutable_summaries_cannot_forge_completeness_or_root(self):
        births = prior.birth_result(prior.birth_records()[:2])
        transported = transport_result(births)
        transported['chains'][0].update(observation_complete=True, producer_return_observed=True)
        parents = lineage_result()
        parents['windows'][0]['complete'] = True
        parents['operations'][0]['observed_callback_sequence_complete'] = True
        assoc = decode(births=births, transported=transported, lineaged=parents)['associations'][0]
        self.assertFalse(assoc['observation_complete'])
        self.assertFalse(assoc['producer_return_observed'])
        self.assertTrue(assoc['renderer_root_associated'])

    def test_canonical_parent_event_and_receipt_mutations_are_revalidated(self):
        for mutate in ('format', 'counter', 'events', 'parent', 'extra'):
            parent = transport_result()
            if mutate == 'format':
                parent['format'] = 'other'
            elif mutate == 'counter':
                parent['counter'] = 0
            elif mutate == 'events':
                parent['events'][3]['engine'] += 4
            elif mutate == 'parent':
                parent['events'][3]['parent'] = 1
            else:
                parent['events'][0]['extra'] = 0
            with self.subTest(transport=mutate), self.assertRaises(ValueError):
                decode(transported=parent)
        for mutate in ('format', 'receipts', 'id', 'origin', 'parent', 'bool', 'extension', 'extra'):
            parent = lineage_result()
            if mutate == 'format':
                parent['format'] = 'other'
            elif mutate == 'receipts':
                parent['receipts'] = None
            else:
                receipt = parent['receipts'][0]
                if mutate in ('id', 'origin', 'parent'):
                    receipt[mutate] = 2
                elif mutate == 'bool':
                    receipt['kind'] = True
                elif mutate == 'extension':
                    receipt['original_entry_revision'] = decoder.FAULT
                else:
                    receipt['extra'] = 0
            with self.subTest(lineage=mutate), self.assertRaises(ValueError):
                decode(lineaged=parent)

    def test_known_lineage_extensions_and_signed_descendant_fields_are_preserved(self):
        parents = lineage_result(current_revision=11)
        original = parents['receipts'][0]
        borrowed = dict(original, id=2, kind=lineage.BORROW, parent=1,
                        job=0x90009000, site=0x48EB40, stack=0x90010000)
        queried = dict(borrowed, id=3, kind=lineage.QUERY, parent=2,
                       dest=0x90011000, site=0x48D1B8, stack=borrowed['stack'] - 0x40,
                       offset=-1, request=3)
        produced = dict(queried, id=4, kind=lineage.PRODUCER, parent=3,
                        stack=queried['stack'] - 0xAD0 - 0xBE0 - 0x80,
                        stmt=0x90012000, site=0x6ED624, producer_revision=11)
        parents['receipts'].extend([borrowed, queried, produced])
        untouched = copy.deepcopy(parents)
        assoc = decode(lineaged=parents)['associations'][0]
        self.assertTrue(assoc['renderer_root_associated'])
        self.assertEqual(parents, untouched)
        for mutate in ('original', 'future-producer', 'producer-before-entry', 'nonproducer-extension', 'signed-bool'):
            changed = copy.deepcopy(parents)
            if mutate == 'original':
                changed['receipts'][1]['original_entry_revision'] = 9
            elif mutate == 'future-producer':
                changed['receipts'][3]['producer_revision'] = 12
            elif mutate == 'producer-before-entry':
                changed['receipts'][3]['producer_revision'] = 9
            elif mutate == 'nonproducer-extension':
                changed['receipts'][0]['producer_revision'] = 10
            else:
                changed['receipts'][2]['offset'] = True
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                decode(lineaged=changed)

    def test_zero_and_maximum_nonfault_revision_scope_domains_remain_historical(self):
        for revision, scope in ((0, 0), (0x7FFFFFFF, 0xFFFF),
                                (0x7FFFFFFF, 0x7FFFFFFF)):
            with self.subTest(revision=revision, scope=scope):
                births = prior.birth_result(prior.birth_records(revision=revision, scope=scope))
                transported = transport_result(births, records=prior.sequence(revision=revision, scope=scope))
                parents = lineage_result([root(entry_revision=revision)], current_revision=revision)
                assoc = decode(snapshot(sequence(revision=revision, scope=scope)),
                               births=births, transported=transported, lineaged=parents,
                               current_revision=revision, scope_issued=scope & 0xFFFF)['associations'][0]
                self.assertTrue(assoc['renderer_root_associated'])
                self.assertTrue(assoc['observation_complete'])
                self.assertEqual(assoc['known_boundary_unchanged'], revision != 0)
                self.assertEqual(assoc['observed_scopes_quiet'], scope >> 16 == 0)
                self.assert_no_authority(assoc)

    def test_every_input_is_owned_and_output_lists_are_independent(self):
        data, births, transported, parents = bytearray(snapshot()), prior.birth_result(), transport_result(), lineage_result()
        before = (bytes(data), copy.deepcopy(births), copy.deepcopy(transported), copy.deepcopy(parents))
        result = decode(memoryview(data), births=births, transported=transported, lineaged=parents)
        result['associations'][0]['birth_event_sequences'].append(123)
        result['associations'][0]['reasons'].append('output only')
        result['events'][0]['engine'] = 0
        result['outers'][0]['lineage_roots'].append(123)
        result['limitations'].append('output only')
        self.assertEqual((bytes(data), births, transported, parents), before)
        again = decode(data, births=births, transported=transported, lineaged=parents)
        self.assertNotIn(123, again['associations'][0]['birth_event_sequences'])
        self.assertNotIn('output only', again['associations'][0]['reasons'])
        self.assertNotEqual(again['events'][0]['engine'], 0)

    def test_exact_owned_extent_capacity_types_and_full_journal_are_not_coverage(self):
        data = snapshot()
        for raw in (None, '', [], 1, b'', data[:-1], data + b'\0'):
            with self.subTest(type=type(raw)), self.assertRaises(ValueError):
                decoder.decode(raw, transport_result(), lineage_result(),
                               birth_result=prior.birth_result(), capacity=CAPACITY)
        for capacity in (True, False, 0, -1, 1.0, '1', decoder.MAX_CAPACITY + 1):
            with self.subTest(capacity=capacity), self.assertRaises(ValueError):
                decoder.decode(data, transport_result(), lineage_result(), birth_result=prior.birth_result(), capacity=capacity)
        full = decoder.decode(snapshot(capacity=2), transport_result(), lineage_result(),
                              birth_result=prior.birth_result(), capacity=2)
        self.assertTrue(full['capacity_full'])
        self.assertTrue(full['observation_complete'])
        self.assert_no_authority(full)
        self.assertEqual(decoder.memory_bytes(decoder.MAX_CAPACITY), 16 + 96 * decoder.MAX_CAPACITY)


if __name__ == '__main__':
    unittest.main()
