#!/usr/bin/env python3
"""Decode executed renderer/root/row identity without promoting UI authority.

The integration fixture executes native callback and call boundaries while
explicitly replacing outer geometry and the renderer suffix/worker/SQL work.
These are owned historical snapshots, not full UI execution or live leases.
"""

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
import struct
import unittest
from unittest.mock import patch

import decode_reveal_renderer_transport_stage as decoder
import decode_reveal_renderer_transport as renderer
import decode_reveal_queue_transport as transport
import decode_reveal_queue_birth as birth
import folderfollow_reveal_lineage_mips as lineage
import test_reveal_renderer_transport_stage as integration


CAPACITIES = dict(capacity=16, row_capacity=16, operation_capacity=16,
                  scope_capacity=16, birth_capacity=32, transport_capacity=64,
                  renderer_capacity=32)
PREVIOUS_CAPACITIES = {key: value for key, value in CAPACITIES.items()
                       if key != 'renderer_capacity'}


def word(data, offset, value):
    changed = bytearray(data)
    struct.pack_into('<I', changed, offset, value)
    return bytes(changed)


class DecodeRevealRendererTransportStageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture_class = integration.RevealRendererTransportStageTests
        fixture_class.setUpClass()
        cls.fixture = fixture_class()
        machine, cls.root, cls.observed = cls.fixture.history(rows=True)
        cls.history = machine.snapshot()
        cls.without_rows = cls.fixture.history(rows=False)[0].snapshot()
        cls.empty = cls.fixture.machine().snapshot()
        cls.renderer_offset = (machine.meta['renderer_transport_buffer'] - machine.meta['buffer'])
        cls.transport_offset = machine.meta['transport_buffer'] - machine.meta['buffer']
        cls.birth_offset = machine.meta['birth_buffer'] - machine.meta['buffer']
        cls.scope_offset = machine.meta['scope_buffer'] - machine.meta['buffer']
        cls.row_offset = machine.meta['row_buffer'] - machine.meta['buffer']
        cls.revision_offset = (machine.meta['contents_revision_buffer'] - machine.meta['buffer'])
        cls.operation_offset = machine.meta['operation_buffer'] - machine.meta['buffer']

    def decode(self, data=None, **capacities):
        options = dict(CAPACITIES)
        options.update(capacities)
        return decoder.decode(self.history if data is None else data, **options)

    def assert_no_authority(self, result):
        for field in renderer.AUTHORITY_FLAGS:
            self.assertIs(result[field], False, field)

    def renderer_word(self, data, field, value, *, seq=1):
        offset = (self.renderer_offset + renderer.HEADER + (seq - 1) * renderer.RECORD
                  + renderer.FIELDS.index(field) * 4)
        return word(data, offset, value)

    def birth_word(self, data, field, value, *, seq=1):
        offset = (self.birth_offset + birth.HEADER + (seq - 1) * birth.RECORD
                  + birth.FIELDS.index(field) * 4)
        return word(data, offset, value)

    def transport_word(self, data, field, value, *, seq=1):
        offset = (self.transport_offset + transport.HEADER + (seq - 1) * transport.RECORD
                  + transport.FIELDS.index(field) * 4)
        return word(data, offset, value)

    def lineage_word(self, data, field, value, *, seq=1):
        return word(data, lineage.HEADER + (seq - 1) * lineage.RECORD + field, value)

    def test_actual_renderer_root_and_captured_rows_are_historically_associated_only(self):
        result = self.decode()
        observed = result['renderer_transport_observation']
        association = observed['associations'][0]
        rows = result['renderer_row_associations'][0]
        self.assertEqual(result['format'], 'lineage-rows-renderer-transport-v1')
        self.assertEqual(result['format'], decoder.FORMAT)
        self.assertEqual(observed['format'], renderer.FORMAT)
        self.assertEqual([item['kind'] for item in observed['events']], [1, 2])
        self.assertEqual([item['parent'] for item in observed['events']], [4, 1])
        self.assertEqual((association['birth'], association['callback'], association['outer'],
                          association['renderer'], association['lineage']), (1, 4, 1, 2, self.root))
        self.assertEqual(association['event_sequences'], [1, 2])
        self.assertTrue(association['renderer_root_associated'])
        self.assertTrue(association['observed_birth_to_renderer_chain'])
        self.assertTrue(association['observation_complete'])
        self.assertTrue(result['renderer_identity_transport_enabled'])
        self.assertTrue(result['renderer_identity_associated'])
        self.assertEqual(result['birth_transport_target'], 'existing-native-renderer-lineage-root')
        self.assertEqual(rows['lineage'], self.root)
        self.assertEqual(rows['producers'], [self.observed['producer']])
        self.assertEqual(rows['row_event_sequences'], [1])
        self.assertEqual(rows['window_indices'], [0])
        self.assertEqual(rows['operation_borrows'], [2])
        self.assertTrue(rows['observed_row_identity_associated'])
        for item in (result, observed, association, observed['outers'][0], rows):
            self.assert_no_authority(item)
        self.assertIn('historical cause evidence', ' '.join(result['limitations']))

    def test_native_renderer_entry_counter_bump_is_not_exempted_from_literal_equality(self):
        result = self.decode(self.without_rows)
        association = result['renderer_transport_observation']['associations'][0]
        self.assertEqual((association['birth_revision'], association['outer_revision'],
                          association['renderer_revision'], association['original_entry_revision']),
                         (0, 0, 1, 1))
        self.assertTrue(association['observation_complete'])
        self.assertFalse(association['known_boundary_unchanged'])
        self.assertIn('known-boundary-unchanged-not-observed', association['reasons'])
        self.assert_no_authority(result)
        self.assert_no_authority(association)

    def test_root_without_rows_is_not_reported_as_captured_row_coverage(self):
        result = self.decode(self.without_rows)
        rows = result['renderer_row_associations'][0]
        self.assertTrue(rows['renderer_root_associated'])
        self.assertFalse(rows['observed_row_identity_associated'])
        for field in ('producers', 'row_event_sequences', 'window_indices', 'operation_borrows'):
            self.assertEqual(rows[field], [])
        self.assertEqual(result['windows'], [])
        self.assertEqual(result['operations'], [])
        self.assert_no_authority(rows)

    def test_empty_format_configuration_is_not_an_observed_root_or_coverage(self):
        result = self.decode(self.empty)
        observed = result['renderer_transport_observation']
        self.assertEqual(observed['events'], [])
        self.assertEqual(observed['associations'], [])
        self.assertEqual(observed['outers'], [])
        self.assertEqual(result['renderer_row_associations'], [])
        self.assertFalse(result['renderer_identity_associated'])
        self.assertFalse(observed['renderer_root_associated'])
        self.assertFalse(observed['observation_complete'])
        self.assertIn('coverage', ' '.join(observed['limitations']))
        self.assert_no_authority(result)
        self.assert_no_authority(observed)

    def test_outer_only_snapshot_does_not_guess_the_present_root_or_rows(self):
        changed = bytearray(word(self.history, self.renderer_offset, 1))
        offset = self.renderer_offset + renderer.HEADER + renderer.RECORD
        changed[offset:offset + renderer.RECORD] = bytes(renderer.RECORD)
        result = self.decode(changed)
        observed = result['renderer_transport_observation']
        self.assertTrue(result['receipts'])
        self.assertTrue(result['windows'][0]['observed_window_complete'])
        self.assertEqual([item['kind'] for item in observed['events']], [renderer.OUTER])
        self.assertEqual(observed['associations'], [])
        self.assertEqual(result['renderer_row_associations'], [])
        self.assertFalse(result['renderer_identity_associated'])
        self.assertFalse(observed['outers'][0]['renderer_root_associated'])
        self.assert_no_authority(result)

    def test_unclassified_route_can_capture_rows_but_cannot_invent_renderer_birth_ancestry(self):
        machine = self.fixture.machine()
        gap = integration.gap
        machine.r[29], machine.r[31] = gap.ENGINE_STACK, 0x8B4998
        machine.r[4:6] = [gap.ENGINE, gap.INPUT]
        machine.external(0x439EC0)
        root = machine.renderer_runs[0]['lineage']
        self.fixture.rows_from_root(machine, root)
        result = self.decode(machine.snapshot())
        self.assertTrue(result['receipts'])
        self.assertTrue(result['windows'][0]['observed_window_complete'])
        self.assertEqual(result['renderer_transport_observation']['events'], [])
        self.assertEqual(result['renderer_transport_observation']['associations'], [])
        self.assertEqual(result['renderer_row_associations'], [])
        self.assertFalse(result['renderer_identity_associated'])
        self.assert_no_authority(result)

    def test_exact_prior_prefix_outputs_and_all_old_rejections_are_preserved(self):
        prior = decoder.previous.decode(self.history[:self.renderer_offset],
                                        **PREVIOUS_CAPACITIES)
        result = self.decode()
        for key in ('receipts', 'events', 'windows', 'operation_events', 'operations',
                    'native_scope', 'scope_quiet', 'known_contents_revision',
                    'queue_birth_observation', 'queue_transport_observation'):
            self.assertEqual(result[key], prior[key], key)
        self.assertTrue(result['windows'][0]['observed_window_complete'])
        self.assertFalse(result['windows'][0]['complete'])
        self.assertIn('known-contents-boundary', result['windows'][0]['reasons'])
        self.assertTrue(result['operations'][0]['observed_callback_sequence_complete'])
        self.assert_no_authority(result)

    def test_new_explicit_row_identity_does_not_repair_original_frontier_rejection(self):
        changed = self.lineage_word(self.history, 60, 0)
        result = self.decode(changed)
        association = result['renderer_transport_observation']['associations'][0]
        rows = result['renderer_row_associations'][0]
        self.assertTrue(association['renderer_root_associated'])
        self.assertTrue(rows['observed_row_identity_associated'])
        self.assertFalse(result['operations'][0]['original_frontier_matches'])
        self.assertFalse(result['operations'][0]['observed_callback_sequence_complete'])
        self.assertIn('original-entry-frontier-mismatch', result['operations'][0]['reasons'])
        self.assertFalse(result['windows'][0]['complete'])
        self.assertIn('known-contents-boundary', result['windows'][0]['reasons'])
        self.assert_no_authority(result)
        self.assert_no_authority(rows)

    def test_equal_native_addresses_do_not_join_second_explicit_root_to_first_roots_rows(self):
        machine = self.fixture.machine()
        machine.repeat_callbacks = 2
        observed = {}

        def rows_from_first_root(current, run):
            # Capture while this root's original frontier is still valid.
            # The later renderer entry must revoke it, not be exempted so an
            # old root could create new rows after a newer entry has started.
            current.on_root = None
            observed.update(self.fixture.rows_from_root(current, run['lineage']))

        machine.on_root = rows_from_first_root
        machine.enqueue()
        machine.consume()
        first, second = machine.renderer_runs
        self.assertEqual(first['frame'], second['frame'])
        self.assertNotEqual(first['lineage'], second['lineage'])
        result = self.decode(machine.snapshot())
        first_association, second_association = result['renderer_transport_observation']['associations']
        for field in ('engine', 'widget', 'view', 'panel', 'job', 'cache', 'frame'):
            self.assertEqual(first_association[field], second_association[field], field)
        first_rows, second_rows = result['renderer_row_associations']
        self.assertEqual(first_rows['lineage'], first['lineage'])
        self.assertEqual(first_rows['producers'], [observed['producer']])
        self.assertEqual(first_rows['row_event_sequences'], [1])
        self.assertTrue(first_rows['observed_row_identity_associated'])
        self.assertEqual(second_rows['lineage'], second['lineage'])
        for field in ('producers', 'row_event_sequences', 'window_indices', 'operation_borrows'):
            self.assertEqual(second_rows[field], [], field)
        self.assertFalse(second_rows['observed_row_identity_associated'])
        self.assert_no_authority(result)
        self.assert_no_authority(second_rows)

    def test_separate_association_output_does_not_rewrite_old_rows_or_receipt_schema(self):
        result = self.decode()
        for entry in result['receipts'] + result['operations'] + result['windows'] + result['events']:
            for forbidden in ('birth', 'queue_birth', 'request_birth', 'queue_transport',
                              'renderer_transport', 'renderer_association', 'callback_birth'):
                self.assertNotIn(forbidden, entry)
        for window in result['windows']:
            for row in window['rows']:
                self.assertNotIn('birth', row)
                self.assertNotIn('renderer_transport', row)

    def test_missing_producer_return_preserves_root_and_row_identity_but_not_complete_observation(self):
        changed = bytearray(word(self.history, self.birth_offset, 2))
        offset = self.birth_offset + birth.HEADER + 2 * birth.RECORD
        changed[offset:offset + birth.RECORD] = bytes(birth.RECORD)
        result = self.decode(changed)
        association = result['renderer_transport_observation']['associations'][0]
        rows = result['renderer_row_associations'][0]
        self.assertTrue(association['renderer_root_associated'])
        self.assertTrue(association['observed_birth_to_renderer_chain'])
        self.assertFalse(association['producer_return_observed'])
        self.assertFalse(association['observation_complete'])
        self.assertIn('producer-return-not-observed', association['reasons'])
        self.assertTrue(rows['observed_row_identity_associated'])
        self.assertFalse(rows['observation_complete'])
        self.assert_no_authority(rows)

    def test_wrong_append_return_is_not_repaired_by_renderer_or_row_identity(self):
        result = self.decode(self.birth_word(self.history, 'result', 0, seq=3))
        association = result['renderer_transport_observation']['associations'][0]
        self.assertTrue(association['renderer_root_associated'])
        self.assertFalse(association['append_return_matches_node'])
        self.assertFalse(association['observation_complete'])
        self.assertIn('append-return-node-mismatch', association['reasons'])
        self.assertTrue(result['renderer_row_associations'][0]['observed_row_identity_associated'])
        self.assert_no_authority(result)

    def test_renderer_header_fault_reserved_counts_and_all_unallocated_words_are_rejected(self):
        candidates = [word(self.history, self.renderer_offset, value)
                      for value in (renderer.FAULT, CAPACITIES['renderer_capacity'] + 1, 0)]
        candidates.extend(word(self.history, self.renderer_offset + offset, 1)
                          for offset in (4, 8, 12))
        candidates.extend(self.renderer_word(self.history, field, 1, seq=32)
                          for field in renderer.FIELDS)
        for data in candidates:
            with self.subTest(header=data[self.renderer_offset:self.renderer_offset + 16]), \
                    self.assertRaises(ValueError):
                self.decode(data)

    def test_malformed_renderer_ancestry_sites_frames_immutable_bindings_padding_rejected(self):
        changes = ((1, 'magic', 0), (1, 'kind', 0), (1, 'site', 0), (1, 'parent', 1),
                   (1, 'origin', 2), (1, 'seq', 2), (1, 'transport', 3), (1, 'engine', 0),
                   (1, 'widget', 1), (1, 'controller', 0), (1, 'frame', 4),
                   (1, 'upstream', 0), (1, 'descriptor', 0), (1, 'input', 0),
                   (1, 'lineage', 1), (1, 'view', 4), (1, 'panel', 4), (1, 'job', 4),
                   (1, 'cache', 4), (1, 'reserved0', 1),
                   (2, 'parent', 2), (2, 'transport', 3), (2, 'origin', 2),
                   (2, 'engine', 4), (2, 'widget', 4), (2, 'view', 0),
                   (2, 'panel', 0), (2, 'frame', 4), (2, 'upstream', 0),
                   (2, 'descriptor', 4), (2, 'input', 4), (2, 'controller', 4),
                   (2, 'job', 4), (2, 'cache', 0), (2, 'site', 0), (2, 'reserved2', 1))
        for seq, field, value in changes:
            with self.subTest(seq=seq, field=field), self.assertRaises(ValueError):
                self.decode(self.renderer_word(self.history, field, value, seq=seq))

    def test_renderer_lineage_foreign_key_must_name_exact_existing_root_and_payload(self):
        for value in (0, 2, 3, 4, 17, 0xFFFFFFFF):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.decode(self.renderer_word(self.history, 'lineage', value, seq=2))
        for field, value in ((lineage.STACK, 4), (lineage.VIEW, 4), (lineage.PANEL, 4),
                             (lineage.JOB, 4), (lineage.SITE, 0), (lineage.PARENT, 1),
                             (lineage.ORIGIN, 2)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.decode(self.lineage_word(self.history, field, value))

    def test_current_counter_scope_bounds_sample_domains_and_entry_order_are_strict(self):
        current = struct.unpack_from('<I', self.history, self.revision_offset)[0]
        candidates = [self.renderer_word(self.history, field, value, seq=seq)
                      for seq, field, value in ((1, 'revision', 0x80000000),
                                                (2, 'revision', current + 1),
                                                (1, 'scope', 0x80000000),
                                                (2, 'scope', 0x10000), (2, 'scope', 1),
                                                (2, 'revision', 0))]
        candidates.extend((word(self.history, self.revision_offset, 0),
                           self.lineage_word(self.history, 60, current + 1)))
        for data in candidates:
            with self.assertRaises(ValueError):
                self.decode(data)

    def test_parent_sample_revision_and_scope_ticket_regressions_are_rejected(self):
        changed = self.renderer_word(self.history, 'revision', 2)
        with self.assertRaises(ValueError):
            self.decode(changed)
        machine = self.fixture.machine()
        machine.reset()
        machine.consume()
        changed = self.renderer_word(machine.snapshot(), 'scope', 0, seq=2)
        with self.assertRaisesRegex(ValueError, 'regressed'):
            self.decode(changed)

    def test_later_final_counter_narrows_history_without_changing_old_prefix_outputs(self):
        current = struct.unpack_from('<I', self.history, self.revision_offset)[0]
        changed = word(self.history, self.revision_offset, current + 1)
        result = self.decode(changed)
        prior = decoder.previous.decode(changed[:self.renderer_offset], **PREVIOUS_CAPACITIES)
        self.assertTrue(result['renderer_transport_observation']['associations'][0]['renderer_root_associated'])
        self.assertFalse(result['renderer_transport_observation']['associations'][0]['known_boundary_unchanged'])
        self.assertTrue(result['renderer_row_associations'][0]['observed_row_identity_associated'])
        for field in ('receipts', 'events', 'windows', 'operations', 'queue_birth_observation',
                      'queue_transport_observation'):
            self.assertEqual(result[field], prior[field], field)
        self.assert_no_authority(result)

    def test_complete_new_ancestry_cannot_mask_faults_or_corruption_in_any_prior_journal(self):
        candidates = [word(self.history, offset, value) for offset, value in
                      ((0, 0xFFFFFFFF), (4, 1), (16, 0),
                       (self.row_offset, 0xFFFFFFFF), (self.row_offset + 4, 1),
                       (self.row_offset + 16, 0), (self.revision_offset, 0xFFFFFFFF),
                       (self.revision_offset + 4, 1),
                       (self.operation_offset + 4, 1), (self.operation_offset + 16, 0),
                       (self.scope_offset, 0xFFFFFFFF), (self.scope_offset + 4, 1),
                       (self.birth_offset, 0xFFFFFFFF), (self.birth_offset + 4, 1),
                       (self.transport_offset, 0xFFFFFFFF), (self.transport_offset + 4, 1))]
        candidates.extend((self.birth_word(self.history, 'parent', 2, seq=2),
                           self.birth_word(self.history, 'copy', 0, seq=2),
                           self.transport_word(self.history, 'parent', 4, seq=4),
                           self.transport_word(self.history, 'origin', 2, seq=4),
                           self.transport_word(self.history, 'frame', 4, seq=4)))
        for data in candidates:
            with self.assertRaises(ValueError):
                self.decode(data)

    def test_owned_buffer_variants_input_immutability_and_no_output_aliases(self):
        expected = self.decode()
        for kind in (bytes, bytearray, memoryview):
            with self.subTest(kind=kind):
                original = bytearray(self.history)
                before = bytes(original)
                result = self.decode(kind(original))
                self.assertEqual(result, expected)
                result['renderer_transport_observation']['events'][0]['widget'] = 0
                result['renderer_transport_observation']['associations'][0]['reasons'].append('output only')
                result['renderer_row_associations'][0]['producers'].append(0)
                result['renderer_row_associations'][0]['row_event_sequences'].append(0)
                result['renderer_transport_observation']['limitations'].append('output only')
                result['queue_transport_observation']['events'][0]['node'] = 0
                result['receipts'][0]['stack'] = 0
                result['windows'][0]['rows'][0]['path'] = 'output only'
                result['operations'][0]['reasons'].append('output only')
                self.assertEqual(bytes(original), before)
                self.assertEqual(self.decode(), expected)

    def test_wrong_sizes_nonbuffer_types_and_default_capacities_are_rejected(self):
        for data in (self.history[:-1], self.history + b'\0', self.history[:self.renderer_offset],
                     b'', '', 1, [], None):
            with self.subTest(kind=type(data)), self.assertRaises(ValueError):
                decoder.decode(data, **CAPACITIES)
        with self.assertRaises(ValueError):
            decoder.decode(self.history)

    def test_each_invalid_or_mismatched_capacity_is_rejected(self):
        for field in CAPACITIES:
            for value in (15, 17, 0, -1, True, False, 1.5, None):
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    self.decode(**{field: value})
        with self.assertRaises(ValueError):
            self.decode(scope_capacity=65536)

    def test_prior_format_rejects_new_extension_and_new_format_rejects_old_prefix(self):
        with self.assertRaises(ValueError):
            decoder.previous.decode(self.history, **PREVIOUS_CAPACITIES)
        previous = decoder.previous.decode(self.history[:self.renderer_offset],
                                            **PREVIOUS_CAPACITIES)
        self.assertFalse(previous['renderer_identity_associated'])
        with self.assertRaises(ValueError):
            self.decode(self.history[:self.renderer_offset])

    def test_cli_uses_only_supplied_local_snapshot_explicit_capacities_and_reports_errors(self):
        args = ['owned.bin']
        for key, value in CAPACITIES.items():
            args.extend(['--' + key.replace('_', '-'), str(value)])
        output = StringIO()
        with patch.object(decoder.Path, 'read_bytes', return_value=self.history) as reader:
            with redirect_stdout(output):
                decoder.main(args)
            reader.assert_called_once_with()
        result = json.loads(output.getvalue())
        self.assertEqual(result['format'], decoder.FORMAT)
        self.assertTrue(result['renderer_row_associations'][0]['observed_row_identity_associated'])
        self.assert_no_authority(result)
        for failure in (b'bad', OSError('unavailable')):
            options = dict(side_effect=failure) if isinstance(failure, OSError) else dict(return_value=failure)
            with patch.object(decoder.Path, 'read_bytes', **options):
                with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as error:
                    decoder.main(args)
                self.assertEqual(error.exception.code, 2)


if __name__ == '__main__':
    unittest.main()
