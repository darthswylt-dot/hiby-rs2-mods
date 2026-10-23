#!/usr/bin/env python3
"""Decode executed callback-entry histories, not native ownership or row joins.

The integration fixture executes the new callback ENTRY and then its existing
mock paint body. It does not execute all intervening widget/render/SQL logic.
The copied snapshots below are owned evidence, not a live coherent capture.
"""

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
import struct
import unittest
from unittest.mock import patch

import decode_reveal_queue_transport_stage as decoder
import decode_reveal_queue_transport as transport
import decode_reveal_queue_birth as birth
import test_reveal_queue_transport_stage as integration


CAPACITIES = dict(capacity=16, row_capacity=16, operation_capacity=16,
                  scope_capacity=16, birth_capacity=32, transport_capacity=64)
PREVIOUS_CAPACITIES = {key: value for key, value in CAPACITIES.items()
                       if key != 'transport_capacity'}


def word(data, offset, value):
    changed = bytearray(data)
    struct.pack_into('<I', changed, offset, value)
    return bytes(changed)


class DecodeRevealQueueTransportStageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture_class = integration.RevealQueueTransportStageTests
        fixture_class.setUpClass()
        cls.fixture = fixture_class()
        machine = cls.fixture.machine()
        machine.enqueue()
        machine.consume()
        cls.fresh = machine.snapshot()
        cls.empty = cls.fixture.machine().snapshot()
        cls.transport_offset = machine.meta['transport_buffer'] - machine.meta['buffer']
        cls.birth_offset = machine.meta['birth_buffer'] - machine.meta['buffer']
        cls.scope_offset = machine.meta['scope_buffer'] - machine.meta['buffer']
        cls.row_offset = machine.meta['row_buffer'] - machine.meta['buffer']
        cls.revision_offset = (machine.meta['contents_revision_buffer']
                               - machine.meta['buffer'])
        cls.operation_offset = machine.meta['operation_buffer'] - machine.meta['buffer']
        history = cls.fixture.machine()
        cls.fixture.sequence(history)
        history.enqueue()
        history.consume()
        cls.history = history.snapshot()

    def decode(self, data=None, **capacities):
        options = dict(CAPACITIES)
        options.update(capacities)
        return decoder.decode(self.fresh if data is None else data, **options)

    def assert_no_authority(self, result):
        for field in transport.AUTHORITY_FLAGS:
            self.assertIs(result[field], False, field)

    def transport_word(self, data, field, value, *, seq=1):
        offset = (self.transport_offset + transport.HEADER + (seq - 1) * transport.RECORD
                  + transport.FIELDS.index(field) * 4)
        return word(data, offset, value)

    def birth_word(self, data, field, value, *, seq=1):
        offset = (self.birth_offset + birth.HEADER + (seq - 1) * birth.RECORD
                  + birth.FIELDS.index(field) * 4)
        return word(data, offset, value)

    def test_exact_fresh_chain_reaches_callback_entry_without_renderer_or_ui_authority(self):
        result = self.decode()
        observed = result['queue_transport_observation']
        chain = observed['chains'][0]
        self.assertEqual(result['format'], 'lineage-rows-queue-transport-v1')
        self.assertEqual(result['format'], decoder.FORMAT)
        self.assertEqual(observed['format'], transport.FORMAT)
        self.assertEqual([item['kind'] for item in observed['events']], [1, 2, 3, 4])
        self.assertEqual([item['parent'] for item in observed['events']], [2, 1, 2, 3])
        self.assertEqual(chain['event_sequences'], [1, 2, 3, 4])
        self.assertEqual(chain['birth_event_sequences'], [1, 2, 3])
        self.assertTrue(chain['observed_birth_to_callback_chain'])
        self.assertTrue(chain['observed_enqueue_sequence_complete'])
        self.assertTrue(chain['append_return_matches_node'])
        self.assertTrue(chain['observation_complete'])
        self.assertTrue(chain['known_boundary_unchanged'])
        self.assertTrue(chain['observed_scopes_quiet'])
        self.assertTrue(result['birth_identity_transported'])
        self.assertEqual(result['birth_transport_target'], '439EC0-entry-only')
        self.assertFalse(result['renderer_identity_associated'])
        for item in (result, observed, chain, observed['installs'][0],
                     result['queue_birth_observation'],
                     result['queue_birth_observation']['requests'][0]):
            self.assert_no_authority(item)
        limitations = ' '.join(result['limitations'])
        self.assertIn('No association to renderer/rows', limitations)
        self.assertIn('20 bytes', limitations)
        self.assertNotIn('Birth receipts have not been transported', limitations)

    def test_empty_format_configuration_is_not_an_observed_chain_or_coverage(self):
        result = self.decode(self.empty)
        observed = result['queue_transport_observation']
        for field in ('receipts', 'windows', 'operations'):
            self.assertEqual(result[field], [])
        self.assertEqual(observed['events'], [])
        self.assertEqual(observed['chains'], [])
        self.assertEqual(observed['installs'], [])
        self.assertFalse(observed['observed_birth_to_callback_chain'])
        self.assertFalse(observed['observation_complete'])
        self.assertFalse(result['renderer_identity_associated'])
        self.assert_no_authority(result)
        self.assert_no_authority(observed)
        self.assertIn('coverage', ' '.join(observed['limitations']))

    def test_native_enqueue_without_consumer_is_a_partial_install_not_callback(self):
        machine = self.fixture.machine()
        machine.enqueue()
        result = self.decode(machine.snapshot())
        observed = result['queue_transport_observation']
        self.assertEqual([item['kind'] for item in observed['events']], [1])
        self.assertEqual(observed['chains'], [])
        self.assertFalse(observed['observation_complete'])
        self.assertFalse(observed['installs'][0]['observed_birth_to_callback_chain'])
        self.assertIn('birth-to-callback-chain-not-observed', observed['installs'][0]['reasons'])
        self.assert_no_authority(result)

    def test_full_null_enqueue_leaves_both_birth_and_transport_empty(self):
        machine = self.fixture.machine()
        machine.enqueue(rectangle=None)
        result = self.decode(machine.snapshot())
        self.assertEqual(result['queue_birth_observation']['events'], [])
        self.assertEqual(result['queue_transport_observation']['events'], [])
        self.assertEqual(machine.allocation_attempts, [])
        self.assertFalse(result['queue_transport_observation']['observation_complete'])
        self.assert_no_authority(result)

    def test_prior_row_callback_and_scope_diagnostics_are_preserved_exactly(self):
        prior = decoder.previous.decode(self.history[:self.transport_offset],
                                        **PREVIOUS_CAPACITIES)
        result = self.decode(self.history)
        for key in ('receipts', 'windows', 'operation_events', 'operations', 'native_scope',
                    'scope_quiet', 'known_contents_revision', 'queue_birth_observation'):
            self.assertEqual(result[key], prior[key], key)
        self.assertTrue(result['windows'][0]['observed_window_complete'])
        self.assertFalse(result['windows'][0]['complete'])
        self.assertIn('known-contents-boundary', result['windows'][0]['reasons'])
        self.assertTrue(result['operations'][0]['observed_callback_sequence_complete'])
        self.assertTrue(result['queue_transport_observation']['chains'][0]['known_boundary_unchanged'])
        self.assert_no_authority(result)

    def test_fresh_callback_transport_does_not_repair_original_frontier_rejection(self):
        changed = word(self.history, 16 + 60, 0)
        result = self.decode(changed)
        chain = result['queue_transport_observation']['chains'][0]
        self.assertTrue(chain['observation_complete'])
        self.assertTrue(chain['known_boundary_unchanged'])
        operation, window = result['operations'][0], result['windows'][0]
        self.assertFalse(operation['original_frontier_matches'])
        self.assertFalse(operation['observed_callback_sequence_complete'])
        self.assertIn('original-entry-frontier-mismatch', operation['reasons'])
        self.assertFalse(window['complete'])
        self.assertIn('known-contents-boundary', window['reasons'])
        self.assert_no_authority(result)

    def test_transport_events_are_not_attached_to_prior_rows_or_origins_by_address(self):
        result = self.decode(self.history)
        self.assertTrue(result['queue_transport_observation']['observation_complete'])
        self.assertFalse(result['renderer_identity_associated'])
        for entry in result['receipts'] + result['operations'] + result['windows']:
            for forbidden in ('birth', 'queue_birth', 'queue_birth_id', 'request_birth',
                              'queue_transport', 'transport_id', 'callback_birth'):
                self.assertNotIn(forbidden, entry)
        self.assert_no_authority(result)

    def test_later_final_revision_narrows_samples_without_erasing_observed_chain(self):
        result = self.decode(word(self.fresh, self.revision_offset, 1))
        chain = result['queue_transport_observation']['chains'][0]
        self.assertTrue(chain['observation_complete'])
        self.assertTrue(chain['observed_birth_to_callback_chain'])
        self.assertFalse(chain['known_boundary_unchanged'])
        self.assertIn('known-boundary-unchanged-not-observed', chain['reasons'])
        self.assert_no_authority(result)
        self.assert_no_authority(chain)

    def test_future_transport_revision_and_scope_samples_are_rejected(self):
        for data in (self.transport_word(self.fresh, 'revision', 1),
                     self.transport_word(self.fresh, 'scope', 1)):
            with self.assertRaises(ValueError):
                self.decode(data)

    def test_child_revision_and_scope_ticket_regressions_are_rejected(self):
        data = word(self.fresh, self.revision_offset, 1)
        data = self.transport_word(data, 'revision', 1, seq=2)
        with self.assertRaisesRegex(ValueError, 'regressed'):
            self.decode(data)
        # A real completed native reset supplies a valid final scope ticket;
        # the transport parser still must reject a child older than its parent.
        machine = self.fixture.machine()
        machine.reset()
        machine.consume()
        data = machine.snapshot()
        observed = self.decode(data)['queue_transport_observation']
        self.assertTrue(observed['chains'])
        helper_seq = observed['chains'][0]['helper']
        data = self.transport_word(data, 'scope', 0, seq=helper_seq)
        with self.assertRaisesRegex(ValueError, 'regressed'):
            self.decode(data)

    def test_transport_header_reserved_fault_count_and_all_unallocated_words_are_rejected(self):
        candidates = [word(self.fresh, self.transport_offset, value)
                      for value in (transport.FAULT, CAPACITIES['transport_capacity'] + 1, 0)]
        candidates.extend(word(self.fresh, self.transport_offset + offset, 1)
                          for offset in (4, 8, 12))
        candidates.extend(self.transport_word(self.fresh, field, 1, seq=64)
                          for field in transport.FIELDS)
        for data in candidates:
            with self.subTest(header=data[self.transport_offset:self.transport_offset + 16]), \
                    self.assertRaises(ValueError):
                self.decode(data)

    def test_transport_malformed_sites_ancestry_immutable_bindings_and_padding_rejected(self):
        changes = ((1, 'magic', 0), (1, 'kind', 0), (1, 'site', 0), (1, 'parent', 1),
                   (1, 'origin', 2), (1, 'seq', 2), (1, 'node', 0), (1, 'copy', 3),
                   (1, 'metadata', 0), (1, 'upstream', 0), (1, 'reserved0', 1),
                   (2, 'parent', 2), (2, 'engine', 0), (2, 'node', 0x9000F000),
                   (2, 'metadata', 0), (2, 'upstream', 4), (2, 'scope', 0x80000000),
                   (3, 'parent', 1), (3, 'frame', 4), (3, 'upstream', 0),
                   (4, 'parent', 2), (4, 'origin', 2), (4, 'reserved1', 1))
        for seq, field, value in changes:
            with self.subTest(seq=seq, field=field), self.assertRaises(ValueError):
                self.decode(self.transport_word(self.fresh, field, value, seq=seq))

    def test_bad_birth_parent_or_prefix_fault_cannot_be_masked_by_complete_transport(self):
        candidates = [word(self.history, offset, value) for offset, value in
                      ((0, 0xFFFFFFFF), (4, 1), (16, 0),
                       (self.row_offset, 0xFFFFFFFF), (self.row_offset + 4, 1),
                       (self.row_offset + 16, 0), (self.revision_offset, 0xFFFFFFFF),
                       (self.revision_offset + 4, 1),
                       (self.operation_offset + 4, 1), (self.operation_offset + 16, 0),
                       (self.scope_offset, 0xFFFFFFFF), (self.scope_offset + 4, 1),
                       (self.birth_offset, 0xFFFFFFFF), (self.birth_offset + 4, 1))]
        candidates.extend(self.birth_word(self.history, field, value, seq=seq)
                          for seq, field, value in ((1, 'magic', 0), (1, 'origin', 2),
                                                   (2, 'parent', 2), (2, 'copy', 0),
                                                   (2, 'metadata', 0), (3, 'parent', 1)))
        for data in candidates:
            with self.assertRaises(ValueError):
                self.decode(data)

    def test_missing_producer_return_keeps_exact_callback_chain_but_incomplete_observation(self):
        data = word(self.fresh, self.birth_offset, 2)
        offset = self.birth_offset + birth.HEADER + 2 * birth.RECORD
        changed = bytearray(data)
        changed[offset:offset + birth.RECORD] = bytes(birth.RECORD)
        result = self.decode(changed)
        chain = result['queue_transport_observation']['chains'][0]
        self.assertTrue(chain['observed_birth_to_callback_chain'])
        self.assertFalse(chain['observed_enqueue_sequence_complete'])
        self.assertFalse(chain['observation_complete'])
        self.assertIn('producer-return-not-observed', chain['reasons'])
        self.assert_no_authority(chain)

    def test_wrong_append_return_is_not_repaired_by_complete_callback_ancestry(self):
        result = self.decode(self.birth_word(self.fresh, 'result', 0, seq=3))
        chain = result['queue_transport_observation']['chains'][0]
        self.assertTrue(chain['observed_birth_to_callback_chain'])
        self.assertTrue(chain['observed_enqueue_sequence_complete'])
        self.assertFalse(chain['append_return_matches_node'])
        self.assertFalse(chain['observation_complete'])
        self.assertIn('append-return-node-mismatch', chain['reasons'])
        self.assert_no_authority(chain)

    def test_exact_owned_bytes_bytearray_memoryview_and_independent_output(self):
        expected = self.decode(self.history)
        for kind in (bytes, bytearray, memoryview):
            with self.subTest(kind=kind):
                original = bytearray(self.history)
                before = bytes(original)
                result = self.decode(kind(original))
                self.assertEqual(result, expected)
                result['queue_transport_observation']['events'][0]['node'] = 0
                result['queue_transport_observation']['chains'][0]['reasons'].append('output only')
                result['queue_transport_observation']['limitations'].append('output only')
                result['queue_birth_observation']['events'][0]['input'] = 0
                result['operations'][0]['reasons'].append('output only')
                result['windows'][0]['rows'][0]['path'] = 'output only'
                self.assertEqual(bytes(original), before)
                self.assertEqual(self.decode(self.history), expected)

    def test_wrong_sizes_nonbuffer_types_and_default_capacities_are_rejected(self):
        for data in (self.fresh[:-1], self.fresh + b'\0', self.fresh[:self.transport_offset],
                     b'', '', 1, [], None):
            with self.subTest(kind=type(data)), self.assertRaises(ValueError):
                decoder.decode(data, **CAPACITIES)
        with self.assertRaises(ValueError):
            decoder.decode(self.fresh)

    def test_each_invalid_or_mismatched_capacity_is_rejected(self):
        for field in CAPACITIES:
            for value in (15, 17, 0, -1, True, False, 1.5, None):
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    self.decode(**{field: value})
        with self.assertRaises(ValueError):
            self.decode(scope_capacity=65536)

    def test_old_format_refuses_transport_extension_and_new_refuses_old_prefix(self):
        with self.assertRaises(ValueError):
            decoder.previous.decode(self.fresh, **PREVIOUS_CAPACITIES)
        previous = decoder.previous.decode(self.fresh[:self.transport_offset],
                                            **PREVIOUS_CAPACITIES)
        self.assertFalse(previous['birth_identity_transported'])
        with self.assertRaises(ValueError):
            self.decode(self.fresh[:self.transport_offset])

    def test_cli_uses_supplied_local_buffer_explicit_capacities_and_errors(self):
        args = ['owned.bin']
        for key, value in CAPACITIES.items():
            args.extend(['--' + key.replace('_', '-'), str(value)])
        output = StringIO()
        with patch.object(decoder.Path, 'read_bytes', return_value=self.fresh) as reader:
            with redirect_stdout(output):
                decoder.main(args)
            reader.assert_called_once_with()
        result = json.loads(output.getvalue())
        self.assertEqual(result['format'], decoder.FORMAT)
        self.assertTrue(result['queue_transport_observation']['chains'][0]['observation_complete'])
        self.assert_no_authority(result)
        for failure in (b'bad', OSError('unavailable')):
            options = dict(side_effect=failure) if isinstance(failure, OSError) else dict(return_value=failure)
            with patch.object(decoder.Path, 'read_bytes', **options):
                with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as error:
                    decoder.main(args)
                self.assertEqual(error.exception.code, 2)


if __name__ == '__main__':
    unittest.main()
