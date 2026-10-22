#!/usr/bin/env python3
"""Combined birth-format checks reuse executed snapshots, not native authority.

Allocator/cache/geometry and optional widget helpers remain explicit fixtures
of the imported integration harness. No device access, actual coherent capture
or request-to-row identity transport is implied by these copied histories.
"""

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
import struct
import unittest
from unittest.mock import patch

import decode_reveal_queue_birth_stage as decoder
import decode_reveal_queue_birth as birth
import test_reveal_queue_birth_stage as integration


CAPACITIES = dict(capacity=16, row_capacity=16, operation_capacity=16,
                  scope_capacity=16, birth_capacity=32)
PREVIOUS_CAPACITIES = {key: value for key, value in CAPACITIES.items()
                       if key != 'birth_capacity'}


def word(data, offset, value):
    changed = bytearray(data)
    struct.pack_into('<I', changed, offset, value)
    return bytes(changed)


class DecodeRevealQueueBirthStageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture_class = integration.RevealQueueBirthStageTests
        fixture_class.setUpClass()
        cls.fixture = fixture_class('test_actual_native_enqueue_has_three_linked_receipts_without_allocation_growth')
        machine, _, _ = cls.fixture.sequence()
        # A fresh observed enqueue after a row history is deliberately not
        # attached to that history. Its own revision can simply stay equal.
        machine.enqueue()
        cls.fresh = machine.snapshot()
        cls.empty = cls.fixture.machine().snapshot()
        cls.birth_offset = machine.meta['birth_buffer'] - machine.meta['buffer']
        cls.scope_offset = machine.meta['scope_buffer'] - machine.meta['buffer']
        cls.row_offset = machine.meta['row_buffer'] - machine.meta['buffer']
        cls.revision_offset = (machine.meta['contents_revision_buffer']
                               - machine.meta['buffer'])
        cls.operation_offset = machine.meta['operation_buffer'] - machine.meta['buffer']

    def decode(self, data=None, **capacities):
        options = dict(CAPACITIES)
        options.update(capacities)
        return decoder.decode(self.fresh if data is None else data, **options)

    def assert_no_authority(self, result):
        for field in birth.AUTHORITY_FLAGS:
            self.assertIs(result[field], False, field)

    def birth_word(self, data, field, value, *, seq=1):
        offset = (self.birth_offset + birth.HEADER + (seq - 1) * birth.RECORD
                  + birth.FIELDS.index(field) * 4)
        return word(data, offset, value)

    def test_fresh_observed_enqueue_remains_untransported_and_unauthorized(self):
        result = self.decode()
        observed = result['queue_birth_observation']
        request = observed['requests'][0]
        self.assertEqual(result['format'], 'lineage-rows-queue-birth-v1')
        self.assertEqual(result['format'], decoder.FORMAT)
        self.assertEqual(observed['format'], birth.FORMAT)
        self.assertTrue(request['observed_enqueue_sequence_complete'])
        self.assertTrue(request['known_boundary_unchanged'])
        self.assertTrue(request['observed_scopes_quiet'])
        self.assertTrue(request['queue_return_observed'])
        self.assertIsInstance(request['append_return'], int)
        self.assertFalse(result['birth_identity_transported'])
        for output in (result, observed, request):
            self.assert_no_authority(output)
        self.assertIn('no request-to-row association', ' '.join(result['limitations']))

    def test_empty_combined_journal_is_not_complete_request_coverage(self):
        result = self.decode(self.empty)
        self.assertEqual(result['receipts'], [])
        self.assertEqual(result['windows'], [])
        self.assertEqual(result['operations'], [])
        self.assertEqual(result['queue_birth_observation']['events'], [])
        self.assertEqual(result['queue_birth_observation']['requests'], [])
        self.assertFalse(result['birth_identity_transported'])
        self.assert_no_authority(result)
        self.assertIn('coverage', ' '.join(result['queue_birth_observation']['limitations']))

    def test_full_null_redraw_keeps_birth_journal_empty_not_fresh(self):
        machine = self.fixture.machine()
        machine.enqueue(rectangle=None)
        result = self.decode(machine.snapshot())
        self.assertEqual(result['queue_birth_observation']['events'], [])
        self.assertEqual(result['queue_birth_observation']['requests'], [])
        self.assertEqual(machine.allocation_attempts, [])
        self.assertEqual(machine.queue(), [])
        self.assertFalse(result['birth_identity_transported'])
        self.assert_no_authority(result)

    def test_birth_inside_reset_is_retained_even_after_reset_scope_closes(self):
        machine = self.fixture.machine()
        machine.reset()
        result = self.decode(machine.snapshot())
        request = result['queue_birth_observation']['requests'][0]
        self.assertTrue(result['scope_quiet'])
        self.assertEqual(result['native_scope']['closed_count'], 1)
        self.assertEqual(request['birth_revision'], 1)
        self.assertEqual(request['birth_scope_state'], 0x10001)
        self.assertTrue(request['born_while_known_scope_active'])
        self.assertTrue(request['observed_enqueue_sequence_complete'])
        self.assertFalse(request['observed_scopes_quiet'])
        self.assertFalse(request['known_boundary_unchanged'])
        self.assertEqual(result['known_contents_revision'], 2)
        self.assert_no_authority(request)

    def test_later_current_counter_narrows_birth_without_mutating_prior_results(self):
        current = struct.unpack_from('<I', self.fresh, self.revision_offset)[0]
        result = self.decode(word(self.fresh, self.revision_offset, current + 1))
        request = result['queue_birth_observation']['requests'][0]
        self.assertTrue(request['observed_enqueue_sequence_complete'])
        self.assertFalse(request['known_boundary_unchanged'])
        self.assertIn('known-boundary-unchanged-not-observed', request['reasons'])
        self.assertFalse(result['windows'][0]['complete'])
        self.assertIn('known-contents-boundary', result['windows'][0]['reasons'])
        self.assert_no_authority(result)

    def test_prefix_diagnostics_and_all_prior_rejections_are_preserved_exactly(self):
        prefix = self.fresh[:self.birth_offset]
        prior = decoder.previous.decode(prefix, **PREVIOUS_CAPACITIES)
        result = self.decode()
        for key in ('receipts', 'windows', 'operations', 'native_scope', 'scope_quiet'):
            self.assertEqual(result[key], prior[key], key)
        self.assertTrue(result['operations'][0]['observed_callback_sequence_complete'])
        self.assertTrue(result['windows'][0]['observed_window_complete'])
        self.assertFalse(result['windows'][0]['complete'])
        self.assertIn('known-contents-boundary', result['windows'][0]['reasons'])
        self.assert_no_authority(result)

    def test_fresh_birth_does_not_repair_original_entry_frontier_rejection(self):
        data = word(self.fresh, 16 + 60, 0)
        result = self.decode(data)
        request = result['queue_birth_observation']['requests'][0]
        self.assertTrue(request['known_boundary_unchanged'])
        self.assertTrue(request['observed_enqueue_sequence_complete'])
        operation, window = result['operations'][0], result['windows'][0]
        self.assertFalse(operation['original_frontier_matches'])
        self.assertFalse(operation['observed_callback_sequence_complete'])
        self.assertFalse(window['complete'])
        self.assertIn('original-entry-frontier-mismatch', operation['reasons'])
        self.assertIn('known-contents-boundary', window['reasons'])
        self.assert_no_authority(result)

    def test_old_and_new_birth_histories_differ_but_rows_are_never_joined(self):
        old_machine, old, _ = self.fixture.observe(before_reset=True)
        new_machine, new, _ = self.fixture.observe(before_reset=False)
        self.assertEqual(old_machine.snapshot()[:self.birth_offset],
                         new_machine.snapshot()[:self.birth_offset])
        self.assertNotEqual(old_machine.snapshot()[self.birth_offset:],
                            new_machine.snapshot()[self.birth_offset:])
        old_request = next(item for item in old['queue_birth_observation']['requests']
                           if item['metadata'] == integration.gap.OLD_METADATA)
        new_request = next(item for item in new['queue_birth_observation']['requests']
                           if item['metadata'] == integration.gap.OLD_METADATA)
        self.assertEqual((old_request['birth_revision'], new_request['birth_revision']), (0, 2))
        for key in ('receipts', 'windows', 'operations', 'native_scope'):
            self.assertEqual(old[key], new[key], key)
        for result in (old, new):
            self.assertFalse(result['birth_identity_transported'])
            self.assert_no_authority(result)
            for entry in result['receipts'] + result['operations'] + result['windows']:
                for forbidden in ('birth', 'queue_birth', 'queue_birth_id', 'request_birth'):
                    self.assertNotIn(forbidden, entry)

    def test_faulted_or_reserved_birth_header_and_unallocated_tail_rejected(self):
        candidates = [word(self.fresh, self.birth_offset, value)
                      for value in (birth.FAULT, CAPACITIES['birth_capacity'] + 1)]
        candidates.extend(word(self.fresh, self.birth_offset + offset, 1)
                          for offset in (4, 8, 12))
        candidates.extend(self.birth_word(self.fresh, field, 1, seq=32)
                          for field in birth.FIELDS)
        for data in candidates:
            with self.subTest(header=data[self.birth_offset:self.birth_offset + 16]), \
                    self.assertRaises(ValueError):
                self.decode(data)

    def test_corrupt_birth_ancestry_sites_bindings_or_scopes_are_rejected(self):
        candidates = [self.birth_word(self.fresh, field, value, seq=seq)
                      for seq, field, value in ((1, 'magic', 0), (1, 'parent', 1),
                                                (1, 'origin', 2), (1, 'reserved0', 1),
                                                (2, 'site', 0x8B42EC), (2, 'seq', 1),
                                                (2, 'engine', 0x9000F000), (2, 'copy', 3),
                                                (3, 'parent', 1), (3, 'copy', 0),
                                                (3, 'scope', 0x80000000))]
        for data in candidates:
            with self.assertRaises(ValueError):
                self.decode(data)

    def test_reserved_or_faulted_prefix_cannot_be_masked_by_fresh_birth(self):
        candidates = [word(self.fresh, offset, value) for offset, value in
                      ((0, 0xFFFFFFFF), (4, 1), (16, 0),
                       (self.row_offset, 0xFFFFFFFF), (self.row_offset + 4, 1),
                       (self.row_offset + 16, 0), (self.revision_offset, 0xFFFFFFFF),
                       (self.revision_offset + 4, 1),
                       (self.operation_offset + 4, 1), (self.operation_offset + 16, 0),
                       (self.scope_offset, 0xFFFFFFFF), (self.scope_offset + 4, 1))]
        for data in candidates:
            with self.assertRaises(ValueError):
                self.decode(data)

    def test_current_counter_lower_than_published_birth_is_rejected(self):
        machine = self.fixture.machine()
        machine.put(machine.meta['contents_revision_buffer'], 1, 4)
        machine.enqueue()
        data = word(machine.snapshot(), self.revision_offset, 0)
        with self.assertRaisesRegex(ValueError, 'beyond the known counter'):
            self.decode(data)

    def test_birth_cannot_sample_scope_ticket_beyond_final_issued_counter(self):
        machine = self.fixture.machine()
        machine.enqueue()
        data = machine.snapshot()
        self.assertEqual(struct.unpack_from('<I', data, self.scope_offset)[0], 0)
        # All three samples are internally quiet and chain-monotonic. They
        # still cannot precede a final no-reuse issued counter of zero.
        for seq in (1, 2, 3):
            data = self.birth_word(data, 'scope', 1, seq=seq)
        with self.assertRaisesRegex(ValueError, 'scope'):
            self.decode(data)

    def test_exact_bytes_bytearray_memoryview_and_input_immutability(self):
        expected = self.decode()
        for kind in (bytes, bytearray, memoryview):
            with self.subTest(kind=kind):
                original = bytearray(self.fresh)
                before = bytes(original)
                result = self.decode(kind(original))
                self.assertEqual(result, expected)
                result['queue_birth_observation']['events'][0]['input'] = 0
                result['queue_birth_observation']['requests'][0]['reasons'].append('output only')
                result['queue_birth_observation']['limitations'].append('output only')
                result['operations'][0]['reasons'].append('output only')
                result['windows'][0]['rows'][0]['path'] = 'output only'
                self.assertEqual(bytes(original), before)
                self.assertEqual(self.decode(), expected)

    def test_wrong_sizes_and_nonbuffer_types_are_rejected(self):
        for data in (self.fresh[:-1], self.fresh + b'\0', self.fresh[:self.birth_offset],
                     b'', '', 1, [], None):
            with self.subTest(kind=type(data)), self.assertRaises(ValueError):
                decoder.decode(data, **CAPACITIES)

    def test_individually_mismatched_and_invalid_capacities_are_rejected(self):
        for field in CAPACITIES:
            for value in (15, 17, 0, -1, True, False, 1.5, None):
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    self.decode(**{field: value})
        with self.assertRaises(ValueError):
            self.decode(scope_capacity=65536)

    def test_prior_format_refuses_extension_and_new_format_refuses_prior_prefix(self):
        with self.assertRaises(ValueError):
            decoder.previous.decode(self.fresh, **PREVIOUS_CAPACITIES)
        prior = decoder.previous.decode(self.fresh[:self.birth_offset], **PREVIOUS_CAPACITIES)
        self.assertTrue(prior['operations'][0]['observed_callback_sequence_complete'])
        with self.assertRaises(ValueError):
            self.decode(self.fresh[:self.birth_offset])

    def test_cli_reads_only_supplied_local_buffer_with_explicit_capacities(self):
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
        self.assertTrue(result['queue_birth_observation']['requests'][0]['known_boundary_unchanged'])
        self.assert_no_authority(result)
        for failure in (b'bad', OSError('unavailable')):
            kwargs = dict(side_effect=failure) if isinstance(failure, OSError) else dict(return_value=failure)
            with patch.object(decoder.Path, 'read_bytes', **kwargs):
                with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as error:
                    decoder.main(args)
                self.assertEqual(error.exception.code, 2)


if __name__ == '__main__':
    unittest.main()
