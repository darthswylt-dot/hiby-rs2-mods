#!/usr/bin/env python3
"""Compose real renderer fixture bytes with explicitly crafted OWNED LALI data.

The prior renderer fixture executes its documented native boundaries; the
notification tail here is parser input, not proof that those notification or
paint-list native instructions executed. Native source/queue execution belongs
to the separate new stage fixture. No device or unowned memory is accessed.
"""

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
import struct
import unittest
from unittest.mock import patch

import decode_reveal_action_link as action
import decode_reveal_action_link_stage as decoder
import decode_reveal_playback_dispatch as dispatch
import decode_reveal_playback_dispatch_stage as previous
import decode_reveal_queue_birth as birth
import folderfollow_reveal_lineage_mips as lineage
import test_decode_reveal_action_link as action_fixture
import test_decode_reveal_playback_dispatch_stage as prior_fixture
import test_reveal_renderer_transport_stage as integration
from test_decode_reveal_playback_dispatch import event, snapshot as dispatch_snapshot


PREVIOUS_CAPACITIES = dict(prior_fixture.CAPACITIES)
CAPACITIES = dict(PREVIOUS_CAPACITIES, action_link_capacity=16)
NEW_FIELDS = {'action_link_observation', 'notification_birth_associations',
              'notification_renderer_associations', 'historical_notification_birth_associated',
              'historical_notification_renderer_associated'}


def word(data, offset, value):
    raw = bytearray(data)
    struct.pack_into('<I', raw, offset, value)
    return bytes(raw)


class DecodeRevealActionLinkStageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture_class = integration.RevealRendererTransportStageTests
        fixture_class.setUpClass()
        cls.fixture = fixture_class()
        machine = cls.fixture.machine()
        machine.enqueue(metadata=0)
        cls.birth_only = machine.snapshot()
        machine.consume()
        cls.root = machine.renderer_runs[0]['lineage']
        cls.without_rows = machine.snapshot()
        cls.fixture.rows_from_root(machine, cls.root)
        cls.with_rows = machine.snapshot()
        cls.empty = cls.fixture.machine().snapshot()
        cls.offsets = {name: machine.meta[name] - machine.meta['buffer'] for name in
                       ('row_buffer', 'contents_revision_buffer', 'operation_buffer',
                        'scope_buffer', 'birth_buffer', 'transport_buffer',
                        'renderer_transport_buffer')}

    def prior_raw(self, prefix=None, dispatch_tail=None):
        return ((self.with_rows if prefix is None else prefix)
                + (dispatch_snapshot() if dispatch_tail is None else dispatch_tail))

    def prior(self, prefix=None, dispatch_tail=None):
        return previous.decode(self.prior_raw(prefix, dispatch_tail), **PREVIOUS_CAPACITIES)

    def action_records(self, prefix=None):
        born = self.prior(prefix)['queue_birth_observation']['events'][0]
        records = action_fixture.sequence(birth_id=born['seq'])
        for item in records[2:]:
            item['node'] = born['engine']
        records[3]['engine'] = born['engine']
        for item in records[4:]:
            item.update(record=born['input'] - 0xC, engine=born['engine'],
                        input=born['input'], metadata=born['metadata'])
        records[4]['frame'] = born['frame'] + 0x68
        records[5]['frame'] = born['frame']
        return records

    def joined(self, prefix=None, tail=None, dispatch_tail=None):
        tail = action_fixture.snapshot(self.action_records(prefix)) if tail is None else tail
        return self.prior_raw(prefix, dispatch_tail) + tail

    def decode(self, prefix=None, tail=None, dispatch_tail=None, **options):
        return decoder.decode(self.joined(prefix, tail, dispatch_tail),
                              **dict(CAPACITIES, **options))

    def assert_no_authority(self, result):
        for field in action.AUTHORITY_FLAGS:
            self.assertIs(result[field], False, field)

    def assert_prior_preserved(self, prefix, result, dispatch_tail=None):
        old = self.prior(prefix, dispatch_tail)
        self.assertEqual(set(result) - set(old), NEW_FIELDS)
        self.assertEqual(set(old) - set(result), set())
        for key, value in old.items():
            if key not in ('format', 'limitations'):
                self.assertEqual(result[key], value, key)
        self.assertEqual(result['limitations'][:-1], old['limitations'])
        self.assertEqual(result['format'], 'lineage-rows-action-birth-link-v1')
        self.assert_no_authority(result)
        self.assertFalse(result['playback_identity_proven'])
        self.assertFalse(result['playback_paint_cause_associated'])
        self.assertFalse(result['complete_playback_coverage'])

    def test_full_notification_to_existing_root_and_rows_is_historical_only(self):
        result = self.decode()
        self.assertTrue(result['historical_notification_birth_associated'])
        self.assertTrue(result['historical_notification_renderer_associated'])
        linked, = result['notification_renderer_associations']
        self.assertEqual((linked['source'], linked['delivery'], linked['explorer'],
                          linked['paint'], linked['paint_delivery'], linked['birth_link'],
                          linked['birth'], linked['callback'], linked['outer'],
                          linked['renderer'], linked['lineage']),
                         (1, 2, 3, 4, 5, 6, 1, 4, 1, 2, self.root))
        self.assertEqual(linked['event_sequences'], [1, 2, 3, 4, 5, 6])
        self.assertEqual(linked['renderer_event_sequences'], [1, 2])
        self.assertEqual(linked['transport_event_sequences'], [1, 2, 3, 4])
        self.assertEqual(linked['row_event_sequences'], [1])
        self.assertEqual(linked['window_indices'], [0])
        self.assertTrue(linked['observed_row_identity_associated'])
        self.assertFalse(linked['native_record_lease_proven'])
        self.assertFalse(linked['native_payload_coherence_proven'])
        self.assertEqual(linked['decision'], 'deny')
        for item in (linked, result['notification_birth_associations'][0],
                     result['action_link_observation']):
            self.assert_no_authority(item)
        self.assert_prior_preserved(self.with_rows, result)

    def test_absent_rows_do_not_remove_actual_renderer_or_birth_association(self):
        result = self.decode(self.without_rows)
        linked, = result['notification_renderer_associations']
        self.assertEqual(linked['row_event_sequences'], [])
        self.assertFalse(linked['observed_row_identity_associated'])
        self.assertTrue(result['historical_notification_renderer_associated'])
        self.assert_prior_preserved(self.without_rows, result)

    def test_actual_birth_link_does_not_require_a_later_renderer(self):
        result = self.decode(self.birth_only)
        self.assertTrue(result['historical_notification_birth_associated'])
        self.assertFalse(result['historical_notification_renderer_associated'])
        self.assertEqual(len(result['notification_birth_associations']), 1)
        self.assertEqual(result['notification_renderer_associations'], [])
        self.assert_prior_preserved(self.birth_only, result)

    def test_empty_notification_tail_cannot_claim_old_renderer_cause(self):
        result = self.decode(tail=action_fixture.snapshot([]))
        self.assertTrue(result['renderer_identity_associated'])
        self.assertFalse(result['historical_notification_birth_associated'])
        self.assertFalse(result['historical_notification_renderer_associated'])
        self.assertEqual(result['notification_birth_associations'], [])
        self.assertEqual(result['notification_renderer_associations'], [])
        self.assert_prior_preserved(self.with_rows, result)

    def test_valid_partial_notification_prefixes_are_not_repaired_by_renderer_history(self):
        for count in range(1, 6):
            with self.subTest(count=count):
                result = self.decode(tail=action_fixture.snapshot(self.action_records()[:count]))
                self.assertFalse(result['historical_notification_birth_associated'])
                self.assertFalse(result['historical_notification_renderer_associated'])
                self.assertEqual(result['action_link_observation']['unassociated_sources'], [1])
                self.assert_prior_preserved(self.with_rows, result)

    def test_empty_old_prefix_and_empty_tail_stay_unknown(self):
        result = self.decode(self.empty, action_fixture.snapshot([]))
        self.assertEqual(result['notification_birth_associations'], [])
        self.assertEqual(result['notification_renderer_associations'], [])
        self.assertFalse(result['historical_notification_birth_associated'])
        self.assert_prior_preserved(self.empty, result)

    def test_old_window_and_renderer_rejection_reasons_are_not_repaired(self):
        result = self.decode()
        self.assertFalse(result['windows'][0]['complete'])
        self.assertIn('known-contents-boundary', result['windows'][0]['reasons'])
        linked = result['notification_renderer_associations'][0]
        self.assertIn('known-boundary-unchanged-not-observed', linked['renderer_reasons'])
        self.assertTrue(linked['renderer_root_associated'])
        self.assert_prior_preserved(self.with_rows, result)

    def test_old_original_entry_refusal_is_not_overridden(self):
        prefix = word(self.with_rows, lineage.HEADER + 60, 0)
        result = self.decode(prefix)
        self.assertFalse(result['operations'][0]['original_frontier_matches'])
        self.assertTrue(result['historical_notification_renderer_associated'])
        self.assert_prior_preserved(prefix, result)

    def test_missing_producer_return_preserves_birth_link_and_incomplete_renderer_evidence(self):
        offset = self.offsets['birth_buffer']
        prefix = bytearray(word(self.with_rows, offset, 2))
        start = offset + birth.HEADER + 2 * birth.RECORD
        prefix[start:start + birth.RECORD] = bytes(birth.RECORD)
        result = self.decode(prefix)
        self.assertTrue(result['historical_notification_birth_associated'])
        linked = result['notification_renderer_associations'][0]
        self.assertFalse(linked['renderer_observation_complete'])
        self.assertFalse(result['renderer_transport_observation']['associations'][0]['producer_return_observed'])
        self.assert_prior_preserved(prefix, result)

    def test_lpdi_intent_is_kept_independent_even_with_coincident_native_values(self):
        born = self.prior()['queue_birth_observation']['events'][0]
        intent = dispatch_snapshot(event(frame=born['frame'], context=born['engine'],
                                         target=0x490980))
        result = self.decode(dispatch_tail=intent)
        linked = result['notification_renderer_associations'][0]
        for key in ('playback_dispatch', 'dispatch_parent', 'target', 'callback_completion_proven'):
            self.assertNotIn(key, linked)
        self.assertFalse(result['playback_paint_cause_associated'])
        self.assert_prior_preserved(self.with_rows, result, intent)

    def test_capacity_full_notification_journal_is_not_complete_coverage(self):
        result = self.decode(tail=action_fixture.snapshot(self.action_records(), capacity=6),
                             action_link_capacity=6)
        self.assertTrue(result['action_link_observation']['capacity_full'])
        self.assertFalse(result['action_link_observation']['complete_coverage_proven'])
        self.assert_no_authority(result)

    def test_same_birth_address_without_explicit_actual_id_is_not_joined(self):
        tail = action_fixture.record_word(action_fixture.snapshot(self.action_records()),
                                         6, 'birth', 0)
        with self.assertRaisesRegex(ValueError, 'missing explicit'):
            self.decode(tail=tail)

    def test_another_real_birth_with_identical_addresses_does_not_select_old_renderer(self):
        offset = self.offsets['birth_buffer']
        prefix = bytearray(word(self.with_rows, offset, 4))
        source = offset + birth.HEADER
        destination = source + 3 * birth.RECORD
        prefix[destination:destination + birth.RECORD] = prefix[source:source + birth.RECORD]
        struct.pack_into('<I', prefix, destination + 12, 4)  # fresh self-origin
        struct.pack_into('<I', prefix, destination + 16, 4)  # fresh actual BIRTH ID
        records = self.action_records(prefix)
        records[-1]['birth'] = 4
        result = self.decode(prefix, action_fixture.snapshot(records))
        self.assertTrue(result['historical_notification_birth_associated'])
        self.assertEqual(result['notification_birth_associations'][0]['birth'], 4)
        self.assertFalse(result['historical_notification_renderer_associated'])
        self.assertEqual(result['notification_renderer_associations'], [])
        self.assertEqual(result['renderer_row_associations'][0]['birth'], 1)
        self.assert_prior_preserved(prefix, result)

    def test_wrong_foreign_birth_scalar_and_duplicate_birth_are_refused(self):
        records = self.action_records()
        records[-1]['frame'] += 4
        with self.assertRaises(ValueError):
            self.decode(tail=action_fixture.snapshot(records))
        records = self.action_records()
        records.append(dict(records[-1], seq=7))
        with self.assertRaisesRegex(ValueError, 'duplicate observed'):
            self.decode(tail=action_fixture.snapshot(records))

    def test_standalone_observation_exactly_matches_raw_foreign_slice_decode(self):
        tail = action_fixture.snapshot(self.action_records())
        offset = self.offsets['birth_buffer']
        size = birth.memory_bytes(CAPACITIES['birth_capacity'])
        result = self.decode(tail=tail)
        expected = action.decode(tail, birth_data=self.with_rows[offset:offset + size],
                                 capacity=CAPACITIES['action_link_capacity'],
                                 birth_capacity=CAPACITIES['birth_capacity'])
        self.assertEqual(result['action_link_observation'], expected)

    def test_all_previous_journal_faults_still_refuse_the_whole_snapshot(self):
        offsets = (0, *self.offsets.values(), len(self.with_rows))
        for offset in offsets:
            raw = word(self.joined(), offset, 0xFFFFFFFF)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                decoder.decode(raw, **CAPACITIES)

    def test_action_header_fault_reserved_unpublished_and_unused_tail_are_refused(self):
        valid = action_fixture.snapshot(self.action_records())
        tails = [word(valid, 0, 0xFFFFFFFF), word(valid, 0, 17),
                 word(valid, 4, 1), word(valid, 8, 1), word(valid, 12, 1),
                 word(valid, action.HEADER, 0), word(valid, len(valid) - 4, 1)]
        for tail in tails:
            with self.subTest(header=tail[:20]), self.assertRaises(ValueError):
                self.decode(tail=tail)

    def test_owned_buffer_kinds_and_previous_report_are_not_mutated(self):
        raw = self.joined()
        expected = decoder.decode(raw, **CAPACITIES)
        for value in (bytearray(raw), memoryview(raw)):
            before = bytes(value)
            self.assertEqual(decoder.decode(value, **CAPACITIES), expected)
            self.assertEqual(bytes(value), before)
        self.assert_prior_preserved(self.with_rows, expected)

    def test_nonraw_public_inputs_are_refused(self):
        for value in ({}, self.prior(), [], None, 'LALI', 1):
            with self.subTest(value_type=type(value).__name__), self.assertRaises(ValueError):
                decoder.decode(value, **CAPACITIES)

    def test_missing_extra_shifted_or_old_only_bytes_are_refused(self):
        raw = self.joined()
        for value in (self.prior_raw(), raw[:-1], raw + b'\0', raw[1:], b''):
            with self.subTest(length=len(value)), self.assertRaises(ValueError):
                decoder.decode(value, **CAPACITIES)

    def test_each_capacity_is_strict_and_part_of_exact_layout(self):
        raw = self.joined()
        for name in CAPACITIES:
            for value in (0, -1, True, 1.0, '16', None, 0x100000000,
                          CAPACITIES[name] + 1):
                options = dict(CAPACITIES, **{name: value})
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    decoder.decode(raw, **options)

    def test_cli_emits_the_same_report_from_one_owned_snapshot(self):
        raw = self.joined()
        argv = ['fixture.raw']
        for name in decoder.CAPACITY_NAMES:
            argv.extend(('--' + name, str(CAPACITIES[name.replace('-', '_')])))
        with patch.object(decoder.Path, 'read_bytes', return_value=raw) as read, \
                redirect_stdout(StringIO()) as output:
            decoder.main(argv)
        read.assert_called_once_with()
        self.assertEqual(json.loads(output.getvalue()), decoder.decode(raw, **CAPACITIES))

    def test_cli_refuses_invalid_input_instead_of_returning_partial_links(self):
        argv = ['fixture.raw']
        for name in decoder.CAPACITY_NAMES:
            argv.extend(('--' + name, str(CAPACITIES[name.replace('-', '_')])))
        with patch.object(decoder.Path, 'read_bytes', return_value=self.prior_raw()), \
                redirect_stderr(StringIO()), self.assertRaises(SystemExit) as exited:
            decoder.main(argv)
        self.assertEqual(exited.exception.code, 2)


if __name__ == '__main__':
    unittest.main()
