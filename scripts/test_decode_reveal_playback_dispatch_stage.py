#!/usr/bin/env python3
"""Preserve actual renderer-prefix evidence beside an independent LPDI tail.

The existing fixture executes the documented native callback/outer/renderer
boundaries, with explicit geometry/resource/renderer-suffix/SQL fixtures. LPDI
bytes here are crafted OWNED parser inputs, not evidence that native playback
or either optional callback executed. No playback -> paint edge is invented.
"""

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
import struct
import unittest
from unittest.mock import patch

import decode_reveal_playback_dispatch_stage as decoder
import decode_reveal_playback_dispatch as dispatch
import decode_reveal_request_age as previous
import decode_reveal_queue_birth as birth
import folderfollow_reveal_lineage_mips as lineage
import test_reveal_renderer_transport_stage as integration
from test_decode_reveal_playback_dispatch import event, snapshot as dispatch_snapshot


DISPATCH_CAPACITY = 4
PREVIOUS_CAPACITIES = dict(integration.CAPACITIES)
CAPACITIES = dict(PREVIOUS_CAPACITIES, playback_dispatch_capacity=DISPATCH_CAPACITY)
NEW_FLAGS = ('playback_paint_cause_associated', 'callback_completion_proven',
             'playback_identity_proven', 'complete_playback_coverage')
NEW_FIELDS = {'playback_dispatch_observation', *NEW_FLAGS}


def word(data, offset, value):
    changed = bytearray(data)
    struct.pack_into('<I', changed, offset, value)
    return bytes(changed)


class DecodeRevealPlaybackDispatchStageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture_class = integration.RevealRendererTransportStageTests
        fixture_class.setUpClass()
        cls.fixture = fixture_class()
        machine, cls.root, _ = cls.fixture.history(rows=True)
        cls.with_rows = machine.snapshot()
        cls.without_rows = cls.fixture.history(rows=False)[0].snapshot()
        cls.empty = cls.fixture.machine().snapshot()
        cls.offsets = {name: machine.meta[name] - machine.meta['buffer'] for name in
                       ('row_buffer', 'contents_revision_buffer', 'operation_buffer',
                        'scope_buffer', 'birth_buffer', 'transport_buffer',
                        'renderer_transport_buffer')}

    def joined(self, prefix=None, tail=None):
        return ((self.with_rows if prefix is None else prefix)
                + (dispatch_snapshot() if tail is None else tail))

    def decode(self, prefix=None, tail=None, **capacities):
        options = dict(CAPACITIES)
        options.update(capacities)
        return decoder.decode(self.joined(prefix, tail), **options)

    def prior(self, prefix=None):
        return previous.decode(self.with_rows if prefix is None else prefix,
                               **PREVIOUS_CAPACITIES)

    def assert_no_authority(self, result):
        for field in dispatch.AUTHORITY_FLAGS:
            self.assertIs(result[field], False, field)

    def assert_independent(self, result):
        self.assert_no_authority(result)
        for field in NEW_FLAGS:
            self.assertIs(result[field], False, field)
        observation = result['playback_dispatch_observation']
        self.assertEqual(observation['decision'], 'deny')
        self.assertIs(observation['complete_coverage'], False)
        self.assert_no_authority(observation)
        for item in observation['events']:
            self.assertEqual(item['decision'], 'deny')
            self.assertIs(item['complete_coverage'], False)
            self.assert_no_authority(item)
        assessment = result['request_age_assessment']
        self.assertEqual(assessment['decision'], 'deny')
        self.assert_no_authority(assessment)
        for request in assessment['requests']:
            self.assertEqual(request['decision'], 'deny')
            self.assert_no_authority(request)

    def assert_prior_preserved(self, prefix, result):
        old = self.prior(prefix)
        self.assertEqual(set(result) - set(old), NEW_FIELDS)
        self.assertEqual(set(old) - set(result), set())
        for key, value in old.items():
            if key not in ('format', 'limitations'):
                self.assertEqual(result[key], value, key)
        self.assertEqual(result['limitations'][:-1], old['limitations'])
        self.assertEqual(len(result['limitations']), len(old['limitations']) + 1)
        self.assertIn('No transported playback/notification parent', result['limitations'][-1])
        self.assertEqual(result['format'], decoder.FORMAT)
        self.assertEqual(result['format'], 'lineage-rows-renderer-playback-dispatch-v1')
        self.assertEqual(result['request_age_assessment'], old['request_age_assessment'])

    def test_exact_actual_renderer_prefix_outputs_and_age_annotation_are_preserved(self):
        for prefix in (self.with_rows, self.without_rows, self.empty):
            with self.subTest(rows=prefix is self.with_rows, empty=prefix is self.empty):
                result = self.decode(prefix, dispatch_snapshot(event()))
                self.assert_prior_preserved(prefix, result)
                self.assert_independent(result)

    def test_standalone_tail_is_decoded_exactly_without_supplying_renderer_summary(self):
        tail = dispatch_snapshot(event(), event(2, dispatch.GENERAL, context=0xBAD00001))
        result = self.decode(tail=tail)
        self.assertEqual(result['playback_dispatch_observation'],
                         dispatch.decode(tail, capacity=DISPATCH_CAPACITY))
        self.assert_independent(result)

    def test_old_window_and_literal_known_boundary_refusals_are_not_repaired(self):
        result = self.decode(tail=dispatch_snapshot(event()))
        window = result['windows'][0]
        association = result['renderer_transport_observation']['associations'][0]
        self.assertTrue(window['observed_window_complete'])
        self.assertFalse(window['complete'])
        self.assertIn('known-contents-boundary', window['reasons'])
        self.assertTrue(association['renderer_root_associated'])
        self.assertFalse(association['known_boundary_unchanged'])
        self.assertIn('known-boundary-unchanged-not-observed', association['reasons'])
        self.assert_prior_preserved(self.with_rows, result)
        self.assert_independent(result)

    def test_old_original_entry_and_callback_sequence_refusals_are_not_repaired(self):
        prefix = word(self.with_rows, lineage.HEADER + 60, 0)
        result = self.decode(prefix, dispatch_snapshot(event()))
        operation = result['operations'][0]
        self.assertFalse(operation['original_frontier_matches'])
        self.assertFalse(operation['observed_callback_sequence_complete'])
        self.assertIn('original-entry-frontier-mismatch', operation['reasons'])
        self.assertTrue(result['renderer_row_associations'][0]['observed_row_identity_associated'])
        self.assert_prior_preserved(prefix, result)
        self.assert_independent(result)

    def test_missing_later_producer_return_is_not_repaired_by_a_dispatch_intent(self):
        offset = self.offsets['birth_buffer']
        prefix = bytearray(word(self.with_rows, offset, 2))
        start = offset + birth.HEADER + 2 * birth.RECORD
        prefix[start:start + birth.RECORD] = bytes(birth.RECORD)
        result = self.decode(prefix, dispatch_snapshot(event()))
        association = result['renderer_transport_observation']['associations'][0]
        self.assertFalse(association['producer_return_observed'])
        self.assertFalse(association['observation_complete'])
        request = result['request_age_assessment']['requests'][0]
        self.assertFalse(request['producer_return_observed'])
        self.assert_prior_preserved(prefix, result)
        self.assert_independent(result)

    def test_empty_partial_and_full_lpdi_never_establish_playback_or_paint_cause(self):
        tails = (dispatch_snapshot(), dispatch_snapshot(event()),
                 dispatch_snapshot(*(event(number) for number in range(1, DISPATCH_CAPACITY + 1))))
        for tail, count in zip(tails, (0, 1, DISPATCH_CAPACITY)):
            with self.subTest(count=count):
                result = self.decode(tail=tail)
                self.assertTrue(result['renderer_identity_associated'])
                self.assertEqual(result['playback_dispatch_observation']['counter'], count)
                self.assert_independent(result)
                self.assert_prior_preserved(self.with_rows, result)

    def test_empty_renderer_prefix_and_present_lpdi_do_not_invent_a_birth_or_root(self):
        result = self.decode(self.empty, dispatch_snapshot(event()))
        self.assertEqual(result['queue_birth_observation']['events'], [])
        self.assertEqual(result['renderer_transport_observation']['associations'], [])
        self.assertEqual(result['renderer_row_associations'], [])
        self.assertEqual(result['request_age_assessment']['requests'], [])
        self.assertFalse(result['renderer_identity_associated'])
        self.assert_independent(result)

    def test_coincident_local_sequence_one_does_not_join_lpdi_to_birth_or_lineage_one(self):
        prior = self.prior(self.without_rows)
        born = prior['queue_birth_observation']['events'][0]
        self.assertEqual(born['seq'], 1)
        self.assertEqual(prior['request_age_assessment']['requests'][0]['lineage'], 1)
        tail = dispatch_snapshot(event(frame=born['frame'], context=born['engine'],
                                       target=0x4906E0))
        result = self.decode(self.without_rows, tail)
        observed = result['playback_dispatch_observation']['events'][0]
        self.assertEqual((observed['seq'], observed['origin'], observed['parent']), (1, 1, 0))
        self.assertEqual(observed['frame'], born['frame'])
        self.assertEqual(observed['context'], born['engine'])
        self.assertEqual(result['request_age_assessment'], prior['request_age_assessment'])
        for item in result['request_age_assessment']['requests']:
            for field in ('playback_dispatch', 'playback_parent', 'dispatch_parent', 'target'):
                self.assertNotIn(field, item)
        self.assert_independent(result)

    def test_equal_target_frame_context_or_descriptor_does_not_merge_independent_lpdi_records(self):
        old = self.prior()
        tail = dispatch_snapshot(event(), event(2), event(3, dispatch.GENERAL))
        result = self.decode(tail=tail)
        intents = result['playback_dispatch_observation']['events']
        self.assertEqual([item['origin'] for item in intents], [1, 2, 3])
        self.assertEqual([item['parent'] for item in intents], [0, 0, 0])
        self.assertEqual([item['target'] for item in intents], [0x12345679] * 3)
        self.assertEqual(result['renderer_row_associations'], old['renderer_row_associations'])
        self.assertEqual(result['request_age_assessment'], old['request_age_assessment'])
        self.assert_independent(result)

    def test_owned_bytes_bytearray_and_memoryview_have_the_same_combined_report(self):
        raw = self.joined(tail=dispatch_snapshot(event()))
        expected = decoder.decode(raw, **CAPACITIES)
        for data in (bytearray(raw), memoryview(raw)):
            self.assertEqual(decoder.decode(data, **CAPACITIES), expected)

    def test_predecoded_dictionary_or_host_state_is_not_combined_decoder_input(self):
        for value in ({}, self.prior(), [], None, 'LPDI', 1):
            with self.subTest(value_type=type(value).__name__), self.assertRaises(ValueError):
                decoder.decode(value, **CAPACITIES)

    def test_old_prefix_alone_wrong_size_and_extra_tail_bytes_are_refused(self):
        raw = self.joined(tail=dispatch_snapshot(event()))
        for data in (self.with_rows, raw[:-1], raw + b'\0', raw[1:], b''):
            with self.subTest(length=len(data)), self.assertRaises(ValueError):
                decoder.decode(data, **CAPACITIES)

    def test_wrong_lpdi_capacity_or_legacy_capacities_cannot_reinterpret_layout(self):
        for name in CAPACITIES:
            options = dict(CAPACITIES)
            options[name] += 1
            with self.subTest(name=name), self.assertRaises(ValueError):
                decoder.decode(self.joined(), **options)

    def test_bad_capacities_are_refused_before_any_layout_is_admitted(self):
        for name in CAPACITIES:
            for value in (0, -1, True, 1.0, '4', None, 0x100000000):
                options = dict(CAPACITIES)
                options[name] = value
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    decoder.decode(self.joined(), **options)

    def test_malformed_each_legacy_journal_or_known_counter_is_still_refused(self):
        offsets = (0, *self.offsets.values())
        for offset in offsets:
            prefix = word(self.with_rows, offset, 0xFFFFFFFF)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                self.decode(prefix, dispatch_snapshot(event()))

    def test_lpdi_header_fault_reserved_unpublished_and_unallocated_tail_are_refused(self):
        valid = dispatch_snapshot(event())
        tails = [word(valid, 0, dispatch.FAULT), word(valid, 0, DISPATCH_CAPACITY + 1),
                 word(valid, 4, 1), word(valid, 8, 1), word(valid, 12, 1),
                 word(valid, dispatch.HEADER, 0),
                 word(valid, len(valid) - 4, 1)]
        for tail in tails:
            with self.subTest(header=tail[:16]), self.assertRaises(ValueError):
                self.decode(tail=tail)

    def test_malformed_lpdi_cannot_be_repaired_by_valid_renderer_history(self):
        changes = ({'kind': 0}, {'site': 0}, {'return_pc': 0}, {'parent': 1},
                   {'origin': 2}, {'seq': 2}, {'frame': 0}, {'frame': 1},
                   {'target': 0}, {'descriptor': 0}, {'player': 0},
                   *({'reserved' + str(number): 1} for number in range(4)))
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.decode(tail=dispatch_snapshot(event(**change)))

    def test_odd_unmapped_target_and_arbitrary_context_stay_raw_not_owner_or_cause(self):
        result = self.decode(tail=dispatch_snapshot(event(target=0xFFFFFFFF, context=1)))
        intent = result['playback_dispatch_observation']['events'][0]
        self.assertEqual((intent['target'], intent['context']), (0xFFFFFFFF, 1))
        self.assert_independent(result)

    def test_cli_decodes_only_owned_snapshot_and_preserves_all_evidence(self):
        raw = self.joined(tail=dispatch_snapshot(event()))
        argv = ['fixture.raw']
        for name in decoder.CAPACITY_NAMES:
            argv.extend(('--' + name, str(CAPACITIES[name.replace('-', '_')])))
        output = StringIO()
        with patch.object(decoder.Path, 'read_bytes', return_value=raw) as read:
            with redirect_stdout(output):
                decoder.main(argv)
        read.assert_called_once_with()
        result = json.loads(output.getvalue())
        self.assertEqual(result, decoder.decode(raw, **CAPACITIES))
        self.assert_independent(result)

    def test_cli_rejects_bad_prefix_or_tail_instead_of_annotating_partial_input(self):
        for raw in (self.with_rows, self.joined(tail=word(dispatch_snapshot(), 0, dispatch.FAULT))):
            argv = ['fixture.raw']
            for name in decoder.CAPACITY_NAMES:
                argv.extend(('--' + name, str(CAPACITIES[name.replace('-', '_')])))
            with patch.object(decoder.Path, 'read_bytes', return_value=raw):
                with redirect_stderr(StringIO()):
                    with self.assertRaises(SystemExit) as raised:
                        decoder.main(argv)
            self.assertEqual(raised.exception.code, 2)


if __name__ == '__main__':
    unittest.main()
