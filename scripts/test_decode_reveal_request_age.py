#!/usr/bin/env python3
"""Reject-only request-age assessment over owned native-instruction histories.

The underlying fixture has explicit geometry/SQL/renderer-suffix stubs. A
known-counter crossing is conservative negative evidence, not proof of a
semantic stale UI request. Absence of that evidence never means fresh.
"""

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
import struct
import unittest
from unittest.mock import patch

import decode_reveal_request_age as decoder
import decode_reveal_renderer_transport_stage as prior
import decode_reveal_renderer_transport as renderer
import decode_reveal_queue_birth as birth
import test_reveal_renderer_transport_stage as integration


CAPACITIES = dict(integration.CAPACITIES)
FORMAT = 'request-age-rejection-v1'


def word(data, offset, value):
    changed = bytearray(data)
    struct.pack_into('<I', changed, offset, value)
    return bytes(changed)


class DecodeRevealRequestAgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture_class = integration.RevealRendererTransportStageTests
        fixture_class.setUpClass()
        cls.fixture = fixture_class()
        machine, cls.root, _ = cls.fixture.history(rows=True)
        cls.with_rows = machine.snapshot()
        cls.baseline = cls.fixture.history(rows=False)[0].snapshot()
        cls.empty = cls.fixture.machine().snapshot()
        cls.offsets = {name: machine.meta[name] - machine.meta['buffer'] for name in
                       ('renderer_transport_buffer', 'transport_buffer', 'birth_buffer',
                        'scope_buffer', 'row_buffer', 'contents_revision_buffer', 'operation_buffer')}

    def decode(self, data=None, **capacities):
        options = dict(CAPACITIES)
        options.update(capacities)
        return decoder.decode(self.baseline if data is None else data, **options)

    def request(self, result, *, birth_id=None):
        requests = result['request_age_assessment']['requests']
        if birth_id is None:
            self.assertEqual(len(requests), 1)
            return requests[0]
        selected = [item for item in requests if item['birth'] == birth_id]
        self.assertEqual(len(selected), 1)
        return selected[0]

    def assert_no_authority(self, result):
        for flag in renderer.AUTHORITY_FLAGS:
            self.assertIs(result[flag], False, flag)

    def assert_deny(self, request):
        self.assertEqual(request['decision'], 'deny')
        self.assertIn(request['status'], ('rejected', 'unproven'))
        self.assert_no_authority(request)
        for field in ('rejection_reasons', 'unproven_reasons'):
            self.assertIsInstance(request[field], list)
        self.assertIn('samples', request)
        self.assertIn('evidence', request)

    def bump_at(self, pc):
        machine = self.fixture.machine()
        fired = []

        def before_instruction(at):
            if at == pc and not fired:
                fired.append(at)
                saved, hi, lo = machine.r.copy(), machine.hi, machine.lo
                machine.run_at(machine.labels['contents_bump'], machine.r[31])
                machine.r, machine.hi, machine.lo = saved, hi, lo

        machine.before_instruction = before_instruction
        machine.enqueue()
        machine.consume()
        self.assertEqual(fired, [pc])
        return machine

    def test_initial_revision_zero_and_scope_zero_are_valid_but_never_freshness(self):
        result = self.decode()
        assessment = result['request_age_assessment']
        request = self.request(result)
        self.assertEqual(result['format'], prior.FORMAT)
        self.assertEqual(assessment['format'], FORMAT)
        self.assertEqual((request['birth'], request['callback'], request['outer'],
                          request['renderer'], request['lineage']), (1, 4, 1, 2, self.root))
        self.assertEqual(request['status'], 'unproven')
        self.assertFalse(request['known_boundary_conflict'])
        self.assertFalse(request['source_order_conflict'])
        self.assertFalse(request['observed_known_scope_active'])
        self.assertEqual(request['pre_outer_revision_advance'], 0)
        self.assertEqual(request['extra_pre_entry_increments'], 0)
        self.assertEqual(request['early_renderer_revision_advance'], 0)
        self.assertEqual(request['scope_ticket_advance'], 0)
        self.assertTrue(request['producer_return_observed'])
        self.assertTrue(request['observation_complete'])
        self.assertTrue(request['unproven_reasons'])
        self.assert_deny(request)
        self.assert_no_authority(result)
        self.assert_no_authority(assessment)

    def test_old_request_queued_before_reset_has_observed_known_boundary_conflict(self):
        machine = self.fixture.machine()
        machine.enqueue()
        machine.reset()
        machine.consume()
        result = self.decode(machine.snapshot())
        request = self.request(result, birth_id=1)
        association = result['renderer_transport_observation']['associations'][0]
        self.assertEqual((association['birth_revision'], association['outer_revision'],
                          association['original_entry_revision'], association['renderer_revision']),
                         (0, 2, 3, 3))
        self.assertEqual(request['status'], 'rejected')
        self.assertTrue(request['known_boundary_conflict'])
        self.assertEqual(request['pre_outer_revision_advance'], 2)
        self.assertEqual(request['extra_pre_entry_increments'], 0)
        self.assertEqual(request['early_renderer_revision_advance'], 0)
        self.assertEqual(request['scope_ticket_advance'], 1)
        self.assertTrue(request['rejection_reasons'])
        self.assert_deny(request)

    def test_new_postreset_request_behind_an_older_paint_is_conservatively_rejected(self):
        machine = self.fixture.machine()
        machine.reset()
        machine.enqueue()
        machine.consume()
        result = self.decode(machine.snapshot())
        request = self.request(result, birth_id=4)
        association = result['renderer_transport_observation']['associations'][1]
        self.assertEqual((association['birth_revision'], association['outer_revision'],
                          association['original_entry_revision'], association['renderer_revision']),
                         (2, 3, 4, 4))
        self.assertEqual(request['status'], 'rejected')
        self.assertTrue(request['known_boundary_conflict'])
        self.assertEqual(request['pre_outer_revision_advance'], 1)
        self.assertFalse(request['observed_known_scope_active'])
        # The crossing is another renderer's known bump; the request was
        # actually born AFTER reset. Do not call this proof of a stale UI cause.
        self.assert_deny(request)

    def test_new_request_after_reset_paint_drained_has_no_extra_age_evidence(self):
        machine = self.fixture.machine()
        machine.reset()
        machine.consume()
        machine.enqueue()
        machine.consume()
        result = self.decode(machine.snapshot())
        request = self.request(result, birth_id=4)
        association = result['renderer_transport_observation']['associations'][1]
        self.assertEqual((association['birth_revision'], association['outer_revision'],
                          association['original_entry_revision'], association['renderer_revision']),
                         (3, 3, 4, 4))
        self.assertEqual(request['status'], 'unproven')
        self.assertFalse(request['known_boundary_conflict'])
        self.assertEqual(request['pre_outer_revision_advance'], 0)
        self.assertEqual(request['extra_pre_entry_increments'], 0)
        self.assertEqual(request['early_renderer_revision_advance'], 0)
        self.assert_deny(request)

    def test_extra_known_increment_before_actual_renderer_entry_is_not_the_own_bump(self):
        machine = self.bump_at(0x4906F8)
        result = self.decode(machine.snapshot())
        request = self.request(result)
        association = result['renderer_transport_observation']['associations'][0]
        self.assertEqual((association['outer_revision'], association['original_entry_revision'],
                          association['renderer_revision']), (0, 2, 2))
        self.assertEqual(request['extra_pre_entry_increments'], 1)
        self.assertEqual(request['early_renderer_revision_advance'], 0)
        self.assertTrue(request['known_boundary_conflict'])
        self.assertEqual(request['status'], 'rejected')
        self.assert_deny(request)

    def test_extra_known_increment_after_entry_is_observed_at_early_renderer(self):
        machine = self.bump_at(0x490758)
        result = self.decode(machine.snapshot())
        request = self.request(result)
        association = result['renderer_transport_observation']['associations'][0]
        self.assertEqual((association['outer_revision'], association['original_entry_revision'],
                          association['renderer_revision']), (0, 1, 2))
        self.assertEqual(request['extra_pre_entry_increments'], 0)
        self.assertEqual(request['early_renderer_revision_advance'], 1)
        self.assertTrue(request['known_boundary_conflict'])
        self.assertEqual(request['status'], 'rejected')
        self.assert_deny(request)

    def test_worker_postfill_and_bind_final_counter_changes_are_not_preentry_age(self):
        result = self.decode(self.with_rows)
        request = self.request(result)
        self.assertEqual(result['known_contents_revision'], 4)
        self.assertEqual(result['renderer_transport_observation']['associations'][0]['renderer_revision'], 1)
        self.assertEqual(request['status'], 'unproven')
        self.assertFalse(request['known_boundary_conflict'])
        self.assertEqual(request['pre_outer_revision_advance'], 0)
        self.assertEqual(request['extra_pre_entry_increments'], 0)
        self.assertEqual(request['early_renderer_revision_advance'], 0)
        self.assertTrue(result['renderer_row_associations'][0]['observed_row_identity_associated'])
        self.assertFalse(result['windows'][0]['complete'])
        self.assertIn('known-contents-boundary', result['windows'][0]['reasons'])
        self.assert_deny(request)

    def test_arbitrarily_later_final_counter_does_not_create_pre_renderer_conflict(self):
        changed = word(self.with_rows, self.offsets['contents_revision_buffer'], 100)
        result = self.decode(changed)
        request = self.request(result)
        self.assertEqual(result['known_contents_revision'], 100)
        self.assertFalse(request['known_boundary_conflict'])
        self.assertEqual(request['status'], 'unproven')
        self.assert_deny(request)

    def test_renderer_can_be_observed_before_return_and_late_return_is_not_preentry_evidence(self):
        machine = self.fixture.machine()
        partial = []

        def before_return(pc):
            if pc == 0x8B42F0 and not partial:
                saved, hi, lo = machine.r.copy(), machine.hi, machine.lo
                machine.consume(stack=integration.gap.ENGINE_STACK - 0x1000)
                partial.append(machine.snapshot())
                machine.r, machine.hi, machine.lo = saved, hi, lo

        machine.before_instruction = before_return
        machine.enqueue()
        before, after = self.decode(partial[0]), self.decode(machine.snapshot())
        for result in (before, after):
            request = self.request(result)
            self.assertFalse(request['known_boundary_conflict'])
            self.assertEqual(request['extra_pre_entry_increments'], 0)
            self.assertEqual(request['early_renderer_revision_advance'], 0)
            self.assert_deny(request)
        self.assertFalse(self.request(before)['producer_return_observed'])
        self.assertFalse(self.request(before)['observation_complete'])
        self.assertTrue(self.request(after)['producer_return_observed'])
        self.assertTrue(self.request(after)['observation_complete'])

    def test_missing_return_does_not_erase_explicit_identity_or_invent_known_age_conflict(self):
        changed = bytearray(word(self.with_rows, self.offsets['birth_buffer'], 2))
        offset = self.offsets['birth_buffer'] + birth.HEADER + 2 * birth.RECORD
        changed[offset:offset + birth.RECORD] = bytes(birth.RECORD)
        result = self.decode(changed)
        request = self.request(result)
        self.assertTrue(result['renderer_row_associations'][0]['observed_row_identity_associated'])
        self.assertFalse(request['producer_return_observed'])
        self.assertFalse(request['observation_complete'])
        self.assertFalse(request['known_boundary_conflict'])
        self.assert_deny(request)

    def test_active_scope_sample_does_not_become_admitted_when_reset_later_closes(self):
        machine = self.fixture.machine()
        machine.reset()
        machine.consume()
        result = self.decode(machine.snapshot())
        request = self.request(result)
        self.assertTrue(result['scope_quiet'])
        self.assertEqual(result['native_scope']['closed_count'], 1)
        self.assertTrue(request['observed_known_scope_active'])
        self.assertEqual(request['status'], 'rejected')
        self.assert_deny(request)

    def test_zero_original_entry_is_denied_without_synthetic_self_bump_or_known_age_conflict(self):
        changed = word(self.baseline, 16 + 60, 0)
        result = self.decode(changed)
        request = self.request(result)
        self.assertEqual(request['status'], 'rejected')
        self.assertFalse(request['known_boundary_conflict'])
        self.assertFalse(request['source_order_conflict'])
        self.assertIsNone(request['extra_pre_entry_increments'])
        self.assertIsNone(request['early_renderer_revision_advance'])
        self.assertTrue(request['unproven_reasons'])
        self.assert_deny(request)

    def test_same_native_addresses_do_not_relabel_an_old_request_with_new_birth(self):
        machine = self.fixture.machine()
        machine.enqueue()
        first_allocations = list(machine.queue_allocations)
        machine.reset()
        machine.consume()
        reused = iter(address for address, _ in first_allocations)
        machine.allocation = lambda size: next(reused)
        machine.enqueue()
        machine.consume()
        result = self.decode(machine.snapshot())
        old, new = self.request(result, birth_id=1), self.request(result, birth_id=7)
        self.assertEqual(old['status'], 'rejected')
        self.assertTrue(old['known_boundary_conflict'])
        self.assertEqual(new['status'], 'unproven')
        self.assertFalse(new['known_boundary_conflict'])
        self.assertNotEqual(old['lineage'], new['lineage'])
        self.assertNotEqual(old['callback'], new['callback'])
        self.assertEqual(machine.queue_allocations[:2], machine.queue_allocations[-2:])
        associations = result['renderer_transport_observation']['associations']
        for field in ('engine', 'widget', 'view', 'panel', 'job', 'cache', 'frame'):
            self.assertEqual(associations[0][field], associations[-1][field], field)
        self.assert_deny(old)
        self.assert_deny(new)

    def test_empty_or_unbound_routes_cannot_generate_request_age_admission(self):
        machine = self.fixture.machine()
        machine.enqueue(rectangle=None)
        for raw in (self.empty, machine.snapshot()):
            result = self.decode(raw)
            self.assertEqual(result['request_age_assessment']['requests'], [])
            self.assert_no_authority(result)
            self.assert_no_authority(result['request_age_assessment'])

    def test_prior_format_all_outputs_flags_and_rejection_reasons_are_unchanged(self):
        for raw in (self.baseline, self.with_rows):
            before = prior.decode(raw, **CAPACITIES)
            result = self.decode(raw)
            assessment = result.pop('request_age_assessment')
            self.assertEqual(result, before)
            self.assertEqual(result['format'], prior.FORMAT)
            self.assertFalse(result['renderer_transport_observation']['associations'][0]['known_boundary_unchanged'])
            self.assert_no_authority(assessment)

    def test_original_frontier_rejection_is_not_repaired_by_no_extra_age_conflict(self):
        changed = word(self.with_rows, 16 + 60, 0)
        result = self.decode(changed)
        request = self.request(result)
        self.assertFalse(request['known_boundary_conflict'])
        self.assertFalse(result['operations'][0]['original_frontier_matches'])
        self.assertFalse(result['operations'][0]['observed_callback_sequence_complete'])
        self.assertIn('original-entry-frontier-mismatch', result['operations'][0]['reasons'])
        self.assertFalse(result['windows'][0]['complete'])
        self.assertIn('known-contents-boundary', result['windows'][0]['reasons'])
        self.assert_deny(request)

    def test_strict_parent_refusals_propagate_before_age_assessment(self):
        candidates = [word(self.with_rows, offset, value) for offset, value in
                      ((0, 0xFFFFFFFF), (4, 1), (16, 0),
                       (self.offsets['row_buffer'], 0xFFFFFFFF),
                       (self.offsets['operation_buffer'] + 4, 1),
                       (self.offsets['scope_buffer'], 0xFFFFFFFF),
                       (self.offsets['birth_buffer'], 0xFFFFFFFF),
                       (self.offsets['transport_buffer'], 0xFFFFFFFF),
                       (self.offsets['renderer_transport_buffer'], 0xFFFFFFFF),
                       (self.offsets['renderer_transport_buffer'] + 4, 1),
                       (self.offsets['renderer_transport_buffer'] + renderer.HEADER, 0),
                       (self.offsets['contents_revision_buffer'], 0xFFFFFFFF))]
        tail = (self.offsets['renderer_transport_buffer'] + renderer.HEADER
                + (CAPACITIES['renderer_capacity'] - 1) * renderer.RECORD)
        candidates.append(word(self.with_rows, tail, 1))
        for raw in candidates:
            with self.assertRaises(ValueError):
                self.decode(raw)

    def test_exact_buffer_variants_input_immutability_and_fresh_output(self):
        expected = self.decode(self.with_rows)
        for kind in (bytes, bytearray, memoryview):
            original = bytearray(self.with_rows)
            before = bytes(original)
            result = self.decode(kind(original))
            self.assertEqual(result, expected)
            request = self.request(result)
            request['rejection_reasons'].append('output only')
            request['unproven_reasons'].append('output only')
            result['request_age_assessment']['requests'].append({})
            result['windows'][0]['rows'][0]['path'] = 'output only'
            self.assertEqual(bytes(original), before)
            self.assertEqual(self.decode(self.with_rows), expected)

    def test_wrong_sizes_nonbuffer_values_and_default_capacities_refused(self):
        for raw in (self.with_rows[:-1], self.with_rows + b'\0', b'', '', 1, [], None):
            with self.subTest(kind=type(raw)), self.assertRaises(ValueError):
                decoder.decode(raw, **CAPACITIES)
        with self.assertRaises(ValueError):
            decoder.decode(self.with_rows)

    def test_each_invalid_and_individually_mismatched_capacity_is_refused(self):
        for field in CAPACITIES:
            for value in (15, 17, 0, -1, True, False, 1.5, None):
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    self.decode(**{field: value})

    def test_cli_reads_only_given_owned_snapshot_and_reports_parent_refusals(self):
        args = ['owned.bin']
        for key, value in CAPACITIES.items():
            args.extend(['--' + key.replace('_', '-'), str(value)])
        output = StringIO()
        with patch.object(decoder.Path, 'read_bytes', return_value=self.with_rows) as reader:
            with redirect_stdout(output):
                decoder.main(args)
            reader.assert_called_once_with()
        result = json.loads(output.getvalue())
        self.assertEqual(result['format'], prior.FORMAT)
        self.assertEqual(result['request_age_assessment']['format'], FORMAT)
        self.assert_deny(self.request(result))
        for failure in (b'bad', OSError('unavailable')):
            options = dict(side_effect=failure) if isinstance(failure, OSError) else dict(return_value=failure)
            with patch.object(decoder.Path, 'read_bytes', **options):
                with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as error:
                    decoder.main(args)
                self.assertEqual(error.exception.code, 2)


if __name__ == '__main__':
    unittest.main()
