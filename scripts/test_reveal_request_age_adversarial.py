#!/usr/bin/env python3
"""Hostile age histories: a lack of negative evidence never admits the UI.

Private-helper fixtures combine canonical outputs of the existing strict
standalone decoders. They test assessment arithmetic, not full native code
execution or coherent acquisition. Public-boundary cases use exact zeroed BSS
buffers and malformed owned bytes; no device or firmware change is involved.
"""

import copy
import struct
import unittest

import decode_reveal_native_scope as scopes
import decode_reveal_queue_birth as birth
import decode_reveal_queue_transport as transport
import decode_reveal_renderer_transport as renderer
import decode_reveal_renderer_transport_stage as previous
import decode_reveal_request_age as age
import folderfollow_reveal_lineage_mips as lineage
import reveal_lineage_rows_mips as rows
import reveal_operation_journal_mips as operation
import test_decode_reveal_renderer_transport as fixtures


MAX = 0x7FFFFFFF
CAPACITIES = dict(capacity=1, row_capacity=1, operation_capacity=1,
                  scope_capacity=1, birth_capacity=1, transport_capacity=1,
                  renderer_capacity=1)


def quiet_scopes(issued=4, *, active_count=0):
    capacity = max(1, issued)
    raw = bytearray(scopes.memory_bytes(capacity))
    struct.pack_into('<I', raw, 0, issued | active_count << 16)
    for index in range(issued):
        struct.pack_into('<8I', raw, scopes.HEADER + index * scopes.RECORD,
                         scopes.MAGIC, scopes.RESET, index + 1,
                         0x70000000 + index * 0x100, 0, 0, scopes.CLOSED, 0)
    return scopes.decode_snapshot(raw, capacity=capacity)


def parent(*, outer_revision=10, entry_revision=11, render_revision=None,
           birth_revision=None, return_revision=None, current_revision=None,
           birth_scope=4, enqueue_scope=4, return_scope=4, render_scope=4,
           outer_scope=4, omit_return=False):
    render_revision = (max(outer_revision, entry_revision) if render_revision is None
                       else render_revision)
    birth_revision = outer_revision if birth_revision is None else birth_revision
    return_revision = outer_revision if return_revision is None else return_revision
    latest = max(outer_revision, entry_revision, render_revision, return_revision)
    current_revision = latest if current_revision is None else current_revision
    records = fixtures.prior.birth_records(revision=outer_revision, scope=4)
    records[0].update(revision=birth_revision, scope=birth_scope)
    records[1]['scope'] = enqueue_scope
    records[2].update(revision=return_revision, scope=return_scope)
    if omit_return:
        records = records[:2]
    born = fixtures.prior.birth_result(records, current_revision=current_revision)
    transported = fixtures.transport_result(born, records=fixtures.prior.sequence(
        revision=outer_revision, scope=4), current_revision=current_revision)
    native_lineage = fixtures.lineage_result(
        [fixtures.root(entry_revision=entry_revision)], current_revision=current_revision)
    observed = [fixtures.event(renderer.OUTER, revision=outer_revision, scope=outer_scope),
                fixtures.event(renderer.RENDER, revision=render_revision, scope=render_scope)]
    rendered = renderer.decode(fixtures.snapshot(observed), transported, native_lineage,
                               birth_result=born, capacity=fixtures.CAPACITY,
                               current_revision=current_revision)
    result = copy.deepcopy(native_lineage)
    result.update(format=previous.FORMAT, queue_birth_observation=born,
                  queue_transport_observation=transported,
                  renderer_transport_observation=rendered,
                  events=[], operation_events=[], operations=[], windows=[],
                  renderer_row_associations=[], native_scope=quiet_scopes(max(
                      4, birth_scope & 0xFFFF, enqueue_scope & 0xFFFF,
                      return_scope & 0xFFFF, render_scope & 0xFFFF,
                      outer_scope & 0xFFFF)), limitations=['existing refusal'])
    return result


def empty_snapshot(*, current_revision=0):
    sizes = (lineage.memory_bytes(1), rows.memory_bytes(1), 16,
             operation.memory_bytes(1), scopes.memory_bytes(1),
             birth.memory_bytes(1), transport.memory_bytes(1), renderer.memory_bytes(1))
    raw = bytearray(sum(sizes))
    struct.pack_into('<I', raw, sizes[0] + sizes[1], current_revision)
    return bytes(raw), sizes


def word(raw, offset, value):
    result = bytearray(raw)
    struct.pack_into('<I', result, offset, value)
    return bytes(result)


class RevealRequestAgeAdversarialTests(unittest.TestCase):
    def assess(self, value=None):
        return age._assess_result(parent() if value is None else value)

    def request(self, value=None):
        return self.assess(value)['requests'][0]

    def assert_deny(self, result):
        self.assertEqual(result['decision'], 'deny')
        for flag in renderer.AUTHORITY_FLAGS:
            self.assertIs(result[flag], False, flag)

    def test_baseline_is_unproven_even_with_exact_own_entry_step(self):
        request = self.request()
        self.assertFalse(request['known_boundary_conflict'])
        self.assertFalse(request['source_order_conflict'])
        self.assertFalse(request['observed_known_scope_active'])
        self.assertEqual(request['pre_outer_revision_advance'], 0)
        self.assertEqual(request['extra_pre_entry_increments'], 0)
        self.assertEqual(request['early_renderer_revision_advance'], 0)
        self.assertEqual(request['scope_ticket_advance'], 0)
        self.assertEqual(request['status'], 'unproven')
        self.assertEqual(request['rejection_reasons'], [])
        self.assertTrue(request['unproven_reasons'])
        self.assert_deny(request)

    def test_same_revision_but_more_scope_tickets_is_negative_not_malformed(self):
        request = self.request(parent(birth_scope=3, enqueue_scope=4))
        self.assertEqual(request['pre_outer_revision_advance'], 0)
        self.assertGreater(request['scope_ticket_advance'], 0)
        self.assertTrue(request['known_boundary_conflict'])
        self.assertFalse(request['source_order_conflict'])
        self.assertFalse(request['observed_known_scope_active'])
        self.assertEqual(request['status'], 'rejected')
        self.assertTrue(request['rejection_reasons'])
        self.assert_deny(request)

    def test_scope_begin_can_be_visible_after_revision_sample_and_later_close(self):
        for birth_scope, enqueue_scope in ((3, 4), (3 | 1 << 16, 4)):
            with self.subTest(birth_scope=birth_scope):
                request = self.request(parent(birth_scope=birth_scope,
                                               enqueue_scope=enqueue_scope))
                self.assertGreater(request['scope_ticket_advance'], 0)
                self.assertEqual(request['pre_outer_revision_advance'], 0)
                self.assertTrue(request['known_boundary_conflict'])
                self.assertEqual(request['observed_known_scope_active'], birth_scope >> 16 != 0)
                self.assert_deny(request)

    def test_known_boundary_before_outer_is_reported_without_calling_request_fresh(self):
        request = self.request(parent(birth_revision=9))
        self.assertEqual(request['pre_outer_revision_advance'], 1)
        self.assertTrue(request['known_boundary_conflict'])
        self.assertEqual(request['extra_pre_entry_increments'], 0)
        self.assertEqual(request['status'], 'rejected')
        self.assert_deny(request)
        for forbidden in ('fresh', 'fresh_request', 'admitted', 'safe', 'eligible'):
            self.assertNotIn(forbidden, request)

    def test_missing_return_does_not_erase_negative_main_path_evidence(self):
        value = parent(birth_revision=9, omit_return=True)
        self.assertFalse(value['renderer_transport_observation']['associations'][0]['observation_complete'])
        request = self.request(value)
        self.assertTrue(request['known_boundary_conflict'])
        self.assertEqual(request['pre_outer_revision_advance'], 1)
        self.assertEqual(request['status'], 'rejected')
        self.assert_deny(request)

    def test_extra_known_entry_increment_is_not_the_one_expected_own_bump(self):
        for entry, expected in ((12, 1), (20, 9), (MAX, MAX - 11)):
            with self.subTest(entry=entry):
                request = self.request(parent(entry_revision=entry))
                self.assertEqual(request['extra_pre_entry_increments'], expected)
                self.assertTrue(request['known_boundary_conflict'])
                self.assertFalse(request['source_order_conflict'])
                self.assertEqual(request['status'], 'rejected')
                self.assert_deny(request)

    def test_early_renderer_increment_is_after_entry_not_before_outer(self):
        request = self.request(parent(render_revision=12))
        self.assertEqual(request['pre_outer_revision_advance'], 0)
        self.assertEqual(request['extra_pre_entry_increments'], 0)
        self.assertEqual(request['early_renderer_revision_advance'], 1)
        self.assertTrue(request['known_boundary_conflict'])
        self.assertEqual(request['status'], 'rejected')
        self.assert_deny(request)

    def test_unbound_zero_entry_never_computes_an_age_or_becomes_zero_delta_pass(self):
        for outer, rendered in ((0, 0), (10, 11), (MAX, MAX)):
            with self.subTest(outer=outer, rendered=rendered):
                request = self.request(parent(outer_revision=outer,
                                               entry_revision=0, render_revision=rendered))
                self.assertIsNone(request['extra_pre_entry_increments'])
                self.assertIsNone(request['early_renderer_revision_advance'])
                self.assertTrue(request['unproven_reasons'])
                self.assert_deny(request)

    def test_equal_positive_entry_ticket_cannot_skip_the_known_own_entry_increment(self):
        request = self.request(parent(entry_revision=10))
        self.assertTrue(request['source_order_conflict'])
        self.assertEqual(request['status'], 'rejected')
        self.assertTrue(request['rejection_reasons'])
        self.assert_deny(request)

    def test_unsupported_entry_is_not_used_to_invent_an_early_renderer_increment(self):
        request = self.request(parent(entry_revision=10, render_revision=11))
        self.assertTrue(request['source_order_conflict'])
        self.assertFalse(request['known_boundary_conflict'])
        self.assertIsNone(request['extra_pre_entry_increments'])
        self.assertIsNone(request['early_renderer_revision_advance'])
        self.assertIn('original-renderer-entry-order-unsupported', request['unproven_reasons'])
        self.assertEqual(request['status'], 'rejected')
        self.assert_deny(request)

    def test_entry_older_than_outer_is_rejected_by_the_existing_strict_boundary(self):
        with self.assertRaisesRegex(ValueError, 'entry revision order'):
            parent(entry_revision=9)

    def test_last_valid_counter_step_does_not_wrap_or_become_known_conflict(self):
        request = self.request(parent(outer_revision=MAX - 1, entry_revision=MAX))
        self.assertEqual(request['pre_outer_revision_advance'], 0)
        self.assertEqual(request['extra_pre_entry_increments'], 0)
        self.assertEqual(request['early_renderer_revision_advance'], 0)
        self.assertFalse(request['known_boundary_conflict'])
        self.assertFalse(request['source_order_conflict'])
        self.assertEqual(request['status'], 'unproven')
        self.assert_deny(request)

    def test_saturated_outer_cannot_wrap_and_issue_a_new_positive_ticket(self):
        request = self.request(parent(outer_revision=MAX, entry_revision=MAX))
        self.assertTrue(request['source_order_conflict'])
        self.assertEqual(request['status'], 'rejected')
        self.assert_deny(request)

    def test_zero_to_one_entry_is_only_unproven_not_a_positive_authority(self):
        request = self.request(parent(outer_revision=0, entry_revision=1))
        self.assertEqual(request['extra_pre_entry_increments'], 0)
        self.assertFalse(request['known_boundary_conflict'])
        self.assertEqual(request['status'], 'unproven')
        self.assert_deny(request)

    def test_final_global_counter_is_not_inserted_into_pre_outer_causal_path(self):
        request = self.request(parent(current_revision=100))
        self.assertEqual(request['pre_outer_revision_advance'], 0)
        self.assertEqual(request['extra_pre_entry_increments'], 0)
        self.assertEqual(request['early_renderer_revision_advance'], 0)
        self.assertFalse(request['known_boundary_conflict'])
        self.assertEqual(request['status'], 'unproven')
        self.assert_deny(request)

    def test_late_producer_return_is_not_inserted_before_renderer(self):
        request = self.request(parent(return_revision=100, current_revision=100))
        self.assertEqual(request['pre_outer_revision_advance'], 0)
        self.assertEqual(request['extra_pre_entry_increments'], 0)
        self.assertFalse(request['known_boundary_conflict'])
        self.assertEqual(request['status'], 'unproven')
        self.assert_deny(request)

    def test_return_scope_ticket_increase_is_not_misdated_before_outer(self):
        request = self.request(parent(return_revision=100, return_scope=5,
                                       current_revision=100))
        self.assertEqual(request['scope_ticket_advance'], 0)
        self.assertFalse(request['known_boundary_conflict'])
        self.assertEqual(request['status'], 'unproven')
        self.assert_deny(request)

    def test_independent_birth_reservation_order_is_not_a_global_revision_clock(self):
        records = fixtures.prior.birth_records(revision=20, scope=7)
        records.extend([
            fixtures.prior.birth_fixtures.event(seq=4, origin=4, revision=10, scope=4),
            fixtures.prior.birth_fixtures.event(birth.ENQUEUE_BEGIN, seq=5, parent=4,
                                                origin=4, revision=10, scope=4),
            fixtures.prior.birth_fixtures.event(birth.RETURN, seq=6, parent=5,
                                                origin=4, revision=10, scope=4,
                                                result=fixtures.prior.NODE)])
        born = fixtures.prior.birth_result(records, current_revision=21)
        native_transport = fixtures.prior.sequence(revision=20, scope=7) + [
            fixtures.prior.event(transport.INSTALL, seq=5, parent=5, origin=4),
            fixtures.prior.event(transport.BORROW, seq=6, parent=5, origin=4),
            fixtures.prior.event(transport.HELPER, seq=7, parent=6, origin=4),
            fixtures.prior.event(transport.CALLBACK, seq=8, parent=7, origin=4)]
        transported = fixtures.transport_result(born, records=native_transport, current_revision=21)
        native_lineage = fixtures.lineage_result([
            fixtures.root(entry_revision=21), fixtures.root(token=2, entry_revision=11)],
            current_revision=21)
        native_render = [fixtures.event(renderer.OUTER, revision=20, scope=7),
                         fixtures.event(renderer.RENDER, revision=21, scope=7),
                         fixtures.event(renderer.OUTER, seq=3, parent=8, transport_id=8,
                                        origin=4, revision=10, scope=4),
                         fixtures.event(renderer.RENDER, seq=4, parent=3, transport_id=8,
                                        origin=4, lineage_id=2, revision=11, scope=4)]
        rendered = renderer.decode(fixtures.snapshot(native_render), transported, native_lineage,
                                   birth_result=born, capacity=fixtures.CAPACITY,
                                   current_revision=21, scope_issued=7)
        value = copy.deepcopy(native_lineage)
        value.update(format=previous.FORMAT, queue_birth_observation=born,
                     queue_transport_observation=transported,
                     renderer_transport_observation=rendered, native_scope=quiet_scopes(7))
        requests = self.assess(value)['requests']
        self.assertEqual([item['birth'] for item in requests], [1, 4])
        self.assertEqual([item['birth_revision'] for item in requests], [20, 10])
        self.assertTrue(all(item['status'] == 'unproven' for item in requests))
        self.assertTrue(all(not item['known_boundary_conflict'] for item in requests))
        self.assertTrue(all(not item['source_order_conflict'] for item in requests))
        for item in requests:
            self.assert_deny(item)

    def test_active_scope_in_main_path_is_negative_even_after_it_is_closed(self):
        for options in (dict(birth_scope=4 | 1 << 16),
                        dict(enqueue_scope=4 | 1 << 16),
                        dict(outer_scope=4 | 1 << 16),
                        dict(render_scope=4 | 1 << 16)):
            with self.subTest(options=options):
                value = parent(**options)
                self.assertTrue(value['native_scope']['scope_quiet'])
                request = self.request(value)
                self.assertTrue(request['observed_known_scope_active'])
                self.assertEqual(request['status'], 'rejected')
                self.assertTrue(request['rejection_reasons'])
                self.assert_deny(request)

    def test_final_scope_transient_stays_a_refusal_without_inventing_pre_outer_overlap(self):
        value = parent(current_revision=100)
        # Legitimate copied transient: CLOSED publishes before active count
        # is decremented. The old scope parser keeps this non-quiet.
        value['native_scope'] = quiet_scopes(active_count=1)
        self.assertFalse(value['native_scope']['scope_quiet'])
        request = self.request(value)
        self.assertFalse(request['known_boundary_conflict'])
        self.assertFalse(request['observed_known_scope_active'])
        self.assertEqual(request['status'], 'rejected')
        self.assertIn('snapshot-known-scope-not-quiet', request['rejection_reasons'])
        self.assert_deny(request)

    def test_parent_summary_timing_or_equality_fields_cannot_forge_an_assessment(self):
        value = parent()
        baseline = self.assess(value)
        association = value['renderer_transport_observation']['associations'][0]
        association.update(birth_revision=0, outer_revision=0,
                           renderer_revision=MAX, original_entry_revision=0,
                           known_boundary_unchanged=True)
        for collection in ('chains', 'installs'):
            for item in value['queue_transport_observation'][collection]:
                item['known_boundary_unchanged'] = True
        self.assertEqual(self.assess(value), baseline)

    def test_assessment_does_not_change_previous_fields_or_repair_old_refusals(self):
        value = parent()
        value['windows'] = [dict(complete=False, observed_window_complete=True,
                                 reasons=['known-contents-boundary'])]
        value['operations'] = [dict(observed_callback_sequence_complete=False,
                                    reasons=['original-entry-frontier-mismatch'])]
        original = copy.deepcopy(value)
        assessed = self.assess(value)
        self.assertEqual(value, original)
        self.assert_deny(assessed)
        self.assert_deny(assessed['requests'][0])
        assessed['requests'][0]['rejection_reasons'].append('output-only')
        assessed['requests'][0]['unproven_reasons'].append('output-only')
        self.assertEqual(value, original)
        fresh = self.assess(value)
        self.assertNotIn('output-only', fresh['requests'][0]['unproven_reasons'])

    def test_empty_public_snapshot_stays_owned_and_keeps_every_previous_field(self):
        raw, _ = empty_snapshot()
        owned = bytearray(raw)
        old = previous.decode(raw, **CAPACITIES)
        output = age.decode(memoryview(owned), **CAPACITIES)
        self.assertEqual(bytes(owned), raw)
        self.assertEqual(output['request_age_assessment']['format'], 'request-age-rejection-v1')
        self.assertEqual(output['request_age_assessment']['requests'], [])
        self.assert_deny(output['request_age_assessment'])
        for key, value in old.items():
            self.assertEqual(output[key], value, key)

    def test_public_api_does_not_accept_a_decoded_or_forged_mutable_result(self):
        raw, _ = empty_snapshot()
        for invalid in (None, {}, parent(), previous.decode(raw, **CAPACITIES),
                        [], 1, '', raw[:-1], raw + b'\0'):
            with self.subTest(type=type(invalid)), self.assertRaises(ValueError):
                age.decode(invalid, **CAPACITIES)

    def test_public_parser_rejects_highbit_or_fault_revision_before_assessment(self):
        raw, sizes = empty_snapshot()
        offset = sizes[0] + sizes[1]
        for value in (0x80000000, 0x80000001, 0xFFFFFFFF):
            with self.subTest(revision=value), self.assertRaises(ValueError):
                age.decode(word(raw, offset, value), **CAPACITIES)
        valid, _ = empty_snapshot(current_revision=MAX)
        result = age.decode(valid, **CAPACITIES)
        self.assertEqual(result['request_age_assessment']['requests'], [])
        self.assert_deny(result['request_age_assessment'])

    def test_public_parser_rejects_highbit_birth_sample_not_only_final_counter(self):
        raw, sizes = empty_snapshot(current_revision=MAX)
        start = sum(sizes[:5])
        raw = bytearray(raw)
        struct.pack_into('<I', raw, start, 1)
        event = fixtures.prior.birth_fixtures.event(revision=0x80000000, scope=0)
        struct.pack_into('<16I', raw, start + birth.HEADER,
                         *(event[field] for field in birth.FIELDS))
        with self.assertRaises(ValueError):
            age.decode(raw, **CAPACITIES)

    def test_public_parser_rejects_faulted_journal_headers_and_dirty_unused_bytes(self):
        raw, sizes = empty_snapshot()
        offsets = [0, sum(sizes[:3]), sum(sizes[:4]), sum(sizes[:5]),
                   sum(sizes[:6]), sum(sizes[:7])]
        for offset in offsets:
            with self.subTest(header=offset), self.assertRaises(ValueError):
                age.decode(word(raw, offset, 0xFFFFFFFF), **CAPACITIES)
        for offset in (lineage.HEADER, sum(sizes[:5]) + birth.HEADER,
                       sum(sizes[:6]) + transport.HEADER,
                       sum(sizes[:7]) + renderer.HEADER):
            with self.subTest(unused=offset), self.assertRaises(ValueError):
                age.decode(word(raw, offset, 1), **CAPACITIES)

    def test_public_parser_rejects_invalid_capacities_not_infers_layout(self):
        raw, _ = empty_snapshot()
        for name in CAPACITIES:
            for value in (True, False, 0, -1, '1', 1.0):
                options = dict(CAPACITIES, **{name: value})
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    age.decode(raw, **options)


if __name__ == '__main__':
    unittest.main()
