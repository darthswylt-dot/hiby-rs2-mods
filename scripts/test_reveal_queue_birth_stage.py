#!/usr/bin/env python3
"""Execute native queue producers with private birth observers; no UI authority.

Resource/cache/SQL/geometry helpers and optional widget work remain explicit
fixtures inherited from the request-age counterexample. Native allocation
sizes, append call/RA/delay, metadata, list links and cleanup are inspected.
No request-to-row join or queue-consumer identity transport is implemented.
"""
import hashlib
import struct
import unittest

import build_reveal_queue_birth_stage as stage
import decode_reveal_queue_birth_stage as decoder
import test_reveal_request_freshness_gap as gap
from verify_reveal_queue_birth_stage import verify


class BirthMachine(gap.RequestMachine):
    def __init__(self, image, meta):
        super().__init__(image, meta)
        self.allocation_attempts = []
        self.fail_allocation = None

    def external(self, target):
        if target == 0x8B0D00:
            self.calls.append(target)
            self.allocation_attempts.append(self.r[4])
            if len(self.allocation_attempts) == self.fail_allocation:
                self.hostile_result(0)
            else:
                size = self.r[4]
                result = self.allocation(size)
                self.queue_allocations.append((result, size))
                self.hostile_result(result)
            return
        super().external(target)


class RevealQueueBirthStageTests(unittest.TestCase):
    sequence = gap.RevealRequestFreshnessGapTests.sequence
    prepare = gap.RevealRequestFreshnessGapTests.prepare
    render = gap.RevealRequestFreshnessGapTests.render
    entry = gap.RevealRequestFreshnessGapTests.entry
    borrow = gap.RevealRequestFreshnessGapTests.borrow
    record = gap.RevealRequestFreshnessGapTests.record
    producer = gap.RevealRequestFreshnessGapTests.producer
    event_site = gap.RevealRequestFreshnessGapTests.event_site
    event_words = gap.RevealRequestFreshnessGapTests.event_words
    event_bytes = gap.RevealRequestFreshnessGapTests.event_bytes
    fill_rows = gap.RevealRequestFreshnessGapTests.fill_rows
    call_fill = gap.RevealRequestFreshnessGapTests.call_fill
    call_post = gap.RevealRequestFreshnessGapTests.call_post
    address = gap.RevealRequestFreshnessGapTests.address
    original = gap.RevealRequestFreshnessGapTests.original
    observe = gap.RevealRequestFreshnessGapTests.observe

    @classmethod
    def setUpClass(cls):
        cls.source = gap.history.prior.rows.lineage_tests.SOURCE.read_bytes()
        cls.image, cls.meta = stage.build(cls.source, capacity=16, row_capacity=16,
                                         operation_capacity=16, scope_capacity=16, birth_capacity=32)

    def machine(self, *, birth_capacity=32):
        if birth_capacity == 32:
            return BirthMachine(self.image, self.meta)
        image, meta = stage.build(self.source, capacity=16, row_capacity=16,
                                  operation_capacity=16, scope_capacity=16, birth_capacity=birth_capacity)
        return BirthMachine(image, meta)

    def decode(self, m):
        return decoder.decode(m.snapshot(), capacity=16, row_capacity=16,
                              operation_capacity=16, scope_capacity=16,
                              birth_capacity=m.meta['birth_capacity'])

    def count(self, m):
        return m.get(m.meta['birth_buffer'], 4)

    def journal(self, m):
        return self.decode(m)['queue_birth_observation']

    def test_entry_prologue_once_and_early_id_do_not_clobber_native_abi_or_later_ra_save(self):
        m = self.machine()
        m.r[29], m.r[31] = gap.ENGINE_STACK, gap.RETURN
        m.r[4:7] = [gap.ENGINE, gap.INPUT, gap.OLD_METADATA]
        before, hi, lo = m.r.copy(), m.hi, m.lo
        m.run_at(0x8B428C, 0x8B4294)
        before[29] -= 0x40
        self.assertEqual((m.r, m.hi, m.lo), (before, hi, lo))
        self.assertEqual(m.get(before[29] + 0x30, 4), before[16])
        self.assertEqual(m.get(before[29] + 0x14, 4), 1)
        self.assertEqual(self.count(m), 1)
        self.assertEqual(m.get(before[29] + 0x3C, 4), 0)
        m.run_at(0x8B4294, 0x8B42A0)
        self.assertEqual(m.get(before[29] + 0x3C, 4), gap.RETURN)
        self.assertEqual(sum(at == before[29] + 0x30 for at, _, _ in m.writes), 1)
        self.assertFalse(m.calls)

    def test_actual_native_enqueue_has_three_linked_receipts_without_allocation_growth(self):
        m = self.machine()
        self.assertEqual(m.enqueue(), 0)
        report = self.journal(m)
        events, request = report['events'], report['requests'][0]
        node, words = m.queue()[0]
        self.assertEqual([event['kind'] for event in events], [1, 2, 3])
        self.assertEqual([event['parent'] for event in events], [0, 1, 2])
        self.assertEqual([event['origin'] for event in events], [1, 1, 1])
        self.assertEqual([event['frame'] for event in events], [gap.ENGINE_STACK - 0x40] * 3)
        self.assertEqual([event['copy'] for event in events], [0, words[0], words[0]])
        self.assertEqual([event['result'] for event in events], [0, 0, node])
        self.assertEqual([event['metadata'] for event in events], [gap.OLD_METADATA] * 3)
        self.assertEqual(m.allocation_attempts, [16, 16])
        self.assertEqual(request['append_return'], node)
        self.assertTrue(request['observed_enqueue_sequence_complete'])
        self.assertTrue(request['known_boundary_unchanged'])
        self.assertTrue(request['observed_scopes_quiet'])
        self.assertFalse(request['request_freshness_proven'])
        self.assertFalse(self.decode(m)['birth_identity_transported'])

    def test_original_append_jal_delay_ra_stack_and_pending_fourth_rect_word_are_preserved(self):
        m = self.machine()
        observed = []

        def entry(pc):
            if pc == 0x8B3CC0:
                observed.append((m.r[31], m.r[29], m.r[4:7], m.quad(m.r[5])))

        m.before_instruction = entry
        m.enqueue(rectangle=(7, 11, 13, 17))
        self.assertEqual(len(observed), 1)
        ra, sp, args, rect = observed[0]
        self.assertEqual((ra, sp), (0x8B42F0, gap.ENGINE_STACK - 0x40))
        self.assertEqual(args[0], gap.ENGINE + 0x34)
        self.assertEqual(args[2], gap.OLD_METADATA)
        self.assertEqual(rect, (7, 11, 13, 17))
        self.assertEqual(m.calls.count(0x8B3CC0), 1)

    def test_full_null_request_clears_carrier_and_remains_unobserved(self):
        m = self.machine()
        m.put(gap.ENGINE_STACK - 0x40 + 0x14, 0xDEADBEEF, 4)
        self.assertEqual(m.enqueue(rectangle=None), 0)
        self.assertEqual(self.count(m), 0)
        self.assertEqual(m.allocation_attempts, [])
        self.assertEqual(m.get(gap.ENGINE_STACK - 0x40 + 0x14, 4), 0)
        self.assertEqual(m.get(gap.ENGINE + 0x3C, 4), 0x40000004)
        self.assertFalse(self.decode(m)['request_freshness_proven'])

    def test_missing_native_canvas_returns_before_observer_and_leaves_stack_untouched(self):
        m = self.machine()
        m.put(gap.ENGINE + 0x44, 0, 4)
        self.assertEqual(m.enqueue(), 0)
        self.assertEqual(m.r[29], gap.ENGINE_STACK)
        self.assertEqual(self.count(m), 0)
        self.assertEqual(m.allocation_attempts, [])

    def test_copy_allocation_failure_records_only_birth_and_preserves_native_minus_one(self):
        m = self.machine()
        m.fail_allocation = 1
        self.assertEqual(m.enqueue(), 0xFFFFFFFF)
        report = self.journal(m)
        self.assertEqual([event['kind'] for event in report['events']], [1])
        self.assertFalse(report['requests'][0]['observed_enqueue_sequence_complete'])
        self.assertFalse(report['requests'][0]['queue_return_observed'])
        self.assertEqual(m.queue(), [])

    def test_node_allocation_failure_preserves_zero_raw_return_without_calling_it_success(self):
        m = self.machine()
        m.fail_allocation = 2
        self.assertEqual(m.enqueue(), 0)
        request = self.journal(m)['requests'][0]
        self.assertTrue(request['observed_enqueue_sequence_complete'])
        self.assertTrue(request['queue_return_observed'])
        self.assertEqual(request['append_return'], 0)
        self.assertFalse(request['append_nonzero'])
        self.assertEqual(m.queue(), [])
        self.assertEqual(len(m.queue_allocations), 1)
        self.assertFalse(m.freed)  # Preserve the original failure behavior.
        self.assertFalse(request['request_freshness_proven'])

    def test_frame_reuse_creates_distinct_births_without_using_raw_addresses_as_identity(self):
        m = self.machine()
        m.enqueue()
        m.enqueue()
        requests = self.journal(m)['requests']
        self.assertEqual([request['birth'] for request in requests], [1, 4])
        self.assertEqual(requests[0]['frame'], requests[1]['frame'])
        self.assertEqual(requests[0]['engine'], requests[1]['engine'])
        self.assertEqual(requests[0]['input'], requests[1]['input'])
        self.assertTrue(all(request['observed_enqueue_sequence_complete'] for request in requests))

    def test_reentrant_enqueues_keep_exact_invocation_local_ancestry(self):
        m = self.machine()
        fired = []

        def nested(pc):
            if pc == 0x8B42C4 and not fired:
                fired.append(pc)
                saved, hi, lo = m.r.copy(), m.hi, m.lo
                m.r[29], m.r[31] = gap.ENGINE_STACK - 0x200, gap.RETURN
                m.r[4:7] = [gap.ENGINE, gap.INPUT, 0x56781234]
                m.run_at(0x8B4280, gap.RETURN)
                m.r, m.hi, m.lo = saved, hi, lo

        m.before_instruction = nested
        m.enqueue()
        requests = self.journal(m)['requests']
        self.assertEqual([request['event_sequences'] for request in requests], [[1, 5, 6], [2, 3, 4]])
        self.assertEqual([request['metadata'] for request in requests], [gap.OLD_METADATA, 0x56781234])
        self.assertNotEqual(requests[0]['frame'], requests[1]['frame'])
        self.assertTrue(all(request['observed_enqueue_sequence_complete'] for request in requests))

    def test_known_boundary_during_allocation_is_observed_not_relabelled_or_suppressed(self):
        m = self.machine()
        fired = []

        def boundary(pc):
            if pc == 0x8B42D8 and not fired:
                fired.append(pc)
                saved, hi, lo = m.r.copy(), m.hi, m.lo
                m.run_at(m.labels['contents_bump'], m.r[31])
                m.r, m.hi, m.lo = saved, hi, lo

        m.before_instruction = boundary
        m.enqueue()
        report = self.journal(m)
        self.assertEqual([event['revision'] for event in report['events']], [0, 1, 1])
        self.assertFalse(report['requests'][0]['known_boundary_unchanged'])
        self.assertTrue(report['requests'][0]['observed_enqueue_sequence_complete'])
        self.assertEqual(len(m.queue()), 1)

    def test_reset_repaint_records_active_birth_and_does_not_delete_old_queue(self):
        m = self.machine()
        m.enqueue()
        m.reset()
        requests = self.journal(m)['requests']
        self.assertEqual([request['birth_revision'] for request in requests], [0, 1])
        self.assertEqual([request['born_while_known_scope_active'] for request in requests], [False, True])
        self.assertTrue(all(not request['known_boundary_unchanged'] for request in requests))
        self.assertEqual([fields[1] for _, fields in m.queue()], [gap.OLD_METADATA, 0])

    def test_birth_observer_distinguishes_old_and_new_histories_but_cannot_join_rows(self):
        old, old_report, _ = self.observe(before_reset=True)
        new, new_report, _ = self.observe(before_reset=False)
        prefix = self.meta['birth_buffer'] - self.meta['buffer']
        self.assertEqual(old.snapshot()[:prefix], new.snapshot()[:prefix])
        self.assertNotEqual(old.snapshot()[prefix:], new.snapshot()[prefix:])
        old_request = next(item for item in old_report['queue_birth_observation']['requests']
                           if item['metadata'] == gap.OLD_METADATA)
        new_request = next(item for item in new_report['queue_birth_observation']['requests']
                           if item['metadata'] == gap.OLD_METADATA)
        self.assertEqual((old_request['birth_revision'], new_request['birth_revision']), (0, 2))
        self.assertTrue(old_report['operations'][0]['observed_callback_sequence_complete'])
        for report in (old_report, new_report):
            self.assertFalse(report['birth_identity_transported'])
            self.assertFalse(report['request_freshness_proven'])
            self.assertFalse(report['contents_current'])
            self.assertFalse(report['autoscroll_authorized'])

    def test_synthetic_borrow_and_queue_cleanup_make_no_new_birth_receipts(self):
        m = self.machine()
        m.enqueue()
        before = self.count(m)
        pointers = {address for address, _ in m.queue_allocations}
        m.consume()
        self.assertEqual(self.count(m), before)
        self.assertTrue(pointers.issubset(set(m.freed)))
        self.assertEqual(m.get(gap.ENGINE + 0x34, 4), 0)
        for index, value in enumerate((1, 2, 8, 8)):
            m.put(gap.INPUT + index * 4, value, 4)
        m.r[29], m.r[31], m.r[4:7] = gap.ENGINE_STACK, gap.RETURN, [gap.ENGINE, gap.INPUT, 0]
        m.run_at(0x8B3FA0, gap.RETURN)
        self.assertEqual(self.count(m), before)
        self.assertFalse(any(gap.INPUT + 16 <= address < gap.INPUT + 20 for address, _ in m.reads))

    def test_journal_exhaustion_and_fault_never_suppress_native_enqueue(self):
        for capacity, fault in ((1, False), (2, False), (32, True)):
            with self.subTest(capacity=capacity, fault=fault):
                m = self.machine(birth_capacity=capacity)
                if fault:
                    m.put(m.meta['birth_buffer'], 0xFFFFFFFF, 4)
                self.assertEqual(m.enqueue(), 0)
                self.assertEqual(self.count(m), 0xFFFFFFFF)
                self.assertEqual(m.allocation_attempts, [16, 16])
                self.assertEqual(len(m.queue()), 1)
                self.assertEqual(m.calls.count(0x8B3CC0), 1)
                with self.assertRaises(ValueError):
                    self.decode(m)

    def test_prior_scope_image_is_byte_identical(self):
        image, _ = stage.previous.build(self.source)
        self.assertEqual(hashlib.sha256(image).hexdigest(),
                         '404827620fc6addba436c1911eb89b72b633562d84331de9e0097ede9469b0d5')

    def test_exact_saved_image_and_unchanged_native_anchors(self):
        meta = verify(self.source, self.image, capacity=16, row_capacity=16,
                      operation_capacity=16, scope_capacity=16, birth_capacity=32)
        self.assertEqual(len(stage.HOOKS), 29)
        self.assertFalse(meta['native_allocations_extended'])
        self.assertFalse(meta['birth_identity_transported'])
        golden, _ = stage.normalize_source(self.source)
        self.assertEqual(stage.build(golden, capacity=16, row_capacity=16,
                                     operation_capacity=16, scope_capacity=16, birth_capacity=32)[0], self.image)
        for offset in (0x8B42E8 - stage.BASE, 0x8B42EC - stage.BASE,
                       meta['code_offset'], meta['phdr_offset'], len(self.image) - 1):
            candidate = bytearray(self.image)
            candidate[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                verify(self.source, candidate, capacity=16, row_capacity=16,
                       operation_capacity=16, scope_capacity=16, birth_capacity=32)

    def test_bad_inputs_active_modes_and_private_aliases_refused(self):
        for enabled in (True, 1, 0, None, 'yes'):
            with self.assertRaises(ValueError):
                stage.build(self.source, enable_reveal=enabled)
        for value in (0, -1, True, None, 1.5):
            with self.assertRaises(ValueError):
                stage.build(self.source, birth_capacity=value)
        for source in (self.image, self.source[:-1], bytes(len(self.source))):
            with self.assertRaises(ValueError):
                stage.build(source)
        first, row, revision, operation, scope, birth, code = (self.meta[key] for key in (
            'buffer', 'row_buffer', 'contents_revision_buffer', 'operation_buffer',
            'scope_buffer', 'birth_buffer', 'code_base'))
        for address in (True, -4, birth + 1, row, revision, operation, scope, code, code - 4, 0xFFFFFFFC):
            with self.subTest(address=address), self.assertRaises(ValueError):
                stage.assemble(first, row, revision, operation, scope, address, code,
                               capacity=16, row_capacity=16, operation_capacity=16,
                               scope_capacity=16, birth_capacity=32)


if __name__ == '__main__':
    unittest.main()
