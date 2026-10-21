#!/usr/bin/env python3
"""Execute historical renderer-entry propagation and bounded payload gates.

Native callback/SQL bodies are explicit harness stubs. Matching the original
entry frontier is negative evidence only, never currentness, lifetime or UI
authority. No device, network, installer or source-binary write is performed.
"""
import hashlib
import struct
import unittest

import build_reveal_origin_frontier_stage as stage
import decode_reveal_origin_frontier as decoder
import test_reveal_operation_stage as previous_tests
from verify_reveal_origin_frontier_stage import verify


STACK, RETURN = previous_tests.STACK, previous_tests.RETURN
VIEW, PANEL, JOB = previous_tests.VIEW, previous_tests.PANEL, previous_tests.JOB
THREAD, DESTINATION = previous_tests.THREAD, previous_tests.DESTINATION
rows = previous_tests.rows


class FrontierMachine(previous_tests.OperationMachine):
    pass


class RevealOriginFrontierStageTests(unittest.TestCase):
    borrow = previous_tests.RevealOperationStageTests.borrow
    record = previous_tests.RevealOperationStageTests.record
    producer = previous_tests.RevealOperationStageTests.producer
    event_site = previous_tests.RevealOperationStageTests.event_site
    event_words = previous_tests.RevealOperationStageTests.event_words
    event_bytes = previous_tests.RevealOperationStageTests.event_bytes
    operation_words = previous_tests.RevealOperationStageTests.operation_words
    prepare = previous_tests.RevealOperationStageTests.prepare
    call_fill = previous_tests.RevealOperationStageTests.call_fill
    fill_rows = previous_tests.RevealOperationStageTests.fill_rows
    call_post = previous_tests.RevealOperationStageTests.call_post
    sequence = previous_tests.RevealOperationStageTests.sequence

    @classmethod
    def setUpClass(cls):
        cls.source = rows.lineage_tests.SOURCE.read_bytes()
        cls.golden, _ = stage.normalize_source(cls.source)
        cls.image, cls.meta = stage.build(
            cls.source, capacity=16, row_capacity=16, operation_capacity=16)

    def machine(self, operation_capacity=16):
        if operation_capacity == 16:
            return FrontierMachine(self.image, self.meta)
        image, meta = stage.build(self.source, capacity=16, row_capacity=16,
                                  operation_capacity=operation_capacity)
        return FrontierMachine(image, meta)

    def decode(self, m):
        return decoder.decode(m.snapshot(), capacity=m.meta['capacity'],
                              row_capacity=m.meta['row_capacity'],
                              operation_capacity=m.meta['operation_capacity'])

    def revision(self, m):
        return m.get(m.meta['contents_revision_buffer'], 4)

    def bump(self, m):
        m.run_at(m.labels['contents_bump'], m.r[31])

    def address(self, m, token):
        return m.state + 16 + (token - 1) * 64

    def entry(self, m):
        # Original caller SP is STACK+30; the native renderer frame is STACK.
        m.r[29], m.r[31] = STACK + 0x30, RETURN
        m.site('contents_render_entry')
        self.assertEqual(m.r[29], STACK)
        # Execute all remaining native saved-register stores, stopping before
        # renderer body lookups. The later root hook sees the same native SP.
        m.run_at(0x490700, 0x490714)

    def render(self, m, view=VIEW, panel=PANEL):
        self.entry(m)
        return rows.RevealLineageRowsStageTests.render(self, m, view=view, panel=panel)

    def mint_without_entry(self, m):
        return rows.RevealLineageRowsStageTests.render(self, m)

    def original(self, m, token):
        return m.get(self.address(m, token) + 60, 4)

    def activate_borrow(self, m, origin):
        token = self.borrow(m, origin)
        m.put(JOB + 0x2C0, 0x48D280, 4)
        m.put(JOB + 0x2BC, 0x48F880, 4)
        m.r[29], m.r[16], m.r[17], m.r[31] = STACK, THREAD, JOB, RETURN
        return token

    def run_prepared(self, m, *, bind=True):
        m.site('operation_fill_begin')
        observed = self.call_fill(m)
        m.site('operation_fill_return')
        m.site('operation_post_target')
        self.call_post(m, bind=bind)
        m.site('operation_normal_end')
        return observed

    def assert_no_payload(self, m, observed):
        producer = self.record(m, observed['producer'])
        sp = producer['STACK']
        self.assertNotIn((DESTINATION + 12, 4), m.reads)
        self.assertFalse(any(sp + 0x24 <= at < sp + 0x22C for at, _ in m.reads))
        self.assertNotIn((sp + 0x444, 4), m.reads)

    def test_native_renderer_prologue_once_one_bump_and_scratch_words_do_not_overlap(self):
        m = self.machine()
        m.r[29], m.r[31] = STACK + 0x30, RETURN
        m.put(STACK + 0x10, 0xDEADBEEF, 4)
        m.put(STACK + 0x14, 0xCAFEBABE, 4)
        before, hi, lo = m.r.copy(), m.hi, m.lo
        initial = len(m.writes)
        m.site('contents_render_entry')
        before[29] = STACK
        self.assertEqual((m.r, m.hi, m.lo), (before, hi, lo))
        self.assertEqual(m.get(STACK + 0x2C, 4), RETURN)
        self.assertEqual(m.get(STACK + 0x10, 4), 1)
        self.assertEqual(m.get(STACK + 0x14, 4), 0xCAFEBABE)
        self.assertEqual(self.revision(m), 1)
        writes = m.writes[initial:]
        self.assertEqual(writes.count((STACK + 0x2C, RETURN, 4)), 1)
        self.assertEqual(sum(at == m.meta['contents_revision_buffer'] for at, _, _ in writes), 1)
        self.assertEqual(sum(at == STACK + 0x10 for at, _, _ in writes), 1)
        self.assertFalse(m.calls)

    def test_entry_records_actual_returned_revision_despite_later_successful_bump(self):
        m = self.machine()
        fired = []

        def race(pc):
            if pc == m.labels['contents_bump_check'] and not fired:
                fired.append(pc)
                # A different caller successfully advanced the clock after
                # this entry issued1 but before its bump returned that token.
                m.put(m.meta['contents_revision_buffer'], 2, 4)

        m.before_instruction = race
        self.entry(m)
        m.before_instruction = None
        self.assertTrue(fired)
        self.assertEqual(self.revision(m), 2)
        self.assertEqual(m.get(STACK + 0x10, 4), 1)
        origin = self.mint_without_entry(m)
        self.assertEqual(self.original(m, origin), 1)

    def test_counter_fault_exhaustion_and_retry_loss_write_zero_but_replay_native_entry(self):
        for value, retries in ((0xFFFFFFFF, 0), (0x7FFFFFFF, 0), (0, 8)):
            with self.subTest(value=value, retries=retries):
                m = self.machine()
                m.put(m.meta['contents_revision_buffer'], value, 4)
                m.sc_failures = retries
                m.put(STACK + 0x10, 0xDEADBEEF, 4)
                m.r[29], m.r[31] = STACK + 0x30, RETURN
                before, hi, lo = m.r.copy(), m.hi, m.lo
                m.site('contents_render_entry')
                before[29] = STACK
                self.assertEqual((m.r, m.hi, m.lo), (before, hi, lo))
                self.assertEqual(m.get(STACK + 0x10, 4), 0)
                self.assertEqual(m.get(STACK + 0x2C, 4), RETURN)
                self.assertEqual(self.revision(m), 0xFFFFFFFF)

    def test_original_render_field_is_published_once_and_never_relabelled(self):
        m = self.machine()
        origin = self.render(m)
        start = self.address(m, origin)
        data, offset = m.region(start, 64)
        frozen = bytes(data[offset:offset + 64])
        self.assertEqual(self.original(m, origin), 1)
        self.assertEqual(m.get(STACK + 0x14, 4), origin)
        self.bump(m)
        self.activate_borrow(m, origin)
        self.assertEqual(bytes(data[offset:offset + 64]), frozen)
        writes = [(at, value, width) for at, value, width in m.writes if at == start + 60]
        self.assertEqual(writes, [(start + 60, 1, 4)])
        for index in range(1, m.get(m.state, 4)):
            self.assertEqual(m.get(m.state + 16 + index * 64 + 60, 4), 0)

    def test_fresh_original_full_native_callback_chain_passes_only_historical_association(self):
        m, token, observed = self.sequence()
        report = self.decode(m)
        operation = report['operations'][0]
        producer = report['receipts'][observed['producer'] - 1]
        self.assertEqual(operation['borrow'], token)
        self.assertEqual(operation['original_entry_revision'], 1)
        self.assertEqual(operation['starting_revision'], 1)
        self.assertEqual(producer['producer_revision'], 2)
        self.assertTrue(operation['original_frontier_matches'])
        self.assertTrue(operation['observed_callback_sequence_complete'])
        self.assertTrue(operation['row_observation_associated'])
        self.assertTrue(report['windows'][0]['observed_window_complete'])
        self.assertFalse(report['windows'][0]['complete'])
        self.assertFalse(report['contents_current'])
        self.assertFalse(report['coherent_capture'])
        self.assertFalse(report['autoscroll_authorized'])
        self.assertEqual([event['revision'] for event in report['operation_events']],
                         [1, 2, 2, 3, 4, 4])

    def test_old_queued_original_after_known_boundary_faults_before_native_payload(self):
        m, _ = self.prepare()
        self.bump(m)
        self.assertEqual(self.revision(m), 2)
        observed = self.run_prepared(m)
        self.assertEqual(self.original(m, 1), 1)
        self.assert_no_payload(m, observed)
        self.assertEqual(m.get(m.meta['row_buffer'], 4), 0xFFFFFFFF)
        self.assertEqual(m.get(JOB + 4, 4), 2)
        self.assertEqual(m.calls.count(rows.APPEND), 1)
        with self.assertRaises(ValueError):
            self.decode(m)

    def test_delayed_root_mint_keeps_its_earlier_entry_not_the_later_counter(self):
        m = self.machine()
        self.entry(m)
        self.bump(m)
        origin = self.mint_without_entry(m)
        self.assertEqual(self.original(m, origin), 1)
        self.assertEqual(self.revision(m), 2)
        self.activate_borrow(m, origin)
        observed = self.run_prepared(m)
        self.assert_no_payload(m, observed)
        self.assertEqual(m.get(m.meta['row_buffer'], 4), 0xFFFFFFFF)

    def test_unknown_zero_original_is_unadmitted_without_following_payload(self):
        m = self.machine()
        origin = self.mint_without_entry(m)
        self.assertEqual(self.original(m, origin), 0)
        self.activate_borrow(m, origin)
        observed = self.run_prepared(m)
        self.assert_no_payload(m, observed)
        self.assertEqual(m.get(m.meta['row_buffer'], 4), 0)
        operation = self.decode(m)['operations'][0]
        self.assertFalse(operation['original_frontier_matches'])
        self.assertFalse(operation['observed_callback_sequence_complete'])

    def test_initial_origin_remains_zero_and_is_skipped_before_payload(self):
        m = self.machine()
        origin = rows.lineage_tests.RevealLineageStageTests.stamp(self, m, initial=True)
        self.assertEqual(self.record(m, origin)['KIND'], 2)
        self.assertEqual(self.original(m, origin), 0)
        self.activate_borrow(m, origin)
        m.calls.clear()
        observed = self.run_prepared(m)
        self.assert_no_payload(m, observed)
        self.assertEqual(m.get(m.meta['row_buffer'], 4), 0)
        report = self.decode(m)
        self.assertFalse(report['operations'][0]['original_frontier_matches'])
        self.assertFalse(report['operations'][0]['observed_callback_sequence_complete'])

    def test_same_original_later_chunk_is_conservatively_rejected_not_relabelled(self):
        m, first, _ = self.sequence()
        origin = self.record(m, first)['ORIGIN']
        frozen = self.original(m, origin)
        second = self.activate_borrow(m, origin)
        m.reads.clear()
        observed = self.run_prepared(m)
        self.assertNotEqual(first, second)
        self.assertEqual(self.original(m, origin), frozen)
        self.assert_no_payload(m, observed)
        self.assertEqual(m.get(m.meta['row_buffer'], 4), 0xFFFFFFFF)
        self.assertEqual(m.get(JOB + 4, 4), 2)

    def test_later_boundary_during_active_producer_keeps_existing_revision_gate(self):
        m = self.machine()
        fired = []

        def race(pc):
            if pc == m.labels['rows_capture'] and not fired:
                fired.append(pc)
                m.put(m.meta['contents_revision_buffer'], 3, 4)

        m.before_instruction = race
        m, _, observed = self.sequence(m)
        self.assertTrue(fired)
        self.assert_no_payload(m, observed)
        self.assertEqual(m.get(m.meta['row_buffer'], 4), 0xFFFFFFFF)
        self.assertEqual(m.calls.count(rows.APPEND), 1)
        with self.assertRaises(ValueError):
            self.decode(m)

    def test_version_discriminator_changes_without_growing_the_bss_layout(self):
        m, _, _ = self.sequence()
        report = self.decode(m)
        self.assertEqual(report['format'], decoder.FORMAT)
        self.assertEqual(self.meta['snapshot_format'], decoder.FORMAT)
        old, older = stage.previous.build(self.source, capacity=16, row_capacity=16,
                                           operation_capacity=16)
        self.assertEqual(self.meta['memory_bytes'], older['memory_bytes'])
        self.assertEqual(self.meta['operation_record_bytes'], 64)
        self.assertNotEqual(self.image, old)
        with self.assertRaises(ValueError):
            previous_tests.decoder.decode(m.snapshot(), capacity=16, row_capacity=16,
                                           operation_capacity=16)

    def test_prior_operation_and_revision_images_remain_byte_identical(self):
        for builder, digest in (
                (stage.previous.build,
                 'be40cecaa6172376f98cd8403477d16f609884347774564d19b7a95f881a49f8'),
                (stage.previous.previous.build,
                 'f4284cb5adf77111d9c114c4c8889c7cb95eefec5e50c757a21544e8568603ac')):
            with self.subTest(digest=digest):
                image, _ = builder(self.source)
                self.assertEqual(hashlib.sha256(image).hexdigest(), digest)

    def test_original_native_footprint_and_exact_saved_image_verification(self):
        meta = verify(self.source, self.image, capacity=16, row_capacity=16, operation_capacity=16)
        self.assertEqual(len(stage.HOOKS), 23)
        self.assertFalse(meta['autoscroll'])
        self.assertFalse(meta['contents_current'])
        self.assertEqual(meta['prefix_bytes'], 708)
        self.assertEqual(meta['element_bytes'], 712)
        self.assertEqual(meta['origin_entry_offset'], 0x10)
        self.assertEqual(meta['origin_entry_revision_offset'], 60)
        self.assertTrue(meta['requires_original_frontier'])
        for pc in (0x490700, 0x490704, 0x490708, 0x49070C, 0x490710,
                   0x48EC54, 0x48EC74, 0x48F8E0, 0x48F8EC):
            self.assertEqual(struct.unpack_from('<I', self.image, pc - stage.BASE),
                             struct.unpack_from('<I', self.golden, pc - stage.BASE))
        self.assertEqual(stage.build(self.golden, capacity=16, row_capacity=16,
                                      operation_capacity=16)[0], self.image)

    def test_unknown_sources_all_capacities_and_active_modes_refused(self):
        for source in (self.image, self.source[:-1], bytes(len(self.source))):
            with self.assertRaises(ValueError):
                stage.build(source)
        for enabled in (True, 1, 0, None, 'yes'):
            with self.subTest(enabled=enabled), self.assertRaises(ValueError):
                stage.build(self.source, enable_reveal=enabled)
        for name in ('capacity', 'row_capacity', 'operation_capacity'):
            for value in (0, -1, True, None, 1.5):
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    stage.build(self.source, **{name: value})
        for options in ({}, {'capacity': 16, 'row_capacity': 16, 'operation_capacity': 15}):
            with self.assertRaises(ValueError):
                verify(self.source, self.image, **options)

    def test_saved_image_tampering_native_carrier_root_gate_and_headers_refused(self):
        offsets = [0x4906F8 - stage.BASE, 0x490758 - stage.BASE,
                   0x48EC54 - stage.BASE, 0x6ED624 - stage.BASE,
                   self.meta['code_offset'], len(self.image) - 1,
                   self.meta['phdr_offset'], self.meta['memsize_offset'], 0x300]
        for offset in offsets:
            with self.subTest(offset=hex(offset)):
                candidate = bytearray(self.image)
                candidate[offset] ^= 1
                with self.assertRaises(ValueError):
                    verify(self.source, candidate, capacity=16, row_capacity=16,
                           operation_capacity=16)

    def test_full_private_extents_and_composed_code_must_remain_disjoint(self):
        first, row, revision, operation, code = (self.meta[key] for key in (
            'buffer', 'row_buffer', 'contents_revision_buffer', 'operation_buffer', 'code_base'))
        for address in (first - 4, first + 16, row - 4, row + 16,
                        revision - 4, revision + 12, code - 4,
                        code + self.meta['code_bytes'] - 4, 0xFFFFFFFC):
            with self.subTest(operation=hex(address)), self.assertRaises(ValueError):
                stage.assemble(first, row, revision, address, code,
                               capacity=16, row_capacity=16, operation_capacity=16)
        for address in (True, -4, code + 1, code + 0x10000000, 0x100000000):
            with self.subTest(code=address), self.assertRaises(ValueError):
                stage.assemble(first, row, revision, operation, address,
                               capacity=16, row_capacity=16, operation_capacity=16)


if __name__ == '__main__':
    unittest.main()
