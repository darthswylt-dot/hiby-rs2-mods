#!/usr/bin/env python3
"""Execute composed scope entry/exit and capture gates; native bodies stubbed."""
import hashlib
import struct
import unittest

import build_reveal_native_scope_stage as stage
import decode_reveal_native_scope_stage as decoder
import test_reveal_origin_frontier_stage as prior
from verify_reveal_native_scope_stage import verify


STACK, RETURN = prior.STACK, prior.RETURN
SCOPE_STACK = STACK + 0x1000


class ScopeMachine(prior.FrontierMachine):
    def site(self, name):
        if name.startswith('scope_'):
            self.run_at(stage.HOOKS[name][0], self.r[31])
        else:
            super().site(name)


class RevealNativeScopeStageTests(unittest.TestCase):
    # Helpers only, not inherited TestCases or duplicate previous test runs.
    borrow = prior.RevealOriginFrontierStageTests.borrow
    record = prior.RevealOriginFrontierStageTests.record
    producer = prior.RevealOriginFrontierStageTests.producer
    event_site = prior.RevealOriginFrontierStageTests.event_site
    event_words = prior.RevealOriginFrontierStageTests.event_words
    event_bytes = prior.RevealOriginFrontierStageTests.event_bytes
    operation_words = prior.RevealOriginFrontierStageTests.operation_words
    prepare = prior.RevealOriginFrontierStageTests.prepare
    call_fill = prior.RevealOriginFrontierStageTests.call_fill
    fill_rows = prior.RevealOriginFrontierStageTests.fill_rows
    call_post = prior.RevealOriginFrontierStageTests.call_post
    sequence = prior.RevealOriginFrontierStageTests.sequence
    revision = prior.RevealOriginFrontierStageTests.revision
    address = prior.RevealOriginFrontierStageTests.address
    entry = prior.RevealOriginFrontierStageTests.entry
    render = prior.RevealOriginFrontierStageTests.render
    mint_without_entry = prior.RevealOriginFrontierStageTests.mint_without_entry
    original = prior.RevealOriginFrontierStageTests.original
    activate_borrow = prior.RevealOriginFrontierStageTests.activate_borrow
    run_prepared = prior.RevealOriginFrontierStageTests.run_prepared
    assert_no_payload = prior.RevealOriginFrontierStageTests.assert_no_payload

    @classmethod
    def setUpClass(cls):
        cls.source = prior.rows.lineage_tests.SOURCE.read_bytes()
        cls.image, cls.meta = stage.build(cls.source, capacity=16, row_capacity=16,
                                         operation_capacity=16, scope_capacity=16)

    def machine(self, operation_capacity=16, *, scope_capacity=16):
        if operation_capacity == scope_capacity == 16:
            return ScopeMachine(self.image, self.meta)
        image, meta = stage.build(self.source, capacity=16, row_capacity=16,
                                  operation_capacity=operation_capacity, scope_capacity=scope_capacity)
        return ScopeMachine(image, meta)

    def decode(self, m):
        return decoder.decode(m.snapshot(), capacity=16, row_capacity=16,
                              operation_capacity=m.meta['operation_capacity'],
                              scope_capacity=m.meta['scope_capacity'])

    def state(self, m):
        return m.get(m.meta['scope_buffer'], 4)

    def slot(self, m, ticket):
        address = m.meta['scope_buffer'] + 16 + (ticket - 1) * 32
        data, offset = m.region(address, 32)
        return struct.unpack_from('<8I', data, offset)

    def begin(self, m, *, reconcile=False, sp=SCOPE_STACK):
        name = 'contents_reconcile' if reconcile else 'contents_reset'
        frame = 0x258 if reconcile else 0x48
        m.r[29], m.r[31], m.r[4], m.r[5] = sp + frame, RETURN, 0x12345678, 0x23456789
        before, hi, lo = m.r.copy(), m.hi, m.lo
        m.site(name)
        before[29] = sp
        self.assertEqual((m.r, m.hi, m.lo), (before, hi, lo))
        return m.get(sp + 0x14, 4)

    def end(self, m, *, name='scope_reset_return', sp=SCOPE_STACK, result=0x87654321):
        frame = 0x48 if name == 'scope_reset_return' else 0x258
        m.r[29], m.r[31], m.r[2] = sp, RETURN, result
        before, hi, lo = m.r.copy(), m.hi, m.lo
        m.site(name)
        before[29] += frame
        self.assertEqual((m.r, m.hi, m.lo), (before, hi, lo))

    def test_native_entries_once_preserve_registers_and_bind_exact_frame_scalars(self):
        for reconcile in (False, True):
            with self.subTest(reconcile=reconcile):
                m = self.machine()
                token = self.begin(m, reconcile=reconcile)
                self.assertEqual(token, 1)
                self.assertEqual(self.state(m), 0x10001)
                self.assertEqual(self.revision(m), 1)
                self.assertEqual(self.slot(m, token),
                                 (stage.scope.MAGIC, 2 if reconcile else 1, 1, SCOPE_STACK,
                                  0x12345678, 0x23456789, stage.scope.OPEN, 0))
                offset, reg = (0x24C, 19) if reconcile else (0x44, 31)
                self.assertEqual(m.get(SCOPE_STACK + offset, 4), m.r[reg])
                self.assertEqual(sum(at == SCOPE_STACK + offset for at, _, _ in m.writes), 1)
                self.assertFalse(m.calls)

    def test_all_normal_exit_pairs_preserve_actual_v0_and_pop_once(self):
        for name in stage.EXITS:
            with self.subTest(name=name):
                m = self.machine()
                token = self.begin(m, reconcile=name != 'scope_reset_return')
                start = len(m.writes)
                self.end(m, name=name)
                self.assertEqual(self.revision(m), 2)
                self.assertEqual(self.state(m), 1)
                self.assertEqual(self.slot(m, token)[6:], (stage.scope.CLOSED, 0x87654321))
                writes = m.writes[start:]
                rev = next(i for i, (at, _, _) in enumerate(writes)
                           if at == m.meta['contents_revision_buffer'])
                close = next(i for i, (at, value, _) in enumerate(writes)
                             if at == m.meta['scope_buffer'] and value == 1)
                self.assertLess(rev, close)
                self.assertFalse(m.calls)

    def test_nested_scopes_close_out_of_order_without_reusing_tickets(self):
        m = self.machine()
        one = self.begin(m)
        two = self.begin(m, reconcile=True, sp=SCOPE_STACK + 0x400)
        self.assertEqual((one, two, self.state(m)), (1, 2, 0x20002))
        self.end(m)
        self.assertEqual(self.state(m), 0x10002)
        self.end(m, name='scope_reconcile_empty_return', sp=SCOPE_STACK + 0x400, result=0)
        self.assertEqual(self.state(m), 2)
        self.assertEqual(self.revision(m), 4)

    def test_open_scope_at_original_entry_remains_unadmitted_after_it_closes(self):
        m = self.machine()
        self.begin(m)
        origin = self.render(m)
        self.assertEqual(self.original(m, origin), 0)
        self.end(m)
        self.activate_borrow(m, origin)
        m.reads.clear()
        observed = self.run_prepared(m)
        self.assert_no_payload(m, observed)
        self.assertEqual(m.get(m.meta['row_buffer'], 4), 0)
        self.assertFalse(self.decode(m)['operations'][0]['observed_callback_sequence_complete'])
        self.assertEqual(m.calls.count(prior.rows.APPEND), 1)

    def test_scope_between_original_entry_and_fill_revokes_even_after_close(self):
        m, _ = self.prepare()
        self.begin(m)
        self.end(m)
        self.activate_borrow(m, 1)
        m.reads.clear()
        observed = self.run_prepared(m)
        self.assert_no_payload(m, observed)
        self.assertEqual(m.get(m.meta['row_buffer'], 4), 0xFFFFFFFF)

    def test_issued_unpublished_scope_is_active_at_original_entry(self):
        m = self.machine()
        m.put(m.meta['scope_buffer'], 0x10001, 4)
        origin = self.render(m)
        self.assertEqual(self.original(m, origin), 0)
        report = self.decode(m)
        self.assertFalse(report['native_scope']['scope_quiet'])

    def race_scope(self, label):
        m = self.machine()
        fired = []

        def race(pc):
            if pc == m.labels[label] and not fired:
                fired.append(pc)
                # An entry has issued its active ticket, but is paused before
                # publishing a slot/bumping the independent revision counter.
                m.put(m.meta['scope_buffer'], 0x10001, 4)

        m.before_instruction = race
        m, _, observed = self.sequence(m)
        self.assertTrue(fired)
        self.assertEqual(m.calls.count(prior.rows.APPEND), 1)
        return m, observed

    def test_active_scope_before_allocation_skips_extra_payload(self):
        m, observed = self.race_scope('rows_capture_scope_pre')
        self.assert_no_payload(m, observed)
        self.assertEqual(m.get(m.meta['row_buffer'], 4), 0)
        self.assertFalse(self.decode(m)['operations'][0]['observed_callback_sequence_complete'])

    def test_active_scope_after_allocation_faults_before_count_read(self):
        m, observed = self.race_scope('rows_capture_scope_reserved')
        self.assert_no_payload(m, observed)
        self.assertEqual(m.get(m.meta['row_buffer'], 4), 0xFFFFFFFF)
        with self.assertRaises(ValueError):
            self.decode(m)

    def test_scope_started_after_payload_prevents_publication_without_claiming_lease(self):
        m, _ = self.race_scope('rows_capture_scope_publish')
        self.assertIn((prior.DESTINATION + 12, 4), m.reads)
        self.assertEqual(m.get(m.meta['row_buffer'], 4), 0xFFFFFFFF)
        self.assertEqual(m.get(m.meta['row_buffer'] + 16, 4), 0)

    def test_fault_and_capacity_loss_never_skip_original_entry_or_exit(self):
        m = self.machine(scope_capacity=1)
        self.begin(m)
        self.end(m)
        self.assertEqual(self.begin(m), 0)
        self.assertEqual(self.state(m), 0xFFFFFFFF)
        self.end(m)
        self.assertEqual(self.state(m), 0xFFFFFFFF)
        self.assertEqual(self.revision(m), 4)
        with self.assertRaises(ValueError):
            self.decode(m)

    def test_duplicate_exit_and_wrong_frame_fault_but_preserve_native_result(self):
        for wrong_frame in (False, True):
            with self.subTest(wrong_frame=wrong_frame):
                m = self.machine()
                self.begin(m)
                if wrong_frame:
                    m.put(SCOPE_STACK + 0x414, 1, 4)
                    self.end(m, sp=SCOPE_STACK + 0x400)
                else:
                    self.end(m)
                    self.end(m)
                self.assertEqual(self.state(m), 0xFFFFFFFF)

    def test_fresh_closed_scope_then_sequence_is_only_historical_evidence(self):
        m = self.machine()
        self.begin(m)
        self.end(m)
        m, _, _ = self.sequence(m)
        report = self.decode(m)
        self.assertEqual(report['format'], decoder.FORMAT)
        self.assertTrue(report['native_scope']['scope_quiet'])
        self.assertTrue(report['operations'][0]['observed_callback_sequence_complete'])
        self.assertFalse(report['windows'][0]['complete'])
        self.assertFalse(report['contents_current'])
        self.assertFalse(report['coherent_capture'])
        self.assertFalse(report['autoscroll_authorized'])

    def test_prior_frontier_image_remains_byte_identical(self):
        image, _ = stage.previous.build(self.source)
        self.assertEqual(hashlib.sha256(image).hexdigest(),
                         'c0db14bd8c1ec6df87eb4690ae55da8f6740e5c59faa9f14f51e6da168818601')

    def test_exact_saved_image_footprint_and_golden_normalization(self):
        meta = verify(self.source, self.image, capacity=16, row_capacity=16,
                      operation_capacity=16, scope_capacity=16)
        self.assertEqual(len(stage.HOOKS), 26)
        self.assertEqual(meta['scope_token_offset'], 0x14)
        self.assertFalse(meta['autoscroll'])
        self.assertFalse(meta['contents_current'])
        golden, _ = stage.normalize_source(self.source)
        self.assertEqual(stage.build(golden, capacity=16, row_capacity=16,
                                     operation_capacity=16, scope_capacity=16)[0], self.image)
        for offset in (stage.EXITS['scope_reset_return'][0] - stage.BASE,
                       meta['code_offset'], meta['memsize_offset'], 0x300, len(self.image) - 1):
            candidate = bytearray(self.image)
            candidate[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                verify(self.source, candidate, capacity=16, row_capacity=16,
                       operation_capacity=16, scope_capacity=16)

    def test_bad_inputs_active_mode_and_region_aliases_refused(self):
        for flag in (True, 1, 0, None, 'yes'):
            with self.assertRaises(ValueError):
                stage.build(self.source, enable_reveal=flag)
        for value in (0, -1, True, None, 1.5, 65536):
            with self.subTest(value=value), self.assertRaises(ValueError):
                stage.build(self.source, scope_capacity=value)
        for source in (self.image, self.source[:-1], bytes(len(self.source))):
            with self.assertRaises(ValueError):
                stage.build(source)
        first, row, revision, operation, scope, code = (self.meta[key] for key in (
            'buffer', 'row_buffer', 'contents_revision_buffer', 'operation_buffer',
            'scope_buffer', 'code_base'))
        for address in (True, -4, scope + 1, row, revision, operation, code, code - 4, 0xFFFFFFFC):
            with self.subTest(address=address), self.assertRaises(ValueError):
                stage.assemble(first, row, revision, operation, address, code, capacity=16,
                               row_capacity=16, operation_capacity=16, scope_capacity=16)


if __name__ == '__main__':
    unittest.main()
