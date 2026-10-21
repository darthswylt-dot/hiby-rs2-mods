#!/usr/bin/env python3
"""Execute emitted callback observers; native/SQL bodies are bounded stubs.

Original native JALR instructions, RA and SP run in the instruction harness.
This is not a device, scheduler, retained-owner or contents-completion proof.
"""
import hashlib
import struct
import unittest

import build_reveal_operation_stage as stage
import decode_reveal_operation_journal as decoder
import test_reveal_contents_revision_stage as previous_tests
from verify_reveal_operation_stage import verify


rows = previous_tests.row_tests
STACK, RETURN = rows.STACK, rows.RETURN
VIEW, PANEL, JOB = rows.VIEW, rows.PANEL, rows.JOB
THREAD = rows.lineage_tests.THREAD
DESTINATION = rows.DESTINATION


class OperationMachine(previous_tests.ContentsMachine):
    def site(self, name):
        pc, _ = stage.HOOKS[name]
        if name == 'operation_fill_begin':
            stop = 0x48EC54 if self.get(self.r[17] + 0x2C0, 4) else 0x48EC7C
        elif name == 'operation_fill_return':
            stop = 0x48EDCC if self.r[2] == 0xFFFFFFFF else 0x48EC68
        elif name == 'operation_post_target':
            stop = 0x48EC74 if self.get(self.r[17] + 0x2BC, 4) else 0x48EC7C
        elif name in ('operation_normal_end', 'operation_error_end'):
            stop = 0x48EC84
        elif name == 'operation_bind_return':
            stop = self.r[31]
        else:
            stop = pc + 8
        self.run_at(pc, stop)


class RevealOperationStageTests(unittest.TestCase):
    render = rows.RevealLineageRowsStageTests.render
    borrow = rows.RevealLineageRowsStageTests.borrow
    record = rows.RevealLineageRowsStageTests.record
    producer = rows.RevealLineageRowsStageTests.producer
    event_site = rows.RevealLineageRowsStageTests.event_site
    event_words = rows.RevealLineageRowsStageTests.event_words
    event_bytes = rows.RevealLineageRowsStageTests.event_bytes

    @classmethod
    def setUpClass(cls):
        cls.source = rows.lineage_tests.SOURCE.read_bytes()
        cls.golden, _ = stage.normalize_source(cls.source)
        cls.image, cls.meta = stage.build(
            cls.source, capacity=16, row_capacity=16, operation_capacity=16)

    def machine(self, operation_capacity=16):
        if operation_capacity == 16:
            return OperationMachine(self.image, self.meta)
        image, meta = stage.build(self.source, capacity=16, row_capacity=16,
                                  operation_capacity=operation_capacity)
        return OperationMachine(image, meta)

    def decode(self, m):
        return decoder.decode(m.snapshot(), capacity=m.meta['capacity'],
                              row_capacity=m.meta['row_capacity'],
                              operation_capacity=m.meta['operation_capacity'])

    def operation_words(self, m, index):
        address = m.meta['operation_buffer'] + 16 + index * 64
        data, offset = m.region(address, 64)
        return struct.unpack_from('<16I', data, offset)

    def prepare(self, m=None, *, fill=0x48D280, post=0x48F880):
        m = self.machine() if m is None else m
        origin = self.render(m)
        token = self.borrow(m, origin)
        m.put(JOB + 0x2C0, fill, 4)
        m.put(JOB + 0x2BC, post, 4)
        m.r[29], m.r[16], m.r[17], m.r[31] = STACK, THREAD, JOB, RETURN
        return m, token

    def call_fill(self, m, *, result=0, with_rows=True):
        observed = {}
        previous = m.callback

        def fill(target):
            self.assertEqual((target, m.r[31], m.r[29], m.r[4:6]),
                             (0x48D280, 0x48EC5C, STACK, [THREAD, JOB]))
            observed['call'] = target, m.r[31], m.r[29]
            saved = m.r[16:24].copy()
            m.site('contents_worker_entry')
            self.assertEqual(m.r[29], STACK - 0x40)
            if with_rows:
                self.fill_rows(m, observed)
            m.r[16:24] = saved
            m.r[29], m.r[31] = STACK, 0x48EC5C
            m.hostile_result(result)
            return True

        m.callback = fill
        m.run_at(0x48EC54, 0x48EC5C)
        m.callback = previous
        return observed

    def fill_rows(self, m, observed):
        fill_sp = STACK - 0x40
        m.map(DESTINATION, 0x38)
        m.r[16], m.r[17] = JOB + 0x88, PANEL
        m.r[4:8] = [DESTINATION, 0, 1, 0]
        m.put(fill_sp + 0x20, VIEW, 4)
        previous = m.callback

        def query(target):
            self.assertEqual(target, 0x6F7CA0)
            query_sp, ra = m.r[29], m.r[31]
            saved = m.r[16:24].copy()
            producer = self.producer(m, query_sp, requested=1)
            observed['producer'] = producer
            sp = query_sp - 0xBE0 - 0xAD0
            self.event_site(m, sp, 'row', ordinal=0, result=0,
                            path='a:\\album\\one.flac', cue=0)
            self.event_site(m, sp, 'terminal', ordinal=1, result=101)
            self.event_site(m, sp, 'end', ordinal=1, result=1)
            m.r[16:24] = saved
            m.r[29], m.r[31] = query_sp, ra
            m.hostile_result(0)
            return True

        m.callback = query
        m.site('query')
        m.callback = previous

    def call_post(self, m, *, bind=True, result=0, cached_view=VIEW,
                  bind_ra=0x48F8E0, saved_ra=0x48EC7C):
        observed = {}
        previous = m.callback

        def post(target):
            self.assertEqual((target, m.r[31], m.r[29], m.r[4:6]),
                             (0x48F880, 0x48EC7C, STACK, [THREAD, JOB]))
            observed['call'] = target, m.r[31], m.r[29]
            m.site('contents_postfill')
            post_sp = STACK - 0x30
            self.assertEqual(m.r[29], post_sp)
            m.r[16] = JOB
            m.put(post_sp + 0x20, cached_view, 4)
            m.put(post_sp + 0x2C, saved_ra, 4)
            if bind:
                m.r[4:6], m.r[25] = [PANEL, DESTINATION], 0x4A0EE0
                saved_callback = m.callback

                def binder(native):
                    self.assertEqual((native, m.r[29], m.r[31]),
                                     (0x4A0EE0, post_sp, 0x48F8E0))
                    s = m.r[16:24].copy()
                    m.r[31] = bind_ra
                    m.site('contents_bind')
                    self.assertEqual(m.r[29], post_sp - 0x40)
                    m.r[16:24] = s
                    m.r[29], m.r[31] = post_sp, 0x48F8E0
                    m.hostile_result(result)
                    return True

                m.callback = binder
                m.run_at(0x48F8D8, 0x48F8E0)
                m.callback = saved_callback
                m.run_at(0x48F8E0, 0x48F8E4)
            else:
                # Native V/P-null routes enter E4 after an earlier RA load.
                m.r[31], m.r[2] = saved_ra, result & 0xFFFFFFFF
            m.site('operation_bind_return')
            self.assertEqual(m.r[29], STACK)
            return True

        m.callback = post
        m.run_at(0x48EC74, 0x48EC7C)
        m.callback = previous
        return observed

    def sequence(self, m=None, *, bind=True, fill_result=0, with_rows=True,
                 post=0x48F880, bind_result=0):
        m, token = self.prepare(m, post=post)
        m.site('operation_fill_begin')
        observed = self.call_fill(m, result=fill_result, with_rows=with_rows)
        m.site('operation_fill_return')
        if fill_result == -1:
            previous = m.callback

            def report(target):
                self.assertEqual(target, 0x467160)
                m.hostile_result(0)
                return True

            m.callback = report
            m.run_at(0x48EDCC, 0x48EDD4)
            m.callback = previous
            m.site('operation_error_end')
        else:
            m.site('operation_post_target')
            if post:
                self.call_post(m, bind=bind, result=bind_result)
            m.site('operation_normal_end')
        return m, token, observed

    def test_actual_native_call_pcs_ra_and_stacks_decode_associated_history(self):
        m, token, observed = self.sequence()
        self.assertEqual(observed['call'], (0x48D280, 0x48EC5C, STACK))
        self.assertIn(0x48F880, m.calls)
        self.assertIn(0x4A0EE0, m.calls)
        report = self.decode(m)
        operation = report['operations'][0]
        self.assertEqual(operation['borrow'], token)
        self.assertTrue(operation['row_observation_associated'])
        self.assertTrue(operation['observed_callback_sequence_complete'], operation['reasons'])
        self.assertEqual(operation['event_kinds'], [1, 2, 3, 4, 5, 6])
        self.assertEqual([event['revision'] for event in report['operation_events']],
                         [0, 1, 1, 2, 3, 3])
        self.assertTrue(report['windows'][0]['observed_window_complete'])
        self.assertFalse(report['windows'][0]['complete'])
        self.assertIn('known-contents-boundary', report['windows'][0]['reasons'])
        self.assertFalse(report['contents_current'])
        self.assertFalse(report['autoscroll_authorized'])

    def test_callback_load_branch_and_original_delay_effects_preserve_abi(self):
        for name, offset in (('operation_fill_begin', 0x2C0),
                             ('operation_post_target', 0x2BC)):
            for callee in (0, 0x48D280, 0x48F880, 0x12345678):
                with self.subTest(name=name, callee=callee):
                    m, _ = self.prepare()
                    m.put(JOB + offset, callee, 4)
                    before, hi, lo = m.r.copy(), m.hi, m.lo
                    m.site(name)
                    before[4], before[25] = before[16], callee
                    self.assertEqual((m.r, m.hi, m.lo), (before, hi, lo))
                    self.assertFalse(m.calls)

    def test_fill_return_branch_preserves_result_and_replays_native_delay(self):
        for result in (0, 19, 0xFFFFFFFF, 0x80000000):
            with self.subTest(result=result):
                m, _ = self.prepare()
                m.r[2] = result
                before, hi, lo = m.r.copy(), m.hi, m.lo
                m.site('operation_fill_return')
                before[3], before[4] = 0xFFFFFFFF, (before[19] + 0x1450) & 0xFFFFFFFF
                self.assertEqual((m.r, m.hi, m.lo), (before, hi, lo))
                self.assertEqual(self.operation_words(m, 0)[8], result)

    def test_normal_and_error_end_both_replay_force_two_and_store_before_ec84(self):
        for name in ('operation_normal_end', 'operation_error_end'):
            with self.subTest(name=name):
                m, _ = self.prepare()
                m.r[2] = 0xDEADBEEF
                before, hi, lo = m.r.copy(), m.hi, m.lo
                m.site(name)
                before[2] = 2
                self.assertEqual((m.r, m.hi, m.lo), (before, hi, lo))
                self.assertEqual(m.get(JOB + 4, 4), 2)
                self.assertEqual(self.operation_words(m, 0)[8], 0xDEADBEEF)

    def test_error_native_report_skips_normal_end_but_preserves_stock_state_two(self):
        m, _, _ = self.sequence(fill_result=-1, with_rows=False)
        self.assertIn(0x467160, m.calls)
        self.assertNotIn(0x48F880, m.calls)
        self.assertEqual(m.get(JOB + 4, 4), 2)
        report = self.decode(m)
        self.assertEqual(report['operations'][0]['event_kinds'], [1, 2, 7])
        self.assertFalse(report['operations'][0]['observed_callback_sequence_complete'])
        self.assertIn('fill-error-end', report['operations'][0]['reasons'])

    def test_missing_binding_and_null_post_target_remain_incomplete(self):
        for options in ({'bind': False}, {'post': 0}):
            with self.subTest(options=options):
                m, _, _ = self.sequence(**options)
                report = self.decode(m)
                self.assertFalse(report['operations'][0]['observed_callback_sequence_complete'])
                self.assertFalse(report['operations'][0]['row_observation_associated'])
                # A null callback causes no postfill/bind entry bump. Keep
                # that base diagnostic window verbatim; it still confers no
                # currentness or callback-sequence completion authority.
                self.assertEqual(report['windows'][0]['complete'], options.get('post') == 0)
                self.assertFalse(report['contents_current'])
                self.assertFalse(report['autoscroll_authorized'])

    def test_nonzero_bind_return_is_not_success_even_with_complete_row_journal(self):
        m, _, _ = self.sequence(bind_result=19)
        operation = self.decode(m)['operations'][0]
        self.assertTrue(operation['row_observation_associated'])
        self.assertFalse(operation['observed_callback_sequence_complete'])
        self.assertIn('bind-return-failed', operation['reasons'])

    def test_safe_post_epilogue_restores_native_s0_sp_ra_on_null_and_foreign_routes(self):
        for ra, saved in ((0x48EC7C, 0x48EC7C), (RETURN, RETURN),
                          (0x48EC7C, RETURN), (RETURN, 0x48EC7C)):
            with self.subTest(ra=ra, saved=saved):
                m, _ = self.prepare()
                sp = STACK - 0x30
                m.r[29], m.r[31], m.r[16] = sp, ra, JOB
                m.put(sp + 0x28, 0xCAFEBABE, 4)
                m.put(sp + 0x2C, saved, 4)
                before, hi, lo = m.r.copy(), m.hi, m.lo
                m.site('operation_bind_return')
                before[16], before[29] = 0xCAFEBABE, STACK
                self.assertEqual((m.r, m.hi, m.lo), (before, hi, lo))
                self.assertEqual(m.get(m.meta['operation_buffer'], 4),
                                 1 if ra == saved == 0x48EC7C else 0)

    def test_bind_entry_foreign_ra_gates_before_ancestry_reads_but_keeps_revision(self):
        for ra, saved in ((RETURN, 0x48EC7C), (0x48F8E0, RETURN)):
            with self.subTest(ra=ra, saved=saved):
                m, _ = self.prepare()
                sp = STACK - 0x30
                m.r[29], m.r[31] = sp, ra
                m.r[4:6] = [PANEL, DESTINATION]
                m.put(sp + 0x2C, saved, 4)
                m.put(sp + 0x20, VIEW, 4)
                before, hi, lo = m.r.copy(), m.hi, m.lo
                m.reads.clear()
                m.site('contents_bind')
                before[29] = sp - 0x40
                self.assertEqual((m.r, m.hi, m.lo), (before, hi, lo))
                self.assertEqual(m.get(sp - 0x40 + 0x2C, 4), JOB)
                self.assertEqual(m.get(m.meta['contents_revision_buffer'], 4), 1)
                self.assertEqual(m.get(m.meta['operation_buffer'], 4), 0)
                self.assertNotIn((sp + 0x20, 4), m.reads)
                self.assertNotIn((STACK + 0xAA0, 4), m.reads)

    def test_same_native_addresses_new_borrow_never_merge_old_operation(self):
        m, first, _ = self.sequence()
        m, second, _ = self.sequence(m, bind=False)
        report = self.decode(m)
        self.assertNotEqual(first, second)
        self.assertEqual([item['borrow'] for item in report['operations']], [first, second])
        self.assertTrue(report['operations'][0]['observed_callback_sequence_complete'])
        self.assertFalse(report['operations'][1]['observed_callback_sequence_complete'])
        self.assertEqual(len(report['windows']), 2)

    def test_journal_fault_and_capacity_loss_never_change_native_observer_effects(self):
        for fault in ('fault', 'capacity', 'retry'):
            for name in ('operation_fill_begin', 'operation_fill_return',
                         'operation_post_target', 'operation_normal_end', 'operation_error_end'):
                with self.subTest(fault=fault, name=name):
                    m, _ = self.prepare(self.machine(operation_capacity=1))
                    if fault == 'fault':
                        m.put(m.meta['operation_buffer'], 0xFFFFFFFF, 4)
                    elif fault == 'capacity':
                        m.site('operation_fill_begin')
                    else:
                        m.sc_failures = 8
                    m.r[2] = 0xFFFFFFFF if name == 'operation_fill_return' else 0x87654321
                    before, hi, lo = m.r.copy(), m.hi, m.lo
                    m.site(name)
                    if name in ('operation_fill_begin', 'operation_post_target'):
                        offset = 0x2C0 if name == 'operation_fill_begin' else 0x2BC
                        before[4], before[25] = before[16], m.get(JOB + offset, 4)
                    elif name == 'operation_fill_return':
                        before[3], before[4] = 0xFFFFFFFF, (before[19] + 0x1450) & 0xFFFFFFFF
                    else:
                        before[2] = 2
                        self.assertEqual(m.get(JOB + 4, 4), 2)
                    self.assertEqual((m.r, m.hi, m.lo), (before, hi, lo))
                    self.assertEqual(m.get(m.meta['operation_buffer'], 4), 0xFFFFFFFF)

    def test_faulted_journal_preserves_custom_post_epilogue_and_bind_prologue(self):
        for name in ('operation_bind_return', 'contents_bind'):
            with self.subTest(name=name):
                m, _ = self.prepare()
                m.put(m.meta['operation_buffer'], 0xFFFFFFFF, 4)
                sp = STACK - 0x30
                m.r[29], m.r[31] = sp, 0x48EC7C if name.endswith('return') else 0x48F8E0
                m.r[4:6] = [PANEL, DESTINATION]
                m.put(sp + 0x20, VIEW, 4)
                m.put(sp + 0x28, 0xCAFEBABE, 4)
                m.put(sp + 0x2C, 0x48EC7C, 4)
                before, hi, lo = m.r.copy(), m.hi, m.lo
                m.site(name)
                before[29] = STACK if name.endswith('return') else sp - 0x40
                if name.endswith('return'):
                    before[16] = 0xCAFEBABE
                self.assertEqual((m.r, m.hi, m.lo), (before, hi, lo))

    def test_new_image_keeps_original_calls_delays_and_prior_candidate_exact(self):
        for pc in (0x48EC50, 0x48EC54, 0x48EC58, 0x48EC64, 0x48EC70,
                   0x48EC74, 0x48EC78, 0x48F8E0, 0x48F8EC):
            self.assertEqual(struct.unpack_from('<I', self.image, pc - stage.BASE),
                             struct.unpack_from('<I', self.golden, pc - stage.BASE))
        older, _ = stage.previous.build(self.source)
        self.assertEqual(hashlib.sha256(older).hexdigest(),
                         'f4284cb5adf77111d9c114c4c8889c7cb95eefec5e50c757a21544e8568603ac')

    def test_exact_verifier_capacity_metadata_and_deterministic_source_normalization(self):
        meta = verify(self.source, self.image, capacity=16, row_capacity=16, operation_capacity=16)
        self.assertEqual(meta['snapshot_format'], decoder.FORMAT)
        self.assertEqual(meta['operation_record_bytes'], 64)
        self.assertEqual(meta['operation_buffer'] + meta['operation_memory_bytes'],
                         meta['buffer'] + meta['memory_bytes'])
        self.assertEqual(len(stage.HOOKS), 23)
        self.assertFalse(meta['contents_current'])
        self.assertFalse(meta['autoscroll'])
        self.assertEqual(stage.build(self.golden, capacity=16, row_capacity=16,
                                      operation_capacity=16)[0], self.image)
        for arguments in ({}, {'capacity': 16, 'row_capacity': 16, 'operation_capacity': 15}):
            with self.assertRaises(ValueError):
                verify(self.source, self.image, **arguments)

    def test_all_new_hooks_original_calls_headers_code_and_data_tampering_refused(self):
        offsets = [pc - stage.BASE for pc, _ in stage.NEW_HOOKS.values()]
        offsets += [0x48EC54 - stage.BASE, 0x48EC74 - stage.BASE,
                    0x48F8EC - stage.BASE, 0x300, self.meta['phdr_offset'],
                    self.meta['memsize_offset'], self.meta['code_offset'], len(self.image) - 1]
        for offset in offsets:
            with self.subTest(offset=hex(offset)):
                modified = bytearray(self.image)
                modified[offset] ^= 1
                with self.assertRaises(ValueError):
                    verify(self.source, modified, capacity=16, row_capacity=16, operation_capacity=16)

    def test_unknown_sources_active_modes_and_all_invalid_capacities_refused(self):
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

    def test_full_region_extents_and_composed_code_overlap_are_refused(self):
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
