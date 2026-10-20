#!/usr/bin/env python3
"""Execute emitted revision hooks; stubs do not prove real SQL or lifetime."""
import hashlib
import struct
import unittest

import build_reveal_contents_revision_stage as stage
import test_reveal_lineage_rows_stage as row_tests
from verify_reveal_contents_revision_stage import verify


class ContentsMachine(row_tests.RowsMachine):
    def site(self, name):
        pc, _ = stage.HOOKS[name]
        self.run_at(pc, pc + 8)


class ContentsRevisionStageTests(unittest.TestCase):
    record = row_tests.RevealLineageRowsStageTests.record
    render = row_tests.RevealLineageRowsStageTests.render
    borrow = row_tests.RevealLineageRowsStageTests.borrow
    producer = row_tests.RevealLineageRowsStageTests.producer
    event_site = row_tests.RevealLineageRowsStageTests.event_site
    event_bytes = row_tests.RevealLineageRowsStageTests.event_bytes
    event_words = row_tests.RevealLineageRowsStageTests.event_words
    capture = row_tests.RevealLineageRowsStageTests.capture

    @classmethod
    def setUpClass(cls):
        cls.source = row_tests.lineage_tests.SOURCE.read_bytes()
        cls.golden, _ = stage.normalize_source(cls.source)
        cls.image, cls.meta = stage.build(cls.source, capacity=16, row_capacity=16)

    def machine(self, row_capacity=16):
        if row_capacity == 16:
            return ContentsMachine(self.image, self.meta)
        image, meta = stage.build(self.source, capacity=16, row_capacity=row_capacity)
        return ContentsMachine(image, meta)

    def decode(self, m):
        from decode_reveal_contents_revision import decode
        return decode(m.snapshot(), capacity=m.meta['capacity'], row_capacity=m.meta['row_capacity'])

    def revision(self, m):
        return m.get(m.meta['contents_revision_buffer'], 4)

    def producer_revision(self, m, token):
        address = m.state + stage.previous.core.HEADER + (token - 1) * stage.previous.core.RECORD
        return m.get(address + 56, 4)

    def bump(self, m):
        m.run_at(m.labels['contents_bump'], m.r[31])

    def boundary(self, m, name):
        # Compare with the displaced native effects, not with a presumed no-op.
        m.r[29], m.r[31] = row_tests.STACK, row_tests.lineage_tests.RETURN
        if name == 'contents_close_attempt':
            m.r[16] = row_tests.VIEW
            if row_tests.VIEW not in m.regions:
                m.map(row_tests.VIEW, 0x4500)
        before, hi, lo = m.r.copy(), m.hi, m.lo
        count = self.revision(m)
        _, displaced = stage.BOUNDARIES[name]
        first, store = displaced
        expected = before.copy()
        if name == 'contents_close_attempt':
            expected[2] = 1
            address, value = before[16] + 0x44, 1
        else:
            delta = first & 0xFFFF
            delta -= 0x10000 if delta & 0x8000 else 0
            expected[29] = (before[29] + delta) & 0xFFFFFFFF
            address = expected[29] + (store & 0xFFFF)
            value = before[(store >> 16) & 31]
        old_writes = len(m.writes)
        m.site(name)
        self.assertEqual((m.r, m.hi, m.lo), (expected, hi, lo))
        self.assertEqual(m.get(address, 4), value)
        self.assertEqual(self.revision(m), count + 1 if count < 0x7FFFFFFF else 0xFFFFFFFF)
        writes = m.writes[old_writes:]
        revision_writes = [index for index, (at, _, _) in enumerate(writes)
                           if at == m.meta['contents_revision_buffer']]
        native_writes = [index for index, (at, val, width) in enumerate(writes)
                         if (at, val, width) == (address, value, 4)]
        self.assertTrue(revision_writes)
        self.assertGreater(native_writes[-1], revision_writes[-1])
        self.assertFalse(m.calls)

    def test_all_eight_boundaries_bump_before_exact_native_effects_and_preserve_abi(self):
        for name in stage.BOUNDARIES:
            with self.subTest(name=name):
                self.boundary(self.machine(), name)

    def test_nested_entry_shapes_increment_instead_of_faulting_or_rearming(self):
        m = self.machine()
        for name in ('contents_reset_named', 'contents_close_attempt', 'contents_reconcile'):
            self.boundary(m, name)
        self.assertEqual(self.revision(m), 3)
        self.assertNotIn('contents_finish', m.labels)

    def test_fault_or_retry_loss_never_skips_native_boundary(self):
        for value, retries in ((0xFFFFFFFF, 0), (0x7FFFFFFF, 0), (0, 8)):
            for name in stage.BOUNDARIES:
                with self.subTest(value=value, retries=retries, name=name):
                    m = self.machine()
                    m.put(m.meta['contents_revision_buffer'], value, 4)
                    m.sc_failures = retries
                    # boundary() expects only the monotonic normal case.
                    m.r[29], m.r[31], m.r[16] = row_tests.STACK, 0xDEAD0000, row_tests.VIEW
                    m.map(row_tests.VIEW, 0x4500)
                    before, hi, lo = m.r.copy(), m.hi, m.lo
                    m.site(name)
                    expected = before.copy()
                    if name == 'contents_close_attempt':
                        expected[2] = 1
                        self.assertEqual(m.get(row_tests.VIEW + 0x44, 4), 1)
                    else:
                        first, store = stage.BOUNDARIES[name][1]
                        delta = (first & 0xFFFF) - 0x10000
                        expected[29] += delta
                        self.assertEqual(m.get(expected[29] + (store & 0xFFFF), 4),
                                         before[(store >> 16) & 31])
                    self.assertEqual((m.r, m.hi, m.lo), (expected, hi, lo))
                    self.assertEqual(self.revision(m), 0xFFFFFFFF)

    def test_real_generated_producer_freezes_revision_and_all_four_kinds_mirror_it(self):
        m = self.machine()
        self.boundary(m, 'contents_reset')
        self.boundary(m, 'contents_worker_entry')
        m, observed = self.capture([('a:\\album\\one.flac', -1)], machine=m)
        self.assertEqual(self.producer_revision(m, observed['producer']), 2)
        self.assertEqual([self.event_words(m, i)[15] for i in range(4)], [2] * 4)
        report = self.decode(m)
        window = report['windows'][0]
        self.assertTrue(window['observed_window_complete'])
        self.assertTrue(window['known_boundary_unchanged'])
        self.assertTrue(window['complete'])
        self.assertFalse(report['contents_current'])
        self.assertFalse(report['autoscroll_authorized'])

    def test_zero_revision_empty_window_is_observation_not_currentness(self):
        m, _ = self.capture((), requested=0)
        window = self.decode(m)['windows'][0]
        self.assertEqual(window['producer_revision'], 0)
        self.assertTrue(window['complete'])
        self.assertFalse(self.decode(m)['contents_current'])

    def test_later_native_entry_revokes_historical_complete_window_without_relabelling(self):
        m, observed = self.capture([('a:\\album\\one.flac', 0)])
        frozen = self.producer_revision(m, observed['producer'])
        # This is a real emitted boundary, not merely editing decoder input.
        m.calls.clear()
        self.boundary(m, 'contents_postfill')
        self.assertEqual(self.producer_revision(m, observed['producer']), frozen)
        report = self.decode(m)
        window = report['windows'][0]
        self.assertTrue(window['observed_window_complete'])
        self.assertFalse(window['known_boundary_unchanged'])
        self.assertFalse(window['complete'])
        self.assertIn('known-contents-boundary', window['reasons'])

    def test_ordinary_postfill_and_bind_also_conservatively_revoke_the_window(self):
        m, _ = self.capture([('a:\\album\\one.flac', 0)])
        m.calls.clear()
        for name in ('contents_postfill', 'contents_bind'):
            self.boundary(m, name)
        report = self.decode(m)
        self.assertEqual(report['known_contents_revision'], 2)
        self.assertTrue(report['windows'][0]['observed_window_complete'])
        self.assertFalse(report['windows'][0]['complete'])
        self.assertFalse(report['autoscroll_authorized'])

    def test_counter_change_before_capture_suppresses_count_and_descriptor_reads(self):
        m = self.machine()
        fired = []

        def interrupt(pc):
            if pc == m.labels['rows_capture'] and not fired:
                fired.append(pc)
                m.put(m.meta['contents_revision_buffer'], 1, 4)

        m.before_instruction = interrupt
        m, observed = self.capture([('a:\\album\\one.flac', 0)], machine=m)
        self.assertTrue(fired)
        self.assertEqual(self.producer_revision(m, observed['producer']), 0)
        self.assertEqual(m.get(m.meta['row_buffer'], 4), 0xFFFFFFFF)
        self.assertNotIn((row_tests.DESTINATION + 12, 4), m.reads)
        self.assertFalse(any(observed['sp'] + 0x24 <= address < observed['sp'] + 0x22C
                             for address, _ in m.reads))
        with self.assertRaises(ValueError):
            self.decode(m)

    def test_change_during_payload_keeps_slot_unpublished_and_native_results_unchanged(self):
        m = self.machine()
        fired = []

        def interrupt(pc):
            if pc == m.labels['rows_capture_path'] and not fired:
                fired.append(pc)
                m.put(m.meta['contents_revision_buffer'], 1, 4)

        m.before_instruction = interrupt
        m, _ = self.capture([('a:\\album\\one.flac', 0)], machine=m)
        self.assertTrue(fired)
        self.assertEqual(m.get(m.meta['row_buffer'], 4), 0xFFFFFFFF)
        self.assertEqual(self.event_words(m, 0)[0], 0)
        self.assertEqual(m.calls.count(row_tests.APPEND), 1)
        self.assertEqual(m.calls.count(0x5C31C0), 1)

    def test_faulted_revision_before_capture_never_reads_native_payload(self):
        m = self.machine()
        m.put(m.meta['contents_revision_buffer'], 0xFFFFFFFF, 4)
        m, _ = self.capture([('a:\\album\\one.flac', 0)], machine=m)
        self.assertEqual(m.get(m.meta['row_buffer'], 4), 0xFFFFFFFF)
        self.assertNotIn((row_tests.DESTINATION + 12, 4), m.reads)
        with self.assertRaises(ValueError):
            self.decode(m)

    def test_entry_after_last_native_read_check_still_revokes_at_decode(self):
        m = self.machine()
        fired = []

        def interrupt(pc):
            if (pc == m.labels['rows_capture_magic_store'] and m.r[16] == 4
                    and not fired):
                fired.append(pc)
                m.put(m.meta['contents_revision_buffer'], 1, 4)

        m.before_instruction = interrupt
        m, _ = self.capture([('a:\\album\\one.flac', 0)], machine=m)
        self.assertTrue(fired)
        report = self.decode(m)
        self.assertTrue(report['windows'][0]['observed_window_complete'])
        self.assertFalse(report['windows'][0]['complete'])
        self.assertFalse(report['contents_current'])

    def test_stale_job_started_after_reset_remains_explicitly_unknown(self):
        # A start sample cannot discover an earlier still-running writer or
        # prove that the exact original job belongs to the newer contents.
        m = self.machine()
        fired = []

        def interrupt(pc):
            # Original render and BORROW already exist, but the producer has
            # not begun. Model another thread's known reset entry here.
            if pc == m.labels['query'] and not fired:
                fired.append(pc)
                m.put(m.meta['contents_revision_buffer'], 1, 4)

        m.before_instruction = interrupt
        m, _ = self.capture([('a:\\album\\one.flac', 0)], machine=m)
        report = self.decode(m)
        self.assertTrue(fired)
        self.assertEqual(report['windows'][0]['producer_revision'], 1)
        self.assertTrue(report['windows'][0]['known_boundary_unchanged'])
        self.assertFalse(report['contents_current'])
        self.assertFalse(report['autoscroll_authorized'])

    def test_all_extensions_keep_previous_saved_images_byte_identical(self):
        for builder, expected in (
                (stage.previous.build, '408163fd6c2d529df2e04976b89e1b9c39f36dbba679dc5fb9520365bc133a81'),
                (stage.previous.lineage.build, 'f31239aa544c55959e9f75686a421489c8ea6d91e1ef6d30b01955d8c75ec139')):
            with self.subTest(expected=expected):
                image, _ = builder(self.source)
                self.assertEqual(hashlib.sha256(image).hexdigest(), expected)

    def test_exact_image_verification_and_capacities(self):
        result = verify(self.source, self.image, capacity=16, row_capacity=16)
        self.assertEqual(result['known_boundary_count'], 8)
        self.assertFalse(result['contents_current'])
        self.assertFalse(result['autoscroll'])
        self.assertEqual(len(stage.HOOKS), 17)
        self.assertEqual(result['contents_revision_buffer'] + 16,
                         result['buffer'] + result['memory_bytes'])
        golden, _ = stage.normalize_source(self.source)
        self.assertEqual(stage.build(golden, capacity=16, row_capacity=16)[0], self.image)
        with self.assertRaises(ValueError):
            verify(self.source, self.image)

    def test_saved_image_rejects_every_new_hook_and_old_code_data_or_header_tamper(self):
        offsets = [pc - stage.BASE for pc, _ in stage.BOUNDARIES.values()]
        offsets += [0x300, self.meta['phdr_offset'], self.meta['memsize_offset'],
                    len(self.source), self.meta['code_offset'], len(self.image) - 1,
                    0x6ED704 - stage.BASE, 0x48F3BC - stage.BASE]
        for offset in offsets:
            with self.subTest(offset=hex(offset)):
                modified = bytearray(self.image)
                modified[offset] ^= 1
                with self.assertRaises(ValueError):
                    verify(self.source, modified, capacity=16, row_capacity=16)

    def test_invalid_sources_active_modes_bounds_and_optional_addresses_refused(self):
        for flag in (True, 1, 0, None, 'yes'):
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                stage.build(self.source, enable_reveal=flag)
        for source in (self.image, self.source[:-1], bytes(len(self.source))):
            with self.assertRaises(ValueError):
                stage.build(source)
        for value in (0, -1, True, None, 1.5):
            for name in ('capacity', 'row_capacity'):
                with self.subTest(value=value, name=name), self.assertRaises(ValueError):
                    stage.build(self.source, **{name: value})
        for address in (-4, True, 3, 0x100000000, self.meta['buffer'],
                        self.meta['row_buffer'], self.meta['code_base']):
            with self.subTest(address=address), self.assertRaises(ValueError):
                stage.previous.assemble(self.meta['buffer'], self.meta['row_buffer'],
                                        self.meta['code_base'], capacity=16, row_capacity=16,
                                        content_revision_address=address)

    def test_full_revision_extent_cannot_overlap_any_ledger_or_composed_code(self):
        first, second, code = self.meta['buffer'], self.meta['row_buffer'], self.meta['code_base']
        for address in (first - 4, first + 16, second - 4, second + 16,
                        code - 4, code + self.meta['code_bytes'] - 4, 0xFFFFFFFC):
            with self.subTest(address=hex(address)), self.assertRaises(ValueError):
                stage.assemble(first, second, address, code, capacity=16, row_capacity=16)
        for code_address in (True, -4, code + 1, code + 0x10000000, 0x100000000):
            with self.subTest(code_address=code_address), self.assertRaises(ValueError):
                stage.assemble(first, second, self.meta['contents_revision_buffer'], code_address,
                               capacity=16, row_capacity=16)


if __name__ == '__main__':
    unittest.main()
