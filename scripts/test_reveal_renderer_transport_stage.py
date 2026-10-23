#!/usr/bin/env python3
"""Execute exact native callback/outer/renderer call boundaries and observers.

Name/resource methods are hostile stubs. The outer geometry/cache middle is
explicitly replaced by a fixture, then its ORIGINAL child call executes. The
child's actual entry, list resolution, native getter, strcpy call and both
observers execute; its suffix/job/SQL path remains the existing composed
fixture. This is not a whole UI execution, native lease or device test.
"""
import hashlib
import struct
import unittest

import build_reveal_renderer_transport_stage as stage
import decode_reveal_renderer_transport_stage as decoder
import test_reveal_queue_transport_stage as prior
from verify_reveal_renderer_transport_stage import verify


gap = prior.gap
CAPACITIES = dict(prior.CAPACITIES, renderer_capacity=32)
RESOURCE, CACHE, WLIST, CELL = 0x2400000, 0x2500000, 0x2600000, 0x2700000
COUNT, INDEX = 0x1F10200, 0x1F10300


class RendererMachine(prior.TransportMachine):
    def __init__(self, image, meta):
        super().__init__(image, meta)
        for address, size in ((RESOURCE, 0x300), (CACHE, 0x80), (WLIST, 0x38),
                              (CELL, 4), (0xA90000, 0x1000)):
            self.map(address, size)
        self.put(0xA90F94, 1, 4)
        self.bytes(CACHE, b'canvas_fixture\0')
        self.put(CACHE + 0x50, 3, 4)
        self.put(CACHE + 0x60, 16, 4)
        self.put(gap.WIDGET + 0xFC, WLIST, 4)
        self.put(gap.WIDGET + 0x148, 0x4906E0, 4)
        self.put(WLIST + 0x30, COUNT, 4)
        self.put(WLIST + 0x2C, INDEX, 4)
        self.put(CELL, gap.PANEL, 4)
        self.put(gap.PANEL + 0x7C, gap.VIEW, 4)
        self.put(gap.PANEL + 0x1BC, 0x76543210, 4)
        self.put(gap.VIEW + 0xDC, 0x13579BDF, 4)
        self.outer_runs, self.renderer_runs = [], []
        self.outer_observer_reads, self.renderer_observer_reads = [], []
        self.on_root = None

    def external(self, target):
        if target == 0x439EC0:
            self.calls.append(target)
            original = self.r.copy()
            for _ in range(self.repeat_callbacks):
                self.r = original.copy()
                frame = self.r[29] - 0x38
                self.run_at(target, original[31])
                self.callback_ids.append(self.get(frame + 0x14, 4))
            return
        if target == 0x438200:
            self.calls.append(target)
            returned = self.r[31]
            read_start = len(self.reads)
            self.run_at(target, 0x438258)
            self.outer_observer_reads.append(self.reads[read_start:].copy())
            frame = self.r[29]
            self.outer_runs.append(dict(frame=frame, ticket=self.get(frame + 0x14, 4)))
            # Explicit fixture: native geometry/cache resolution is omitted.
            # Keep the actual original W+148 load/JALR/argument delay below.
            self.put(frame + 0x1B0, CACHE, 4)
            self.put(frame + 0x1CC, 0, 4)
            self.run_at(0x43872C, 0x438748)
            self.run_at(0x43866C, returned)  # actual native outer epilogue
            return
        if target == 0x4906E0:
            self.calls.append(target)
            returned = self.r[31]
            read_start = len(self.reads)
            self.run_at(target, 0x490778)
            self.renderer_observer_reads.append(self.reads[read_start:].copy())
            frame = self.r[29]
            run = dict(frame=frame, lineage=self.get(frame + 0x14, 4),
                       entry=self.get(frame + 0x10, 4),
                       last_receipt=self.get(self.meta['renderer_transport_buffer'], 4),
                       native_result=self.r[2])
            self.renderer_runs.append(run)
            if self.on_root is not None:
                saved, hi, lo = self.r.copy(), self.hi, self.lo
                self.on_root(self, run)
                self.r, self.hi, self.lo = saved, hi, lo
            # Explicit suffix fixture, followed by actual renderer epilogue.
            self.r[2] = 0
            self.run_at(0x490818, returned)
            return
        if target == 0x459340:
            self.calls.append(target)
            self.run_at(target, self.r[31])  # actual native P+7C getter
            return
        if target in (COUNT, INDEX, 0x485DE0, 0x439E20, 0xA5BEE0) or (
                target == 0x485420 and self.r[31] == 0x439F64):
            self.calls.append(target)
            if target == COUNT:
                if self.r[4] != WLIST:
                    raise AssertionError('wrong native list count receiver')
                result = 1
            elif target == INDEX:
                if self.r[4:6] != [WLIST, 0]:
                    raise AssertionError('wrong native list index arguments')
                result = CELL
            elif target == 0xA5BEE0:
                destination, source = self.r[4:6]
                if (destination, source) != (gap.VIEW + 0x38AC, CACHE):
                    raise AssertionError('wrong native strcpy arguments')
                copied = bytearray()
                for offset in range(0x80):
                    copied.append(self.get(source + offset, 1))
                    if copied[-1] == 0:
                        break
                else:
                    raise AssertionError('fixture cache string not terminated')
                self.bytes(destination, bytes(copied))
                result = destination
            else:
                result = gap.WIDGET if target == 0x439E20 else RESOURCE
            self.hostile_result(result)
            return
        super().external(target)


class RevealRendererTransportStageTests(unittest.TestCase):
    # Prior fixture helpers only; no earlier TestCases are inherited/repeated.
    borrow = prior.RevealQueueTransportStageTests.borrow
    record = prior.RevealQueueTransportStageTests.record
    producer = prior.RevealQueueTransportStageTests.producer
    event_site = prior.RevealQueueTransportStageTests.event_site
    event_words = prior.RevealQueueTransportStageTests.event_words
    event_bytes = prior.RevealQueueTransportStageTests.event_bytes
    fill_rows = prior.RevealQueueTransportStageTests.fill_rows
    call_fill = prior.RevealQueueTransportStageTests.call_fill
    call_post = prior.RevealQueueTransportStageTests.call_post
    operation_words = gap.history.RevealNativeScopeStageTests.operation_words
    run_prepared = gap.history.RevealNativeScopeStageTests.run_prepared

    @classmethod
    def setUpClass(cls):
        cls.source = gap.history.prior.rows.lineage_tests.SOURCE.read_bytes()
        cls.image, cls.meta = stage.build(cls.source, **CAPACITIES)

    def machine(self, **overrides):
        if not overrides:
            return RendererMachine(self.image, self.meta)
        image, meta = stage.build(self.source, **dict(CAPACITIES, **overrides))
        return RendererMachine(image, meta)

    def decode(self, m):
        return decoder.decode(m.snapshot(), **{key: m.meta[key] for key in CAPACITIES})

    def count(self, m):
        return m.get(m.meta['renderer_transport_buffer'], 4)

    def journal(self, m):
        return self.decode(m)['renderer_transport_observation']

    def history(self, *, rows=True, machine=None):
        m = self.machine() if machine is None else machine
        m.enqueue()
        m.consume()
        root = m.renderer_runs[0]['lineage']
        observed = self.rows_from_root(m, root) if rows else {}
        return m, root, observed

    def rows_from_root(self, m, root):
        # Explicit composed worker/query fixture: use the exact already-
        # captured renderer ID, not a new root or native address lookup.
        self.borrow(m, root)
        old = gap.history.prior
        m.put(old.JOB + 0x2C0, 0x48D280, 4)
        m.put(old.JOB + 0x2BC, 0x48F880, 4)
        m.r[29], m.r[16], m.r[17], m.r[31] = old.STACK, old.THREAD, old.JOB, old.RETURN
        return self.run_prepared(m)

    def test_exact_native_callback_outer_and_renderer_root_association(self):
        m, root, _ = self.history(rows=False)
        report = self.journal(m)
        self.assertEqual([event['kind'] for event in report['events']], [1, 2])
        association = report['associations'][0]
        self.assertEqual((association['birth'], association['callback'], association['outer'],
                          association['renderer'], association['lineage']), (1, 4, 1, 2, root))
        self.assertTrue(association['renderer_root_associated'])
        self.assertTrue(association['observation_complete'])
        self.assertEqual(m.outer_runs[0]['ticket'], 1)
        self.assertEqual(m.renderer_runs[0]['entry'], 1)
        self.assertEqual(m.renderer_runs[0]['native_result'], 0x76543210)
        self.assertEqual(m.get(gap.VIEW + 0x3B50, 4), CACHE)
        self.assertEqual(m.callback_ids, [4])
        for target in (0x439EC0, 0x438200, 0x4906E0, 0x459340, 0xA5BEE0):
            self.assertEqual(m.calls.count(target), 1)
        self.assertFalse(association['request_freshness_proven'])

    def test_exact_root_links_captured_rows_but_preserves_old_rejections(self):
        m, root, observed = self.history()
        result = self.decode(m)
        associated = result['renderer_row_associations'][0]
        self.assertEqual(associated['lineage'], root)
        self.assertEqual(associated['producers'], [observed['producer']])
        self.assertEqual(associated['row_event_sequences'], [1])
        self.assertTrue(associated['observed_row_identity_associated'])
        self.assertEqual(associated['window_indices'], [0])
        self.assertFalse(result['windows'][0]['complete'])
        self.assertIn('known-contents-boundary', result['windows'][0]['reasons'])
        for field in ('contents_current', 'coherent_capture', 'autoscroll_authorized',
                      'request_freshness_proven', 'current_owner_proven'):
            self.assertFalse(result[field])
            self.assertFalse(associated[field])

    def test_two_callbacks_same_native_addresses_keep_different_renderer_roots(self):
        m = self.machine()
        m.repeat_callbacks = 2
        m.enqueue()
        m.consume()
        report = self.journal(m)
        self.assertEqual([event['kind'] for event in report['events']], [1, 2, 1, 2])
        first, second = report['associations']
        self.assertEqual((first['birth'], second['birth']), (1, 1))
        self.assertEqual((first['callback'], second['callback']), (4, 5))
        self.assertEqual((first['lineage'], second['lineage']), (1, 2))
        self.assertEqual(m.renderer_runs[0]['frame'], m.renderer_runs[1]['frame'])
        self.assertTrue(all(item['observation_complete'] for item in report['associations']))

    def test_root_observer_preserves_actual_strcpy_result_hi_lo_native_pair_and_carriers(self):
        m = self.machine()
        observed = {}

        def instruction(pc):
            if pc == 0x49076C:
                observed.update(regs=m.r.copy(), hi=m.hi, lo=m.lo,
                                entry=m.get(m.r[29] + 0x10, 4), root=m.get(m.r[29] + 0x14, 4))
            elif pc == 0x490774:
                expected = observed['regs'].copy()
                expected[2] = m.get(gap.PANEL + 0x1BC, 4)
                self.assertEqual((m.r, m.hi, m.lo), (expected, observed['hi'], observed['lo']))
                self.assertEqual(m.get(m.r[29] + 0x10, 4), observed['entry'])
                self.assertEqual(m.get(m.r[29] + 0x14, 4), observed['root'])

        m.before_instruction = instruction
        m.enqueue()
        m.consume()
        self.assertEqual(observed['regs'][2], gap.VIEW + 0x38AC)
        self.assertEqual(observed['regs'][20], 0x13579BDF)  # no longer coordinates
        self.assertEqual(observed['root'], 1)

    def test_outer_observer_replays_native_pair_once_and_preserves_other_registers(self):
        m = self.machine()
        observed = {}

        def instruction(pc):
            if pc == 0x438248:
                observed.update(regs=m.r.copy(), hi=m.hi, lo=m.lo)
            elif pc == 0x438250:
                expected = observed['regs'].copy()
                expected[20], expected[17] = expected[6], expected[7]
                self.assertEqual((m.r, m.hi, m.lo), (expected, observed['hi'], observed['lo']))

        m.before_instruction = instruction
        m.enqueue()
        m.consume()
        self.assertEqual(self.count(m), 2)

    def test_unclassified_callback_stays_zero_without_outer_or_renderer_ancestor_carrier_reads(self):
        m = self.machine()
        m.r[29], m.r[31], m.r[4:6] = gap.ENGINE_STACK, 0x8B4998, [gap.ENGINE, gap.INPUT]
        m.reads.clear()
        m.external(0x439EC0)
        self.assertEqual(self.count(m), 0)
        self.assertEqual(m.outer_runs[0]['ticket'], 0)
        self.assertEqual(m.callback_ids, [0])
        self.assertGreater(m.renderer_runs[0]['lineage'], 0)
        self.assertFalse(self.decode(m)['renderer_identity_associated'])
        callback_frame = gap.ENGINE_STACK - 0x38
        outer_frame = callback_frame - 0x200
        for address in (callback_frame + 0x14, outer_frame + 0x14):
            for reads in (*m.outer_observer_reads, *m.renderer_observer_reads):
                self.assertFalse(any(at == address for at, _ in reads))

    def test_outer_each_gate_precedes_upstream_carrier_read_and_preserves_native_pair(self):
        for failed in ('outer-ra', 'callback-ra', 'coords', 'engine', 'widget', 'input', 'controller'):
            with self.subTest(failed=failed):
                m = self.machine()
                outer, callback = gap.ENGINE_STACK - 0x200, gap.ENGINE_STACK
                m.r[29], m.r[4:8], m.r[19] = outer, [gap.ENGINE, gap.WIDGET, callback + 0x18, callback + 0x90], gap.OWNER
                for offset, value in ((0x1FC, 0x439F98), (0x234, 0x8B40EC),
                                      (0x1D8, gap.ENGINE), (0x1DC, gap.WIDGET),
                                      (0x1E0, callback + 0x90), (0x1E4, gap.OWNER),
                                      (0x214, 0xDEADBEEF), (0x14, 0xCAFEBABE)):
                    m.put(outer + offset, value, 4)
                if failed in ('outer-ra', 'callback-ra'):
                    m.put(outer + (0x1FC if failed == 'outer-ra' else 0x234), gap.RETURN, 4)
                elif failed == 'controller':
                    m.put(outer + 0x1E4, gap.NAME, 4)
                else:
                    m.r[{'coords': 6, 'engine': 4, 'widget': 5, 'input': 7}[failed]] = gap.INPUT
                expected, hi, lo = m.r.copy(), m.hi, m.lo
                expected[20], expected[17] = expected[6], expected[7]
                m.reads.clear()
                m.run_at(0x438248, 0x438250)
                self.assertEqual((m.r, m.hi, m.lo), (expected, hi, lo))
                self.assertFalse(any(at == outer + 0x214 for at, _ in m.reads))
                if failed == 'outer-ra':
                    self.assertFalse(any(at == outer + 0x234 for at, _ in m.reads))
                self.assertEqual(m.get(outer + 0x14, 4), 0)
                self.assertEqual(self.count(m), 0)

    def test_renderer_each_gate_precedes_outer_carrier_and_never_overwrites_entry_or_root(self):
        for failed in ('child-ra', 'outer-ra', 'callback-ra', 'engine', 'cache', 'unknown-root'):
            with self.subTest(failed=failed):
                m = self.machine()
                frame = gap.ENGINE_STACK - 0x30
                m.r[29], m.r[16:20], m.r[30] = frame, [gap.VIEW, CACHE, gap.PANEL, gap.ENGINE], gap.WIDGET
                for offset, value in ((0x2C, 0x438748), (0x22C, 0x439F98), (0x264, 0x8B40EC),
                                      (0x18, gap.ENGINE), (0x1E0, CACHE), (0x14, 0xCAFEBABE),
                                      (0x10, 0x12345678), (0x44, 0xDEADBEEF)):
                    m.put(frame + offset, value, 4)
                if failed in ('child-ra', 'outer-ra', 'callback-ra'):
                    m.put(frame + {'child-ra': 0x2C, 'outer-ra': 0x22C, 'callback-ra': 0x264}[failed], gap.RETURN, 4)
                else:
                    m.put(frame + {'engine': 0x18, 'cache': 0x1E0, 'unknown-root': 0x14}[failed], 0, 4)
                entry, root = m.get(frame + 0x10, 4), m.get(frame + 0x14, 4)
                expected, hi, lo = m.r.copy(), m.hi, m.lo
                expected[2] = 0x76543210
                m.reads.clear()
                m.run_at(0x49076C, 0x490774)
                self.assertEqual((m.r, m.hi, m.lo), (expected, hi, lo))
                self.assertFalse(any(at == frame + 0x44 for at, _ in m.reads))
                if failed == 'child-ra':
                    self.assertFalse(any(at == frame + 0x22C for at, _ in m.reads))
                if failed in ('child-ra', 'outer-ra'):
                    self.assertFalse(any(at == frame + 0x264 for at, _ in m.reads))
                self.assertEqual((m.get(frame + 0x10, 4), m.get(frame + 0x14, 4)), (entry, root))
                self.assertEqual(self.count(m), 0)

    def test_same_addresses_new_request_keep_distinct_birth_and_renderer_identity(self):
        m, root, _ = self.history(rows=False)
        reused = iter(address for address, _ in m.queue_allocations)
        m.allocation = lambda size: next(reused)
        m.enqueue()
        m.consume()
        first, second = self.journal(m)['associations']
        self.assertEqual((first['birth'], second['birth']), (1, 4))
        self.assertEqual((first['callback'], second['callback']), (4, 8))
        self.assertEqual((first['lineage'], second['lineage']), (root, root + 1))
        for field in ('engine', 'widget', 'view', 'panel', 'job', 'cache', 'frame'):
            self.assertEqual(first[field], second[field], field)
        self.assertEqual(m.queue_allocations[:2], m.queue_allocations[2:])

    def test_old_reset_request_is_associated_without_becoming_fresh(self):
        m = self.machine()
        m.enqueue()
        m.reset()
        m.consume()
        report = self.journal(m)
        self.assertEqual([item['birth'] for item in report['associations']], [1, 4])
        self.assertEqual([item['birth_revision'] for item in report['associations']], [0, 1])
        self.assertEqual([item['original_entry_revision'] for item in report['associations']], [3, 4])
        for association in report['associations']:
            self.assertTrue(association['renderer_root_associated'])
            self.assertTrue(association['observation_complete'])
            self.assertFalse(association['known_boundary_unchanged'])
            self.assertFalse(association['request_freshness_proven'])

    def test_native_renderer_can_precede_producer_return_without_fabricating_it(self):
        m = self.machine()
        partial = []

        def before_return(pc):
            if pc == 0x8B42F0 and not partial:
                saved, hi, lo = m.r.copy(), m.hi, m.lo
                m.consume(stack=gap.ENGINE_STACK - 0x1000)
                partial.append(self.journal(m))
                m.r, m.hi, m.lo = saved, hi, lo

        m.before_instruction = before_return
        m.enqueue()
        association = partial[0]['associations'][0]
        self.assertTrue(association['renderer_root_associated'])
        self.assertFalse(association['producer_return_observed'])
        self.assertFalse(association['observation_complete'])
        self.assertTrue(self.journal(m)['associations'][0]['observation_complete'])

    def test_fault_exhaustion_or_bad_upstream_does_not_suppress_native_calls_or_cleanup(self):
        for case in ('fault', 'capacity', 'upstream', 'lineage'):
            with self.subTest(case=case):
                m = self.machine(renderer_capacity=1) if case == 'capacity' else self.machine()
                if case == 'fault':
                    m.put(m.meta['renderer_transport_buffer'], 0xFFFFFFFF, 4)
                elif case == 'upstream':
                    m.put(m.meta['transport_buffer'], 0xFFFFFFFF, 4)
                elif case == 'lineage':
                    m.put(m.meta['buffer'], 0xFFFFFFFF, 4)
                m.enqueue()
                node = m.queue()[0][0]
                m.consume()
                self.assertEqual(m.calls.count(0x438200), 1)
                self.assertEqual(m.calls.count(0x4906E0), 1)
                self.assertEqual(m.calls.count(0xA5BEE0), 1)
                self.assertEqual(m.get(gap.VIEW + 0x3B50, 4), CACHE)
                self.assertEqual(m.allocation_attempts, [16, 20])
                self.assertEqual(m.get(gap.ENGINE + 0x34, 4), 0)
                self.assertIn(node, m.freed)
                with self.assertRaises(ValueError):
                    self.decode(m)

    def test_prior_transport_default_remains_byte_identical(self):
        image, _ = stage.previous.build(self.source)
        self.assertEqual(hashlib.sha256(image).hexdigest(),
                         '754ea4f3b1a6351b4409f1229a84ac380d18365fa32ce91062489b08b2bedba6')

    def test_exact_image_hooks_and_original_call_delay_anchors(self):
        checked = verify(self.source, self.image, **CAPACITIES)
        self.assertEqual(len(stage.HOOKS), 35)
        self.assertFalse(checked['renderer_identity_associated'])
        golden, _ = stage.normalize_source(self.source)
        self.assertEqual(stage.build(golden, **CAPACITIES)[0], self.image)
        for pc in (0x438248, 0x43824C, 0x438740, 0x438744,
                   0x439F90, 0x439F94, 0x490758, 0x490764, 0x490768, 0x49076C, 0x490770):
            changed = bytearray(self.image)
            changed[pc - stage.BASE] ^= 1
            with self.subTest(pc=pc), self.assertRaises(ValueError):
                verify(self.source, changed, **CAPACITIES)

    def test_active_modes_bad_capacities_sources_and_private_aliases_refused(self):
        for value in (True, 1, 0, None, 'yes'):
            with self.assertRaises(ValueError):
                stage.build(self.source, enable_reveal=value)
        for value in (0, -1, True, None, 1.5):
            with self.assertRaises(ValueError):
                stage.build(self.source, renderer_capacity=value)
        for source in (self.image, self.source[:-1], bytes(len(self.source))):
            with self.assertRaises(ValueError):
                stage.build(source)
        regions = [self.meta[key] for key in ('buffer', 'row_buffer', 'contents_revision_buffer',
                                             'operation_buffer', 'scope_buffer', 'birth_buffer', 'transport_buffer')]
        code, address = self.meta['code_base'], self.meta['renderer_transport_buffer']
        for value in (True, -4, address + 1, *regions, code, code - 4, 0xFFFFFFFC):
            with self.subTest(value=value), self.assertRaises(ValueError):
                stage.assemble(*regions, value, code, **CAPACITIES)


if __name__ == '__main__':
    unittest.main()
