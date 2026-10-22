#!/usr/bin/env python3
"""Execute the queued-paint age counterexample; never grant UI authority.

The pinned reset body, repaint wrapper, queue append, queued-loop and queued
paint callback builder execute native instructions. Allocator, resource/cache,
SQL/list binder and in-bounds geometry helpers are explicit hostile-ABI stubs.
The optional widget-to-job part reuses the existing composed lineage fixture;
it is NOT an execution of every intervening widget/native SQL routine. These
tests establish a missing request-birth association, not stale row contents,
concurrent teardown, actual hardware behavior or permission to enable reveal.
No device, network, firmware output or new instrumentation is performed.
"""
import struct
import unittest

import test_reveal_native_scope_stage as history


MASK, STACK, RETURN = 0xFFFFFFFF, history.STACK, history.RETURN
ENGINE, SURFACE, OWNER, WIDGET = 0x1500000, 0x1600000, 0x1700000, 0x1400000
VIEW, PANEL = history.prior.VIEW, history.prior.PANEL
INPUT, NAME = 0x2200000, 0x2300000
BUILD, BIND = 0x1F10000, 0x1F10100
OLD_METADATA = 0x12345678
ENGINE_STACK, RESET_STACK = STACK + 0x1800, STACK + 0x1000


class RequestMachine(history.ScopeMachine):
    def __init__(self, image, meta):
        super().__init__(image, meta)
        for address, size in ((ENGINE, 0x54), (SURFACE, 0x100), (OWNER, 0x300),
                              (WIDGET, 0x200), (VIEW, 0x4500), (PANEL, 0x500),
                              (INPUT, 16), (NAME, 64)):
            self.map(address, size)
        self.bytes(NAME, b'vg_listview_explorer\0')
        for offset, value in ((0, NAME), (0x3C, 4), (0x44, SURFACE),
                              (0x48, 0x439EC0), (0x50, OWNER)):
            self.put(ENGINE + offset, value, 4)
        for offset in (0x1C, 0x20):
            self.put(SURFACE + offset, 1024, 4)
        for offset, value in ((0xCC, ENGINE), (0xD0, WIDGET), (0x3B68, PANEL),
                              (0x4218, BUILD), (0x6C, 1), (0x5C, 16), (0x60, 16)):
            self.put(VIEW + offset, value, 4)
        self.put(PANEL + 0x410, BIND, 4)
        self.put(WIDGET + 0x50, 16, 4)
        self.put(WIDGET + 0x60, 16, 4)
        self.queue_allocations, self.paints, self.cache_clears = [], [], []
        self.on_paint = None

    def plain(self, word):
        if word >> 26 == 0 and word & 63 in (0x24, 0x25):
            rs, rt, rd = (word >> 21) & 31, (word >> 16) & 31, (word >> 11) & 31
            self.r[rd] = ((self.r[rs] & self.r[rt]) if word & 63 == 0x24
                          else (self.r[rs] | self.r[rt])) & MASK
            self.r[0] = 0
            return
        super().plain(word)

    def quad(self, address):
        return tuple(self.get(address + i * 4, 4) for i in range(4))

    def external(self, target):
        # Execute these native bodies recursively instead of substituting a
        # Python queue. They still use original call/return PCs and frames.
        native = (0x459840, 0x8B4280, 0x8B3CC0, 0x8B3FA0,
                  0x8B3F00, 0x8B3100)
        if target in native:
            self.calls.append(target)
            self.run_at(target, self.r[31])
            return
        if target == 0x8B0D00:
            self.calls.append(target)
            size = self.r[4]
            result = self.allocation(size)
            self.queue_allocations.append((result, size))
        elif target == 0x8B0D20:
            self.calls.append(target)
            self.freed.append(self.r[4])
            result = 0
        elif target == 0x468D40:
            self.calls.append(target)
            if self.r[4] != ENGINE:
                raise AssertionError('wrong engine argument to the global redraw predicate')
            result = 1
        elif target in (BUILD, BIND, 0x459660, 0x4596E0, 0x8B5B60):
            self.calls.append(target)
            # Fixture list/geometry was initialized above. No helper clears
            # the engine queue. Source contracts separately pin that boundary.
            result = 0
        elif target == 0x485420:
            self.calls.append(target)
            result = WIDGET
        elif target == 0x47AA20:
            self.calls.append(target)
            if self.r[4:6] != [OWNER, NAME]:
                raise AssertionError('wrong cache-clear name/owner')
            self.cache_clears.append(tuple(self.r[4:6]))
            result = 0
        elif target in (0x8B3220, 0x8B3A00):
            self.calls.append(target)
            # Selected fixtures are in bounds and need one unchanged region.
            values = self.quad(self.r[5])
            for index, value in enumerate(values):
                self.put(self.r[4] + index * 4, value, 4)
            result = 1
        elif target == 0x439EC0:
            self.calls.append(target)
            descriptor = self.r[5]
            words = tuple(self.get(descriptor + i * 4, 4) for i in range(5))
            paint = dict(engine=self.r[4], descriptor=descriptor, words=words,
                         first=self.quad(words[0]), second=self.quad(words[1]),
                         revision=self.get(self.meta['contents_revision_buffer'], 4),
                         scope_state=self.get(self.meta['scope_buffer'], 4))
            self.paints.append(paint)
            if self.on_paint is not None:
                saved, hi, lo = self.r.copy(), self.hi, self.lo
                self.on_paint(self, paint)
                self.r, self.hi, self.lo = saved, hi, lo
            result = 0
        else:
            super().external(target)
            return
        self.hostile_result(result)

    def enqueue(self, metadata=OLD_METADATA, rectangle=(1, 2, 8, 8)):
        if rectangle is not None:
            for index, value in enumerate(rectangle):
                self.put(INPUT + index * 4, value, 4)
        self.r[29], self.r[31] = ENGINE_STACK, RETURN
        self.r[4:7] = [ENGINE, INPUT if rectangle is not None else 0, metadata]
        self.run_at(0x8B4280, RETURN)
        return self.r[2]

    def reset(self):
        # Run the actual native reset body, including the composed entry and
        # return observers, not merely an artificial revision-counter update.
        self.r[29], self.r[31], self.r[4], self.r[5] = RESET_STACK, RETURN, OWNER, VIEW
        self.run_at(0x491240, RETURN)
        return self.r[2]

    def consume(self):
        # Execute the exact queued-loop/cleanup segment. The earlier render
        # surface-selection/geometry branch is not modeled by this fixture.
        self.r[29], self.r[31], self.r[21], self.r[16] = ENGINE_STACK, RETURN, ENGINE, SURFACE
        self.run_at(0x8B4740, 0x8B478C)

    def queue(self):
        result, node = [], self.get(ENGINE + 0x34, 4)
        while node:
            if len(result) >= 16:
                raise AssertionError('unexpected queue cycle')
            result.append((node, self.quad(node)))
            node = result[-1][1][3]
        return result


class RevealRequestFreshnessGapTests(unittest.TestCase):
    # Only helpers are reused; previous TestCases are not recollected here.
    sequence = history.RevealNativeScopeStageTests.sequence
    prepare = history.RevealNativeScopeStageTests.prepare
    render = history.RevealNativeScopeStageTests.render
    entry = history.RevealNativeScopeStageTests.entry
    borrow = history.RevealNativeScopeStageTests.borrow
    record = history.RevealNativeScopeStageTests.record
    producer = history.RevealNativeScopeStageTests.producer
    event_site = history.RevealNativeScopeStageTests.event_site
    event_words = history.RevealNativeScopeStageTests.event_words
    event_bytes = history.RevealNativeScopeStageTests.event_bytes
    fill_rows = history.RevealNativeScopeStageTests.fill_rows
    call_fill = history.RevealNativeScopeStageTests.call_fill
    call_post = history.RevealNativeScopeStageTests.call_post
    address = history.RevealNativeScopeStageTests.address
    original = history.RevealNativeScopeStageTests.original

    @classmethod
    def setUpClass(cls):
        cls.source = history.prior.rows.lineage_tests.SOURCE.read_bytes()
        cls.image, cls.meta = history.stage.build(cls.source, capacity=16, row_capacity=16,
                                                operation_capacity=16, scope_capacity=16)

    def machine(self):
        return RequestMachine(self.image, self.meta)

    def decode(self, m):
        return history.decoder.decode(m.snapshot(), capacity=16, row_capacity=16,
                                      operation_capacity=16, scope_capacity=16)

    def test_native_enqueue_copies_exactly_sixteen_bytes_and_keeps_occupied_metadata(self):
        m = self.machine()
        self.assertEqual(m.enqueue(), 0)
        node, fields = m.queue()[0]
        self.assertEqual(fields[1:], (OLD_METADATA, 0, 0))
        self.assertEqual(m.quad(fields[0]), (1, 2, 8, 8))
        self.assertEqual(m.queue_allocations, [(fields[0], 16), (node, 16)])
        m.put(INPUT, 999, 4)
        self.assertEqual(m.quad(fields[0]), (1, 2, 8, 8))

    def test_actual_reset_keeps_old_queue_head_and_appends_new_nonnull_rectangle(self):
        m = self.machine()
        m.enqueue()
        old = m.queue()[0]
        self.assertEqual(m.reset(), 0)
        queue = m.queue()
        self.assertEqual(len(queue), 2)
        self.assertEqual(queue[0][0], old[0])
        self.assertEqual(queue[0][1][:3], old[1][:3])
        self.assertEqual(queue[0][1][3], queue[1][0])
        self.assertEqual(queue[1][1][1:3], (0, queue[0][0]))
        self.assertEqual(m.quad(queue[1][1][0]), (0, 0, 16, 376))
        self.assertEqual(m.cache_clears, [(OWNER, NAME)])
        self.assertEqual(m.get(ENGINE + 0x3C, 4), 4)
        self.assertEqual(m.get(m.meta['contents_revision_buffer'], 4), 2)
        self.assertEqual(m.get(m.meta['scope_buffer'], 4), 1)

    def test_later_native_queue_loop_dispatches_old_request_then_reset_request(self):
        m = self.machine()
        m.enqueue()
        m.reset()
        pointers = {address for address, _ in m.queue_allocations}
        m.consume()
        self.assertEqual([paint['words'][4] for paint in m.paints], [OLD_METADATA, 0])
        self.assertEqual([paint['revision'] for paint in m.paints], [2, 2])
        self.assertEqual([paint['scope_state'] for paint in m.paints], [1, 1])
        self.assertEqual([paint['first'] for paint in m.paints], [(1, 2, 8, 8), (0, 0, 16, 376)])
        self.assertEqual([paint['words'][2:4] for paint in m.paints], [(0, 0), (0, 0)])
        self.assertTrue(all(paint['engine'] == ENGINE for paint in m.paints))
        self.assertEqual(m.get(ENGINE + 0x34, 4), 0)
        self.assertTrue(pointers.issubset(set(m.freed)))

    def test_two_full_redraw_requests_coalesce_without_allocating_birth_identity(self):
        m = self.machine()
        m.enqueue()
        before = m.queue()
        count = len(m.queue_allocations)
        m.enqueue(rectangle=None)
        flags = m.get(ENGINE + 0x3C, 4)
        m.enqueue(rectangle=None)
        self.assertEqual(flags, 0x40000004)
        self.assertEqual(m.get(ENGINE + 0x3C, 4), flags)
        self.assertEqual(m.queue(), before)
        self.assertEqual(len(m.queue_allocations), count)

    def test_synthetic_geometry_borrow_still_accepts_only_an_ordinary_sixteen_byte_rect(self):
        m = self.machine()
        for index, value in enumerate((1, 2, 8, 8)):
            m.put(INPUT + index * 4, value, 4)
        m.r[29], m.r[31] = ENGINE_STACK, RETURN
        m.r[4:7] = [ENGINE, INPUT, 0]
        m.run_at(0x8B3FA0, RETURN)
        self.assertEqual(len(m.paints), 1)
        self.assertEqual(m.paints[0]['words'][4], 0)
        self.assertFalse(any(INPUT + 16 <= address < INPUT + 20 for address, _ in m.reads))

    def observe(self, *, before_reset):
        m = self.machine()
        if before_reset:
            m.enqueue()
        m.reset()
        if not before_reset:
            m.enqueue()
        observed = {}

        def widget_fixture(machine, paint):
            if paint['words'][4] == OLD_METADATA:
                machine.on_paint = None
                _, token, producer = self.sequence(machine)
                observed.update(token=token, producer=producer['producer'])

        m.on_paint = widget_fixture
        m.consume()
        self.assertTrue(observed)
        return m, self.decode(m), observed

    def test_current_negative_filters_do_not_establish_request_birth_freshness(self):
        m, report, observed = self.observe(before_reset=True)
        operation = report['operations'][0]
        self.assertEqual(operation['original_entry_revision'], 3)
        self.assertEqual(report['receipts'][observed['producer'] - 1]['producer_revision'], 4)
        self.assertTrue(operation['original_frontier_matches'])
        self.assertTrue(operation['observed_callback_sequence_complete'])
        self.assertTrue(report['native_scope']['scope_quiet'])
        self.assertEqual(m.paints[0]['words'][4], OLD_METADATA)
        self.assertEqual(m.paints[0]['revision'], 2)
        self.assertFalse(report['contents_current'])
        self.assertFalse(report['coherent_capture'])
        self.assertFalse(report['autoscroll_authorized'])

    def test_old_and_new_request_histories_have_identical_private_capture_bytes(self):
        old, old_report, _ = self.observe(before_reset=True)
        new, new_report, _ = self.observe(before_reset=False)
        self.assertNotEqual([paint['words'][4] for paint in old.paints],
                            [paint['words'][4] for paint in new.paints])
        # The existing ledger correctly makes only a historical claim. Paint
        # birth is absent: equal current stamps/quiet cannot distinguish age.
        self.assertEqual(old.snapshot(), new.snapshot())
        self.assertEqual(old_report, new_report)


if __name__ == '__main__':
    unittest.main()
