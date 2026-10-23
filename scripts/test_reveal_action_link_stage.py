#!/usr/bin/env python3
"""Execute two native queues and the exact action/explorer/paint/BIRTH path.

Actual ELF constructors, 20/36-byte segmented-list methods, worker selection
and fanout, explorer handler, paint producer/getter/consumer, redraw wrapper
and existing BIRTH/transport observers execute. Registry/name resolution,
thread scheduling, mutex services and allocators are explicit bounded stubs.
The worker is stopped after one native drain and executes its actual exit
epilogue; this is not a scheduler, concurrent native lease or hardware test.
Optional renderer consumption retains the predecessor's documented geometry,
resource and SQL fixture boundaries. A frozen parent is historical control
flow, never a coherent post-unlock native payload or permission to reveal.
"""

import hashlib
import struct
import unittest

import build_reveal_action_link_stage as stage
import decode_reveal_action_link as decoder
import decode_reveal_action_link_stage as combined_decoder
import reveal_action_link_mips as core
import decode_reveal_queue_birth as birth_decoder
import test_reveal_renderer_transport_stage as prior
import test_folderfollow_reveal_static_contract as source


gap = prior.gap
CAPACITIES = dict(prior.CAPACITIES, playback_dispatch_capacity=8, action_link_capacity=64)
PLAYER = 0xADD368
CONTROLLER, RESOURCE, NODE = gap.OWNER, prior.RESOURCE, gap.ENGINE
REGISTRY, LINK = 0x2800000, 0x2801000
REGISTRY_LOCK, REGISTRY_UNLOCK = 0x1F20000, 0x1F20100
PAINT_LOCK = 0x1F20200
PRODUCER_STACK, WORKER_STACK, CONSUMER_STACK = 0x200A800, 0x2009800, 0x2005800
RETURN, MASK = gap.RETURN, 0xFFFFFFFF


class ActionLinkMachine(prior.RendererMachine):
    def __init__(self, image, meta):
        super().__init__(image, meta)
        self.trace, self.read_events, self.lock_events = [], [], []
        self.native_entries, self.copies = [], []
        self.pc = None
        self.action_locked = self.paint_locked = False
        self.action_worker = self.action_list = 0
        self.current_controller = CONTROLLER
        self.registry_present = True
        self.extra_engines = set()
        self.fail_next_heap = False
        self.wakes, self.next_mutex = 0, 0x1F30000
        self.on_instruction = self.after_paint_unlock = None
        self.before_instruction = self.observe
        self.paint_getter_active = False
        for address, size in ((PLAYER, 0xC00), (REGISTRY, 0x100), (LINK, 0x20)):
            self.map(address, size)
        self.bytes(RESOURCE + 0x20, b'vg_listview_explorer\0')
        self.put(RESOURCE + 0x7C, gap.VIEW, 4)
        self.put(RESOURCE + 0x150, 0x490980, 4)
        self.put(gap.VIEW + 0x4C, 8, 4)
        for offset, value in ((0xC, 8), (0x10, 8), (0x14, 1), (0x18, 8)):
            self.put(NODE + offset, value, 4)
        self.put(CONTROLLER + 0x24, REGISTRY, 4)
        self.put(CONTROLLER + 0x34, LINK, 4)
        self.put(LINK, CONTROLLER + 0x34, 4)
        self.put(LINK + 8, NODE, 4)
        self.put(CONTROLLER + 0x274, REGISTRY_LOCK, 4)
        self.put(CONTROLLER + 0x278, REGISTRY_UNLOCK, 4)
        self.put(CONTROLLER + 0x148, PAINT_LOCK, 4)
        self.put(CONTROLLER + 0x284, 0x437CE0, 4)
        self.put(CONTROLLER + 0x288, 0x437D60, 4)
        self.action_worker = self.stock(0x4BAAC0)
        self.action_list = self.peek(self.action_worker + 0x1C)
        self.put(CONTROLLER + 0xC4, self.action_worker, 4)
        self.stock(0x439840, CONTROLLER)
        self.paint_list = self.peek(CONTROLLER + 0x128)
        self.trace.clear()
        self.read_events.clear()
        self.native_entries.clear()
        self.copies.clear()

    def peek(self, address, size=4):
        data, offset = self.region(address, size)
        return int.from_bytes(data[offset:offset + size], 'little')

    def memory(self, address, size):
        data, offset = self.region(address, size)
        return bytes(data[offset:offset + size])

    def get(self, address, size):
        if hasattr(self, 'read_events') and self.pc is not None:
            self.read_events.append((self.pc, address, size, self.action_locked, self.paint_locked))
        return super().get(address, size)

    def observe(self, pc):
        self.pc = pc
        self.trace.append(pc)
        if pc == 0x4399C0:
            self.paint_getter_active = True
        if pc == 0x43C918:
            self.paint_getter_active = False
        if pc in (0x455DA0, 0x490980, 0x43C860, 0x439900, 0x4399C0,
                  0x459840, 0x8B4280, 0x8B3CC0):
            self.native_entries.append((pc, self.r[31], self.r[29], tuple(self.r[4:8])))
        if self.on_instruction is not None:
            self.on_instruction(pc)

    def stock(self, target, *args):
        self.r[29], self.r[31] = PRODUCER_STACK, RETURN
        self.r[4:4 + len(args)] = args
        self.run_at(target, RETURN)
        self.pc = None
        return self.r[2]

    def external(self, target):
        native = (0x4BAC80, 0x490980, 0x43C860, 0x439900, 0x4399C0,
                  0x439960, 0x437CE0, 0x437D60, 0x455DC0)
        if target in native:
            self.calls.append(target)
            self.run_at(target, self.r[31])
            return
        if target == 0x43D200:
            self.calls.append(target)
            self.hostile_result(self.current_controller)
            return
        if target == 0x468D40:
            # Visibility/readiness is a fixture, not a current-owner proof.
            self.calls.append(target)
            if self.r[4] not in {CONTROLLER, NODE, *self.extra_engines}:
                raise AssertionError('unexpected predicate receiver')
            self.hostile_result(1)
            return
        if target in (0x466D60, 0x466C80, 0x466BA0):
            self.calls.append(target)
            value = self.next_mutex
            self.next_mutex += 4
            self.hostile_result(value)
            return
        if target in (0x466DA0, 0x466DC0):
            self.calls.append(target)
            pointer, acquiring = self.r[4], target == 0x466DA0
            self.lock_events.append((acquiring, pointer, self.r[31]))
            if self.action_worker and pointer == self.peek(self.action_worker + 0x10):
                if self.action_locked == acquiring:
                    raise AssertionError('unpaired action-queue mutex in fixture')
                self.action_locked = acquiring
            elif pointer == PAINT_LOCK:
                if self.paint_locked == acquiring:
                    raise AssertionError('unpaired paint-list mutex in fixture')
                self.paint_locked = acquiring
                if not acquiring and self.paint_getter_active and self.after_paint_unlock is not None:
                    saved, hi, lo = self.r.copy(), self.hi, self.lo
                    self.after_paint_unlock(self)
                    self.r, self.hi, self.lo = saved, hi, lo
            self.hostile_result(0)
            return
        if target in (0x466D00, 0x466CE0, 0x466DE0, 0x466C40):
            self.calls.append(target)
            self.wakes += target == 0x466D00
            self.hostile_result(0)
            return
        if target in (REGISTRY_LOCK, REGISTRY_UNLOCK):
            self.calls.append(target)
            self.hostile_result(0)
            return
        if target == 0x43A0C0:
            # Explicit name/registry fixture: no claim of retained node life.
            self.calls.append(target)
            self.hostile_result(NODE if self.registry_present else 0)
            return
        if target == 0x485DE0:
            self.calls.append(target)
            self.hostile_result(RESOURCE if self.registry_present else 0)
            return
        if target == 0xA5BEE0 and self.r[5] == RESOURCE + 0x20:
            self.calls.append(target)
            destination, original = self.r[4], self.r[5]
            data, offset = self.region(original, 64)
            raw = bytes(data[offset:offset + 64]).split(b'\0')[0] + b'\0'
            self.bytes(destination, raw)
            self.hostile_result(destination)
            return
        if target == 0x4669E0 and self.fail_next_heap:
            self.calls.append(target)
            self.fail_next_heap = False
            self.hostile_result(0)
            return
        if target == 0xA5B440:
            self.copies.append((self.r[4], self.r[5], self.r[6], self.r[31]))
        super().external(target)

    def post(self, param1=2, *, classified=True, action=1, param2=0):
        self.r[29], self.r[16] = PRODUCER_STACK, PLAYER
        if classified:
            if action != 1 or param2:
                raise AssertionError('native GENERAL source emits only (1,B+38,0)')
            self.put(PLAYER + 0x38, param1 & MASK, 4)
            self.run_at(0x42D60C, 0x42D61C)
        else:
            self.r[31], self.r[4:7] = RETURN, [action, param1 & MASK, param2]
            self.run_at(0x4BAC80, RETURN)
        self.pc = None
        return self.peek(PRODUCER_STACK - 0x40 + 0x28)

    def dispatch_actions(self):
        if not self.count(self.action_list):
            raise AssertionError('bounded worker fixture requires pending actions')
        self.r[29], self.r[31], self.r[4] = WORKER_STACK, RETURN, self.action_worker
        self.run_at(0x4BA880, 0x4BA914)
        self.run_at(0x4BA914, 0x4BA91C)  # actual queue unlock
        self.run_at(0x4BAA78, RETURN)    # explicit scheduler boundary; actual exit
        self.pc = None

    def process_paint(self):
        self.r[29], self.r[31], self.r[4] = CONSUMER_STACK, RETURN, CONTROLLER
        self.run_at(0x43C900, RETURN)
        self.pc = None
        return self.r[2]

    def count(self, pointer):
        return self.peek(pointer + 0xC)

    def element(self, pointer, index=0):
        chunk_count = self.peek(pointer + 0x14)
        stride = self.peek(pointer + 0x10)
        table = self.peek(pointer)
        chunk = self.peek(table + index // chunk_count * 4)
        return chunk + index % chunk_count * stride

    def words_at(self, address, count):
        return tuple(self.peek(address + 4 * index) for index in range(count))

    def raw_link(self):
        return self.memory(self.meta['action_link_buffer'], self.meta['action_link_memory_bytes'])

    def raw_birth(self):
        return self.memory(self.meta['birth_buffer'], self.meta['birth_memory_bytes'])


class RevealActionLinkStageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = source.SOURCE.read_bytes()
        if (hashlib.sha256(cls.source).hexdigest() != source.SOURCE_SHA256
                or len(cls.source) != source.SOURCE_SIZE):
            raise AssertionError('unrecognized native source')
        cls.image, cls.meta = stage.build(cls.source, **CAPACITIES)

    def machine(self, **overrides):
        if not overrides:
            return ActionLinkMachine(self.image, self.meta)
        image, meta = stage.build(self.source, **dict(CAPACITIES, **overrides))
        return ActionLinkMachine(image, meta)

    def report(self, m):
        return decoder.decode(m.raw_link(), birth_data=m.raw_birth(),
                              capacity=m.meta['action_link_capacity'],
                              birth_capacity=m.meta['birth_capacity'])

    def history(self, *, consume=False, rows=False, machine=None):
        m = self.machine() if machine is None else machine
        m.post()
        m.dispatch_actions()
        m.process_paint()
        if consume or rows:
            m.consume()
        if rows:
            root = m.renderer_runs[0]['lineage']
            m.row_observation = prior.RevealRendererTransportStageTests().rows_from_root(m, root)
        return m

    def test_actual_general_action_through_two_native_lists_to_actual_birth(self):
        m = self.history()
        report = self.report(m)
        self.assertEqual([event['kind'] for event in report['events']], list(range(1, 7)))
        self.assertEqual([event['parent'] for event in report['events']], [0, 1, 2, 3, 4, 5])
        self.assertEqual([event['origin'] for event in report['events']], [1] * 6)
        self.assertEqual(report['associations'][0]['birth'], 1)
        self.assertEqual(report['associations'][0]['event_sequences'], list(range(1, 7)))
        self.assertEqual(m.peek(m.action_list + 0x10), 20)
        self.assertEqual(m.peek(m.paint_list + 0x10), 36)
        self.assertEqual((m.count(m.action_list), m.count(m.paint_list)), (0, 0))
        self.assertEqual(len(m.queue()), 1)
        self.assertFalse(m.action_locked or m.paint_locked)
        for pc in (0x42D614, 0x4BAC80, 0x455DA0, 0x4BA95C, 0x490980,
                   0x43C860, 0x439900, 0x4399E8, 0x43C900, 0x459840, 0x8B4280):
            self.assertIn(pc, m.trace)

    def test_native_copy_widths_and_unchanged_constructor_capacity_requests(self):
        m = self.machine()
        self.assertEqual((m.peek(m.action_list + 8), m.peek(m.action_list + 0x14)), (20, 10))
        self.assertEqual((m.peek(m.paint_list + 8), m.peek(m.paint_list + 0x14)), (70, 10))
        m.post()
        action = m.element(m.action_list)
        self.assertEqual(m.words_at(action, 5), (1, 2, 0, 1, 1))
        m.dispatch_actions()
        paint = m.element(m.paint_list)
        self.assertIn((action, PRODUCER_STACK - 0x40 + 0x18, 20, 0x455CF0), m.copies)
        paint_frame = WORKER_STACK - 0x2050 - 0x40 - 0x40
        self.assertIn((paint, paint_frame + 0x18, 36, 0x455CF0), m.copies)
        # Native removal shifts a zero following element over the old head.
        self.assertEqual(m.words_at(action, 5), (0, 0, 0, 0, 0))
        self.assertEqual(m.words_at(paint, 9), (0, 0, NODE, 1, 16, 8, 8, 0, 4))

    def test_identical_payloads_and_reused_frames_keep_distinct_ids_through_fifo_movement(self):
        m = self.machine()
        self.assertEqual((m.post(), m.post()), (1, 2))
        head = m.element(m.action_list)
        self.assertEqual(m.words_at(head, 4), m.words_at(head + 20, 4))
        self.assertEqual((m.peek(head + 16), m.peek(head + 36)), (1, 2))
        m.dispatch_actions()
        paint = m.element(m.paint_list)
        self.assertEqual(m.words_at(paint, 8), m.words_at(paint + 36, 8))
        self.assertEqual((m.peek(paint + 32), m.peek(paint + 68)), (5, 8))
        m.process_paint()
        self.assertEqual(m.element(m.paint_list), paint)
        self.assertEqual(m.peek(paint + 32), 8)  # native remove moved all36 bytes
        m.process_paint()
        report = self.report(m)
        self.assertEqual([item['source'] for item in report['associations']], [1, 2])
        self.assertEqual([item['birth'] for item in report['associations']], [1, 4])
        deliveries = [event for event in report['events'] if event['kind'] == core.DELIVERY]
        self.assertEqual([event['record'] for event in deliveries], [head, head])
        paint_deliveries = [event for event in report['events'] if event['kind'] == core.PAINT_DELIVERY]
        self.assertEqual([event['record'] for event in paint_deliveries], [paint, paint])
        self.assertEqual([event['parent'] for event in paint_deliveries], [5, 8])
        self.assertEqual(len(m.queue()), 2)

    def test_unclassified_sender_zeroes_reused_action_explorer_and_paint_carriers(self):
        m = self.machine()
        self.assertEqual(m.post(), 1)
        m.dispatch_actions()
        self.assertEqual(m.post(classified=False), 0)
        self.assertEqual(m.peek(m.element(m.action_list) + 16), 0)
        m.dispatch_actions()
        self.assertEqual([m.peek(m.element(m.paint_list, index) + 32) for index in range(2)], [4, 0])
        m.process_paint()
        m.process_paint()
        report = self.report(m)
        self.assertEqual([item['source'] for item in report['associations']], [1])
        self.assertEqual(report['unassociated_births'], [4])
        self.assertEqual(report['counter'], 6)
        self.assertEqual(m.peek(WORKER_STACK - 0x2050 + 0x1C), 0)
        self.assertEqual(len(m.queue()), 2)  # unknown ancestry does not suppress native paint

    def test_unknown_paint_producer_initializes_tail_zero_without_using_last_parent(self):
        m = self.machine()
        m.post()
        m.dispatch_actions()
        self.assertEqual(m.peek(m.element(m.paint_list) + 32), 4)
        for index, value in enumerate((1, 16, 8, 8)):
            m.put(gap.INPUT + 4 * index, value, 4)
        m.put(PRODUCER_STACK - 0x40 + 0x38, 4, 4)
        m.stock(0x43C860, CONTROLLER, NODE, gap.INPUT, 0)
        self.assertEqual(m.peek(m.element(m.paint_list, 1) + 32), 0)
        m.process_paint()
        m.process_paint()
        report = self.report(m)
        self.assertEqual(len(report['associations']), 1)
        self.assertEqual(report['unassociated_births'], [4])

    def test_wrong_source_caller_and_null_current_controller_do_not_invent_source(self):
        m = self.machine()
        m.post(classified=False)
        m.dispatch_actions()
        m.process_paint()
        report = self.report(m)
        self.assertEqual((report['events'], report['associations']), ([], []))
        self.assertEqual(report['unassociated_births'], [1])
        other = self.machine()
        other.current_controller = 0
        wakes = other.wakes
        other.post()
        self.assertEqual(other.count(other.action_list), 0)
        self.assertEqual(other.peek(other.meta['action_link_buffer']), 0)
        self.assertEqual(other.wakes, wakes)

    def test_missing_registry_or_null_handler_retains_only_selected_delivery(self):
        for missing in ('registry', 'handler'):
            with self.subTest(missing=missing):
                m = self.machine()
                if missing == 'registry':
                    m.registry_present = False
                else:
                    m.put(RESOURCE + 0x150, 0, 4)
                m.post()
                m.dispatch_actions()
                report = self.report(m)
                self.assertEqual([event['kind'] for event in report['events']], [1, 2])
                self.assertEqual(report['associations'], [])
                self.assertEqual((m.count(m.action_list), m.count(m.paint_list)), (0, 0))
                self.assertNotIn(0x490980, m.trace)

    def test_actual_explorer_entry_can_return_without_paint_and_without_repair(self):
        m = self.machine()
        m.put(NODE + 0x50, 0, 4)
        m.post()
        m.dispatch_actions()
        report = self.report(m)
        self.assertEqual([event['kind'] for event in report['events']], [1, 2, 3])
        self.assertEqual(report['associations'], [])
        self.assertEqual(m.count(m.paint_list), 0)
        self.assertIn(0x490A2C, m.trace)
        self.assertNotIn(0x43C860, m.trace)

    def test_selected_paint_id_is_read_once_under_lock_and_not_restamped_after_unlock(self):
        m = self.machine()
        m.post()
        m.dispatch_actions()
        paint = m.element(m.paint_list)
        m.read_events.clear()
        mutations = []

        def mutate(observed):
            observed.put(paint + 32, 0xFFFFFFFF, 4)
            mutations.append((paint, observed.peek(paint + 32)))

        m.after_paint_unlock = mutate
        m.process_paint()
        report = self.report(m)
        tail_reads = [item for item in m.read_events if item[1] == paint + 32]
        self.assertEqual(len(tail_reads), 1)
        self.assertTrue(tail_reads[0][4])
        self.assertEqual(mutations, [(paint, 0xFFFFFFFF)])
        self.assertEqual(report['events'][4]['parent'], 4)
        self.assertEqual(report['associations'][0]['source'], 1)
        self.assertEqual(m.peek(paint + 32), 0)  # later native removal, not observer repair
        self.assertFalse(report['native_record_lease_proven'])
        self.assertFalse(report['native_payload_coherence_proven'])

    def test_native_metadata_change_after_unlock_faults_link_but_native_birth_continues(self):
        m = self.machine()
        m.post()
        m.dispatch_actions()
        paint = m.element(m.paint_list)
        m.after_paint_unlock = lambda observed: observed.put(paint + 0x1C, 0x12345678, 4)
        m.process_paint()
        self.assertEqual(m.peek(m.meta['action_link_buffer']), core.FAULT)
        with self.assertRaises(ValueError):
            self.report(m)
        births = birth_decoder.decode(m.raw_birth(), capacity=m.meta['birth_capacity'])
        self.assertEqual([event['metadata'] for event in births['events']], [0x12345678] * 3)
        self.assertEqual(m.queue()[0][1][1], 0x12345678)
        self.assertEqual(m.count(m.paint_list), 0)

    def test_native_engine_change_after_unlock_faults_link_but_original_call_continues(self):
        m = self.machine()
        m.post()
        m.dispatch_actions()
        paint, other_engine = m.element(m.paint_list), 0x2900000
        m.map(other_engine, 0x54)
        m.bytes(other_engine, m.memory(NODE, 0x54))
        m.extra_engines.add(other_engine)
        m.after_paint_unlock = lambda observed: observed.put(paint + 8, other_engine, 4)
        m.process_paint()
        self.assertEqual(m.peek(m.meta['action_link_buffer']), core.FAULT)
        births = birth_decoder.decode(m.raw_birth(), capacity=m.meta['birth_capacity'])
        self.assertEqual([event['engine'] for event in births['events']], [other_engine] * 3)
        self.assertNotEqual(m.peek(other_engine + 0x34), 0)
        self.assertEqual(m.queue(), [])
        self.assertEqual(m.count(m.paint_list), 0)

    def test_zero_selected_ids_do_not_fall_back_to_matching_payload_or_addresses(self):
        for which in ('action', 'paint'):
            with self.subTest(which=which):
                m = self.machine()
                m.post()
                if which == 'action':
                    m.put(m.element(m.action_list) + 16, 0, 4)
                m.dispatch_actions()
                if which == 'paint':
                    m.put(m.element(m.paint_list) + 32, 0, 4)
                m.process_paint()
                report = self.report(m)
                self.assertEqual(report['associations'], [])
                self.assertEqual(report['unassociated_births'], [1])
                self.assertEqual(len(m.queue()), 1)
                expected = [1] if which == 'action' else [1, 2, 3, 4]
                self.assertEqual([event['kind'] for event in report['events']], expected)

    def test_nonconsumer_getter_caller_does_not_read_tail_or_write_callers_sp18(self):
        m = self.machine()
        m.post()
        m.dispatch_actions()
        paint = m.element(m.paint_list)
        m.put(PRODUCER_STACK + 0x18, 0xBADC0DE, 4)
        m.read_events.clear()
        self.assertEqual(m.stock(0x4399C0, CONTROLLER), paint)
        self.assertEqual(m.peek(PRODUCER_STACK + 0x18), 0xBADC0DE)
        self.assertFalse(any(address == paint + 32 for _, address, _, _, _ in m.read_events))
        self.assertEqual(self.report(m)['counter'], 4)
        m.process_paint()
        self.assertEqual(len(self.report(m)['associations']), 1)

    def test_other_redraw_wrapper_caller_has_native_birth_without_link_repair(self):
        m = self.history()
        for index, value in enumerate((1, 16, 8, 8)):
            m.put(gap.INPUT + index * 4, value, 4)
        # Current native RA=45987C passes, but saved wrapper RA is RETURN,
        # not43C970. A valid historical parent elsewhere must not repair it.
        m.put(PRODUCER_STACK + 0x18, 5, 4)
        m.stock(0x459840, NODE, gap.INPUT, 0)
        report = self.report(m)
        self.assertEqual(len(report['associations']), 1)
        self.assertEqual(report['unassociated_births'], [4])
        self.assertEqual(len(m.queue()), 2)

    def test_full_faulted_or_retry_exhausted_diagnostics_never_suppress_native_paths(self):
        for failure in ('full', 'fault', 'retry'):
            with self.subTest(failure=failure):
                m = self.machine(action_link_capacity=4)
                if failure == 'fault':
                    m.put(m.meta['action_link_buffer'], core.FAULT, 4)
                elif failure == 'retry':
                    m.sc_failures = 8
                m.post()
                m.dispatch_actions()
                if failure == 'full':
                    self.assertEqual(m.peek(m.meta['action_link_buffer']), 4)
                m.process_paint()
                self.assertEqual(m.peek(m.meta['action_link_buffer']), core.FAULT)
                self.assertEqual((m.count(m.action_list), m.count(m.paint_list)), (0, 0))
                self.assertEqual(len(m.queue()), 1)
                self.assertEqual(m.quad(m.queue()[0][1][0]), (1, 16, 8, 8))
                self.assertFalse(m.action_locked or m.paint_locked)
                self.assertEqual(len(birth_decoder.decode(m.raw_birth(),
                    capacity=m.meta['birth_capacity'])['events']), 3)

    def test_real_segmented_action_growth_failure_keeps_native_unlock_and_wake(self):
        m = self.machine()
        for _ in range(20):
            m.post(classified=False)
        self.assertEqual(m.count(m.action_list), 20)
        wakes = m.wakes
        m.fail_next_heap = True
        m.post()
        self.assertFalse(m.fail_next_heap)
        self.assertEqual(m.count(m.action_list), 20)
        self.assertEqual(m.wakes, wakes + 1)
        self.assertFalse(m.action_locked)
        self.assertIn(0x455D94, m.trace)  # actual native append failure return
        report = self.report(m)
        self.assertEqual([event['kind'] for event in report['events']], [core.SOURCE])
        self.assertEqual(report['unassociated_sources'], [1])

    def test_native_copy_allocation_failure_observes_birth_not_successful_enqueue(self):
        m = self.machine()
        m.post()
        m.dispatch_actions()
        m.fail_allocation = 1
        m.process_paint()
        report = self.report(m)
        self.assertEqual(report['associations'][0]['birth'], 1)
        births = birth_decoder.decode(m.raw_birth(), capacity=m.meta['birth_capacity'])
        self.assertEqual([event['kind'] for event in births['events']], [1])
        self.assertFalse(births['requests'][0]['observed_enqueue_sequence_complete'])
        self.assertEqual(m.queue(), [])
        self.assertEqual(m.count(m.paint_list), 0)

    def test_source_explorer_paint_and_getter_hooks_preserve_native_abi(self):
        m = self.machine()
        saved, checked = {}, set()
        pairs = {0x4BACBC: (0x4BACC4, 'source'), 0x4909A4: (0x4909AC, 'explorer'),
                 0x43C868: (0x43C870, 'paint'), 0x4399E8: (0x4399F0, 'getter')}

        def observe(pc):
            if pc in pairs:
                saved[pairs[pc][1]] = (m.r.copy(), m.hi, m.lo)
            for entry, (resume, name) in pairs.items():
                if pc != resume:
                    continue
                before, hi, lo = saved[name]
                expected = before.copy()
                if name == 'source':
                    expected[4], expected[2] = m.action_list, 1
                elif name in ('explorer', 'paint'):
                    expected[29] -= 0x40
                    self.assertEqual(m.peek(expected[29] + 0x3C), before[31])
                else:
                    expected[25], expected[4] = 0x437D60, CONTROLLER
                self.assertEqual((m.r, m.hi, m.lo), (expected, hi, lo), name)
                checked.add(name)

        m.on_instruction = observe
        m.post()
        m.dispatch_actions()
        m.process_paint()
        self.assertEqual(checked, {'source', 'explorer', 'paint', 'getter'})
        entries = {pc: (ra, args) for pc, ra, _, args in m.native_entries}
        self.assertEqual(entries[0x490980][0], 0x4BAA68)
        self.assertEqual(entries[0x43C860][0], 0x490A10)
        self.assertEqual(entries[0x4399C0][0], 0x43C918)
        self.assertEqual(entries[0x459840][0], 0x43C970)
        self.assertEqual(entries[0x8B4280][0], 0x45987C)
        self.assertEqual(entries[0x8B3CC0][0], 0x8B42F0)
        self.assertEqual(m.r[29], CONSUMER_STACK)

    def test_birth_private_posthelper_preserves_old_birth_id_and_native_prologue(self):
        m = self.machine()
        saved, observed = {}, []

        def observe(pc):
            if pc == 0x8B428C:
                saved['registers'], saved['hi'], saved['lo'] = m.r.copy(), m.hi, m.lo
            elif pc == 0x8B4294:
                expected = saved['registers'].copy()
                expected[29] -= 0x40
                self.assertEqual((m.r, m.hi, m.lo), (expected, saved['hi'], saved['lo']))
                self.assertEqual(m.peek(m.r[29] + 0x14), 1)  # old BIRTH ID, NOT LALI6
                self.assertEqual(m.peek(m.r[29] + 0x64), 0x43C970)
                self.assertEqual(m.peek(m.r[29] + 0x80), 5)
                observed.append(m.r[31])
            elif pc == 0x8B4298:
                self.assertEqual(m.peek(m.r[29] + 0x3C), 0x45987C)

        m.on_instruction = observe
        m.post()
        m.dispatch_actions()
        m.process_paint()
        self.assertEqual(observed, [0x45987C])
        self.assertEqual(self.report(m)['events'][-1]['seq'], 6)

    def test_historical_chain_never_grants_authority_and_can_feed_old_renderer_fixture(self):
        m = self.history(consume=True)
        report = self.report(m)
        self.assertEqual(len(m.renderer_runs), 1)
        self.assertEqual(m.queue(), [])
        for target in (report, report['associations'][0]):
            self.assertEqual(target['decision'], 'deny')
            for name in decoder.AUTHORITY_FLAGS:
                self.assertIs(target[name], False)
            for name in ('native_record_lease_proven', 'native_payload_coherence_proven',
                         'source_playback_identity_proven', 'universal_playback_coverage_proven'):
                self.assertIs(target[name], False)

    def test_actual_birth_continues_through_existing_renderer_root_and_row_fixture(self):
        m = self.history(rows=True)
        report = self.report(m)
        prefix = (m.meta['renderer_transport_buffer'] + m.meta['renderer_transport_memory_bytes']
                  - m.meta['buffer'])
        old = prior.decoder.decode(m.memory(m.meta['buffer'], prefix),
                                   **{key: m.meta[key] for key in prior.CAPACITIES})
        row = old['renderer_row_associations'][0]
        association = report['associations'][0]
        self.assertEqual((association['birth'], row['birth']), (1, 1))
        self.assertEqual((row['renderer'], row['lineage'], row['producers'],
                          row['row_event_sequences']), (2, 1, [4], [1]))
        self.assertEqual(m.row_observation['producer'], 4)
        self.assertTrue(row['observed_row_identity_associated'])
        # New historical notification ancestry never repairs the predecessor's
        # original known-boundary rejection or any row/UI-authority flag.
        renderer = old['renderer_transport_observation']['associations'][0]
        self.assertFalse(renderer['known_boundary_unchanged'])
        self.assertIn('known-boundary-unchanged-not-observed', renderer['reasons'])
        for name in decoder.AUTHORITY_FLAGS:
            self.assertIs(row[name], False)
            self.assertIs(report[name], False)
        combined = combined_decoder.decode(m.memory(m.meta['buffer'], m.meta['memory_bytes']),
                                            **{key: m.meta[key] for key in CAPACITIES})
        self.assertEqual(len(combined['notification_renderer_associations']), 1)
        linked = combined['notification_renderer_associations'][0]
        self.assertEqual((linked['birth'], linked['renderer'], linked['lineage'],
                          linked['producers'], linked['row_event_sequences']),
                         (1, 2, 1, [4], [1]))
        self.assertTrue(linked['historical_notification_renderer_associated'])
        self.assertIn('known-boundary-unchanged-not-observed', linked['renderer_reasons'])
        original_renderer = combined['renderer_transport_observation']['associations'][0]
        self.assertFalse(original_renderer['known_boundary_unchanged'])
        self.assertEqual(original_renderer, renderer)
        self.assertEqual(combined['renderer_row_associations'], old['renderer_row_associations'])
        for target in (combined, linked, combined['action_link_observation']):
            for name in decoder.AUTHORITY_FLAGS:
                self.assertIs(target[name], False)
        for name in ('native_record_lease_proven', 'native_payload_coherence_proven',
                     'source_playback_identity_proven', 'universal_playback_coverage_proven'):
            self.assertIs(linked[name], False)


if __name__ == '__main__':
    unittest.main()
