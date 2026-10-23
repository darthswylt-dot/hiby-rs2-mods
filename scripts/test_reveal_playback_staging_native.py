#!/usr/bin/env python3
"""Execute original staged-selection/event-9 instructions without firmware edits.

Actual pinned ELF instructions execute the segmented-list constructor/append/
index/count/clear, 428B40/42B180 producers, the 8-byte native event queue, and
the worker's event-9 dispatch/selection/copy/clear/call boundaries. The final
42CC60 consumer is opaque: these tests do not execute decoder setup or claim
playback completion, coherent identity, causal UI linkage or live ownership.
In particular, the opaque consumer does NOT execute the original queue flush
at 42CD6C -> 450720. Repeated-dequeue tests are conditional on pending messages
surviving that stub; they do not predict a complete original player sequence.

Allocator/free, memcpy/memset, mutex, thread naming, one readiness gate and two
string helpers are explicit bounded hostile-ABI stubs. An injected producer
between two mutex brackets is a deterministic instruction-boundary schedule,
not an OS scheduler or proof that a hardware race occurs. Freed fixture
storage stays mapped. No device, network, firmware output or source changes.
"""

import hashlib
import struct
import unittest

import test_folderfollow_reveal_static_contract as reference
import test_reveal_lineage_stage as native_harness


PLAYER, ITEM_BYTES, ELEMENT_BYTES = 0xADD368, 0xA88, 0xA90
LOCK, LIFETIME_LOCK, STARTUP_LOCK = 0xBAD00010, 0xBAD00020, 0xBAD00030
CONTEXT = 0xBAD00040
SOURCE_BASE = 0x1800000
STACK, RETURN = native_harness.STACK, native_harness.RETURN
PRODUCER_STACK, WORKER_STACK_TOP = STACK - 0x1000, STACK + 0x2000
WORKER_FRAME = WORKER_STACK_TOP - 0xAE0
MESSAGE_BYTES, QUEUE_REQUEST_CAPACITY = 8, 8
APPEND, CLEAR, INDEX, COUNT = 0x455DA0, 0x4557C0, 0x4557E0, 0x455DC0


class StagingMachine(native_harness.LineageMachine):
    """Fetch native bytes unchanged; reuse ISA helpers, not a firmware builder."""

    def __init__(self, image):
        super().__init__(image, dict(code_base=0xC70000, code_offset=len(image),
                                     buffer=0xBD4000, memory_bytes=16, labels={}))
        self.map(PLAYER, 0x1E68)
        self.map(SOURCE_BASE, 0x4000)
        self.map(0x921000, 0x1000)
        self.bytes(0x921000, image[0x921000 - 0x400000:0x922000 - 0x400000])
        self.trace, self.lock_events, self.copy_events, self.commits = [], [], [], []
        self.staging_locked = False
        self.on_instruction = None
        self.before_instruction = self.observe_instruction
        self.r[29] = PRODUCER_STACK
        self.list_pointer = self.stock(0x456E60, 16, ELEMENT_BYTES)
        self.queue_pointer = self.stock(0x450460, QUEUE_REQUEST_CAPACITY)
        for offset, value in ((0, self.queue_pointer), (0xBB0, self.list_pointer),
                              (0xBB4, LOCK), (0xC, LIFETIME_LOCK),
                              (8, STARTUP_LOCK), (0xBA4, CONTEXT)):
            self.put(PLAYER + offset, value, 4)

    def observe_instruction(self, pc):
        self.trace.append(pc)
        if self.on_instruction is not None:
            self.on_instruction(pc)

    def external(self, target):
        # Internal native list methods 4557C0..455DBF are already fetched by
        # the inherited interpreter. COUNT lies just beyond that interval.
        if target in (0x428B40, 0x42B140, 0x4504E0, 0x450600, COUNT):
            self.calls.append(target)
            self.run_at(target, self.r[31])
            return
        if target == 0xA5B440:
            self.copy_events.append((self.r[4], self.r[5], self.r[6], self.r[31]))
        if target in (0x466DA0, 0x466DC0):
            self.calls.append(target)
            pointer = self.r[4]
            if pointer not in (LOCK, LIFETIME_LOCK, STARTUP_LOCK):
                raise AssertionError('unexpected mutex scalar ' + hex(pointer))
            acquiring = target == 0x466DA0
            self.lock_events.append(('lock' if acquiring else 'unlock', pointer, self.r[31]))
            if pointer == LOCK:
                if self.staging_locked == acquiring:
                    raise AssertionError('fixture staged lock pairing failure')
                self.staging_locked = acquiring
            self.hostile_result(0)
            return
        if target in (0x466C40, 0x423980, 0x41FE00, 0x41FCE0):
            self.calls.append(target)
            # Do not inspect borrowed strings or call any actual scheduler.
            # A nonzero comparison selects the direct event-9 post in B180;
            # readiness is true so event-9 reaches its opaque consumer call.
            result = 1 if target in (0x423980, 0x41FCE0) else 0
            self.hostile_result(result)
            return
        if target == 0x42CC60:
            self.calls.append(target)
            if self.r[4] != CONTEXT:
                raise AssertionError('wrong native context passed to general consumer')
            self.commits.append(dict(context=self.r[4], source=self.r[5],
                                     transition=self.r[6], data=self.memory(self.r[5], ITEM_BYTES),
                                     return_pc=self.r[31], frame=self.r[29],
                                     staged_count=self.count()))
            self.hostile_result(0)
            return
        super().external(target)

    def memory(self, address, size):
        data, offset = self.region(address, size)
        return bytes(data[offset:offset + size])

    def source(self, number):
        pointer = SOURCE_BASE + (number - 1) * 0x1000
        data = bytes([number]) * ITEM_BYTES
        self.bytes(pointer, data)
        return pointer, data

    def stage_selection(self, pointer, transition):
        self.r[29], self.r[31] = PRODUCER_STACK, RETURN
        self.r[4:6] = [pointer, transition]
        self.run_at(0x428B40, RETURN)

    def post_selection(self, pointer, transition):
        self.r[29], self.r[31] = PRODUCER_STACK, RETURN
        self.r[4:7] = [CONTEXT, pointer, transition]
        self.run_at(0x42B180, RETURN)

    def post_event9(self):
        self.r[29], self.r[31] = PRODUCER_STACK, RETURN
        self.r[4:6] = [9, 0]
        self.run_at(0x42B140, RETURN)

    def count(self):
        return self.get(self.list_pointer + 0xC, 4)

    def element(self, index):
        # Only test inspection of the already-created native segmented list.
        # No pointer address becomes a causal ID or survives as a live lease.
        chunk_count = self.get(self.list_pointer + 0x14, 4)
        table = self.get(self.list_pointer, 4)
        chunk = self.get(table + (index // chunk_count) * 4, 4)
        return chunk + (index % chunk_count) * ELEMENT_BYTES

    def messages(self):
        queue = self.queue_pointer
        capacity = self.get(queue, 4)
        head, tail = self.get(queue + 4, 4), self.get(queue + 8, 4)
        result = []
        for _ in range(capacity):
            if head == tail:
                return result
            pointer = self.get(queue + 16 + head * 4, 4)
            result.append((pointer, self.memory(pointer, MESSAGE_BYTES)))
            head = (head + 1) % capacity
        raise AssertionError('unexpected native fixture ring state')

    def event9(self):
        if not self.messages():
            raise AssertionError('fixture requires a pending native event')
        self.r[29], self.r[31] = WORKER_STACK_TOP, RETURN
        # Actual worker prologue, startup, dequeue, dispatch table and event9
        # execute. Stop at the original loop-back before stock sleeps/retries.
        self.run_at(0x42E1E0, 0x42E434)
        self.run_at(0x42E2BC, RETURN)  # actual lifetime unlock and epilogue
        if self.r[29] != WORKER_STACK_TOP:
            raise AssertionError('native worker frame did not unwind')


class RevealPlaybackStagingNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = reference.SOURCE.read_bytes()
        digest = hashlib.sha256(cls.source).hexdigest()
        if digest != reference.SOURCE_SHA256 or len(cls.source) != reference.SOURCE_SIZE:
            raise AssertionError('unrecognized original reference ' + digest)

    def machine(self):
        return StagingMachine(self.source)

    def test_actual_constructor_installs_the_methods_executed_by_native_producer_and_worker(self):
        machine = self.machine()
        self.assertEqual({offset: machine.get(machine.list_pointer + offset, 4)
                          for offset in (0x18, 0x24, 0x2C, 0x30)},
                         {0x18: APPEND, 0x24: CLEAR, 0x2C: INDEX, 0x30: COUNT})
        self.assertEqual(machine.get(machine.list_pointer + 0x10, 4), ELEMENT_BYTES)
        self.assertEqual(machine.get(machine.list_pointer + 0x14, 4), 10)
        self.assertEqual(machine.get(machine.list_pointer + 8, 4), 20)
        self.assertNotEqual(machine.get(machine.list_pointer + 8, 4), 16)
        self.assertEqual(machine.count(), 0)
        self.assertEqual(machine.get(machine.queue_pointer, 4), QUEUE_REQUEST_CAPACITY)
        self.assertEqual(machine.code, b'')  # No emitted diagnostic/firmware stage.

    def test_428b40_executes_original_append_with_copied_a88_and_occupied_transition_tail(self):
        machine = self.machine()
        pointer, original = machine.source(1)
        machine.trace.clear()
        machine.stage_selection(pointer, 0x12345678)
        self.assertEqual(machine.count(), 1)
        element = machine.element(0)
        self.assertEqual(machine.memory(element, ITEM_BYTES), original)
        self.assertEqual(machine.get(element + ITEM_BYTES, 4), 0x12345678)
        for pc in (0x428B40, APPEND, 0x455BC0, 0x455CE8):
            self.assertIn(pc, machine.trace)
        self.assertIn((PRODUCER_STACK - 0xAC0 + 0x18, pointer, ITEM_BYTES, 0x428B90),
                      machine.copy_events)
        self.assertTrue(any(destination == element and size == ELEMENT_BYTES
                            for destination, _, size, _ in machine.copy_events))
        self.assertFalse(machine.staging_locked)

    def test_mutating_original_after_append_does_not_change_the_already_copied_record(self):
        machine = self.machine()
        pointer, original = machine.source(1)
        machine.stage_selection(pointer, 7)
        machine.bytes(pointer, bytes([0xFF]) * ITEM_BYTES)
        self.assertEqual(machine.memory(machine.element(0), ITEM_BYTES), original)
        # This only checks copy direction/lifetime in this sequential fixture,
        # not coherence of arbitrary original inputs under another writer.

    def test_two_native_event9_messages_are_exactly_identical_eight_bytes_without_item_identity(self):
        machine = self.machine()
        first, _ = machine.source(1)
        second, _ = machine.source(2)
        machine.post_selection(first, 0x1111)
        machine.post_selection(second, 0x2222)
        self.assertEqual(machine.count(), 2)
        messages = machine.messages()
        self.assertEqual([payload for _, payload in messages], [struct.pack('<2I', 9, 0)] * 2)
        for pointer, _ in messages:
            self.assertEqual(machine.get(pointer - 4, 4), MESSAGE_BYTES)
        self.assertEqual(machine.get(machine.element(0) + ITEM_BYTES, 4), 0x1111)
        self.assertEqual(machine.get(machine.element(1) + ITEM_BYTES, 4), 0x2222)
        self.assertEqual(machine.trace.count(0x42B140), 2)  # native tail J, not JAL
        self.assertEqual(machine.calls.count(0x4504E0), 2)

    def test_first_event9_selects_last_b_and_clears_both_a_and_b_instead_of_fifo_pairing(self):
        machine = self.machine()
        first, _ = machine.source(1)
        second, expected = machine.source(2)
        machine.post_selection(first, 0x1111)
        machine.post_selection(second, 0x2222)
        message_pointer = machine.messages()[0][0]
        machine.trace.clear()
        machine.event9()
        self.assertEqual(len(machine.commits), 1)
        selected = machine.commits[0]
        self.assertEqual(selected['data'], expected)
        self.assertEqual(selected['transition'], 0x2222)
        self.assertEqual(selected['source'], WORKER_FRAME + 0x18)
        self.assertEqual(selected['return_pc'], 0x42E434)
        self.assertEqual(selected['staged_count'], 0)
        self.assertEqual(machine.count(), 0)
        self.assertEqual(len(machine.messages()), 1)
        self.assertIn(message_pointer, machine.freed)
        for pc in (0x42E270, 0x450600, 0x42E3A8, COUNT, 0x42E7E8,
                   INDEX, 0x42E804, 0x42E80C, CLEAR, 0x42E42C):
            self.assertIn(pc, machine.trace)
        self.assertEqual(machine.r[29], WORKER_STACK_TOP)

    def test_second_event_retained_by_opaque_consumer_supplies_zero_item_not_b_again(self):
        machine = self.machine()
        first, _ = machine.source(1)
        second, expected = machine.source(2)
        machine.post_selection(first, 0x1111)
        machine.post_selection(second, 0x2222)
        messages = [pointer for pointer, _ in machine.messages()]
        machine.event9()
        machine.trace.clear()
        # The CC60 stub leaves the second message pending. The full original
        # consumer can flush it at42CD6C; this next dequeue is deliberately a
        # conditional fixture path, not a claim it occurs after real playback.
        machine.event9()
        self.assertEqual([item['data'] for item in machine.commits], [expected, bytes(ITEM_BYTES)])
        self.assertEqual([item['transition'] for item in machine.commits], [0x2222, 0])
        self.assertNotIn(INDEX, machine.trace)
        self.assertNotIn(0x42E804, machine.trace)
        self.assertEqual(machine.messages(), [])
        self.assertTrue(set(messages).issubset(machine.freed))
        # Reaching the mocked CC60 with zero bytes is not a playback clear or
        # success claim: that actual callee is outside the execution boundary.

    def test_c_appended_between_copy_unlock_and_clear_is_discarded_without_replacing_selected_b(self):
        machine = self.machine()
        first, _ = machine.source(1)
        second, expected = machine.source(2)
        third, third_data = machine.source(3)
        machine.post_selection(first, 0x1111)
        machine.post_selection(second, 0x2222)
        observed = []

        def between_brackets(pc):
            if pc == 0x42E3EC and not observed:
                self.assertFalse(machine.staging_locked)
                observed.append(machine.count())
                saved, hi, lo = machine.r.copy(), machine.hi, machine.lo
                machine.post_selection(third, 0x3333)
                observed.append(machine.count())
                self.assertEqual(machine.memory(machine.element(2), ITEM_BYTES), third_data)
                machine.r, machine.hi, machine.lo = saved, hi, lo

        machine.on_instruction = between_brackets
        machine.event9()
        self.assertEqual(observed, [2, 3])
        self.assertEqual(machine.commits[0]['data'], expected)
        self.assertEqual(machine.commits[0]['transition'], 0x2222)
        self.assertEqual(machine.count(), 0)
        self.assertEqual(len(machine.messages()), 2)
        # These survive only because the opaque CC60 stub omits its native
        # queue flush. They exercise empty selection, not whole-player timing.
        machine.event9()
        machine.event9()
        self.assertEqual([item['data'] for item in machine.commits],
                         [expected, bytes(ITEM_BYTES), bytes(ITEM_BYTES)])
        self.assertEqual([item['transition'] for item in machine.commits], [0x2222, 0, 0])
        self.assertEqual(machine.messages(), [])

    def test_mutex_trace_confirms_separate_selection_and_clear_brackets(self):
        machine = self.machine()
        pointer, _ = machine.source(1)
        machine.post_selection(pointer, 5)
        machine.lock_events.clear()
        machine.event9()
        staging = [item for item in machine.lock_events if item[1] == LOCK]
        self.assertEqual(staging, [('lock', LOCK, 0x42E3C4), ('unlock', LOCK, 0x42E3EC),
                                   ('lock', LOCK, 0x42E3F8), ('unlock', LOCK, 0x42E414)])
        self.assertFalse(machine.staging_locked)

    def test_empty_staged_list_event9_has_no_element_transition_or_tail_read(self):
        machine = self.machine()
        machine.post_event9()
        old_element = machine.element(0)
        old_transition_and_tail = (old_element + ITEM_BYTES, old_element + ITEM_BYTES + 4)
        machine.trace.clear()
        machine.reads.clear()
        machine.event9()
        self.assertEqual(machine.count(), 0)
        self.assertEqual(machine.commits[0]['data'], bytes(ITEM_BYTES))
        self.assertEqual(machine.commits[0]['transition'], 0)
        self.assertNotIn(INDEX, machine.trace)
        self.assertNotIn(0x42E80C, machine.trace)
        self.assertFalse(any(address in old_transition_and_tail for address, _ in machine.reads))
        self.assertIn(CLEAR, machine.trace)

    def test_null_producer_source_still_posts_event9_without_an_item_append(self):
        machine = self.machine()
        machine.trace.clear()
        machine.post_selection(0, 0x1234)
        self.assertEqual(machine.count(), 0)
        self.assertNotIn(APPEND, machine.trace)
        self.assertEqual([payload for _, payload in machine.messages()], [struct.pack('<2I', 9, 0)])
        machine.event9()
        self.assertEqual(machine.commits[0]['data'], bytes(ITEM_BYTES))
        self.assertEqual(machine.commits[0]['transition'], 0)

    def test_null_staged_list_is_skipped_but_event9_and_opaque_call_remain_native(self):
        machine = self.machine()
        pointer, _ = machine.source(1)
        machine.put(PLAYER + 0xBB0, 0, 4)
        machine.trace.clear()
        machine.post_selection(pointer, 3)
        self.assertNotIn(APPEND, machine.trace)
        machine.event9()
        self.assertNotIn(COUNT, machine.trace)
        self.assertNotIn(INDEX, machine.trace)
        self.assertNotIn(CLEAR, machine.trace)
        self.assertEqual(machine.commits[0]['data'], bytes(ITEM_BYTES))
        self.assertEqual(machine.commits[0]['transition'], 0)

    def test_original_entry_and_worker_epilogue_preserve_callee_saved_registers(self):
        machine = self.machine()
        pointer, _ = machine.source(1)
        before = machine.r.copy()
        machine.post_selection(pointer, 0x4444)
        for register in (*range(16, 24), 26, 27, 28, 30):
            self.assertEqual(machine.r[register], before[register], register)
        self.assertEqual(machine.r[29], PRODUCER_STACK)
        before = machine.r.copy()
        machine.event9()
        for register in (*range(16, 24), 26, 27, 28, 30):
            self.assertEqual(machine.r[register], before[register], register)
        self.assertEqual(machine.r[29], WORKER_STACK_TOP)
        self.assertEqual(machine.r[31], RETURN)


if __name__ == '__main__':
    unittest.main()
