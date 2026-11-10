#!/usr/bin/env python3
"""Trace a queued data_dealing context through the checked completion route."""

import struct
import unittest

import factory_null_audit as audit
from mips_static_trace import sx16
from test_factory_d180_allocation_continuations import FACTORY, AllocationContinuationMachine
from test_factory_null_audit import (
    ALLOCATION, ALLOCATOR, CONFIGURATOR, CONTEXT, FREE, HANDLE, MASK, RETURN, STACK, LineageMachine,
)


OLD_DIALOG, OPERATION, WORKER = CONTEXT + 0x100, 0x1D08000, 0x1D09000
PRODUCER, POST, QUEUE_WRITE = 0x4AEF08, 0x474380, 0x4504E0
WORKER_COPY, COPY_BYTES = 0x48F220, 0xA5B440
CALLBACK, COMPLETION = 0x453320, 0x450D60
EVENT_TABLE, EVENT_ENTRY = 0x926B94, 0x926D2C
EVENT = 0x138
DESCRIPTOR = b'\xA5' * 0xA88
POLL, CLOSE, DIALOG_FINISH, OLD_CALLBACK = 0x47CC20, 0x47CF80, 0x47C740, 0x4AEC60
DIALOG_LIST, QUEUE_RECORD, QUEUE = 0x1D0A000, 0x1D0B000, 0x1D0B100
WAIT_MUTEX, FINISH_MUTEX = ALLOCATION + 0x20, ALLOCATION + 0x40
OLD_NAME = 0x946144
QUEUE_BUILD, QUEUE_READ, QUEUE_DESTROY = 0x450460, 0x450600, 0x4507E0
APP_QUEUE = 0xB89C68
MAIN_DISPATCH, OTHER_DISPATCH, OTHER_EVENT_TABLE = 0x454200, 0x4542C0, 0x926F94
WORKER_READERS = (
    # Thread entry, continuation after dequeue, queue global, record frame offset.
    (0x42E1E0, 0x42E288, 0xADD368, 0xAA8),
    (0x454380, 0x454418, 0xB89250, 0x828),
)
APP_LOOP, CONTROLLER_LOOP, SELECT_ACTIVITY = 0x474800, 0x43CFE0, 0x43CE40
REQUEST_EXIT, CLOSE_DIALOG, TIMER_PUMP = 0x43CD20, 0x47D060, 0x473560
CURRENT_CONTROLLER, NEXT_CONTROLLER, CONTROLLER_REGISTRY = 0xADF208, 0xADF20C, 0xA90F98
MUSIC, CHARGE, CLOSE_NODE = 0x1D0C000, 0x1D0C300, 0x1D0C600
CHARGE_ACTIVITY = 0x922730
DATA_DEALING_NAME, FIND_DIALOG = 0x9267C0, 0x47CA40
SECOND_OPERATION, SECOND_RECORD = 0x1D0D000, QUEUE_RECORD + 0x40


class DataDealingMachine(AllocationContinuationMachine):
    def __init__(self, image, *, supplied_early_return=False, **options):
        super().__init__(image, **options)
        self.supplied_early_return = supplied_early_return
        self.frees = []
        self.map(OPERATION, 0xCF0)
        self.bytes(OPERATION + 0x50, DESCRIPTOR)
        self.map(WORKER, 0xC00)
        self.put(WORKER + 0x10, ALLOCATION, 4)
        self.put(WORKER + 0x14, ALLOCATION + 0x10, 4)
        self.put(CONTEXT + 0x30, WORKER, 4)
        self.put(OLD_DIALOG + 0x48, CONTEXT, 4)
        self.put(OLD_DIALOG + 0x58, OPERATION, 4)
        self.put(APP_QUEUE, CONTEXT, 4)
        self.put(HANDLE + 0x10, ALLOCATION, 4)
        self.put(HANDLE + 0x58, 0, 4)  # Completion's native direct-free branch.
        self.map(0x938C94, 4)
        self.put(0x938C94, image.word(0x938C94), 4)
        table_size = EVENT_ENTRY + 8 - EVENT_TABLE
        self.map(EVENT_TABLE, table_size)
        offset = image.va_to_off(EVENT_TABLE)
        self.bytes(EVENT_TABLE, image.data[offset:offset + table_size])

    def external(self, target):
        if target in (POST, WORKER_COPY, COMPLETION):
            self.calls.append(target)
            self.run_at(target, self.r[31])
            if target == POST:
                self.post_status = self.r[2]
        elif target == QUEUE_WRITE:
            self.calls.append(target)
            queue, record, size = self.r[4:7]
            if queue != CONTEXT or size != 20:
                raise AssertionError('unexpected queued event arguments')
            data, offset = self.region(record, size)
            self.record = bytes(data[offset:offset + size])
            self.hostile_result(0)
        elif target in (0x466960, 0x466D00):
            self.calls.append(target)
            self.hostile_result(0)
        elif target == COPY_BYTES:
            self.copy_args = tuple(self.r[4:7])
            LineageMachine.external(self, target)
        elif target == CALLBACK:
            self.calls.append(target)
            return_pc = self.r[31]
            if self.supplied_early_return:
                self.run_at(target, 0x453374)
                if self.r[2] != 0:
                    raise AssertionError('expected a zero factory result at the supplied cut')
                self.run_at(0x453388, return_pc)
            else:
                self.run_at(target, return_pc)
        elif target == FACTORY and self.factory_result:
            # Supply the new dialog and execute its actual descriptor stores.
            saved_s2 = self.r[18]
            self.r[3], self.r[18] = self.factory_result, self.get(self.r[29] + 0x10, 4)
            self.run_at(0x47D24C, 0x47D264)
            self.r[18] = saved_s2
            super().external(target)
        elif target == FREE:
            self.calls.append(target)
            self.frees.append(self.r[4])
            self.hostile_result(0)
        else:
            super().external(target)

    def post_operation(self):
        self.seed_frame(5312, 5)
        self.r[16] = OLD_DIALOG
        self.run_at(0x4AECA8, 0x4AECC0)
        # The intervening view and path checks select the event-producing tail.
        self.run_at(PRODUCER, RETURN)

    def dispatch(self):
        self.seed_frame(64, 2)
        self.bytes(self.r[29] + 0x18, self.record)
        self.r[2], self.r[17] = 0, CONTEXT
        self.run_at(0x454254, RETURN)


class NativeDataDealingOwnershipTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = audit.source_image()

    def test_producer_posts_the_context_then_copies_from_it_before_return(self):
        machine = DataDealingMachine(self.image)
        machine.post_operation()

        self.assertEqual(struct.unpack('<5I', machine.record), (0, EVENT, OPERATION, 0, 0))
        self.assertLess(machine.calls.index(QUEUE_WRITE), machine.calls.index(COPY_BYTES))
        self.assertEqual(machine.copy_args, (WORKER + 0x140, OPERATION + 0x50, len(DESCRIPTOR)))
        data, offset = machine.region(WORKER + 0x140, len(DESCRIPTOR))
        self.assertEqual(data[offset:offset + len(DESCRIPTOR)], DESCRIPTOR)
        self.assertEqual(machine.get(WORKER + 0x120, 4), 2)
        self.assertEqual(machine.get(OLD_DIALOG + 0x58, 4), OPERATION)
        self.assertEqual(machine.frees, [])
        self.assertEqual((machine.r[29], machine.r[31]), (STACK, RETURN))

    def test_successful_dispatch_attaches_the_context_and_completion_frees_it(self):
        machine = DataDealingMachine(self.image, factory_result=HANDLE)
        machine.post_operation()
        machine.dispatch()

        self.assertEqual((machine.r[2], machine.r[29], machine.r[31]), (0, STACK, RETURN))
        self.assertEqual(machine.config_inputs, (HANDLE, HANDLE, 4))
        self.assertEqual(machine.get(HANDLE + 0x50, 4), OPERATION)
        self.assertEqual(machine.get(HANDLE + 0x5C, 4), 1)
        self.assertEqual(machine.get(HANDLE + 0x74, 4), COMPLETION)
        self.assertEqual(machine.frees, [])

        machine.r[16] = HANDLE
        machine.run_at(0x47C7B8, 0x47C7D0)
        self.assertEqual(machine.calls[-2:], [COMPLETION, FREE])
        self.assertEqual(machine.frees, [OPERATION])

    def test_supplied_early_return_leaves_the_context_without_the_checked_completion(self):
        machine = DataDealingMachine(self.image, supplied_early_return=True)
        machine.post_operation()
        machine.dispatch()

        self.assertEqual(machine.calls[-2:], [CALLBACK, FACTORY])
        self.assertEqual((machine.r[2], machine.r[29], machine.r[31]), (0, STACK, RETURN))
        self.assertNotIn(CONFIGURATOR, machine.calls)
        self.assertEqual(machine.get(HANDLE + 0x50, 4), 0)
        self.assertEqual(machine.get(HANDLE + 0x74, 4), 0)
        self.assertEqual(machine.get(OLD_DIALOG + 0x58, 4), OPERATION)
        self.assertEqual(machine.frees, [])


class OldDialogRetirementMachine(DataDealingMachine):
    def __init__(self, image, **options):
        super().__init__(image, allocation_result=QUEUE_RECORD, **options)
        self.queue_observations = []
        self.copied_operation = False
        self.old_alias_at_free = None
        self.map(QUEUE_RECORD, 20)
        self.map(QUEUE, 0x20)
        self.put(QUEUE, 2, 4)
        self.put(APP_QUEUE, QUEUE, 4)

        self.map(DIALOG_LIST, 0x100)
        self.r[16] = DIALOG_LIST
        self.run_at(0x456CB0, 0x456CEC)  # Native list method assignments.
        directory, cell = DIALOG_LIST + 0x40, DIALOG_LIST + 0x60
        for offset, value in ((0, directory), (0xC, 1), (0x10, 4), (0x14, 10)):
            self.put(DIALOG_LIST + offset, value, 4)
        self.put(directory, cell, 4)
        self.put(cell, OLD_DIALOG, 4)
        self.put(0xB8AEB8, DIALOG_LIST, 4)

        carrier = CONTEXT + 0x180
        self.put(carrier + 0x50, CONTEXT, 4)
        self.put(CONTEXT + 0x24, CONTEXT + 0xC0, 4)
        for offset, value in ((0xC, WAIT_MUTEX), (0x10, FINISH_MUTEX), (0x24, OLD_NAME),
                              (0x3C, carrier), (0x6C, DIALOG_FINISH), (0x74, OLD_CALLBACK)):
            self.put(OLD_DIALOG + offset, value, 4)
        self.put(OLD_DIALOG + 0x1C, 1, 1)

    def plain(self, word):
        if word >> 26 != 0x24:
            return super().plain(word)
        self.executing_pc = self.fetch_pc
        base, target = (word >> 21) & 31, (word >> 16) & 31
        self.r[target] = self.get((self.r[base] + sx16(word & 0xFFFF)) & MASK, 1)
        self.r[0] = 0

    def external(self, target):
        if target in (POLL, DIALOG_FINISH, 0x455DC0, 0x466DE0, QUEUE_WRITE):
            self.calls.append(target)
            self.run_at(target, self.r[31])
        elif target == OLD_CALLBACK:
            self.calls.append(target)
            return_pc = self.r[31]
            self.run_at(target, 0x4AECC0)
            self.run_at(PRODUCER, return_pc)  # Selected view/path branch.
        elif target == 0xA5B600:
            self.calls.append(target)
            if self.r[4:6] != [OLD_NAME, OLD_NAME]:
                raise AssertionError('unexpected close name arguments')
            self.hostile_result(0)
        elif target == MAIN_DISPATCH:
            self.calls.append(target)
            self.queue_observations.append(
                (self.get(QUEUE + 0x10, 4), self.copied_operation, self.old_alias_at_free))
            self.hostile_result(0)
        elif target in (0x47AA20, 0x439780, 0x4395A0, 0x485320, 0xA5B0F0,
                        0x43C900, 0x468D40, 0x437CC0, 0x437A60, 0x437D40,
                        0x473560, 0x4725A0, 0x47B980, 0x47BA40):
            self.calls.append(target)
            self.hostile_result(int(target == 0x4725A0))
        else:
            if target == FREE and self.r[4] == OLD_DIALOG:
                self.old_alias_at_free = self.get(OLD_DIALOG + 0x58, 4)
            worker_copy = target == COPY_BYTES and self.r[4] == WORKER + 0x140
            super().external(target)
            self.copied_operation |= worker_copy


class NativeOldDialogRetirementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = audit.source_image()

    def test_poll_and_close_free_mutexes_and_old_dialog_after_the_event_post(self):
        for entry in (POLL, CLOSE):
            with self.subTest(entry=hex(entry)):
                machine = OldDialogRetirementMachine(self.image)
                machine.r[4] = OLD_NAME
                machine.run_at(entry, RETURN)

                self.assertEqual(machine.post_status, 0)
                self.assertEqual(machine.get(QUEUE + 0x10, 4), QUEUE_RECORD)
                self.assertEqual(struct.unpack('<5I', machine.regions[QUEUE_RECORD]),
                                 (0, EVENT, OPERATION, 0, 0))
                self.assertTrue(machine.copied_operation)
                self.assertEqual(machine.get(DIALOG_LIST + 0xC, 4), 0)
                self.assertEqual(machine.frees, [WAIT_MUTEX, FINISH_MUTEX, OLD_DIALOG])
                self.assertEqual(machine.old_alias_at_free, OPERATION)
                self.assertEqual((machine.r[29], machine.r[31]), (STACK, RETURN))

    def test_same_loop_dispatches_again_only_after_the_copy_and_old_dialog_free(self):
        machine = OldDialogRetirementMachine(self.image)
        machine.seed_frame(72, 2)
        machine.r[16] = CONTEXT
        machine.run_at(0x43C9A4, 0x43C9AC)
        machine.run_at(0x43C9AC, 0x43C9A4)
        machine.run_at(0x43C9A4, 0x43C9AC)

        self.assertEqual(machine.queue_observations,
                         [(0, False, None), (QUEUE_RECORD, True, OPERATION)])
        self.assertEqual(machine.frees, [WAIT_MUTEX, FINISH_MUTEX, OLD_DIALOG])

    def test_full_queue_refuses_the_record_but_the_producer_still_copies_and_retires(self):
        machine = OldDialogRetirementMachine(self.image)
        machine.put(QUEUE + 4, 1, 4)  # Next write index meets the read index.
        machine.run_at(POLL, RETURN)

        self.assertEqual(machine.post_status, MASK)
        self.assertEqual(machine.get(QUEUE + 0x10, 4), 0)
        self.assertNotIn(ALLOCATOR, machine.calls)
        self.assertTrue(machine.copied_operation)
        self.assertEqual(machine.old_alias_at_free, OPERATION)
        self.assertEqual(machine.frees, [WAIT_MUTEX, FINISH_MUTEX, OLD_DIALOG])

    def test_absent_queue_returns_zero_but_producer_still_copies_and_retires(self):
        machine = OldDialogRetirementMachine(self.image)
        machine.put(APP_QUEUE, 0, 4)
        machine.run_at(POLL, RETURN)

        self.assertEqual(machine.post_status, 0)
        self.assertNotIn(QUEUE_WRITE, machine.calls)
        self.assertNotIn(ALLOCATOR, machine.calls)
        self.assertEqual(machine.get(QUEUE + 0x10, 4), 0)
        self.assertTrue(machine.copied_operation)
        self.assertEqual(machine.old_alias_at_free, OPERATION)
        self.assertEqual(machine.frees, [WAIT_MUTEX, FINISH_MUTEX, OLD_DIALOG])


class QueueDisposalMachine(OldDialogRetirementMachine):
    def __init__(self, image, **options):
        super().__init__(image, factory_result=HANDLE, **options)
        self.put(0xB8A9EC, CONTEXT, 4)
        self.put(CONTEXT + 0x14, QUEUE, 4)
        table_size = 128 * 8
        self.map(OTHER_EVENT_TABLE, table_size)
        offset = image.va_to_off(OTHER_EVENT_TABLE)
        self.bytes(OTHER_EVENT_TABLE, image.data[offset:offset + table_size])

    def external(self, target):
        if target in (0x475320, 0x8B1F60, QUEUE_BUILD, QUEUE_READ, QUEUE_DESTROY):
            self.calls.append(target)
            self.run_at(target, self.r[31])
        elif target in (0x44FAC0, 0x466C40, 0x466F80):
            self.calls.append(target)
            self.hostile_result(0)
        else:
            super().external(target)


class ReusedDataDealingMachine(QueueDisposalMachine):
    def __init__(self, image):
        super().__init__(image)
        self.reuse_dialog = False
        self.map(SECOND_RECORD, 20)
        self.map(SECOND_OPERATION, 0xCF0)

    def external(self, target):
        if target == FIND_DIALOG or (target == FACTORY and self.reuse_dialog):
            self.calls.append(target)
            self.run_at(target, self.r[31])
        elif target == 0xA5B600 and self.r[4:6] == [DATA_DEALING_NAME, DATA_DEALING_NAME]:
            self.calls.append(target)
            self.hostile_result(0)
        else:
            super().external(target)

    def register_existing_dialog(self):
        # The first dispatch supplied a fresh dialog. Bind its live list record.
        self.put(DIALOG_LIST + 0xC, 1, 4)
        self.put(DIALOG_LIST + 0x60, HANDLE, 4)
        self.put(HANDLE + 0x24, DATA_DEALING_NAME, 4)
        self.put(HANDLE + 0x30, 15000, 4)
        self.put(HANDLE + 0x38, 0x13572468, 4)
        self.put(HANDLE + 0x48, CONTEXT, 4)
        self.reuse_dialog = True


class ChargeTransitionMachine(QueueDisposalMachine):
    """Native controller and dialog ordering with bounded power and UI services."""

    def __init__(self, image, **options):
        super().__init__(image, **options)
        self.dispatches, self.loop_entries, self.loop_exits = [], [], []
        self.charge_reads = []
        self.map(CURRENT_CONTROLLER, 0x10)
        self.map(CONTROLLER_REGISTRY, 8)
        self.map(CLOSE_NODE, 0x1C)
        for controller, bind in ((MUSIC, 0x4E3E40), (CHARGE, 0x51A2E0)):
            self.map(controller, 0x300)
            self.stock(bind, controller)
            self.put(controller + 0x2C, 1, 4)
            self.put(controller + 0x34, controller + 0x34, 4)
            self.put(controller + 0x274, 0x437D20, 4)
            self.put(controller + 0x278, 0x437DA0, 4)
        self.put(NEXT_CONTROLLER, MUSIC, 4)
        self.put(CONTROLLER_REGISTRY, CHARGE, 4)
        self.put(CONTROLLER_REGISTRY + 4, CHARGE_ACTIVITY, 4)
        self.put(MUSIC + 0x30, WORKER, 4)
        self.put(MUSIC + 0x34, CLOSE_NODE, 4)
        self.put(CLOSE_NODE, MUSIC + 0x34, 4)
        self.put(CLOSE_NODE + 0x14, OLD_DIALOG, 4)
        self.put(CLOSE_NODE + 0x18, CLOSE_DIALOG, 4)
        self.put(OLD_DIALOG + 0x48, MUSIC, 4)
        self.put(OLD_DIALOG + 0x1C, 0, 1)  # Poll leaves this dialog for teardown.
        self.put(CONTEXT + 0x180 + 0x50, MUSIC, 4)

    def external(self, target):
        if target == APP_LOOP:
            self.calls.append(target)
            self.loop_entries.append((self.r[4], self.get(NEXT_CONTROLLER, 4), self.get(QUEUE + 0x10, 4)))
            self.run_at(target, self.r[31])
            self.loop_exits.append((self.get(CURRENT_CONTROLLER, 4), self.get(QUEUE + 0x10, 4)))
        elif target in (MAIN_DISPATCH, OTHER_DISPATCH):
            self.calls.append(target)
            self.dispatches.append((target, self.get(QUEUE + 0x10, 4), self.copied_operation,
                                    self.old_alias_at_free))
            self.run_at(target, self.r[31])
        elif target == TIMER_PUMP:
            self.calls.append(target)
            # A supplied exit request takes the real controller exit path.
            self.r[4] = 0
            self.run_at(REQUEST_EXIT, self.r[31])
        elif target == 0x4771A0:
            self.calls.append(target)
            selector, output = self.r[4:6]
            if selector == 11:
                value = int(not self.charge_reads)
                self.charge_reads.append(value)
                self.put(output, value, 4)
            self.hostile_result(0)
        elif target == 0x4395A0:
            self.calls.append(target)
            if self.r[4] != MUSIC or not self.copied_operation:
                raise AssertionError('unexpected old controller record removal')
            self.put(MUSIC + 0x34, MUSIC + 0x34, 4)
            self.hostile_result(0)
        elif target == 0xA5B600 and self.r[4:6] == [CHARGE_ACTIVITY, CHARGE_ACTIVITY]:
            self.calls.append(target)
            self.hostile_result(0)
        elif target in (CONTROLLER_LOOP, SELECT_ACTIVITY, REQUEST_EXIT, CLOSE_DIALOG, CLOSE, 0x47C9A0,
                        0x4E3DE0, 0x4E4AC0, 0x4E3EA0, 0x43C980, 0x437A60,
                        0x51A280, 0x51A4E0, 0x51A340, 0x43CA60):
            self.calls.append(target)
            self.run_at(target, self.r[31])
        elif target in (0x4E4DE0, 0x51A440, 0x437D20, 0x437DA0, 0x43CB20, 0x448200,
                        0x466E20, 0x431FA0, 0x457300, 0x457420, 0x477700, 0x42BC80, 0x477180):
            self.calls.append(target)
            self.hostile_result(0)
        else:
            super().external(target)


class NativeQueuedContextDisposalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = audit.source_image()

    def posted(self):
        machine = QueueDisposalMachine(self.image)
        machine.run_at(POLL, RETURN)
        self.assertEqual(machine.frees, [WAIT_MUTEX, FINISH_MUTEX, OLD_DIALOG])
        self.assertEqual(machine.get(QUEUE + 0x10, 4), QUEUE_RECORD)
        self.assertEqual(struct.unpack('<5I', machine.regions[QUEUE_RECORD]),
                         (0, EVENT, OPERATION, 0, 0))
        return machine

    def test_application_startup_publishes_the_same_ring_to_post_and_dispatch(self):
        machine = QueueDisposalMachine(self.image)
        application_queue = QUEUE + 0x100
        machine.map(application_queue, (128 + 5) * 4)
        machine.allocation_result = application_queue
        machine.put(APP_QUEUE, 0, 4)
        machine.put(CONTEXT + 0x14, 0, 4)
        # The preceding startup code has supplied the application and global base.
        machine.r[17:19] = [0xB90000, CONTEXT]
        machine.run_at(0x4747AC, 0x4747D0)

        self.assertEqual(machine.calls, [QUEUE_BUILD, ALLOCATOR, 0x44FAC0])
        self.assertEqual(machine.get(application_queue, 4), 128)
        self.assertEqual(machine.get(APP_QUEUE, 4), application_queue)
        self.assertEqual(machine.get(CONTEXT + 0x14, 4), application_queue)

    def test_two_worker_readers_consume_eight_bytes_from_their_own_rings(self):
        worker_queue, worker_record = QUEUE + 0x100, QUEUE_RECORD + 0x40
        record = struct.pack('<2I', 9, 0)
        for entry, stop, queue_slot, frame_offset in WORKER_READERS:
            with self.subTest(entry=hex(entry)):
                machine = self.posted()
                machine.map(0xADD368, 0x14)
                machine.map(worker_queue, 0x20)
                machine.map(worker_record, len(record))
                machine.bytes(worker_record, record)
                for address, value in ((queue_slot, worker_queue), (queue_slot + 8, WAIT_MUTEX),
                                       (queue_slot + 0xC, FINISH_MUTEX), (worker_queue, 2),
                                       (worker_queue + 8, 1), (worker_queue + 0x10, worker_record)):
                    machine.put(address, value, 4)
                machine.run_at(entry, stop)

                destination = machine.r[29] + frame_offset
                self.assertEqual(machine.copy_args, (destination, worker_record, len(record)))
                self.assertEqual(machine.get(destination, 4), 9)
                self.assertEqual(machine.get(destination + 4, 4), 0)
                self.assertEqual(machine.get(worker_queue + 0x10, 4), 0)
                self.assertEqual(machine.get(QUEUE + 0x10, 4), QUEUE_RECORD)
                self.assertEqual(machine.frees[3:], [worker_record])

    def test_main_dispatch_pops_the_record_and_hands_operation_to_the_dialog(self):
        machine = self.posted()
        machine.r[4] = CONTEXT
        machine.run_at(MAIN_DISPATCH, RETURN)

        self.assertIn(QUEUE_READ, machine.calls)
        self.assertIn(CALLBACK, machine.calls)
        self.assertEqual(machine.get(QUEUE + 0x10, 4), 0)
        self.assertEqual(machine.get(QUEUE + 4, 4), 1)
        self.assertEqual(machine.frees[3:], [QUEUE_RECORD])
        self.assertEqual(machine.get(HANDLE + 0x50, 4), OPERATION)

        machine.r[16] = HANDLE
        machine.run_at(0x47C7B8, 0x47C7D0)
        self.assertEqual(machine.frees[3:], [QUEUE_RECORD, OPERATION])

    def test_same_name_reuse_replaces_the_request_with_the_next_record(self):
        sends = (
            (None, None, SECOND_OPERATION),  # A second distinct owned request.
            (0x4ABF9C, 0x4ABFAC, 0),
            (0x4B2134, 0x4B2144, 0),
            (0x4B66E0, 0x4B67B8, 0),
            (0x530764, 0x530774, 0),
        )
        for start, stop, next_operation in sends:
            with self.subTest(send=start, next_operation=hex(next_operation)):
                machine = ReusedDataDealingMachine(self.image)
                machine.run_at(POLL, RETURN)
                machine.stock(MAIN_DISPATCH, CONTEXT)
                self.assertEqual(machine.get(HANDLE + 0x50, 4), OPERATION)
                self.assertEqual(machine.frees, [WAIT_MUTEX, FINISH_MUTEX, OLD_DIALOG, QUEUE_RECORD])
                machine.register_existing_dialog()
                unchanged_offsets = (0x10, 0x24, 0x30, 0x38, 0x48, 0x58, 0x74)
                previous = [machine.get(HANDLE + offset, 4) for offset in unchanged_offsets]

                machine.allocation_result = SECOND_RECORD
                if next_operation:
                    machine.stock(POST, EVENT, next_operation, 0)
                else:
                    machine.r[2] = 1  # Selects the posting branch at 4B66E0.
                    machine.run_at(start, stop)
                self.assertEqual(struct.unpack('<5I', machine.regions[SECOND_RECORD]),
                                 (0, EVENT, next_operation, 0, 0))

                first = len(machine.calls)
                machine.stock(MAIN_DISPATCH, CONTEXT)
                reuse = machine.calls[first:]
                self.assertIn(FIND_DIALOG, reuse)
                self.assertNotIn(ALLOCATOR, reuse)
                self.assertEqual(machine.config_inputs, (HANDLE, HANDLE, 4))
                self.assertEqual(machine.get(HANDLE + 0x50, 4), next_operation)
                self.assertEqual(machine.get(HANDLE + 0x5C, 4), 1)
                self.assertEqual([machine.get(HANDLE + offset, 4) for offset in unchanged_offsets],
                                 previous)

                machine.r[16] = HANDLE
                machine.run_at(0x47C7B8, 0x47C7D0)
                self.assertEqual(machine.frees[4:], [SECOND_RECORD] +
                                 ([SECOND_OPERATION] if next_operation else []))

    def test_other_dispatch_pops_the_record_and_exhausts_its_table(self):
        machine = self.posted()
        machine.r[4] = CONTEXT
        machine.run_at(OTHER_DISPATCH, RETURN)

        self.assertIn(QUEUE_READ, machine.calls)
        self.assertNotIn(CALLBACK, machine.calls)
        self.assertNotIn(FACTORY, machine.calls)
        self.assertEqual(machine.get(QUEUE + 0x10, 4), 0)
        self.assertEqual(machine.get(QUEUE + 4, 4), 1)
        self.assertEqual(machine.frees[3:], [QUEUE_RECORD])
        self.assertIn(('read', 0x454340, OTHER_EVENT_TABLE + 127 * 8, 4), machine.accesses)
        self.assertEqual((machine.r[29], machine.r[31]), (STACK, RETURN))

    def test_music_teardown_can_post_for_the_subsequent_charge_loop(self):
        machine = ChargeTransitionMachine(self.image)
        machine.frame(56, 0x34)
        machine.r[17:19] = [CONTEXT, CHARGE_ACTIVITY]
        machine.run_at(0x47569C, 0x475834)

        self.assertEqual(machine.charge_reads, [1, 0])
        self.assertEqual(machine.loop_entries, [(CONTEXT, MUSIC, 0), (CONTEXT, CHARGE, QUEUE_RECORD)])
        self.assertEqual(machine.loop_exits, [(MUSIC, QUEUE_RECORD), (CHARGE, 0)])
        self.assertEqual(machine.dispatches, [(MAIN_DISPATCH, 0, False, None),
                                             (OTHER_DISPATCH, QUEUE_RECORD, True, OPERATION)])
        order = (MAIN_DISPATCH, 0x4E3EA0, CLOSE_DIALOG, POST, WORKER_COPY, OTHER_DISPATCH)
        self.assertEqual(sorted(order, key=machine.calls.index), list(order))
        self.assertNotIn(CALLBACK, machine.calls)
        self.assertEqual(machine.frees, [WAIT_MUTEX, FINISH_MUTEX, OLD_DIALOG, QUEUE_RECORD])
        self.assertEqual(machine.get(APP_QUEUE, 4), QUEUE)
        self.assertEqual(machine.get(QUEUE + 4, 4), 1)

    def test_shutdown_frees_the_record_and_queue_without_loading_the_operation(self):
        machine = self.posted()
        machine.r[16], machine.r[17] = 0x930000, 0xB90000
        first = len(machine.accesses)
        machine.run_at(0x474880, 0x47489C)

        self.assertIn(QUEUE_DESTROY, machine.calls)
        self.assertEqual(machine.frees[3:], [QUEUE_RECORD, QUEUE])
        self.assertEqual(machine.get(APP_QUEUE, 4), 0)
        self.assertFalse(any(operation == 'read' and QUEUE_RECORD <= address < QUEUE_RECORD + 20
                             for operation, _, address, _ in machine.accesses[first:]))


if __name__ == '__main__':
    unittest.main()
