#!/usr/bin/env python3
"""Reproduce native Tidal queue boundaries under the current local composer.

These are diagnostic regressions, not a queue repair. Actual POST/ring/copy/
free instructions execute with bounded allocation and byte-copy services.
Two CPU contexts share memory and interleave at explicit instruction cuts.
The schedules are conditional: no producer-thread census or second Tidal
worker is established here, and no occurrence on the player is claimed.
Retired-storage checks model loss of lifetime after native free returns.
No scheduler, libc allocator, native worker join or device is emulated here.
"""

import unittest

import factory_null_audit as audit
import reveal_tidal_job_snapshot_mips as stage
import reveal_tidal_request_identity_mips as identity
import reveal_tidal_response_reader_bridge_mips as session
from test_factory_d180_qr_continuation import MESSAGE, MEMCPY, QUEUE, QUEUE_SLOT, STATUS
from test_factory_null_audit import CONTEXT, FREE, RETURN, STACK
from test_reveal_d180_book_percent_guard_mips import RAW_ALLOC
from test_reveal_tidal_request_identity_mips import IdentityMachine
from test_reveal_tidal_response_reader_bridge_mips import CODE_BASE, MUTEX


WRITE, READ, DESTROY, ARM = 0x4504E0, 0x450600, 0x4507E0, 0x454BA0
SECOND_MESSAGE = MESSAGE + 0x40
OUTPUT, SECOND_OUTPUT = CONTEXT + 0x100, CONTEXT + 0x140


class QueuePause(Exception):
    """An explicit fixture scheduling cut inside a nested native WRITE."""


class QueueBoundaryFault(RuntimeError):
    def __init__(self, kind, address, size):
        self.kind, self.address, self.size = kind, address, size
        super().__init__(f'{kind}: {address:#x}, {size} bytes')


class QueueTransportMachine(IdentityMachine):
    def __init__(self, *args, **kwargs):
        self.retired_queues, self.retired_packets = set(), set()
        self.copy_calls, self.packet_allocations = [], []
        self.packet_address, self.pause_write_at = MESSAGE, None
        super().__init__(*args, **kwargs)
        self.map(QUEUE - 4, 4)
        self.put(QUEUE - 4, 32, 4)
        self.map(SECOND_MESSAGE - 4, 12)
        self.put(QUEUE, 4, 4)

    def get(self, address, size):
        for pointer in self.retired_queues:
            if pointer <= address < pointer + 32:
                raise QueueBoundaryFault('retired queue read', address, size)
        return super().get(address, size)

    def external(self, target):
        if target == RAW_ALLOC and self.r[4] == 24:
            self.calls.append(target)
            self.packet_allocations.append(self.packet_address)
            self.hostile_result(self.packet_address - 4 if self.packet_address else 0)
        elif target == WRITE and self.pause_write_at is not None:
            self.calls.append(target)
            self.run_at(target, self.pause_write_at)
            raise QueuePause()
        elif target == MEMCPY:
            destination, source, size = self.r[4:7]
            self.copy_calls.append((destination, source, size))
            if source in self.retired_packets:
                raise QueueBoundaryFault('retired packet copy', source, size)
            if not destination and size:
                raise QueueBoundaryFault('NULL copy destination', destination, size)
            super().external(target)
        elif target == FREE:
            pointer = self.r[4]
            super().external(target)
            if pointer == QUEUE:
                self.retired_queues.add(pointer)
            elif pointer in (MESSAGE, SECOND_MESSAGE):
                self.retired_packets.add(pointer)
        else:
            super().external(target)

    def pause_post_in_write(self, pc):
        self.pause_write_at = pc
        try:
            self.stock(identity.POST, 0, 0)
        except QueuePause:
            pass
        else:
            raise AssertionError('native WRITE did not reach its scheduling cut')
        finally:
            self.pause_write_at = None


class NativeTidalQueueTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = audit.source_image()
        cls.code, cls.patches = stage.assemble(MUTEX, CODE_BASE)

    def machine(self):
        return QueueTransportMachine(self.image, self.code, self.patches)

    def test_source_queue_gate_is_plain_memory_and_allocation_has_no_null_branch_before_copy(self):
        self.assertEqual(len(self.patches), 44)
        words = {0x450504: 0x8C82000C, 0x450510: 0x18400006,
                 0x450534: 0x8E03000C, 0x45054C: 0xAE03000C,
                 0x450564: 0x0C119A78, 0x45056C: 0x00402021,
                 0x450570: 0x02802821, 0x450574: 0x02403021,
                 0x450578: 0x0C296D10, 0x45057C: 0x00409821,
                 0x450594: 0xAC730000, 0x45059C: 0xAE110008,
                 0x450644: 0x8E07000C, 0x450654: 0xAE07000C,
                 0x45066C: 0x8C450000, 0x450670: 0x0C296D10,
                 0x450694: 0x0C119AA0, 0x4506AC: 0xAC600000,
                 0x45085C: 0x0C119AA0, 0x454B4C: 0x8C449250}
        for pc, word in words.items():
            self.assertEqual(self.image.word(pc), word, hex(pc))
        expected_calls = {WRITE: {0x466E20, 0x4669E0, MEMCPY},
                          READ: {0x466E20, MEMCPY, FREE},
                          DESTROY: {0x466E20, FREE}}
        for begin, end in ((WRITE, 0x4505E8), (READ, 0x450710), (DESTROY, 0x450878)):
            calls = set()
            for pc in range(begin, end, 4):
                word = self.image.word(pc)
                op = word >> 26
                self.assertNotIn(op, (0x30, 0x38), hex(pc))  # No LL/SC admission.
                if op == 3:
                    calls.add(((pc + 4) & 0xF0000000) | ((word & 0x3FFFFFF) << 2))
            self.assertEqual(calls, expected_calls[begin])

    def test_serial_post_owns_a_copied_packet_until_dequeue_frees_it(self):
        machine = self.machine()
        self.assertEqual(machine.stock(identity.POST, 0, 0), 0)
        self.assertEqual((machine.get(MESSAGE, 4), machine.get(MESSAGE + 4, 4)), (0, 1))
        self.assertEqual(machine.get(QUEUE + 0x10, 4), MESSAGE)
        self.assertEqual(machine.stock(READ, QUEUE, OUTPUT, 8), 0)
        self.assertEqual((machine.get(OUTPUT, 4), machine.get(OUTPUT + 4, 4)), (0, 1))
        self.assertEqual(machine.get(QUEUE + 0x10, 4), 0)
        self.assertEqual(machine.retired_packets, {MESSAGE})
        self.assertEqual(machine.stock(READ, QUEUE, OUTPUT, 8), 0xFFFFFFFF)
        self.assertEqual(machine.releases, [MESSAGE])

    def test_native_full_and_absent_queue_fail_without_clearing_armed_pending(self):
        for absent in (False, True):
            with self.subTest(absent=absent):
                machine = self.machine()
                machine.stock(ARM, 0, 1)
                if absent:
                    machine.put(QUEUE_SLOT, 0, 4)
                else:
                    machine.put(QUEUE + 4, 1, 4)
                self.assertEqual(machine.stock(identity.POST, 0, 0), 0xFFFFFFFF)
                self.assertEqual(machine.get(STATUS, 4), 1)
                self.assertEqual(machine.packet_allocations, [])
                self.assertEqual(machine.get(QUEUE + 0xC, 4), 0)
                self.assertEqual(machine.get(MUTEX + session.PHASE, 4), session.READY)
                self.assertEqual(machine.get(MUTEX + session.WRITER, 4), 0)

    def test_packet_allocation_failure_reaches_nonzero_memcpy_with_null_destination(self):
        machine = self.machine()
        machine.packet_address = 0
        with self.assertRaises(QueueBoundaryFault) as error:
            machine.stock(identity.POST, 0, 0)
        self.assertEqual((error.exception.kind, error.exception.address, error.exception.size),
                         ('NULL copy destination', 0, 8))
        self.assertEqual(machine.copy_calls[-1][0::2], (0, 8))
        self.assertEqual(machine.get(QUEUE + 0xC, 4), 1)
        self.assertEqual(machine.get(QUEUE + 8, 4), 0)
        self.assertEqual(machine.get(QUEUE + 0x10, 4), 0)
        self.assertEqual(machine.get(MUTEX + session.PHASE, 4), session.READY)

    def test_two_guarded_producers_can_both_report_success_with_one_unreachable_packet(self):
        first = self.machine()
        second = first.fork_cpu()
        second.r[29] = STACK + 0x1800
        second.packet_address = SECOND_MESSAGE
        # Both observe an idle +C before either changes it. The generation
        # capture mutex has already been released before either queue entry.
        for machine in (first, second):
            machine.pause_post_in_write(0x45052C)
        for machine in (first, second):
            machine.run_at(0x45052C, 0x450550)
        self.assertEqual((first.r[17], second.r[17]), (1, 1))
        self.assertEqual(first.get(QUEUE + 0xC, 4), 2)
        first.run_at(0x450550, RETURN)
        second.run_at(0x450550, RETURN)
        self.assertEqual((first.r[2], second.r[2]), (0, 0))
        self.assertEqual([first.get(QUEUE + offset, 4) for offset in (4, 8, 12)], [0, 1, 0])
        self.assertEqual([first.get(QUEUE + offset, 4) for offset in (0x10, 0x14)],
                         [MESSAGE, SECOND_MESSAGE])
        self.assertEqual(first.stock(READ, QUEUE, OUTPUT, 8), 0)
        self.assertEqual(first.stock(READ, QUEUE, OUTPUT, 8), 0xFFFFFFFF)
        self.assertEqual(first.retired_packets, {MESSAGE})
        self.assertEqual(first.get(QUEUE + 0x14, 4), SECOND_MESSAGE)
        self.assertEqual(first.get(MUTEX + session.WRITER, 4), 0)

    def test_two_native_readers_can_capture_the_same_record_before_one_releases_it(self):
        first = self.machine()
        self.assertEqual(first.stock(identity.POST, 0, 0), 0)
        second = first.fork_cpu()
        second.r[29] = STACK + 0x1800
        for machine, output in ((first, OUTPUT), (second, SECOND_OUTPUT)):
            machine.r[4:7], machine.r[31] = [QUEUE, output, 8], RETURN
            machine.run_at(READ, 0x450644)
        for machine in (first, second):
            machine.run_at(0x450644, 0x450670)
        self.assertEqual((first.r[5], second.r[5]), (MESSAGE, MESSAGE))
        first.run_at(0x450670, RETURN)
        self.assertEqual(first.retired_packets, {MESSAGE})
        with self.assertRaises(QueueBoundaryFault) as error:
            second.run_at(0x450670, RETURN)
        self.assertEqual((error.exception.kind, error.exception.address, error.exception.size),
                         ('retired packet copy', MESSAGE, 8))

    def test_an_admitted_post_has_no_queue_pin_across_the_close_and_destroy_boundary(self):
        machine = self.machine()
        machine.r[4:6] = [0, 0]
        machine.run_at(identity.POST, identity.POST + 8)
        self.assertEqual((machine.get(MUTEX + session.WRITER, 4),
                          machine.get(MUTEX + session.BORROWS, 4)), (0, 0))
        closer = machine.fork_cpu()
        closer.seed_native_frame()  # Reuse the actual stamped main activation.
        site = session.CLOSE_SITES[0][0]
        closer.run_at(site, site + 8)
        self.assertEqual(machine.get(MUTEX + session.LIFECYCLE, 4), session.CLOSING)
        # Isolate the selected native shutdown's queue-destroy suffix after
        # its worker-stop premise. No worker-join implementation is invented.
        closer.stock(DESTROY, QUEUE)
        self.assertEqual(machine.get(QUEUE_SLOT, 4), QUEUE)
        with self.assertRaises(QueueBoundaryFault) as error:
            machine.run_at(identity.POST + 8, RETURN)
        self.assertEqual(error.exception.kind, 'retired queue read')
        self.assertEqual(error.exception.address, QUEUE + 0xC)
        self.assertEqual(machine.get(MUTEX + session.PHASE, 4), session.READY)


if __name__ == '__main__':
    unittest.main()
