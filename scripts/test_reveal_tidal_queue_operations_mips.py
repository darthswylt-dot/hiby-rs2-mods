#!/usr/bin/env python3
"""Execute selected queue gates with native operations and shared CPU memory.

Allocator/copy/free services are bounded substitutes. Two CPUs share only
the modeled gate reservation domain and memory, with explicit scheduling
cuts; this is not a scheduler or queue-retirement simulation. Direct native
READ/WRITE calls remain outside the selected callsite protocol.
"""

import unittest

import factory_null_audit as audit
import reveal_tidal_queue_operations_mips as operations
import reveal_tidal_request_identity_mips as identity
import reveal_tidal_response_reader_bridge_mips as session
from test_factory_d180_qr_continuation import MESSAGE, MEMCPY, QUEUE, QUEUE_SLOT
from test_factory_null_audit import CONTEXT, FREE, RETURN, STACK
from test_factory_tidal_queue_transport import (
    OUTPUT, READ, SECOND_MESSAGE, SECOND_OUTPUT, WRITE,
    QueuePause, QueueTransportMachine,
)
from test_reveal_d180_book_percent_guard_mips import RAW_ALLOC
from test_reveal_tidal_response_reader_bridge_mips import CODE_BASE, MUTEX


GATE, OTHER_QUEUE = 0x1D0F000, CONTEXT + 0x300


class QueueOperationsMachine(QueueTransportMachine):
    def __init__(self, *args, **options):
        # A dict survives fork_cpu by reference. Its epoch invalidates another
        # CPU's LL reservation when either CPU stores the shared gate word.
        self.gate_domain = {'version': 0}
        self.gate_events, self.service_gate_events = [], []
        self.pause_read_at = self.on_native = None
        super().__init__(*args, **options)
        self.map(GATE, 4)
        self.put(GATE, 0, 4)
        self.gate_events.clear()

    def fork_cpu(self):
        other = super().fork_cpu()
        other.reservation = None
        other.on_native = None
        return other

    def put(self, address, value, size):
        super().put(address, value, size)
        if address < GATE + 4 and GATE < address + size:
            self.gate_domain['version'] += 1
            self.gate_events.append((getattr(self, 'fetch_pc', None), value))

    def plain(self, word):
        op, rs, rt = word >> 26, (word >> 21) & 31, (word >> 16) & 31
        offset = word & 0xFFFF
        offset -= 0x10000 if offset & 0x8000 else 0
        address = (self.r[rs] + offset) & 0xFFFFFFFF
        if op in (0x30, 0x38) and address == GATE:
            if op == 0x30:
                self.r[rt] = self.get(address, 4)
                self.reservation = address, self.gate_domain['version']
            else:
                success = self.reservation == (address, self.gate_domain['version'])
                self.reservation = None
                if self.sc_failures:
                    self.sc_failures -= 1
                    success = False
                if success:
                    self.put(address, self.r[rt], 4)
                self.r[rt] = int(success)
            self.r[0] = 0
            return
        super().plain(word)

    def external(self, target):
        if target in (MEMCPY, FREE) or target == RAW_ALLOC and self.r[4] == 24:
            self.service_gate_events.append((target, self.get(GATE, 4), self.held))
            if self.on_native is not None:
                callback, self.on_native = self.on_native, None
                callback(target)
        if target == READ:
            self.calls.append(target)
            self.run_at(target, self.pause_read_at or self.r[31])
            if self.pause_read_at is not None:
                raise QueuePause()
        else:
            super().external(target)

    def selected_read(self, output=OUTPUT):
        self.r[4:7] = [QUEUE, output, 8]
        self.run_at(operations.READ_SITE, operations.READ_SITE + 8)
        return self.r[2]

    def pause_selected_read(self, pc):
        self.pause_read_at = pc
        try:
            self.selected_read()
        except QueuePause:
            pass
        else:
            raise AssertionError('native READ did not reach its scheduling cut')
        finally:
            self.pause_read_at = None


class NativeTidalQueueOperationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = audit.source_image()
        cls.code, cls.patches = operations.assemble(
            MUTEX, CODE_BASE, queue_gate_address=GATE)

    def machine(self):
        return QueueOperationsMachine(self.image, self.code, self.patches)

    def assert_registers(self, machine, before, hi, lo, *, changed=()):
        for register in range(32):
            if register not in changed:
                self.assertEqual(machine.r[register], before[register], f'r{register}')
        self.assertEqual((machine.hi, machine.lo), (hi, lo))

    def test_three_added_redirects_pin_source_and_require_distinct_gate_storage(self):
        self.assertEqual(len(self.patches), 47)
        for site, original in operations.HOOKS:
            self.assertEqual(original, (self.image.word(site), self.image.word(site + 4)))
            self.assertEqual(self.patches[site][0], original)
        for address in (MUTEX, MUTEX + session.CONTROL_BYTES - 4, CODE_BASE, GATE + 1):
            with self.subTest(address=hex(address)), self.assertRaises(ValueError):
                operations.assemble(MUTEX, CODE_BASE, queue_gate_address=address)
        with self.assertRaises(TypeError):
            operations.assemble(MUTEX, CODE_BASE)

    def test_allocation_null_returns_enomem_balances_native_counter_and_releases_gate(self):
        machine = self.machine()
        machine.packet_address = 0
        self.assertEqual(machine.stock(identity.POST, 0, 0), 0xFFFFFFFF)
        self.assertEqual(machine.r[3], 12)
        self.assertEqual(machine.copy_calls, [])
        self.assertEqual([machine.get(QUEUE + offset, 4) for offset in (4, 8, 12, 16)], [0] * 4)
        self.assertEqual(machine.get(GATE, 4), 0)
        self.assertEqual(machine.releases, [])
        self.assertEqual(machine.get(MUTEX + session.PHASE, 4), session.READY)
        self.assertEqual(machine.service_gate_events, [(RAW_ALLOC, 1, False)])

    def test_two_producers_refuse_contention_then_retry_without_losing_a_packet(self):
        first = self.machine()
        second = first.fork_cpu()
        second.r[29] = STACK + 0x1800
        second.packet_address = SECOND_MESSAGE
        first.pause_post_in_write(0x45052C)
        self.assertEqual(first.get(GATE, 4), 1)
        self.assertEqual(second.stock(identity.POST, 0, 0), 0xFFFFFFFF)
        self.assertEqual(second.r[3], 16)
        self.assertEqual(second.packet_allocations, [])
        self.assertEqual(first.get(GATE, 4), 1)
        first.run_at(0x45052C, RETURN)
        self.assertEqual(first.get(GATE, 4), 0)
        self.assertEqual(second.stock(identity.POST, 0, 0), 0)
        self.assertEqual([first.get(QUEUE + offset, 4) for offset in (4, 8, 12)], [0, 2, 0])
        self.assertEqual([first.get(QUEUE + offset, 4) for offset in (16, 20)],
                         [MESSAGE, SECOND_MESSAGE])
        self.assertEqual(first.selected_read(OUTPUT), 0)
        self.assertEqual(first.selected_read(SECOND_OUTPUT), 0)
        self.assertEqual(first.selected_read(), 0xFFFFFFFF)
        self.assertEqual(first.releases, [MESSAGE, SECOND_MESSAGE])
        self.assertEqual(first.retired_packets, {MESSAGE, SECOND_MESSAGE})

    def test_competing_ll_reservation_cannot_admit_two_operations(self):
        first = self.machine()
        second = first.fork_cpu()
        second.r[29] = STACK + 0x1800
        # Stop both emitted helpers at their first SC after LL observed zero.
        helper = self.patches[operations.WRITE_SITE][1][0] & 0x3FFFFFF
        helper <<= 2
        sc = next(pc for pc in range(helper, helper + 256, 4)
                  if first.word(pc) >> 26 == 0x38)
        for machine in (first, second):
            machine.r[4:7] = [QUEUE, 0, 8]
            machine.run_at(operations.WRITE_SITE, sc)
        first.pause_write_at = 0x450504
        try:
            with self.assertRaises(QueuePause):
                first.run_at(sc, operations.WRITE_SITE + 8)
        finally:
            first.pause_write_at = None
        self.assertEqual(first.get(GATE, 4), 1)
        second.run_at(sc, operations.WRITE_SITE + 8)
        self.assertEqual((second.r[2], second.r[3]), (0xFFFFFFFF, 16))
        self.assertEqual(second.packet_allocations, [])
        self.assertEqual(first.get(GATE, 4), 1)
        first.run_at(0x450504, operations.WRITE_SITE + 8)
        self.assertEqual(first.get(GATE, 4), 0)

    def test_two_selected_readers_cannot_copy_the_same_record(self):
        first = self.machine()
        self.assertEqual(first.stock(identity.POST, 0, 0), 0)
        second = first.fork_cpu()
        second.r[29] = STACK + 0x1800
        first.pause_selected_read(0x450670)
        self.assertEqual(first.get(GATE, 4), 1)
        self.assertEqual(second.selected_read(SECOND_OUTPUT), 0xFFFFFFFF)
        self.assertEqual(second.r[3], 16)
        self.assertEqual(second.copy_calls, [])
        first.run_at(0x450670, operations.READ_SITE + 8)
        self.assertEqual(first.releases, [MESSAGE])
        self.assertEqual(first.get(GATE, 4), 0)
        self.assertEqual(second.selected_read(SECOND_OUTPUT), 0xFFFFFFFF)
        self.assertEqual(first.retired_packets, {MESSAGE})

    def test_read_gate_survives_native_counter_clear_until_index_commit(self):
        machine = self.machine()
        self.assertEqual(machine.stock(identity.POST, 0, 0), 0)
        machine.pause_selected_read(0x4506D0)
        self.assertEqual((machine.get(QUEUE + 12, 4), machine.get(QUEUE + 4, 4),
                          machine.get(GATE, 4)), (0, 0, 1))
        machine.run_at(0x4506D0, 0x4506D8)
        self.assertEqual((machine.get(QUEUE + 4, 4), machine.get(GATE, 4)), (1, 1))
        machine.run_at(0x4506D8, operations.READ_SITE + 8)
        self.assertEqual(machine.get(GATE, 4), 0)

    def test_write_gate_covers_pointer_publication_and_write_index_commit(self):
        machine = self.machine()
        machine.pause_post_in_write(0x450594)
        self.assertEqual((machine.get(QUEUE + 16, 4), machine.get(QUEUE + 8, 4),
                          machine.get(GATE, 4)), (0, 0, 1))
        machine.run_at(0x450594, 0x45059C)
        self.assertEqual((machine.get(QUEUE + 16, 4), machine.get(QUEUE + 8, 4),
                          machine.get(GATE, 4)), (MESSAGE, 0, 1))
        machine.run_at(0x45059C, 0x4505A8)
        self.assertEqual((machine.get(QUEUE + 8, 4), machine.get(QUEUE + 12, 4),
                          machine.get(GATE, 4)), (1, 0, 1))
        machine.run_at(0x4505A8, RETURN)
        self.assertEqual(machine.get(GATE, 4), 0)

    def test_opaque_reentry_via_selected_callsite_refuses_without_session_mutex(self):
        first = self.machine()
        nested = first.fork_cpu()
        nested.r[29] = STACK + 0x1800
        outcomes = []

        def reenter(target):
            self.assertEqual(target, RAW_ALLOC)
            outcomes.append((nested.selected_read(), nested.r[3]))

        first.on_native = reenter
        self.assertEqual(first.stock(identity.POST, 0, 0), 0)
        self.assertEqual(outcomes, [(0xFFFFFFFF, 16)])
        self.assertEqual(first.get(GATE, 4), 0)
        self.assertTrue(first.service_gate_events)
        self.assertTrue(all(gate == 1 and not held for _, gate, held in first.service_gate_events))

    def test_preexisting_native_busy_negative_or_null_refuses_before_native_sleep(self):
        for counter, diagnostic in ((1, 16), (0xFFFFFFFF, 71), (None, 22)):
            for site in (operations.WRITE_SITE, operations.READ_SITE):
                with self.subTest(counter=counter, site=hex(site)):
                    machine = self.machine()
                    machine.r[4:7] = [QUEUE if counter is not None else 0, OUTPUT, 8]
                    if counter is not None:
                        machine.put(QUEUE + 12, counter, 4)
                    machine.run_at(site, site + 8)
                    self.assertEqual((machine.r[2], machine.r[3]), (0xFFFFFFFF, diagnostic))
                    self.assertEqual(machine.get(GATE, 4), 0)
                    self.assertNotIn(0x466E20, machine.calls)
                    self.assertEqual(machine.packet_allocations, [])
                    self.assertEqual(machine.copy_calls, [])
                    if counter is not None:
                        self.assertEqual(machine.get(QUEUE + 12, 4), counter)

    def test_sc_retry_limit_preserves_foreign_gate_and_original_abi(self):
        for owned in (False, True):
            machine = self.machine()
            machine.put(GATE, int(owned), 4)
            machine.sc_failures = operations.MAX_ATTEMPTS if not owned else 0
            machine.r[4:7] = [QUEUE, OUTPUT, 8]
            before, hi, lo = machine.r.copy(), machine.hi, machine.lo
            machine.run_at(operations.READ_SITE, operations.READ_SITE + 8)
            self.assert_registers(machine, before, hi, lo, changed=(2, 3, 31))
            self.assertEqual((machine.r[2], machine.r[3], machine.r[31]),
                             (0xFFFFFFFF, 16, operations.READ_SITE + 8))
            self.assertEqual(machine.get(GATE, 4), int(owned))
            self.assertEqual(machine.sc_failures, 0)
            self.assertEqual(machine.packet_allocations, [])
            self.assertEqual(machine.get(before[29] + 0x824, 4), 0)

    def test_sc_retry_can_succeed_on_the_last_permitted_attempt(self):
        machine = self.machine()
        machine.sc_failures = operations.MAX_ATTEMPTS - 1
        self.assertEqual(machine.stock(identity.POST, 0, 0), 0)
        self.assertEqual(machine.sc_failures, 0)
        self.assertEqual(machine.packet_allocations, [MESSAGE])
        self.assertEqual((machine.get(MESSAGE, 4), machine.get(MESSAGE + 4, 4)), (0, 1))
        self.assertEqual(machine.get(QUEUE + 16, 4), MESSAGE)
        self.assertEqual(machine.get(GATE, 4), 0)
        self.assertEqual([value for _, value in machine.gate_events], [1, 0])

    def test_gate_zero_one_zero_aba_invalidates_an_older_cpu_reservation(self):
        first = self.machine()
        second = first.fork_cpu()
        second.r[29] = STACK + 0x1800
        helper = (self.patches[operations.WRITE_SITE][1][0] & 0x3FFFFFF) << 2
        sc = next(pc for pc in range(helper, helper + 256, 4)
                  if first.word(pc) >> 26 == 0x38)
        first.r[4:7] = [QUEUE, OUTPUT, 8]
        first.run_at(operations.WRITE_SITE, sc)
        old_epoch = first.gate_domain['version']
        self.assertEqual(first.reservation, (GATE, old_epoch))
        self.assertIs(first.gate_domain, second.gate_domain)

        # The other CPU owns and releases the initially empty queue. Its
        # gate ends at zero again, but the first CPU's old LL is invalid.
        self.assertEqual(second.selected_read(), 0xFFFFFFFF)
        self.assertEqual([value for _, value in second.gate_events], [1, 0])
        self.assertEqual((first.get(GATE, 4), first.gate_domain['version']),
                         (0, old_epoch + 2))
        self.assertEqual(first.reservation, (GATE, old_epoch))
        first.run_at(sc, sc + 4)
        result_register = (first.word(sc) >> 16) & 31
        self.assertEqual(first.r[result_register], 0)
        self.assertIsNone(first.reservation)
        self.assertEqual((first.get(GATE, 4), first.gate_domain['version']),
                         (0, old_epoch + 2))

        # A fresh LL/SC retry may now claim it; the failed stale SC did not.
        first.run_at(sc + 4, operations.WRITE_SITE + 8)
        self.assertEqual(first.r[2], 0)
        self.assertEqual(first.packet_allocations, [MESSAGE])
        self.assertEqual([value for _, value in first.gate_events], [1, 0])
        self.assertEqual((first.get(GATE, 4), first.gate_domain['version']),
                         (0, old_epoch + 4))

    def test_successful_selected_calls_preserve_registers_and_native_delay_effects(self):
        machine = self.machine()
        machine.r[4:7] = [QUEUE, 0x11111111, 8]
        machine.put(STACK + 0x18, 6, 4)
        machine.put(STACK + 0x1C, 0x12345678, 4)
        before, hi, lo = machine.r.copy(), machine.hi, machine.lo
        machine.run_at(operations.WRITE_SITE, operations.WRITE_SITE + 8)
        self.assert_registers(machine, before, hi, lo, changed=(2, 3, 5, 31))
        self.assertEqual((machine.r[2], machine.r[5], machine.r[31]),
                         (0, STACK + 0x18, operations.WRITE_SITE + 8))
        self.assertEqual((machine.get(MESSAGE, 4), machine.get(MESSAGE + 4, 4)),
                         (6, 0x12345678))
        machine.r[4:7] = [QUEUE, OUTPUT, 8]
        before, hi, lo = machine.r.copy(), machine.hi, machine.lo
        machine.run_at(operations.READ_SITE, operations.READ_SITE + 8)
        self.assert_registers(machine, before, hi, lo, changed=(2, 3, 31))
        self.assertEqual((machine.r[2], machine.r[31]), (0, operations.READ_SITE + 8))
        self.assertEqual((machine.get(OUTPUT, 4), machine.get(OUTPUT + 4, 4)),
                         (6, 0x12345678))
        self.assertEqual(machine.get(GATE, 4), 0)
        self.assertTrue(all(gate == 1 and not held for _, gate, held in machine.service_gate_events))

    def test_unrelated_direct_native_ring_operations_do_not_acquire_selected_gate(self):
        machine = self.machine()
        machine.map(OTHER_QUEUE, 0x20)
        machine.put(OTHER_QUEUE, 4, 4)
        machine.put(GATE, 1, 4)  # Another selected Tidal operation owns it.
        machine.put(OUTPUT, 0xCAFEBABE, 4)
        machine.put(OUTPUT + 4, 0x12345678, 4)
        self.assertEqual(machine.stock(WRITE, OTHER_QUEUE, OUTPUT, 8), 0)
        self.assertEqual(machine.get(OTHER_QUEUE + 16, 4), MESSAGE)
        self.assertEqual(machine.stock(READ, OTHER_QUEUE, SECOND_OUTPUT, 8), 0)
        self.assertEqual((machine.get(SECOND_OUTPUT, 4), machine.get(SECOND_OUTPUT + 4, 4)),
                         (0xCAFEBABE, 0x12345678))
        self.assertEqual(machine.get(GATE, 4), 1)
        self.assertEqual(machine.get(QUEUE + 8, 4), 0)
        self.assertEqual(machine.releases, [MESSAGE])

    def test_common_null_allocation_refusal_also_protects_an_unrelated_ring(self):
        machine = self.machine()
        machine.map(OTHER_QUEUE, 0x20)
        machine.put(OTHER_QUEUE, 4, 4)
        machine.put(GATE, 1, 4)
        machine.packet_address = 0
        self.assertEqual(machine.stock(WRITE, OTHER_QUEUE, OUTPUT, 8), 0xFFFFFFFF)
        self.assertEqual(machine.r[3], 12)
        self.assertEqual([machine.get(OTHER_QUEUE + offset, 4) for offset in (4, 8, 12, 16)],
                         [0] * 4)
        self.assertEqual(machine.copy_calls, [])
        self.assertEqual(machine.get(GATE, 4), 1)
        self.assertEqual(machine.releases, [])


if __name__ == '__main__':
    unittest.main()
