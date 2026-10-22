#!/usr/bin/env python3
"""Execute private native-scope instructions; not a cache/native-thread proof."""

import struct
import random
import unittest

import reveal_native_scope_mips as scope
import test_reveal_lineage_rows_mips as harness


SCOPE, CODE, RETURN, STACK = 0x800000, harness.CODE, harness.RETURN, harness.STACK
FRAME, ARG0, ARG1, MASK = 0xBAD10000, 0xBAD20000, 0xBAD30000, 0xFFFFFFFF


class Memory(harness.Memory):
    def __init__(self, capacity=32):
        self.capacity, self.regions, self.accesses, self.version = capacity, {}, [], 0
        self.map(SCOPE, scope.memory_bytes(capacity))

    def write(self, address, value, size=4):
        super().write(address, value, size)
        self.version += 1


class ScopeMachine(harness.RowsMachine):
    def __init__(self, shared=None, *, capacity=32):
        self.shared = shared if shared is not None else Memory(capacity)
        self.code, self.labels = scope.assemble(SCOPE, CODE, self.shared.capacity)
        self.words = struct.unpack('<%dI' % (len(self.code) // 4), self.code)
        self.r = [0] + [0x11000000 + reg for reg in range(1, 32)]
        self.r[29], self.r[31] = STACK, RETURN
        self.hi, self.lo = 0x13579BDF, 0x2468ACE0
        self.reservation = None
        self.sc_failures = self.sc_attempts = 0
        self.pc, self.delay_target, self.steps = RETURN, None, 0
        self.trace, self.calls = [], []

    def begin(self, kind=scope.RESET, frame=FRAME, arg0=ARG0, arg1=ARG1):
        return self.call('begin', kind, frame, arg0, arg1)

    def end(self, ticket=1, kind=scope.RESET, frame=FRAME, result=0):
        return self.call('end', ticket, kind, frame, result)

    @staticmethod
    def record_address(ticket):
        return SCOPE + scope.HEADER + (ticket - 1) * scope.RECORD

    def record(self, ticket):
        start = scope.HEADER + (ticket - 1) * scope.RECORD
        return bytes(self.shared.regions[SCOPE][start:start + scope.RECORD])


class NativeScopeCoreTests(unittest.TestCase):
    def test_exact_schema_and_one_shot_actual_result(self):
        m = ScopeMachine()
        self.assertEqual(m.begin(), 1)
        self.assertEqual(m.shared.read(SCOPE), 0x10001)
        self.assertEqual(struct.unpack('<8I', m.record(1)),
                         (scope.MAGIC, scope.RESET, 1, FRAME, ARG0, ARG1, scope.OPEN, 0))
        self.assertEqual(m.end(result=-1), 0)
        self.assertEqual(m.shared.read(SCOPE), 1)
        self.assertEqual(struct.unpack('<8I', m.record(1)),
                         (scope.MAGIC, scope.RESET, 1, FRAME, ARG0, ARG1, scope.CLOSED, MASK))
        self.assertEqual(m.shared.regions[SCOPE][4:16], bytes(12))

    def test_raw_arguments_are_not_pointers_and_both_kinds_are_supported(self):
        for kind in (scope.RESET, scope.RECONCILE):
            m = ScopeMachine()
            self.assertEqual(m.begin(kind, arg0=0, arg1=MASK), 1)
            self.assertEqual(m.end(kind=kind, result=0x80000000), 0)
            self.assertEqual(m.field(1, scope.RAWARG0), 0)
            self.assertEqual(m.field(1, scope.RAWARG1), MASK)
            self.assertEqual(m.field(1, scope.RESULT), 0x80000000)
            self.assertTrue(all(SCOPE <= address < SCOPE + scope.memory_bytes(m.shared.capacity)
                                for _, address, _ in m.shared.accesses))

    def test_nested_and_overlapping_scopes_close_in_any_order(self):
        m = ScopeMachine()
        tokens = [m.begin(kind=1 + i % 2, frame=FRAME + i * 4) for i in range(8)]
        self.assertEqual(tokens, list(range(1, 9)))
        self.assertEqual(m.shared.read(SCOPE), 0x80008)
        for left, i in enumerate((7, 0, 6, 1, 5, 2, 4, 3)):
            m.end(i + 1, 1 + i % 2, FRAME + i * 4, i)
            self.assertEqual(m.shared.read(SCOPE), ((7 - left) << 16) | 8)
        self.assertTrue(all(m.field(i, scope.STATUS) == scope.CLOSED for i in tokens))

    def test_invalid_begin_kind_or_frame_faults_before_issuance(self):
        for kind, frame in ((0, FRAME), (3, FRAME), (MASK, FRAME), (1, 0), (1, FRAME + 1)):
            m = ScopeMachine()
            self.assertEqual(m.begin(kind, frame), 0)
            self.assertEqual(m.shared.read(SCOPE), scope.FAULT)
            self.assertEqual(m.record(1), bytes(scope.RECORD))

    def test_malformed_packed_state_and_terminal_fault_are_sticky(self):
        for state in (0x80000000, 0x80000001, MASK, 33, 0x10000, 0x20001, 0x10021):
            for entry in ('begin', 'end'):
                m = ScopeMachine()
                m.shared.write(SCOPE, state)
                args = (1, FRAME, ARG0, ARG1) if entry == 'begin' else (1, 1, FRAME, 0)
                self.assertEqual(m.call(entry, *args), 0)
                self.assertEqual(m.shared.read(SCOPE), scope.FAULT)
                self.assertEqual(m.begin(), 0)
                self.assertEqual(m.shared.read(SCOPE), scope.FAULT)

    def test_capacity_exhaustion_is_permanent_even_after_every_scope_closed(self):
        for capacity in (1, 2, 32, 1024):
            m = ScopeMachine(capacity=capacity)
            for ticket in range(1, capacity + 1):
                self.assertEqual(m.begin(), ticket)
                m.end(ticket)
                self.assertEqual(m.shared.read(SCOPE), ticket)
            first = m.record(1)
            self.assertEqual(m.begin(), 0)
            self.assertEqual(m.shared.read(SCOPE), scope.FAULT)
            self.assertEqual(m.begin(), 0)
            self.assertEqual(m.record(1), first)

    def test_ticket_and_active_boundaries_never_wrap(self):
        m = ScopeMachine(capacity=scope.MAX_CAPACITY)
        m.shared.write(SCOPE, scope.MAX_CAPACITY - 1)
        self.assertEqual(m.begin(), scope.MAX_CAPACITY)
        self.assertEqual(m.shared.read(SCOPE), 0x1FFFF)
        m.end(scope.MAX_CAPACITY)
        self.assertEqual(m.shared.read(SCOPE), 0xFFFF)
        self.assertEqual(m.begin(), 0)
        self.assertEqual(m.shared.read(SCOPE), scope.FAULT)
        for active in (scope.ACTIVE_MAX - 1, scope.ACTIVE_MAX):
            m = ScopeMachine(capacity=scope.MAX_CAPACITY)
            m.shared.write(SCOPE, (active << 16) | scope.ACTIVE_MAX)
            token = m.begin()
            self.assertEqual(token, scope.ACTIVE_MAX + 1 if active < scope.ACTIVE_MAX else 0)
            self.assertEqual(m.shared.read(SCOPE), 0x7FFF8000 if token else scope.FAULT)

    def test_wrong_unissued_duplicate_or_foreign_end_faults(self):
        for ticket, kind, frame in ((0, 1, FRAME), (2, 1, FRAME), (MASK, 1, FRAME),
                                    (1, 0, FRAME), (1, 3, FRAME), (1, 2, FRAME),
                                    (1, 1, 0), (1, 1, FRAME + 1), (1, 1, FRAME + 4)):
            m = ScopeMachine()
            m.begin()
            self.assertEqual(m.end(ticket, kind, frame), 0)
            self.assertEqual(m.shared.read(SCOPE), scope.FAULT)
            self.assertEqual(m.field(1, scope.STATUS), scope.OPEN)
        m = ScopeMachine()
        m.begin()
        m.end(result=17)
        saved = m.record(1)
        m.end(result=99)
        self.assertEqual(m.shared.read(SCOPE), scope.FAULT)
        self.assertEqual(m.record(1), saved)

    def test_corrupt_or_unpublished_slot_and_nonopen_status_are_rejected(self):
        for offset, value in ((scope.MAGIC_OFFSET, 0), (scope.MAGIC_OFFSET, scope.MAGIC ^ 1),
                              (scope.KIND, 2), (scope.TICKET, 2), (scope.FRAME, FRAME + 4),
                              (scope.STATUS, 0), (scope.STATUS, scope.CLOSING),
                              (scope.STATUS, scope.CLOSED), (scope.STATUS, MASK)):
            m = ScopeMachine()
            m.begin()
            m.shared.write(m.record_address(1) + offset, value)
            m.end(result=99)
            self.assertEqual(m.shared.read(SCOPE), scope.FAULT)
            self.assertEqual(m.field(1, scope.RESULT), 0)

    def test_nonzero_destination_magic_cannot_be_reused(self):
        m = ScopeMachine()
        m.shared.write(m.record_address(1), scope.MAGIC)
        m.begin()
        self.assertEqual(m.shared.read(SCOPE), scope.FAULT)
        self.assertEqual(m.field(1, scope.KIND), 0)

    def test_atomic_active_issuance_precedes_any_slot_publication(self):
        shared = Memory()
        paused, other = ScopeMachine(shared), ScopeMachine(shared)
        paused.start('begin', 1, FRAME, ARG0, ARG1).until('begin_reserved')
        self.assertEqual(shared.read(SCOPE), 0x10001)
        self.assertEqual(paused.record(1), bytes(scope.RECORD))
        self.assertEqual(other.begin(2, FRAME + 4), 2)
        other.end(2, 2, FRAME + 4)
        self.assertEqual(shared.read(SCOPE), 0x10002)
        self.assertEqual(paused.run_to_return(), 1)
        self.assertEqual(paused.field(1, scope.TICKET), 1)
        paused.end(1)
        self.assertEqual(shared.read(SCOPE), 2)

    def test_begin_returns_own_ticket_not_later_global_issued_value(self):
        shared = Memory()
        paused, other = ScopeMachine(shared), ScopeMachine(shared)
        paused.start('begin', 1, FRAME, ARG0, ARG1).until('begin_publish')
        self.assertEqual(other.begin(2, FRAME + 4), 2)
        self.assertEqual(paused.run_to_return(), 1)
        self.assertEqual(shared.read(SCOPE), 0x20002)

    def test_end_of_issued_but_unpublished_begin_faults_and_never_becomes_quiet(self):
        shared = Memory()
        paused, other = ScopeMachine(shared), ScopeMachine(shared)
        paused.start('begin', 1, FRAME, ARG0, ARG1).until('begin_reserved')
        self.assertEqual(other.end(1), 0)
        self.assertEqual(shared.read(SCOPE), scope.FAULT)
        self.assertEqual(paused.run_to_return(), 0)
        self.assertEqual(shared.read(SCOPE), scope.FAULT)
        self.assertEqual(paused.field(1, scope.MAGIC_OFFSET), 0)

    def test_two_context_random_instruction_interleavings_keep_exact_count(self):
        for seed in range(40):
            rng, shared = random.Random(seed), Memory()
            contexts = [ScopeMachine(shared), ScopeMachine(shared)]
            for index, machine in enumerate(contexts):
                machine.start('begin', index + 1, FRAME + index * 4, ARG0 + index, ARG1)
            while any(machine.pc != RETURN for machine in contexts):
                rng.choice([machine for machine in contexts if machine.pc != RETURN]).step()
            tickets = [machine.r[2] for machine in contexts]
            self.assertEqual(sorted(tickets), [1, 2], seed)
            self.assertEqual(shared.read(SCOPE), 0x20002, seed)
            for index, machine in enumerate(contexts):
                machine.start('end', tickets[index], index + 1, FRAME + index * 4, 17 + index)
            while any(machine.pc != RETURN for machine in contexts):
                rng.choice([machine for machine in contexts if machine.pc != RETURN]).step()
            self.assertEqual(shared.read(SCOPE), 2, seed)
            for index, ticket in enumerate(tickets):
                self.assertEqual(contexts[index].field(ticket, scope.RESULT), 17 + index)
                self.assertEqual(contexts[index].field(ticket, scope.STATUS), scope.CLOSED)

    def test_competing_begin_reservations_issue_unique_tickets(self):
        shared = Memory()
        a, other = ScopeMachine(shared), ScopeMachine(shared)
        a.start('begin', 1, FRAME, ARG0, ARG1).until('begin_sc')
        other.start('begin', 2, FRAME + 4, 0, MASK).until('begin_sc')
        self.assertEqual(a.run_to_return(), 1)
        self.assertEqual(other.run_to_return(), 2)
        self.assertEqual(shared.read(SCOPE), 0x20002)
        self.assertEqual((a.field(1, scope.FRAME), other.field(2, scope.FRAME)), (FRAME, FRAME + 4))

    def test_two_different_closures_retry_state_without_lost_decrement(self):
        shared = Memory()
        a, other = ScopeMachine(shared), ScopeMachine(shared)
        a.begin()
        other.begin(2, FRAME + 4)
        a.start('end', 1, 1, FRAME, 17).until('end_state_sc')
        other.start('end', 2, 2, FRAME + 4, 23).until('end_state_sc')
        self.assertEqual(shared.read(SCOPE), 0x20002)
        self.assertEqual((a.field(1, scope.STATUS), a.field(2, scope.STATUS)), (3, 3))
        a.run_to_return()
        self.assertEqual(shared.read(SCOPE), 0x10002)
        other.run_to_return()
        self.assertEqual(shared.read(SCOPE), 2)
        self.assertEqual((a.field(1, scope.RESULT), a.field(2, scope.RESULT)), (17, 23))

    def test_duplicate_concurrent_end_cannot_decrement_twice(self):
        shared = Memory()
        a, other = ScopeMachine(shared), ScopeMachine(shared)
        a.begin()
        a.begin(2, FRAME + 4)
        a.start('end', 1, 1, FRAME, 17).until('end_status_sc')
        other.start('end', 1, 1, FRAME, 99).until('end_status_sc')
        a.run_to_return()
        self.assertEqual(shared.read(SCOPE), 0x10002)
        other.run_to_return()
        self.assertEqual(shared.read(SCOPE), scope.FAULT)
        self.assertEqual(a.field(1, scope.RESULT), 17)
        self.assertEqual(a.field(2, scope.STATUS), scope.OPEN)

    def test_closing_is_visible_before_result_and_active_remains_until_decrement(self):
        m = ScopeMachine()
        m.begin()
        m.start('end', 1, 1, FRAME, 0x80000000).until('end_claimed')
        self.assertEqual(m.field(1, scope.STATUS), scope.CLOSING)
        self.assertEqual(m.field(1, scope.RESULT), 0)
        self.assertEqual(m.shared.read(SCOPE), 0x10001)
        m.until('end_state_ll')
        self.assertEqual(m.field(1, scope.STATUS), scope.CLOSED)
        self.assertEqual(m.field(1, scope.RESULT), 0x80000000)
        self.assertEqual(m.shared.read(SCOPE), 0x10001)
        m.run_to_return()
        self.assertEqual(m.shared.read(SCOPE), 1)

    def test_closure_only_changes_its_status_result_and_packed_count(self):
        m = ScopeMachine()
        m.begin()
        identity = m.record(1)[:scope.STATUS]
        m.shared.accesses.clear()
        m.end(result=23)
        self.assertEqual(m.record(1)[:scope.STATUS], identity)
        writes = [(address, size) for kind, address, size in m.shared.accesses if kind == 'write']
        self.assertEqual(writes, [(m.record_address(1) + scope.STATUS, 4),
                                  (m.record_address(1) + scope.RESULT, 4),
                                  (m.record_address(1) + scope.STATUS, 4), (SCOPE, 4)])

    def test_fault_or_corrupt_counter_after_claim_never_releases_active_scope(self):
        for packed in (scope.FAULT, 0, 1, 0x20001, 0x10021):
            m = ScopeMachine()
            m.begin()
            m.start('end', 1, 1, FRAME, 17).until('end_state_ll')
            m.shared.write(SCOPE, packed)
            m.run_to_return()
            self.assertEqual(m.shared.read(SCOPE), scope.FAULT)
            self.assertEqual(m.field(1, scope.STATUS), scope.CLOSED)
            self.assertEqual(m.field(1, scope.RESULT), 17)

    def test_retry_budget_for_begin_status_and_state_decrement(self):
        for entry in ('begin_ll', 'end_status_ll', 'end_state_ll'):
            for failures in (7, 8):
                m = ScopeMachine()
                if entry == 'begin_ll':
                    m.start('begin', 1, FRAME, ARG0, ARG1).until(entry)
                else:
                    m.begin()
                    m.start('end', 1, 1, FRAME, 17).until(entry)
                attempts = m.sc_attempts
                m.sc_failures = failures
                m.run_to_return()
                expected_attempts = 9 if entry == 'end_status_ll' and failures == 7 else 8
                self.assertEqual(m.sc_attempts - attempts, expected_attempts)
                expected = scope.FAULT if failures == 8 else (0x10001 if entry == 'begin_ll' else 1)
                self.assertEqual(m.shared.read(SCOPE), expected)

    def test_invalidation_at_every_begin_and_end_instruction_never_clears_fault(self):
        for entry in ('begin', 'end'):
            probe = ScopeMachine()
            if entry == 'end':
                probe.begin()
            args = (1, FRAME, ARG0, ARG1) if entry == 'begin' else (1, 1, FRAME, 17)
            probe.call(entry, *args)
            for boundary in range(len(probe.trace) + 1):
                with self.subTest(entry=entry, boundary=boundary):
                    shared = Memory()
                    a, invalidator = ScopeMachine(shared), ScopeMachine(shared)
                    if entry == 'end':
                        a.begin()
                    a.start(entry, *args)
                    for _ in range(boundary):
                        a.step()
                    invalidator.call('invalidate')
                    a.run_to_return()
                    self.assertEqual(shared.read(SCOPE), scope.FAULT)
                    self.assertEqual(invalidator.begin(), 0)
                    self.assertEqual(shared.read(SCOPE), scope.FAULT)

    def test_abi_no_native_access_or_calls_and_v0_is_not_restored(self):
        for entry, args in (('begin', (1, FRAME, ARG0, ARG1)),
                            ('end', (1, 1, FRAME, 17)),
                            ('end', (1, 2, FRAME, 17)), ('invalidate', ())):
            m = ScopeMachine()
            if entry == 'end':
                m.begin()
            before, hi, lo = m.r.copy(), m.hi, m.lo
            m.shared.accesses.clear()
            m.call(entry, *args)
            for register in (*range(16, 24), 26, 27, 28, 29, 30, 31):
                self.assertEqual(m.r[register], before[register], (entry, register))
            self.assertEqual((m.hi, m.lo), (hi, lo))
            self.assertEqual(m.calls, [])
            self.assertNotEqual(m.r[2], before[2])
            self.assertTrue(all(SCOPE <= address < SCOPE + scope.memory_bytes(m.shared.capacity)
                                for _, address, _ in m.shared.accesses))

    def test_magic_last_publication_and_only_fault_plain_state_store(self):
        m = ScopeMachine()
        m.begin()
        slot_writes = [(address, size) for kind, address, size in m.shared.accesses
                       if kind == 'write' and m.record_address(1) <= address < m.record_address(2)]
        self.assertEqual(slot_writes[-1], (m.record_address(1), 4))
        state_stores = [(CODE + i * 4, word >> 26) for i, word in enumerate(m.words)
                        if word >> 26 in (0x2B, 0x38) and (word >> 21) & 31 == 8
                        and word & 0xFFFF == 0]
        # Includes the status CAS via t0=slot+24, but no healthy plain state store.
        self.assertEqual([op for _, op in state_stores], [0x38, 0x38, 0x38, 0x2B])
        self.assertEqual(state_stores[-1][0], m.labels['fault_store'])

    def test_all_control_transfers_are_internal_and_no_sneaky_instruction(self):
        m = ScopeMachine()
        for index, word in enumerate(m.words):
            op, rs = word >> 26, (word >> 21) & 31
            self.assertIn(op, (0, 2, 4, 5, 9, 11, 12, 13, 15, 35, 43, 48, 56))
            if op == 2:
                target = ((CODE + index * 4 + 4) & 0xF0000000) | ((word & 0x3FFFFFF) << 2)
                self.assertTrue(CODE <= target < CODE + len(m.code))
                self.assertEqual(m.words[index + 1], 0)
            if op == 0:
                self.assertIn(word & 63, (0, 2, 8, 15, 0x21, 0x2B))
                if word & 63 == 8:
                    self.assertEqual(rs, 31)
                    self.assertEqual(m.words[index + 1], 0)

    def test_layout_types_capacities_wrap_jump_region_and_overlap(self):
        self.assertEqual(scope.memory_bytes(), 32784)
        self.assertEqual(scope.MAGIC.to_bytes(4, 'little'), b'LSCP')
        for capacity in (0, -1, True, 1.0, scope.MAX_CAPACITY + 1):
            with self.assertRaises(ValueError):
                scope.memory_bytes(capacity)
            with self.assertRaises(ValueError):
                scope.assemble(SCOPE, CODE, capacity)
        for name, values in (('scope_address', (True, 1, -4, 0x100000000, 0xFFFFFFFC, CODE)),
                             ('code_base', (True, 1, -4, 0x100000000, 0xFFFFFFFC, SCOPE, 0x0FFFFE00))):
            for value in values:
                args = dict(scope_address=SCOPE, code_base=CODE)
                args[name] = value
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    scope.assemble(**args)


if __name__ == '__main__':
    unittest.main()
