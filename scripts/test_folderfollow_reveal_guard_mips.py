#!/usr/bin/env python3
"""Execute emitted guard instructions with shared-memory LL/SC interleavings.

This is an instruction/ABI contract test, not a CPU cache or firmware-thread
model. Reservation versions model coherent stores invalidating LL/SC. SYNC is
checked structurally, not used to claim target hardware ordering is proven.
"""

import struct
import unittest

import folderfollow_reveal_guard_mips as guard
from test_reveal_bridge_hooks import HookMachine


STATE, CODE, RETURN = 0xBD4000, 0xC70000, 0xDEAD0000
MASK = 0xFFFFFFFF


class SharedWord:
    def __init__(self, value=0):
        self.value = value
        self.version = 0
        self.accesses = []

    def read(self, address, size):
        if (address, size) != (STATE, 4):
            raise AssertionError('nonprivate read')
        self.accesses.append(('read', address, size))
        return self.value

    def write(self, address, value, size):
        if (address, size) != (STATE, 4):
            raise AssertionError('nonprivate write')
        self.accesses.append(('write', address, size))
        self.value = value & MASK
        self.version += 1


class GuardMachine(HookMachine):
    """Reuse arithmetic helpers; replace LL/SC and all control-flow handling."""
    def __init__(self, shared=None, *, limit=guard.REVISION_MASK, retries=8):
        self.shared = shared if shared is not None else SharedWord()
        self.code, self.labels = guard.build_guard(
            STATE, CODE, revision_limit=limit, retries=retries)
        self.words = struct.unpack('<%dI' % (len(self.code) // 4), self.code)
        self.r = [0] + [0x11000000 + r for r in range(1, 32)]
        self.r[31] = RETURN
        self.hi, self.lo = 0x13579BDF, 0x2468ACE0
        self.reservation = None
        self.sc_failures = 0
        self.pc = RETURN
        self.delay_target = None
        self.steps = 0
        self.sc_attempts = 0
        self.trace = []

    def get(self, address, size):
        return self.shared.read(address, size)

    def put(self, address, value, size):
        self.shared.write(address, value, size)

    def plain(self, word):
        op, rs, rt, rd = word >> 26, (word >> 21) & 31, (word >> 16) & 31, (word >> 11) & 31
        imm = word & 0xFFFF
        signed = imm - 0x10000 if imm & 0x8000 else imm
        address = (self.r[rs] + signed) & MASK
        if op == 0x30:
            self.r[rt] = self.get(address, 4)
            self.reservation = (address, self.shared.version)
        elif op == 0x38:
            self.sc_attempts += 1
            succeeds = self.reservation == (address, self.shared.version)
            if self.sc_failures:
                self.sc_failures -= 1
                succeeds = False
            value = self.r[rt]
            self.reservation = None
            if succeeds:
                self.put(address, value, 4)
            self.r[rt] = int(succeeds)
        elif op == 0 and word & 63 == 2:
            self.r[rd] = self.r[rt] >> ((word >> 6) & 31)
        elif op == 0 and word & 63 == 0x2B:
            self.r[rd] = int(self.r[rs] < self.r[rt])
        else:
            return super().plain(word)
        self.r[0] = 0

    def start(self, entry, ticket=0):
        if self.pc != RETURN:
            raise AssertionError('context is already executing')
        self.r[4] = ticket & MASK
        self.pc = self.labels[entry]
        self.delay_target = None
        return self

    def step(self):
        if self.pc == RETURN:
            return False
        if not CODE <= self.pc < CODE + len(self.code) or self.pc % 4:
            raise AssertionError('unexpected transfer ' + hex(self.pc))
        self.steps += 1
        if self.steps > 10000:
            raise AssertionError('execution budget exceeded')
        word = self.words[(self.pc - CODE) // 4]
        self.trace.append((self.pc, word))
        op, rs, rt = word >> 26, (word >> 21) & 31, (word >> 16) & 31
        if self.delay_target is not None:
            if op in (2, 3, 4, 5) or (op == 0 and word & 63 in (8, 9)):
                raise AssertionError('control transfer in delay slot')
            target, self.delay_target = self.delay_target, None
            self.plain(word)
            self.pc = target
        elif op in (4, 5):
            taken = (self.r[rs] == self.r[rt]) == (op == 4)
            offset = word & 0xFFFF
            offset -= 0x10000 if offset & 0x8000 else 0
            self.delay_target = self.pc + 4 + offset * 4 if taken else self.pc + 8
            self.pc += 4
        elif op == 2 or (op == 0 and word & 63 == 8):
            target = (((self.pc + 4) & 0xF0000000) | ((word & 0x3FFFFFF) << 2)
                      if op == 2 else self.r[rs])
            if target != RETURN and not CODE <= target < CODE + len(self.code):
                raise AssertionError('external transfer')
            self.delay_target, self.pc = target, self.pc + 4
        elif op == 3 or (op == 0 and word & 63 == 9):
            raise AssertionError('linked/external call is forbidden')
        else:
            self.plain(word)
            self.pc += 4
        return True

    def until(self, label):
        target = self.labels[label]
        while self.pc != target:
            if not self.step():
                raise AssertionError('returned before requested label')
        return self

    def run_to_return(self):
        while self.step():
            pass
        return self.r[2]

    def call(self, entry, ticket=0):
        self.start(entry, ticket)
        return self.run_to_return()


class GuardTests(unittest.TestCase):
    def test_zero_initialized_begin_finish_and_monotonic_tickets(self):
        m = GuardMachine()
        self.assertEqual(m.shared.value, guard.EMPTY)
        for expected in range(1, 20):
            self.assertEqual(m.call('begin'), expected)
            self.assertEqual(m.shared.value, guard.WRITER_MASK | expected)
            self.assertEqual(m.call('finish', expected), 1)
            self.assertEqual(m.shared.value, expected)

    def test_no_identity_input_means_same_value_mutation_still_changes_ticket(self):
        m = GuardMachine()
        first = m.call('begin')
        m.call('finish', first)
        second = m.call('begin')
        self.assertEqual((first, second), (1, 2))
        self.assertEqual(m.call('finish', first), 0)
        self.assertEqual(m.shared.value, guard.FAULT)

    def test_overlapping_writer_and_all_later_operations_fault(self):
        shared = SharedWord()
        a, b = GuardMachine(shared), GuardMachine(shared)
        ticket = a.call('begin')
        self.assertEqual(b.call('begin'), 0)
        self.assertEqual(shared.value, guard.FAULT)
        for operation, ticket in (('finish', ticket), ('begin', 0), ('invalidate', 0)):
            self.assertEqual(a.call(operation, ticket), 0)
            self.assertEqual(shared.value, guard.FAULT)

    def test_wrong_duplicate_and_unissued_finish_fault(self):
        for ticket in (0, 2, 0xFFFFFFFF, 0x80000000):
            m = GuardMachine()
            m.call('begin')
            self.assertEqual(m.call('finish', ticket), 0)
            self.assertEqual(m.shared.value, guard.FAULT)
        for state in (guard.EMPTY, 1, 2, guard.FAULT):
            m = GuardMachine(SharedWord(state))
            self.assertEqual(m.call('finish', 1), 0)
            self.assertEqual(m.shared.value, guard.FAULT)

    def test_revision_exhaustion_never_wraps(self):
        for limit in (1, 2, 3, guard.REVISION_MASK):
            m = GuardMachine(SharedWord(limit - 1), limit=limit)
            self.assertEqual(m.call('begin'), limit)
            self.assertEqual(m.call('finish', limit), 1)
            self.assertEqual(m.call('begin'), 0)
            self.assertEqual(m.shared.value, guard.FAULT)
            self.assertEqual(m.call('begin'), 0)

    def test_out_of_configuration_state_and_ticket_fault(self):
        m = GuardMachine(SharedWord(4), limit=3)
        self.assertEqual(m.call('begin'), 0)
        self.assertEqual(m.shared.value, guard.FAULT)
        m = GuardMachine(SharedWord(guard.WRITER_MASK | 4), limit=3)
        self.assertEqual(m.call('finish', 4), 0)
        self.assertEqual(m.shared.value, guard.FAULT)

    def test_bounded_sc_failure_begin_and_finish(self):
        for retries in (1, 2, 8):
            for operation in ('begin', 'finish'):
                initial = 0 if operation == 'begin' else guard.WRITER_MASK | 1
                m = GuardMachine(SharedWord(initial), retries=retries)
                m.sc_failures = retries
                self.assertEqual(m.call(operation, 1), 0)
                self.assertEqual(m.sc_attempts, retries)
                self.assertEqual(m.shared.value, guard.FAULT)
                self.assertLess(m.steps, 300)

    def test_transient_sc_failure_retries_with_fresh_reservation(self):
        for operation in ('begin', 'finish'):
            initial = 0 if operation == 'begin' else guard.WRITER_MASK | 1
            m = GuardMachine(SharedWord(initial))
            m.sc_failures = 7
            self.assertEqual(m.call(operation, 1), 1)
            self.assertEqual(m.sc_attempts, 8)
            self.assertEqual(m.shared.value, guard.WRITER_MASK | 1 if operation == 'begin' else 1)

    def test_invalidate_between_ll_and_sc_cannot_be_overwritten(self):
        for operation in ('begin', 'finish'):
            initial = 0 if operation == 'begin' else guard.WRITER_MASK | 1
            shared = SharedWord(initial)
            a, invalidator = GuardMachine(shared), GuardMachine(shared)
            a.start(operation, 1).until(operation + '_sc')
            self.assertIsNotNone(a.reservation)
            self.assertEqual(invalidator.call('invalidate'), 0)
            self.assertEqual(a.run_to_return(), 0)
            self.assertEqual(shared.value, guard.FAULT)

    def test_competing_begin_at_sc_faults_both_completed_contexts(self):
        shared = SharedWord()
        a, b = GuardMachine(shared), GuardMachine(shared)
        a.start('begin').until('begin_sc')
        b.start('begin').until('begin_sc')
        self.assertEqual(a.run_to_return(), 1)
        self.assertEqual(b.run_to_return(), 0)
        self.assertEqual(shared.value, guard.FAULT)
        self.assertEqual(a.call('finish', 1), 0)

    def test_two_finish_calls_cannot_both_publish(self):
        shared = SharedWord(guard.WRITER_MASK | 1)
        a, b = GuardMachine(shared), GuardMachine(shared)
        a.start('finish', 1).until('finish_sc')
        b.start('finish', 1).until('finish_sc')
        self.assertEqual(a.run_to_return(), 1)
        self.assertEqual(b.run_to_return(), 0)
        self.assertEqual(shared.value, guard.FAULT)

    def test_invalidation_at_every_instruction_never_resurrects_ready(self):
        # Suspend immediately before every instruction on an ordinary call's
        # path, execute invalidate to completion, then resume the suspended call.
        # A post-SC invalidation may coexist with a successful return; that
        # historical result never grants a lease or restores the atomic state.
        for operation in ('begin', 'finish'):
            initial = 0 if operation == 'begin' else guard.WRITER_MASK | 1
            probe = GuardMachine(SharedWord(initial))
            probe.call(operation, 1)
            for before_step in range(len(probe.trace) + 1):
                with self.subTest(operation=operation, before_step=before_step):
                    shared = SharedWord(initial)
                    a, invalidator = GuardMachine(shared), GuardMachine(shared)
                    a.start(operation, 1)
                    for _ in range(before_step):
                        a.step()
                    invalidator.call('invalidate')
                    a.run_to_return()
                    self.assertEqual(shared.value, guard.FAULT)
                    self.assertEqual(a.call('begin'), 0)

    def test_fault_store_after_successful_sc_still_withdraws(self):
        shared = SharedWord(guard.WRITER_MASK | 1)
        a, invalidator = GuardMachine(shared), GuardMachine(shared)
        invalidator.start('invalidate').until('fault_store')
        self.assertEqual(a.call('finish', 1), 1)
        self.assertEqual(shared.value, 1)
        invalidator.run_to_return()
        self.assertEqual(shared.value, guard.FAULT)

    def test_abi_and_private_memory_only_on_every_entry(self):
        for entry, initial, ticket in (('begin', 0, 0), ('finish', guard.WRITER_MASK | 1, 1),
                                       ('finish', 0, 1), ('invalidate', 1, 0)):
            m = GuardMachine(SharedWord(initial))
            m.r[4] = ticket
            before, hi, lo = m.r.copy(), m.hi, m.lo
            m.call(entry, ticket)
            for reg in (1, 3, *range(4, 8), *range(15, 32)):
                self.assertEqual(m.r[reg], before[reg], (entry, reg))
            self.assertEqual((m.hi, m.lo), (hi, lo))
            self.assertTrue(m.shared.accesses)
            self.assertEqual({(address, size) for _, address, size in m.shared.accesses}, {(STATE, 4)})

    def test_sync_brackets_each_state_store_and_success_path(self):
        m = GuardMachine()
        words = m.words
        for entry in ('begin', 'finish', 'invalidate'):
            index = (m.labels[entry] - CODE) // 4
            self.assertIn(guard.SYNC, words[index:index + 10])
        for label in ('begin_success', 'finish_success', 'fault_store'):
            index = (m.labels[label] - CODE) // 4
            self.assertIn(guard.SYNC, words[index:index + 4])
        fault_index = (m.labels['fault_store'] - CODE) // 4
        self.assertEqual(words[fault_index - 1], guard.SYNC)
        self.assertEqual(words[fault_index + 1], guard.SYNC)

    def test_entire_emission_has_only_known_instructions_and_internal_targets(self):
        m = GuardMachine()
        for index, word in enumerate(m.words):
            pc, op = CODE + index * 4, word >> 26
            if op in (4, 5):
                imm = word & 0xFFFF
                imm -= 0x10000 if imm & 0x8000 else 0
                self.assertTrue(CODE <= pc + 4 + 4 * imm < CODE + len(m.code))
                self.assertEqual(m.words[index + 1], 0)
            elif op == 2:
                target = ((pc + 4) & 0xF0000000) | ((word & 0x3FFFFFF) << 2)
                self.assertTrue(CODE <= target < CODE + len(m.code))
                self.assertEqual(m.words[index + 1], 0)
            elif op == 0:
                self.assertIn(word & 63, (0, 2, 8, 15, 0x21, 0x2B))
                if word & 63 == 8:
                    self.assertEqual((word >> 21) & 31, 31)
                    self.assertEqual(m.words[index + 1], 0)
            else:
                self.assertIn(op, (9, 13, 15, 0x2B, 0x30, 0x38))
                if op in (0x2B, 0x30, 0x38):
                    self.assertEqual(((word >> 21) & 31, word & 0xFFFF), (8, 0))

    def test_configuration_rejects_bad_layout_and_bounds(self):
        for name, values in (('state_address', (-4, 1, True, 0x100000000, CODE)),
                             ('code_base', (-4, 1, True, 0x100000000, 0xFFFFFFFC, 0x0FFFFFFC, STATE)),
                             ('revision_limit', (0, -1, True, 0x80000000)),
                             ('retries', (0, -1, True, 32768))):
            for value in values:
                kwargs = dict(state_address=STATE, code_base=CODE)
                kwargs[name] = value
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    guard.build_guard(**kwargs)


if __name__ == '__main__':
    unittest.main()
