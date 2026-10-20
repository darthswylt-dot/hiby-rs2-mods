#!/usr/bin/env python3
"""Execute the private diagnostic clock, not a contents completion model.

The module-qualified emulator models stores invalidating LL/SC reservations.
SYNC is checked structurally; neither caches nor native lifetimes are modeled.
"""

import struct
import unittest

import reveal_contents_revision_mips as revision
import test_folderfollow_reveal_guard_mips as guard_harness


STATE, CODE, RETURN = guard_harness.STATE, guard_harness.CODE, guard_harness.RETURN
MASK = 0xFFFFFFFF


class SharedState:
    def __init__(self, counter=0):
        self.data = bytearray(revision.memory_bytes())
        struct.pack_into('<I', self.data, 0, counter)
        self.version = 0
        self.accesses = []

    def offset(self, address, size):
        if size != 4 or address % 4 or not STATE <= address <= STATE + 12:
            raise AssertionError('nonprivate or unaligned access ' + hex(address))
        return address - STATE

    def read(self, address, size=4):
        offset = self.offset(address, size)
        self.accesses.append(('read', address, size))
        return struct.unpack_from('<I', self.data, offset)[0]

    def write(self, address, value, size=4):
        offset = self.offset(address, size)
        self.accesses.append(('write', address, size))
        struct.pack_into('<I', self.data, offset, value & MASK)
        self.version += 1

    @property
    def counter(self):
        return self.read(STATE)


class RevisionMachine(guard_harness.GuardMachine):
    def __init__(self, shared=None, *, limit=revision.REVISION_MASK, retries=8):
        self.shared = shared if shared is not None else SharedState()
        self.code, self.labels = revision.build_revision(
            STATE, CODE, revision_limit=limit, retries=retries)
        self.words = struct.unpack('<%dI' % (len(self.code) // 4), self.code)
        self.r = [0] + [0x11000000 + r for r in range(1, 32)]
        self.r[31] = RETURN
        self.hi, self.lo = 0x13579BDF, 0x2468ACE0
        self.reservation = None
        self.sc_failures = self.sc_attempts = 0
        self.pc = RETURN
        self.delay_target = None
        self.steps = 0
        self.trace = []

    def start(self, entry, ticket=0):
        self.steps = 0
        self.trace = []
        return super().start(entry, ticket)


class RevisionTests(unittest.TestCase):
    def test_zero_state_and_sequential_bumps_never_need_finish(self):
        m = RevisionMachine()
        self.assertEqual(m.shared.counter, 0)
        for expected in range(1, 101):
            self.assertEqual(m.call('bump'), expected)
            self.assertEqual(m.shared.counter, expected)
        self.assertEqual(bytes(m.shared.data[4:]), bytes(12))
        self.assertNotIn('finish', m.labels)
        self.assertNotIn('ready', m.labels)
        self.assertNotIn('rearm', m.labels)

    def test_nested_and_same_value_aba_bumps_have_distinct_revisions(self):
        shared = SharedState()
        outer, inner = RevisionMachine(shared), RevisionMachine(shared)
        first = outer.call('bump')
        second = inner.call('bump')
        # A caller may still be executing the mutation associated with first.
        # A third beginning returning to the same native value still advances.
        third = outer.call('bump')
        self.assertEqual((first, second, third), (1, 2, 3))
        self.assertEqual(shared.counter, 3)

    def test_competing_ll_sc_reservations_retry_without_reusing_revisions(self):
        shared = SharedState()
        a, other = RevisionMachine(shared), RevisionMachine(shared)
        a.start('bump').until('bump_sc')
        other.start('bump').until('bump_sc')
        self.assertEqual(a.run_to_return(), 1)
        self.assertEqual(other.run_to_return(), 2)
        self.assertEqual((a.sc_attempts, other.sc_attempts), (1, 2))
        self.assertEqual(shared.counter, 2)

    def test_competing_bump_at_every_instruction_keeps_unique_historical_results(self):
        probe = RevisionMachine()
        probe.call('bump')
        for boundary in range(len(probe.trace) + 1):
            with self.subTest(boundary=boundary):
                shared = SharedState()
                a, other = RevisionMachine(shared), RevisionMachine(shared)
                a.start('bump')
                for _ in range(boundary):
                    a.step()
                second = other.call('bump')
                first = a.run_to_return()
                self.assertEqual({first, second}, {1, 2})
                self.assertEqual(shared.counter, 2)
                self.assertEqual(bytes(shared.data[4:]), bytes(12))

    def test_invalidation_between_ll_sc_is_permanent(self):
        shared = SharedState()
        a, invalidator = RevisionMachine(shared), RevisionMachine(shared)
        a.start('bump').until('bump_sc')
        self.assertEqual(invalidator.call('invalidate'), 0)
        self.assertEqual(a.run_to_return(), 0)
        self.assertEqual(shared.counter, revision.FAULT)
        self.assertEqual(a.call('bump'), 0)

    def test_invalidation_at_every_instruction_cannot_be_overwritten(self):
        probe = RevisionMachine()
        probe.call('bump')
        for boundary in range(len(probe.trace) + 1):
            with self.subTest(boundary=boundary):
                shared = SharedState()
                a, invalidator = RevisionMachine(shared), RevisionMachine(shared)
                a.start('bump')
                for _ in range(boundary):
                    a.step()
                invalidator.call('invalidate')
                self.assertIn(a.run_to_return(), (0, 1))
                self.assertEqual(shared.counter, revision.FAULT)
                self.assertEqual(a.call('bump'), 0)
                self.assertEqual(a.call('invalidate'), 0)
                self.assertEqual(shared.counter, revision.FAULT)

    def test_fault_already_pending_cannot_be_erased_by_successful_bump(self):
        shared = SharedState()
        a, invalidator = RevisionMachine(shared), RevisionMachine(shared)
        invalidator.start('invalidate').until('fault_store')
        self.assertEqual(a.call('bump'), 1)
        self.assertEqual(shared.counter, 1)
        invalidator.run_to_return()
        self.assertEqual(shared.counter, revision.FAULT)
        self.assertEqual(a.call('bump'), 0)

    def test_invalidation_after_allocation_before_final_check_returns_zero(self):
        shared = SharedState()
        a, invalidator = RevisionMachine(shared), RevisionMachine(shared)
        a.start('bump').until('bump_check')
        self.assertEqual(shared.counter, 1)
        invalidator.call('invalidate')
        self.assertEqual(a.run_to_return(), 0)
        self.assertEqual(shared.counter, revision.FAULT)

    def test_historical_success_does_not_certify_current_or_completed_mutation(self):
        m = RevisionMachine()
        old = m.call('bump')
        self.assertEqual(m.call('bump'), 2)
        self.assertEqual(old, 1)
        m.call('invalidate')
        self.assertEqual(old, 1)
        self.assertEqual(m.shared.counter, revision.FAULT)

    def test_revision_limit_exact_then_exhaustion_without_wrap(self):
        for limit in (1, 2, 17, revision.REVISION_MASK):
            with self.subTest(limit=limit):
                m = RevisionMachine(SharedState(limit - 1), limit=limit)
                self.assertEqual(m.call('bump'), limit)
                self.assertEqual(m.shared.counter, limit)
                self.assertEqual(m.call('bump'), 0)
                self.assertEqual(m.shared.counter, revision.FAULT)
                self.assertEqual(m.call('bump'), 0)

    def test_malformed_counter_and_reserved_words_permanently_fault(self):
        for counter in (18, 0x80000000, 0xFFFFFFFE, revision.FAULT):
            m = RevisionMachine(SharedState(counter), limit=17)
            self.assertEqual(m.call('bump'), 0)
            self.assertEqual(m.shared.counter, revision.FAULT)
            self.assertEqual(m.sc_attempts, 0)
        for offset in revision.RESERVED:
            for value in (1, 0x80000000, MASK):
                m = RevisionMachine()
                m.shared.write(STATE + offset, value)
                self.assertEqual(m.call('bump'), 0)
                self.assertEqual(m.shared.counter, revision.FAULT)
                self.assertEqual(m.shared.read(STATE + offset), value)
                self.assertEqual(m.sc_attempts, 0)

    def test_malformed_interference_between_ll_sc_is_not_replaced_by_counter(self):
        for value in (0x80000000, 0xFFFFFFFE, revision.FAULT):
            m = RevisionMachine()
            m.start('bump').until('bump_sc')
            m.shared.write(STATE, value)
            self.assertEqual(m.run_to_return(), 0)
            self.assertEqual(m.shared.counter, revision.FAULT)

    def test_bounded_sc_failure_and_last_allowed_attempt_success(self):
        for retries in (1, 2, 8):
            m = RevisionMachine(retries=retries)
            m.sc_failures = retries
            self.assertEqual(m.call('bump'), 0)
            self.assertEqual(m.sc_attempts, retries)
            self.assertEqual(m.shared.counter, revision.FAULT)
            self.assertLess(m.steps, 200)
            m = RevisionMachine(retries=retries)
            m.sc_failures = retries - 1
            self.assertEqual(m.call('bump'), 1)
            self.assertEqual(m.sc_attempts, retries)
            self.assertEqual(m.shared.counter, 1)

    def test_exhaustion_under_interleaving_does_not_issue_duplicate_limit(self):
        shared = SharedState()
        a, other = RevisionMachine(shared, limit=1), RevisionMachine(shared, limit=1)
        a.start('bump').until('bump_sc')
        self.assertEqual(other.call('bump'), 1)
        self.assertEqual(a.run_to_return(), 0)
        self.assertEqual(shared.counter, revision.FAULT)

    def test_abi_private_memory_and_reserved_zero_on_success_and_failure(self):
        for entry, counter in (('bump', 0), ('bump', revision.FAULT),
                               ('invalidate', 0), ('invalidate', revision.FAULT)):
            m = RevisionMachine(SharedState(counter))
            before, hi, lo = m.r.copy(), m.hi, m.lo
            m.call(entry)
            for register in (*range(16, 24), 26, 27, 28, 29, 30, 31):
                self.assertEqual(m.r[register], before[register], (entry, register))
            self.assertEqual((m.hi, m.lo), (hi, lo))
            self.assertEqual(bytes(m.shared.data[4:]), bytes(12))
            for kind, address, size in m.shared.accesses:
                self.assertEqual(size, 4)
                self.assertIn(address - STATE, (0, *revision.RESERVED))
                if kind == 'write':
                    self.assertEqual(address, STATE)

    def test_only_atomic_increment_and_sticky_fault_store_change_state(self):
        m = RevisionMachine()
        stores = [(word >> 26, index) for index, word in enumerate(m.words)
                  if word >> 26 in (0x2B, 0x38)]
        self.assertEqual([op for op, _ in stores], [0x38, 0x2B])
        for _, index in stores:
            word = m.words[index]
            self.assertEqual(((word >> 21) & 31, word & 0xFFFF), (8, 0))
        fault_index = (m.labels['fault_store'] - CODE) // 4
        self.assertEqual(stores[-1][1], fault_index)
        self.assertEqual(m.words[fault_index - 1], revision.SYNC)
        self.assertEqual(m.words[fault_index + 1], revision.SYNC)

    def test_emitted_control_is_internal_no_native_calls_stack_or_hilo_writes(self):
        m = RevisionMachine()
        for index, word in enumerate(m.words):
            pc, op, rs = CODE + index * 4, word >> 26, (word >> 21) & 31
            if op in (4, 5):
                imm = word & 0xFFFF
                imm -= 0x10000 if imm & 0x8000 else 0
                self.assertTrue(CODE <= pc + 4 + imm * 4 < CODE + len(m.code))
                self.assertEqual(m.words[index + 1], 0)
            elif op == 2:
                target = ((pc + 4) & 0xF0000000) | ((word & 0x3FFFFFF) << 2)
                self.assertTrue(CODE <= target < CODE + len(m.code))
                self.assertEqual(m.words[index + 1], 0)
            elif op == 0:
                self.assertIn(word & 63, (0, 8, 15, 0x21, 0x2B))
                if word & 63 == 8:
                    self.assertEqual(rs, 31)
            else:
                self.assertIn(op, (9, 13, 15, 0x23, 0x2B, 0x30, 0x38))
                if op in (0x23, 0x2B, 0x30, 0x38):
                    self.assertEqual(rs, 8)

    def test_configuration_alignment_wrap_overlap_and_type_bounds(self):
        self.assertEqual(revision.memory_bytes(), 16)
        cases = (
            ('state_address', (-4, 1, True, 0x100000000, 0xFFFFFFFC, CODE)),
            ('code_base', (-4, 1, True, 0x100000000, 0xFFFFFFFC, 0x0FFFFFFC,
                           STATE, STATE + 12)),
            ('revision_limit', (0, -1, True, 1.0, 0x80000000)),
            ('retries', (0, -1, True, 1.0, 32768)),
        )
        for name, values in cases:
            for value in values:
                args = dict(state_address=STATE, code_base=CODE)
                args[name] = value
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    revision.build_revision(**args)
        code, _ = revision.build_revision(0xFFFFFFF0, CODE)
        self.assertGreater(len(code), 0)
        code, _ = revision.build_revision(STATE, CODE, retries=32767)
        self.assertGreater(len(code), 0)


if __name__ == '__main__':
    unittest.main()
