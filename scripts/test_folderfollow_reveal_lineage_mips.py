#!/usr/bin/env python3
"""Execute the diagnostic lineage core, not a native lifetime/UI model.

Shared stores invalidate LL/SC reservations at the private allocator word.
SYNC is checked structurally; these tests do not simulate CPU caches. Test
publication helpers stand for the wrapper's payload writes + SYNC + MAGIC.
"""

import struct
import unittest

import folderfollow_reveal_lineage_mips as lineage
from test_folderfollow_reveal_guard_mips import GuardMachine


STATE, CODE, RETURN = 0xBD4000, 0xC70000, 0xDEAD0000
MASK = 0xFFFFFFFF


class SharedLedger:
    def __init__(self, capacity=32):
        self.capacity = capacity
        self.data = bytearray(lineage.memory_bytes(capacity))
        self.version = 0
        self.accesses = []

    def offset(self, address, size):
        if size != 4 or address % 4 or not STATE <= address <= STATE + len(self.data) - size:
            raise AssertionError('nonprivate or unaligned ledger access ' + hex(address))
        return address - STATE

    def read(self, address, size=4):
        offset = self.offset(address, size)
        self.accesses.append(('read', address, size))
        return struct.unpack_from('<I', self.data, offset)[0]

    def write(self, address, value, size=4):
        offset = self.offset(address, size)
        self.accesses.append(('write', address, size))
        struct.pack_into('<I', self.data, offset, value & MASK)
        if address == STATE:
            self.version += 1

    @property
    def state(self):
        return self.read(STATE)


class LineageMachine(GuardMachine):
    def __init__(self, shared=None, *, capacity=32, retries=8):
        self.shared = shared if shared is not None else SharedLedger(capacity)
        self.code, self.labels = lineage.build_lineage(
            STATE, CODE, capacity=self.shared.capacity, retries=retries)
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

    def start(self, entry, *args):
        if self.pc != RETURN:
            raise AssertionError('context is already executing')
        if len(args) > 4:
            raise AssertionError('four register arguments maximum')
        for index, value in enumerate(args):
            self.r[4 + index] = value & MASK
        self.pc = self.labels[entry]
        self.delay_target = None
        self.steps = 0
        self.trace = []
        return self

    def call(self, entry, *args):
        self.start(entry, *args)
        return self.run_to_return()

    def reserve(self, kind=lineage.RENDER, parent=0, view=0x12345678, panel=0xABCDEF00):
        slot = self.call('reserve', kind, parent, view, panel)
        return slot, self.r[3]

    @staticmethod
    def slot(token):
        return STATE + lineage.HEADER + (token - 1) * lineage.RECORD

    def field(self, token, offset):
        return self.shared.read(self.slot(token) + offset)

    def publish(self, token, **payload):
        for field, value in payload.items():
            self.shared.write(self.slot(token) + getattr(lineage, field), value)
        self.shared.write(self.slot(token) + lineage.MAGIC_OFFSET, lineage.MAGIC)

    def chain(self, origin_kind=lineage.RENDER):
        tokens = []
        for kind in (origin_kind, lineage.BORROW, lineage.QUERY, lineage.PRODUCER):
            slot, token = self.reserve(kind, tokens[-1] if tokens else 0)
            if slot == 0:
                raise AssertionError('chain creation failed')
            self.publish(token)
            tokens.append(token)
        return tokens


class LineageTests(unittest.TestCase):
    def test_fresh_origin_raw_scalars_and_unpublished_header(self):
        m = LineageMachine()
        slot, token = m.reserve(view=0xFFFFFFFF, panel=0)
        self.assertEqual((slot, token), (STATE + 16, 1))
        self.assertEqual(m.shared.state, 1)
        expected = {lineage.MAGIC_OFFSET: 0, lineage.KIND: lineage.RENDER,
                    lineage.ORIGIN: 1, lineage.PARENT: 0,
                    lineage.VIEW: 0xFFFFFFFF, lineage.PANEL: 0}
        for offset, value in expected.items():
            self.assertEqual(m.field(token, offset), value)
        self.assertEqual(bytes(m.shared.data[4:16]), bytes(12))

    def test_both_origin_kinds_and_complete_chain_inherit_not_caller_identity(self):
        for kind in (lineage.RENDER, lineage.INITIAL):
            m = LineageMachine()
            _, root = m.reserve(kind, view=0x1234, panel=0x5678)
            m.publish(root, JOB=0xDEAD0001, SITE=0x490758)
            previous = root
            for child_kind in (lineage.BORROW, lineage.QUERY, lineage.PRODUCER):
                slot, token = m.reserve(child_kind, previous, 0xBAD, 0xBAD)
                self.assertEqual(m.field(token, lineage.VIEW), 0x1234)
                self.assertEqual(m.field(token, lineage.PANEL), 0x5678)
                self.assertEqual(m.field(token, lineage.ORIGIN), root)
                self.assertEqual(m.field(token, lineage.PARENT), previous)
                m.publish(token, JOB=0xDEAD0001)
                self.assertEqual(m.call('validate', token, child_kind), slot)
                self.assertEqual(m.call('validate', token, 0), slot)
                previous = token

    def test_one_origin_can_fan_out_without_retagging_prior_records(self):
        m = LineageMachine()
        _, root = m.reserve()
        m.publish(root)
        children = [m.reserve(lineage.BORROW, root)[1] for _ in range(4)]
        self.assertEqual(children, [2, 3, 4, 5])
        for token in children:
            m.publish(token)
            self.assertEqual(m.field(token, lineage.ORIGIN), root)
            self.assertEqual(m.call('validate', token, lineage.BORROW), m.slot(token))

    def test_same_native_scalars_or_name_reuse_never_reuses_tokens(self):
        m = LineageMachine()
        slots = []
        for token in range(1, 21):
            slot, actual = m.reserve(view=0x2222, panel=0x3333)
            self.assertEqual(actual, token)
            m.publish(token, JOB=0x4444, DEST=0x5555)
            slots.append(slot)
        self.assertEqual(len(set(slots)), 20)
        for token in range(1, 21):
            self.assertEqual(m.field(token, lineage.ORIGIN), token)

    def test_capacity_exact_then_terminal_exhaustion(self):
        for capacity in (1, 2, 32, 1024):
            m = LineageMachine(capacity=capacity)
            for expected in range(1, capacity + 1):
                slot, token = m.reserve()
                self.assertEqual((slot, token), (m.slot(expected), expected))
                m.publish(token)
            self.assertEqual(m.reserve(), (0, 0))
            self.assertEqual(m.shared.state, lineage.FAULT)
            self.assertEqual(m.call('validate', 1, 0), 0)

    def test_unpublished_child_parent_or_validation_permanently_faults(self):
        for operation in ('child', 'validate'):
            m = LineageMachine()
            _, root = m.reserve()
            result = (m.reserve(lineage.BORROW, root)[0] if operation == 'child'
                      else m.call('validate', root, 0))
            self.assertEqual(result, 0)
            self.assertEqual(m.shared.state, lineage.FAULT)
            m.publish(root)  # Late publication cannot resurrect global validity.
            self.assertEqual(m.call('validate', root, 0), 0)

    def test_invalid_kind_parent_and_exact_kind_fault(self):
        for kind in (0, 6, 0x80000000, 0xFFFFFFFF):
            m = LineageMachine()
            self.assertEqual(m.reserve(kind), (0, 0))
            self.assertEqual(m.shared.state, lineage.FAULT)
        for kind in (lineage.RENDER, lineage.INITIAL):
            m = LineageMachine()
            self.assertEqual(m.reserve(kind, 1), (0, 0))
        for parent in (0, 1, 0xFFFFFFFF, 0x80000000):
            m = LineageMachine()
            self.assertEqual(m.reserve(lineage.BORROW, parent), (0, 0))
        for exact in (lineage.INITIAL, lineage.BORROW, 6, 0xFFFFFFFF):
            m = LineageMachine()
            _, root = m.reserve()
            m.publish(root)
            self.assertEqual(m.call('validate', root, exact), 0)
            self.assertEqual(m.shared.state, lineage.FAULT)

    def test_wrong_parent_kind_cannot_skip_or_repeat_a_stage(self):
        for child_kind, parent_index in ((3, 1), (3, 2), (3, 3),
                                         (4, 0), (4, 2), (4, 3),
                                         (5, 0), (5, 1), (5, 3)):
            m = LineageMachine()
            tokens = m.chain()
            self.assertEqual(m.reserve(child_kind, tokens[parent_index]), (0, 0))
            self.assertEqual(m.shared.state, lineage.FAULT)

    def test_bad_record_header_is_not_accepted_as_a_published_parent(self):
        corruptions = ((lineage.MAGIC_OFFSET, 1), (lineage.KIND, 0),
                       (lineage.KIND, 6), (lineage.ORIGIN, 0),
                       (lineage.ORIGIN, 2), (lineage.PARENT, 1))
        for offset, value in corruptions:
            m = LineageMachine()
            _, token = m.reserve()
            m.publish(token)
            m.shared.write(m.slot(token) + offset, value)
            self.assertEqual(m.reserve(lineage.BORROW, token), (0, 0))
            self.assertEqual(m.shared.state, lineage.FAULT)

    def test_bad_descendant_origin_parent_or_inherited_scalars_fault(self):
        for offset, value in ((lineage.ORIGIN, 0), (lineage.ORIGIN, 4),
                              (lineage.PARENT, 0), (lineage.PARENT, 3),
                              (lineage.PARENT, 1), (lineage.VIEW, 0),
                              (lineage.PANEL, 0)):
            m = LineageMachine()
            tokens = m.chain()
            m.shared.write(m.slot(tokens[2]) + offset, value)
            self.assertEqual(m.call('validate', tokens[2], 0), 0)
            self.assertEqual(m.shared.state, lineage.FAULT)

    def test_forged_unissued_or_native_pointer_tokens_do_not_read_native_memory(self):
        for token in (0, 1, 0x12345678, STATE, 0xFFFFFFFF, 0x80000000):
            m = LineageMachine()
            self.assertEqual(m.call('validate', token, 0), 0)
            self.assertEqual(m.shared.state, lineage.FAULT)

    def test_bounded_sc_failure_and_last_attempt_success(self):
        for retries in (1, 2, 8):
            m = LineageMachine(retries=retries)
            m.sc_failures = retries
            self.assertEqual(m.reserve(), (0, 0))
            self.assertEqual(m.sc_attempts, retries)
            self.assertEqual(m.shared.state, lineage.FAULT)
            m = LineageMachine(retries=retries)
            m.sc_failures = retries - 1
            self.assertEqual(m.reserve()[1], 1)
            self.assertEqual(m.sc_attempts, retries)

    def test_competing_reservations_allocate_distinct_slots(self):
        shared = SharedLedger()
        a, b = LineageMachine(shared), LineageMachine(shared)
        a.start('reserve', lineage.RENDER, 0, 0x11, 0x22).until('reserve_sc')
        b.start('reserve', lineage.INITIAL, 0, 0x33, 0x44).until('reserve_sc')
        self.assertEqual(a.run_to_return(), a.slot(1))
        self.assertEqual(b.run_to_return(), b.slot(2))
        self.assertEqual((a.r[3], b.r[3]), (1, 2))
        self.assertEqual(shared.state, 2)
        self.assertEqual(a.field(1, lineage.VIEW), 0x11)
        self.assertEqual(b.field(2, lineage.VIEW), 0x33)

    def test_invalidation_between_ll_sc_is_sticky(self):
        shared = SharedLedger()
        a, invalidator = LineageMachine(shared), LineageMachine(shared)
        a.start('reserve', lineage.RENDER, 0, 0x11, 0x22).until('reserve_sc')
        invalidator.call('invalidate')
        self.assertEqual(a.run_to_return(), 0)
        self.assertEqual(a.r[3], 0)
        self.assertEqual(shared.state, lineage.FAULT)

    def test_invalidation_at_each_instruction_never_restores_ledger(self):
        for entry in ('reserve', 'validate', 'child'):
            base = LineageMachine()
            _, root = base.reserve()
            base.publish(root)
            initial = bytes(base.shared.data)
            args = ((lineage.RENDER, 0, 0x11, 0x22) if entry == 'reserve' else
                    (lineage.BORROW, root, 0, 0) if entry == 'child' else (root, 0))
            function = 'reserve' if entry != 'validate' else 'validate'
            probe = LineageMachine()
            probe.shared.data[:] = initial
            probe.call(function, *args)
            for boundary in range(len(probe.trace) + 1):
                with self.subTest(entry=entry, boundary=boundary):
                    shared = SharedLedger()
                    shared.data[:] = initial
                    a, invalidator = LineageMachine(shared), LineageMachine(shared)
                    a.start(function, *args)
                    for _ in range(boundary):
                        a.step()
                    invalidator.call('invalidate')
                    a.run_to_return()
                    self.assertEqual(shared.state, lineage.FAULT)
                    self.assertEqual(a.call('validate', root, 0), 0)
                    self.assertEqual(a.reserve(), (0, 0))

    def test_post_validation_invalidation_means_result_is_not_a_lease(self):
        m = LineageMachine()
        _, token = m.reserve()
        m.publish(token)
        self.assertEqual(m.call('validate', token, lineage.RENDER), m.slot(token))
        m.call('invalidate')
        self.assertEqual(m.field(token, lineage.MAGIC_OFFSET), lineage.MAGIC)
        self.assertEqual(m.call('validate', token, 0), 0)

    def test_bad_allocator_state_and_nonfresh_slot_fail_closed(self):
        for state in (33, 0x80000000, 0xFFFFFFFF):
            for entry, args in (('reserve', (lineage.RENDER, 0, 0, 0)),
                                ('validate', (1, 0))):
                m = LineageMachine()
                m.shared.write(STATE, state)
                self.assertEqual(m.call(entry, *args), 0)
                self.assertEqual(m.shared.state, lineage.FAULT)
        m = LineageMachine()
        m.shared.write(m.slot(1), lineage.MAGIC)
        self.assertEqual(m.reserve(), (0, 0))

    def test_abi_private_accesses_and_payload_are_not_native_reads(self):
        for entry, args in (('reserve', (lineage.RENDER, 0, 0xFFFFFFFF, 0xDEAD0000)),
                            ('reserve', (lineage.BORROW, 1, 0xBAD, 0xBAD)),
                            ('validate', (1, 0)), ('invalidate', ())):
            m = LineageMachine()
            _, root = m.reserve()
            m.publish(root, JOB=0xDEAD0001, DEST=0xDEAD0002, STMT=0xDEAD0003)
            before, hi, lo = m.r.copy(), m.hi, m.lo
            m.call(entry, *args)
            for register in (*range(16, 24), 26, 27, 28, 29, 30, 31):
                self.assertEqual(m.r[register], before[register], (entry, register))
            self.assertEqual((m.hi, m.lo), (hi, lo))
            for _, address, size in m.shared.accesses:
                self.assertTrue(STATE <= address <= STATE + len(m.shared.data) - size)

    def test_only_atomic_increment_or_sticky_fault_write_allocator(self):
        m = LineageMachine()
        stores = []
        for index, word in enumerate(m.words):
            op, rs, offset = word >> 26, (word >> 21) & 31, word & 0xFFFF
            if op in (0x2B, 0x38) and rs == 8 and offset == lineage.STATE:
                stores.append((op, index))
        self.assertEqual([op for op, _ in stores], [0x38, 0x2B])
        fault = (m.labels['fault_store'] - CODE) // 4
        self.assertEqual(stores[-1][1], fault)
        self.assertEqual(m.words[fault - 1], lineage.SYNC)
        self.assertEqual(m.words[fault + 1], lineage.SYNC)
        # MAGIC is exclusively a wrapper publication obligation.
        self.assertFalse(any(word >> 26 == 0x2B and (word >> 21) & 31 == 15
                             and word & 0xFFFF == lineage.MAGIC_OFFSET for word in m.words))

    def test_entire_emission_has_only_internal_control_and_no_stack_calls_or_hilo(self):
        m = LineageMachine()
        for index, word in enumerate(m.words):
            pc, op = CODE + index * 4, word >> 26
            rs = (word >> 21) & 31
            if op in (4, 5):
                imm = word & 0xFFFF
                imm -= 0x10000 if imm & 0x8000 else 0
                self.assertTrue(CODE <= pc + 4 + imm * 4 < CODE + len(m.code))
                self.assertEqual(m.words[index + 1], 0)
            elif op == 2:
                target = ((pc + 4) & 0xF0000000) | ((word & 0x3FFFFFF) << 2)
                self.assertTrue(CODE <= target < CODE + len(m.code))
            elif op == 0:
                self.assertIn(word & 63, (0, 8, 15, 0x21, 0x2B))
                if word & 63 == 8:
                    self.assertEqual(rs, 31)
            else:
                self.assertIn(op, (9, 11, 13, 15, 0x23, 0x2B, 0x30, 0x38))
                if op in (0x23, 0x2B, 0x30, 0x38):
                    self.assertIn(rs, (8, 13, 15))

    def test_layout_and_configuration_bounds(self):
        self.assertEqual(lineage.memory_bytes(), 16 + 64 * 1024)
        self.assertEqual(lineage.MAGIC.to_bytes(4, 'little'), b'LNRG')
        for capacity in (0, -1, True, 1.0, lineage.MAX_CAPACITY + 1):
            with self.assertRaises(ValueError):
                lineage.memory_bytes(capacity)
        for name, values in (('state_address', (-4, 1, True, 0x100000000, CODE, 0xFFFFFFFC)),
                             ('code_base', (-4, 1, True, 0x100000000, 0xFFFFFFFC, 0x0FFFFFFC, STATE)),
                             ('capacity', (0, -1, True, lineage.MAX_CAPACITY + 1)),
                             ('retries', (0, -1, True, 32768))):
            for value in values:
                args = dict(state_address=STATE, code_base=CODE)
                args[name] = value
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    lineage.build_lineage(**args)


if __name__ == '__main__':
    unittest.main()
