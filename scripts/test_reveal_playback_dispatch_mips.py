#!/usr/bin/env python3
"""Execute LPDI without mapping any callback, player, descriptor or UI object.

The shared LL/SC fixture models coherent stores and bounded instruction
interleavings, not firmware thread scheduling, hardware caches or causality.
"""

import struct
import unittest

import reveal_playback_dispatch_mips as dispatch
import test_reveal_lineage_rows_mips as harness


CODE, RETURN_ADDRESS, STACK, PARAMS = (
    harness.CODE, harness.RETURN, harness.STACK, harness.PARAMS)
JOURNAL, FRAME, TARGET, CONTEXT = 0xBD4000, 0xBAD40000, 0xBAD50001, 0x87654321
MASK = 0xFFFFFFFF


class Memory(harness.Memory):
    def __init__(self, capacity=32):
        self.capacity, self.regions, self.accesses, self.version = capacity, {}, [], 0
        self.map(JOURNAL, dispatch.memory_bytes(capacity))
        self.map(STACK - 0x1000, 0x2000)
        self.map(PARAMS, dispatch.METADATA_WORDS * 4)

    def write(self, address, value, size=4):
        super().write(address, value, size)
        self.version += 1


class DispatchMachine(harness.RowsMachine):
    def __init__(self, shared=None, *, capacity=32):
        self.shared = shared if shared is not None else Memory(capacity)
        self.code, self.labels = dispatch.assemble(JOURNAL, CODE, self.shared.capacity)
        self.words = struct.unpack('<%dI' % (len(self.code) // 4), self.code)
        self.r = [0] + [0x11000000 + reg for reg in range(1, 32)]
        self.r[29], self.r[31] = STACK, RETURN_ADDRESS
        self.hi, self.lo = 0x13579BDF, 0x2468ACE0
        self.reservation = None
        self.sc_failures = self.sc_attempts = 0
        self.pc, self.delay_target, self.steps = RETURN_ADDRESS, None, 0
        self.trace, self.calls = [], []

    def metadata(self, *, frame=FRAME, site=dispatch.FAST_SITE, return_address=None,
                 target=TARGET, context=CONTEXT, descriptor=dispatch.DESCRIPTOR_ADDRESS,
                 player=dispatch.PLAYER_ADDRESS):
        if return_address is None:
            return_address = site + 8
        values = (frame, site, return_address, target, context, descriptor, player)
        for index, value in enumerate(values):
            self.shared.write(PARAMS + 4 * index, value)
        return tuple(value & MASK for value in values)

    def capture(self, kind=dispatch.FAST, params=PARAMS):
        return self.call('capture', kind, params)

    def fast(self, **kwargs):
        self.metadata(**kwargs)
        return self.capture()

    def general(self, **kwargs):
        values = dict(site=dispatch.GENERAL_SITE)
        values.update(kwargs)
        self.metadata(**values)
        return self.capture(dispatch.GENERAL)

    @staticmethod
    def record_address(sequence):
        return JOURNAL + dispatch.HEADER + (sequence - 1) * dispatch.RECORD

    def record(self, sequence):
        start = dispatch.HEADER + (sequence - 1) * dispatch.RECORD
        return bytes(self.shared.regions[JOURNAL][start:start + dispatch.RECORD])


class DispatchCoreTests(unittest.TestCase):
    def test_exact_schema_self_origin_no_parent_and_zero_reserved(self):
        m = DispatchMachine()
        self.assertEqual((m.fast(), m.general()), (1, 2))
        for sequence, kind, site in ((1, dispatch.FAST, dispatch.FAST_SITE),
                                     (2, dispatch.GENERAL, dispatch.GENERAL_SITE)):
            self.assertEqual(struct.unpack('<16I', m.record(sequence)),
                             (dispatch.MAGIC, kind, 0, sequence, sequence, FRAME,
                              site, site + 8, TARGET, CONTEXT,
                              dispatch.DESCRIPTOR_ADDRESS, dispatch.PLAYER_ADDRESS,
                              0, 0, 0, 0))
        self.assertEqual(m.shared.regions[JOURNAL][4:16], bytes(12))
        self.assertEqual(set(m.labels) & {'ready', 'reset', 'finish', 'validate'}, set())

    def test_kind_and_owned_block_address_fault_before_metadata_reads(self):
        for kind, params in ((0, PARAMS), (3, PARAMS), (MASK, PARAMS),
                             (1, 0), (1, PARAMS + 1), (1, 0xFFFFFFE8),
                             (1, 0xFFFFFFFC)):
            with self.subTest(kind=kind, params=params):
                m = DispatchMachine()
                m.shared.accesses.clear()
                self.assertEqual(m.capture(kind, params), 0)
                self.assertEqual(m.shared.read(JOURNAL), dispatch.FAULT)
                self.assertFalse(any(access == 'read' and PARAMS <= address < PARAMS + 28
                                     for access, address, _ in m.shared.accesses))
                self.assertEqual(m.record(1), bytes(dispatch.RECORD))

    def test_exact_kind_site_return_descriptor_player_and_frame_contracts(self):
        cases = ({'frame': 0}, {'frame': FRAME + 1}, {'target': 0},
                 {'site': dispatch.FAST_SITE + 4},
                 {'site': dispatch.GENERAL_SITE},
                 {'return_address': dispatch.FAST_SITE + 4},
                 {'return_address': dispatch.GENERAL_SITE + 8},
                 {'descriptor': 0}, {'descriptor': dispatch.DESCRIPTOR_ADDRESS + 4},
                 {'player': 0}, {'player': dispatch.PLAYER_ADDRESS + 4})
        for changes in cases:
            with self.subTest(changes=changes):
                m = DispatchMachine()
                self.assertEqual(m.fast(**changes), 0)
                self.assertEqual(m.shared.read(JOURNAL), dispatch.FAULT)
                self.assertEqual(m.record(1), bytes(dispatch.RECORD))
        m = DispatchMachine()
        self.assertEqual(m.general(site=dispatch.FAST_SITE), 0)
        self.assertEqual(m.shared.read(JOURNAL), dispatch.FAULT)

    def test_target_is_nonzero_raw_scalar_not_pointer_alignment_or_executable_admission(self):
        for target in (1, 2, 3, 0x80000000, 0xBAD50000, MASK):
            for context in (0, 1, 2, 3, 0x80000000, MASK):
                m = DispatchMachine()
                self.assertEqual(m.fast(target=target, context=context), 1)
                self.assertEqual(m.field(1, dispatch.TARGET), target)
                self.assertEqual(m.field(1, dispatch.CONTEXT), context)
                self.assertEqual(set(m.shared.regions),
                                 {JOURNAL, STACK - 0x1000, PARAMS})

    def test_aligned_high_native_frame_is_only_unaccessed_scalar(self):
        for frame in (4, FRAME, 0x80000000, 0xFFFFFFFC):
            m = DispatchMachine()
            self.assertEqual(m.fast(frame=frame), 1)
            self.assertEqual(m.field(1, dispatch.FRAME), frame)

    def test_owned_metadata_copied_once_and_frozen_before_reservation(self):
        m = DispatchMachine()
        values = m.metadata()
        m.shared.accesses.clear()
        m.start('capture', dispatch.FAST, PARAMS).until('reserve_ll')
        m.metadata(target=TARGET + 7, context=0, player=0)
        self.assertEqual(m.run_to_return(), 1)
        self.assertEqual(struct.unpack('<16I', m.record(1))[5:12], values)
        for index in range(dispatch.METADATA_WORDS):
            self.assertEqual(m.shared.accesses.count(('read', PARAMS + 4 * index, 4)), 1)

    def test_identical_native_addresses_always_receive_independent_fresh_ids(self):
        m = DispatchMachine()
        self.assertEqual((m.fast(), m.fast(), m.general(), m.fast()), (1, 2, 3, 4))
        self.assertEqual([m.field(i, dispatch.ORIGIN) for i in range(1, 5)], [1, 2, 3, 4])
        self.assertEqual([m.field(i, dispatch.PARENT) for i in range(1, 5)], [0] * 4)
        self.assertEqual([m.field(i, dispatch.TARGET) for i in range(1, 5)], [TARGET] * 4)

    def test_capacity_stride_nonreuse_and_terminal_exhaustion(self):
        for capacity in (1, 2, 32, 1024):
            m = DispatchMachine(capacity=capacity)
            for sequence in range(1, capacity + 1):
                self.assertEqual(m.fast(), sequence)
                self.assertEqual(m.field(sequence, dispatch.SEQ), sequence)
            first, last = m.record(1), m.record(capacity)
            self.assertEqual(m.fast(), 0)
            self.assertEqual(m.shared.read(JOURNAL), dispatch.FAULT)
            self.assertEqual(m.general(), 0)
            self.assertEqual((m.record(1), m.record(capacity)), (first, last))

    def test_out_of_domain_allocator_state_and_existing_slot_magic_fault_without_overwrite(self):
        for state in (33, 0x7FFFFFFF, 0x80000000, MASK):
            m = DispatchMachine()
            m.shared.write(JOURNAL, state)
            self.assertEqual(m.fast(), 0)
            self.assertEqual(m.shared.read(JOURNAL), dispatch.FAULT)
            self.assertEqual(m.record(1), bytes(dispatch.RECORD))
        for magic in (1, dispatch.MAGIC, MASK):
            m = DispatchMachine()
            m.shared.write(m.record_address(1), magic)
            before = m.record(1)
            self.assertEqual(m.fast(), 0)
            self.assertEqual(m.shared.read(JOURNAL), dispatch.FAULT)
            self.assertEqual(m.record(1), before)

    def test_exact_eight_llsc_attempts_last_success_and_bounded_failure(self):
        for failures in (0, 7, 8, 100):
            m = DispatchMachine()
            m.sc_failures = failures
            self.assertEqual(m.fast(), 1 if failures < 8 else 0)
            self.assertEqual(m.sc_attempts, min(failures + 1, 8))
            self.assertEqual(m.shared.read(JOURNAL),
                             1 if failures < 8 else dispatch.FAULT)

    def test_competing_allocators_retry_without_reusing_slot(self):
        shared = Memory()
        first, second = DispatchMachine(shared), DispatchMachine(shared)
        first.start('reserve').until('reserve_sc')
        second.start('reserve').until('reserve_sc')
        self.assertEqual(first.run_to_return(), first.record_address(1))
        self.assertEqual(first.r[3], 1)
        self.assertEqual(second.run_to_return(), second.record_address(2))
        self.assertEqual(second.r[3], 2)
        self.assertEqual((first.sc_attempts, second.sc_attempts), (1, 2))

    def test_unpublished_first_dispatch_does_not_parent_later_observer(self):
        shared = Memory()
        first, second = DispatchMachine(shared), DispatchMachine(shared)
        # Distinct invocation-owned frames; sharing a native stack frame
        # between simultaneous contexts would itself violate this core's ABI.
        second.r[29] = STACK + 0x800
        first.metadata()
        first.start('capture', dispatch.FAST, PARAMS).until('capture_publish')
        self.assertEqual(shared.read(JOURNAL), 1)
        self.assertEqual(first.field(1, dispatch.MAGIC_OFFSET), 0)
        self.assertEqual(second.general(context=7), 2)
        self.assertEqual(first.field(1, dispatch.MAGIC_OFFSET), 0)
        self.assertEqual(first.run_to_return(), 1)
        self.assertEqual([first.field(i, dispatch.ORIGIN) for i in (1, 2)], [1, 2])
        self.assertEqual([first.field(i, dispatch.PARENT) for i in (1, 2)], [0, 0])
        self.assertEqual(first.field(1, dispatch.CONTEXT), CONTEXT)
        self.assertEqual(first.field(2, dispatch.CONTEXT), 7)

    def test_global_fault_before_final_check_keeps_partial_record_unpublished(self):
        m = DispatchMachine()
        m.metadata()
        m.start('capture', dispatch.FAST, PARAMS).until('capture_publish')
        m.shared.write(JOURNAL, dispatch.FAULT)
        self.assertEqual(m.run_to_return(), 0)
        self.assertEqual(m.field(1, dispatch.MAGIC_OFFSET), 0)
        self.assertEqual(m.field(1, dispatch.SEQ), 1)
        self.assertEqual(m.shared.read(JOURNAL), dispatch.FAULT)

    def test_fault_after_final_check_may_race_magic_but_never_repairs_global_fault(self):
        shared = Memory()
        first, invalidator = DispatchMachine(shared), DispatchMachine(shared)
        first.metadata()
        first.start('capture', dispatch.FAST, PARAMS).until('capture_magic_store')
        invalidator.call('invalidate')
        self.assertEqual(first.run_to_return(), 1)
        self.assertEqual(first.field(1, dispatch.MAGIC_OFFSET), dispatch.MAGIC)
        self.assertEqual(shared.read(JOURNAL), dispatch.FAULT)
        self.assertEqual(first.call('reserve'), 0)

    def test_fault_at_each_capture_instruction_is_terminal_including_stale_sc(self):
        probe = DispatchMachine()
        probe.fast()
        for boundary in range(len(probe.trace) + 1):
            shared = Memory()
            m, invalidator = DispatchMachine(shared), DispatchMachine(shared)
            m.metadata()
            m.start('capture', dispatch.FAST, PARAMS)
            for _ in range(boundary):
                m.step()
            invalidator.call('invalidate')
            m.run_to_return()
            self.assertEqual(shared.read(JOURNAL), dispatch.FAULT, boundary)
            self.assertEqual(m.call('reserve'), 0, boundary)

    def test_all_public_entry_abi_and_only_owned_metadata_private_journal_own_stack(self):
        for entry, args in (('capture', (dispatch.FAST, PARAMS)),
                            ('capture', (dispatch.GENERAL, PARAMS)),
                            ('capture', (0, PARAMS)), ('capture', (1, 0)),
                            ('reserve', ()), ('invalidate', ())):
            m = DispatchMachine()
            m.metadata(site=dispatch.GENERAL_SITE if args and args[0] == 2
                       else dispatch.FAST_SITE)
            before, hi, lo = m.r.copy(), m.hi, m.lo
            m.shared.accesses.clear()
            m.call(entry, *args)
            for register in (*range(16, 24), 26, 27, 28, 29, 30, 31):
                self.assertEqual(m.r[register], before[register], (entry, register))
            self.assertEqual((m.hi, m.lo), (hi, lo))
            for access, address, size in m.shared.accesses:
                self.assertTrue(JOURNAL <= address <= JOURNAL + dispatch.memory_bytes(32) - size
                                or STACK - dispatch.CALL_FRAME <= address <= STACK - size
                                or (access == 'read' and PARAMS <= address <= PARAMS + 28 - size),
                                (entry, access, hex(address), size))

    def test_magic_publishes_last_and_only_plain_state_store_is_terminal_fault(self):
        m = DispatchMachine()
        m.metadata()
        m.shared.accesses.clear()
        m.capture()
        writes = [(address, size) for access, address, size in m.shared.accesses
                  if access == 'write' and m.record_address(1) <= address < m.record_address(2)]
        self.assertEqual(writes[-1], (m.record_address(1), 4))
        stores = [(index, word >> 26) for index, word in enumerate(m.words)
                  if word >> 26 in (0x2B, 0x38) and (word >> 21) & 31 == 8
                  and word & 0xFFFF == 0]
        self.assertEqual([op for _, op in stores], [0x38, 0x2B])
        self.assertEqual(CODE + stores[-1][0] * 4, m.labels['fault_store'])
        self.assertEqual(m.words[(m.labels['capture_magic_store'] - CODE) // 4 - 3],
                         dispatch.SYNC)

    def test_no_external_calls_no_indirect_target_transfer_and_all_delays_nop(self):
        m = DispatchMachine()
        for index, word in enumerate(m.words):
            op, rs = word >> 26, (word >> 21) & 31
            if op in (2, 3):
                pc = CODE + index * 4
                target = ((pc + 4) & 0xF0000000) | ((word & 0x3FFFFFF) << 2)
                self.assertTrue(CODE <= target < CODE + len(m.code))
                self.assertEqual(m.words[index + 1], 0)
            if op in (4, 5) or (op == 0 and word & 63 in (8, 9)):
                if op == 0:
                    self.assertEqual((word & 63, rs), (8, 31))
                self.assertEqual(m.words[index + 1], 0)

    def test_layout_types_capacity_storage_wrap_overlap_and_code_jump_region(self):
        self.assertEqual(dispatch.memory_bytes(), 65552)
        self.assertEqual(dispatch.MAGIC.to_bytes(4, 'little'), b'LPDI')
        for value in (0, -1, True, 1.0, dispatch.MAX_CAPACITY + 1):
            with self.assertRaises(ValueError):
                dispatch.memory_bytes(value)
        self.assertLessEqual(dispatch.memory_bytes(dispatch.MAX_CAPACITY), 0x100000000)
        for name, values in (
                ('capacity', (0, -1, True, 1.0, dispatch.MAX_CAPACITY + 1)),
                ('journal_address', (True, 1, -4, 0x100000000, 0xFFFFFFFC, CODE)),
                ('code_base', (True, 1, -4, 0x100000000, 0xFFFFFFFC, JOURNAL,
                               0x0FFFFF00))):
            for value in values:
                args = dict(journal_address=JOURNAL, code_base=CODE)
                args[name] = value
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    dispatch.assemble(**args)


if __name__ == '__main__':
    unittest.main()
