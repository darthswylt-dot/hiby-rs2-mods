#!/usr/bin/env python3
"""Run the combined test image's D180 redirects in the bounded model."""

import struct
import unittest

import build_reveal_bridge_diag as bridge
import build_reveal_d180_payload_guard_test as build_test
import build_reveal_d960_payload_guard_test as previous
import factory_null_audit as audit
from mips_static_trace import sx16
from test_factory_d180_allocation_continuations import (
    LOCK_IMPORT, LOWER, NOTICE_UPPER, SAMPLE, STRCPY, TEXT, UNLOCK_IMPORT, AllocationContinuationMachine,
)
from test_factory_null_audit import ALLOCATION, ALLOCATOR, CONFIGURATOR, CONTEXT, HANDLE, MASK, RETURN, STACK
from test_reveal_d960_payload_guard_mips import OLD_PAYLOAD, PayloadGuardMachine


CODE_BASE = 0xC70D98
RX_HEADER = 0x154
PATCH_SITES = (0x5270AC, 0x4CFF44, 0x4D1AE8, 0x4D2B50, 0x4D3730, 0x515224, 0x509A38)
FACTORY, WRAPPER, LOOKUP = 0x47D180, 0x527040, 0x423980
GLOBAL_CLEAR, RESOURCE_ROOT, RESOURCE = 0xB8BE04, 0xADD360, 0x1D07000
TABLE_START, TABLE_END = 0x92073C, 0x920754
RESOURCE_FIELDS = (0x6CC, 0x6C4, 0x6C8, 0x6D8)
VALUES = (0x13570001, 0x13570002, 0x13570003, 0x13570004)
NOTICE_FACTORY = 0x509A2C
NOTICE_WRAPPER = NOTICE_UPPER[1]
OLD_NOTICE = CONTEXT + 0x100
NOTICE_MUTEX = ALLOCATION + 0x80


class D180PayloadGuardMachine(PayloadGuardMachine):
    def __init__(self, image, **options):
        super().__init__(image, **options)
        self.lookups = []
        self.wrapper_result = None
        self.map(RESOURCE_ROOT, 4)
        self.map(RESOURCE, 0x700)
        self.map(TABLE_START, TABLE_END - TABLE_START)
        self.put(RESOURCE_ROOT, RESOURCE, 4)
        for address in range(TABLE_START, TABLE_END, 4):
            self.put(address, image.word(address), 4)
        for offset, value in zip(RESOURCE_FIELDS, VALUES):
            self.put(RESOURCE + offset, value, 4)
        self.put(GLOBAL_CLEAR, 0x13572468, 4)
        self.put(HANDLE + 0x58, OLD_PAYLOAD, 4)
        self.bytes(ALLOCATION, b'\xCC' * 16)
        self.writes.clear()

    def external(self, target):
        if target == WRAPPER:
            self.calls.append(target)
            self.run_at(target, self.r[31])
            self.wrapper_result = self.r[2]
        elif target == LOOKUP:
            self.calls.append(target)
            self.lookups.append(self.r[4])
            self.run_at(target, self.r[31])
        else:
            super().external(target)


class NoticeGuardMachine(AllocationContinuationMachine):
    def external(self, target):
        if target == NOTICE_WRAPPER:
            self.calls.append(target)
            self.run_at(target, self.r[31])
            self.notice_result = self.r[2]
            return
        if target == CONFIGURATOR:
            self.config_scratch = tuple(self.r[6:8])
        super().external(target)
        if target == ALLOCATOR:
            # Model allowed volatile clobbers distinct from the factory's.
            self.r[6:8] = [0xA2600006, 0xA2600007]


class D180PayloadGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = audit.source_image()
        capture, _ = bridge.build(cls.image.data)
        cls.baseline = previous.build(capture)
        cls.candidate = build_test.build(cls.baseline)
        cls.code = cls.candidate[len(cls.baseline):]
        cls.patches = {
            pc: (struct.unpack_from('<2I', cls.baseline, pc - bridge.BASE),
                 struct.unpack_from('<2I', cls.candidate, pc - bridge.BASE))
            for pc in PATCH_SITES
        }

    def guarded(self, machine_type=D180PayloadGuardMachine, **options):
        return machine_type(self.image, code=self.code, patches=self.patches,
                            code_base=CODE_BASE, **options)

    def test_combined_image_extends_only_the_existing_rx_page_and_seven_redirects(self):
        self.assertEqual(len(self.baseline), 0x6D0D98)
        self.assertEqual(len(self.candidate), 0x6D0E5C)
        self.assertEqual(struct.unpack_from('<8I', self.candidate, RX_HEADER),
                         (1, 0x6D0000, 0xC70000, 0xC70000, 0xE5C, 0xE5C, 5, 0x10000))

        restored = bytearray(self.candidate[:len(self.baseline)])
        restored[RX_HEADER + 16:RX_HEADER + 24] = self.baseline[RX_HEADER + 16:RX_HEADER + 24]
        for index, pc in enumerate(PATCH_SITES):
            original, replacement = self.patches[pc]
            target = CODE_BASE + 28 * index
            self.assertEqual(replacement, ((2 << 26) | (target >> 2), original[1]))
            struct.pack_into('<I', restored, pc - bridge.BASE, original[0])
        self.assertEqual(bytes(restored), self.baseline)
        with self.assertRaisesRegex(ValueError, 'exact hardware-tested D960 ELF'):
            build_test.build(self.candidate)

    def test_redirect_matches_stock_and_wrapper_has_one_encoded_caller(self):
        original, replacement = self.patches[0x5270AC]
        self.assertEqual(original, (0x0C119A78, 0x00408821))
        self.assertEqual(original, (self.image.word(0x5270AC), self.image.word(0x5270B0)))
        self.assertEqual(replacement[1], original[1])
        incoming = [
            pc for first, last in self.image.executable_ranges() for pc in range(first, last, 4)
            if self.image.word(pc) in (0x08149C10, 0x0C149C10)
        ]
        self.assertEqual(incoming, [0x4C1A3C])

    def test_null_uses_the_native_exit_and_keeps_the_pre_factory_clear(self):
        machine = self.guarded()
        saved = machine.r[16:18]
        machine.run_at(WRAPPER, RETURN)

        self.assertEqual(machine.calls, [FACTORY])
        self.assertEqual((machine.r[2], machine.r[29], machine.r[31]), (0, STACK, RETURN))
        self.assertEqual(machine.r[16:18], saved)
        self.assertIn(('write', 0x5270A4, GLOBAL_CLEAR, 4), machine.accesses)
        non_stack_writes = [(address, value, size) for address, value, size in machine.writes
                            if not STACK - 80 <= address < STACK]
        self.assertEqual(non_stack_writes, [(GLOBAL_CLEAR, 0, 4)])

    def test_native_upper_continuation_returns_one_after_null_wrapper_result(self):
        machine = self.guarded()
        frame = machine.frame(48, 0x2C)
        saved = (0x55000000, 0x55000001, 0x55000002, 0x55000003)
        for index, value in enumerate(saved):
            machine.put(frame + 0x1C + index * 4, value, 4)
        machine.r[4] = 0  # A0 from the selected branch delay at 4C194C.
        machine.run_at(0x4C1A3C, RETURN)

        self.assertEqual(machine.calls, [WRAPPER, FACTORY])
        self.assertEqual(machine.wrapper_result, 0)
        self.assertEqual((machine.r[2], machine.r[29], machine.r[31]), (1, STACK, RETURN))
        self.assertEqual(tuple(machine.r[16:20]), saved)

    def test_live_handle_matches_stock_on_both_allocation_outcomes(self):
        for allocation in (0, ALLOCATION):
            with self.subTest(allocation=allocation):
                options = dict(factory_result=HANDLE, allocation_result=allocation)
                native = D180PayloadGuardMachine(self.image, **options)
                guarded = self.guarded(**options)
                native.run_at(WRAPPER, RETURN)

                guarded.run_at(WRAPPER, ALLOCATOR)
                self.assertEqual(guarded.calls, [FACTORY])
                self.assertEqual((guarded.r, guarded.hi, guarded.lo), native.allocation_entry)
                self.assertEqual((guarded.r[4], guarded.r[17], guarded.r[29], guarded.r[31]),
                                 (16, HANDLE, STACK - 80, 0x5270B4))
                # The harness dispatches linked calls. The emitted tail J
                # reaches the same allocator entry, which uses the same stub.
                guarded.external(ALLOCATOR)
                guarded.run_at(guarded.r[31], RETURN)

                self.assertEqual((guarded.r, guarded.hi, guarded.lo),
                                 (native.r, native.hi, native.lo))
                self.assertEqual((guarded.r[2], guarded.r[29], guarded.r[31]),
                                 (HANDLE, STACK, RETURN))
                self.assertEqual(guarded.writes, native.writes)
                self.assertEqual(guarded.get(GLOBAL_CLEAR, 4), 0)
                self.assertEqual(guarded.get(HANDLE + 0x58, 4), allocation)
                expected_keys = [84, 82, 83, 87] if allocation else []
                self.assertEqual(guarded.lookups, expected_keys)
                self.assertEqual(guarded.calls, [FACTORY, ALLOCATOR] + [LOOKUP] * len(expected_keys))
                payload = tuple(guarded.get(ALLOCATION + offset, 4) for offset in (0, 4, 8, 12))
                self.assertEqual(payload, VALUES if allocation else (0xCCCCCCCC,) * 4)

    def failure_exit(self, site):
        branch = self.image.word(site + 20)
        self.assertEqual(branch >> 16, 0x1040)
        return site + 24 + 4 * sx16(branch & 0xFFFF)

    def test_batch_pairs_keep_both_native_delay_instructions(self):
        self.assertEqual(len(LOWER), 6)
        self.assertEqual(len(self.code), 196)
        self.assertEqual(set(self.patches), {0x5270AC, *(site + 12 for site, *_ in LOWER)})
        for site, _, _, _ in LOWER:
            with self.subTest(site=hex(site)):
                original, replacement = self.patches[site + 12]
                self.assertEqual(original, (0x0C119A78, self.image.word(site + 16)))
                self.assertEqual(original[0], self.image.word(site + 12))
                self.assertEqual(replacement[1], original[1])
                self.assertEqual(replacement[0] >> 26, 2)
                entry = (replacement[0] & 0x03FFFFFF) << 2
                failure_jump, delay = struct.unpack_from('<2I', self.code, entry - CODE_BASE + 20)
                self.assertEqual(failure_jump, (2 << 26) | (self.failure_exit(site) >> 2))
                self.assertEqual(delay, self.image.word(site + 24))

    def test_batch_null_exits_skip_allocation_and_restore_the_native_frames(self):
        for site, _, size, saved_count in LOWER:
            with self.subTest(site=hex(site)):
                machine = self.guarded(AllocationContinuationMachine)
                saved = machine.seed_frame(size, saved_count)
                machine.run_at(site, site + 8)
                writes = machine.writes.copy()
                exit_pc = self.failure_exit(site)
                machine.run_at(site + 8, exit_pc)
                machine.run_at(exit_pc, RETURN)

                self.assertEqual(machine.calls, [FACTORY])
                self.assertEqual(machine.writes, writes)
                self.assertEqual((machine.r[2], machine.r[29], machine.r[31]), (0, STACK, RETURN))
                self.assertEqual(machine.r[16:16 + saved_count], saved)
                self.assertEqual(machine.get(HANDLE + 0x58, 4), OLD_PAYLOAD)

    def test_batch_live_paths_match_stock_through_attach_or_failure_return(self):
        for site, store, size, saved_count in LOWER:
            for allocation in (0, ALLOCATION):
                with self.subTest(site=hex(site), allocation=allocation):
                    options = dict(factory_result=HANDLE, allocation_result=allocation)
                    native = AllocationContinuationMachine(self.image, **options)
                    guarded = self.guarded(AllocationContinuationMachine, **options)
                    start = NOTICE_WRAPPER if site == NOTICE_FACTORY else site
                    for machine in (native, guarded):
                        if site == NOTICE_FACTORY:
                            machine.r[6] = TEXT
                        else:
                            machine.seed_frame(size, saved_count)
                        machine.bytes(ALLOCATION, b'\xCC' * 0x100)

                    stop = store + 4 if allocation and site != NOTICE_FACTORY else RETURN
                    native.run_at(start, stop)
                    guarded.run_at(start, ALLOCATOR)
                    self.assertEqual(guarded.calls, [FACTORY])
                    self.assertEqual((guarded.r, guarded.hi, guarded.lo), native.allocation_entry)
                    self.assertEqual((guarded.r[29], guarded.r[31]), (STACK - size, site + 20))
                    guarded.external(ALLOCATOR)
                    guarded.run_at(guarded.r[31], stop)

                    self.assertEqual(guarded.calls, native.calls)
                    self.assertEqual((guarded.r, guarded.hi, guarded.lo),
                                     (native.r, native.hi, native.lo))
                    self.assertEqual(guarded.writes, native.writes)
                    self.assertEqual(guarded.regions[ALLOCATION], native.regions[ALLOCATION])
                    self.assertEqual(guarded.get(HANDLE + 0x58, 4), allocation or OLD_PAYLOAD)
                    if site == NOTICE_FACTORY and allocation:
                        self.assertEqual(guarded.regions[ALLOCATION][:4 + len(SAMPLE)], b'\0' * 4 + SAMPLE)

    def test_notice_early_exit_preserves_the_actual_upper_configuration(self):
        _, _, size, saved_count = NOTICE_UPPER
        for old in (OLD_NOTICE, 0):
            with self.subTest(old=old):
                native = NoticeGuardMachine(self.image, allocation_result=0)
                guarded = self.guarded(NoticeGuardMachine)
                for machine in (native, guarded):
                    saved = machine.seed_frame(size, saved_count)
                    machine.r[16:21] = [CONTEXT, old, 7, TEXT - 4, TEXT]
                    machine.put(OLD_NOTICE + 4, 0x13572468, 4)
                    machine.put(OLD_NOTICE + 0x10, NOTICE_MUTEX, 4)
                    machine.put(OLD_NOTICE + 0x58, TEXT - 4, 4)
                    machine.run_at(0x509360, RETURN)

                    self.assertEqual(machine.notice_result, 0)
                    self.assertEqual(machine.config_inputs, (0, old, 1))
                    self.assertEqual(machine.config_result, 0 if old else MASK)
                    self.assertEqual((machine.r[2], machine.r[29], machine.r[31]),
                                     (1, STACK, RETURN))
                    self.assertEqual(machine.r[16:21], saved)
                    self.assertEqual(machine.get(OLD_NOTICE + 4, 4), 1 if old else 0x13572468)
                    self.assertEqual(machine.get(OLD_NOTICE + 0x58, 4), TEXT - 4)
                    self.assertEqual(machine.get(HANDLE + 0x58, 4), OLD_PAYLOAD)

                self.assertEqual(native.calls[:3], [NOTICE_WRAPPER, FACTORY, ALLOCATOR])
                self.assertEqual(guarded.calls, [target for target in native.calls if target != ALLOCATOR])
                self.assertNotIn(STRCPY, guarded.calls)
                self.assertNotEqual(native.config_scratch, guarded.config_scratch)
                expected_mutex = [(LOCK_IMPORT, NOTICE_MUTEX), (UNLOCK_IMPORT, NOTICE_MUTEX)] if old else []
                self.assertEqual(native.mutex_calls, expected_mutex)
                self.assertEqual(guarded.mutex_calls, expected_mutex)
                for base in (CONTEXT, HANDLE, ALLOCATION):
                    self.assertEqual(guarded.regions[base], native.regions[base])


if __name__ == '__main__':
    unittest.main()
