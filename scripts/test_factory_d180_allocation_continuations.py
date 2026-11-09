#!/usr/bin/env python3
"""Execute the six allocation-dependent D180 callers and known upper exits."""

import unittest

import factory_null_audit as audit
from test_factory_null_audit import (
    ALLOCATION, ALLOCATOR, CONFIGURATOR, CONTEXT, HANDLE, MASK, RETURN, STACK,
    LineageMachine, NullFault,
)
from test_reveal_d960_payload_guard_mips import PayloadGuardMachine


FACTORY, MEMSET, TIME, STRCPY = 0x47D180, 0xA5BC60, 0xA5B630, 0xA5BEE0
LOCK, UNLOCK = 0x466DA0, 0x466DC0
LOCK_IMPORT, UNLOCK_IMPORT = 0xA5B960, 0xA5B830
OLD_PAYLOAD, TEXT = 0x1D06000, CONTEXT + 0x80
SAMPLE = b'fixture\0'
LOWER = (
    # Factory JAL, unchecked store, frame bytes, saved S-register count.
    (0x4CFF38, 0x4CFF6C, 80, 2),
    (0x4D1ADC, 0x4D1B10, 144, 3),
    (0x4D2B44, 0x4D2B70, 88, 4),
    (0x4D3724, 0x4D3750, 80, 2),
    (0x509A2C, 0x509A58, 80, 3),
    (0x515218, 0x515244, 80, 2),
)
PURE_UPPER = (
    # Upper JAL, wrapper entry, frame bytes, saved S-register count.
    (0x4CB100, 0x4CFEE0, 40, 3),
    (0x4CB0A4, 0x4D1A80, 40, 3),
    (0x4C9124, 0x4D2AE0, 192, 4),
    (0x4C8C20, 0x4D36C0, 192, 4),
    (0x4C1A2C, 0x5151C0, 48, 4),
)
NOTICE_UPPER = (0x509368, 0x5099C0, 48, 5)
ALL_UPPER = (*PURE_UPPER, NOTICE_UPPER)
WRAPPERS = {wrapper for _, wrapper, _, _ in ALL_UPPER}


class AllocationContinuationMachine(PayloadGuardMachine):
    def __init__(self, image, *, wrapper_result=0, **options):
        super().__init__(image, **options)
        self.wrapper_result = wrapper_result
        self.r[18] = TEXT
        self.bytes(TEXT, SAMPLE)
        self.put(HANDLE + 0x58, OLD_PAYLOAD, 4)
        self.map(0x938C88, 4)
        self.put(0x938C88, image.word(0x938C88), 4)
        self.mutex_calls = []
        self.config_inputs = self.config_result = None

    def seed_frame(self, size, saved_count):
        frame = self.frame(size, size - 4)
        saved = [0x55000000 + index for index in range(saved_count)]
        for index, value in enumerate(saved):
            self.put(frame + size - 4 * (saved_count + 1 - index), value, 4)
        return saved

    def external(self, target):
        if target == MEMSET:
            LineageMachine.external(self, target)
        elif target == STRCPY:
            self.calls.append(target)
            if self.r[4:6] != [ALLOCATION + 4, TEXT]:
                raise AssertionError('unexpected string copy arguments')
            for offset in range(len(SAMPLE)):
                self.put(self.r[4] + offset, self.get(TEXT + offset, 1), 1)
            self.hostile_result(self.r[4])
        elif target == TIME or target in WRAPPERS:
            self.calls.append(target)
            self.hostile_result(0 if target == TIME else self.wrapper_result)
        elif target == CONFIGURATOR:
            self.calls.append(target)
            self.config_inputs = (self.r[2], self.r[4], self.r[5])
            self.run_at(target, self.r[31])
            self.config_result = self.r[2]
        elif target in (LOCK, UNLOCK):
            self.calls.append(target)
            self.run_at(target, self.r[31])
        elif target in (LOCK_IMPORT, UNLOCK_IMPORT):
            self.calls.append(target)
            self.mutex_calls.append((target, self.r[4]))
            self.hostile_result(0)
        else:
            super().external(target)


class NativeD180AllocationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = audit.source_image()

    def framed(self, size, saved_count, **options):
        machine = AllocationContinuationMachine(self.image, **options)
        return machine, machine.seed_frame(size, saved_count)

    def test_each_wrapper_has_one_encoded_direct_caller(self):
        found = set()
        for start, end in self.image.executable_ranges():
            for pc in range(start, end, 4):
                word = self.image.word(pc)
                if word >> 26 in (2, 3):
                    target = ((pc + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)
                    if target in WRAPPERS:
                        found.add((pc, target))
        self.assertEqual(found, {(site, wrapper) for site, wrapper, _, _ in ALL_UPPER})

    def test_six_successful_allocations_reach_the_unchecked_store(self):
        for site, fault, size, saved_count in LOWER:
            with self.subTest(site=hex(site)):
                empty, _ = self.framed(size, saved_count)
                with self.assertRaises(NullFault) as failed:
                    empty.run_at(site, fault + 4)
                self.assertEqual((failed.exception.pc, failed.exception.address,
                                  failed.exception.operation), (fault, 0x58, 'write'))
                self.assertEqual(empty.calls[:2], [FACTORY, ALLOCATOR])

                live, _ = self.framed(size, saved_count, factory_result=HANDLE)
                live.run_at(site, fault + 4)
                self.assertEqual(live.get(HANDLE + 0x58, 4), ALLOCATION)

    def test_six_failed_allocations_return_the_saved_factory_result(self):
        for site, _, size, saved_count in LOWER:
            for result in (0, HANDLE):
                with self.subTest(site=hex(site), result=result):
                    machine, saved = self.framed(size, saved_count, factory_result=result,
                                                 allocation_result=0)
                    machine.run_at(site, RETURN)
                    self.assertEqual(machine.calls, [FACTORY, ALLOCATOR])
                    self.assertEqual((machine.r[2], machine.r[29], machine.r[31]),
                                     (result, STACK, RETURN))
                    self.assertEqual(machine.r[16:16 + saved_count], saved)
                    self.assertEqual(machine.get(HANDLE + 0x58, 4), OLD_PAYLOAD)

    def test_five_upper_continuations_replace_the_wrapper_result_with_one(self):
        for site, wrapper, size, saved_count in PURE_UPPER:
            for result in (0, HANDLE):
                with self.subTest(site=hex(site), result=result):
                    machine, saved = self.framed(size, saved_count, wrapper_result=result)
                    machine.run_at(site, RETURN)
                    self.assertEqual(machine.calls, [wrapper])
                    self.assertEqual((machine.r[2], machine.r[29], machine.r[31]),
                                     (1, STACK, RETURN))
                    self.assertEqual(machine.r[16:16 + saved_count], saved)

    def test_notice_continuation_configures_only_the_old_context_then_returns_one(self):
        site, wrapper, size, saved_count = NOTICE_UPPER
        for old in (0, CONTEXT):
            for result in (0, HANDLE):
                with self.subTest(old=old, result=result):
                    machine, saved = self.framed(size, saved_count, wrapper_result=result)
                    machine.r[17] = old
                    machine.put(CONTEXT + 0x10, ALLOCATION, 4)
                    machine.run_at(site, RETURN)
                    self.assertEqual(machine.config_inputs, (result, old, 1))
                    self.assertEqual(machine.calls[:2], [wrapper, CONFIGURATOR])
                    self.assertEqual(machine.config_result, 0 if old else MASK)
                    self.assertEqual(machine.mutex_calls,
                                     [(LOCK_IMPORT, ALLOCATION), (UNLOCK_IMPORT, ALLOCATION)]
                                     if old else [])
                    self.assertEqual(machine.get(CONTEXT + 4, 4), int(bool(old)))
                    self.assertEqual((machine.r[2], machine.r[29], machine.r[31]),
                                     (1, STACK, RETURN))
                    self.assertEqual(machine.r[16:21], saved)


if __name__ == '__main__':
    unittest.main()
