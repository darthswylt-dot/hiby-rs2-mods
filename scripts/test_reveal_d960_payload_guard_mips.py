#!/usr/bin/env python3
"""Run the test image's two payload redirects in the bounded caller model."""

import struct
import unittest

import build_reveal_bridge_diag as bridge
import build_reveal_d960_payload_guard_test as build_test
import factory_null_audit as audit
import reveal_d960_payload_guard_mips as guard
from test_factory_null_audit import (
    ALLOCATION, ALLOCATOR, COPY, HANDLE, RETURN, STACK, GuardedNullCallerMachine,
)


CODE_BASE = 0xC70D60
OLD_PAYLOAD = 0x1D06000
SAVED = (0x55000000, 0x55000001, 0x55000002)
FACTORY = 0x47D960
CASES = (
    # Factory JAL, failure suffix, frame size, saved GPRs, prior V0 home, payload size.
    (0x5091A8, 0x5091E4, 144, 3, 0x10, 72),
    (0x50BAB4, 0x50BAEC, 72, 1, 0x24, 4),
)


class PayloadGuardMachine(GuardedNullCallerMachine):
    def __init__(self, image, code=b'', patches=None, **options):
        super().__init__(image, **options)
        self.code = code
        self.replacements = {
            pc + offset: word
            for pc, (_, pair) in (patches or {}).items()
            for offset, word in zip((0, 4), pair)
        }
        self.allocation_entry = None

    def word(self, pc):
        self.fetch_pc = pc
        if pc in self.replacements:
            return self.replacements[pc]
        if CODE_BASE <= pc < CODE_BASE + len(self.code):
            return struct.unpack_from('<I', self.code, pc - CODE_BASE)[0]
        return super().word(pc)

    def external(self, target):
        if target == ALLOCATOR:
            self.allocation_entry = (self.r.copy(), self.hi, self.lo)
        super().external(target)


class D960PayloadGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = audit.source_image()
        cls.baseline, cls.layout = bridge.build(cls.image.data)
        cls.candidate = build_test.build(cls.baseline)
        cls.code = cls.candidate[len(cls.baseline):]
        _, patches = guard.assemble(CODE_BASE)
        cls.patches = {
            pc: (original, struct.unpack_from('<2I', cls.candidate, pc - bridge.BASE))
            for pc, (original, _) in patches.items()
        }

    def seed(self, machine, frame_size, saved_count):
        frame = machine.frame(frame_size, frame_size - 4)
        first_save = frame + frame_size - 4 * (saved_count + 1)
        for index, value in enumerate(SAVED[:saved_count]):
            machine.put(first_save + 4 * index, value, 4)
        if frame_size == 144:
            machine.bytes(frame + 0x20, bytes(range(1, 65)))
        machine.put(HANDLE + 0x58, OLD_PAYLOAD, 4)
        machine.bytes(ALLOCATION, b'\xCC' * 0x100)
        machine.writes.clear()
        return frame

    def test_redirects_match_the_pinned_native_pairs(self):
        expected = {
            0x5091B4: (0x0C119A78, 0x00408821),
            0x50BAC0: (0x0C119A78, 0x00408021),
        }
        self.assertEqual(set(self.patches), set(expected))
        self.assertEqual(len(self.code), 56)
        for pc, pair in expected.items():
            original, replacement = self.patches[pc]
            self.assertEqual(original, pair)
            self.assertEqual(original, (self.image.word(pc), self.image.word(pc + 4)))
            self.assertEqual(replacement[1], original[1])

    def test_image_extends_the_hardware_baseline_within_one_rx_page(self):
        old_code_size = self.layout['code_bytes']
        self.assertEqual(self.layout['code_base'] + old_code_size, CODE_BASE)
        header = self.layout['phdr_offset']
        new_code_size = old_code_size + len(self.code)
        self.assertEqual(struct.unpack_from('<8I', self.candidate, header),
                         (1, self.layout['code_offset'], self.layout['code_base'],
                          self.layout['code_base'], new_code_size, new_code_size, 5, 0x10000))
        self.assertLessEqual(new_code_size, 0x1000)

        restored = bytearray(self.candidate[:len(self.baseline)])
        restored[header + 16:header + 24] = self.baseline[header + 16:header + 24]
        for pc, (original, _) in self.patches.items():
            struct.pack_into('<I', restored, pc - bridge.BASE, original[0])
        self.assertEqual(bytes(restored), self.baseline)
        with self.assertRaisesRegex(ValueError, 'exact hardware-tested capture ELF'):
            build_test.build(self.candidate)

    def test_entire_generated_span_must_fit_outside_native_loads(self):
        for base in (True, 0, CODE_BASE + 1, 0x3FFFFC, 0x5091B4,
                     0xA6BFFC, 0xBD3000, 0x0FFFFFCC, 0x10000000):
            with self.subTest(base=base), self.assertRaises(ValueError):
                guard.assemble(base)
        self.assertEqual(len(guard.assemble(0x0FFFFFC8)[0]), 56)

    def test_null_factory_result_unwinds_without_calling_allocator(self):
        for factory_pc, suffix, frame_size, saved_count, result_home, size in CASES:
            with self.subTest(site=hex(factory_pc)):
                machine = PayloadGuardMachine(self.image, self.code, self.patches)
                frame = self.seed(machine, frame_size, saved_count)
                prior_v0 = machine.r[2]
                machine.run_at(factory_pc, suffix)
                if size == 72:
                    self.assertEqual(machine.r[16], 0)  # addu s0,v0,zero
                else:
                    self.assertEqual(machine.r[4], 0x510000)  # lui a0,0x51
                machine.run_at(suffix, RETURN)

                self.assertEqual(machine.calls, [FACTORY])
                self.assertIsNone(machine.allocation_entry)
                self.assertEqual((machine.r[2], machine.r[29], machine.r[31]),
                                 (0, STACK, RETURN))
                self.assertEqual(tuple(machine.r[16:16 + saved_count]), SAVED[:saved_count])
                self.assertEqual(machine.get(frame + result_home, 4), prior_v0)
                self.assertEqual(machine.get(HANDLE + 0x58, 4), OLD_PAYLOAD)
                self.assertEqual(machine.regions[ALLOCATION], b'\xCC' * 0x100)
                self.assertEqual([address for address, _, _ in machine.writes],
                                 [frame + result_home, frame, frame + 4, frame + 8, frame + 12])

    def test_live_factory_result_matches_native_allocation_paths(self):
        for factory_pc, _, frame_size, saved_count, _, size in CASES:
            for allocation in (0, ALLOCATION):
                with self.subTest(site=hex(factory_pc), allocation=allocation):
                    options = dict(factory_result=HANDLE, allocation_result=allocation)
                    native = PayloadGuardMachine(self.image, **options)
                    guarded = PayloadGuardMachine(self.image, self.code, self.patches, **options)
                    self.seed(native, frame_size, saved_count)
                    frame = self.seed(guarded, frame_size, saved_count)

                    native.run_at(factory_pc, RETURN)
                    # The harness dispatches linked calls, so cut at the tail
                    # target and run the same bounded allocator substitute.
                    guarded.run_at(factory_pc, ALLOCATOR)
                    self.assertEqual(guarded.calls, [FACTORY])
                    self.assertEqual((guarded.r, guarded.hi, guarded.lo), native.allocation_entry)
                    self.assertEqual((guarded.r[4], guarded.r[29], guarded.r[31]),
                                     (size, frame, factory_pc + 20))
                    guarded.external(ALLOCATOR)
                    guarded.run_at(guarded.r[31], RETURN)

                    expected_calls = [FACTORY, ALLOCATOR]
                    if allocation:
                        expected_calls.append(COPY if size == 72 else 0x477600)
                    self.assertEqual(guarded.calls, expected_calls)
                    self.assertEqual(guarded.calls, native.calls)
                    self.assertEqual((guarded.r, guarded.hi, guarded.lo),
                                     (native.r, native.hi, native.lo))
                    self.assertEqual((guarded.r[2], guarded.r[29], guarded.r[31]),
                                     (HANDLE, STACK, RETURN))
                    self.assertEqual(guarded.writes, native.writes)
                    self.assertEqual(guarded.regions[ALLOCATION], native.regions[ALLOCATION])
                    self.assertEqual(guarded.get(HANDLE + 0x58, 4), allocation or OLD_PAYLOAD)


if __name__ == '__main__':
    unittest.main()
