#!/usr/bin/env python3
"""Run the D180 context-read helpers through their checked native callers."""

import unittest

import factory_null_audit as audit
from test_factory_null_audit import ALLOCATION, ALLOCATOR, CONTEXT, HANDLE, RETURN, STACK
from test_reveal_d180_wifi_scan_guard_mips import CODE_BASE, ui_guard_fixture
from test_reveal_d960_payload_guard_mips import OLD_PAYLOAD, PayloadGuardMachine


REMOVE, COLOR, VIEW_LOOKUP, FACTORY = 0x4AF8C0, 0x4CF180, 0x4E5320, 0x47D180
OWNER, VIEW = CONTEXT + 0x80, CONTEXT + 0x100
BRANCHES = (
    # Wrapper entry, first instruction with an empty or a populated context.
    (REMOVE, 0x4AFB80, 0x4AF970),
    (COLOR, 0x4CF23C, 0x4CF20C),
)
UPPER = (
    # Wrapper entry, caller slice, caller frame size, saved S-register count.
    (REMOVE, 0x4B9880, 120, 3),
    (COLOR, 0x4C84AC, 192, 4),
)


class ContextReadMachine(PayloadGuardMachine):
    def __init__(self, image, *, payload=OLD_PAYLOAD, **options):
        super().__init__(image, **options)
        self.map(OLD_PAYLOAD, 0xCF0)
        self.put(HANDLE + 0x58, payload, 4)
        self.put(CONTEXT + 0x50, OWNER, 4)
        self.r[4:7] = [OWNER, VIEW, CONTEXT]
        self.wrapper_results = []

    def external(self, target):
        if target in (REMOVE, COLOR):
            self.calls.append(target)
            self.run_at(target, self.r[31])
            self.wrapper_results.append(self.r[2])
        elif target == VIEW_LOOKUP:
            self.calls.append(target)
            self.put(self.r[6], VIEW, 4)
            self.hostile_result(0)
        else:
            super().external(target)


class D180ContextGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = audit.source_image()
        baseline, candidate, cls.patches = ui_guard_fixture(cls.image)
        cls.code = candidate[len(baseline):]

    def guarded(self, **options):
        return ContextReadMachine(self.image, code=self.code, patches=self.patches,
                                  code_base=CODE_BASE, **options)

    def test_redirects_match_the_native_save_and_load_pairs(self):
        expected_pairs = (
            (0x4AF960, (0x00409021, 0x8C420058)),
            (0x4CF1FC, (0x00408021, 0x8C420058)),
            (0x4AFC7C, (0x00408821, 0x8C420058)),
        )
        for index, (pc, expected) in enumerate(expected_pairs, start=1):
            original, replacement = self.patches[pc]
            target = CODE_BASE + index * 24
            self.assertEqual(original, expected)
            self.assertEqual(original, (self.image.word(pc), self.image.word(pc + 4)))
            self.assertEqual(replacement, ((2 << 26) | (target >> 2), expected[0]))

    def test_null_wrapper_results_reach_the_two_native_upper_returns(self):
        for wrapper, site, size, count in UPPER:
            with self.subTest(wrapper=hex(wrapper)):
                machine = self.guarded()
                frame = machine.frame(size, size - 4)
                saved = [0x55000000 + index for index in range(count)]
                for index, value in enumerate(saved):
                    machine.put(frame + size - 4 * (count + 1 - index), value, 4)
                machine.r[18] = OWNER
                machine.run_at(site, RETURN)

                expected = [wrapper, VIEW_LOOKUP, FACTORY] if wrapper == REMOVE else [wrapper, FACTORY]
                self.assertEqual(machine.calls, expected)
                self.assertEqual(machine.wrapper_results, [0])
                self.assertEqual((machine.r[2], machine.r[29], machine.r[31]), (1, STACK, RETURN))
                self.assertEqual(machine.r[16:16 + count], saved)
                self.assertEqual(machine.get(HANDLE + 0x58, 4), OLD_PAYLOAD)

    def test_live_handles_follow_the_same_native_context_branches(self):
        for wrapper, empty_pc, cached_pc in BRANCHES:
            for payload in (0, OLD_PAYLOAD):
                with self.subTest(wrapper=hex(wrapper), payload=payload):
                    options = dict(factory_result=HANDLE, payload=payload)
                    native = ContextReadMachine(self.image, **options)
                    guarded = self.guarded(**options)
                    stop = cached_pc if payload else empty_pc
                    for machine in (native, guarded):
                        machine.run_at(wrapper, stop)
                        self.assertEqual(machine.r[2], payload)

                    self.assertEqual(guarded.calls, native.calls)
                    self.assertEqual((guarded.r, guarded.hi, guarded.lo),
                                     (native.r, native.hi, native.lo))
                    self.assertEqual(guarded.writes, native.writes)

    def test_color_keeps_the_native_allocation_failure_and_publication(self):
        for allocation, stop in ((0, RETURN), (ALLOCATION, 0x4CF250)):
            with self.subTest(allocation=allocation):
                options = dict(factory_result=HANDLE, payload=0, allocation_result=allocation)
                native = ContextReadMachine(self.image, **options)
                guarded = self.guarded(**options)
                for machine in (native, guarded):
                    machine.run_at(COLOR, stop)
                    self.assertEqual(machine.calls, [FACTORY, ALLOCATOR])
                    self.assertEqual(machine.get(HANDLE + 0x58, 4), allocation)
                    self.assertIn(('write', 0x4CF24C, HANDLE + 0x58, 4), machine.accesses)

                self.assertEqual((guarded.r, guarded.hi, guarded.lo),
                                 (native.r, native.hi, native.lo))
                self.assertEqual(guarded.writes, native.writes)


if __name__ == '__main__':
    unittest.main()
