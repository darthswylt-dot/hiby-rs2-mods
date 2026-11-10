#!/usr/bin/env python3
"""Run the update-check guard with the stock timer registration and queue writer."""

import struct
import unittest

import build_reveal_d180_check_upgrade_test as build_test
import factory_null_audit as audit
import reveal_d180_check_upgrade_guard_mips as guard
from build_reveal_bridge_diag import BASE
from build_reveal_d960_payload_guard_test import RX_HEADER
from test_factory_null_audit import ALLOCATION, ALLOCATOR, CONTEXT, HANDLE, RETURN, STACK
from test_reveal_d180_data_dealing_snapshot_mips import CODE_BASE as DATA_CODE_BASE, data_dealing_fixture
from test_reveal_d960_payload_guard_mips import PayloadGuardMachine


CODE_BASE = 0xC711F8
PATCH_SITES = (0x4D4FF0, 0x4D5018)
WRAPPER, FACTORY, INIT, REGISTER = 0x4D4FA0, 0x47D180, 0x4D4CC0, 0x4738A0
POST, QUEUE_WRITE = 0x454B40, 0x4504E0
QUEUE, QUEUE_GLOBAL, STATUS = 0x1D0B100, 0xB89250, 0xB8927C
OWNER_FLAG, PROGRESS = CONTEXT + 0x208, 0xB8BAA4
TIMER_COUNT, TIMER = 0xB89B74, 0xB89B78
UPPER = (
    # Native call, frame size, first saved S-register offset, count, expected return.
    (0x453CF8, 32, 0x18, 1, 0),
    (0x4CBEEC, 56, 0x28, 3, 1),
    (0x4D732C, 56, 0x2C, 2, 1),
)


class UpgradeMachine(PayloadGuardMachine):
    def __init__(self, image, *, status=3, mode=0, **options):
        super().__init__(image, **options)
        self.map(QUEUE, 0x20)
        self.put(QUEUE, 2, 4)
        self.put(QUEUE_GLOBAL, QUEUE, 4)
        self.put(STATUS, status, 4)
        self.put(OWNER_FLAG, 0x26, 4)
        self.put(PROGRESS, 0x17, 4)
        self.r[4:7] = [CONTEXT + 0x80, CONTEXT, mode]
        self.descriptor = self.status_at_factory = self.status_at_post = None
        self.wrapper_result = None

    def external(self, target):
        if target == FACTORY:
            self.calls.append(target)
            self.status_at_factory = self.get(STATUS, 4)
            descriptor = self.get(self.r[29] + 0x10, 4)
            self.descriptor = tuple(self.get(descriptor + offset, 4) for offset in range(0, 28, 4))
            if self.factory_result:
                self.put(HANDLE + 0x74, self.descriptor[1], 4)
                self.r[4] = HANDLE
                self.calls.append(INIT)
                self.run_at(INIT, self.r[31])
            self.hostile_result(self.factory_result)
        elif target in (WRAPPER, guard.ARM, REGISTER, POST, QUEUE_WRITE):
            self.calls.append(target)
            if target == POST:
                self.status_at_post = self.get(STATUS, 4)
            self.run_at(target, self.r[31])
            if target == WRAPPER:
                self.wrapper_result = self.r[2]
        else:
            super().external(target)

    def queued_message(self):
        return struct.unpack_from('<2I', self.regions[ALLOCATION])


class D180CheckUpgradeGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = audit.source_image()
        book, cls.baseline, cls.data_patches = data_dealing_fixture(cls.image)
        cls.candidate = build_test.build(cls.baseline)
        cls.code = cls.candidate[len(book):]
        cls.patches = {
            pc: (struct.unpack_from('<2I', cls.baseline, pc - BASE),
                 struct.unpack_from('<2I', cls.candidate, pc - BASE))
            for pc in PATCH_SITES
        }

    def guarded(self, **options):
        return UpgradeMachine(self.image, code=self.code,
                              patches={**self.data_patches, **self.patches},
                              code_base=DATA_CODE_BASE, **options)

    def test_patches_match_the_native_prearm_and_result_pairs(self):
        code, patches = guard.assemble(CODE_BASE)
        self.assertEqual(code, self.candidate[len(self.baseline):])
        self.assertEqual(patches, self.patches)
        for pc, (original, _) in self.patches.items():
            self.assertEqual(original, (self.image.word(pc), self.image.word(pc + 4)))
        self.assertEqual(self.patches[0x4D4FF0][1], (0, 0xAFA00038))
        self.assertEqual(self.patches[0x4D5018][1], ((2 << 26) | (CODE_BASE >> 2), 0x00408021))

    def test_image_restores_to_the_entire_data_dealing_baseline(self):
        self.assertEqual(len(self.baseline), 0x6D11F8)
        self.assertEqual(len(self.candidate), 0x6D121C)
        self.assertEqual(struct.unpack_from('<8I', self.candidate, RX_HEADER),
                         (1, 0x6D0000, 0xC70000, 0xC70000, 0x121C, 0x121C, 5, 0x10000))
        restored = bytearray(self.candidate[:len(self.baseline)])
        restored[RX_HEADER + 16:RX_HEADER + 24] = self.baseline[RX_HEADER + 16:RX_HEADER + 24]
        for pc, (original, _) in self.patches.items():
            struct.pack_into('<2I', restored, pc - BASE, *original)
        self.assertEqual(bytes(restored), self.baseline)
        with self.assertRaisesRegex(ValueError, 'exact hardware-tested data_dealing ELF'):
            build_test.build(self.candidate)

    def test_refusal_preserves_preexisting_status_progress_and_owner(self):
        for status in (0, 1, 3):
            for mode in (0, 1):
                with self.subTest(status=status, mode=mode):
                    machine = self.guarded(status=status, mode=mode)
                    saved = machine.r[16:19]
                    machine.run_at(WRAPPER, RETURN)
                    self.assertEqual(machine.calls, [FACTORY])
                    self.assertEqual(machine.descriptor, (INIT, 0x4D4C80, 0, 0, 0, 0, 0))
                    self.assertEqual(machine.status_at_factory, status)
                    self.assertEqual(machine.get(STATUS, 4), status)
                    self.assertEqual(machine.get(PROGRESS, 4), 0x17)
                    self.assertEqual(machine.get(OWNER_FLAG, 4), 0x26)
                    self.assertEqual(machine.get(TIMER_COUNT, 4), 0)
                    self.assertEqual(machine.get(QUEUE + 0x10, 4), 0)
                    self.assertEqual(machine.r[16:19], saved)
                    self.assertEqual((machine.r[2], machine.r[29], machine.r[31]), (0, STACK, RETURN))

    def test_live_result_keeps_the_timer_state_and_worker_message_for_both_modes(self):
        for mode in (0, 1):
            with self.subTest(mode=mode):
                native = UpgradeMachine(self.image, mode=mode, factory_result=HANDLE)
                guarded = self.guarded(mode=mode, factory_result=HANDLE)
                for machine in (native, guarded):
                    machine.run_at(WRAPPER, RETURN)
                    self.assertEqual(machine.status_at_post, 1)
                    self.assertEqual(machine.queued_message(), (4, mode))
                    self.assertEqual(machine.get(QUEUE + 0x10, 4), ALLOCATION)
                    self.assertEqual(machine.get(STATUS, 4), 1)
                    self.assertEqual(machine.get(PROGRESS, 4), 0)
                    self.assertEqual(machine.get(OWNER_FLAG, 4), 0)
                    self.assertEqual(machine.get(HANDLE + 0x4C, 4), mode)
                    self.assertEqual(machine.get(HANDLE + 0x5C, 4), 1)
                    self.assertEqual(machine.get(TIMER_COUNT, 4), 1)
                    self.assertEqual(tuple(machine.get(TIMER + offset, 4) for offset in range(0, 24, 4)),
                                     (HANDLE, 200, 0, 1, HANDLE, 0x4D4D00))
                    self.assertEqual((machine.r[2], machine.r[29], machine.r[31]), (HANDLE, STACK, RETURN))
                self.assertEqual(native.status_at_factory, 1)
                self.assertEqual(guarded.status_at_factory, 3)
                self.assertEqual(native.calls, [guard.ARM, FACTORY, INIT, REGISTER, POST, QUEUE_WRITE,
                                               ALLOCATOR, 0xA5B440])
                self.assertEqual(guarded.calls, [FACTORY, INIT, REGISTER, guard.ARM, POST, QUEUE_WRITE,
                                                ALLOCATOR, 0xA5B440])
                self.assertEqual(guarded.r, native.r)

    def test_live_queue_allocation_refusal_uses_the_inherited_writer_guard(self):
        machine = self.guarded(factory_result=HANDLE, allocation_result=0)
        queue_before = bytes(machine.regions[QUEUE])
        machine.run_at(WRAPPER, RETURN)

        self.assertIn(ALLOCATOR, machine.calls)
        self.assertNotIn(0xA5B440, machine.calls)
        self.assertEqual(bytes(machine.regions[QUEUE]), queue_before)
        self.assertEqual(machine.get(STATUS, 4), 1)
        self.assertEqual(machine.get(TIMER_COUNT, 4), 1)
        self.assertEqual((machine.r[2], machine.r[29], machine.r[31]), (HANDLE, STACK, RETURN))

    def test_three_encoded_callers_keep_their_native_returns_after_refusal(self):
        for site, size, offset, count, expected in UPPER:
            with self.subTest(site=hex(site)):
                machine = self.guarded()
                frame = machine.frame(size, size - 4)
                saved = [0x55000000 + index for index in range(count)]
                for index, value in enumerate(saved):
                    machine.put(frame + offset + index * 4, value, 4)
                machine.run_at(site, RETURN)

                self.assertEqual(machine.calls, [WRAPPER, FACTORY])
                self.assertEqual(machine.wrapper_result, 0)
                self.assertEqual((machine.r[2], machine.r[29], machine.r[31]),
                                 (expected, STACK, RETURN))
                self.assertEqual(machine.r[16:16 + count], saved)


if __name__ == '__main__':
    unittest.main()
