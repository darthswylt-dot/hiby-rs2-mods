#!/usr/bin/env python3
"""Run the book-percent guard with bounded allocation and dialog services."""

import struct
import unittest

import build_reveal_d180_book_percent_guard_test as build_test
import build_reveal_d180_volume_guard_test as volume
import factory_null_audit as audit
from build_reveal_bridge_diag import BASE
from build_reveal_d960_payload_guard_test import RX_HEADER
from test_factory_null_audit import (
    ALLOCATION, ALLOCATOR, CONTEXT, FREE, HANDLE, MASK, RETURN, STACK, LineageMachine,
)
from test_reveal_d180_wifi_scan_guard_mips import ui_guard_fixture
from test_reveal_d960_payload_guard_mips import PayloadGuardMachine


CODE_BASE = 0xC70ED4
PATCH_PC = 0x5276B8
WRAPPER, UPPER, DESTROY = 0x527620, 0x4C1B78, 0x527120
FACTORY, DESCRIPTOR = 0x47D180, 0x95064C
RAW_ALLOC, RAW_FREE, MEMSET = 0xA5B4B0, 0xA5B9C0, 0xA5BC60
FIND_DIALOG, MAKE_LOCK, DROP_LOCK = 0x47CA40, 0x466D60, 0x466DE0
SELECT_RESOURCE, OPEN_RESOURCE, LOG = 0x47E6C0, 0x48BDE0, 0x467160
TRACKED = 0xB894AC
PERCENT_BITS, SAVED_FP = 0x42480000, 0x123456789ABCDEF0


def book_guard_fixture(image):
    _, ui_image, _ = ui_guard_fixture(image)
    baseline = volume.build(ui_image)
    return baseline, build_test.build(baseline)


class BookPercentMachine(PayloadGuardMachine):
    payload_size = 4
    descriptor_name = DESCRIPTOR

    def __init__(self, image, *, allocate=True, resource_failure=False, **options):
        super().__init__(image, **options)
        self.allocate = allocate
        self.resource_failure = resource_failure
        self.releases, self.raw_releases, self.descriptors = [], [], []
        self.wrapper_result = None
        self.map(ALLOCATION - 4, 4)
        self.map(HANDLE - 4, 4)
        self.r[4:7] = [0, CONTEXT + 0x80, PERCENT_BITS]
        self.fp[20] = SAVED_FP

    def plain(self, word):
        # Only the three raw FP transfers in the wrapper prologue and init.
        self.executing_pc = self.fetch_pc
        if word == 0xF7B40050:  # sdc1 f20,0x50(sp)
            self.put(self.r[29] + 0x50, self.fp[20], 8)
        elif word == 0x4486A000:  # mtc1 a2,f20
            self.fp[20] = (self.fp[20] & ~MASK) | self.r[6]
        elif word == 0xE6140000:  # swc1 f20,0(s0)
            self.put(self.r[16], self.fp[20] & MASK, 4)
        else:
            super().plain(word)

    def external(self, target):
        if target in (WRAPPER, ALLOCATOR, FREE):
            self.calls.append(target)
            if target == FREE:
                self.releases.append(self.r[4])
            self.run_at(target, self.r[31])
            if target == WRAPPER:
                self.wrapper_result = self.r[2]
        elif target == FACTORY:
            self.calls.append(target)
            self.assert_descriptor()
            if self.resource_failure:
                self.run_at(target, self.r[31])
            else:
                self.hostile_result(self.factory_result)
        elif target == RAW_ALLOC:
            self.calls.append(target)
            addresses = {self.payload_size + 16: ALLOCATION - 4 if self.allocate else 0, 144: HANDLE - 4}
            self.hostile_result(addresses[self.r[4]])
        elif target == RAW_FREE:
            self.calls.append(target)
            address = self.r[4]
            if address in self.raw_releases:
                raise AssertionError('duplicate raw release')
            self.raw_releases.append(address)
            self.hostile_result(0x12345678)
        elif target in (FIND_DIALOG, MAKE_LOCK, DROP_LOCK, SELECT_RESOURCE, OPEN_RESOURCE, LOG):
            self.calls.append(target)
            self.hostile_result({MAKE_LOCK: CONTEXT + 0x10, OPEN_RESOURCE: MASK}.get(target, 0))
        elif target == MEMSET:
            LineageMachine.external(self, target)
        else:
            super().external(target)

    def assert_descriptor(self):
        frame = self.r[29]
        descriptor = self.get(frame + 0x10, 4)
        if self.r[4] != self.descriptor_name or descriptor != frame + 0x20:
            raise AssertionError('unexpected reader dialog descriptor')
        self.descriptors.append(tuple(self.get(descriptor + offset, 4) for offset in range(0, 28, 4)))


class D180BookPercentGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = audit.source_image()
        cls.baseline, cls.candidate = book_guard_fixture(cls.image)
        cls.code = cls.candidate[len(cls.baseline):]
        cls.patches = {
            PATCH_PC: (struct.unpack_from('<2I', cls.baseline, PATCH_PC - BASE),
                       struct.unpack_from('<2I', cls.candidate, PATCH_PC - BASE)),
        }

    def guarded(self, **options):
        return BookPercentMachine(self.image, code=self.code, patches=self.patches,
                                  code_base=CODE_BASE, **options)

    def test_redirect_preserves_native_ra_load_in_its_delay_slot(self):
        original, replacement = self.patches[PATCH_PC]
        self.assertEqual(original, (0xAC500058, 0x8FBF004C))
        self.assertEqual(original, (self.image.word(PATCH_PC), self.image.word(PATCH_PC + 4)))
        self.assertEqual(replacement, ((2 << 26) | (CODE_BASE >> 2), original[1]))

    def test_image_changes_one_word_and_extends_the_existing_rx_page(self):
        self.assertEqual(len(self.baseline), 0x6D0ED4)
        self.assertEqual(len(self.candidate), 0x6D0EFC)
        self.assertEqual(struct.unpack_from('<8I', self.candidate, RX_HEADER),
                         (1, 0x6D0000, 0xC70000, 0xC70000, 0xEFC, 0xEFC, 5, 0x10000))
        restored = bytearray(self.candidate[:len(self.baseline)])
        restored[RX_HEADER + 16:RX_HEADER + 24] = self.baseline[RX_HEADER + 16:RX_HEADER + 24]
        original, _ = self.patches[PATCH_PC]
        struct.pack_into('<I', restored, PATCH_PC - BASE, original[0])
        self.assertEqual(bytes(restored), self.baseline)
        with self.assertRaisesRegex(ValueError, 'exact hardware-tested volume ELF'):
            build_test.build(self.candidate)

    def test_null_factory_releases_only_a_live_payload_and_returns_zero(self):
        for allocate in (False, True):
            with self.subTest(allocate=allocate):
                machine = self.guarded(allocate=allocate)
                saved = machine.r[16:19]
                machine.run_at(WRAPPER, RETURN)
                self.assertEqual(machine.descriptors,
                                 [(0x527480, 0x527120, 0, ALLOCATION if allocate else 0, 0, 0, 0)])
                self.assertEqual(machine.releases, [ALLOCATION] if allocate else [])
                self.assertEqual(machine.raw_releases, [ALLOCATION - 4] if allocate else [])
                self.assertEqual(machine.get(TRACKED, 4), 0)
                self.assertEqual(machine.get(HANDLE + 0x58, 4), ALLOCATION)
                self.assertEqual(machine.r[16:19], saved)
                self.assertEqual((machine.r[2], machine.r[29], machine.r[31], machine.fp[20]),
                                 (0, STACK, RETURN, SAVED_FP))

    def test_native_resource_failure_releases_handle_then_caller_payload(self):
        machine = self.guarded(resource_failure=True)
        machine.run_at(WRAPPER, RETURN)
        self.assertEqual(machine.descriptors[0][3], ALLOCATION)
        self.assertEqual(machine.get(HANDLE + 0x4C, 4), ALLOCATION)
        self.assertEqual(machine.get(HANDLE + 0x58, 4), 0)
        self.assertEqual(machine.releases, [HANDLE, ALLOCATION])
        self.assertEqual(machine.raw_releases, [HANDLE - 4, ALLOCATION - 4])
        self.assertIn(DROP_LOCK, machine.calls)
        self.assertEqual(machine.get(TRACKED, 4), 0)
        self.assertEqual((machine.r[2], machine.r[29], machine.r[31], machine.fp[20]),
                         (0, STACK, RETURN, SAVED_FP))

    def test_live_handle_matches_native_publication_and_later_destruction(self):
        for allocate in (False, True):
            with self.subTest(allocate=allocate):
                options = dict(allocate=allocate, factory_result=HANDLE)
                native = BookPercentMachine(self.image, **options)
                guarded = self.guarded(**options)
                for machine in (native, guarded):
                    machine.run_at(WRAPPER, RETURN)
                    self.assertEqual(machine.get(HANDLE + 0x58, 4), ALLOCATION if allocate else 0)
                    self.assertEqual(machine.r[2], HANDLE)
                    self.assertEqual(machine.releases, [])
                    if allocate:
                        self.assertEqual(machine.get(ALLOCATION, 4), PERCENT_BITS)
                self.assertEqual(guarded.calls, native.calls)
                self.assertEqual((guarded.r, guarded.fp, guarded.writes), (native.r, native.fp, native.writes))

                guarded.put(HANDLE + 0x48, CONTEXT, 4)
                guarded.stock(DESTROY, HANDLE)
                self.assertEqual(guarded.releases, [ALLOCATION] if allocate else [])
                self.assertEqual(guarded.raw_releases, [ALLOCATION - 4] if allocate else [])

    def test_upper_caller_discards_both_wrapper_returns(self):
        for result in (0, HANDLE):
            with self.subTest(result=result):
                machine = self.guarded(factory_result=result)
                saved = [0x55000000 + index for index in range(4)]
                frame = machine.frame(56, 0x34)
                for index, value in enumerate(saved):
                    machine.put(frame + 0x24 + index * 4, value, 4)
                machine.run_at(UPPER, RETURN)
                self.assertEqual(machine.wrapper_result, result)
                self.assertEqual((machine.r[2], machine.r[29], machine.r[31]), (1, STACK, RETURN))
                self.assertEqual(machine.r[16:20], saved)


if __name__ == '__main__':
    unittest.main()
