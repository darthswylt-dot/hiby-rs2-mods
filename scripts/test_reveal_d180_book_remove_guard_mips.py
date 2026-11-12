#!/usr/bin/env python3
"""Exercise the book and bookmark removal guards and their native callers."""

import struct
import unittest

import build_reveal_d180_book_remove_guard_test as build_test
import build_reveal_d180_check_upgrade_test as check_upgrade
import factory_null_audit as audit
from build_reveal_bridge_diag import BASE
from build_reveal_d960_payload_guard_test import RX_HEADER
from test_factory_d180_allocation_continuations import LOCK, UNLOCK
from test_factory_null_audit import ALLOCATION, CONFIGURATOR, CONTEXT, HANDLE, RETURN, STACK, LineageMachine
from test_reveal_d180_book_percent_guard_mips import BookPercentMachine
from test_reveal_d180_data_dealing_snapshot_mips import data_dealing_fixture


CODE_BASE = 0xC7121C
SOURCE = 0x1D06000
COPY_BYTES = 0xA88
SOURCE_BYTES = bytes(index % 256 for index in range(COPY_BYTES))
OLD_PAYLOAD, OLD_DIALOG = CONTEXT + 0x100, CONTEXT + 0x200
REFRESH, COPY = 0x493AC0, 0xA5B440
CASES = (
    # Wrapper, guarded store, resource name, initializer, destructor, number of modes.
    (0x527F00, 0x527FA4, 0x95069C, 0x527720, 0x5276E0, 2),
    (0x529540, 0x5295E0, 0x9509A4, 0x528F00, 0x528EC0, 3),
)
UPPER = (
    # Calls converging on the refresh and mode-1 continuations, respectively.
    ((0x4AC168, 0x4AC180), (0x4B65A8, 0x4B65F8)),
    ((0x4ABF84, 0x4AC198, 0x4AC1B0), (0x4B6554, 0x4B6614, 0x4B6630)),
)


class ReaderRemoveMachine(BookPercentMachine):
    payload_size = 0xA90

    def __init__(self, image, case, *, mode=0, **options):
        super().__init__(image, **options)
        self.wrapper, _, self.descriptor_name, _, _, _ = case
        self.map(ALLOCATION, self.payload_size)
        self.put(ALLOCATION + 0xA8C, 0xCCCCCCCC, 4)
        self.map(SOURCE, len(SOURCE_BYTES))
        self.bytes(SOURCE, SOURCE_BYTES)
        self.put(HANDLE + 0x4C, OLD_PAYLOAD, 4)
        self.put(HANDLE + 0x58, OLD_PAYLOAD, 4)
        self.map(0x938C88, 4)
        self.put(0x938C88, image.word(0x938C88), 4)
        self.put(OLD_DIALOG + 0x10, CONTEXT + 0x80, 4)
        self.r[4:8] = [0, CONTEXT, SOURCE, mode]
        self.upper_call = None

    def external(self, target):
        if target == self.wrapper:
            self.calls.append(target)
            self.run_at(target, self.r[31])
            self.wrapper_result = self.r[2]
        elif target == COPY:
            if self.r[4:7] != [ALLOCATION, SOURCE, COPY_BYTES]:
                raise AssertionError('unexpected reader payload copy')
            LineageMachine.external(self, target)
        elif target == REFRESH:
            self.calls.append(target)
            self.upper_call = target, self.r[4]
            self.hostile_result(0x12345678)
        elif target == CONFIGURATOR:
            self.calls.append(target)
            self.upper_call = target, self.r[4], self.r[5]
            self.run_at(target, self.r[31])
        elif target in (LOCK, UNLOCK):
            self.calls.append(target)
            self.hostile_result(0)
        else:
            super().external(target)


class D180BookRemoveGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = audit.source_image()
        _, data_image, _ = data_dealing_fixture(cls.image)
        cls.baseline = check_upgrade.build(data_image)
        cls.candidate = build_test.build(cls.baseline)
        cls.code = cls.candidate[len(cls.baseline):]
        cls.patches = {
            site: (struct.unpack_from('<2I', cls.baseline, site - BASE),
                   struct.unpack_from('<2I', cls.candidate, site - BASE))
            for _, site, _, _, _, _ in CASES
        }

    def guarded(self, case, **options):
        return ReaderRemoveMachine(self.image, case, code=self.code, patches=self.patches,
                                   code_base=CODE_BASE, **options)

    def test_redirects_change_only_the_two_store_words_and_rx_sizes(self):
        self.assertEqual(len(self.baseline), 0x6D121C)
        self.assertEqual(len(self.candidate), 0x6D126C)
        self.assertEqual(struct.unpack_from('<8I', self.candidate, RX_HEADER),
                         (1, 0x6D0000, 0xC70000, 0xC70000, 0x126C, 0x126C, 5, 0x10000))
        restored = bytearray(self.candidate[:len(self.baseline)])
        restored[RX_HEADER + 16:RX_HEADER + 24] = self.baseline[RX_HEADER + 16:RX_HEADER + 24]
        for index, (site, (original, replacement)) in enumerate(self.patches.items()):
            self.assertEqual(original, (self.image.word(site), self.image.word(site + 4)))
            self.assertEqual(replacement, ((2 << 26) | ((CODE_BASE + index * 40) >> 2), original[1]))
            struct.pack_into('<I', restored, site - BASE, original[0])
        self.assertEqual(bytes(restored), self.baseline)
        with self.assertRaisesRegex(ValueError, 'exact hardware-tested update-check ELF'):
            build_test.build(self.candidate)

    def test_refusal_releases_only_an_allocated_payload(self):
        for case in CASES:
            wrapper, _, _, init, destroy, _ = case
            for allocate in (False, True):
                with self.subTest(wrapper=hex(wrapper), allocate=allocate):
                    machine = self.guarded(case, allocate=allocate)
                    saved = machine.r[16:21]
                    machine.run_at(wrapper, RETURN)
                    self.assertEqual(machine.descriptors, [(init, destroy, 0, ALLOCATION if allocate else 0, 0, 0, 0)])
                    self.assertEqual(machine.releases, [ALLOCATION] if allocate else [])
                    self.assertEqual(machine.raw_releases, [ALLOCATION - 4] if allocate else [])
                    self.assertEqual(machine.get(HANDLE + 0x58, 4), OLD_PAYLOAD)
                    self.assertEqual(machine.regions[SOURCE], SOURCE_BYTES)
                    self.assertEqual(machine.r[16:21], saved)
                    self.assertEqual((machine.r[2], machine.r[29], machine.r[31]), (0, STACK, RETURN))

    def test_native_resource_failure_releases_dialog_and_then_caller_payload(self):
        for case in CASES:
            with self.subTest(wrapper=hex(case[0])):
                machine = self.guarded(case, resource_failure=True)
                machine.run_at(case[0], RETURN)
                self.assertEqual(machine.get(HANDLE + 0x4C, 4), ALLOCATION)
                self.assertEqual(machine.get(HANDLE + 0x58, 4), 0)
                self.assertEqual(machine.releases, [HANDLE, ALLOCATION])
                self.assertEqual(machine.raw_releases, [HANDLE - 4, ALLOCATION - 4])
                self.assertEqual((machine.r[2], machine.r[29], machine.r[31]), (0, STACK, RETURN))

    def test_live_handle_matches_stock_and_destructor_releases_payload(self):
        for case in CASES:
            wrapper, _, _, _, destroy, modes = case
            for mode in range(modes):
                for allocate in (False, True):
                    with self.subTest(wrapper=hex(wrapper), mode=mode, allocate=allocate):
                        options = dict(mode=mode, allocate=allocate, factory_result=HANDLE)
                        native = ReaderRemoveMachine(self.image, case, **options)
                        guarded = self.guarded(case, **options)
                        for machine in (native, guarded):
                            machine.run_at(wrapper, RETURN)
                            self.assertEqual(machine.r[2], HANDLE)
                            self.assertEqual(machine.get(HANDLE + 0x4C, 4), OLD_PAYLOAD)
                            self.assertEqual(machine.get(HANDLE + 0x58, 4), ALLOCATION if allocate else 0)
                            self.assertEqual(machine.releases, [])
                            if allocate:
                                tail = (mode, mode if wrapper == 0x527F00 else 0xCCCCCCCC)
                                self.assertEqual(machine.regions[ALLOCATION], SOURCE_BYTES + struct.pack('<2I', *tail))
                        self.assertEqual((guarded.r, guarded.writes, guarded.calls),
                                         (native.r, native.writes, native.calls))
                        guarded.stock(destroy, HANDLE)
                        self.assertEqual(guarded.releases, [ALLOCATION] if allocate else [])
                        self.assertEqual(guarded.raw_releases, [ALLOCATION - 4] if allocate else [])

    def test_known_upper_callers_discard_the_wrapper_result(self):
        for case, (refresh_sites, configure_sites) in zip(CASES, UPPER):
            continuations = (
                (refresh_sites, 0xAD0, 7, (REFRESH, CONTEXT)),
                (configure_sites, 0x30, 4, (CONFIGURATOR, OLD_DIALOG, 1)),
            )
            for sites, frame_size, count, expected_call in continuations:
                for site in sites:
                    for result in (0, HANDLE):
                        with self.subTest(site=hex(site), result=result):
                            self.assertEqual(self.image.word(site), (3 << 26) | (case[0] >> 2))
                            machine = self.guarded(case, factory_result=result)
                            frame = machine.frame(frame_size, frame_size - 4)
                            saved = [0x55000000 + index for index in range(count)]
                            for index, value in enumerate(saved):
                                machine.put(frame + frame_size - 4 * (count + 1 - index), value, 4)
                            machine.r[16], machine.r[18] = CONTEXT, OLD_DIALOG
                            machine.run_at(site, RETURN)
                            self.assertEqual(machine.wrapper_result, result)
                            self.assertEqual(machine.upper_call, expected_call)
                            if expected_call[0] == CONFIGURATOR:
                                self.assertEqual(machine.get(OLD_DIALOG + 4, 4), 1)
                            self.assertEqual(machine.r[16:16 + count], saved)
                            self.assertEqual((machine.r[2], machine.r[29], machine.r[31]), (1, STACK, RETURN))


if __name__ == '__main__':
    unittest.main()
