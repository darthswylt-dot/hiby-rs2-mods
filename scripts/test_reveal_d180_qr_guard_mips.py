#!/usr/bin/env python3
"""Execute the ordinary QR guard bytes with the native wrapper and bounded services."""

import struct
import unittest

import build_reveal_d180_book_remove_guard_test as book_remove
import build_reveal_d180_check_upgrade_test as check_upgrade
import build_reveal_d180_qr_guard_test as build_test
import factory_null_audit as audit
import reveal_d180_qr_guard_mips as guard
from build_reveal_bridge_diag import BASE
from build_reveal_d960_payload_guard_test import RX_HEADER
from test_factory_d180_qr_continuation import (
    DESTROY, OPEN_TIDAL, OWNER_FLAG, REQUEST, SESSION, STATUS, TEXT, WRAPPER, QrMachine,
)
from test_factory_null_audit import ALLOCATION, CONTEXT, HANDLE, RETURN, STACK
from test_reveal_d180_book_percent_guard_mips import FACTORY
from test_reveal_d180_data_dealing_snapshot_mips import data_dealing_fixture


CODE_BASE = 0xC7126C
PATCH_SITES = (guard.MODE_SITE, guard.OWNER_SITE, guard.RESULT_SITE)
FIRST_HANDLE_STORE = 0x501AA4
WRAPPER_FRAME = 0x58


class ObservedQrMachine(QrMachine):
    def __init__(self, image, **options):
        super().__init__(image, **options)
        self.factory_inputs = []

    def external(self, target):
        if target == FACTORY:
            self.factory_inputs.append((self.r.copy(), self.get(OWNER_FLAG, 4)))
        super().external(target)


class D180QrGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = audit.source_image()
        _, data_image, _ = data_dealing_fixture(cls.image)
        cls.baseline = book_remove.build(check_upgrade.build(data_image))
        cls.candidate = build_test.build(cls.baseline)
        cls.code = cls.candidate[len(cls.baseline):]
        cls.patches = {
            pc: (struct.unpack_from('<2I', cls.baseline, pc - BASE),
                 struct.unpack_from('<2I', cls.candidate, pc - BASE))
            for pc in PATCH_SITES
        }

    def guarded(self, **options):
        return ObservedQrMachine(self.image, code=self.code, patches=self.patches,
                                 code_base=CODE_BASE, **options)

    def assert_unwound(self, machine, saved, result=0):
        self.assertEqual(machine.r[16:20], saved)
        self.assertEqual((machine.r[2], machine.r[29], machine.r[31]), (result, STACK, RETURN))

    def assert_stock_effects(self, native, guarded, *, frame_top=STACK):
        private_words = {frame_top - WRAPPER_FRAME + offset for offset in (guard.SELECTOR, guard.SAVED_OWNER)}
        guarded_writes = [write for write in guarded.writes if write[0] not in private_words]
        self.assertEqual(guarded.factory_inputs, native.factory_inputs)
        self.assertEqual(guarded.descriptors, native.descriptors)
        self.assertEqual((guarded.r, guarded.calls, guarded_writes), (native.r, native.calls, native.writes))

    def test_appends_two_page_code_and_only_changes_the_expected_pairs(self):
        self.assertEqual(len(self.baseline), 0x6D126C)
        self.assertEqual(len(self.candidate), 0x6D1308)
        self.assertEqual(struct.unpack_from('<8I', self.candidate, RX_HEADER),
                         (1, 0x6D0000, 0xC70000, 0xC70000, 0x1308, 0x1308, 5, 0x10000))
        code, patches = guard.assemble(CODE_BASE)
        self.assertEqual((code, patches), (self.code, self.patches))
        restored = bytearray(self.candidate[:len(self.baseline)])
        restored[RX_HEADER + 16:RX_HEADER + 24] = self.baseline[RX_HEADER + 16:RX_HEADER + 24]
        for pc, (original, _) in self.patches.items():
            self.assertEqual(original, (self.image.word(pc), self.image.word(pc + 4)))
            struct.pack_into('<2I', restored, pc - BASE, *original)
        self.assertEqual(bytes(restored), self.baseline)
        with self.assertRaisesRegex(ValueError, 'exact hardware-tested removal-dialog ELF'):
            build_test.build(self.candidate)

    def test_allocation_refusal_returns_before_owner_clear_or_factory(self):
        for text in (0, TEXT):
            with self.subTest(text=text):
                machine = self.guarded(allocate=False)
                machine.put(REQUEST + 8, text, 4)
                saved = machine.r[16:20]
                machine.writes.clear()
                machine.run_at(WRAPPER, RETURN)

                self.assertEqual(machine.factory_inputs, [])
                self.assertEqual(machine.releases, [])
                self.assertEqual(machine.get(OWNER_FLAG, 4), 1)
                self.assertNotIn(OWNER_FLAG, {address for address, _, _ in machine.writes})
                self.assert_unwound(machine, saved)

    def test_factory_refusal_releases_ordinary_payload_and_restores_owner(self):
        for native_failure in (False, True):
            for owner in (0, 1, 0x13572468):
                with self.subTest(native_failure=native_failure, owner=owner):
                    machine = self.guarded(resource_failure=native_failure)
                    machine.put(OWNER_FLAG, owner, 4)
                    saved = machine.r[16:20]
                    machine.run_at(WRAPPER, RETURN)

                    self.assertEqual(len(machine.factory_inputs), 1)
                    self.assertEqual(machine.factory_inputs[0][1], 0)
                    expected = [HANDLE, ALLOCATION] if native_failure else [ALLOCATION]
                    self.assertEqual(machine.releases, expected)
                    self.assertEqual(machine.raw_releases, [address - 4 for address in expected])
                    self.assertEqual(machine.response_releases, [])
                    self.assertEqual(machine.get(OWNER_FLAG, 4), owner)
                    self.assertEqual(machine.get(STATUS, 4), 3)
                    self.assert_unwound(machine, saved)

    def test_rollback_preserves_an_owner_write_before_or_after_linked_load(self):
        for after_linked_load in (False, True):
            with self.subTest(after_linked_load=after_linked_load):
                machine = self.guarded(resource_failure=True)

                def write_owner(pc):
                    if after_linked_load:
                        reached = machine.reservation == (OWNER_FLAG, machine.version)
                    else:
                        reached = pc == guard.RESULT_SITE
                    if reached:
                        machine.put(OWNER_FLAG, 7, 4)

                machine.before_instruction = write_owner
                machine.run_at(WRAPPER, RETURN)
                self.assertEqual(machine.get(OWNER_FLAG, 4), 7)
                self.assertEqual(machine.releases, [HANDLE, ALLOCATION])
                self.assertEqual(machine.r[2], 0)

    def test_owner_restore_retries_a_lost_reservation(self):
        machine = self.guarded(resource_failure=True)
        machine.sc_failures = 1
        machine.run_at(WRAPPER, RETURN)
        self.assertEqual(machine.sc_failures, 0)
        self.assertEqual(machine.get(OWNER_FLAG, 4), 1)
        self.assertEqual(machine.releases, [HANDLE, ALLOCATION])
        self.assertEqual(machine.r[2], 0)

    def test_success_and_same_name_lookup_keep_the_native_effects(self):
        for reuse in (False, True):
            with self.subTest(reuse=reuse):
                native = ObservedQrMachine(self.image, reuse=reuse, factory_result=HANDLE)
                guarded = self.guarded(reuse=reuse, factory_result=HANDLE)
                for machine in (native, guarded):
                    machine.bytes(TEXT, b'RS2 fixture\0')
                    machine.put(REQUEST + 8, TEXT, 4)
                    machine.run_at(WRAPPER, RETURN)
                    self.assertEqual(machine.r[2], HANDLE)
                    self.assertEqual(machine.get(HANDLE + 0x54, 4), ALLOCATION)
                    self.assertEqual(machine.get(HANDLE + 0x78, 4), 0x501680)
                    self.assertEqual(machine.releases, [])
                self.assert_stock_effects(native, guarded)

                if not reuse:
                    # Supply the fields the fresh factory publishes and run
                    # the stock close handler on the guarded payload.
                    guarded.put(HANDLE + 0x48, CONTEXT, 4)
                    guarded.put(HANDLE + 0x4C, ALLOCATION, 4)
                    guarded.put(HANDLE + 0x58, 0, 4)
                    guarded.stock(DESTROY, HANDLE)
                    self.assertEqual(guarded.releases, [ALLOCATION])
                    self.assertEqual(guarded.get(OWNER_FLAG, 4), 1)

    def test_nonzero_modes_keep_native_live_and_refusal_prefixes(self):
        for mode in (1, 2):
            for allocate in (False, True):
                for result in (0, HANDLE):
                    with self.subTest(mode=mode, allocate=allocate, result=result):
                        options = dict(mode=mode, allocate=allocate, factory_result=result)
                        native = ObservedQrMachine(self.image, **options)
                        guarded = self.guarded(**options)
                        stop = RETURN if result else FIRST_HANDLE_STORE
                        for machine in (native, guarded):
                            machine.run_at(WRAPPER, stop)
                        self.assert_stock_effects(native, guarded)

    def test_tidal_queue_and_status_match_stock(self):
        for queue_full in (False, True):
            with self.subTest(queue_full=queue_full):
                options = dict(mode=2, queue_full=queue_full, factory_result=HANDLE)
                native = ObservedQrMachine(self.image, **options)
                guarded = self.guarded(**options)
                for machine in (native, guarded):
                    machine.r[4:6] = [CONTEXT, 0]
                    machine.run_at(OPEN_TIDAL, RETURN)
                    self.assertEqual(machine.get(ALLOCATION + 0x18C, 4), SESSION)
                self.assertEqual(guarded.post_result, native.post_result)
                self.assert_stock_effects(native, guarded, frame_top=STACK - 0x50)


if __name__ == '__main__':
    unittest.main()
