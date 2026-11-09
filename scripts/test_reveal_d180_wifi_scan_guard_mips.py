#!/usr/bin/env python3
"""Execute the selected wifi_scan path with bounded factory and transport."""

import unittest

import factory_null_audit as audit
import reveal_d180_wifi_scan_guard_mips as guard
from test_factory_null_audit import CONTEXT, HANDLE, RETURN, STACK, NullFault
from test_reveal_d960_payload_guard_mips import PayloadGuardMachine


CODE_BASE = 0xC70E5C
START, FACTORY, SETTER = 0x4A4C24, 0x47D180, 0x477600
SCAN, MARK, CLOCK, TRANSPORT = 0x469CA0, 0x477680, 0x466960, 0x701640
CALLBACK, INTERFACE, TIME = 0x4A48E0, 0x92B480, 0x10203040
STATE_WORDS = (0xB8ABBC, 0xB8AA54, 0xB8AB08, 0xB8AC60, 0xB8ACD0, 0xB8ACD4)
INITIAL = (0x44440001, 0x44440002, 0x44440003, 0xA0, 0x44440005, 0x44440006)
SAVED = (0x55000000, 0x55000001, 0x55000002)


class WifiScanMachine(PayloadGuardMachine):
    def __init__(self, image, **options):
        super().__init__(image, **options)
        self.frame_address = self.frame(568, 0x234)
        for index, value in enumerate(SAVED):
            self.put(self.frame_address + 0x228 + index * 4, value, 4)
        self.r[3], self.r[18] = 0, 0x940000
        self.put(CONTEXT + 0xD4, CONTEXT + 0x100, 4)
        self.put(HANDLE + 0x5C, 0x31415926, 4)
        for address, value in zip(STATE_WORDS, INITIAL):
            self.put(address, value, 4)

    def external(self, target):
        if target in (SCAN, MARK):
            self.calls.append(target)
            self.run_at(target, self.r[31])
        elif target in (CLOCK, TRANSPORT):
            self.calls.append(target)
            if target == TRANSPORT:
                self.transport_interface = self.r[4]
            self.hostile_result(TIME if target == CLOCK else 0)
        else:
            if target == SETTER:
                self.setter_entry = (self.r.copy(), self.hi, self.lo)
                self.flag_at_setter = self.get(HANDLE + 0x5C, 4)
            super().external(target)

    def scan_state(self):
        return tuple(self.get(address, 4) for address in STATE_WORDS)


class D180WifiScanGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = audit.source_image()
        cls.code, cls.patches = guard.assemble(CODE_BASE)

    def guarded(self, **options):
        return WifiScanMachine(self.image, code=self.code, patches=self.patches,
                               code_base=CODE_BASE, **options)

    def test_redirect_replays_the_pinned_setup_before_the_unchanged_store(self):
        self.assertEqual(len(self.code), 24)
        self.assertEqual(set(self.patches), {0x4A4F24})
        original, replacement = self.patches[0x4A4F24]
        self.assertEqual(original, (self.image.word(0x4A4F24), self.image.word(0x4A4F28)))
        self.assertEqual(replacement, ((2 << 26) | (CODE_BASE >> 2), original[0]))
        self.assertEqual(self.image.word(0x4A4F2C), 0xAC43005C)
        self.assertEqual(self.image.word(0xA9A40C), 0x4A6120)
        self.assertEqual(self.image.word(0x4A6120), 0x08129270)

    def test_null_returns_one_without_changing_the_callback_or_scan_state(self):
        native = WifiScanMachine(self.image)
        with self.assertRaises(NullFault) as failed:
            native.run_at(START, RETURN)
        self.assertEqual((failed.exception.pc, failed.exception.address), (0x4A4F2C, 0x5C))

        machine = self.guarded()
        machine.run_at(START, RETURN)
        self.assertEqual(machine.calls, [FACTORY])
        self.assertEqual((machine.r[2], machine.r[29], machine.r[31]), (1, STACK, RETURN))
        self.assertEqual(tuple(machine.r[16:19]), SAVED)
        self.assertEqual(machine.scan_state(), INITIAL)
        self.assertEqual(machine.get(HANDLE + 0x5C, 4), 0x31415926)
        self.assertEqual(machine.get(machine.frame_address + 0x10, 4), machine.frame_address + 0x20)
        self.assertEqual(machine.get(machine.frame_address + 0x20, 4), 0x4A4200)

    def test_live_result_matches_native_flag_registration_and_scan_request(self):
        native = WifiScanMachine(self.image, factory_result=HANDLE)
        guarded = self.guarded(factory_result=HANDLE)
        for machine in (native, guarded):
            machine.run_at(START, RETURN)
            self.assertEqual(machine.flag_at_setter, 1)
            self.assertEqual(machine.calls, [FACTORY, SETTER, SCAN, MARK, CLOCK, TRANSPORT])
            self.assertEqual(machine.ui_calls, [(SETTER, (CALLBACK, 0, 0, 12))])
            self.assertEqual(machine.transport_interface, INTERFACE)
            self.assertEqual(machine.scan_state(), (CALLBACK, 0, 0, 0xA1, TIME, 0))
            self.assertEqual((machine.r[2], machine.r[29], machine.r[31]), (1, STACK, RETURN))
            self.assertEqual(tuple(machine.r[16:19]), SAVED)

        self.assertEqual(guarded.setter_entry, native.setter_entry)
        self.assertEqual((guarded.r, guarded.hi, guarded.lo), (native.r, native.hi, native.lo))
        self.assertEqual(guarded.writes, native.writes)


if __name__ == '__main__':
    unittest.main()
