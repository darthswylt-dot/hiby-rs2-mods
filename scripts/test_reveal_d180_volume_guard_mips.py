#!/usr/bin/env python3
"""Run the emitted volume guard and the native lower and upper slices."""

import unittest

import factory_null_audit as audit
import reveal_d180_volume_guard_mips as guard
from test_factory_null_audit import ALLOCATION, ALLOCATOR, CONTEXT, HANDLE, RETURN, STACK, LineageMachine
from test_reveal_d960_payload_guard_mips import OLD_PAYLOAD, PayloadGuardMachine


CODE_BASE = 0xC70EBC
VOLUME, VOLUME_DISPATCH, FACTORY = 0x505000, 0x43C360, 0x47D180
READY, FIND_WIDGET, MEMSET, PROPERTY = 0x468D40, 0x43A0C0, 0xA5BC60, 0x423980
OWNER, OLD_STATE, WIDGET = CONTEXT, CONTEXT + 0x100, CONTEXT + 0x180
OWNER_PENDING, OWNER_VISIBLE = OWNER + 0x208, OWNER + 0x170
RESOURCE, RESOURCE_ROOT = 0x1D07000, 0xADD360
SAVED_VALUE, STATE_GLOBAL = 0x13572468, 0xADF200
UPPER = ((0x43C528, 72, 3, SAVED_VALUE), (0x4E1058, 56, 2, 1))


class VolumeGuardMachine(PayloadGuardMachine):
    def __init__(self, image, *, widget=0, payload=OLD_PAYLOAD, **options):
        super().__init__(image, **options)
        self.widget = widget
        self.native_results, self.properties = [], []
        self.map(OLD_PAYLOAD, 12)
        self.bytes(OLD_PAYLOAD, b'\xA6' * 12)
        self.bytes(ALLOCATION, b'\xCC' * 0x100)
        self.put(HANDLE + 0x58, payload, 4)
        self.put(OWNER_PENDING, 0x22, 4)
        self.put(OWNER_VISIBLE, 0x33, 4)
        self.put(OLD_STATE + 0x10, SAVED_VALUE, 4)
        self.map(STATE_GLOBAL, 4)
        self.map(RESOURCE_ROOT, 4)
        self.map(RESOURCE, 0x240)
        self.put(RESOURCE_ROOT, RESOURCE, 4)
        self.put(RESOURCE + 0x23C, 0x13570011, 4)
        self.put(RESOURCE + 0x1C, 0x13570004, 4)
        for address in (0x920638, 0x920604):
            self.map(address, 4)
            self.put(address, image.word(address), 4)
        self.r[4:6] = [0, OWNER]

    def external(self, target):
        if target in (VOLUME, VOLUME_DISPATCH, READY):
            self.calls.append(target)
            self.run_at(target, self.r[31])
            if target != READY:
                self.native_results.append((target, self.r[2]))
        elif target == FIND_WIDGET:
            self.calls.append(target)
            self.hostile_result(self.widget)
        elif target == PROPERTY:
            self.calls.append(target)
            self.properties.append(self.r[4])
            self.run_at(target, self.r[31])
        elif target == MEMSET:
            LineageMachine.external(self, target)
        else:
            super().external(target)


class D180VolumeGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = audit.source_image()
        cls.code, cls.patches = guard.assemble(CODE_BASE)

    def guarded(self, **options):
        return VolumeGuardMachine(self.image, code=self.code, patches=self.patches,
                                  code_base=CODE_BASE, **options)

    def test_redirect_replaces_only_the_pinned_save_and_read_pair(self):
        self.assertEqual(len(self.code), 24)
        self.assertEqual(set(self.patches), {0x505074})
        original, replacement = self.patches[0x505074]
        self.assertEqual(original, (0x00408821, 0x8C420058))
        self.assertEqual(original, (self.image.word(0x505074), self.image.word(0x505078)))
        self.assertEqual(replacement, ((2 << 26) | (CODE_BASE >> 2), original[0]))

    def test_null_returns_through_both_dispatch_branches_and_outer_callers(self):
        for site, size, count, expected in UPPER:
            for widget in (0, WIDGET):
                with self.subTest(site=hex(site), widget=widget):
                    machine = self.guarded(widget=widget)
                    frame = machine.frame(size, size - 4)
                    saved = [0x55000000 + index for index in range(count)]
                    for index, value in enumerate(saved):
                        machine.put(frame + size - 4 * (count + 1 - index), value, 4)
                    machine.r[16:19] = [OLD_STATE, OWNER, 0xAE0000]
                    if site == 0x4E1058:
                        machine.r[16] = OWNER
                    machine.run_at(site, RETURN)

                    self.assertEqual(machine.calls, [VOLUME_DISPATCH, FIND_WIDGET, READY,
                                                     VOLUME, READY, FACTORY])
                    self.assertEqual(machine.native_results, [(VOLUME, 0), (VOLUME_DISPATCH, 0)])
                    self.assertEqual((machine.r[2], machine.r[29], machine.r[31]),
                                     (expected, STACK, RETURN))
                    self.assertEqual(machine.r[16:16 + count], saved)
                    self.assertEqual(machine.get(OWNER_PENDING, 4), 0)
                    self.assertEqual(machine.get(OWNER_VISIBLE, 4), 0x33)
                    self.assertEqual(machine.get(HANDLE + 0x58, 4), OLD_PAYLOAD)
                    if site == 0x43C528:
                        self.assertEqual(machine.get(STATE_GLOBAL, 4), SAVED_VALUE)

    def test_live_cached_context_matches_native_return_and_owner_updates(self):
        native = VolumeGuardMachine(self.image, factory_result=HANDLE)
        guarded = self.guarded(factory_result=HANDLE)
        for machine in (native, guarded):
            machine.run_at(VOLUME, RETURN)
            self.assertEqual(machine.calls, [READY, FACTORY])
            self.assertEqual((machine.r[2], machine.r[29], machine.r[31]), (HANDLE, STACK, RETURN))
            self.assertEqual(machine.get(OWNER_PENDING, 4), 0)
            self.assertEqual(machine.get(OWNER_VISIBLE, 4), 1)
            self.assertEqual(machine.get(HANDLE + 0x58, 4), OLD_PAYLOAD)
            self.assertEqual(machine.regions[OLD_PAYLOAD], b'\xA6' * 12)
        self.assertEqual((guarded.r, guarded.hi, guarded.lo), (native.r, native.hi, native.lo))
        self.assertEqual(guarded.writes, native.writes)

    def test_live_empty_context_matches_native_allocation_and_publication(self):
        options = dict(factory_result=HANDLE, payload=0)
        native = VolumeGuardMachine(self.image, **options)
        guarded = self.guarded(**options)
        for machine in (native, guarded):
            machine.run_at(VOLUME, 0x505100)
            self.assertEqual(machine.calls, [READY, FACTORY, ALLOCATOR, MEMSET, PROPERTY, PROPERTY])
            self.assertEqual(machine.properties, [17, 4])
            self.assertEqual(machine.get(HANDLE + 0x58, 4), ALLOCATION)
            values = tuple(machine.get(ALLOCATION + offset, 4) for offset in (0, 4, 8))
            self.assertEqual(values, (0, 0x13570011, 0x13570004))
        self.assertEqual((guarded.r, guarded.hi, guarded.lo), (native.r, native.hi, native.lo))
        self.assertEqual(guarded.writes, native.writes)
        self.assertEqual(guarded.regions[ALLOCATION], native.regions[ALLOCATION])


if __name__ == '__main__':
    unittest.main()
