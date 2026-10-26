#!/usr/bin/env python3
"""Execute original mutex facades, proving lower failures are not receipts.

Only A5B960/A5B830 service bodies are hostile ABI stubs. The pinned original
437CE0/D60/D20/DA0 and466DA0/DC0 instructions all execute; no friendly facade
intercept manufactures the result. This does not simulate pthread ownership,
initialization, hardware, runtime imports or a concurrent native scheduler.
"""

import hashlib
import unittest

import test_folderfollow_reveal_static_contract as source
from test_reveal_lineage_stage import LineageMachine, STACK, RETURN, MASK


CONTROLLER, PAINT_MUTEX, REGISTRY_MUTEX = 0x1800000, 0x1F20200, 0x1F20300
RAW_LOCK, RAW_UNLOCK = 0xA5B960, 0xA5B830
STATUSES = (0, 1, 22, MASK)
NATIVE = {0x437CE0, 0x437D60, 0x437D20, 0x437DA0, 0x466DA0, 0x466DC0}
PRESERVED = (0, *range(16, 24), 28, 29, 30, 31)


class MutexStatusMachine(LineageMachine):
    """Reuse bounded instruction/ABI helpers, not inherited service policy."""

    def __init__(self, image, *, acquire=0, release=0):
        # No emitted stage or image build: native instruction fetches use the
        # hash-pinned original image, while the auxiliary code extent is empty.
        super().__init__(image, {'code_base': 0x1E80000, 'buffer': 0x1F50000,
                                 'code_offset': len(image), 'labels': {},
                                 'memory_bytes': 16})
        self.map(CONTROLLER, 0x28C)
        self.put(CONTROLLER + 0x148, PAINT_MUTEX, 4)
        self.put(CONTROLLER + 0x13C, REGISTRY_MUTEX, 4)
        self.acquire, self.release = acquire, release
        self.trace, self.service_calls = [], []
        self.before_instruction = self.trace.append
        self.calls.clear()
        self.reads.clear()
        self.writes.clear()

    def external(self, target):
        self.calls.append(target)
        if target in NATIVE:
            # In particular466DA0/DC0 execute rather than using predecessor
            # fixtures' always-friendly lock/unlock replacement.
            self.run_at(target, self.r[31])
            return
        if target not in (RAW_LOCK, RAW_UNLOCK):
            raise AssertionError('unexpected service ' + hex(target))
        result = self.acquire if target == RAW_LOCK else self.release
        self.service_calls.append((target, self.r[4], self.r[29], self.r[31], result))
        self.hostile_result(result)

    def invoke(self, target, argument):
        self.r[29], self.r[31], self.r[4] = STACK, RETURN, argument
        before = self.r.copy()
        self.run_at(target, RETURN)
        return self.r[2], before


class RevealPaintMutexStatusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        elf = source.Elf32(source.SOURCE)
        digest = hashlib.sha256(elf.data).hexdigest()
        if digest != source.SOURCE_SHA256 or len(elf.data) != source.SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: SHA-256 {digest}, '
                                 f'size {len(elf.data)}')
        cls.image = elf.data

    def machine(self, **options):
        return MutexStatusMachine(self.image, **options)

    def preserved(self, machine, before):
        self.assertEqual({reg: machine.r[reg] for reg in PRESERVED},
                         {reg: before[reg] for reg in PRESERVED})

    def check(self, facade, raw, mutex, status, *, direct=False):
        machine = self.machine(acquire=status, release=status)
        result, before = machine.invoke(facade, mutex if direct else CONTROLLER)
        self.assertEqual(result, 0)
        self.preserved(machine, before)
        self.assertEqual(len(machine.service_calls), 1)
        target, argument, service_sp, service_ra, returned = machine.service_calls[0]
        self.assertEqual((target, argument, returned), (raw, mutex, status))
        self.assertEqual(service_sp, STACK - (0x20 if direct else 0x40))
        self.assertEqual(service_ra, 0x466DB0 if raw == RAW_LOCK else 0x466DD0)
        self.assertIn(facade, machine.trace)
        self.assertIn(0x466DA0 if raw == RAW_LOCK else 0x466DC0, machine.trace)
        self.assertIn(0x466DB4 if raw == RAW_LOCK else 0x466DD4, machine.trace)
        return machine

    def test_original_direct_lock_wrapper_masks_all_four_raw_statuses(self):
        for status in STATUSES:
            with self.subTest(status=status):
                self.check(0x466DA0, RAW_LOCK, PAINT_MUTEX, status, direct=True)

    def test_original_direct_unlock_wrapper_masks_all_four_raw_statuses(self):
        for status in STATUSES:
            with self.subTest(status=status):
                self.check(0x466DC0, RAW_UNLOCK, PAINT_MUTEX, status, direct=True)

    def test_original_paint_lock_facade_masks_service_failures(self):
        for status in STATUSES:
            with self.subTest(status=status):
                self.check(0x437CE0, RAW_LOCK, PAINT_MUTEX, status)

    def test_original_paint_unlock_facade_masks_service_failures(self):
        for status in STATUSES:
            with self.subTest(status=status):
                self.check(0x437D60, RAW_UNLOCK, PAINT_MUTEX, status)

    def test_original_registry_lock_facade_masks_service_failures(self):
        for status in STATUSES:
            with self.subTest(status=status):
                self.check(0x437D20, RAW_LOCK, REGISTRY_MUTEX, status)

    def test_original_registry_unlock_facade_masks_service_failures(self):
        for status in STATUSES:
            with self.subTest(status=status):
                self.check(0x437DA0, RAW_UNLOCK, REGISTRY_MUTEX, status)

    def test_pair_of_facades_cannot_reconstruct_two_raw_statuses(self):
        for acquire in STATUSES:
            for release in STATUSES:
                with self.subTest(acquire=acquire, release=release):
                    machine = self.machine(acquire=acquire, release=release)
                    for facade in (0x437CE0, 0x437D60):
                        result, before = machine.invoke(facade, CONTROLLER)
                        self.assertEqual(result, 0)
                        self.preserved(machine, before)
                    self.assertEqual([(item[0], item[1], item[4])
                                      for item in machine.service_calls],
                                     [(RAW_LOCK, PAINT_MUTEX, acquire),
                                      (RAW_UNLOCK, PAINT_MUTEX, release)])

    def test_hostile_service_homes_never_overwrite_the_native_callers_homes(self):
        machine = self.machine(acquire=22)
        for offset in range(0, 16, 4):
            machine.put(STACK + offset, 0xCA110000 + offset, 4)
        result, before = machine.invoke(0x437D20, CONTROLLER)
        self.assertEqual(result, 0)
        self.preserved(machine, before)
        self.assertEqual([machine.get(STACK + offset, 4)
                          for offset in range(0, 16, 4)],
                         [0xCA110000 + offset for offset in range(0, 16, 4)])
        self.assertEqual([machine.get(STACK - 0x40 + offset, 4)
                          for offset in range(0, 16, 4)],
                         [0xD00D0000 + offset for offset in range(0, 16, 4)])

    def test_no_mutex_body_or_native_owner_pointer_is_dereferenced(self):
        for facade in (0x437CE0, 0x437D60, 0x437D20, 0x437DA0):
            with self.subTest(facade=facade):
                machine = self.check(facade,
                                     RAW_LOCK if facade in (0x437CE0, 0x437D20)
                                     else RAW_UNLOCK,
                                     PAINT_MUTEX if facade in (0x437CE0, 0x437D60)
                                     else REGISTRY_MUTEX, MASK)
                for address, size in machine.reads:
                    self.assertTrue(CONTROLLER <= address < CONTROLLER + 0x28C
                                    or STACK - 0x40 <= address < STACK)
                for address, value, size in machine.writes:
                    self.assertTrue(STACK - 0x40 <= address < STACK)
                # The fake mutex scalars need no mapped native allocation;
                # service stubs, not these facades, would dereference them.


if __name__ == '__main__':
    unittest.main()
