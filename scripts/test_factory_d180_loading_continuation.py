#!/usr/bin/env python3
"""Run the loading-dialog guard and trace native source cleanup."""

import unittest

import factory_null_audit as audit
from test_factory_d180_allocation_continuations import FACTORY, AllocationContinuationMachine
from test_factory_null_audit import ALLOCATION, ALLOCATOR, CONTEXT, COPY, FREE, HANDLE, RETURN, STACK
from test_reveal_d180_wifi_scan_guard_mips import CODE_BASE, ui_guard_fixture


LOADING, REMOVE_COMPLETE, VIEW_LOOKUP = 0x4AFBE0, 0x4AFD40, 0x4E5320
WIDE_COPY, RAW_FREE = 0x41FB80, 0xA5B9C0
VIEW_LOCK, VIEW_UNLOCK = 0x490960, 0x490940
OLD_DIALOG, OWNER = CONTEXT + 0x100, CONTEXT + 0x80
SOURCE, DESTINATION, VIEW, LIST = 0x1D08000, 0x1D09000, 0x1D0A000, 0x1D0B000
CACHED_CONTEXT = 0x1D0C000
CONTEXT_SIZE = 0xCF0
VIEW_NAME = b'fixture-view\0'.ljust(64, b'\0')
WIDE_NAME = 'fixture-path'.encode('utf-16le') + b'\0\0'
SOURCE_VALUE, FREE_RESULT = 0x24681357, 0x135700FE


class LoadingContinuationMachine(AllocationContinuationMachine):
    def __init__(self, image, *, flags=(), lookup_miss=0, factory_result=HANDLE,
                 reused_dialog=False, **options):
        super().__init__(image, factory_result=factory_result, allocation_result=DESTINATION,
                         **options)
        self.lookup_miss = lookup_miss
        self.reused_dialog = reused_dialog
        self.lookups, self.wrapper_results = [], []
        self.free_arguments, self.raw_free_arguments = [], []
        self.name_copy = None
        self.map(SOURCE - 4, CONTEXT_SIZE + 4)
        self.map(DESTINATION, CONTEXT_SIZE)
        self.put(SOURCE - 4, CONTEXT_SIZE + 4, 4)
        self.put(SOURCE, SOURCE_VALUE, 4)
        self.put(SOURCE + 4, 1, 4)
        self.put(SOURCE + 8, 4, 4)
        self.bytes(SOURCE + 0xC, VIEW_NAME)
        self.bytes(SOURCE + 0xAE4, WIDE_NAME)
        self.put(OLD_DIALOG + 0x48, OWNER, 4)
        self.put(OLD_DIALOG + 0x58, SOURCE, 4)
        self.put(HANDLE + 0x58, CACHED_CONTEXT if reused_dialog else 0, 4)
        if reused_dialog:
            self.map(CACHED_CONTEXT, CONTEXT_SIZE)
            self.bytes(CACHED_CONTEXT, b'\xA7' * CONTEXT_SIZE)
            self.put(HANDLE + 0x74, 0x450D60, 4)
            self.put(HANDLE + 0x78, 0x4AE180, 4)

        self.map(VIEW, 0x100)
        self.bytes(VIEW, VIEW_NAME)
        for offset, value in ((0xBC, LIST), (0xC0, ALLOCATION), (0xC4, VIEW_LOCK),
                              (0xC8, VIEW_UNLOCK), (0xD4, OWNER)):
            self.put(VIEW + offset, value, 4)
        self.map(LIST, 0x100)
        directory, rows = LIST + 0x40, LIST + 0x60
        for offset, value in ((0, directory), (0xC, len(flags)), (0x10, 8), (0x14, 0x200),
                              (0x2C, 0x4557E0), (0x30, 0x455DC0)):
            self.put(LIST + offset, value, 4)
        self.put(directory, rows, 4)
        for index, flag in enumerate(flags):
            self.put(rows + index * 8 + 4, flag, 4)

    def external(self, target):
        if target == LOADING:
            self.calls.append(target)
            self.run_at(target, self.r[31])
            self.wrapper_results.append(self.r[2])
        elif target == VIEW_LOOKUP:
            self.calls.append(target)
            self.lookups.append(tuple(self.r[4:6]))
            self.put(self.r[6], 0 if len(self.lookups) == self.lookup_miss else VIEW, 4)
            self.hostile_result(0)
        elif target == FACTORY and self.factory_result and not self.reused_dialog:
            saved_s2 = self.r[18]
            self.r[3], self.r[18] = self.factory_result, self.get(self.r[29] + 0x10, 4)
            self.run_at(0x47D24C, 0x47D25C)  # Register the two descriptor callbacks.
            self.r[18] = saved_s2
            super().external(target)
        elif target in (WIDE_COPY, 0x455DC0, VIEW_LOCK, VIEW_UNLOCK):
            self.calls.append(target)
            self.run_at(target, self.r[31])
        elif target == FREE:
            self.calls.append(target)
            self.free_arguments.append(self.r[4])
            self.run_at(target, self.r[31])
        elif target == RAW_FREE:
            self.calls.append(target)
            self.raw_free_arguments.append(self.r[4])
            if self.r[4] != SOURCE - 4:
                raise AssertionError('unexpected raw free argument')
            del self.regions[SOURCE - 4]
            self.hostile_result(FREE_RESULT)
        else:
            if target == COPY:
                self.name_copy = tuple(self.r[4:7])
            super().external(target)


class NativeLoadingContinuationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = audit.source_image()
        baseline, candidate, cls.patches = ui_guard_fixture(cls.image)
        cls.code = candidate[len(baseline):]

    def guarded(self, **options):
        return LoadingContinuationMachine(self.image, code=self.code, patches=self.patches,
                                          code_base=CODE_BASE, **options)

    def assert_loading_copy(self, machine, source):
        self.assertEqual(machine.name_copy, (DESTINATION + 0xC, VIEW, 64))
        self.assertEqual(machine.get(HANDLE + 0x58, 4), DESTINATION)
        self.assertEqual((machine.get(HANDLE + 0x74, 4), machine.get(HANDLE + 0x78, 4)),
                         (0x4AEA80, 0x4ADBE0))
        words = tuple(machine.get(DESTINATION + offset, 4) for offset in (0, 4, 8, 0xAD8, 0xADC))
        self.assertEqual(words, (SOURCE_VALUE, 0, 4, 0, 0) if source else (0,) * 5)
        data = machine.regions[DESTINATION]
        self.assertEqual(data[0xC:0x4C], VIEW_NAME)
        self.assertEqual(data[0xAE4:0xAE4 + len(WIDE_NAME)],
                         WIDE_NAME if source else bytes(len(WIDE_NAME)))

    def test_old_completion_keeps_or_releases_the_source_from_its_own_list(self):
        for flags in ((), (0, 2), (2, 1)):
            for scenario in ('live', 'view_miss', 'factory_null'):
                with self.subTest(flags=flags, scenario=scenario):
                    machine = self.guarded(
                        flags=flags, lookup_miss=2 if scenario == 'view_miss' else 0,
                        factory_result=0 if scenario == 'factory_null' else HANDLE,
                    )
                    machine.r[4] = OLD_DIALOG
                    machine.run_at(REMOVE_COMPLETE, RETURN)

                    self.assertEqual(machine.lookups, [(OWNER, SOURCE + 0xC), (OWNER, VIEW)])
                    self.assertEqual(machine.wrapper_results, [HANDLE if scenario == 'live' else 0])
                    self.assertEqual(machine.calls.count(FACTORY), int(scenario != 'view_miss'))
                    release = 1 in flags
                    last_flag = flags[-1] if flags else 0
                    self.assertEqual((machine.r[2], machine.r[29], machine.r[31]),
                                     (FREE_RESULT if release else last_flag, STACK, RETURN))
                    self.assertEqual(machine.free_arguments, [SOURCE] if release else [])
                    self.assertEqual(machine.raw_free_arguments, [SOURCE - 4] if release else [])
                    self.assertEqual(machine.get(OLD_DIALOG + 0x58, 4), 0 if release else SOURCE)
                    if scenario == 'live':
                        self.assert_loading_copy(machine, SOURCE)
                    else:
                        self.assertNotIn(ALLOCATOR, machine.calls)
                        self.assertEqual(machine.get(HANDLE + 0x58, 4), 0)
                        self.assertEqual(machine.get(HANDLE + 0x78, 4), 0)

    def test_temporary_callers_free_their_source_after_live_or_zero_results(self):
        callers = (
            # Slice, frame size, temp and view homes, saved registers.
            (0x4A731C, 1160, 0x44C, 0x450, (*range(16, 24), 30)),
            (0x4A79A0, 88, 0x3C, 0x40, (16, 17)),
        )
        for site, size, temp_home, view_home, registers in callers:
            for source in (SOURCE, 0):
                for refused in (False, True):
                    with self.subTest(site=hex(site), source=source, refused=refused):
                        machine = self.guarded(factory_result=0 if refused else HANDLE)
                        frame = machine.frame(size, size - 4)
                        saved = [0x55000000 + register for register in registers]
                        for index, value in enumerate(saved):
                            machine.put(frame + size - 4 * (len(registers) + 1 - index), value, 4)
                        machine.put(frame + temp_home, source, 4)
                        machine.put(frame + view_home, VIEW, 4)
                        machine.run_at(site, RETURN)

                        result = 0 if refused else HANDLE
                        expected = FREE_RESULT if source else result
                        if site == 0x4A79A0:
                            expected = 1
                        self.assertEqual(machine.wrapper_results, [result])
                        self.assertEqual(machine.free_arguments, [source])
                        self.assertEqual(machine.raw_free_arguments, [SOURCE - 4] if source else [])
                        self.assertEqual((machine.r[2], machine.r[29], machine.r[31]),
                                         (expected, STACK, RETURN))
                        self.assertEqual([machine.r[register] for register in registers], saved)
                        if refused:
                            self.assertNotIn(ALLOCATOR, machine.calls)
                            self.assertEqual(machine.get(HANDLE + 0x58, 4), 0)
                        else:
                            self.assert_loading_copy(machine, source)

    def test_live_loading_matches_stock_when_creating_or_reusing_context(self):
        for reused in (False, True):
            with self.subTest(reused=reused):
                native = LoadingContinuationMachine(self.image, reused_dialog=reused)
                guarded = self.guarded(reused_dialog=reused)
                for machine in (native, guarded):
                    machine.r[4:8] = [OWNER, 0, VIEW, SOURCE]
                    machine.run_at(LOADING, RETURN)
                    self.assertEqual((machine.r[2], machine.r[29], machine.r[31]),
                                     (HANDLE, STACK, RETURN))
                    if reused:
                        self.assertEqual(machine.calls, [VIEW_LOOKUP, FACTORY])
                        self.assertEqual(machine.get(HANDLE + 0x58, 4), CACHED_CONTEXT)
                        self.assertEqual(machine.regions[CACHED_CONTEXT], b'\xA7' * CONTEXT_SIZE)
                        self.assertEqual((machine.get(HANDLE + 0x74, 4),
                                          machine.get(HANDLE + 0x78, 4)), (0x450D60, 0x4AE180))
                    else:
                        self.assert_loading_copy(machine, SOURCE)

                self.assertEqual(guarded.calls, native.calls)
                self.assertEqual((guarded.r, guarded.hi, guarded.lo),
                                 (native.r, native.hi, native.lo))
                self.assertEqual(guarded.writes, native.writes)
                self.assertEqual(guarded.regions[DESTINATION], native.regions[DESTINATION])


if __name__ == '__main__':
    unittest.main()
