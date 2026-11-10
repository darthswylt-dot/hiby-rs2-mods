#!/usr/bin/env python3
"""Exercise the music dispatcher's request transfer and completion."""

import unittest

import factory_null_audit as audit
import reveal_d180_data_dealing_snapshot_mips as guard
from test_factory_d180_data_dealing_continuation import (
    EVENT, MAIN_DISPATCH, OPERATION, POLL, POST, QUEUE_RECORD, SECOND_OPERATION, SECOND_RECORD,
    ReusedDataDealingMachine,
)
from test_factory_null_audit import ALLOCATION, CONFIGURATOR, CONTEXT, FREE, HANDLE, RETURN, STACK
from test_reveal_d180_data_dealing_snapshot_mips import CODE_BASE, data_dealing_fixture


DIALOG_MUTEX = ALLOCATION + 0x60
FOREIGN_COMPLETION = 0x450D50


class MusicOwnershipMachine(ReusedDataDealingMachine):
    def __init__(self, image, **options):
        super().__init__(image, **options)
        self.put(HANDLE + 0x10, DIALOG_MUTEX, 4)
        self.lock_result = self.unlock_result = 0
        self.dialog_locked = False
        self.release_states = []
        self.refreshes = []

    def external(self, target):
        if target in (guard.LOCK, guard.UNLOCK) and self.r[4] == DIALOG_MUTEX:
            self.calls.append(target)
            result = self.lock_result if target == guard.LOCK else self.unlock_result
            if result == 0:
                self.dialog_locked = target == guard.LOCK
            self.hostile_result(result)
        elif target == 0x4E5680:
            self.calls.append(target)
            self.put(self.r[5], CONTEXT, 4)
            self.hostile_result(0)
        elif target == 0x4AD880:
            self.calls.append(target)
            self.refreshes.append(tuple(self.r[4:7]))
            self.hostile_result(0)
        else:
            if target == FREE:
                self.release_states.append((self.r[4], self.dialog_locked))
            super().external(target)

    def queue_first(self, *, owned=True):
        self.stock(POLL)
        if not owned:
            self.put(QUEUE_RECORD, 0, 4)

    def queue_next(self, operation, *, owned):
        self.allocation_result = SECOND_RECORD
        self.stock(POST, EVENT, operation, 0)
        if owned:
            self.put(SECOND_RECORD, guard.OWNED_TAG, 4)

    def complete(self):
        self.r[16] = HANDLE
        # This slice starts after the completion caller acquires H+10.
        self.run_at(0x47C7B8, 0x47C7D0)


class MusicOwnershipTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = audit.source_image()
        baseline, candidate, cls.patches = data_dealing_fixture(cls.image)
        cls.code = candidate[len(baseline):]

    def machine(self, **options):
        return MusicOwnershipMachine(self.image, code=self.code, patches=self.patches,
                                     code_base=CODE_BASE, **options)

    def test_factory_refusal_releases_only_an_owned_request(self):
        for owned in (False, True):
            with self.subTest(owned=owned):
                machine = self.machine(factory_result=0)
                machine.queue_first(owned=owned)
                first = len(machine.frees)
                machine.stock(MAIN_DISPATCH, CONTEXT)
                self.assertEqual(machine.frees[first:], [QUEUE_RECORD] + ([OPERATION] if owned else []))
                self.assertEqual((machine.r[2], machine.r[29], machine.r[31]), (0, STACK, RETURN))
                self.assertNotIn(CONFIGURATOR, machine.calls)

    def test_live_request_keeps_the_native_completion_refresh_and_releases_once(self):
        machine = self.machine()
        machine.queue_first()
        machine.stock(MAIN_DISPATCH, CONTEXT)
        self.assertEqual(machine.get(HANDLE + 0x50, 4), OPERATION)
        self.assertEqual(machine.get(HANDLE + 0x5C, 4), 1)
        self.assertNotEqual(machine.get(HANDLE + 0x74, 4), guard.COMPLETION)
        self.assertNotIn(OPERATION, machine.frees)

        machine.put(HANDLE + 0x58, 1, 4)
        machine.put(HANDLE + 0x48, CONTEXT, 4)
        machine.put(OPERATION, 0x11223344, 4)
        machine.complete()
        machine.complete()
        self.assertEqual(machine.refreshes, [(CONTEXT, OPERATION + 0x50, 0x11223344)])
        self.assertEqual(machine.frees.count(OPERATION), 1)
        self.assertEqual(machine.get(HANDLE + 0x50, 4), 0)
        self.assertEqual(machine.get(HANDLE + 0x74, 4), guard.COMPLETION)

    def test_reuse_releases_only_a_different_previously_owned_request(self):
        cases = ((SECOND_OPERATION, True), (SECOND_OPERATION, False), (0, False),
                 (OPERATION, True), (OPERATION, False))
        for incoming, marked in cases:
            with self.subTest(incoming=hex(incoming), marked=marked):
                machine = self.machine()
                machine.queue_first()
                machine.stock(MAIN_DISPATCH, CONTEXT)
                callback = machine.get(HANDLE + 0x74, 4)
                machine.register_existing_dialog()
                machine.queue_next(incoming, owned=marked)

                first = len(machine.frees)
                machine.stock(MAIN_DISPATCH, CONTEXT)
                same = incoming == OPERATION
                self.assertEqual(machine.get(HANDLE + 0x50, 4), incoming)
                self.assertEqual(machine.get(HANDLE + 0x74, 4),
                                 callback if marked or same else guard.COMPLETION)
                self.assertEqual(machine.frees[first:], [SECOND_RECORD] + ([] if same else [OPERATION]))
                if not same:
                    self.assertEqual(machine.release_states[-1], (OPERATION, False))

                machine.complete()
                self.assertEqual(machine.frees.count(OPERATION), 1)
                self.assertEqual(machine.frees.count(SECOND_OPERATION), int(incoming == SECOND_OPERATION))

    def test_ordinary_live_message_uses_the_native_configurator(self):
        machine = self.machine()
        machine.queue_first(owned=False)
        machine.stock(MAIN_DISPATCH, CONTEXT)

        self.assertEqual(machine.config_inputs, (HANDLE, HANDLE, 4))
        self.assertEqual(machine.get(HANDLE + 0x50, 4), OPERATION)
        self.assertEqual(machine.get(HANDLE + 0x74, 4), guard.COMPLETION)
        self.assertNotIn(OPERATION, machine.frees)

    def test_foreign_callback_retains_its_request_and_declines_owned_input(self):
        machine = self.machine()
        machine.queue_first()
        machine.register_existing_dialog()
        machine.put(HANDLE + 0x50, SECOND_OPERATION, 4)
        machine.put(HANDLE + 0x74, FOREIGN_COMPLETION, 4)
        machine.stock(MAIN_DISPATCH, CONTEXT)

        self.assertEqual(machine.get(HANDLE + 0x50, 4), SECOND_OPERATION)
        self.assertEqual(machine.get(HANDLE + 0x74, 4), FOREIGN_COMPLETION)
        self.assertEqual(machine.release_states[-1], (OPERATION, False))
        self.assertNotIn(SECOND_OPERATION, machine.frees)

    def test_unavailable_dialog_lock_keeps_fields_and_release_authority_open(self):
        for mutex in (0, DIALOG_MUTEX):
            with self.subTest(mutex=hex(mutex)):
                machine = self.machine()
                machine.queue_first()
                machine.register_existing_dialog()
                machine.put(HANDLE + 0x10, mutex, 4)
                machine.put(HANDLE + 0x50, SECOND_OPERATION, 4)
                machine.put(HANDLE + 0x74, guard.COMPLETION, 4)
                machine.lock_result = 22
                first = len(machine.calls)
                machine.stock(MAIN_DISPATCH, CONTEXT)

                self.assertEqual(guard.LOCK in machine.calls[first:], bool(mutex))
                self.assertEqual(machine.get(HANDLE + 0x50, 4), SECOND_OPERATION)
                self.assertEqual(machine.get(HANDLE + 0x5C, 4), 0)
                self.assertEqual(machine.get(HANDLE + 0x74, 4), guard.COMPLETION)
                self.assertNotIn(OPERATION, machine.frees)
                self.assertFalse(machine.dialog_locked)

    def test_unlock_error_leaves_the_displaced_request_unreleased(self):
        machine = self.machine()
        machine.queue_first()
        machine.stock(MAIN_DISPATCH, CONTEXT)
        callback = machine.get(HANDLE + 0x74, 4)
        machine.register_existing_dialog()
        machine.queue_next(SECOND_OPERATION, owned=True)
        machine.unlock_result = 22
        machine.stock(MAIN_DISPATCH, CONTEXT)

        self.assertEqual(machine.get(HANDLE + 0x50, 4), SECOND_OPERATION)
        self.assertEqual(machine.get(HANDLE + 0x74, 4), callback)
        self.assertNotIn(OPERATION, machine.frees)
        self.assertTrue(machine.dialog_locked)


if __name__ == '__main__':
    unittest.main()
