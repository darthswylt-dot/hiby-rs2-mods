#!/usr/bin/env python3
"""Execute checked cleanup detach, callbacks and owner-pin finalization."""

import threading
import unittest

import factory_null_audit as audit
import reveal_tidal_response_cleanup_mips as cleanup
import reveal_tidal_request_identity_mips as identity
import reveal_tidal_response_reader_bridge_mips as session
from test_factory_d180_tidal_response_lifecycle import (
    COPY_OUTPUT, COPY_RESPONSE, COPY_TEXT, HAS_RESPONSE, NEW_FOLLOWUP, NEW_RESPONSE,
    OLD_FOLLOWUP, OLD_RESPONSE, RESPONSE_DATA, SESSION,
)
from test_factory_null_audit import RETURN, STACK
from test_reveal_tidal_request_identity_mips import IdentityMachine
from test_reveal_tidal_response_reader_bridge_mips import CODE_BASE, MUTEX
from test_reveal_tidal_response_pair_mips import PairMachine


class CleanupMachine(IdentityMachine):
    def __init__(self, *args, cleanup_result=0, **kwargs):
        super().__init__(*args, **kwargs)
        self.cleanup_result = cleanup_result
        self.cleanup_events = []
        self.on_cleanup_callback = None

    def external(self, target):
        if target in (cleanup.CLOSE, cleanup.RELEASE):
            if self.held:
                raise AssertionError('cleanup callback ran under the session mutex')
            self.cleanup_events.append((target, tuple(self.r[4:6])))
            if self.on_cleanup_callback is not None:
                self.on_cleanup_callback(target)
        super().external(target)


class NativeTidalResponseCleanupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = audit.source_image()
        cls.code, cls.patches = cleanup.assemble(MUTEX, CODE_BASE)

    def machine(self, **options):
        return CleanupMachine(self.image, self.code, self.patches, **options)

    def assert_abi(self, machine, before, hi, lo):
        self.assertEqual((machine.hi, machine.lo), (hi, lo))
        for register in range(32):
            if register not in (2, 3):
                self.assertEqual(machine.r[register], before[register], f'r{register}')

    def assert_detached(self, machine):
        self.assertEqual(machine.slots(), (0, 0))
        self.assertEqual(machine.get(session.SESSION_SLOT, 4), SESSION)

    def test_composed_entry_pins_the_native_cleanup_pair(self):
        self.assertEqual(len(self.patches), 17)
        self.assertEqual(cleanup.ENTRY_PAIR,
                         (self.image.word(cleanup.ENTRY), self.image.word(cleanup.ENTRY + 4)))
        self.assertEqual(self.patches[cleanup.ENTRY][0], cleanup.ENTRY_PAIR)

    def test_close_success_or_failure_always_releases_detached_objects_once(self):
        for close_result in (0, -1, 1):
            with self.subTest(close_result=close_result):
                machine = self.machine(cleanup_result=close_result)
                before, hi, lo = machine.r.copy(), machine.hi, machine.lo
                self.assertEqual(machine.stock(cleanup.ENTRY), close_result & 0xFFFFFFFF)
                self.assert_abi(machine, before, hi, lo)
                self.assertEqual(machine.r[3], 0)
                self.assert_detached(machine)
                self.assertEqual(machine.cleanup_events[0], (cleanup.CLOSE, (RESPONSE_DATA, 0)))
                self.assertEqual([target for target, _ in machine.cleanup_events],
                                 [cleanup.CLOSE, cleanup.RELEASE, cleanup.RELEASE])
                self.assertEqual(machine.response_releases, [OLD_RESPONSE, OLD_FOLLOWUP])
                self.assertEqual(machine.get(MUTEX + session.WRITER, 4), 0)
                self.assertEqual(machine.get(MUTEX + session.PHASE, 4), session.READY)

    def test_primary_only_cleanup_skips_null_secondary_release(self):
        machine = self.machine()
        machine.put(SESSION + 0x1C, 0, 4)
        self.assertEqual(machine.stock(cleanup.ENTRY), 0)
        self.assert_detached(machine)
        self.assertEqual(machine.response_releases, [OLD_RESPONSE])
        self.assertEqual(len(machine.cleanup_events), 2)

    def test_empty_pair_is_an_idempotent_noop_and_disabled_keeps_native_minus_one(self):
        for enabled, empty, result in ((False, False, 0xFFFFFFFF), (True, True, 0)):
            with self.subTest(enabled=enabled, empty=empty):
                machine = self.machine()
                machine.put(SESSION + 0x20, int(enabled), 4)
                if empty:
                    machine.put(SESSION + 0x18, 0, 4)
                    machine.put(SESSION + 0x1C, 0, 4)
                before = machine.slots()
                self.assertEqual(machine.stock(cleanup.ENTRY), result)
                self.assertEqual(machine.r[3], 0)
                self.assertEqual(machine.slots(), before)
                self.assertEqual(machine.cleanup_events, [])
                self.assertEqual(machine.get(MUTEX + session.WRITER, 4), 0)

    def test_invalid_pair_never_detaches_or_guesses_release_ownership(self):
        for kind, error in (('orphan', 71), ('alias', 22), ('null_data', 22)):
            with self.subTest(kind=kind):
                machine = self.machine()
                if kind == 'orphan':
                    machine.put(SESSION + 0x18, 0, 4)
                elif kind == 'alias':
                    machine.put(SESSION + 0x1C, OLD_RESPONSE, 4)
                else:
                    machine.put(OLD_RESPONSE + 8, 0, 4)
                before = machine.slots()
                self.assertEqual(machine.stock(cleanup.ENTRY), 0xFFFFFFFF)
                self.assertEqual(machine.r[3], error)
                self.assertEqual(machine.slots(), before)
                self.assertEqual(machine.cleanup_events, [])
                self.assertEqual(machine.get(MUTEX + session.WRITER, 4), 0)
                self.assertEqual(machine.get(MUTEX + session.PHASE, 4), session.READY)

    def test_guarded_readers_observe_empty_slots_during_all_cleanup_callbacks(self):
        machine = self.machine()
        observed = []

        def read_detached(_):
            reader = machine.fork_cpu()
            reader.r[29] = STACK - 0x800
            for site in (COPY_RESPONSE, HAS_RESPONSE):
                observed.append((reader.stock(site, COPY_OUTPUT), reader.r[3]))
            self.assertEqual(reader.get(COPY_OUTPUT, 1), 0xCC)

        machine.on_cleanup_callback = read_detached
        self.assertEqual(machine.stock(cleanup.ENTRY), 0)
        self.assertEqual(observed, [(0, 0)] * 6)

    def test_detach_waits_for_an_active_native_string_copy(self):
        reader = self.machine()
        disposer = reader.fork_cpu()
        disposer.r[29] = STACK - 0x800
        entered, permit, requested = threading.Event(), threading.Event(), threading.Event()
        failures = []

        def hold_copy():
            entered.set()
            if not permit.wait(3):
                raise AssertionError('copy was not released')

        def capture(operation):
            try:
                operation()
            except BaseException as error:
                failures.append(error)

        reader.on_string, disposer.on_acquire = hold_copy, requested.set
        copying = threading.Thread(target=capture, args=(lambda: reader.stock(COPY_RESPONSE, COPY_OUTPUT),))
        disposing = threading.Thread(target=capture, args=(lambda: disposer.stock(cleanup.ENTRY),))
        copying.start()
        try:
            self.assertTrue(entered.wait(2))
            disposing.start()
            self.assertTrue(requested.wait(2))
            self.assertEqual(reader.slots(), (OLD_RESPONSE, OLD_FOLLOWUP))
            self.assertEqual(disposer.cleanup_events, [])
            self.assertEqual(reader.get(MUTEX + session.WRITER, 4), 0)
        finally:
            permit.set()
            copying.join(4)
            if disposing.ident is not None:
                disposing.join(4)
        self.assertFalse(copying.is_alive() or disposing.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(bytes(reader.get(COPY_OUTPUT + offset, 1) for offset in range(len(COPY_TEXT))), COPY_TEXT)
        self.assertEqual(disposer.r[2], 0)
        self.assertEqual(disposer.response_releases, [OLD_RESPONSE, OLD_FOLLOWUP])
        self.assert_detached(reader)

    def test_main_close_and_reentrant_cleanup_refuse_the_distinct_owner_pin(self):
        for close, _, _ in session.CLOSE_SITES:
            with self.subTest(close=hex(close)):
                machine = self.machine()
                observed_pins = []

                def attempt_close(_):
                    observed_pins.append(machine.get(MUTEX + session.WRITER, 4))
                    closer = machine.fork_cpu()
                    closer.on_cleanup_callback = None
                    closer.seed_native_frame()
                    closer.run_at(close, RETURN)
                    self.assertEqual((closer.r[2], closer.r[3]), (0xFFFFFFFF, 16))
                    self.assertEqual(closer.teardown_events, [])
                    nested = machine.fork_cpu()
                    nested.on_cleanup_callback = None
                    nested.r[29] = STACK - 0x800
                    self.assertEqual(nested.stock(cleanup.ENTRY), 0xFFFFFFFF)
                    self.assertEqual(nested.r[3], 16)
                    self.assertEqual(nested.cleanup_events, [])

                machine.on_cleanup_callback = attempt_close
                self.assertEqual(machine.stock(cleanup.ENTRY), 0)
                self.assertEqual(observed_pins, [cleanup.OWNER_BIT | 1] * 3)
                self.assertEqual(machine.get(MUTEX + session.WRITER, 4), 0)

    def test_existing_worker_pin_or_foreign_global_preserves_the_pair(self):
        for kind, error in (('writer', 16), ('global', 116)):
            with self.subTest(kind=kind):
                machine = self.machine()
                if kind == 'writer':
                    machine.put(MUTEX + session.WRITER, 1, 4)
                else:
                    machine.put(session.SESSION_SLOT, SESSION + 0x800, 4)
                before = machine.slots()
                self.assertEqual(machine.stock(cleanup.ENTRY), 0xFFFFFFFF)
                self.assertEqual(machine.r[3], error)
                self.assertEqual(machine.slots(), before)
                self.assertEqual(machine.cleanup_events, [])

    def test_admission_raw_errors_skip_callbacks_and_preserve_actual_detach_effect(self):
        for acquire, release in ((22, 0), (0, 1)):
            with self.subTest(acquire=acquire, release=release):
                machine = self.machine(acquire=acquire, release=release)
                before, hi, lo = machine.r.copy(), machine.hi, machine.lo
                self.assertEqual(machine.stock(cleanup.ENTRY), 0xFFFFFFFF)
                self.assert_abi(machine, before, hi, lo)
                self.assertEqual(machine.r[3], acquire or release)
                self.assertEqual(machine.get(MUTEX + session.PHASE, 4), session.FAILED)
                self.assertEqual(machine.slots(), (OLD_RESPONSE, OLD_FOLLOWUP) if acquire else (0, 0))
                self.assertEqual(machine.get(MUTEX + session.WRITER, 4), 0 if acquire else cleanup.OWNER_BIT | 1)
                self.assertEqual(machine.cleanup_events, [])
                expected = [(session.LOCK, MUTEX, acquire)]
                if not acquire:
                    expected.append((session.UNLOCK, MUTEX, release))
                self.assertEqual(machine.mutex_events, expected)

    def test_finalize_raw_errors_do_not_repeat_already_completed_callbacks(self):
        for acquire, release in ((22, 0), (0, 1)):
            with self.subTest(acquire=acquire, release=release):
                machine = self.machine()

                def fail_finalize(target):
                    if target == cleanup.RELEASE and machine.r[4] == OLD_FOLLOWUP:
                        machine.acquire_result, machine.release_result = acquire, release

                machine.on_cleanup_callback = fail_finalize
                self.assertEqual(machine.stock(cleanup.ENTRY), 0xFFFFFFFF)
                self.assertEqual(machine.r[3], acquire or release)
                self.assertEqual(machine.get(MUTEX + session.PHASE, 4), session.FAILED)
                self.assert_detached(machine)
                self.assertEqual(machine.response_releases, [OLD_RESPONSE, OLD_FOLLOWUP])
                self.assertEqual(machine.get(MUTEX + session.WRITER, 4), cleanup.OWNER_BIT | 1 if acquire else 0)
                calls, callbacks = machine.mutex_events.copy(), machine.cleanup_events.copy()
                self.assertEqual(machine.stock(cleanup.ENTRY), 0xFFFFFFFF)
                self.assertEqual(machine.cleanup_events, callbacks)
                self.assertEqual(machine.mutex_events, calls)

    def test_finalize_never_clears_a_replaced_owner_pin(self):
        machine = self.machine()

        def replace_pin(target):
            if target == cleanup.RELEASE and machine.r[4] == OLD_FOLLOWUP:
                machine.put(MUTEX + session.WRITER, 2, 4)

        machine.on_cleanup_callback = replace_pin
        self.assertEqual(machine.stock(cleanup.ENTRY), 0xFFFFFFFF)
        self.assertEqual(machine.r[3], 116)
        self.assert_detached(machine)
        self.assertEqual(machine.response_releases, [OLD_RESPONSE, OLD_FOLLOWUP])
        self.assertEqual(machine.get(MUTEX + session.WRITER, 4), 2)
        self.assertEqual(machine.get(MUTEX + session.PHASE, 4), session.READY)

    def test_observed_callback_fault_suppresses_later_release_without_lock_retry(self):
        for fault_at in (cleanup.CLOSE, cleanup.RELEASE):
            with self.subTest(fault_at=fault_at):
                machine = self.machine()

                def fault_during_callback(target):
                    if target == fault_at:
                        machine.put(MUTEX + session.INIT_ERROR, 22, 4)
                        machine.put(MUTEX + session.PHASE, session.FAILED, 4)

                machine.on_cleanup_callback = fault_during_callback
                self.assertEqual(machine.stock(cleanup.ENTRY), 0xFFFFFFFF)
                self.assertEqual(machine.r[3], 22)
                self.assert_detached(machine)
                expected = [] if fault_at == cleanup.CLOSE else [OLD_RESPONSE]
                self.assertEqual(machine.response_releases, expected)
                self.assertEqual(machine.get(MUTEX + session.WRITER, 4), cleanup.OWNER_BIT | 1)
                self.assertEqual(machine.mutex_events,
                                 [(session.LOCK, MUTEX, 0), (session.UNLOCK, MUTEX, 0)])

    def test_complete_composed_worker_commit_cleanup_and_idempotent_repeat(self):
        machine = PairMachine(self.image, self.code, self.patches)
        machine.seed_worker()
        machine.run_at(identity.WORK_BEGIN, identity.WORK_END + 8)
        self.assertEqual(machine.slots(), (NEW_RESPONSE, NEW_FOLLOWUP))
        self.assertEqual(machine.response_releases, [OLD_RESPONSE, OLD_FOLLOWUP])
        self.assertEqual(machine.get(MUTEX + session.WRITER, 4), 0)
        machine.r[29] = STACK
        self.assertEqual(machine.stock(cleanup.ENTRY), 0)
        self.assertEqual(machine.slots(), (0, 0))
        self.assertEqual(machine.response_releases,
                         [OLD_RESPONSE, OLD_FOLLOWUP, NEW_RESPONSE, NEW_FOLLOWUP])
        releases = machine.response_releases.copy()
        self.assertEqual(machine.stock(cleanup.ENTRY), 0)
        self.assertEqual(machine.response_releases, releases)


if __name__ == '__main__':
    unittest.main()
