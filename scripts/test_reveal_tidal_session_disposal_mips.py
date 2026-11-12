#!/usr/bin/env python3
"""Exercise final pair disposal through both full native session-close routes."""

import unittest

import factory_null_audit as audit
import reveal_tidal_session_disposal_mips as disposal
import reveal_tidal_response_reader_bridge_mips as session
from test_factory_d180_tidal_response_lifecycle import (
    COPY_OUTPUT, COPY_RESPONSE, HAS_RESPONSE, NEW_RESPONSE, OLD_FOLLOWUP, OLD_RESPONSE, SESSION,
)
from test_factory_null_audit import RETURN, STACK
from test_reveal_tidal_qr_generation_mips import QrGenerationMachine
from test_reveal_tidal_response_reader_bridge_mips import CODE_BASE, MUTEX, NATIVE_TOP


class DisposalMachine(QrGenerationMachine):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.disposal_events = []
        self.on_disposal_release = None
        self.pair_at_free = None
        self._linked_free = False

    def word(self, pc):
        if pc == disposal.AFTER_DETACH:
            self.external(pc)
            self.fetch_pc = pc
            return 0x03E00008
        if pc == disposal.AFTER_DETACH + 4:
            self.fetch_pc = pc
            return 0
        if pc == disposal.FREE and not self._linked_free:
            # The helper tail-calls native FREE with RA=475810. Record entry,
            # then execute its actual allocator-header/free instructions.
            self.disposal_events.append((pc, self.r[4]))
            self.pair_at_free = self.slots()
            self.releases.append(self.r[4])
            self.teardown_events.append(pc)
            self.teardown_phases.append(self.get(MUTEX + session.LIFECYCLE, 4))
        return super().word(pc)

    def external(self, target):
        if hasattr(self, 'disposal_events') and target in (
                disposal.RELEASE, disposal.AFTER_DETACH, 0x4556E0, 0x8B1180, disposal.FREE, 0x466980):
            if self.held:
                raise AssertionError('disposal callback or native teardown held the session mutex')
            self.disposal_events.append((target, self.r[4]))
            if target == disposal.RELEASE and self.on_disposal_release is not None:
                self.on_disposal_release(self.r[4])
        if target == disposal.FREE:
            self._linked_free = True
            try:
                super().external(target)
            finally:
                self._linked_free = False
        else:
            super().external(target)


class NativeTidalSessionDisposalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = audit.source_image()
        cls.code, cls.patches = disposal.assemble(MUTEX, CODE_BASE)

    def machine(self):
        return DisposalMachine(self.image, self.code, self.patches)

    def run_close(self, machine, site=None):
        machine.seed_native_frame()
        machine.run_at(site or session.CLOSE_SITES[0][0], RETURN)

    def assert_retained_failure(self, machine, error, *, raw=False):
        self.assertEqual((machine.r[2], machine.r[3]), (0xFFFFFFFF, error))
        self.assertEqual(machine.get(MUTEX + session.LIFECYCLE, 4), session.CLOSING)
        self.assertEqual(machine.get(MUTEX + session.PHASE, 4), session.FAILED if raw else session.READY)
        self.assertEqual(machine.get(session.SESSION_SLOT, 4), SESSION)
        self.assertEqual(machine.get(MUTEX + session.BOUND_SESSION, 4), SESSION)
        self.assertNotIn(SESSION, machine.releases)
        self.assertNotIn(0x466980, [target for target, _ in machine.disposal_events])
        self.assertEqual((machine.r[29], machine.r[31]), (NATIVE_TOP, RETURN))

    def test_source_pairs_and_both_full_close_routes_release_pair_before_context_and_session(self):
        self.assertEqual(len(self.patches), 39)
        for site, original in disposal.HOOKS:
            self.assertEqual(original, (self.image.word(site), self.image.word(site + 4)))
        for site, _, _ in session.CLOSE_SITES:
            with self.subTest(site=hex(site)):
                machine = self.machine()
                self.run_close(machine, site)
                self.assertEqual(machine.response_releases, [OLD_RESPONSE, OLD_FOLLOWUP])
                self.assertEqual(machine.releases, [SESSION])
                self.assertEqual(machine.raw_releases, [SESSION - 4])
                self.assertEqual(machine.pair_at_free, (0, 0))
                targets = [target for target, _ in machine.disposal_events]
                self.assertLess(targets.index(0x4556E0), targets.index(disposal.RELEASE))
                self.assertLess(max(index for index, target in enumerate(targets) if target == disposal.RELEASE),
                                targets.index(disposal.AFTER_DETACH))
                self.assertLess(targets.index(disposal.AFTER_DETACH), targets.index(0x8B1180))
                self.assertLess(targets.index(0x8B1180), targets.index(disposal.FREE))
                self.assertLess(targets.index(disposal.FREE), targets.index(0x466980))
                self.assertEqual(machine.get(session.SESSION_SLOT, 4), 0)
                self.assertEqual(machine.get(MUTEX + session.BOUND_SESSION, 4), 0)
                self.assertEqual(machine.get(MUTEX + session.LIFECYCLE, 4), session.EMPTY)
                self.assertEqual(machine.r[16:20], [0x55000000 + index for index in range(4)])
                self.assertEqual((machine.r[29], machine.r[31]), (NATIVE_TOP, RETURN))

    def test_disabled_cleanup_flag_empty_pair_and_orphan_slots_still_allow_final_disposal(self):
        for kind, expected in (('disabled', [OLD_RESPONSE, OLD_FOLLOWUP]),
                               ('null_data', [OLD_RESPONSE, OLD_FOLLOWUP]), ('primary', [OLD_RESPONSE]),
                               ('orphan', [OLD_FOLLOWUP]), ('empty', [])):
            with self.subTest(kind=kind):
                machine = self.machine()
                if kind == 'disabled':
                    machine.put(SESSION + 0x20, 0, 4)
                if kind == 'null_data':
                    machine.put(OLD_RESPONSE + 8, 0, 4)
                if kind in ('orphan', 'empty'):
                    machine.put(SESSION + 0x18, 0, 4)
                if kind in ('primary', 'empty'):
                    machine.put(SESSION + 0x1C, 0, 4)
                self.run_close(machine)
                self.assertEqual(machine.response_releases, expected)
                self.assertEqual(machine.releases, [SESSION])
                self.assertEqual(machine.pair_at_free, (0, 0))
                self.assertNotIn(0x8BD9D4, machine.calls)

    def test_alias_rejects_before_detach_and_never_guesses_reference_ownership(self):
        machine = self.machine()
        machine.put(SESSION + 0x1C, OLD_RESPONSE, 4)
        self.run_close(machine)
        self.assert_retained_failure(machine, 22)
        self.assertEqual(machine.slots(), (OLD_RESPONSE, OLD_RESPONSE))
        self.assertEqual(machine.response_releases, [])

    def test_live_state_bad_frame_token_and_drained_counts_refuse_disposal(self):
        for kind, error in (('live', 116), ('token', 116), ('writer', 16), ('borrow', 16)):
            with self.subTest(kind=kind):
                machine = self.machine()
                frame = machine.seed_native_frame()
                machine.r[16] = SESSION
                machine.put(MUTEX + session.LIFECYCLE, session.LIVE if kind == 'live' else session.CLOSING, 4)
                if kind == 'token':
                    machine.put(frame + session.TOKEN, 2, 4)
                if kind in ('writer', 'borrow'):
                    machine.put(MUTEX + (session.WRITER if kind == 'writer' else session.BORROWS), 1, 4)
                machine.run_at(disposal.DETACH, RETURN)
                self.assertEqual((machine.r[2], machine.r[3]), (0xFFFFFFFF, error))
                self.assertEqual(machine.response_releases, [])
                self.assertEqual(machine.slots(), (OLD_RESPONSE, OLD_FOLLOWUP))

    def test_reentrant_readers_are_closed_and_new_publication_is_blocked_during_releases(self):
        machine = self.machine()
        observed = []

        def reenter(_):
            reader = machine.fork_cpu()
            reader.r[29] = STACK - 0x800
            for site in (COPY_RESPONSE, HAS_RESPONSE):
                observed.append((reader.stock(site, COPY_OUTPUT), reader.r[3]))
            observed.append((reader.stock(0x4B16A0), reader.r[3]))
            candidate = machine.fork_cpu()
            candidate.seed_native_frame(session=SESSION + 0x800, top=NATIVE_TOP + 0x400)
            candidate.run_at(session.INIT_SITE, session.INIT_SITE + 8)
            candidate.run_at(session.PUBLISH_SITES[0][0], RETURN)
            self.assertEqual((candidate.r[2], candidate.r[3]), (0xFFFFFFFF, 116))
            self.assertEqual(machine.get(MUTEX + session.LIFECYCLE, 4), session.CLOSING)

        machine.on_disposal_release = reenter
        self.run_close(machine)
        self.assertEqual(observed, [(0, 0), (0, 0), (0, 116)] * 2)
        self.assertEqual(machine.response_releases, [OLD_RESPONSE, OLD_FOLLOWUP])
        self.assertEqual(machine.releases, [SESSION])

    def test_repopulated_fields_after_callbacks_or_during_later_teardown_prevent_session_free(self):
        for late in (False, True):
            with self.subTest(late=late):
                machine = self.machine()
                if late:
                    machine.on_teardown = lambda target: machine.put(SESSION + 0x18, NEW_RESPONSE, 4) if target == disposal.AFTER_DETACH else None
                else:
                    machine.on_disposal_release = lambda pointer: machine.put(SESSION + 0x18, NEW_RESPONSE, 4) if pointer == OLD_FOLLOWUP else None
                self.run_close(machine)
                self.assert_retained_failure(machine, 71)
                self.assertEqual(machine.response_releases, [OLD_RESPONSE, OLD_FOLLOWUP])
                self.assertEqual(machine.slots(), (NEW_RESPONSE, 0))

    def test_raw_detach_errors_preserve_actual_field_effect_and_skip_callbacks(self):
        for acquire, release in ((22, 0), (0, 1)):
            with self.subTest(acquire=acquire, release=release):
                machine = self.machine()

                def fail_after_stop(target):
                    if target == 0x4556E0:
                        machine.acquire_result, machine.release_result = acquire, release

                machine.on_teardown = fail_after_stop
                self.run_close(machine)
                self.assert_retained_failure(machine, acquire or release, raw=True)
                self.assertEqual(machine.slots(), (OLD_RESPONSE, OLD_FOLLOWUP) if acquire else (0, 0))
                self.assertEqual(machine.response_releases, [])

    def test_raw_postcallback_and_final_free_gates_do_not_repeat_disposal_or_free_session(self):
        for phase in ('callbacks', 'free'):
            for acquire, release in ((22, 0), (0, 1)):
                with self.subTest(phase=phase, acquire=acquire, release=release):
                    machine = self.machine()

                    def fail_after_release(pointer):
                        if pointer == OLD_FOLLOWUP:
                            machine.acquire_result, machine.release_result = acquire, release

                    def fail_after_context(target):
                        if target == 0x8B1180:
                            machine.acquire_result, machine.release_result = acquire, release

                    machine.on_disposal_release = fail_after_release if phase == 'callbacks' else None
                    machine.on_teardown = fail_after_context if phase == 'free' else None
                    self.run_close(machine)
                    self.assert_retained_failure(machine, acquire or release, raw=True)
                    self.assertEqual(machine.response_releases, [OLD_RESPONSE, OLD_FOLLOWUP])
                    self.assertEqual(machine.slots(), (0, 0))

    def test_observed_fault_in_first_release_suppresses_the_second_and_all_later_teardown(self):
        machine = self.machine()

        def fault_in_release(pointer):
            if pointer == OLD_RESPONSE:
                reader = machine.fork_cpu()
                reader.r[29] = STACK - 0x800
                reader.acquire_result = 22
                reader.stock(COPY_RESPONSE, COPY_OUTPUT)
                self.assertEqual(reader.r[3], 22)

        machine.on_disposal_release = fault_in_release
        self.run_close(machine)
        self.assert_retained_failure(machine, 22, raw=True)
        self.assertEqual(machine.response_releases, [OLD_RESPONSE])
        self.assertNotIn(disposal.AFTER_DETACH, [target for target, _ in machine.disposal_events])

    def test_observed_fault_after_the_final_unlock_suppresses_the_native_free(self):
        machine = self.machine()

        def fault_after_final_unlock():
            if 0x8B1180 in [target for target, _ in machine.disposal_events]:
                machine.put(MUTEX + session.INIT_ERROR, 22, 4)
                machine.put(MUTEX + session.PHASE, session.FAILED, 4)

        machine.on_release = fault_after_final_unlock
        self.run_close(machine)
        self.assert_retained_failure(machine, 22, raw=True)
        self.assertEqual(machine.response_releases, [OLD_RESPONSE, OLD_FOLLOWUP])
        self.assertFalse(machine.held)

    def test_observed_fault_after_disposal_unlock_suppresses_context_teardown(self):
        machine = self.machine()

        def fault_after_disposal_unlock():
            if machine.response_releases == [OLD_RESPONSE, OLD_FOLLOWUP]:
                machine.put(MUTEX + session.INIT_ERROR, 22, 4)
                machine.put(MUTEX + session.PHASE, session.FAILED, 4)

        machine.on_release = fault_after_disposal_unlock
        self.run_close(machine)
        self.assert_retained_failure(machine, 22, raw=True)
        self.assertEqual(machine.slots(), (0, 0))
        self.assertEqual(machine.response_releases, [OLD_RESPONSE, OLD_FOLLOWUP])
        targets = [target for target, _ in machine.disposal_events]
        self.assertNotIn(disposal.AFTER_DETACH, targets)
        self.assertNotIn(0x8B1180, targets)
        self.assertFalse(machine.held)


if __name__ == '__main__':
    unittest.main()
