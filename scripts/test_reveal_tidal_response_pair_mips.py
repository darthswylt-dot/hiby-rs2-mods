#!/usr/bin/env python3
"""Execute private native request preparation and checked pair replacement."""

import threading
import unittest

import factory_null_audit as audit
import reveal_tidal_response_pair_mips as pair
import reveal_tidal_request_identity_mips as identity
import reveal_tidal_response_reader_bridge_mips as session
from test_factory_d180_qr_continuation import RELEASE_RESPONSE
from test_factory_d180_tidal_response_lifecycle import (
    COPY_OUTPUT, COPY_RESPONSE, COPY_TEXT, FOLLOWUP_SERVICE, NEW_DATA,
    NEW_FOLLOWUP, NEW_RESPONSE, OLD_FOLLOWUP, OLD_RESPONSE, REQUEST_SERVICE,
    RESPONSE_DATA, SESSION, STRING_SIZE, USER_ID,
)
from test_factory_null_audit import RETURN, STACK
from test_reveal_tidal_request_identity_mips import IdentityMachine
from test_reveal_tidal_response_reader_bridge_mips import CODE_BASE, MUTEX


class PairMachine(IdentityMachine):
    def __init__(self, *args, request_result=NEW_RESPONSE, followup_result=NEW_FOLLOWUP, **kwargs):
        super().__init__(*args, **kwargs)
        self.request_result, self.followup_result = request_result, followup_result
        self.on_response_release = None
        self.released_objects = set()

    def get(self, address, size):
        for pointer in getattr(self, 'released_objects', ()):
            if pointer <= address < pointer + 0x10:
                raise AssertionError('access to a released response fixture')
        return super().get(address, size)

    def external(self, target):
        if target == RELEASE_RESPONSE:
            if self.held:
                raise AssertionError('response release callback ran under the mutex')
            pointer = self.r[4]
            if pointer in self.released_objects:
                raise AssertionError('duplicate response release')
            super().external(target)
            self.released_objects.add(pointer)
            if self.on_response_release is not None:
                self.on_response_release(pointer)
        elif target == STRING_SIZE:
            if not self.held:
                raise AssertionError('string query outside the reader mutex')
            if self.on_string is not None:
                self.on_string()
            strings = {RESPONSE_DATA: COPY_TEXT, NEW_DATA: b'new'}
            self.calls.append(target)
            self.hostile_result(len(strings[self.r[4]]))
        else:
            super().external(target)


class NativeTidalResponsePairTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = audit.source_image()
        cls.code, cls.patches = pair.assemble(MUTEX, CODE_BASE)

    def machine(self, **options):
        return PairMachine(self.image, self.code, self.patches, **options)

    def test_all_sixteen_redirects_match_the_pinned_source(self):
        self.assertEqual(len(self.patches), 16)
        for site, original in pair.HOOKS:
            self.assertEqual(original, (self.image.word(site), self.image.word(site + 4)))
            self.assertEqual(self.patches[site][0], original)

    def test_native_preparation_keeps_both_old_slots_until_joint_commit(self):
        machine = self.machine()
        machine.seed_worker()
        stack = machine.r[29]
        machine.run_at(identity.WORK_BEGIN, pair.CALL)
        saved = machine.r[16:24]
        machine.run_at(pair.CALL, pair.FIRST)
        self.assertEqual(machine.slots(), (OLD_RESPONSE, OLD_FOLLOWUP))
        machine.run_at(pair.FIRST, pair.FINISH)
        self.assertEqual(machine.slots(), (OLD_RESPONSE, OLD_FOLLOWUP))
        followup_args = next(args for target, args in machine.service_inputs if target == FOLLOWUP_SERVICE)
        self.assertEqual(followup_args[:2], (NEW_DATA, USER_ID))
        self.assertEqual(machine.response_releases, [])
        hi, lo = machine.hi, machine.lo
        machine.run_at(pair.FINISH, identity.WORK_END)
        self.assertEqual(machine.slots(), (NEW_RESPONSE, NEW_FOLLOWUP))
        self.assertEqual(machine.response_releases, [OLD_RESPONSE, OLD_FOLLOWUP])
        self.assertEqual((machine.r[2], machine.r[3]), (0, 0))
        self.assertEqual(machine.r[16:24], saved)
        self.assertEqual((machine.r[29], machine.r[31]), (stack, identity.WORK_END))
        self.assertEqual((machine.hi, machine.lo), (hi, lo))
        self.assertEqual(machine.get(MUTEX + session.WRITER, 4), 1)
        machine.run_at(identity.WORK_END, identity.WORK_END + 8)
        self.assertEqual(machine.get(MUTEX + session.WRITER, 4), 0)

    def test_first_request_failure_preserves_old_pair_without_release(self):
        machine = self.machine(request_result=0)
        machine.seed_worker()
        machine.run_at(identity.WORK_BEGIN, identity.WORK_END)
        self.assertEqual((machine.r[2], machine.r[3]), (0xFFFFFFFE, 0))
        self.assertEqual(machine.slots(), (OLD_RESPONSE, OLD_FOLLOWUP))
        self.assertEqual(machine.response_releases, [])
        self.assertNotIn(FOLLOWUP_SERVICE, machine.worker_services)

    def test_first_complete_pair_publishes_into_empty_slots_without_release(self):
        machine = self.machine()
        machine.put(SESSION + 0x18, 0, 4)
        machine.put(SESSION + 0x1C, 0, 4)
        machine.seed_worker()
        machine.run_at(identity.WORK_BEGIN, identity.WORK_END)
        self.assertEqual((machine.r[2], machine.r[3]), (0, 0))
        self.assertEqual(machine.slots(), (NEW_RESPONSE, NEW_FOLLOWUP))
        self.assertEqual(machine.response_releases, [])

    def test_followup_failure_keeps_old_pair_and_releases_only_the_private_primary(self):
        machine = self.machine(followup_result=0)
        machine.seed_worker()
        machine.run_at(identity.WORK_BEGIN, identity.WORK_END)
        self.assertEqual((machine.r[2], machine.r[3]), (0xFFFFFFFE, 0))
        self.assertEqual(machine.slots(), (OLD_RESPONSE, OLD_FOLLOWUP))
        self.assertEqual(machine.response_releases, [NEW_RESPONSE])
        reader = machine.fork_cpu()
        reader.r[29] = STACK
        self.assertEqual(reader.stock(COPY_RESPONSE, COPY_OUTPUT), 0)
        self.assertEqual(bytes(reader.get(COPY_OUTPUT + n, 1) for n in range(len(COPY_TEXT))), COPY_TEXT)

    def test_ambiguous_aliases_reject_commit_without_guessing_release_authority(self):
        for candidate, followup, old_second in (
                (OLD_RESPONSE, NEW_FOLLOWUP, OLD_FOLLOWUP),
                (NEW_RESPONSE, OLD_FOLLOWUP, OLD_FOLLOWUP),
                (NEW_RESPONSE, NEW_RESPONSE, OLD_FOLLOWUP),
                (NEW_RESPONSE, NEW_FOLLOWUP, OLD_RESPONSE)):
            with self.subTest(candidate=candidate, followup=followup, old_second=old_second):
                machine = self.machine(request_result=candidate, followup_result=followup)
                machine.put(SESSION + 0x1C, old_second, 4)
                machine.seed_worker()
                machine.run_at(identity.WORK_BEGIN, identity.WORK_END)
                self.assertEqual((machine.r[2], machine.r[3]), (0xFFFFFFFE, 22))
                self.assertEqual(machine.slots(), (OLD_RESPONSE, old_second))
                self.assertEqual(machine.response_releases, [])
                self.assertEqual(machine.get(MUTEX + session.PHASE, 4), session.READY)

    def test_request_admission_rejects_a_wrong_generation_before_network_calls(self):
        machine = self.machine()
        machine.put(MUTEX + session.WRITER, 1, 4)
        saved = machine.r[16:24]
        machine.stock(pair.REQUEST, RESPONSE_DATA, COPY_OUTPUT, COPY_OUTPUT + 0x18, 2)
        self.assertEqual((machine.r[2], machine.r[3]), (0xFFFFFFFE, 116))
        self.assertEqual(machine.r[16:24], saved)
        self.assertEqual((machine.r[29], machine.r[31]), (STACK, RETURN))
        self.assertEqual(machine.worker_services, [])
        self.assertEqual(machine.slots(), (OLD_RESPONSE, OLD_FOLLOWUP))
        self.assertEqual(machine.response_releases, [])

    def test_raw_admission_errors_never_issue_a_network_request(self):
        for acquire, release in ((22, 0), (0, 1)):
            with self.subTest(acquire=acquire, release=release):
                machine = self.machine(acquire=acquire, release=release)
                machine.put(MUTEX + session.WRITER, 1, 4)
                machine.stock(pair.REQUEST, RESPONSE_DATA, COPY_OUTPUT, COPY_OUTPUT + 0x18, 1)
                self.assertEqual((machine.r[2], machine.r[3]), (0xFFFFFFFE, acquire or release))
                self.assertEqual(machine.get(MUTEX + session.PHASE, 4), session.FAILED)
                self.assertEqual(machine.worker_services, [])
                self.assertEqual(machine.response_releases, [])
                self.assertEqual(machine.slots(), (OLD_RESPONSE, OLD_FOLLOWUP))

    def test_raw_finish_errors_quarantine_without_release_after_possible_commit(self):
        for acquire, release in ((22, 0), (0, 1)):
            with self.subTest(acquire=acquire, release=release):
                machine = self.machine()
                machine.seed_worker()
                machine.run_at(identity.WORK_BEGIN, pair.FINISH)
                machine.acquire_result, machine.release_result = acquire, release
                machine.run_at(pair.FINISH, identity.WORK_END)
                self.assertEqual((machine.r[2], machine.r[3]), (0xFFFFFFFE, acquire or release))
                expected = (OLD_RESPONSE, OLD_FOLLOWUP) if acquire else (NEW_RESPONSE, NEW_FOLLOWUP)
                self.assertEqual(machine.slots(), expected)
                self.assertEqual(machine.response_releases, [])
                self.assertEqual(machine.get(MUTEX + session.PHASE, 4), session.FAILED)
                self.assertEqual(machine.get(MUTEX + session.WRITER, 4), 1)

    def test_changed_global_at_finish_preserves_slots_without_dereferencing_the_old_session(self):
        machine = self.machine()
        machine.seed_worker()
        machine.run_at(identity.WORK_BEGIN, pair.FINISH)
        machine.put(session.SESSION_SLOT, SESSION + 0x600, 4)
        machine.response_reads.clear()
        machine.run_at(pair.FINISH, identity.WORK_END)
        self.assertEqual((machine.r[2], machine.r[3]), (0xFFFFFFFE, 116))
        self.assertEqual(machine.response_reads, [])
        self.assertEqual(machine.response_releases, [])
        self.assertEqual(machine.slots(), (OLD_RESPONSE, OLD_FOLLOWUP))

    def test_release_callbacks_observe_the_complete_new_pair_and_busy_close(self):
        machine = self.machine()
        machine.seed_worker()
        observed = []

        def during_release(pointer):
            reader = machine.fork_cpu()
            reader.r[29] = STACK + 0x1000
            self.assertEqual(reader.stock(COPY_RESPONSE, COPY_OUTPUT), 0)
            self.assertEqual(bytes(reader.get(COPY_OUTPUT + n, 1) for n in range(3)), b'new')
            closer = machine.fork_cpu()
            closer.seed_native_frame()
            closer.run_at(session.CLOSE_SITES[0][0], RETURN)
            self.assertEqual((closer.r[2], closer.r[3]), (0xFFFFFFFF, 16))
            self.assertEqual(closer.teardown_events, [])
            observed.append((pointer, machine.slots(), machine.held))

        machine.on_response_release = during_release
        machine.run_at(identity.WORK_BEGIN, identity.WORK_END)
        self.assertEqual(observed, [(OLD_RESPONSE, (NEW_RESPONSE, NEW_FOLLOWUP), False),
                                    (OLD_FOLLOWUP, (NEW_RESPONSE, NEW_FOLLOWUP), False)])

    def test_pair_commit_waits_for_an_active_native_reader_before_reclamation(self):
        machine = self.machine()
        machine.seed_worker()
        machine.run_at(identity.WORK_BEGIN, pair.FINISH)
        reader = machine.fork_cpu()
        reader.r[29] = STACK + 0x1000
        entered, release_reader, requested = threading.Event(), threading.Event(), threading.Event()
        failures = []

        def hold_string():
            entered.set()
            if not release_reader.wait(3):
                raise AssertionError('reader was not released')

        def capture(operation):
            try:
                operation()
            except BaseException as error:
                failures.append(error)

        reader.on_string, machine.on_acquire = hold_string, requested.set
        reading = threading.Thread(target=capture, args=(lambda: reader.stock(COPY_RESPONSE, COPY_OUTPUT),))
        commit = threading.Thread(target=capture, args=(lambda: machine.run_at(pair.FINISH, identity.WORK_END),))
        reading.start()
        try:
            self.assertTrue(entered.wait(2))
            commit.start()
            self.assertTrue(requested.wait(2))
            self.assertEqual(machine.slots(), (OLD_RESPONSE, OLD_FOLLOWUP))
            self.assertEqual(machine.response_releases, [])
        finally:
            release_reader.set()
            reading.join(4)
            if commit.ident is not None:
                commit.join(4)
        self.assertFalse(reading.is_alive() or commit.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(bytes(reader.get(COPY_OUTPUT + n, 1) for n in range(len(COPY_TEXT))), COPY_TEXT)
        self.assertEqual(machine.slots(), (NEW_RESPONSE, NEW_FOLLOWUP))
        self.assertEqual(machine.response_releases, [OLD_RESPONSE, OLD_FOLLOWUP])

    def test_fault_observed_after_first_release_suppresses_the_remaining_callback(self):
        machine = self.machine()
        machine.seed_worker()

        def fault_after_first(pointer):
            if pointer == OLD_RESPONSE:
                machine.put(MUTEX + session.INIT_ERROR, 22, 4)
                machine.put(MUTEX + session.PHASE, session.FAILED, 4)

        machine.on_response_release = fault_after_first
        machine.run_at(identity.WORK_BEGIN, identity.WORK_END)
        self.assertEqual((machine.r[2], machine.r[3]), (0xFFFFFFFE, 22))
        self.assertEqual(machine.slots(), (NEW_RESPONSE, NEW_FOLLOWUP))
        self.assertEqual(machine.response_releases, [OLD_RESPONSE])
        self.assertEqual(machine.get(MUTEX + session.WRITER, 4), 1)


if __name__ == '__main__':
    unittest.main()
