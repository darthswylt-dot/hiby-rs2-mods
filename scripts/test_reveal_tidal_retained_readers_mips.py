#!/usr/bin/env python3
"""Execute retained native readers across synchronous service borrow spans."""

import unittest

import factory_null_audit as audit
import reveal_tidal_retained_readers_mips as retained
import reveal_tidal_response_cleanup_mips as cleanup
import reveal_tidal_request_identity_mips as identity
import reveal_tidal_response_reader_bridge_mips as session
from test_factory_d180_tidal_response_lifecycle import (
    COPY_OUTPUT, NEW_FOLLOWUP, NEW_RESPONSE, OLD_FOLLOWUP, OLD_RESPONSE,
    RESPONSE_DATA, SESSION, STRING_SIZE, USER_ID,
)
from test_factory_null_audit import COPY, NullCallerMachine, RETURN, STACK
from test_reveal_tidal_response_pair_mips import PairMachine
from test_reveal_tidal_response_reader_bridge_mips import CODE_BASE, MUTEX


APP, LIST, RESULT = 0x1D0A000, 0x1D0D000, 0x1D0E000
RESULT_TEXT, FOLLOW_TEXT = RESULT + 0x100, RESULT + 0x140
PAGES, CALLBACK, PAIR_COPY, USER = (row[1] for row in retained.READERS)
PAGE_SERVICE, PAIR_SERVICE = 0x8C0B80, 0x8BE50C
SERVICES = (PAGE_SERVICE, PAIR_SERVICE, *retained.CALLBACKS)


class RetainedMachine(PairMachine):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.map(APP, 0x2000)
        self.map(LIST, 0x400)
        self.map(RESULT, 0x200)
        self.map(OLD_FOLLOWUP, 0x28)
        self.put(APP + 0xBD8, LIST, 4)
        self.put(APP + 0xA64, 3, 4)
        self.put(LIST + 0x2A4, 0, 4)
        self.put(OLD_RESPONSE + 4, USER_ID, 4)
        self.put(OLD_FOLLOWUP + 0x14, FOLLOW_TEXT, 4)
        self.bytes(FOLLOW_TEXT, b'L\0')
        self.put(RESULT + 4, RESULT_TEXT, 4)
        self.put(RESULT + 0xC, 1, 4)
        self.put(RESULT + 0x18, RESULT_TEXT, 4)
        self.bytes(RESULT_TEXT, b'copied result\0')
        self.reader_services = []
        self.on_reader_service = None

    def arguments(self, site):
        return {PAGES: (APP, 7, LIST, COPY_OUTPUT),
                CALLBACK: (APP, retained.CALLBACKS[0], COPY_OUTPUT),
                PAIR_COPY: (APP, COPY_OUTPUT), USER: ()}[site]

    def plain(self, word):
        op, rs, rt, offset = word >> 26, word >> 21 & 31, word >> 16 & 31, word & 0xFFFF
        if op not in (0x24, 0x29):
            return super().plain(word)
        self.executing_pc = self.fetch_pc
        offset -= 0x10000 if offset & 0x8000 else 0
        address = (self.r[rs] + offset) & 0xFFFFFFFF
        if op == 0x24:  # Native LBU of the follow-up format string.
            self.r[rt] = self.get(address, 1)
        else:  # Native SH of the selected result mode at application+A60.
            self.put(address, self.r[rt], 2)
        self.r[0] = 0

    def external(self, target):
        if target in SERVICES:
            if self.held or not self.get(MUTEX + session.BORROWS, 4):
                raise AssertionError('service must run in an admitted span outside the mutex')
            self.reader_services.append((target, tuple(self.r[4:8])))
            if self.on_reader_service is not None:
                self.on_reader_service(target)
            self.calls.append(target)
            self.hostile_result(RESULT)
        elif target == STRING_SIZE:
            if self.held:
                super().external(target)
                return
            if not self.get(MUTEX + session.BORROWS, 4):
                raise AssertionError('unretained native string query')
            self.calls.append(target)
            self.hostile_result(len(b'copied result') if self.r[4] == RESULT_TEXT else 0)
        elif target == COPY and not self.held:
            if not self.get(MUTEX + session.BORROWS, 4):
                raise AssertionError('unretained native copy')
            NullCallerMachine.external(self, target)
        elif target == 0x46FCE0:
            self.calls.append(target)
            self.hostile_result(0)
        else:
            super().external(target)


class NativeTidalRetainedReaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = audit.source_image()
        cls.code, cls.patches = retained.assemble(MUTEX, CODE_BASE)

    def machine(self, **options):
        return RetainedMachine(self.image, self.code, self.patches, **options)

    def test_all_twenty_one_redirects_pin_the_native_entry_pairs(self):
        self.assertEqual(len(self.patches), 21)
        for _, site, original, _ in retained.READERS:
            self.assertEqual(original, (self.image.word(site), self.image.word(site + 4)))
            self.assertEqual(self.patches[site][0], original)

    def test_complete_native_bodies_return_owned_results_copies_or_a_scalar(self):
        for _, site, _, _ in retained.READERS:
            with self.subTest(site=hex(site)):
                machine = self.machine()
                saved = machine.r[16:24]
                expected = {PAGES: RESULT, CALLBACK: RESULT, PAIR_COPY: 0, USER: USER_ID}[site]
                self.assertEqual(machine.stock(site, *machine.arguments(site)), expected)
                self.assertEqual(machine.r[16:24], saved)
                self.assertEqual((machine.r[3], machine.r[29], machine.r[31]), (0, STACK, RETURN))
                self.assertEqual(machine.get(MUTEX + session.BORROWS, 4), 0)
                self.assertFalse(machine.held)
                self.assertEqual(machine.mutex_events, [(session.LOCK, MUTEX, 0),
                                                       (session.UNLOCK, MUTEX, 0)] * 2)
                if site == PAIR_COPY:
                    self.assertEqual(bytes(machine.get(COPY_OUTPUT + n, 1) for n in range(14)),
                                     b'copied result\0')
                    self.assertEqual(machine.response_releases, [RESULT])
                elif site != USER:
                    self.assertEqual(machine.response_releases, [])
                    self.assertEqual(machine.get(RESULT + 4, 4), RESULT_TEXT)

    def test_both_identified_callbacks_are_allowed_but_unknown_callback_is_rejected(self):
        for callback in (*retained.CALLBACKS, 0xDEAD1230):
            with self.subTest(callback=hex(callback)):
                machine = self.machine()
                result = machine.stock(CALLBACK, APP, callback, COPY_OUTPUT)
                if callback in retained.CALLBACKS:
                    self.assertEqual(result, RESULT)
                    self.assertEqual(machine.reader_services[0][0], callback)
                else:
                    self.assertEqual((result, machine.r[3]), (0, 22))
                    self.assertEqual(machine.reader_services, [])
                    self.assertEqual(machine.mutex_events, [])
                self.assertEqual(machine.get(MUTEX + session.BORROWS, 4), 0)

    def test_null_pair_copy_arguments_reject_before_native_nonreturning_assertions(self):
        for arguments in ((0, COPY_OUTPUT), (APP, 0)):
            with self.subTest(arguments=arguments):
                machine = self.machine()
                self.assertEqual(machine.stock(PAIR_COPY, *arguments), 0xFFFFFFFF)
                self.assertEqual(machine.r[3], 22)
                self.assertEqual(machine.mutex_events, [])
                self.assertEqual(machine.reader_services, [])
                self.assertEqual(machine.get(MUTEX + session.BORROWS, 4), 0)

    def test_empty_native_response_returns_without_a_service_and_releases_the_count(self):
        for _, site, _, failure in retained.READERS:
            with self.subTest(site=hex(site)):
                machine = self.machine()
                machine.put(SESSION + 0x18, 0, 4)
                self.assertEqual(machine.stock(site, *machine.arguments(site)), failure & 0xFFFFFFFF)
                self.assertEqual(machine.r[3], 0)
                self.assertEqual(machine.get(MUTEX + session.BORROWS, 4), 0)
                self.assertEqual(machine.reader_services, [])

    def test_callbacks_can_nest_a_second_reader_without_holding_the_mutex(self):
        machine = self.machine()
        observed = []

        def nested_reader(_):
            observed.append(machine.get(MUTEX + session.BORROWS, 4))
            nested = machine.fork_cpu()
            nested.r[29] = STACK + 0x4000
            nested_counts = []
            nested.on_acquire = lambda: nested_counts.append(nested.get(MUTEX + session.BORROWS, 4))
            self.assertEqual(nested.stock(USER), USER_ID)
            self.assertEqual(nested_counts, [1, 2])
            observed.append(machine.get(MUTEX + session.BORROWS, 4))

        machine.on_reader_service = nested_reader
        self.assertEqual(machine.stock(CALLBACK, *machine.arguments(CALLBACK)), RESULT)
        self.assertEqual(observed, [1, 1])
        self.assertEqual(machine.get(MUTEX + session.BORROWS, 4), 0)

    def test_close_and_cleanup_refuse_reclamation_through_the_last_service_use(self):
        for close, _, _ in session.CLOSE_SITES:
            with self.subTest(close=hex(close)):
                machine = self.machine()
                observations = []

                def try_reclamation(_):
                    closer = machine.fork_cpu()
                    closer.seed_native_frame()
                    closer.run_at(close, RETURN)
                    self.assertEqual((closer.r[2], closer.r[3]), (0xFFFFFFFF, 16))
                    self.assertEqual(closer.teardown_events, [])
                    disposer = machine.fork_cpu()
                    disposer.r[29] = STACK + 0x4000
                    self.assertEqual(disposer.stock(cleanup.ENTRY), 0xFFFFFFFF)
                    self.assertEqual(disposer.r[3], 16)
                    self.assertEqual(disposer.response_releases, [])
                    observations.append(machine.slots())

                machine.on_reader_service = try_reclamation
                self.assertEqual(machine.stock(CALLBACK, *machine.arguments(CALLBACK)), RESULT)
                self.assertEqual(observations, [(OLD_RESPONSE, OLD_FOLLOWUP)])
                self.assertEqual(machine.get(MUTEX + session.BORROWS, 4), 0)

    def test_new_pair_cannot_replace_the_pair_during_a_retained_service_call(self):
        machine = self.machine()
        machine.r[29] = STACK + 0x4000
        observed = []

        def prepare_during_read(_):
            writer = machine.fork_cpu()
            writer.on_reader_service = None
            writer.seed_worker()
            writer.run_at(identity.WORK_BEGIN, identity.WORK_END)
            self.assertEqual((writer.r[2], writer.r[3]), (0xFFFFFFFE, 16))
            self.assertEqual(writer.response_releases, [NEW_RESPONSE, NEW_FOLLOWUP])
            writer.run_at(identity.WORK_END, identity.WORK_END + 8)
            observed.append((machine.slots(), machine.get(MUTEX + session.WRITER, 4)))

        machine.on_reader_service = prepare_during_read
        self.assertEqual(machine.stock(CALLBACK, *machine.arguments(CALLBACK)), RESULT)
        self.assertEqual(observed, [((OLD_RESPONSE, OLD_FOLLOWUP), 0)])
        self.assertEqual(machine.get(MUTEX + session.BORROWS, 4), 0)

    def test_unready_closing_or_cleanup_owned_state_never_enters_the_native_body(self):
        for kind, expected in (('unready', 11), ('closing', 116), ('cleanup', 16), ('global', 116)):
            with self.subTest(kind=kind):
                machine = self.machine()
                if kind == 'unready':
                    machine.put(MUTEX + session.PHASE, session.NEW, 4)
                elif kind == 'closing':
                    machine.put(MUTEX + session.LIFECYCLE, session.CLOSING, 4)
                elif kind == 'cleanup':
                    machine.put(MUTEX + session.WRITER, cleanup.OWNER_BIT | 1, 4)
                else:
                    machine.put(session.SESSION_SLOT, SESSION + 0x600, 4)
                self.assertEqual(machine.stock(CALLBACK, *machine.arguments(CALLBACK)), 0)
                self.assertEqual(machine.r[3], expected)
                self.assertEqual(machine.reader_services, [])
                self.assertEqual(machine.get(MUTEX + session.BORROWS, 4), 0)

    def test_counter_exhaustion_refuses_admission_without_wrapping(self):
        machine = self.machine()
        machine.put(MUTEX + session.BORROWS, retained.MAX_BORROWS, 4)
        self.assertEqual(machine.stock(USER), 0)
        self.assertEqual(machine.r[3], 75)
        self.assertEqual(machine.get(MUTEX + session.BORROWS, 4), retained.MAX_BORROWS)

    def test_raw_admission_errors_skip_native_effects_and_quarantine_actual_count(self):
        for acquire, release in ((22, 0), (0, 1)):
            with self.subTest(acquire=acquire, release=release):
                machine = self.machine(acquire=acquire, release=release)
                saved = machine.r.copy()
                arguments = machine.arguments(CALLBACK)
                saved[4:7] = arguments
                self.assertEqual(machine.stock(CALLBACK, *arguments), 0)
                self.assertEqual(machine.r[3], acquire or release)
                self.assertEqual(machine.r[4:], saved[4:])
                self.assertEqual(machine.get(MUTEX + session.PHASE, 4), session.FAILED)
                self.assertEqual(machine.get(MUTEX + session.BORROWS, 4), 0 if acquire else 1)
                self.assertEqual(machine.reader_services, [])
                expected = [(session.LOCK, MUTEX, acquire)]
                if not acquire:
                    expected.append((session.UNLOCK, MUTEX, release))
                self.assertEqual(machine.mutex_events, expected)

    def test_raw_unpin_errors_preserve_native_effects_without_guessing_rollback(self):
        for acquire, release in ((22, 0), (0, 1)):
            with self.subTest(acquire=acquire, release=release):
                machine = self.machine()

                def fail_unpin(_):
                    machine.acquire_result, machine.release_result = acquire, release

                machine.on_reader_service = fail_unpin
                self.assertEqual(machine.stock(CALLBACK, *machine.arguments(CALLBACK)), 0)
                self.assertEqual(machine.r[3], acquire or release)
                self.assertEqual(machine.get(LIST + 0x2A4, 4), 999)
                self.assertEqual(machine.get(MUTEX + session.BORROWS, 4), 1 if acquire else 0)
                self.assertEqual(machine.get(MUTEX + session.PHASE, 4), session.FAILED)
                self.assertEqual((machine.r[29], machine.r[31]), (STACK, RETURN))
                self.assertEqual(machine.get(RESULT + 4, 4), RESULT_TEXT)

    def test_post_body_identity_mismatch_never_decrements_an_unmatched_generation(self):
        machine = self.machine()
        machine.on_reader_service = lambda _: machine.put(MUTEX + session.GENERATION, 2, 4)
        self.assertEqual(machine.stock(CALLBACK, *machine.arguments(CALLBACK)), 0)
        self.assertEqual(machine.r[3], 116)
        self.assertEqual(machine.get(MUTEX + session.BORROWS, 4), 1)
        self.assertEqual(machine.get(MUTEX + session.PHASE, 4), session.READY)


if __name__ == '__main__':
    unittest.main()
