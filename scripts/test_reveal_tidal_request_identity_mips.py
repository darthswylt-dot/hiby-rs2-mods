#!/usr/bin/env python3
"""Execute local generation transport and worker pins with native continuations."""

import unittest

import factory_null_audit as audit
import reveal_tidal_request_identity_mips as identity
import reveal_tidal_response_reader_bridge_mips as session
from test_factory_d180_qr_continuation import MESSAGE, QUEUE, QUEUE_SLOT, READ_WORKER_INPUT, STATUS
from test_factory_d180_tidal_response_lifecycle import REQUEST_SERVICE, FOLLOWUP_SERVICE, SESSION
from test_factory_null_audit import CONTEXT, RETURN, STACK
from test_reveal_tidal_response_reader_bridge_mips import CODE_BASE, MUTEX, ReaderBridgeMachine


class IdentityMachine(ReaderBridgeMachine):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.worker_services = []
        self.notifications = []
        self.on_release = None

    def word(self, pc):
        if pc == identity.NOTIFY:
            self.external(pc)
            self.fetch_pc = pc
            return 0x03E00008
        if pc == identity.NOTIFY + 4:
            self.fetch_pc = pc
            return 0
        return super().word(pc)

    def external(self, target):
        if target == identity.NOTIFY:
            if self.held:
                raise AssertionError('worker notification ran under the session mutex')
            self.notifications.append(tuple(self.r[4:6]))
        if target in (READ_WORKER_INPUT, REQUEST_SERVICE, FOLLOWUP_SERVICE):
            if self.held:
                raise AssertionError('input/network service ran under the session mutex')
            self.worker_services.append(target)
        super().external(target)
        if target == session.UNLOCK and self.release_result == 0 and getattr(self, 'on_release', None):
            self.on_release()

    def seed_worker(self, generation=1):
        self.r[29] = STACK - 0x868
        self.r[16], self.r[19], self.r[23] = QUEUE_SLOT, 0x920000, 0x9273A0
        self.r[20] = 0x9276B0
        self.map(0x9276B0, 32)
        for index in range(8):
            self.put(0x9276B0 + index * 4, self.elf.word(0x9276B0 + index * 4), 4)
        self.r[21], self.r[18] = self.r[29] + 0x418, self.r[29] + 0x18
        self.put(self.r[29] + 0x820, 0, 4)
        self.put(self.r[29] + 0x824, generation, 4)
        self.put(self.r[29] + 0x830, 200, 4)
        self.r[30] = QUEUE_SLOT + 0x18
        self.put(STATUS, 0x11223344, 4)


class NativeTidalRequestIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = audit.source_image()
        cls.code, cls.patches = identity.assemble(MUTEX, CODE_BASE)

    def machine(self, **options):
        return IdentityMachine(self.image, self.code, self.patches, **options)

    def assert_preserved(self, machine, before, hi, lo, *, changed=()):
        self.assertEqual((machine.hi, machine.lo), (hi, lo))
        for register in range(32):
            if register not in changed:
                self.assertEqual(machine.r[register], before[register], f'r{register}')

    def test_all_redirects_pin_the_native_source_pairs(self):
        self.assertEqual(len(self.patches), 11)
        for site, original in identity.HOOKS:
            self.assertEqual(original, (self.image.word(site), self.image.word(site + 4)))
            self.assertEqual(self.patches[site][0], original)
        self.assertEqual(self.image.word(identity.WORK_BEGIN + 8), identity.BEGIN_DELAY)

    def test_command_zero_stamps_generation_before_native_post_frame(self):
        machine = self.machine()
        machine.r[4:6] = [0, 0]
        before, hi, lo = machine.r.copy(), machine.hi, machine.lo
        machine.run_at(identity.POST, identity.POST + 8)
        self.assert_preserved(machine, before, hi, lo, changed=(2, 5, 29))
        self.assertEqual((machine.r[2], machine.r[5], machine.r[29]), (0xB90000, 1, STACK - 40))
        self.assertEqual(machine.mutex_events, [(session.LOCK, MUTEX, 0), (session.UNLOCK, MUTEX, 0)])
        self.assertFalse(machine.held)

    def test_generation_roundtrips_through_native_post_queue_copy_and_release(self):
        machine = self.machine()
        self.assertEqual(machine.stock(identity.POST, 0, 0), 0)
        self.assertEqual(machine.get(MESSAGE - 4, 4), 8)
        self.assertEqual((machine.get(MESSAGE, 4), machine.get(MESSAGE + 4, 4)), (0, 1))
        self.assertEqual(machine.get(QUEUE + 0x10, 4), MESSAGE)
        output = CONTEXT + 0x180
        self.assertEqual(machine.stock(0x450600, QUEUE, output, 8), 0)
        self.assertEqual((machine.get(output, 4), machine.get(output + 4, 4)), (0, 1))
        self.assertEqual(machine.get(QUEUE + 0x10, 4), 0)
        self.assertEqual(machine.releases, [MESSAGE])
        self.assertEqual(machine.raw_releases, [MESSAGE - 4])
        self.assertEqual(machine.get(MUTEX + session.WRITER, 4), 0)

    def test_other_commands_replay_the_native_entry_even_when_unavailable(self):
        for command in (1, 3, 7):
            with self.subTest(command=command):
                machine = self.machine(initialize=False)
                machine.r[4:6] = [command, 0x12345678]
                before, hi, lo = machine.r.copy(), machine.hi, machine.lo
                machine.run_at(identity.POST, identity.POST + 8)
                self.assert_preserved(machine, before, hi, lo, changed=(2, 29))
                self.assertEqual((machine.r[2], machine.r[5], machine.r[29]),
                                 (0xB90000, 0x12345678, STACK - 40))
                self.assertEqual(machine.mutex_events, [])

    def test_post_rejects_unready_or_closing_sessions_without_native_effect(self):
        for phase, life, error in ((session.NEW, session.EMPTY, 11),
                                   (session.READY, session.CLOSING, 116)):
            with self.subTest(phase=phase, life=life):
                machine = self.machine()
                machine.put(MUTEX + session.PHASE, phase, 4)
                machine.put(MUTEX + session.LIFECYCLE, life, 4)
                machine.r[4:6] = [0, 0x12345678]
                before, hi, lo = machine.r.copy(), machine.hi, machine.lo
                machine.run_at(identity.POST, RETURN)
                self.assert_preserved(machine, before, hi, lo, changed=(2, 3))
                self.assertEqual((machine.r[2], machine.r[3]), (0xFFFFFFFF, error))

    def test_worker_entry_preserves_native_call_arguments_and_bypasses_other_commands(self):
        for command in (0, 3):
            with self.subTest(command=command):
                machine = self.machine()
                machine.seed_worker()
                machine.put(machine.r[29] + identity.QUEUED_COMMAND, command, 4)
                if command:
                    machine.put(MUTEX + session.PHASE, session.FAILED, 4)
                before, hi, lo = machine.r.copy(), machine.hi, machine.lo
                machine.run_at(identity.WORK_BEGIN, identity.NOTIFY)
                self.assert_preserved(machine, before, hi, lo, changed=(4, 5, 31))
                self.assertEqual((machine.r[4], machine.r[5], machine.r[31]),
                                 (20, 1, identity.BEGIN_RESUME))
                self.assertEqual(machine.get(MUTEX + session.WRITER, 4), 0 if command else 1)
                if command:
                    self.assertEqual(machine.mutex_events, [])
                self.assertFalse(machine.held)

    def test_native_input_and_network_run_between_pin_and_matching_release(self):
        machine = self.machine()
        machine.seed_worker()
        machine.run_at(identity.WORK_BEGIN, identity.WORK_END)
        self.assertEqual(machine.get(MUTEX + session.WRITER, 4), 1)
        self.assertEqual(machine.worker_services, [READ_WORKER_INPUT, REQUEST_SERVICE, FOLLOWUP_SERVICE])
        self.assertEqual(machine.notifications, [(20, 1)])
        self.assertFalse(machine.held)
        before, hi, lo = machine.r.copy(), machine.hi, machine.lo
        result = before[2]
        machine.run_at(identity.WORK_END, identity.WORK_END + 8)
        self.assert_preserved(machine, before, hi, lo, changed=(4,))
        self.assertEqual(machine.get(MUTEX + session.WRITER, 4), 0)
        self.assertEqual(machine.r[4], 200)
        self.assertEqual(machine.get(STATUS, 4), result)

    def test_stale_queued_generation_skips_input_and_preserves_new_shared_status(self):
        for token in (0, 2, 0xFFFFFFFF):
            with self.subTest(token=token):
                machine = self.machine()
                machine.seed_worker(token)
                before, hi, lo = machine.r.copy(), machine.hi, machine.lo
                machine.run_at(identity.WORK_BEGIN, identity.WORK_SKIP)
                self.assert_preserved(machine, before, hi, lo)
                self.assertEqual(machine.worker_services, [])
                self.assertEqual(machine.notifications, [])
                self.assertEqual(machine.get(MUTEX + session.WRITER, 4), 0)
                self.assertEqual(machine.get(STATUS, 4), 0x11223344)

    def test_reader_binding_mismatch_and_duplicate_worker_entry_do_not_start_request(self):
        for offset, value in ((session.BOUND_SESSION, SESSION + 4), (session.WRITER, 1)):
            with self.subTest(offset=offset):
                machine = self.machine()
                machine.seed_worker()
                machine.put(MUTEX + offset, value, 4)
                machine.run_at(identity.WORK_BEGIN, identity.WORK_SKIP)
                self.assertEqual(machine.worker_services, [])
                self.assertEqual(machine.get(STATUS, 4), 0x11223344)
                self.assertEqual(machine.get(MUTEX + offset, 4), value)

    def test_close_refuses_busy_writer_and_can_retry_after_worker_completion(self):
        for close, _, _ in session.CLOSE_SITES:
            with self.subTest(close=hex(close)):
                machine = self.machine()
                machine.seed_worker()
                machine.run_at(identity.WORK_BEGIN, identity.BEGIN_RESUME)
                closer = machine.fork_cpu()
                closer.seed_native_frame()
                closer.run_at(close, RETURN)
                self.assertEqual((closer.r[2], closer.r[3]), (0xFFFFFFFF, 16))
                self.assertEqual(closer.teardown_events, [])
                self.assertEqual(machine.get(MUTEX + session.LIFECYCLE, 4), session.LIVE)
                self.assertEqual(machine.get(session.SESSION_SLOT, 4), SESSION)
                machine.r[2] = 0xFFFFFFFE
                machine.run_at(identity.WORK_END, identity.WORK_END + 8)
                self.assertEqual(machine.get(STATUS, 4), 0xFFFFFFFE)
                closer.seed_native_frame()
                closer.run_at(close, RETURN)
                self.assertEqual(closer.releases, [SESSION])
                self.assertEqual(machine.get(session.SESSION_SLOT, 4), 0)

    def test_mismatched_end_never_clears_another_pin_or_publishes_the_result(self):
        for token, writer in ((0, 1), (2, 1), (1, 2), (1, 0)):
            with self.subTest(token=token, writer=writer):
                machine = self.machine()
                machine.seed_worker(token)
                machine.put(MUTEX + session.WRITER, writer, 4)
                machine.r[2] = 0xFFFFFFFE
                before, hi, lo = machine.r.copy(), machine.hi, machine.lo
                machine.run_at(identity.WORK_END, identity.WORK_SKIP)
                self.assert_preserved(machine, before, hi, lo)
                self.assertEqual(machine.get(MUTEX + session.WRITER, 4), writer)
                self.assertEqual(machine.get(STATUS, 4), 0x11223344)

    def test_end_commits_result_before_unlock_allows_close_and_rebind(self):
        machine = self.machine()
        machine.seed_worker()
        machine.run_at(identity.WORK_BEGIN, identity.BEGIN_RESUME)
        closer = machine.fork_cpu()
        closer.seed_native_frame()
        observed = []

        def rebind_after_unlock():
            machine.on_release = None
            observed.append((machine.get(STATUS, 4), machine.get(MUTEX + session.WRITER, 4),
                             machine.get(MUTEX + session.LIFECYCLE, 4)))
            closer.run_at(session.CLOSE_SITES[0][0], RETURN)
            closer.seed_native_frame(top=STACK + 0x2400)
            closer.run_at(session.INIT_SITE, session.INIT_SITE + 8)
            site = session.PUBLISH_SITES[0][0]
            closer.run_at(site, site + 8)
            machine.put(STATUS, 0x55667788, 4)

        machine.r[2] = 0xFFFFFFFE
        machine.on_release = rebind_after_unlock
        machine.run_at(identity.WORK_END, identity.WORK_END + 8)
        self.assertEqual(observed, [(0xFFFFFFFE, 0, session.LIVE)])
        self.assertEqual(machine.get(MUTEX + session.GENERATION, 4), 2)
        self.assertEqual(machine.get(STATUS, 4), 0x55667788)
        self.assertEqual(machine.r[2], 0xFFFFFFFE)

    def test_raw_errors_quarantine_without_guessed_unlock_or_worker_continuation(self):
        for site in (identity.POST, identity.WORK_BEGIN, identity.WORK_END):
            for acquire, release in ((22, 0), (0, 1)):
                with self.subTest(site=hex(site), acquire=acquire, release=release):
                    machine = self.machine(acquire=acquire, release=release)
                    if site == identity.POST:
                        machine.r[4:6] = [0, 0x12345678]
                    else:
                        machine.seed_worker()
                        if site == identity.WORK_END:
                            machine.put(MUTEX + session.WRITER, 1, 4)
                            machine.r[2] = 0xFFFFFFFE
                    before, hi, lo = machine.r.copy(), machine.hi, machine.lo
                    machine.run_at(site, RETURN if site == identity.POST else identity.WORK_SKIP)
                    changed = (2, 3) if site == identity.POST else ()
                    self.assert_preserved(machine, before, hi, lo, changed=changed)
                    if site == identity.POST:
                        self.assertEqual((machine.r[2], machine.r[3]), (0xFFFFFFFF, acquire or release))
                    else:
                        expected_result = 0xFFFFFFFE if site == identity.WORK_END and release else 0x11223344
                        self.assertEqual(machine.get(STATUS, 4), expected_result)
                    self.assertEqual(machine.get(MUTEX + session.PHASE, 4), session.FAILED)
                    self.assertEqual(machine.get(MUTEX + session.INIT_ERROR, 4), acquire or release)
                    expected = [(session.LOCK, MUTEX, acquire)]
                    if not acquire:
                        expected.append((session.UNLOCK, MUTEX, release))
                    self.assertEqual(machine.mutex_events, expected)
                    self.assertEqual(machine.worker_services, [])
                    self.assertEqual(machine.notifications, [])
                    calls = machine.mutex_events.copy()
                    machine.run_at(identity.WORK_BEGIN, identity.WORK_SKIP)
                    self.assertEqual(machine.mutex_events, calls)


if __name__ == '__main__':
    unittest.main()
