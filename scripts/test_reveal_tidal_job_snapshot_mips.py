#!/usr/bin/env python3
"""Exercise independent native job locking and the compound reader under it."""

import threading
import unittest

import factory_null_audit as audit
import reveal_tidal_job_snapshot_mips as job
import reveal_tidal_request_identity_mips as identity
import reveal_tidal_response_reader_bridge_mips as session
from test_factory_d180_tidal_response_lifecycle import (
    NEW_FOLLOWUP, NEW_RESPONSE, OLD_RESPONSE, RESPONSE_DATA, SESSION,
)
from test_factory_null_audit import RETURN, STACK
from test_reveal_tidal_compound_snapshot_mips import (
    AUTHENTICATED_API, CompoundMachine, OLD_ID, OLD_TEXT,
)
from test_reveal_tidal_response_reader_bridge_mips import CODE_BASE, MUTEX


TOP, JOB, CONTROLLER, JOB_MUTEX = STACK + 0x2000, 0x1D0A000, 0x1D0B000, 0x1D0C000
INDEX_VALUE, COMPARE, PROPERTY, NOTIFY = 7, 0x41FEC0, 0x42AD60, 0x47D0A0


class JobMachine(CompoundMachine):
    def __init__(self, *args, job_acquire=0, job_release=0, **kwargs):
        self.job_acquire, self.job_release = job_acquire, job_release
        self.job_held = False
        self.job_mutex = threading.Lock()
        self.job_events, self.job_callbacks, self.job_notifies, self.compares = [], [], [], []
        self.on_cleanup = None
        super().__init__(*args, **kwargs)
        self.map(JOB, 0x20)
        self.map(CONTROLLER, 0x80)
        self.put(JOB + 0xC, JOB_MUTEX, 4)
        self.put(JOB + 4, 1, 4)
        self.put(JOB + 8, 91, 4)
        self.put(CONTROLLER + 0x58, JOB, 4)

    def seed_job(self):
        frame = TOP - job.NATIVE_FRAME
        self.r[29], self.r[31] = frame, RETURN
        for index in range(7):
            self.put(frame + 0xFC0 + index * 4, 0x55000000 + index, 4)
        self.put(frame + 0xFDC, RETURN, 4)
        self.put(frame + job.SAVED_INDEX, INDEX_VALUE, 4)
        self.put(frame + job.RECEIPT, 0xBAD00000, 4)
        self.r[16:22] = [JOB, CONTROLLER, 7, 17, frame + job.BUFFER, 31]
        self.r[4] = JOB_MUTEX
        self.bytes(frame + job.BUFFER, bytes(job.CAPACITY))
        self.put(frame + job.BUFFER - 4, 0xAABBCCDD, 4)
        self.put(frame + job.BUFFER + job.CAPACITY, 0x12345678, 4)
        return frame

    def acquire_job(self):
        frame = self.seed_job()
        self.run_at(job.ACQUIRE, job.ACQUIRE + 8)
        return frame

    def external(self, target):
        if target in (session.LOCK, session.UNLOCK) and self.r[4] != MUTEX:
            pointer = self.r[4]
            if pointer != JOB_MUTEX:
                raise AssertionError('attempted unlock/acquire of an uncaptured job mutex')
            result = self.job_acquire if target == session.LOCK else self.job_release
            self.job_events.append((target, pointer, result))
            self.calls.append(target)
            if target == session.LOCK and result == 0:
                if not self.job_mutex.acquire(timeout=3):
                    raise AssertionError('job mutex acquired twice')
                self.job_held = True
            elif target == session.UNLOCK:
                if not self.job_held:
                    raise AssertionError('unlock without a successful job acquire')
                if result == 0:
                    self.job_held = False
                    self.job_mutex.release()
            self.hostile_result(result)
        elif target in (job.COMPLETE_INDEX, job.CLEAR_PENDING):
            if not self.job_held or self.held:
                raise AssertionError('native cleanup must hold only the job mutex')
            arguments = tuple(self.r[4:6])
            self.job_callbacks.append((target, arguments, self.get(MUTEX + session.PHASE, 4)))
            self.calls.append(target)
            if self.on_cleanup is not None:
                self.on_cleanup(target)
            self.hostile_result(0)
        elif target == NOTIFY:
            if self.job_held or self.held:
                raise AssertionError('native notification before releasing both mutexes')
            self.job_notifies.append(tuple(self.r[4:6]))
            self.calls.append(target)
            self.hostile_result(0)
        elif target == COMPARE:
            if self.held or not self.job_held:
                raise AssertionError('native comparison must retain only the job lock')
            self.compares.append((tuple(self.r[4:6]), self.r[21]))
            self.calls.append(target)
            self.hostile_result(1)
        elif target == PROPERTY:
            if self.held or not self.job_held:
                raise AssertionError('native property query must retain only the job lock')
            prop, destination = self.r[4:6]
            if prop == 11:
                self.put(destination, INDEX_VALUE, 4)
            elif prop in (21, 24, 27):
                self.bytes(destination, b'fixture\0')
            else:
                raise AssertionError('unbounded native property query')
            self.calls.append(target)
            self.hostile_result(0)
        elif target in (0x4ACFC0, 0x4ACEC0):
            if not self.job_held:
                raise AssertionError('native job operation without its mutex')
            self.calls.append(target)
            self.hostile_result(0 if target == 0x4ACFC0 else 2)
        else:
            if target == AUTHENTICATED_API and not self.job_held:
                raise AssertionError('native API lost its job mutex')
            super().external(target)


class NativeTidalJobSnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = audit.source_image()
        cls.code, cls.patches = job.assemble(MUTEX, CODE_BASE)

    def machine(self, **options):
        return JobMachine(self.image, self.code, self.patches, **options)

    def assert_error_return(self, machine, error):
        self.assertEqual((machine.r[2], machine.r[3], machine.r[29], machine.r[31]),
                         (0xFFFFFFFF, error, TOP, RETURN))
        self.assertEqual(machine.r[16:23], [0x55000000 + index for index in range(7)])
        self.assertEqual(machine.api_inputs, [])
        self.assertEqual(machine.job_notifies, [])
        self.assertEqual(machine.get(JOB + 8, 4), 91)

    def test_forty_four_hooks_pin_source_pairs_frame_receipt_and_native_output_width(self):
        self.assertEqual(len(self.patches), 44)
        prefix, patches = job.preserved.assemble(MUTEX, CODE_BASE)
        self.assertEqual(self.code[:len(prefix)], prefix)
        self.assertEqual({site: pair for site, pair in self.patches.items()
                          if site not in {site for site, _ in job.HOOKS}}, patches)
        for site, pair in (*job.HOOKS, (job.SECOND, job.SECOND_PAIR)):
            self.assertEqual(pair, (self.image.word(site), self.image.word(site + 4)))
        self.assertNotIn(job.SECOND, self.patches)
        sizes = {0x20: 1, 0x24: 1, 0x28: 1, 0x21: 2, 0x25: 2, 0x29: 2,
                 0x23: 4, 0x2B: 4, 0x31: 4, 0x39: 4, 0x35: 8, 0x3D: 8}
        for pc in range(job.ENTRY, job.END, 4):
            word = self.image.word(pc)
            op, rs, offset = word >> 26, word >> 21 & 31, word & 0xFFFF
            offset -= 0x10000 if offset & 0x8000 else 0
            if rs == 29 and op in sizes:
                self.assertFalse(offset < job.RECEIPT + 4 and job.RECEIPT < offset + sizes[op], hex(pc))
            if rs == 29 and op == 9:
                self.assertNotEqual(offset, job.RECEIPT, hex(pc))
        self.assertEqual(self.image.word(0x9212E4), 0x42AF2C)  # property 11 case
        self.assertEqual(self.image.word(0x42AF3C), 0xAE220000)  # one output word
        self.assertEqual((self.image.word(0x4ECC68), self.image.word(0x4ECC70),
                          self.image.word(0x4ECC74)), (0x02802021, 0x0C296F18, 0x24060080))
        self.assertEqual(self.image.word(job.EPILOGUE), 0x8FBF0FDC)

    def test_every_normal_return_after_acquire_crosses_the_single_native_unlock_gate(self):
        def reachable(blocked=()):
            seen, pending = set(), [job.ACQUIRE + 8]
            while pending:
                pc = pending.pop()
                if pc in seen or pc in blocked:
                    continue
                self.assertTrue(job.ENTRY <= pc < job.END, hex(pc))
                seen.add(pc)
                word = self.image.word(pc)
                op, rs, rt = word >> 26, word >> 21 & 31, word >> 16 & 31
                indirect = op == 0 and word & 63 in (8, 9)
                if indirect:
                    self.assertEqual(word, 0x03E00008)
                elif op == 3:
                    pending.append(pc + 8)
                elif op == 2:
                    pending.append(((pc + 4) & 0xF0000000) | ((word & 0x3FFFFFF) << 2))
                elif op in (1, 4, 5, 6, 7):
                    offset = word & 0xFFFF
                    offset -= 0x10000 if offset & 0x8000 else 0
                    if not (op == 5 and rs == rt):
                        pending.append(pc + 4 + offset * 4)
                    if not (op == 4 and rs == rt):
                        pending.append(pc + 8)
                else:
                    pending.append(pc + 4)
            return seen

        returns = {pc for pc in reachable() if self.image.word(pc) == 0x03E00008}
        self.assertEqual(returns, {0x4ECBB4})
        self.assertTrue(returns.isdisjoint(reachable({job.RELEASE})))

    def test_raw_job_acquire_preserves_abi_and_unlock_uses_the_actual_captured_mutex(self):
        machine = self.machine()
        frame = machine.seed_job()
        before, hi, lo = machine.r.copy(), machine.hi, machine.lo
        machine.run_at(job.ACQUIRE, job.ACQUIRE + 8)
        expected = before.copy()
        expected[2], expected[18], expected[31] = 0, 0, job.ACQUIRE + 8
        self.assertEqual((machine.r, machine.hi, machine.lo), (expected, hi, lo))
        self.assertEqual(machine.get(frame + job.RECEIPT, 4), JOB_MUTEX)
        machine.put(JOB + 0xC, JOB_MUTEX + 0x80, 4)
        machine.r[4] = JOB_MUTEX + 0x80
        before = machine.r.copy()
        machine.run_at(job.RELEASE, job.RELEASE + 8)
        expected = before.copy()
        expected[2], expected[31] = 0, job.RELEASE + 8
        self.assertEqual((machine.r, machine.hi, machine.lo), (expected, hi, lo))
        self.assertEqual(machine.get(JOB + 8, 4), 17)
        self.assertEqual(machine.get(frame + job.RECEIPT, 4), 0)
        self.assertEqual(machine.job_events, [(session.LOCK, JOB_MUTEX, 0), (session.UNLOCK, JOB_MUTEX, 0)])
        self.assertFalse(machine.job_held)

    def test_complete_native_non_snapshot_route_and_nullable_job_keep_ordinary_behavior(self):
        machine = self.machine()
        machine.seed_job()
        machine.run_at(job.ACQUIRE, RETURN)
        self.assertEqual((machine.r[29], machine.r[31]), (TOP, RETURN))
        self.assertEqual(machine.get(JOB + 8, 4), 2)
        self.assertEqual(machine.job_notifies, [(CONTROLLER, 1)])
        self.assertFalse(machine.job_held)
        self.assertEqual(machine.mutex_events, [])

        machine = self.machine()
        machine.r[29], machine.r[31], machine.r[4] = TOP, RETURN, CONTROLLER
        machine.put(CONTROLLER + 0x58, 0, 4)
        saved = machine.r[16:23]
        machine.run_at(job.ENTRY, RETURN)
        self.assertEqual((machine.r[29], machine.r[31], machine.r[16:23]), (TOP, RETURN, saved))
        self.assertEqual(machine.job_events, [])

    def test_success_snapshot_runs_native_s5_api_and_final_cleanup_with_only_job_lock(self):
        machine = self.machine()
        frame = machine.acquire_job()
        before, hi, lo = machine.r.copy(), machine.hi, machine.lo
        machine.run_at(job.SNAPSHOT, job.SECOND + 8)
        expected = before.copy()
        expected[2], expected[3], expected[4], expected[31] = OLD_ID, 0, frame + job.BUFFER, job.SECOND + 8
        self.assertEqual((machine.r, machine.hi, machine.lo), (expected, hi, lo))
        self.assertEqual(machine.string(frame + job.BUFFER), OLD_TEXT)
        self.assertEqual(machine.get(frame + job.BUFFER + job.CAPACITY, 4), 0x12345678)
        machine.run_at(job.SECOND + 8, RETURN)
        self.assertEqual(machine.api_inputs[0][:2], (OLD_TEXT, OLD_ID))
        self.assertEqual(machine.compares[0][1], OLD_ID)
        self.assertEqual((machine.job_callbacks[0][0], machine.job_callbacks[0][1][0]),
                         (job.COMPLETE_INDEX, INDEX_VALUE))
        self.assertEqual(machine.job_notifies, [(CONTROLLER, 1)])
        self.assertEqual(machine.get(JOB + 8, 4), 17)
        self.assertFalse(machine.job_held)

    def test_actual_pair_replacement_after_session_unlock_preserves_private_inputs(self):
        machine = self.machine()
        frame = machine.acquire_job()
        observed = []

        def replace_pair():
            machine.on_release = None
            writer = machine.fork_cpu()
            writer.on_release = None
            writer.seed_worker()
            writer.run_at(identity.WORK_BEGIN, identity.WORK_END)
            observed.append((machine.slots(), machine.string(frame + job.BUFFER), machine.job_held))

        machine.on_release = replace_pair
        machine.run_at(job.SNAPSHOT, RETURN)
        self.assertEqual(observed, [((NEW_RESPONSE, NEW_FOLLOWUP), OLD_TEXT, True)])
        self.assertEqual(machine.api_inputs[0][:2], (OLD_TEXT, OLD_ID))
        self.assertFalse(machine.job_held)

    def test_boundary_strings_include_nul_and_refusal_balances_both_locks_without_status_or_notify(self):
        for length in (0, 127, 128):
            with self.subTest(length=length):
                machine = self.machine()
                frame = machine.acquire_job()
                machine.bytes(RESPONSE_DATA, b'x' * length + b'\0')
                if length < 128:
                    machine.run_at(job.SNAPSHOT, job.SECOND + 8)
                    self.assertEqual(machine.string(frame + job.BUFFER), b'x' * length)
                    self.assertEqual(machine.get(frame + job.BUFFER + length, 1), 0)
                    self.assertEqual(machine.get(frame + job.BUFFER + job.CAPACITY, 4), 0x12345678)
                    machine.run_at(job.RELEASE, job.RELEASE + 8)
                else:
                    machine.r[18] = 1  # Native pending packet needs balancing on policy refusal.
                    machine.run_at(job.SNAPSHOT, RETURN)
                    self.assert_error_return(machine, 75)
                    self.assertEqual([target for target, _, _ in machine.job_callbacks],
                                     [job.COMPLETE_INDEX, job.CLEAR_PENDING])
                    self.assertEqual(machine.job_callbacks[-1][1], (8, 0))
                    self.assertEqual(machine.get(MUTEX + session.PHASE, 4), session.READY)
                    self.assertFalse(machine.job_held)

    def test_missing_response_stale_binding_closing_and_unavailable_never_use_the_api(self):
        for kind, error in (('primary', 61), ('text', 22), ('binding', 116),
                            ('closing', 116), ('new', 11), ('failed', 22)):
            with self.subTest(kind=kind):
                machine = self.machine()
                machine.acquire_job()
                if kind == 'primary':
                    machine.put(SESSION + 0x18, 0, 4)
                elif kind == 'text':
                    machine.put(OLD_RESPONSE + 8, 0, 4)
                elif kind == 'binding':
                    machine.put(session.SESSION_SLOT, SESSION + 0x600, 4)
                elif kind == 'closing':
                    machine.put(MUTEX + session.LIFECYCLE, session.CLOSING, 4)
                else:
                    machine.put(MUTEX + session.PHASE, getattr(session, kind.upper()), 4)
                    machine.put(MUTEX + session.INIT_ERROR, 22 if kind == 'failed' else 0, 4)
                machine.run_at(job.SNAPSHOT, RETURN)
                self.assert_error_return(machine, error)
                self.assertFalse(machine.job_held)
                if kind in ('new', 'failed'):
                    self.assertEqual(machine.job_callbacks, [])
                    self.assertEqual(machine.mutex_events, [])

    def test_job_acquire_errors_and_null_or_recursive_mutex_never_guess_unlock(self):
        for result, pointer in ((22, JOB_MUTEX), (0, 0), (0, MUTEX)):
            with self.subTest(result=result, pointer=hex(pointer)):
                machine = self.machine(job_acquire=result)
                frame = machine.seed_job()
                machine.r[4] = pointer
                machine.run_at(job.ACQUIRE, RETURN)
                self.assert_error_return(machine, 22)
                self.assertEqual(machine.get(frame + job.RECEIPT, 4), 0)
                self.assertEqual(machine.job_events, [(session.LOCK, JOB_MUTEX, 22)] if result else [])
                self.assertEqual(machine.job_callbacks, [])
                self.assertFalse(machine.job_held)

    def test_session_raw_failures_release_only_the_known_independent_job_mutex_once(self):
        for acquire, release in ((22, 0), (0, 1)):
            with self.subTest(acquire=acquire, release=release):
                machine = self.machine(acquire=acquire, release=release)
                frame = machine.acquire_job()
                machine.run_at(job.SNAPSHOT, RETURN)
                self.assert_error_return(machine, acquire or release)
                self.assertEqual(machine.get(MUTEX + session.PHASE, 4), session.FAILED)
                self.assertEqual(machine.get(MUTEX + session.INIT_ERROR, 4), acquire or release)
                self.assertEqual(machine.job_callbacks, [])
                self.assertEqual(machine.job_events, [(session.LOCK, JOB_MUTEX, 0), (session.UNLOCK, JOB_MUTEX, 0)])
                self.assertFalse(machine.job_held)
                self.assertEqual(machine.held, bool(release))
                self.assertEqual(machine.string(frame + job.BUFFER), OLD_TEXT if release else b'')

    def test_failed_job_unlock_is_not_repeated_and_overrides_the_policy_diagnostic(self):
        for policy in (False, True):
            with self.subTest(policy=policy):
                machine = self.machine(job_release=1)
                frame = machine.acquire_job()
                if policy:
                    machine.put(SESSION + 0x18, 0, 4)
                    machine.run_at(job.SNAPSHOT, RETURN)
                    self.assert_error_return(machine, 1)
                else:
                    machine.run_at(job.RELEASE, RETURN)
                    self.assertEqual((machine.r[2], machine.r[3]), (0xFFFFFFFF, 1))
                    self.assertEqual(machine.job_notifies, [])
                self.assertEqual(machine.job_events, [(session.LOCK, JOB_MUTEX, 0), (session.UNLOCK, JOB_MUTEX, 1)])
                self.assertTrue(machine.job_held)
                self.assertEqual(machine.get(frame + job.RECEIPT, 4), JOB_MUTEX)
                self.assertEqual(machine.get(MUTEX + session.PHASE, 4), session.FAILED)

    def test_cleanup_callback_fault_suppresses_later_callbacks_but_balances_the_job_lock(self):
        for fault_at in (job.COMPLETE_INDEX, job.CLEAR_PENDING):
            with self.subTest(fault_at=hex(fault_at)):
                machine = self.machine()
                machine.acquire_job()
                machine.r[18] = 1
                machine.put(SESSION + 0x18, 0, 4)

                def fault(target):
                    if target == fault_at:
                        machine.put(MUTEX + session.INIT_ERROR, 22, 4)
                        machine.put(MUTEX + session.PHASE, session.FAILED, 4)

                machine.on_cleanup = fault
                machine.run_at(job.SNAPSHOT, RETURN)
                self.assert_error_return(machine, 22)
                expected = [job.COMPLETE_INDEX]
                if fault_at == job.CLEAR_PENDING:
                    expected.append(job.CLEAR_PENDING)
                self.assertEqual([target for target, _, _ in machine.job_callbacks], expected)
                self.assertFalse(machine.job_held)

    def test_missing_job_receipt_never_guesses_unlock_or_writes_job_status(self):
        for site in (job.RELEASE, job.SNAPSHOT):
            with self.subTest(site=hex(site)):
                machine = self.machine()
                frame = machine.seed_job()
                machine.put(frame + job.RECEIPT, 0, 4)
                machine.run_at(site, RETURN)
                self.assert_error_return(machine, 1)
                self.assertEqual(machine.job_events, [])
                self.assertEqual(machine.job_callbacks, [])
                self.assertEqual(machine.mutex_events, [])


if __name__ == '__main__':
    unittest.main()
