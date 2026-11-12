#!/usr/bin/env python3
"""Pin known native caller behavior after guarded command-zero POST refusal.

These bounded regressions record remaining deficiencies, not a rollback or
caller-quarantine fix. The current 44-hook composer runs with actual native
POST/status/continuation instructions. Input copies and queue publication run
their native bodies; opaque UI/configuration services are bounded substitutes.
No real UI, file, network or device operation is performed by this fixture.
"""

import unittest

import factory_null_audit as audit
import reveal_tidal_job_snapshot_mips as composed
import reveal_tidal_qr_generation_mips as qr
import reveal_tidal_request_identity_mips as identity
import reveal_tidal_response_reader_bridge_mips as session
from test_factory_d180_qr_continuation import (
    CALL_QR, MESSAGE, OPEN_TIDAL, OWNER_FLAG, QUEUE, QUEUE_SLOT, RESET_FILE, STATUS,
)
from test_factory_null_audit import ALLOCATION, CONTEXT, HANDLE, RETURN, STACK
from test_reveal_tidal_qr_generation_mips import QrGenerationMachine
from test_reveal_tidal_response_reader_bridge_mips import CODE_BASE, MUTEX


POST, ARM, GET_STATUS = 0x454B40, 0x454BA0, 0x454B80
COPY_INPUT, STRCPY, UPDATE_UI = 0x5134C0, 0xA5BEE0, 0x5090E0
INPUT_A, INPUT_B = 0xB8BBE8, 0xB8BCEC
OTHER_INPUT = (0x52D860, 0x52D760)
LATER_NATIVE = (0x510340, 0x4552E0, 0x529AC0)
UI_RESULT = 0x55
WORKER_MUTEX, PAUSE, NATIVE_UNLOCK = 0x1D0D000, 0x466E20, 0x466DC0

NATIVE_WORDS = {
    0x478254: 0x0C1152E8, 0x478260: 0x0C1152D0,
    0x478268: 0x27A40340, 0x4782C4: 0x0C1152D0,
    0x47832C: 0x00001021,
    0x50779C: 0x0C144D30, 0x5077A8: 0x0C1152D0,
    0x5077B0: 0x0C1152E0, 0x5077C4: 0x0C1152E8,
    0x5077D4: 0x0C142438,
    0x508290: 0x0C144CD8, 0x50829C: 0x0C1152E8,
    0x5082A8: 0x0C1152D0, 0x5082B8: 0x0C140670,
    0x5082CC: 0x00001021,
    0x508720: 0x0C144D30, 0x50872C: 0x0C1152D0,
    0x508734: 0x0C1152E0, 0x508748: 0x0C1152E8,
    0x508758: 0x0C142438, 0x508778: 0x24020001,
    0x45442C: 0x24040014, 0x454430: 0x0C11DC60,
    0x454434: 0x24050001,
    0x4544E4: 0x0C11DC60, 0x4544E8: 0x00002821,
    0x4544EC: 0x0C119B88, 0x4544F0: 0x2404000A,
    0x4544F4: 0x8E020010, 0x4544F8: 0x1040FFC2,
    0x4544FC: 0x8E249250, 0x454500: 0x0C119B70,
    0x454504: 0x8E04000C, 0x454508: 0x8FBF0864,
    0x454530: 0x03E00008, 0x454534: 0x27BD0868,
}


class CallerRefusalMachine(QrGenerationMachine):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.post_outcomes, self.continuation_events = [], []
        self.worker_mutex_held = False
        self.worker_unlocks, self.worker_pauses, self.busy_values = [], [], []

    def c_string(self, address):
        result = bytearray()
        for offset in range(260):
            value = self.get(address + offset, 1)
            if not value:
                return bytes(result)
            result.append(value)
        raise AssertionError('fixture input must terminate within native capacity')

    def external(self, target):
        if target == PAUSE:
            self.worker_pauses.append(self.r[4])
            self.calls.append(target)
            # Bound the native suffix to its ordinary stop-and-return route.
            self.put(QUEUE_SLOT + 0x10, 1, 4)
            self.hostile_result(0)
        elif target == NATIVE_UNLOCK and self.r[4] == WORKER_MUTEX:
            self.calls.append(target)
            self.run_at(target, self.r[31])
        elif target == session.UNLOCK and self.r[4] == WORKER_MUTEX:
            if not self.worker_mutex_held:
                raise AssertionError('worker mutex was not independently owned')
            self.worker_mutex_held = False
            self.worker_unlocks.append(self.r[4])
            self.calls.append(target)
            self.hostile_result(0)
        elif target == POST:
            command = self.r[4]
            super().external(target)
            self.post_outcomes.append((command, self.r[2], self.r[3]))
        elif target in (COPY_INPUT, 0x454C20):  # The latter is a native return-zero leaf.
            self.calls.append(target)
            self.run_at(target, self.r[31])
        elif target == STRCPY:
            destination, source = self.r[4:6]
            self.calls.append(target)
            self.bytes(destination, self.c_string(source) + b'\0')
            self.hostile_result(destination)
        elif target in (*OTHER_INPUT, *LATER_NATIVE, UPDATE_UI):
            if self.held:
                raise AssertionError('native caller continuation held session mutex')
            self.continuation_events.append((target, tuple(self.r[4:7])))
            self.calls.append(target)
            if target in OTHER_INPUT:
                # Force the independent command-six branch after command-zero
                # refusal, without invoking its real credential source.
                for destination in self.r[4:6]:
                    self.bytes(destination, b'other-cloud\0')
            self.hostile_result(UI_RESULT if target == UPDATE_UI else 0)
        else:
            if target == identity.NOTIFY and self.r[4] == 20:
                self.busy_values.append(self.r[5])
            super().external(target)

    def seed_frame(self, size, saved_s0, register_count, ra_offset):
        frame = STACK - size
        self.r[29], self.r[31] = frame, RETURN
        for index in range(register_count):
            self.put(frame + saved_s0 + index * 4, 0x55000000 + index, 4)
        self.put(frame + ra_offset, RETURN, 4)
        return frame


class NativeTidalCallerRefusalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = audit.source_image()
        cls.code, cls.patches = composed.assemble(MUTEX, CODE_BASE)

    def machine(self):
        return CallerRefusalMachine(self.image, self.code, self.patches)

    def close_admission(self, machine):
        machine.put(MUTEX + session.LIFECYCLE, session.CLOSING, 4)

    def test_exact_native_caller_words_keep_refusal_observations_source_bound(self):
        self.assertEqual(len(self.patches), 44)
        for pc, word in NATIVE_WORDS.items():
            self.assertEqual(self.image.word(pc), word, hex(pc))

    def test_startup_ignores_refusal_retains_pending_and_can_post_another_command(self):
        for failed in (False, True):
            with self.subTest(failed=failed):
                machine = self.machine()
                frame = machine.seed_frame(0x610, 0x5EC, 8, 0x60C)
                machine.r[16], machine.r[21] = frame + 0x20, CONTEXT
                machine.put(CONTEXT + 0x1D8, 0, 4)
                if failed:
                    machine.put(MUTEX + session.INIT_ERROR, 22, 4)
                    machine.put(MUTEX + session.PHASE, session.FAILED, 4)
                else:
                    self.close_admission(machine)
                machine.run_at(0x478250, RETURN)
                self.assertEqual(machine.post_outcomes[0],
                                 (0, 0xFFFFFFFF, 22 if failed else 116))
                self.assertEqual([row[0] for row in machine.post_outcomes], [0, 6])
                self.assertEqual(machine.post_outcomes[1][1], 0)
                self.assertEqual(machine.get(STATUS, 4), 1)
                self.assertEqual(machine.get(STATUS + 6 * 4, 4), 1)
                self.assertEqual((machine.get(MESSAGE, 4), machine.get(MESSAGE + 4, 4)), (6, 0))
                self.assertEqual(machine.get(QUEUE + 0x10, 4), MESSAGE)
                self.assertEqual([target for target, _ in machine.continuation_events],
                                 [*OTHER_INPUT, *LATER_NATIVE])
                self.assertEqual((machine.r[2], machine.r[29], machine.r[31]), (0, STACK, RETURN))

    def test_login_callers_copy_inputs_then_ignore_refusal_and_rearm_pending_before_ui(self):
        callers = (
            # first input copy, frame, saved S0, saved-register count, RA,
            # string offsets, native final result (or last opaque UI result).
            (0x50779C, 0x568, 0x54C, 6, 0x564, (0x33C, 0x440), UI_RESULT),
            (0x508720, 0x240, 0x228, 5, 0x23C, (0x20, 0x124), 1),
        )
        for start, size, saved_s0, count, ra, offsets, final_result in callers:
            for old_status in (3, 1):
                with self.subTest(start=hex(start), status=old_status):
                    machine = self.machine()
                    frame = machine.seed_frame(size, saved_s0, count, ra)
                    machine.r[16:20] = [CONTEXT, CONTEXT + 0x40, CONTEXT + 0x80, CONTEXT + 0x100]
                    self.close_admission(machine)
                    machine.put(STATUS, old_status, 4)
                    for offset, text in zip(offsets, (b'new-user\0', b'new-password\0')):
                        machine.bytes(frame + offset, text)
                    machine.r[4] = frame + offsets[0]
                    machine.run_at(start, RETURN)
                    self.assertEqual(machine.post_outcomes, [(0, 0xFFFFFFFF, 116)])
                    self.assertEqual(machine.c_string(INPUT_A), b'new-user')
                    self.assertEqual(machine.c_string(INPUT_B), b'new-password')
                    self.assertEqual(machine.get(QUEUE + 0x10, 4), 0)
                    self.assertEqual(machine.get(STATUS, 4), 1)
                    self.assertEqual(machine.calls.count(ARM), int(old_status != 1))
                    self.assertEqual(machine.calls.count(GET_STATUS), 1)
                    self.assertEqual([target for target, _ in machine.continuation_events], [UPDATE_UI])
                    self.assertEqual((machine.r[2], machine.r[29], machine.r[31]),
                                     (final_result, STACK, RETURN))

    def test_qr_policy_refusal_skips_constructor_but_keeps_prior_native_effects_and_pending(self):
        machine = self.machine()

        def close_after_capture():
            machine.on_release = None
            self.close_admission(machine)

        machine.on_release = close_after_capture
        self.assertEqual(machine.stock(OPEN_TIDAL, CONTEXT, 0), 0)
        self.assertEqual(machine.r[3], 116)
        self.assertEqual(machine.calls.count(RESET_FILE), 1)
        self.assertEqual(machine.get(STATUS, 4), 1)
        self.assertEqual(machine.get(QUEUE + 0x10, 4), 0)
        self.assertEqual(machine.descriptors, [])
        self.assertEqual(machine.get(OWNER_FLAG, 4), 1)
        self.assertEqual((machine.r[29], machine.r[31]), (STACK, RETURN))

    def test_worker_begin_and_end_refusal_skip_busy_clear_but_run_the_native_stop_suffix(self):
        for at_end in (False, True):
            with self.subTest(at_end=at_end):
                machine = self.machine()
                machine.seed_worker(generation=1 if at_end else 2)
                machine.r[17] = 0xB90000  # Native worker's queue-global base.
                frame = machine.r[29]
                for index in range(9):
                    machine.put(frame + 0x840 + index * 4, 0x55000000 + index, 4)
                machine.put(frame + 0x864, RETURN, 4)
                machine.put(QUEUE_SLOT + 0xC, WORKER_MUTEX, 4)
                machine.put(QUEUE_SLOT + 0x10, 0, 4)
                machine.put(STATUS, 1, 4)  # Actual caller-side pending value.
                # Native worker admission normally owns this separate mutex
                # across its loop. Its valid ownership is a bounded premise.
                machine.worker_mutex_held = True
                if at_end:
                    machine.run_at(identity.WORK_BEGIN, identity.BEGIN_RESUME)
                    self.assertEqual(machine.busy_values, [1])
                    self.assertEqual(machine.get(MUTEX + session.WRITER, 4), 1)
                    # A raw admission failure at the result boundary is
                    # reachable without mutating the worker's queued packet.
                    machine.acquire_result = 22
                    machine.r[2] = 0xFFFFFFFE
                machine.run_at(identity.WORK_END if at_end else identity.WORK_BEGIN,
                               identity.WORK_SKIP)
                self.assertEqual(machine.get(STATUS, 4), 1)
                self.assertEqual(machine.get(MUTEX + session.WRITER, 4), int(at_end))
                self.assertEqual(machine.get(MUTEX + session.PHASE, 4),
                                 session.FAILED if at_end else session.READY)
                self.assertEqual(machine.get(MUTEX + session.INIT_ERROR, 4), 22 if at_end else 0)
                machine.run_at(identity.WORK_SKIP, RETURN)
                self.assertEqual(machine.worker_pauses, [10])
                self.assertEqual(machine.worker_unlocks, [WORKER_MUTEX])
                self.assertFalse(machine.worker_mutex_held)
                self.assertEqual(machine.busy_values, [1] if at_end else [])
                self.assertEqual(machine.get(STATUS, 4), 1)
                self.assertEqual(machine.worker_services, [])
                self.assertEqual(machine.r[16:24], [0x55000000 + index for index in range(8)])
                self.assertEqual(machine.r[30], 0x55000008)
                self.assertEqual((machine.r[29], machine.r[31]), (STACK, RETURN))

    def test_qr_native_enqueue_failure_after_admission_is_ignored_and_constructor_runs(self):
        machine = self.machine()
        machine.put(QUEUE + 4, 1, 4)  # Capacity two: next ring index is already full.
        machine.r[4:6] = [CONTEXT, 0]
        machine.run_at(OPEN_TIDAL, CALL_QR)
        self.assertEqual(machine.r[2], 0xFFFFFFFF)
        self.assertEqual(machine.get(QUEUE + 0x10, 4), 0)
        self.assertEqual(machine.get(STATUS, 4), 1)
        self.assertEqual(machine.descriptors, [])
        machine.run_at(CALL_QR, RETURN)
        self.assertEqual(machine.r[2], 0)
        self.assertEqual(len(machine.descriptors), 1)
        self.assertEqual(machine.get(HANDLE + 0x4C, 4), ALLOCATION)
        self.assertEqual(machine.get(ALLOCATION + qr.PAYLOAD_TOKEN, 4), 1)
        self.assertEqual(machine.get(OWNER_FLAG, 4), 0)
        self.assertEqual(machine.get(STATUS, 4), 1)
        self.assertEqual(machine.get(QUEUE + 0x10, 4), 0)


if __name__ == '__main__':
    unittest.main()
