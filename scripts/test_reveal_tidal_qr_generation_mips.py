#!/usr/bin/env python3
"""Execute stamped QR construction, native timer return and schema rejection."""

import unittest

import factory_null_audit as audit
import reveal_tidal_qr_generation_mips as qr
import reveal_tidal_response_reader_bridge_mips as session
from test_factory_d180_qr_continuation import QR_NAME, TIDAL_NAME, REQUEST, TEXT, OLD_PAYLOAD, MESSAGE, QUEUE, STATUS
from test_factory_d180_tidal_response_lifecycle import OLD_RESPONSE, OLD_FOLLOWUP, SESSION
from test_factory_null_audit import ALLOCATION, CONTEXT, HANDLE, COPY, NullCallerMachine, RETURN, STACK
from test_reveal_d180_book_percent_guard_mips import RAW_ALLOC, FACTORY
from test_reveal_tidal_response_reader_bridge_mips import CODE_BASE, MUTEX
from test_reveal_tidal_retained_readers_mips import RetainedMachine


WRAPPER, OPEN, OWNER_FLAG = 0x5019C0, 0x508240, CONTEXT + 0x208


class QrGenerationMachine(RetainedMachine):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.map(ALLOCATION, qr.TIDAL_BYTES)
        self.factory_result = HANDLE
        self.qr_events = []
        self.on_qr_event = None

    def plain(self, word):
        if word >> 26 == 0x20:  # Native timer's signed byte read of its owned token.
            self.executing_pc = self.fetch_pc
            rs, rt, offset = word >> 21 & 31, word >> 16 & 31, word & 0xFFFF
            offset -= 0x10000 if offset & 0x8000 else 0
            value = self.get((self.r[rs] + offset) & 0xFFFFFFFF, 1)
            self.r[rt] = (value - 256 if value & 0x80 else value) & 0xFFFFFFFF
            self.r[0] = 0
        else:
            super().plain(word)

    def external(self, target):
        if target in (qr.ALLOCATOR, qr.MEMSET, FACTORY, qr.FREE, 0x454B80, 0x477180):
            if self.held:
                raise AssertionError('QR native service ran under the session mutex')
            if hasattr(self, 'qr_events'):
                self.qr_events.append((target, self.get(MUTEX + session.BORROWS, 4)))
                if self.on_qr_event is not None:
                    self.on_qr_event(target)
        if target == RAW_ALLOC and self.r[4] == qr.TIDAL_BYTES + 16:
            self.calls.append(target)
            self.hostile_result(ALLOCATION - 4 if self.allocate else 0)
        elif target == FACTORY:
            if not self.resource_failure and not self.reuse:
                self.put(HANDLE + 0x4C, self.r[16], 4)
            super().external(target)
        elif target == 0x454B80:
            self.calls.append(target)
            self.run_at(target, self.r[31])
        elif target == COPY:
            NullCallerMachine.external(self, target)
        else:
            super().external(target)

    def seed_request(self, mode=2, generation=1):
        self.put(REQUEST, mode, 4)
        self.put(REQUEST + 0x18, SESSION if mode == 2 else 0, 4)
        self.put(REQUEST + qr.DESCRIPTOR_TOKEN, generation, 4)
        self.put(REQUEST + 8, TEXT, 4)
        self.bytes(TEXT, b'ordinary QR fixture\0')
        self.put(OWNER_FLAG, 1, 4)
        self.descriptor_name = TIDAL_NAME if mode == 2 else QR_NAME
        self.r[4:7] = [0, CONTEXT, REQUEST]

    def seed_timer(self, mode=2, *, size=qr.TIDAL_BYTES, generation=1, alias=SESSION, status=1):
        self.put(ALLOCATION - 4, size, 4)
        self.bytes(ALLOCATION, bytes(qr.TIDAL_BYTES))
        self.put(ALLOCATION, mode, 4)
        self.put(ALLOCATION + 0x18C, alias if mode == 2 else 0, 4)
        self.put(ALLOCATION + qr.PAYLOAD_TOKEN, generation, 4)
        self.put(HANDLE + 0x4C, ALLOCATION, 4)
        self.put(STATUS, status, 4)
        self.accesses.clear()

    def seed_capture(self):
        frame = STACK - 80
        self.r[29], self.r[2] = frame, 2
        self.put(frame + 0x4C, RETURN, 4)
        self.put(frame + 0x44, self.r[16], 4)
        self.put(frame + 0x48, self.r[17], 4)
        return frame


class NativeTidalQrGenerationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = audit.source_image()
        cls.code, cls.patches = qr.assemble(MUTEX, CODE_BASE)

    def machine(self, **options):
        return QrGenerationMachine(self.image, self.code, self.patches, **options)

    def test_source_pairs_and_descriptor_capture_preserve_mode_and_binding(self):
        self.assertEqual(len(self.patches), 33)
        for site, original in qr.HOOKS:
            self.assertEqual(original, (self.image.word(site), self.image.word(site + 4)))
        machine = self.machine()
        frame = machine.seed_capture()
        before, hi, lo = machine.r.copy(), machine.hi, machine.lo
        machine.run_at(qr.CAPTURE, qr.CAPTURE + 8)
        self.assertEqual(machine.get(frame + 0x20, 4), 2)
        self.assertEqual(machine.get(frame + qr.CALLER_TOKEN, 4), 1)
        self.assertEqual((machine.r[2], machine.r[31]), (SESSION, qr.CAPTURE + 8))
        self.assertEqual((machine.hi, machine.lo), (hi, lo))
        self.assertEqual(machine.r[4:31], before[4:31])

    def test_constructor_uses_mode_specific_size_and_stamps_only_tidal(self):
        for mode, size in ((0, qr.ORDINARY_BYTES), (2, qr.TIDAL_BYTES)):
            with self.subTest(mode=mode):
                machine = self.machine()
                machine.seed_request(mode)
                saved = machine.r[16:24]
                self.assertEqual(machine.stock(WRAPPER, *machine.r[4:7]), HANDLE)
                self.assertEqual(machine.get(ALLOCATION - 4, 4), size)
                self.assertEqual(machine.get(ALLOCATION + 0x18C, 4), SESSION if mode == 2 else 0)
                self.assertEqual(machine.get(ALLOCATION + qr.PAYLOAD_TOKEN, 4), 1 if mode == 2 else 0)
                self.assertEqual(machine.get(HANDLE + 0x4C, 4), ALLOCATION)
                self.assertEqual(machine.r[16:24], saved)
                self.assertEqual((machine.r[29], machine.r[31]), (STACK, RETURN))

    def test_complete_native_open_carries_the_captured_generation_through_queue_and_payload(self):
        machine = self.machine()
        machine.accesses.clear()
        self.assertEqual(machine.stock(OPEN, CONTEXT, 0), 0)
        self.assertEqual((machine.get(MESSAGE, 4), machine.get(MESSAGE + 4, 4)), (0, 1))
        self.assertEqual(machine.get(ALLOCATION - 4, 4), qr.TIDAL_BYTES)
        self.assertEqual(machine.get(ALLOCATION + 0x18C, 4), SESSION)
        self.assertEqual(machine.get(ALLOCATION + qr.PAYLOAD_TOKEN, 4), 1)
        self.assertFalse(any(address == SESSION + 0x18 for _, _, address, _ in machine.accesses))
        self.assertEqual(machine.get(HANDLE + 0x4C, 4), ALLOCATION)
        self.assertEqual((machine.r[29], machine.r[31]), (STACK, RETURN))

    def test_constructor_rejects_stale_descriptor_and_allocation_failure_before_factory(self):
        for mode, stale, allocate, error in ((2, True, True, 116), (2, False, False, 12),
                                            (0, False, False, 12)):
            with self.subTest(mode=mode, stale=stale, allocate=allocate):
                machine = self.machine()
                machine.allocate = allocate
                machine.seed_request(mode, generation=2 if stale else 1)
                self.assertEqual(machine.stock(WRAPPER, *machine.r[4:7]), 0)
                self.assertEqual(machine.r[3], error)
                self.assertEqual(machine.get(OWNER_FLAG, 4), 1)
                self.assertEqual(machine.descriptors, [])
                self.assertEqual(machine.releases, [ALLOCATION] if stale else [])

    def test_factory_refusal_restores_owner_and_reuse_releases_only_unused_private_payload(self):
        for reuse in (False, True):
            with self.subTest(reuse=reuse):
                machine = self.machine()
                machine.seed_request()
                machine.resource_failure, machine.reuse = True, reuse
                if reuse:
                    machine.map(OLD_PAYLOAD - 4, qr.ORDINARY_BYTES + 4)
                    machine.put(OLD_PAYLOAD - 4, qr.ORDINARY_BYTES, 4)
                    machine.put(HANDLE + 0x4C, OLD_PAYLOAD, 4)
                    machine.put(HANDLE + 0x54, 0x12345678, 4)
                self.assertEqual(machine.stock(WRAPPER, *machine.r[4:7]), HANDLE if reuse else 0)
                self.assertIn(ALLOCATION, machine.releases)
                if reuse:
                    self.assertEqual(machine.get(HANDLE + 0x4C, 4), OLD_PAYLOAD)
                    self.assertEqual(machine.get(HANDLE + 0x54, 4), 0x12345678)
                else:
                    self.assertEqual(machine.get(OWNER_FLAG, 4), 1)
                    self.assertEqual(machine.r[3], 12)

    def test_timer_pending_path_is_retained_and_ordinary_matches_native_control(self):
        for mode in (0, 2):
            with self.subTest(mode=mode):
                machine = self.machine()
                machine.seed_timer(mode)
                saved = machine.r[16:24]
                machine.stock(qr.TIMER, HANDLE)
                self.assertEqual(machine.r[16:24], saved)
                self.assertEqual((machine.r[29], machine.r[31]), (STACK, RETURN))
                self.assertEqual(machine.get(MUTEX + session.BORROWS, 4), 0)
                if mode == 2:
                    self.assertEqual(machine.r[3], 0)
                    self.assertIn((0x477180, 1), machine.qr_events)
                    self.assertIn((0x454B80, 1), machine.qr_events)
                else:
                    native = self.machine()
                    native.seed_timer(0)
                    native.replacements.pop(qr.TIMER)
                    native.replacements.pop(qr.TIMER + 4)
                    native.stock(qr.TIMER, HANDLE)
                    self.assertEqual((machine.r, machine.hi, machine.lo), (native.r, native.hi, native.lo))

    def test_null_factory_owner_restore_retries_reservation_loss_and_preserves_a_nonzero_update(self):
        for update in (False, True):
            with self.subTest(update=update):
                machine = self.machine()
                machine.seed_request()
                machine.resource_failure = True
                machine.sc_failures = 1

                def owner_update(target):
                    if target == qr.FREE and machine.r[4] == ALLOCATION:
                        machine.put(OWNER_FLAG, 7, 4)

                if update:
                    machine.on_qr_event = owner_update
                self.assertEqual(machine.stock(WRAPPER, *machine.r[4:7]), 0)
                self.assertEqual(machine.get(OWNER_FLAG, 4), 7 if update else 1)
                self.assertEqual(machine.releases.count(ALLOCATION), 1)
                self.assertEqual(machine.sc_failures, 1 if update else 0)

    def test_stale_same_address_unmapped_alias_and_legacy_timer_reject_before_session_field_reads(self):
        for kind, error in (('aba', 116), ('alias', 116), ('legacy', 71)):
            with self.subTest(kind=kind):
                machine = self.machine()
                machine.seed_timer(size=qr.ORDINARY_BYTES if kind == 'legacy' else qr.TIDAL_BYTES,
                                   alias=0x12000000 if kind == 'alias' else SESSION)
                if kind == 'aba':
                    machine.put(MUTEX + session.GENERATION, 2, 4)
                self.assertEqual(machine.stock(qr.TIMER, HANDLE), 0xFFFFFFFF)
                self.assertEqual(machine.r[3], error)
                self.assertFalse(any(address == SESSION + 0x18 for _, _, address, _ in machine.accesses))
                if kind == 'legacy':
                    self.assertFalse(any(address == ALLOCATION + qr.PAYLOAD_TOKEN
                                         for _, _, address, _ in machine.accesses))
                self.assertEqual(machine.qr_events, [])

    def test_status_200_rejects_incompatible_schema_and_preserves_diagnostic_after_unpin(self):
        machine = self.machine()
        machine.seed_timer(status=200)
        self.assertEqual(machine.stock(qr.TIMER, HANDLE), 0xFFFFFFFF)
        self.assertEqual(machine.r[3], 71)
        self.assertEqual(machine.get(MUTEX + session.BORROWS, 4), 0)
        self.assertFalse(any(address in (SESSION + 0x18, OLD_RESPONSE + 4, OLD_RESPONSE + 0x10)
                             for _, _, address, _ in machine.accesses))

    def test_qr_post_uses_captured_generation_and_rejects_a_changed_descriptor_generation(self):
        for stale in (False, True):
            with self.subTest(stale=stale):
                machine = self.machine()
                frame = machine.seed_capture()
                machine.put(frame + 0x38, SESSION, 4)
                machine.put(frame + qr.CALLER_TOKEN, 1, 4)
                if stale:
                    machine.put(MUTEX + session.GENERATION, 2, 4)
                    machine.run_at(qr.POST, RETURN)
                    self.assertEqual(machine.r[3], 116)
                    self.assertEqual(machine.get(QUEUE + 0x10, 4), 0)
                else:
                    machine.on_release = lambda: machine.put(MUTEX + session.GENERATION, 2, 4)
                    machine.run_at(qr.POST, qr.POST + 8)
                    self.assertEqual((machine.get(MESSAGE, 4), machine.get(MESSAGE + 4, 4)), (0, 1))

    def test_raw_admission_errors_quarantine_capture_bind_and_timer_without_cleanup_guess(self):
        for action in ('capture', 'post', 'bind', 'timer'):
            for acquire, release in ((22, 0), (0, 1)):
                with self.subTest(action=action, acquire=acquire, release=release):
                    machine = self.machine(acquire=acquire, release=release)
                    if action == 'capture':
                        machine.seed_capture()
                        machine.run_at(qr.CAPTURE, RETURN)
                    elif action == 'post':
                        frame = machine.seed_capture()
                        machine.put(frame + 0x38, SESSION, 4)
                        machine.put(frame + qr.CALLER_TOKEN, 1, 4)
                        machine.run_at(qr.POST, RETURN)
                        self.assertEqual(machine.get(QUEUE + 0x10, 4), 0)
                    elif action == 'bind':
                        machine.seed_request()
                        machine.stock(WRAPPER, *machine.r[4:7])
                    else:
                        machine.seed_timer()
                        machine.stock(qr.TIMER, HANDLE)
                    self.assertEqual(machine.r[3], acquire or release)
                    self.assertEqual(machine.get(MUTEX + session.PHASE, 4), session.FAILED)
                    self.assertEqual(machine.releases, [])

    def test_timer_raw_unpin_errors_preserve_the_actual_counter_effect_and_quarantine(self):
        for acquire, release in ((22, 0), (0, 1)):
            with self.subTest(acquire=acquire, release=release):
                machine = self.machine()
                machine.seed_timer()

                def fail_after_body(target):
                    if target == 0x454B80:
                        machine.acquire_result, machine.release_result = acquire, release

                machine.on_qr_event = fail_after_body
                self.assertEqual(machine.stock(qr.TIMER, HANDLE), 0xFFFFFFFF)
                self.assertEqual(machine.r[3], acquire or release)
                self.assertEqual(machine.get(MUTEX + session.PHASE, 4), session.FAILED)
                self.assertEqual(machine.get(MUTEX + session.BORROWS, 4), 1 if acquire else 0)
                self.assertIn((0x477180, 1), machine.qr_events)
                self.assertEqual((machine.r[29], machine.r[31]), (STACK, RETURN))

    def test_reused_dialog_keeps_its_old_stamp_and_cannot_adopt_a_new_session_generation(self):
        machine = self.machine()
        machine.put(MUTEX + session.GENERATION, 2, 4)
        machine.seed_request(generation=2)
        machine.resource_failure = machine.reuse = True
        machine.map(OLD_PAYLOAD - 4, qr.TIDAL_BYTES + 4)
        machine.put(OLD_PAYLOAD - 4, qr.TIDAL_BYTES, 4)
        machine.put(OLD_PAYLOAD, 2, 4)
        machine.put(OLD_PAYLOAD + 0x18C, SESSION, 4)
        machine.put(OLD_PAYLOAD + qr.PAYLOAD_TOKEN, 1, 4)
        machine.put(HANDLE + 0x4C, OLD_PAYLOAD, 4)
        machine.put(HANDLE + 0x54, OLD_PAYLOAD, 4)
        self.assertEqual(machine.stock(WRAPPER, *machine.r[4:7]), HANDLE)
        self.assertEqual(machine.releases, [ALLOCATION])
        self.assertEqual(machine.get(HANDLE + 0x4C, 4), OLD_PAYLOAD)
        self.assertEqual(machine.get(HANDLE + 0x54, 4), OLD_PAYLOAD)
        self.assertEqual(machine.get(OLD_PAYLOAD + qr.PAYLOAD_TOKEN, 4), 1)
        machine.accesses.clear()
        machine.qr_events.clear()
        self.assertEqual(machine.stock(qr.TIMER, HANDLE), 0xFFFFFFFF)
        self.assertEqual(machine.r[3], 116)
        self.assertEqual(machine.qr_events, [])
        self.assertFalse(any(address == SESSION + 0x18 for _, _, address, _ in machine.accesses))

    def test_raw_unpin_error_overrides_the_schema_refusal_diagnostic(self):
        for acquire, release in ((22, 0), (0, 1)):
            with self.subTest(acquire=acquire, release=release):
                machine = self.machine()
                machine.seed_timer(status=200)

                def fail_after_body(target):
                    if target == 0x454B80:
                        machine.acquire_result, machine.release_result = acquire, release

                machine.on_qr_event = fail_after_body
                self.assertEqual(machine.stock(qr.TIMER, HANDLE), 0xFFFFFFFF)
                self.assertEqual(machine.r[3], acquire or release)
                self.assertEqual(machine.get(MUTEX + session.PHASE, 4), session.FAILED)
                self.assertEqual(machine.get(MUTEX + session.BORROWS, 4), 1 if acquire else 0)
                self.assertFalse(any(address in (SESSION + 0x18, OLD_RESPONSE + 4, OLD_RESPONSE + 0x10)
                                     for _, _, address, _ in machine.accesses))


if __name__ == '__main__':
    unittest.main()
