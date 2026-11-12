#!/usr/bin/env python3
"""Check the RS2 QR dialog's payload and queue boundaries offline."""

import unittest

import factory_null_audit as audit
from test_factory_null_audit import ALLOCATION, CONTEXT, COPY, HANDLE, MASK, RETURN, LineageMachine, NullCallerMachine
from test_reveal_d180_book_percent_guard_mips import BookPercentMachine, FIND_DIALOG, RAW_ALLOC


WRAPPER, FACTORY_RETURN, DESTROY = 0x5019C0, 0x501A9C, 0x500CE0
QR_NAME, TIDAL_NAME = 0x94DE78, 0x94D9D4
OPEN_TIDAL, CALL_QR = 0x508240, 0x5082B8
GET_SESSION, RESET_FILE, RELEASE_RESPONSE = 0x475320, 0x513360, 0x8CBD6C
ARM, POST, WRITE_QUEUE, MEMCPY = 0x454BA0, 0x454B40, 0x4504E0, 0xA5B440
WORKER_CASE, WORKER_DONE = 0x454770, 0x4547DC
READ_WORKER_INPUT, WORKER_REQUEST = 0x513480, 0x513860
SESSION_SLOT, QUEUE_SLOT, STATUS = 0xB8A9EC, 0xB89250, 0xB8926C
OWNER_FLAG = CONTEXT + 0x208
REQUEST, TEXT = CONTEXT + 0x40, CONTEXT + 0x100
QUEUE, MESSAGE = 0x1D06000, 0x1D06100
OLD_PAYLOAD, SIDE_PAYLOAD, SESSION, RESPONSE = 0x1D07000, 0x1D07400, 0x1D08000, 0x1D08100


class QrMachine(BookPercentMachine):
    payload_size = 0x1A8

    def __init__(self, image, *, mode=0, reuse=False, queue_full=False, resource_failure=False, **options):
        super().__init__(image, resource_failure=reuse or resource_failure, **options)
        self.reuse = reuse
        self.descriptor_name = {0: QR_NAME, 2: TIDAL_NAME}.get(mode, 0)
        self.post_result = None
        self.response_releases = []
        self.map(ALLOCATION, self.payload_size)
        self.map(QUEUE, 0x20)
        self.map(MESSAGE - 4, 12)
        self.map(SESSION, 0x20)
        self.put(QUEUE, 2, 4)
        self.put(QUEUE + 4, int(queue_full), 4)
        self.put(QUEUE_SLOT, QUEUE, 4)
        self.put(SESSION_SLOT, SESSION, 4)
        self.put(STATUS, 3, 4)
        self.put(OWNER_FLAG, 1, 4)
        self.put(REQUEST, mode, 4)
        self.r[4:7] = [0, CONTEXT, REQUEST]
        self.writes.clear()

    def external(self, target):
        if target in (WRAPPER, GET_SESSION, ARM, POST, WRITE_QUEUE):
            self.calls.append(target)
            self.run_at(target, self.r[31])
            if target == POST:
                self.post_result = self.r[2]
        elif target == FIND_DIALOG and self.reuse:
            self.calls.append(target)
            self.put(self.r[5], HANDLE, 4)
            self.hostile_result(1)
        elif target == RAW_ALLOC and self.r[4] == 24:
            self.calls.append(target)
            self.hostile_result(MESSAGE - 4)
        elif target == MEMCPY:
            LineageMachine.external(self, target)
        elif target == COPY:
            NullCallerMachine.external(self, target)
        elif target in (RESET_FILE, READ_WORKER_INPUT, WORKER_REQUEST, RELEASE_RESPONSE):
            self.calls.append(target)
            if target == RELEASE_RESPONSE:
                self.response_releases.append(self.r[4])
            # Bound file and service operations. A distinctive file result
            # distinguishes it from the session pointer saved by the caller.
            result = {RESET_FILE: 7, WORKER_REQUEST: -2}.get(target, 0)
            self.hostile_result(result)
        else:
            super().external(target)


class NativeQrContinuationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = audit.source_image()

    def test_ordinary_qr_prepares_its_payload_and_clears_owner_before_factory(self):
        machine = QrMachine(self.image, resource_failure=True)
        machine.put(REQUEST + 8, TEXT, 4)
        machine.bytes(TEXT, b'RS2 fixture\0')
        machine.run_at(WRAPPER, FACTORY_RETURN)

        self.assertEqual(machine.descriptors, [(0x500FE0, DESTROY, 0, ALLOCATION, 0, 0, 0)])
        self.assertEqual(machine.regions[ALLOCATION][4:16], b'RS2 fixture\0')
        self.assertEqual(machine.get(OWNER_FLAG, 4), 0)
        self.assertEqual(machine.r[2], 0)
        self.assertEqual(machine.releases, [HANDLE])
        self.assertEqual(machine.raw_releases, [HANDLE - 4])
        self.assertEqual(machine.response_releases, [])

    def test_mode_zero_payload_is_used_before_factory(self):
        machine = QrMachine(self.image, allocate=False)
        # Stop before the first mode-zero payload write, with no text copy.
        machine.run_at(WRAPPER, 0x501A74)
        self.assertEqual(machine.r[16], 0)
        self.assertEqual(machine.descriptors, [])
        self.assertEqual(machine.get(OWNER_FLAG, 4), 1)

    def test_reused_dialog_destroys_old_payload_and_separate_side_payload(self):
        machine = QrMachine(self.image, reuse=True, mode=2)
        for payload, size in ((OLD_PAYLOAD, 0x1A8), (SIDE_PAYLOAD, 4)):
            machine.map(payload - 4, 4)
            machine.put(payload - 4, size, 4)
            machine.map(payload, size)
        machine.put(REQUEST + 0x18, SESSION, 4)
        machine.put(OLD_PAYLOAD + 0x18C, SESSION, 4)
        machine.put(SESSION + 0x18, RESPONSE, 4)
        machine.put(HANDLE + 0x48, CONTEXT, 4)
        machine.put(HANDLE + 0x4C, OLD_PAYLOAD, 4)
        machine.put(HANDLE + 0x58, SIDE_PAYLOAD, 4)
        machine.run_at(WRAPPER, RETURN)

        self.assertEqual(machine.r[2], HANDLE)
        self.assertEqual(machine.get(ALLOCATION + 0x18C, 4), SESSION)
        self.assertEqual(machine.get(HANDLE + 0x4C, 4), OLD_PAYLOAD)
        self.assertEqual(machine.get(HANDLE + 0x54, 4), ALLOCATION)
        self.assertEqual(machine.releases, [])
        machine.stock(DESTROY, HANDLE)
        self.assertEqual(machine.response_releases, [RESPONSE])
        self.assertEqual(machine.releases, [OLD_PAYLOAD, SIDE_PAYLOAD])
        self.assertEqual(machine.get(SESSION + 0x18, 4), 0)
        self.assertEqual(machine.get(SESSION_SLOT, 4), SESSION)
        self.assertEqual(machine.get(HANDLE + 0x54, 4), ALLOCATION)
        self.assertEqual(machine.get(OWNER_FLAG, 4), 1)

    def test_tidal_posts_before_opening_and_rearms_the_shared_status(self):
        for queue_full in (False, True):
            with self.subTest(queue_full=queue_full):
                machine = QrMachine(self.image, mode=2, queue_full=queue_full, factory_result=HANDLE)
                machine.r[4:6] = [CONTEXT, 0]
                machine.run_at(OPEN_TIDAL, CALL_QR)
                self.assertEqual(machine.get(OWNER_FLAG, 4), 1)
                self.assertEqual(machine.get(STATUS, 4), 1)
                self.assertEqual(machine.descriptors, [])
                if queue_full:
                    self.assertEqual(machine.post_result, MASK)
                    self.assertEqual(machine.get(QUEUE + 0x10, 4), 0)
                else:
                    self.assertEqual(machine.post_result, 0)
                    self.assertEqual(machine.get(QUEUE + 0x10, 4), MESSAGE)
                    worker = QrMachine(self.image, mode=2)
                    frame = worker.frame(0x870, 0x86C)
                    packet = machine.get(MESSAGE, 8)
                    self.assertEqual(packet, 0)
                    worker.put(frame + 0x820, packet, 8)
                    worker.r[16] = QUEUE_SLOT
                    worker.run_at(WORKER_CASE, WORKER_DONE)
                    self.assertEqual(worker.get(STATUS, 4), MASK - 1)
                    # Supply the worker's completed status before the UI opens.
                    machine.put(STATUS, worker.get(STATUS, 4), 4)
                machine.run_at(CALL_QR, RETURN)
                self.assertEqual(machine.r[2], 0)
                self.assertEqual(machine.get(ALLOCATION + 0x18C, 4), SESSION)
                self.assertEqual(machine.get(STATUS, 4), 1)
                self.assertEqual(machine.get(OWNER_FLAG, 4), 0)


if __name__ == '__main__':
    unittest.main()
