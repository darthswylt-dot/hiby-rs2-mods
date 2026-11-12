#!/usr/bin/env python3
"""Exercise Tidal response publication and cleanup with bounded service results."""

import json
import struct
import unittest

import factory_null_audit as audit
from test_factory_d180_qr_continuation import (
    QUEUE_SLOT, RELEASE_RESPONSE, SESSION, SESSION_SLOT, STATUS, WORKER_CASE, QrMachine,
)
from test_factory_null_audit import CONTEXT, MASK, RETURN, STACK


REQUEST_WRAPPER, CLEANUP_WRAPPER = 0x513860, 0x5139C0
HAS_RESPONSE, SAVE_INPUT, NOTIFY = 0x513A40, 0x513520, 0x477180
REQUEST_SERVICE, FOLLOWUP_SERVICE, CLOSE_SERVICE = 0x8BD74C, 0x8BE0F4, 0x8BD9D4
INFO_LOG, ERROR_LOG = 0x466F80, 0x467160
OLD_RESPONSE, NEW_RESPONSE = 0x1D08200, 0x1D08300
OLD_FOLLOWUP, NEW_FOLLOWUP = 0x1D08400, 0x1D08500
RESPONSE_DATA, STATUS_OUT = CONTEXT + 0x100, CONTEXT + 0x80
USER_ID = 123456
COPY_RESPONSE, STRING_SIZE = 0x4B1620, 0xA5B4E0
COPY_OUTPUT, NEW_DATA = CONTEXT + 0x180, CONTEXT + 0x140
COPY_TEXT = b'response fixture'


class TidalResponseMachine(QrMachine):
    def __init__(self, image, *, request_result=NEW_RESPONSE, followup_result=NEW_FOLLOWUP,
                 cleanup_result=0, old_slots=True, **options):
        super().__init__(image, mode=2, **options)
        self.request_result = request_result
        self.followup_result = followup_result
        self.cleanup_result = cleanup_result
        self.service_inputs = []
        self.map(SESSION, 0x40)
        for pointer in (OLD_RESPONSE, NEW_RESPONSE, OLD_FOLLOWUP, NEW_FOLLOWUP):
            self.map(pointer, 0x10)
        self.put(NEW_RESPONSE + 4, USER_ID, 4)
        self.put(NEW_RESPONSE + 8, RESPONSE_DATA, 4)
        self.put(OLD_RESPONSE + 8, RESPONSE_DATA, 4)
        self.put(SESSION + 0x18, OLD_RESPONSE if old_slots else 0, 4)
        self.put(SESSION + 0x1C, OLD_FOLLOWUP if old_slots else 0, 4)
        self.put(SESSION + 0x20, 1, 4)
        self.calls.clear()
        self.writes.clear()

    def external(self, target):
        if target == REQUEST_WRAPPER:
            self.calls.append(target)
            self.run_at(target, self.r[31])
        elif target in (REQUEST_SERVICE, FOLLOWUP_SERVICE, CLOSE_SERVICE):
            self.calls.append(target)
            self.service_inputs.append((target, tuple(self.r[4:7])))
            if target == REQUEST_SERVICE:
                self.put(self.r[6], 200, 4)
                result = self.request_result
            elif target == FOLLOWUP_SERVICE:
                self.put(self.r[6], 17, 4)
                result = self.followup_result
            else:
                result = self.cleanup_result
            self.hostile_result(result)
        elif target in (INFO_LOG, ERROR_LOG, SAVE_INPUT, NOTIFY):
            self.calls.append(target)
            self.hostile_result(0)
        else:
            super().external(target)

    def run_request(self):
        return self.stock(REQUEST_WRAPPER, CONTEXT, CONTEXT + 0x40, STATUS_OUT)

    def slots(self):
        return self.get(SESSION + 0x18, 4), self.get(SESSION + 0x1C, 4)


class TidalCopyMachine(TidalResponseMachine):
    def __init__(self, image, **options):
        super().__init__(image, **options)
        self.bytes(RESPONSE_DATA, COPY_TEXT + b'\0')
        self.bytes(NEW_DATA, b'new\0')
        self.put(NEW_RESPONSE + 8, NEW_DATA, 4)
        self.bytes(COPY_OUTPUT, bytes([0xCC]) * 32)

    def external(self, target):
        if target == STRING_SIZE:
            self.calls.append(target)
            if self.r[4] != RESPONSE_DATA:
                raise AssertionError('unexpected borrowed response data')
            self.hostile_result(len(COPY_TEXT))
        else:
            super().external(target)


class NativeTidalResponseLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = audit.source_image()

    def test_access_inventory_covers_encoded_getter_calls_with_native_words(self):
        path = audit.ROOT / 'notes/folderfollow-tidal-response-access-audit.json'
        document = json.loads(path.read_text(encoding='utf-8'))
        getter = audit.hex_word(document['getter'])
        self.assertEqual(getter, 0x475320)
        self.assertEqual(document['source_sha256'], audit.SOURCE_SHA256)
        expected = set()
        for first, last in self.image.executable_ranges():
            offset = self.image.va_to_off(first)
            data = self.image.data[offset:offset + (last - first) // 4 * 4]
            for index, (word,) in enumerate(struct.iter_unpack('<I', data)):
                if word in ((2 << 26) | (getter >> 2), (3 << 26) | (getter >> 2)):
                    expected.add(first + index * 4)
        callers = document['callers']
        actual = [audit.hex_word(row['callsite']) for row in callers]
        self.assertEqual(len(actual), 41)
        self.assertEqual(len(actual), len(set(actual)))
        self.assertEqual(set(actual), expected)
        for row in callers:
            with self.subTest(callsite=row['callsite']):
                self.assertTrue(row['notes'].strip())
                self.assertIsInstance(row['accesses'], list)
                words = {audit.hex_word(item['pc']): audit.hex_word(item['word'])
                         for item in row['evidence']}
                callsite = audit.hex_word(row['callsite'])
                self.assertIn(callsite, words)
                self.assertIn(callsite + 4, words)
        self.assertEqual(len(document['qr_payload_alias_routes']), 2)
        self.assertEqual(len(document['upper_copy_field_pairs']), 7)
        for pc, word in audit._evidence(document):
            self.assertEqual(word, self.image.word(pc))

    def assert_unwound(self, machine, saved):
        self.assertEqual(machine.r[16:19], saved)
        self.assertEqual((machine.r[29], machine.r[31]), (STACK, RETURN))
        self.assertEqual(machine.get(SESSION_SLOT, 4), SESSION)

    def test_request_refusal_keeps_both_previous_slots(self):
        for old_slots in (False, True):
            with self.subTest(old_slots=old_slots):
                machine = TidalResponseMachine(self.image, request_result=0, old_slots=old_slots)
                before, saved = machine.slots(), machine.r[16:19]
                self.assertEqual(machine.run_request(), MASK - 1)
                self.assertEqual(machine.slots(), before)
                self.assertNotIn(FOLLOWUP_SERVICE, machine.calls)
                self.assertEqual(machine.response_releases, [])
                self.assert_unwound(machine, saved)

    def test_followup_refusal_publishes_response_and_keeps_previous_followup_slot(self):
        for old_slots in (False, True):
            with self.subTest(old_slots=old_slots):
                machine = TidalResponseMachine(self.image, followup_result=0, old_slots=old_slots)
                saved = machine.r[16:19]
                self.assertEqual(machine.run_request(), MASK - 1)
                self.assertEqual(machine.slots(), (NEW_RESPONSE, OLD_FOLLOWUP if old_slots else 0))
                followup_args = next(args for target, args in machine.service_inputs if target == FOLLOWUP_SERVICE)
                self.assertEqual(followup_args[:2], (RESPONSE_DATA, USER_ID))
                self.assertIn(ERROR_LOG, machine.calls)
                self.assertEqual(machine.response_releases, [])
                self.assert_unwound(machine, saved)

    def test_wrapper_publishes_success_without_local_release_of_previous_slots(self):
        machine = TidalResponseMachine(self.image)
        saved = machine.r[16:19]
        self.assertEqual(machine.run_request(), 0)
        self.assertEqual(machine.slots(), (NEW_RESPONSE, NEW_FOLLOWUP))
        self.assertEqual(machine.response_releases, [])
        published = [(address, value) for address, value, size in machine.writes
                     if address in (SESSION + 0x18, SESSION + 0x1C) and size == 4]
        self.assertEqual(published, [(SESSION + 0x18, NEW_RESPONSE), (SESSION + 0x1C, NEW_FOLLOWUP)])
        self.assert_unwound(machine, saved)

    def test_worker_command_zero_saves_input_and_keeps_published_slots(self):
        machine = TidalResponseMachine(self.image)
        frame = machine.frame(0x868, 0x864)
        machine.put(frame + 0x820, 0, 8)
        machine.r[16] = QUEUE_SLOT
        machine.r[19], machine.r[23] = 0x920000, 0x9273A0
        machine.run_at(WORKER_CASE, 0x4544EC)

        self.assertEqual(machine.get(STATUS, 4), 0)
        self.assertEqual(machine.slots(), (NEW_RESPONSE, NEW_FOLLOWUP))
        self.assertIn(SAVE_INPUT, machine.calls)
        self.assertNotIn(CLEANUP_WRAPPER, machine.calls)
        self.assertEqual(machine.response_releases, [])

    def test_disabled_cleanup_returns_minus_one_and_keeps_slots(self):
        machine = TidalResponseMachine(self.image)
        machine.put(SESSION + 0x20, 0, 4)
        before, saved = machine.slots(), machine.r[16:19]
        self.assertEqual(machine.stock(CLEANUP_WRAPPER), MASK)
        self.assertEqual(machine.slots(), before)
        self.assertNotIn(CLOSE_SERVICE, machine.calls)
        self.assertEqual(machine.response_releases, [])
        self.assert_unwound(machine, saved)

    def test_cleanup_success_releases_both_slots_and_clears_them(self):
        machine = TidalResponseMachine(self.image)
        saved = machine.r[16:19]
        self.assertEqual(machine.stock(CLEANUP_WRAPPER), 0)
        self.assertEqual(machine.response_releases, [OLD_RESPONSE, OLD_FOLLOWUP])
        self.assertEqual(machine.slots(), (0, 0))
        self.assertEqual(machine.stock(HAS_RESPONSE), 0)
        self.assertEqual(machine.get(SESSION + 0x20, 4), 1)
        self.assertEqual([(target, args[:2]) for target, args in machine.service_inputs],
                         [(CLOSE_SERVICE, (RESPONSE_DATA, 0))])
        self.assertEqual([target for target in machine.calls if target in (CLOSE_SERVICE, RELEASE_RESPONSE)],
                         [CLOSE_SERVICE, RELEASE_RESPONSE, RELEASE_RESPONSE])
        self.assert_unwound(machine, saved)

    def test_cleanup_failure_releases_slots_and_retains_their_values(self):
        for cleanup_result in (-1, 1):
            with self.subTest(cleanup_result=cleanup_result):
                machine = TidalResponseMachine(self.image, cleanup_result=cleanup_result)
                before, saved = machine.slots(), machine.r[16:19]
                self.assertEqual(machine.stock(CLEANUP_WRAPPER), cleanup_result & MASK)
                self.assertEqual(machine.response_releases, [OLD_RESPONSE, OLD_FOLLOWUP])
                self.assertEqual(machine.slots(), before)
                self.assertEqual(machine.stock(HAS_RESPONSE), 1)
                self.assert_unwound(machine, saved)

    def test_copy_uses_its_original_borrow_after_session_replacement(self):
        machine = TidalCopyMachine(self.image)
        saved = machine.r[16:19]

        def replace_response(pc):
            if pc == 0x4B1650:
                machine.put(SESSION + 0x18, NEW_RESPONSE, 4)

        machine.before_instruction = replace_response
        self.assertEqual(machine.stock(COPY_RESPONSE, COPY_OUTPUT), 0)
        self.assertEqual(machine.get(SESSION + 0x18, 4), NEW_RESPONSE)
        data, offset = machine.region(COPY_OUTPUT, len(COPY_TEXT) + 1)
        self.assertEqual(data[offset:offset + len(COPY_TEXT)], COPY_TEXT)
        self.assertEqual(data[offset + len(COPY_TEXT)], 0xCC)
        self.assert_unwound(machine, saved)


if __name__ == '__main__':
    unittest.main()
