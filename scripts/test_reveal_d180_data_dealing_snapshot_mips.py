#!/usr/bin/env python3
"""Exercise the producer's snapshot, queue transfer and refusal cleanup."""

import struct
import unittest
from unittest.mock import patch

import build_reveal_d180_data_dealing_test as build_test
import factory_null_audit as audit
import reveal_d180_data_dealing_snapshot_mips as snapshot
from build_reveal_bridge_diag import BASE
from build_reveal_d960_payload_guard_test import RX_HEADER
from test_factory_d180_data_dealing_continuation import (
    APP_QUEUE, CHARGE_ACTIVITY, CLOSE, COPY_BYTES, DESCRIPTOR, EVENT, OLD_DIALOG, OLD_NAME,
    OPERATION, OTHER_DISPATCH, POLL, POST, QUEUE, QUEUE_DESTROY, QUEUE_RECORD, QUEUE_WRITE,
    SECOND_OPERATION, SECOND_RECORD, WORKER, WORKER_COPY, ChargeTransitionMachine, QueueDisposalMachine,
)
from test_factory_null_audit import CONTEXT, MASK, RETURN, STACK
from test_reveal_d180_book_percent_guard_mips import book_guard_fixture


CODE_BASE = 0xC70EFC
PATCH_SITES = (0x4AEF08, 0x4AEF24, 0x45056C, 0x45431C, 0x450830, 0x453374)
NOTIFY = 0x466D00
TICKS = 0x12345678
PATH_PREFIX = b'worker path fixture\0'


def data_dealing_fixture(image):
    _, baseline = book_guard_fixture(image)
    candidate = build_test.build(baseline)
    patches = {
        pc: (struct.unpack_from('<2I', baseline, pc - BASE),
             struct.unpack_from('<2I', candidate, pc - BASE))
        for pc in PATCH_SITES
    }
    return baseline, candidate, patches


class SnapshotMachine(QueueDisposalMachine):
    def __init__(self, image, **options):
        super().__init__(image, **options)
        self.handoff = []
        self.producer_frame = None
        self.worker_entry = None
        self.alias_at_post = self.queue_status = None

    def external(self, target):
        if target == snapshot.CLOCK:
            self.calls.append(target)
            self.hostile_result(TICKS)
            return
        if target == COPY_BYTES and self.r[6] == len(DESCRIPTOR):
            self.handoff.append(('copy', tuple(self.r[4:7])))
        elif target == QUEUE_WRITE:
            self.alias_at_post = self.get(OLD_DIALOG + 0x58, 4)
            self.handoff.append(('publish', self.get(WORKER + 0x120, 4)))
        elif target == WORKER_COPY:
            self.worker_entry = tuple(self.r[4:8])
        elif target == NOTIFY:
            self.handoff.append(('notify', (self.r[4], self.get(QUEUE + 0x10, 4))))
        super().external(target)
        if target == QUEUE_WRITE:
            self.queue_status = self.r[2]

    def run_at(self, pc, stop):
        if pc == snapshot.POST_SETUP:
            self.producer_frame = self.r[29]
            self.bytes(self.producer_frame + 0xAA8, PATH_PREFIX)
        super().run_at(pc, stop)

    def worker_bytes(self):
        data, offset = self.region(WORKER + 0x140, len(DESCRIPTOR))
        return bytes(data[offset:offset + len(DESCRIPTOR)])


class DataDealingSnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = audit.source_image()
        cls.baseline, cls.candidate, cls.patches = data_dealing_fixture(cls.image)
        cls.code = cls.candidate[len(cls.baseline):]

    def guarded(self):
        return SnapshotMachine(self.image, code=self.code, patches=self.patches, code_base=CODE_BASE)

    def test_patches_match_the_six_native_pairs_and_expected_delays(self):
        code, emitted = snapshot.assemble(CODE_BASE)
        self.assertEqual(code, self.code)
        self.assertEqual(emitted, self.patches)
        changed_delays = {0x4AEF24: 0x27A70020, 0x453374: 0x8E030008}
        for pc, (original, replacement) in self.patches.items():
            self.assertEqual(original, (self.image.word(pc), self.image.word(pc + 4)))
            self.assertEqual(replacement[1], changed_delays.get(pc, original[1]))
        self.assertEqual(self.image.word(0x4AEF10), 0x0C11D0E0)
        self.assertEqual(self.patches[0x4AEF24][1][0], self.image.word(0x4AEF24))

    def test_image_restores_to_the_entire_book_baseline(self):
        self.assertEqual(len(self.baseline), 0x6D0EFC)
        self.assertEqual(len(self.code), 0x2FC)
        self.assertEqual(len(self.candidate), 0x6D11F8)
        self.assertEqual(struct.unpack_from('<8I', self.candidate, RX_HEADER),
                         (1, 0x6D0000, 0xC70000, 0xC70000, 0x11F8, 0x11F8, 5, 0x10000))
        restored = bytearray(self.candidate[:len(self.baseline)])
        restored[RX_HEADER + 16:RX_HEADER + 24] = self.baseline[RX_HEADER + 16:RX_HEADER + 24]
        for pc, (original, _) in self.patches.items():
            struct.pack_into('<2I', restored, pc - BASE, *original)
        self.assertEqual(bytes(restored), self.baseline)
        with self.assertRaisesRegex(ValueError, 'exact book-percent test ELF'):
            build_test.build(self.candidate)

    def test_builder_rejects_a_third_rx_page(self):
        oversized = self.code.ljust(0x2004 - 0xEFC, b'\0')
        with patch.object(snapshot, 'assemble', return_value=(oversized, self.patches)):
            with self.assertRaisesRegex(ValueError, 'final RX page limit'):
                build_test.build(self.baseline)

    def test_builder_rejects_an_unexpected_delay_at_each_redirect(self):
        for pc, (original, replacement) in self.patches.items():
            with self.subTest(pc=hex(pc)):
                patches = {**self.patches, pc: (original, (replacement[0], 0))}
                with patch.object(snapshot, 'assemble', return_value=(self.code, patches)):
                    with self.assertRaisesRegex(ValueError, f'unexpected delay at {pc:#x}'):
                        build_test.build(self.baseline)

    def test_original_buffer_is_copied_before_publish_and_worker_is_notified_after(self):
        machine = self.guarded()
        machine.run_at(POLL, RETURN)
        scratch = machine.producer_frame + snapshot.SNAPSHOT_OFFSET
        count = len(DESCRIPTOR)

        self.assertEqual(machine.handoff, [('copy', (scratch, OPERATION + 0x50, count)),
                                          ('publish', 0),
                                          ('copy', (WORKER + 0x140, scratch, count)),
                                          ('notify', (machine.get(WORKER + 0x14, 4), QUEUE_RECORD))])
        self.assertEqual(machine.worker_bytes(), DESCRIPTOR)
        path = machine.producer_frame + 0xAA8
        self.assertEqual(machine.worker_entry, (WORKER, 2, path, scratch))
        data, offset = machine.region(path, len(PATH_PREFIX))
        self.assertEqual(data[offset:offset + len(PATH_PREFIX)], PATH_PREFIX)
        self.assertEqual(struct.unpack('<5I', machine.regions[QUEUE_RECORD]),
                         (snapshot.OWNED_TAG, EVENT, OPERATION, 0, TICKS))
        self.assertEqual(machine.alias_at_post, 0)
        self.assertEqual(machine.old_alias_at_free, 0)
        self.assertEqual(sum(access == 'read' and address == APP_QUEUE
                             for access, _, address, _ in machine.accesses), 1)
        self.assertNotIn(OPERATION, machine.frees)
        self.assertEqual((machine.r[29], machine.r[31]), (STACK, RETURN))

    def test_ready_full_and_absent_queue_preserve_worker_behavior_on_both_close_paths(self):
        for entry in (POLL, CLOSE):
            for state in ('ready', 'full', 'absent'):
                with self.subTest(entry=hex(entry), state=state):
                    native, guarded = SnapshotMachine(self.image), self.guarded()
                    for machine in (native, guarded):
                        if state == 'full':
                            machine.put(QUEUE + 4, 1, 4)
                        elif state == 'absent':
                            machine.put(APP_QUEUE, 0, 4)
                        machine.stock(entry, OLD_NAME)
                        self.assertEqual(machine.worker_bytes(), DESCRIPTOR)
                        self.assertEqual(machine.get(WORKER + 0x120, 4), 2)
                        self.assertEqual(machine.calls.count(WORKER_COPY), 1)

                    expected_frees = native.frees.copy()
                    if state != 'ready':
                        expected_frees.insert(1, OPERATION)
                    self.assertEqual(guarded.frees, expected_frees)
                    self.assertEqual(guarded.old_alias_at_free, 0)
                    self.assertEqual(guarded.queue_status, native.queue_status)
                    self.assertEqual(guarded.mutex_calls, native.mutex_calls)
                    self.assertEqual(guarded.regions[QUEUE], native.regions[QUEUE])
                    self.assertEqual(guarded.regions[QUEUE_RECORD][4:], native.regions[QUEUE_RECORD][4:])
                    self.assertEqual(guarded.get(QUEUE_RECORD, 4),
                                     snapshot.OWNED_TAG if state == 'ready' else 0)
                    self.assertEqual(guarded.handoff[-1], native.handoff[-1])

    def test_queue_record_allocation_failure_releases_the_request_without_publishing(self):
        machine = self.guarded()
        machine.allocation_result = 0
        queue_before = bytes(machine.regions[QUEUE])
        machine.stock(POLL)

        self.assertEqual(machine.queue_status, MASK)
        self.assertEqual(bytes(machine.regions[QUEUE]), queue_before)
        self.assertEqual(machine.frees.count(OPERATION), 1)
        self.assertEqual(machine.old_alias_at_free, 0)
        self.assertEqual(machine.worker_bytes(), DESCRIPTOR)
        self.assertEqual(machine.handoff[-1], ('notify', (machine.get(WORKER + 0x14, 4), 0)))

    def test_changed_retirement_binding_keeps_the_native_post_and_alias(self):
        for offset, value in ((0x7C, 0x47C740), (0x58, OLD_DIALOG + 0x80)):
            with self.subTest(offset=hex(offset)):
                machine = self.guarded()
                machine.seed_frame(5312, 5)
                machine.r[16:19] = [OLD_DIALOG, OPERATION, CONTEXT]
                machine.put(OLD_DIALOG + offset, value, 4)
                saved_alias = machine.get(OLD_DIALOG + 0x58, 4)
                machine.run_at(snapshot.POST_SETUP, RETURN)

                self.assertIn(POST, machine.calls)
                self.assertEqual(machine.alias_at_post, saved_alias)
                self.assertEqual(machine.get(OLD_DIALOG + 0x58, 4), saved_alias)
                self.assertEqual(machine.frees, [])
                self.assertEqual(machine.worker_bytes(), DESCRIPTOR)
                self.assertEqual(machine.get(QUEUE_RECORD, 4), 0)

    def test_charge_loop_disposes_a_marked_request_after_music_teardown(self):
        machine = ChargeTransitionMachine(self.image, code=self.code, patches=self.patches,
                                          code_base=CODE_BASE)
        machine.frame(56, 0x34)
        machine.r[17:19] = [CONTEXT, CHARGE_ACTIVITY]
        machine.run_at(0x47569C, 0x475834)

        self.assertEqual(machine.dispatches[1], (OTHER_DISPATCH, QUEUE_RECORD, True, 0))
        self.assertEqual(machine.frees[-2:], [QUEUE_RECORD, OPERATION])
        self.assertEqual(machine.frees.count(OPERATION), 1)
        self.assertEqual(machine.get(QUEUE + 0x10, 4), 0)

    def test_alternate_dispatch_does_not_release_ordinary_records_payloads(self):
        for offset, value in ((0, 0), (4, 0xFFFF), (8, 0)):
            with self.subTest(offset=offset):
                machine = self.guarded()
                machine.stock(POLL)
                machine.put(QUEUE_RECORD + offset, value, 4)
                first = len(machine.frees)
                machine.stock(OTHER_DISPATCH, CONTEXT)

                self.assertEqual(machine.frees[first:], [QUEUE_RECORD])
                self.assertEqual(machine.get(QUEUE + 0x10, 4), 0)
                self.assertEqual((machine.r[29], machine.r[31]), (STACK, RETURN))

    def test_shutdown_releases_marked_payload_before_record_and_queue(self):
        machine = self.guarded()
        machine.put(QUEUE, 3, 4)
        machine.stock(POLL)
        machine.map(SECOND_RECORD, 20)
        machine.allocation_result = SECOND_RECORD
        machine.stock(POST, EVENT, SECOND_OPERATION, 0)
        first = len(machine.frees)
        machine.r[16:18] = [0x930000, 0xB90000]
        machine.run_at(0x474880, 0x47489C)

        self.assertEqual(machine.frees[first:], [OPERATION, QUEUE_RECORD, SECOND_RECORD, QUEUE])
        self.assertEqual(machine.get(APP_QUEUE, 4), 0)
        machine.run_at(0x474880, 0x47489C)
        self.assertEqual(machine.frees[first:], [OPERATION, QUEUE_RECORD, SECOND_RECORD, QUEUE])

    def test_shutdown_preserves_ordinary_records_and_other_queue_widths(self):
        for application_queue in (False, True):
            with self.subTest(application_queue=application_queue):
                machine = self.guarded()
                machine.stock(POLL)
                first = len(machine.frees)
                if application_queue:
                    machine.put(QUEUE_RECORD, 0, 4)
                    machine.r[16:18] = [0x930000, 0xB90000]
                    machine.run_at(0x474880, 0x47489C)
                    self.assertEqual(machine.frees[first:], [QUEUE_RECORD, QUEUE])
                else:
                    worker_queue = QUEUE + 0x100
                    machine.map(worker_queue, 0x20)
                    machine.map(SECOND_RECORD, 8)
                    machine.bytes(SECOND_RECORD, struct.pack('<2I', snapshot.OWNED_TAG, EVENT))
                    machine.put(worker_queue, 2, 4)
                    machine.put(worker_queue + 8, 1, 4)
                    machine.put(worker_queue + 0x10, SECOND_RECORD, 4)
                    machine.stock(QUEUE_DESTROY, worker_queue)
                    self.assertEqual(machine.frees[first:], [SECOND_RECORD, worker_queue])
                    self.assertEqual(machine.get(QUEUE + 0x10, 4), QUEUE_RECORD)


if __name__ == '__main__':
    unittest.main()
