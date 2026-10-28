#!/usr/bin/env python3
"""Execute a one-shot exact-identity cleanup request, never native cleanup.

The actual native constructor produces GCAP; emitted retained operations own
and finish requests; the optional emitted prepare entry reserves a retained
word before the real checked retire/drained barrier and exports owned CINT48.
No native object, callback, detach, destructor or device operation is added.
The native bundle must still be retained by an external cooperating caller.
"""

import unittest

import reveal_paint_retirement_mips as paint
import reveal_registry_receipt_mips as receipt
import reveal_retained_operations_mips as core
import reveal_retained_operations_stage as stage
import test_reveal_retained_operations_mips as retained
from test_reveal_constructor_capture_mips import OUTPUT, RESOURCE
from test_reveal_deferred_queue_mips import TRANSPORT_MUTEX, FAULT, SECOND_STACK
from test_reveal_registry_owner_mips import (
    STATE, BIND_STATE, OWNER_STATE, CODE, CONTROLLER, REGISTRY_MUTEX,
    PAINT_MUTEX, RAW_LOCK, RAW_UNLOCK, STACK, MASK)
from test_reveal_retained_operations_mips import (
    LEDGER, RETAINED_MUTEX, BUNDLE, HEADER_BYTES, OP_BYTES,
    OPEN, CLOSED, QUEUED, PUBLISHED, DONE)


INTENT, CLEANUP_OUTPUT, SECOND_OUTPUT = 0x1F20600, 0x1F36000, 0x1F36030


class CleanupIntentMachine(retained.RetainedOperationsMachine):
    """Only opt in and observe; the emitted code implements every transition."""

    def __init__(self, image, **options):
        super().__init__(image, **options)
        self.composition = stage.assemble(
            STATE, BIND_STATE, OWNER_STATE, CONTROLLER, REGISTRY_MUTEX,
            PAINT_MUTEX, CODE, self.deferred_list, TRANSPORT_MUTEX, FAULT,
            LEDGER, self.retained_list, RETAINED_MUTEX,
            capacity=options.get('capacity', 16),
            owner_capacity=options.get('owner_capacity', 16),
            ticket_limit=options.get('ticket_limit', paint.MAX_TICKET),
            queue_capacity=options.get('queue_capacity', 64),
            transport_capacity=options.get(
                'transport_capacity', self.peek(self.deferred_list + 8)),
            operation_capacity=self.operation_capacity,
            retained_capacity=self.peek(self.retained_list + 8),
            cleanup_intent_address=INTENT)
        self.code = self.code_bytes = self.composition['code']
        self.labels = self.composition['labels']
        for name in ('owner_labels', 'issuer_labels', 'receipt_labels',
                     'adapter_labels', 'capture_labels', 'envelope_labels',
                     'queue_labels', 'constructor_labels', 'retained_labels'):
            setattr(self, name, self.composition[name])
        self.bridge_labels = self.receipt_labels
        for pc, words in {
                **receipt.hook_words(self.receipt_labels),
                **self.composition['release_hooks'],
                **self.composition['constructor_hooks']}.items():
            for index, word in enumerate(words):
                self.patches[pc + 4 * index] = word
        self.map(INTENT, 4)
        self.map(CLEANUP_OUTPUT, 0x1000)
        self.intent_accesses, self.intent_output_accesses = [], []
        self.clear_events()

    def tracked_access(self, kind, address, size):
        super().tracked_access(kind, address, size)
        if not hasattr(self, 'intent_accesses'):
            return
        event = (kind, self.current_pc, address, size, self.retained_held,
                 self.registry_held, self.paint_held, self.transport_held)
        if INTENT <= address < INTENT + 4:
            self.intent_accesses.append(event)
        if (hasattr(self, 'intent_output_accesses')
                and CLEANUP_OUTPUT <= address < CLEANUP_OUTPUT + 0x1000):
            self.intent_output_accesses.append(event)

    def clear_events(self):
        super().clear_events()
        for name in ('intent_accesses', 'intent_output_accesses'):
            if hasattr(self, name):
                getattr(self, name).clear()

    def prepare_cleanup(self, output=CLEANUP_OUTPUT, **options):
        return self.invoke_retained('prepare_cleanup', output, **options)

    def cleanup_output(self, pointer=CLEANUP_OUTPUT):
        return self.words_at(pointer, 12)


class CleanupIntentTests(unittest.TestCase):
    setUpClass = classmethod(retained.RetainedOperationsTests.setUpClass.__func__)
    prepared = retained.RetainedOperationsTests.prepared
    publish_one = retained.RetainedOperationsTests.publish_one

    def machine(self, **options):
        return CleanupIntentMachine(self.image, **options)

    def closed_empty(self, machine):
        self.prepared(machine)
        self.assertEqual(machine.close(), (1, 0))
        machine.clear_events()

    def assert_request(self, machine, expected, pointer=CLEANUP_OUTPUT):
        self.assertEqual(machine.cleanup_output(pointer),
                         (core.CLEANUP_INTENT_MAGIC, *expected))
        self.assertEqual(machine.peek(INTENT), 1)
        self.assertEqual(machine.freed, [])
        self.assertEqual(machine.captured_carriers, [])

    def assert_no_barrier(self, machine):
        self.assertNotIn(machine.retained_labels['quiescent'], machine.trace)
        self.assertNotIn(machine.owner_labels['retire'], machine.trace)
        self.assertNotIn(machine.owner_labels['drained'], machine.trace)

    def test_actual_constructor_operation_ack_then_exact_cleanup_request(self):
        m = self.machine()
        self.publish_one(m)
        expected = m.ledger_header()[4:15]
        self.assertEqual(m.claim()[1], 2)
        self.assertEqual(m.complete(2), (1, 0))
        self.assertEqual(m.operation(), (1, DONE, 2, 0))
        self.assertEqual(m.close(), (1, 0))
        m.clear_events()
        self.assertEqual(m.prepare_cleanup(), (CLEANUP_OUTPUT, 0))
        self.assert_request(m, expected)
        self.assertIn(m.retained_labels['quiescent'], m.trace)
        self.assertIn(m.owner_labels['retire'], m.trace)
        self.assertIn(m.owner_labels['drained'], m.trace)
        self.assertEqual(m.owner_record()[2], 1)

    def test_closed_bound_bundle_without_operations_can_request_cleanup(self):
        m = self.machine()
        self.closed_empty(m)
        expected = m.ledger_header()[4:15]
        self.assertEqual(m.prepare_cleanup(), (CLEANUP_OUTPUT, 0))
        self.assert_request(m, expected)
        self.assertEqual(m.ledger_header()[2], 0)

    def test_open_bundle_refuses_without_consuming_the_sole_attempt(self):
        m = self.machine()
        self.prepared(m)
        m.clear_events()
        self.assertEqual(m.prepare_cleanup(), (0, 0))
        self.assertEqual(m.peek(INTENT), 0)
        self.assertEqual(m.cleanup_output(), (0,) * 12)
        self.assertEqual(m.ledger_header()[0], OPEN)
        self.assert_no_barrier(m)
        self.assertEqual(m.close(), (1, 0))
        self.assertEqual(m.prepare_cleanup(), (CLEANUP_OUTPUT, 0))

    def test_queued_operation_requires_exact_cancel_before_reservation(self):
        m = self.machine()
        self.prepared(m)
        self.assertEqual(m.enqueue(), (1, 0))
        self.assertEqual(m.close(), (1, 0))
        m.clear_events()
        self.assertEqual(m.prepare_cleanup(), (0, 0))
        self.assertEqual(m.peek(INTENT), 0)
        self.assertEqual(m.operation(), (1, QUEUED, 0, 0))
        self.assert_no_barrier(m)
        self.assertEqual(m.pop_dispatch(), (0, 0))
        self.assertEqual(m.operation(), (1, DONE, 0, 0))
        self.assertEqual(m.prepare_cleanup(), (CLEANUP_OUTPUT, 0))

    def test_published_and_claimed_work_cannot_reserve_until_exact_ack(self):
        for claimed in (False, True):
            with self.subTest(claimed=claimed):
                m = self.machine()
                self.publish_one(m)
                if claimed:
                    self.assertEqual(m.claim()[1], 2)
                self.assertEqual(m.close(), (1, 0))
                m.clear_events()
                self.assertEqual(m.prepare_cleanup(), (0, 0))
                self.assertEqual(m.peek(INTENT), 0)
                self.assertEqual(m.operation(), (1, PUBLISHED, 2, 0))
                self.assert_no_barrier(m)
                if not claimed:
                    self.assertEqual(m.claim()[1], 2)
                self.assertEqual(m.complete(2), (1, 0))
                self.assertEqual(m.prepare_cleanup(), (CLEANUP_OUTPUT, 0))

    def test_failed_render_terminal_ack_still_exports_the_exact_context(self):
        m = self.machine()
        self.publish_one(m)
        expected = m.ledger_header()[4:15]
        m.claim()
        self.assertEqual(m.complete(2, 0), (2, 0))
        self.assertEqual(m.close(), (1, 0))
        self.assertEqual(m.prepare_cleanup(), (CLEANUP_OUTPUT, 0))
        self.assert_request(m, expected)

    def test_identical_operation_clones_must_both_finish_before_request(self):
        m = self.machine()
        self.prepared(m)
        for token in (1, 2):
            self.assertEqual(m.enqueue(), (token, 0))
        self.assertEqual(m.pop_dispatch(), (2, 0))
        self.assertEqual(m.pop_dispatch(), (3, 1))
        self.assertEqual(m.close(), (1, 0))
        m.claim()
        self.assertEqual(m.complete(2), (1, 0))
        self.assertEqual(m.prepare_cleanup(), (0, 0))
        self.assertEqual(m.peek(INTENT), 0)
        m.claim()
        self.assertEqual(m.complete(3), (1, 0))
        self.assertEqual(m.prepare_cleanup(), (CLEANUP_OUTPUT, 0))

    def test_duplicate_request_refuses_before_checked_paint_barrier(self):
        m = self.machine()
        self.closed_empty(m)
        self.assertEqual(m.prepare_cleanup(), (CLEANUP_OUTPUT, 0))
        original = m.cleanup_output()
        m.clear_events()
        self.assertEqual(m.prepare_cleanup(SECOND_OUTPUT), (0, 0))
        self.assertEqual(m.cleanup_output(), original)
        self.assertEqual(m.cleanup_output(SECOND_OUTPUT), (0,) * 12)
        self.assertEqual(m.peek(INTENT), 1)
        self.assert_no_barrier(m)
        self.assertEqual([(e[0], e[1]) for e in m.raw_events],
                         [(RAW_LOCK, RETAINED_MUTEX), (RAW_UNLOCK, RETAINED_MUTEX)])

    def test_request_uses_owned_binding_not_stale_constructor_or_bundle_sources(self):
        m = self.machine()
        self.closed_empty(m)
        expected = m.ledger_header()[4:15]
        for pointer, length in ((BUNDLE, 44), (OUTPUT, 48)):
            for offset in range(0, length, 4):
                m.put(pointer + offset, MASK, 4)
        m.clear_events()
        self.assertEqual(m.prepare_cleanup(), (CLEANUP_OUTPUT, 0))
        self.assert_request(m, expected)
        self.assertFalse(any(pointer <= address < pointer + length
                             for address, _ in m.reads
                             for pointer, length in ((BUNDLE, 44), (OUTPUT, 48))))

    def test_resource_callback_and_context_stay_opaque_even_in_export(self):
        m = self.machine()
        self.prepared(m, bind=False)
        opaque = (0, 0xBAD00000, MASK)
        m.copy_bundle(opaque=opaque)
        self.assertEqual(m.bind(), (1, 0))
        self.assertEqual(m.close(), (1, 0))
        expected = m.ledger_header()[4:15]
        m.clear_events()
        self.assertEqual(m.prepare_cleanup(), (CLEANUP_OUTPUT, 0))
        self.assert_request(m, expected)
        self.assertEqual(m.cleanup_output()[-3:], opaque)
        self.assertFalse(any(address in opaque for address, _ in m.reads))
        self.assertNotIn(opaque[1], m.calls)

    def test_output_body_is_written_before_the_single_committing_magic(self):
        m = self.machine()
        self.closed_empty(m)
        self.assertEqual(m.prepare_cleanup(), (CLEANUP_OUTPUT, 0))
        writes = [(address, value, size) for address, value, size in m.writes
                  if CLEANUP_OUTPUT <= address < CLEANUP_OUTPUT + 48]
        self.assertEqual([address for address, _, _ in writes],
                         [CLEANUP_OUTPUT + offset for offset in range(4, 48, 4)]
                         + [CLEANUP_OUTPUT])
        self.assertEqual(writes[-1],
                         (CLEANUP_OUTPUT, core.CLEANUP_INTENT_MAGIC, 4))

    def test_reservation_is_guarded_and_no_paint_lock_is_nested_under_m(self):
        m = self.machine()
        self.closed_empty(m)
        observations = []

        def observe(machine, target):
            if machine.r[4] in (REGISTRY_MUTEX, PAINT_MUTEX):
                observations.append(machine.retained_held)

        m.on_service = observe
        self.assertEqual(m.prepare_cleanup(), (CLEANUP_OUTPUT, 0))
        self.assertTrue(m.intent_accesses)
        self.assertTrue(all(e[4] and not any(e[5:]) for e in m.intent_accesses))
        self.assertTrue(observations)
        self.assertFalse(any(observations))
        self.assertTrue(all(not any(e[4:]) for e in m.intent_output_accesses
                            if e[0] == 'write'))
        self.assertEqual([e[1] for e in m.raw_events],
                         [RETAINED_MUTEX] * 4 + [PAINT_MUTEX] * 4)

    def test_independent_cpu_loser_refuses_after_reserve_before_any_barrier(self):
        m = self.machine()
        self.closed_empty(m)
        second = m.fork_cpu('cleanup-loser')
        observations = []

        def compete(machine, pc):
            if pc == machine.retained_labels['before_cleanup_intent_barrier']:
                self.assertEqual(machine.peek(INTENT), 1)
                self.assertFalse(machine.retained_held)
                observations.append(second.prepare_cleanup(
                    SECOND_OUTPUT, stack=SECOND_STACK))
                self.assert_no_barrier(second)

        m.on_instruction = compete
        self.assertEqual(m.prepare_cleanup(), (CLEANUP_OUTPUT, 0))
        self.assertEqual(observations, [(0, 0)])
        self.assertEqual(second.cleanup_output(SECOND_OUTPUT), (0,) * 12)

    def test_independent_cpu_loser_refuses_after_barrier_before_export(self):
        m = self.machine()
        self.closed_empty(m)
        second = m.fork_cpu('late-cleanup-loser')
        observations = []

        def compete(machine, pc):
            if pc == machine.retained_labels['before_cleanup_intent_output']:
                self.assertEqual(machine.cleanup_output(), (0,) * 12)
                observations.append(second.prepare_cleanup(
                    SECOND_OUTPUT, stack=SECOND_STACK))
                self.assert_no_barrier(second)

        m.on_instruction = compete
        self.assertEqual(m.prepare_cleanup(), (CLEANUP_OUTPUT, 0))
        self.assertEqual(observations, [(0, 0)])
        self.assertEqual(second.cleanup_output(SECOND_OUTPUT), (0,) * 12)

    def test_no_native_cleanup_lookup_callback_or_free_is_executed(self):
        m = self.machine()
        engine = self.prepared(m)
        self.assertEqual(m.close(), (1, 0))
        m.clear_events()
        self.assertEqual(m.prepare_cleanup(), (CLEANUP_OUTPUT, 0))
        for address in (0x4395A0, 0x8B4220, 0x8B0D20, 0x8B0760,
                        0x485320, 0x485280, 0x484700, 0x43D4C0,
                        0x43A0C0, 0x485DE0, 0x490980):
            self.assertNotIn(address, m.trace)
            self.assertNotIn(address, m.calls)
        self.assertFalse(any(start <= address < start + length
                             for address, _ in m.reads
                             for start, length in ((engine, 84), (RESOURCE, 0x1000))))
        self.assertEqual(m.freed, [])


if __name__ == '__main__':
    unittest.main()
