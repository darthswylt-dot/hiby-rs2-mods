#!/usr/bin/env python3
"""Execute a historical-binding/current-ring diagnostic, never native cleanup.

Actual first construction, registration, capture and one-shot CINT preparation
precede the emitted audit. The diagnostic itself only consumes owned CINT,
reads the bounded binding table/current native ring under checked raw R, and
exports owned RIAU. Matching fields are deliberately not an incarnation lease.
"""

import unittest

import reveal_paint_retirement_mips as paint
import reveal_registry_identity_mips as core
import reveal_registry_identity_stage as stage
import reveal_registry_receipt_mips as receipt
import test_reveal_cleanup_intent_mips as cleanup
from test_reveal_cleanup_intent_mips import (
    INTENT, CLEANUP_OUTPUT, SECOND_OUTPUT, LEDGER, RETAINED_MUTEX)
from test_reveal_constructor_capture_mips import (
    DESCRIPTOR, OUTPUT, RESOURCE, NATIVE_CONSTRUCTOR)
from test_reveal_deferred_queue_mips import TRANSPORT_MUTEX, FAULT
from test_reveal_registry_owner_mips import (
    STATE, BIND_STATE, OWNER_STATE, CODE, CONTROLLER, REGISTRY_MUTEX,
    PAINT_MUTEX, RAW_LOCK, RAW_UNLOCK, STACK, RETURN, MASK)


AUDIT_OUTPUT, SECOND_AUDIT_OUTPUT = 0x1F37000, 0x1F37040
NATIVE_DELETE = 0x4395A0


class RegistryIdentityMachine(cleanup.CleanupIntentMachine):
    """Actual emitted audit with explicitly bounded native-delete services."""

    def __init__(self, image, *, max_nodes=64, **options):
        super().__init__(image, **options)
        self.composition = stage.assemble(
            STATE, BIND_STATE, OWNER_STATE, CONTROLLER, REGISTRY_MUTEX,
            PAINT_MUTEX, CODE, self.deferred_list, TRANSPORT_MUTEX, FAULT,
            LEDGER, self.retained_list, RETAINED_MUTEX, INTENT,
            capacity=options.get('capacity', 16),
            owner_capacity=options.get('owner_capacity', 16),
            ticket_limit=options.get('ticket_limit', paint.MAX_TICKET),
            queue_capacity=options.get('queue_capacity', 64),
            transport_capacity=options.get(
                'transport_capacity', self.peek(self.deferred_list + 8)),
            operation_capacity=self.operation_capacity,
            retained_capacity=self.peek(self.retained_list + 8),
            max_nodes=max_nodes)
        self.code = self.code_bytes = self.composition['code']
        self.labels = self.composition['labels']
        for name in ('owner_labels', 'issuer_labels', 'receipt_labels',
                     'adapter_labels', 'capture_labels', 'envelope_labels',
                     'queue_labels', 'constructor_labels', 'retained_labels',
                     'identity_labels'):
            setattr(self, name, self.composition[name])
        self.bridge_labels = self.receipt_labels
        for pc, words in {
                **receipt.hook_words(self.receipt_labels),
                **self.composition['release_hooks'],
                **self.composition['constructor_hooks']}.items():
            for index, word in enumerate(words):
                self.patches[pc + 4 * index] = word
        self.map(AUDIT_OUTPUT, 0x1000)
        self.identity_accesses, self.ring_accesses = [], []
        self.reuse_allocations = {}
        self.reused_allocations, self.delete_services = [], []
        self.clear_events()

    def tracked_access(self, kind, address, size):
        super().tracked_access(kind, address, size)
        if not hasattr(self, 'identity_accesses'):
            return
        event = (kind, self.current_pc, address, size, self.registry_held,
                 self.paint_held, self.transport_held, self.retained_held)
        self.identity_accesses.append(event)
        if (CONTROLLER + 0x34 <= address < CONTROLLER + 0x3C
                or any(node <= address < node + 28
                       for node in self.allocations if node)):
            self.ring_accesses.append(event)

    def allocation(self, size):
        pointer = getattr(self, 'reuse_allocations', {}).pop(size, None)
        if pointer is not None:
            self.reused_allocations.append((size, pointer))
            # Deliberate bounded allocator reuse, not a Python generation or
            # native-link oracle. Actual constructors/registration write it.
            return pointer
        return super().allocation(size)

    def external(self, target):
        if target in (NATIVE_DELETE, 0x8B3F00, 0x8B4220, 0x8B0D20):
            self.calls.append(target)
            self.run_at(target, self.r[31])
            return
        if target in (0xA5B600, 0x8B5BA0, 0xA5B9C0):
            self.calls.append(target)
            self.delete_services.append((target, tuple(self.r[4:8])))
            if target == 0xA5B600:
                def bounded_string(pointer):
                    result = bytearray()
                    for offset in range(1024):
                        value = self.get(pointer + offset, 1)
                        if not value:
                            return bytes(result)
                        result.append(value)
                    raise AssertionError('bounded native strcmp exhausted')

                left, right = map(bounded_string, self.r[4:6])
                result = (left > right) - (left < right)
            elif target == 0xA5B9C0:
                self.freed.append(self.r[4])
                result = 0
            else:
                # Opaque engine+44 widget destructor import. This substitute
                # does not certify native object-graph destruction/retention.
                result = 0
            self.hostile_result(result)
            return
        return super().external(target)

    def clear_events(self):
        super().clear_events()
        for name in ('identity_accesses', 'ring_accesses',
                     'reused_allocations', 'delete_services'):
            if hasattr(self, name):
                getattr(self, name).clear()

    def audit(self, intent=CLEANUP_OUTPUT, output=AUDIT_OUTPUT,
              *, controller=CONTROLLER, stack=STACK, caller=RETURN):
        self.r[29], self.r[31] = stack, caller
        self.r[4:7] = controller, intent, output
        self.run_at(self.identity_labels['audit_identity'], caller)
        return self.r[2], self.r[3]

    def audit_output(self, pointer=AUDIT_OUTPUT):
        return self.words_at(pointer, 16)

    def delete_native(self, name=DESCRIPTOR):
        self.r[29], self.r[31] = STACK, RETURN
        self.r[4:6] = CONTROLLER, name
        self.run_at(NATIVE_DELETE, RETURN)
        return self.r[2], self.r[3]

    def copy_intent(self, destination=SECOND_OUTPUT):
        data, offset = self.region(CLEANUP_OUTPUT, 48)
        self.bytes(destination, bytes(data[offset:offset + 48]))
        return destination


class RegistryIdentityTests(unittest.TestCase):
    setUpClass = classmethod(cleanup.CleanupIntentTests.setUpClass.__func__)
    prepared = cleanup.CleanupIntentTests.prepared
    publish_one = cleanup.CleanupIntentTests.publish_one

    def machine(self, **options):
        return RegistryIdentityMachine(self.image, **options)

    def ready(self, machine):
        engine = self.prepared(machine)
        self.assertEqual(machine.close(), (1, 0))
        self.assertEqual(machine.prepare_cleanup(), (CLEANUP_OUTPUT, 0))
        expected = machine.cleanup_output()[1:]
        node = machine.binding_record()[5]
        machine.clear_events()
        return engine, node, expected

    def assert_result(self, machine, expected, node, engine, count,
                      kind=1, output=AUDIT_OUTPUT):
        self.assertEqual(machine.audit_output(output),
                         (core.OUTPUT_MAGIC, kind, *expected, node, engine, count))
        self.assertEqual(machine.peek(CLEANUP_OUTPUT), core.CONSUMED_MAGIC)

    def assert_read_only_diagnostic(self, machine, *, intent=CLEANUP_OUTPUT,
                                    output=AUDIT_OUTPUT):
        permitted = ((STACK - core.FRAME, core.FRAME), (intent, 4), (output, 64))
        unexpected = [(address, value, size) for address, value, size in machine.writes
                      if not any(start <= address and address + size <= start + length
                                 for start, length in permitted)]
        self.assertEqual(unexpected, [])
        self.assertEqual(machine.freed, [])
        self.assertEqual([(event[0], event[1]) for event in machine.raw_events],
                         [(RAW_LOCK, REGISTRY_MUTEX), (RAW_UNLOCK, REGISTRY_MUTEX)])
        self.assertTrue(machine.ring_accesses)
        self.assertTrue(all(event[0] == 'read' and event[4]
                            and not any(event[5:]) for event in machine.ring_accesses))

    def test_actual_constructor_and_cleanup_request_are_compared_under_checked_r(self):
        m = self.machine()
        engine, node, expected = self.ready(m)
        self.assertEqual(m.audit(), (AUDIT_OUTPUT, 0))
        self.assert_result(m, expected, node, engine, 1)
        self.assert_read_only_diagnostic(m)
        self.assertTrue(m.binding_accesses)
        self.assertTrue(all(event[-2] and not event[-1] for event in m.binding_accesses))

    def test_absent_historical_node_in_empty_native_ring_is_only_diagnostic(self):
        m = self.machine()
        engine, node, expected = self.ready(m)
        m.delete_native()
        self.assertEqual(m.words_at(CONTROLLER + 0x34, 2), (CONTROLLER + 0x34,) * 2)
        m.freed.clear()
        m.clear_events()
        self.assertEqual(m.audit(), (AUDIT_OUTPUT, 0))
        self.assert_result(m, expected, node, 0, 0, kind=2)
        self.assertFalse(any(node <= address < node + 28 for address, _ in m.reads))
        self.assert_read_only_diagnostic(m)

    def test_same_native_node_with_different_engine_exports_scalar_mismatch(self):
        m = self.machine()
        engine, node, expected = self.ready(m)
        m.put(node + 8, engine + 4, 4)
        m.clear_events()
        self.assertEqual(m.audit(), (AUDIT_OUTPUT, 0))
        self.assert_result(m, expected, node, engine + 4, 1, kind=3)
        self.assert_read_only_diagnostic(m)

    def test_zero_observed_engine_is_a_present_node_mismatch_not_absence(self):
        m = self.machine()
        _, node, expected = self.ready(m)
        m.put(node + 8, 0, 4)
        m.clear_events()
        self.assertEqual(m.audit(), (AUDIT_OUTPUT, 0))
        self.assert_result(m, expected, node, 0, 1, kind=3)
        self.assert_read_only_diagnostic(m)

    def test_full_ring_is_scanned_after_the_historical_node_matches(self):
        m = self.machine()
        engine, node, expected = self.ready(m)
        second, _ = m.construct(output=OUTPUT + 48)
        self.assertNotEqual(second, engine)
        second_node = m.binding_record(1)[5]
        m.clear_events()
        self.assertEqual(m.audit(), (AUDIT_OUTPUT, 0))
        self.assert_result(m, expected, node, engine, 2)
        self.assertTrue(any(second_node <= address < second_node + 28
                            for address, _ in m.reads))
        self.assert_read_only_diagnostic(m)

    def test_name_resource_callback_context_and_engine_remain_opaque(self):
        m = self.machine()
        engine, node, expected = self.ready(m)
        name = m.peek(node + 12)
        m.put(node + 12, 0xBAD00000, 4)
        m.clear_events()
        self.assertEqual(m.audit(), (AUDIT_OUTPUT, 0))
        self.assert_result(m, expected, node, engine, 1)
        ranges = ((engine, 84), (RESOURCE, 0x1000), (name, 64), (0xBAD00000, 64))
        self.assertFalse(any(start <= address < start + length
                             for address, _ in m.reads for start, length in ranges))
        self.assertEqual(m.calls, [RAW_LOCK, RAW_UNLOCK])

    def test_consumed_owned_intent_cannot_repeat_the_same_audit(self):
        m = self.machine()
        self.ready(m)
        self.assertEqual(m.audit(), (AUDIT_OUTPUT, 0))
        original = m.audit_output()
        m.clear_events()
        self.assertEqual(m.audit(output=SECOND_AUDIT_OUTPUT), (0, 0))
        self.assertEqual(m.audit_output(), original)
        self.assertEqual(m.audit_output(SECOND_AUDIT_OUTPUT), (0,) * 16)
        self.assertEqual(m.raw_events, [])
        self.assertEqual(m.ring_accesses, [])

    def test_independent_owned_copies_are_not_global_once_or_an_incarnation_token(self):
        m = self.machine()
        engine, node, expected = self.ready(m)
        m.copy_intent()
        self.assertEqual(m.audit(), (AUDIT_OUTPUT, 0))
        self.assertEqual(m.audit(SECOND_OUTPUT, SECOND_AUDIT_OUTPUT),
                         (SECOND_AUDIT_OUTPUT, 0))
        self.assert_result(m, expected, node, engine, 1, output=SECOND_AUDIT_OUTPUT)
        self.assertEqual(m.peek(SECOND_OUTPUT), core.CONSUMED_MAGIC)

    def test_consumption_precedes_raw_r_acquisition(self):
        m = self.machine()
        self.ready(m)
        observed = []

        def observe(machine, target):
            if target == RAW_LOCK:
                observed.append((machine.peek(CLEANUP_OUTPUT),
                                 machine.audit_output(), machine.retained_held,
                                 machine.paint_held, machine.transport_held))

        m.on_service = observe
        self.assertEqual(m.audit(), (AUDIT_OUTPUT, 0))
        self.assertEqual(observed, [(core.CONSUMED_MAGIC, (0,) * 16,
                                     False, False, False)])

    def test_export_follows_raw_zero_release_and_commits_magic_last(self):
        m = self.machine()
        self.ready(m)
        self.assertEqual(m.audit(), (AUDIT_OUTPUT, 0))
        stores = [event for event in m.identity_accesses if event[0] == 'write'
                  and AUDIT_OUTPUT <= event[2] < AUDIT_OUTPUT + 64]
        self.assertEqual([event[2] for event in stores],
                         [AUDIT_OUTPUT + offset for offset in range(4, 64, 4)]
                         + [AUDIT_OUTPUT])
        self.assertTrue(all(not any(event[4:]) for event in stores))
        self.assertLess(m.trace.index(m.identity_labels['raw_release_return']),
                        m.trace.index(m.identity_labels['export_commit']))

    def test_old_cint_does_not_borrow_stale_constructor_or_ledger_sources(self):
        m = self.machine()
        engine, node, expected = self.ready(m)
        for pointer, length in ((OUTPUT, 48), (LEDGER, 64)):
            for offset in range(0, length, 4):
                m.put(pointer + offset, MASK, 4)
        m.clear_events()
        self.assertEqual(m.audit(), (AUDIT_OUTPUT, 0))
        self.assert_result(m, expected, node, engine, 1)
        self.assertFalse(any(pointer <= address < pointer + length
                             for address, _ in m.reads
                             for pointer, length in ((OUTPUT, 48), (LEDGER, 64))))

    def test_current_ring_match_does_not_read_or_call_native_cleanup(self):
        m = self.machine()
        self.ready(m)
        self.assertEqual(m.audit(), (AUDIT_OUTPUT, 0))
        for target in (NATIVE_DELETE, 0x8B4220, 0x8B0D20, 0x8B0760,
                       0x485320, 0x485280, 0x484700, 0x43D4C0,
                       0x43A0C0, 0x485DE0, 0x490980):
            self.assertNotIn(target, m.trace)
            self.assertNotIn(target, m.calls)
        self.assertEqual(m.freed, [])

    def test_matching_fields_after_real_native_delete_and_allocator_aba_is_not_identity(self):
        m = self.machine(capacity=1)
        engine, node, expected = self.ready(m)
        historical_binding = m.binding_record()
        m.delete_native()
        self.assertIn(0x439618, m.trace)  # actual next->prev unlink store
        self.assertIn(0x43961C, m.trace)  # actual prev->next unlink store
        self.assertIn(0x8B4220, m.trace)
        self.assertIn(0x8B0D20, m.trace)
        self.assertIn(engine, m.freed)
        self.assertIn(node, m.freed)
        m.reuse_allocations = {84: engine, 28: node}
        second_engine, second_output = m.construct(output=OUTPUT + 48)
        self.assertEqual((second_engine, second_output), (engine, OUTPUT + 48))
        self.assertEqual(sorted(m.reused_allocations), [(28, node), (84, engine)])
        self.assertEqual(m.binding_header()[0], 1)  # issuer quota denies B
        self.assertEqual(m.binding_record(), historical_binding)
        self.assertEqual(m.constructor_output(OUTPUT + 48)[:8],
                         (int.from_bytes(b'CNFL', 'little'), *([0] * 7)))
        self.assertEqual(m.words_at(CONTROLLER + 0x34, 2), (node, node))
        self.assertEqual(m.peek(node + 8), engine)
        self.assertIn(NATIVE_CONSTRUCTOR, m.trace)
        self.assertIn(0x4389E0, m.trace)
        m.freed.clear()
        m.clear_events()
        self.assertEqual(m.audit(), (AUDIT_OUTPUT, 0))
        self.assert_result(m, expected, node, engine, 1, kind=1)
        self.assert_read_only_diagnostic(m)
        # RIAU is intentionally identical to the old incarnation's scalar
        # comparison: it cannot convey continuous incarnation or safe free.

    def test_absent_old_node_among_other_live_nodes_is_not_dereferenced(self):
        m = self.machine()
        engine, node, expected = self.ready(m)
        m.delete_native()
        m.set_descriptor(b'Other_album\0')
        m.construct(output=OUTPUT + 48)
        other_node = m.binding_record(1)[5]
        self.assertNotEqual(other_node, node)
        m.freed.clear()
        m.clear_events()
        self.assertEqual(m.audit(), (AUDIT_OUTPUT, 0))
        self.assert_result(m, expected, node, 0, 1, kind=2)
        self.assertFalse(any(node <= address < node + 28 for address, _ in m.reads))

    def test_saved_registers_stack_return_and_hilo_survive_hostile_raw_services(self):
        m = self.machine()
        self.ready(m)
        saved = {reg: 0x77200000 + reg for reg in (*range(16, 24), 28, 30)}
        for reg, value in saved.items():
            m.r[reg] = value
        m.hi, m.lo = 0x12345678, 0xABCDEF01
        self.assertEqual(m.audit(), (AUDIT_OUTPUT, 0))
        self.assertEqual({reg: m.r[reg] for reg in saved}, saved)
        self.assertEqual((m.r[29], m.r[31]), (STACK, RETURN))
        self.assertEqual((m.hi, m.lo), (0x12345678, 0xABCDEF01))


if __name__ == '__main__':
    unittest.main()
