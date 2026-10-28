#!/usr/bin/env python3
"""Execute independent historical birth recording, not native liveness.

Actual4389E0 publication and the emitted fresh raw-result gates execute. The
new callback records before any old receipt/issuer quota gate. Its tokens name
historical observations only: there is no unlink observer, current-incarnation
query, allocation retention, cleanup authority or device operation here.
"""

import hashlib
import unittest

from build_reveal_bridge_diag import b
import reveal_creation_capture_mips as capture
import reveal_paint_retirement_mips as owner
import reveal_registry_birth_mips as core
import reveal_registry_birth_stage as stage
import reveal_registry_owner_mips as bindings
import reveal_registry_receipt_mips as receipt
import test_folderfollow_reveal_static_contract as source
from test_reveal_creation_capture_mips import CreationCaptureMachine, OUTPUT
from test_reveal_registry_owner_mips import (
    STATE, CODE, CONTROLLER, INPUT, REGISTRY_MUTEX, PAINT_MUTEX, ENGINE,
    DESCRIPTOR, RAW_LOCK, RAW_UNLOCK, STACK, RETURN, MASK, OWNER_STATE,
    BIND_STATE)


BIRTH, EVENT = 0x1F38000, 0x1F39000


class RegistryBirthMachine(CreationCaptureMachine):
    """Bounded native registration with real emitted callback stores."""

    def __init__(self, image, *, capacity=16, birth_capacity=16,
                 owner_capacity=16, ticket_limit=owner.MAX_TICKET,
                 queue_capacity=64, acquire=0, release=0,
                 paint_acquire_result=0, paint_release_result=0, hooks=True):
        super().__init__(
            image, capacity=capacity, owner_capacity=owner_capacity,
            ticket_limit=ticket_limit, queue_capacity=queue_capacity,
            acquire=acquire, release=release,
            paint_acquire_result=paint_acquire_result,
            paint_release_result=paint_release_result, hooks=False)
        self.composition = stage.assemble(
            STATE, BIND_STATE, OWNER_STATE, CONTROLLER, REGISTRY_MUTEX,
            PAINT_MUTEX, CODE, BIRTH, capacity=capacity,
            birth_capacity=birth_capacity, owner_capacity=owner_capacity,
            ticket_limit=ticket_limit, queue_capacity=queue_capacity)
        self.code = self.code_bytes = self.composition['code']
        self.labels = self.composition['labels']
        for name in ('owner', 'issuer', 'receipt', 'adapter', 'capture', 'birth'):
            setattr(self, name + '_labels', self.composition[name + '_labels'])
        self.bridge_labels = self.receipt_labels
        self.patches = {0x439844: b.addiu(5, 0, owner.ELEMENT_BYTES)}
        if hooks:
            maps = (receipt.hook_words(self.receipt_labels),
                    self.composition['release_hooks'])
            for redirects in maps:
                for pc, words in redirects.items():
                    for index, word in enumerate(words):
                        self.patches[pc + index * 4] = word
        self.birth_capacity = birth_capacity
        self.map(BIRTH, core.memory_bytes(birth_capacity))
        self.map(EVENT, 0x100)
        self.birth_accesses = []
        self.birth_requests = []
        self.clear_events()

    def tracked_access(self, kind, address, size):
        super().tracked_access(kind, address, size)
        if (hasattr(self, 'birth_accesses') and BIRTH <= address
                < BIRTH + core.memory_bytes(self.birth_capacity)):
            self.birth_accesses.append((kind, self.current_pc, address, size,
                                        self.registry_held, self.paint_held))

    def instruction(self, pc):
        if (hasattr(self, 'birth_requests')
                and pc == self.birth_labels['observe']):
            try:
                event = self.words_at(self.r[5], 8)
            except AssertionError:
                event = None
            self.birth_requests.append(event)
        super().instruction(pc)

    def clear_events(self):
        super().clear_events()
        for name in ('birth_accesses', 'birth_requests'):
            if hasattr(self, name):
                getattr(self, name).clear()

    def birth_header(self):
        return self.words_at(BIRTH, core.HEADER_BYTES // 4)

    def birth_record(self, index=0):
        return self.words_at(BIRTH + core.HEADER_BYTES + index * core.RECORD_BYTES,
                             core.RECORD_BYTES // 4)

    def birth_snapshot(self):
        return self.words_at(BIRTH, core.memory_bytes(self.birth_capacity) // 4)

    def write_event(self, words=None, address=EVENT):
        words = ((CONTROLLER, REGISTRY_MUTEX, 1, ENGINE, 3, RETURN, 0x438A5C, 0)
                 if words is None else words)
        if len(words) != 8:
            raise ValueError('a birth event contains exactly eight words')
        for index, word in enumerate(words):
            self.put(address + index * 4, word, 4)
        return address

    def invoke_observe(self, event=EVENT, *, controller=CONTROLLER,
                       stack=STACK, caller=RETURN):
        self.r[29], self.r[31] = stack, caller
        self.r[4], self.r[5] = controller, event
        self.run_at(self.birth_labels['observe'], caller)
        return self.r[2], self.r[3]


class RegistryBirthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = source.SOURCE.read_bytes()
        digest = hashlib.sha256(cls.image).hexdigest()
        if digest != source.SOURCE_SHA256 or len(cls.image) != source.SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: {digest}, size {len(cls.image)}')

    def machine(self, **options):
        return RegistryBirthMachine(self.image, **options)

    def test_actual_native_publication_records_an_independent_historical_token(self):
        m = self.machine()
        self.assertEqual(m.register(), 0)
        node = m.allocations[0]
        self.assertEqual(m.birth_header(), (1, 0, 0, 0))
        self.assertEqual(m.birth_record(), (
            core.RECORD_MAGIC, 1, CONTROLLER, REGISTRY_MUTEX, node, ENGINE,
            STACK - 0x28, RETURN, 0x438A5C, 0))
        self.assertEqual(m.birth_requests, [(
            CONTROLLER, REGISTRY_MUTEX, node, ENGINE, STACK - 0x28,
            RETURN, 0x438A5C, 0)])
        self.assertEqual(m.words_at(node, 7), (CONTROLLER + 0x34,
                                             CONTROLLER + 0x34, *DESCRIPTOR))
        self.assertTrue(all(event[-2] and not event[-1]
                            for event in m.birth_accesses))
        self.assertEqual(m.captured_carriers, [])

    def test_callback_runs_after_final_ring_store_before_first_receipt_access(self):
        m = self.machine()
        boundaries = []

        def inspect(machine, pc):
            if pc == machine.birth_labels['observe']:
                node = machine.allocations[-1]
                boundaries.append((machine.words_at(CONTROLLER + 0x34, 2),
                                   machine.words_at(node, 2),
                                   len(machine.journal_accesses),
                                   len(machine.binding_accesses),
                                   len(machine.owner_accesses)))

        m.on_instruction = inspect
        self.assertEqual(m.register(), 0)
        node = m.allocations[0]
        self.assertEqual(boundaries, [((node, node), (CONTROLLER + 0x34,
                                                     CONTROLLER + 0x34), 0, 0, 0)])

    def test_full_old_receipt_and_binding_quota_does_not_hide_new_native_birth(self):
        m = self.machine(capacity=1, birth_capacity=4)
        self.assertEqual(m.register(), 0)
        receipt_before, binding_before = m.record(), m.binding_record()
        m.clear_events()
        self.assertEqual(m.register(), 0)
        self.assertEqual(m.header(), (1, 0, 0, 0))
        self.assertEqual(m.record(), receipt_before)
        self.assertEqual(m.binding_record(), binding_before)
        self.assertEqual(m.birth_header(), (2, 0, 0, 0))
        self.assertEqual(m.birth_record(1)[1:6],
                         (2, CONTROLLER, REGISTRY_MUTEX, m.allocations[1], ENGINE))
        self.assertEqual(m.paint_events, [])
        self.assertEqual(len(m.allocations), 2)

    def test_existing_old_receipt_fault_does_not_gate_the_independent_callback(self):
        m = self.machine()
        m.put(STATE + receipt.FAULT, 1, 4)
        m.clear_events()
        self.assertEqual(m.register(), 0)
        self.assertEqual(m.birth_header(), (1, 0, 0, 0))
        self.assertEqual(m.header(), (0, 1, 0, 0))
        self.assertEqual(m.issue_requests, [])
        self.assertEqual(m.paint_events, [])

    def test_malformed_old_receipt_prefix_cannot_suppress_a_new_birth(self):
        m = self.machine()
        m.put(STATE + receipt.COUNT, 1, 4)
        m.clear_events()
        self.assertEqual(m.register(), 0)
        self.assertEqual(m.birth_header(), (1, 0, 0, 0))
        self.assertEqual(m.header(), (1, 1, 0, 0))
        self.assertEqual(m.issue_requests, [])

    def test_old_receipt_dirty_target_is_checked_only_after_birth_is_committed(self):
        m = self.machine()
        m.put(STATE + receipt.HEADER_BYTES + receipt.ENGINE, 0xD1A70000, 4)
        m.clear_events()
        self.assertEqual(m.register(), 0)
        self.assertEqual(m.birth_header(), (1, 0, 0, 0))
        self.assertEqual(m.header(), (0, 1, 0, 0))
        self.assertEqual(m.issue_requests, [])

    def test_owner_full_or_closed_does_not_gate_birth_recording(self):
        for case in ('full', 'closed', 'fault'):
            with self.subTest(case=case):
                m = self.machine(owner_capacity=1)
                if case == 'full':
                    self.assertEqual(m.register(), 0)
                else:
                    offset = owner.CLOSED if case == 'closed' else owner.FAULT
                    m.put(OWNER_STATE + offset, 1, 4)
                previous = m.birth_header()[0]
                m.clear_events()
                self.assertEqual(m.register(), 0)
                self.assertEqual(m.birth_header(), (previous + 1, 0, 0, 0))
                self.assertEqual(m.birth_record(previous)[4], m.allocations[-1])

    def test_binding_quarantine_does_not_gate_birth_recording(self):
        m = self.machine()
        m.put(BIND_STATE + bindings.QUARANTINE, 1, 4)
        m.clear_events()
        self.assertEqual(m.register(), 0)
        self.assertEqual(m.birth_header(), (1, 0, 0, 0))
        self.assertEqual(m.binding_header()[0], 0)
        self.assertEqual(m.paint_events, [])

    def test_exhausted_owner_ticket_serial_does_not_suppress_next_birth(self):
        m = self.machine(owner_capacity=2, ticket_limit=1)
        self.assertEqual(m.register(), 0)
        first = m.birth_record()
        self.assertEqual(m.register(), 0)
        self.assertEqual(m.birth_header(), (2, 0, 0, 0))
        self.assertEqual(m.birth_record(), first)
        self.assertEqual(m.birth_record(1)[1], 2)
        self.assertEqual(m.binding_header()[0], 1)
        self.assertEqual(m.owner_state(owner.OWNER_COUNT), 1)

    def test_paint_acquire_and_release_errors_cannot_erase_preceding_birth(self):
        for field in ('paint_acquire_result', 'paint_release_result'):
            for status in (1, 22, 0x82, MASK):
                with self.subTest(field=field, status=status):
                    m = self.machine(**{field: status})
                    self.assertEqual(m.register(), 0)
                    self.assertEqual(m.birth_header(), (1, 0, 0, 0))
                    self.assertEqual(m.birth_record()[-1], 0)
                    self.assertEqual(m.binding_header(), (0, 1, status, 0))

    def test_birth_exhaustion_latches_fault_but_does_not_revoke_old_rows_or_native_success(self):
        m = self.machine(birth_capacity=1)
        self.assertEqual(m.register(), 0)
        first = m.birth_record()
        m.clear_events()
        self.assertEqual(m.register(), 0)
        self.assertEqual(m.birth_header(), (1, 1, 0, 0))
        self.assertEqual(m.birth_record(), first)
        self.assertEqual(m.binding_header()[0], 2)
        self.assertEqual(len(m.allocations), 2)
        self.assertEqual([(address, value) for address, value, _ in m.writes
                          if BIRTH <= address < BIRTH + core.memory_bytes(1)],
                         [(BIRTH + core.FAULT, 1)])

    def test_equal_engine_births_have_distinct_append_only_tokens(self):
        m = self.machine()
        self.assertEqual(m.register(), 0)
        first = m.birth_record()
        self.assertEqual(m.register(), 0)
        self.assertEqual(m.birth_record(), first)
        second = m.birth_record(1)
        self.assertEqual((first[1], second[1]), (1, 2))
        self.assertEqual((first[5], second[5]), (ENGINE, ENGINE))
        self.assertNotEqual(first[4], second[4])

    def test_no_engine_name_mutex_storage_or_cleanup_operation_is_followed(self):
        m = self.machine()
        self.assertEqual(m.register(), 0)
        for address, _ in m.reads:
            for start, size in ((ENGINE, 0x100), (DESCRIPTOR[1], 0x100),
                                (REGISTRY_MUTEX, 24), (PAINT_MUTEX, 24)):
                self.assertFalse(start <= address < start + size)
        self.assertEqual(m.freed, [])
        self.assertFalse(set(m.calls) & {0x4395A0, 0x43CB20, 0x466A80,
                                        0x8B4220, 0x8B3F00})

    def test_birth_commit_writes_body_then_magic_then_monotonic_count(self):
        m = self.machine()
        self.assertEqual(m.register(), 0)
        writes = [(address, value) for address, value, _ in m.writes
                  if BIRTH <= address < BIRTH + core.memory_bytes(m.birth_capacity)]
        self.assertEqual(writes[-2:],
                         [(BIRTH + core.HEADER_BYTES + core.MAGIC, core.RECORD_MAGIC),
                          (BIRTH + core.COUNT, 1)])
        self.assertEqual(len(writes), 12)

    def test_callback_preserves_every_gpr_and_hilo_in_success_and_fault_paths(self):
        for case in ('success', 'fault', 'full', 'bad_schema', 'bad_pointer',
                     'bad_controller'):
            with self.subTest(case=case):
                m = self.machine(birth_capacity=1)
                m.write_event()
                m.registry_held = True
                if case == 'fault':
                    m.put(BIRTH + core.FAULT, 1, 4)
                elif case == 'full':
                    m.invoke_observe()
                elif case == 'bad_schema':
                    m.put(EVENT + core.REQUEST_RAW_STATUS, 22, 4)
                event = EVENT + 1 if case == 'bad_pointer' else EVENT
                controller = CONTROLLER + 4 if case == 'bad_controller' else CONTROLLER
                m.r[:] = [0] + [0x55660000 + register for register in range(1, 32)]
                m.r[29], m.r[31], m.r[4], m.r[5] = STACK, RETURN, controller, event
                m.hi, m.lo = 0x12345678, 0xABCDEF01
                before = m.r.copy(), m.hi, m.lo
                m.registry_held = True
                m.clear_events()
                m.invoke_observe(event, controller=controller)
                self.assertEqual((m.r, m.hi, m.lo), before)
                self.assertEqual(m.raw_events, [])
                self.assertEqual(m.calls, [])

    def test_direct_event_scalar_values_are_historical_not_dereferenced(self):
        m = self.machine()
        event = (CONTROLLER, REGISTRY_MUTEX, 1, MASK, 3, 7, 0x438A5C, 0)
        m.write_event(event)
        m.registry_held = True
        m.clear_events()
        m.invoke_observe()
        self.assertEqual(m.birth_header(), (1, 0, 0, 0))
        self.assertEqual(m.birth_record(), (core.RECORD_MAGIC, 1, *event))
        self.assertFalse(any(address in (1, 3, 7, MASK) for address, _ in m.reads))
        self.assertEqual(m.raw_events, [])

    def test_identical_direct_events_are_distinct_history_not_deduplicated_liveness(self):
        m = self.machine()
        event = m.write_event()
        m.registry_held = True
        m.invoke_observe(event)
        first = m.birth_record()
        m.invoke_observe(event)
        self.assertEqual(m.birth_record(), first)
        self.assertEqual(m.birth_record(1), (core.RECORD_MAGIC, 2, *first[2:]))
        self.assertEqual(m.birth_header(), (2, 0, 0, 0))

    def test_native_allocation_failure_never_reaches_birth_callback(self):
        m = self.machine()
        m.fail_allocation = True
        self.assertEqual(m.register(), MASK)
        self.assertEqual(m.birth_requests, [])
        self.assertEqual(m.birth_accesses, [])
        self.assertEqual(m.birth_header(), (0, 0, 0, 0))
        self.assertTrue(m.registry_held)

    def test_raw_release_error_leaves_history_without_upgrading_to_release_or_liveness_proof(self):
        for status in (1, 22, 0x82, MASK):
            with self.subTest(status=status):
                m = self.machine(release=status)
                boundaries = []

                def at_unlock(machine, target):
                    if target == RAW_UNLOCK and machine.r[4] == REGISTRY_MUTEX:
                        boundaries.append(len(machine.birth_accesses))

                m.on_service = at_unlock
                self.assertEqual(m.invoke_register(), (MASK, status))
                self.assertEqual(m.outwords(), (0,) * 8)
                self.assertEqual(m.birth_header(), (1, 0, 0, 0))
                self.assertEqual(boundaries, [len(m.birth_accesses)])
                self.assertEqual(m.raw_events[-1][-1], status)

    def test_publication_bridge_preserves_displaced_native_register_effects(self):
        m = self.machine()
        snapshots = {}

        def inspect(machine, pc):
            if pc in (0x438A58, 0x438A60):
                snapshots[pc] = machine.r.copy(), machine.hi, machine.lo

        m.on_instruction = inspect
        self.assertEqual(m.register(), 0)
        expected, hi, lo = snapshots[0x438A58]
        expected[25] = 0x437DA0
        self.assertEqual(snapshots[0x438A60], (expected, hi, lo))

    def test_outer_registration_descriptor_and_output_cannot_alias_birth_history(self):
        for field in ('descriptor', 'output'):
            for offset in (0, core.memory_bytes() - 4):
                with self.subTest(field=field, offset=offset):
                    m = self.machine()
                    before = m.birth_snapshot()
                    m.clear_events()
                    self.assertEqual(m.invoke_register(**{field: BIRTH + offset}),
                                     (MASK, 0))
                    self.assertEqual(m.birth_snapshot(), before)
                    self.assertEqual(m.birth_accesses, [])
                    self.assertEqual(m.native_entries, [])
                    self.assertEqual(m.raw_events, [])
                    self.assertEqual(m.writes, [])


if __name__ == '__main__':
    unittest.main()
