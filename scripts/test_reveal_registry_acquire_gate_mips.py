#!/usr/bin/env python3
"""Execute two bounded raw-acquisition vetoes, never caller isolation.

Actual native prologues, receipt/retirement dispatch, registration, deletion
and FIFO/history consumers run. Native and extra save frames are genuinely
retained here; no test pretends an invalid frame can be safely unwound.
Raw pthread and opaque graph cleanup retain the earlier bounded substitutes.
"""

import unittest

import reveal_registry_acquire_gate_mips as core
import reveal_registry_acquire_gate_stage as stage
import reveal_registry_lifecycle_mips as lifecycle
import reveal_registry_receipt_mips as receipt
import reveal_registry_retirement_mips as retirement
import test_reveal_birth_consumer_mips as previous
from test_reveal_birth_consumer_mips import (
    BirthConsumerMachine, QUEUE, TRANSPORT_MUTEX, FAULT, SOURCE, OUTPUT,
    LIFECYCLE, ENGINE, NAME, NATIVE_DELETE, CONTROLLER, REGISTRY_MUTEX,
    PAINT_MUTEX, CODE, INPUT, STATE, BIND_STATE, OWNER_STATE,
    RAW_LOCK, RAW_UNLOCK, STACK, RETURN, MASK)


class RegistryAcquireGateMachine(BirthConsumerMachine):
    """Existing emitted diagnostics plus two coherent native fixture redirects."""

    def __init__(self, image, **options):
        super().__init__(image, **options)
        selected = {name: options[name] for name in (
            'capacity', 'lifecycle_capacity', 'owner_capacity', 'ticket_limit',
            'queue_capacity') if name in options}
        self.composition = stage.assemble(
            STATE, BIND_STATE, OWNER_STATE, CONTROLLER, REGISTRY_MUTEX,
            PAINT_MUTEX, CODE, LIFECYCLE, QUEUE, TRANSPORT_MUTEX, FAULT,
            transport_capacity=self.peek(QUEUE + 8), **selected)
        self.code = self.code_bytes = self.composition['code']
        self.labels = self.composition['labels']
        for name in ('owner', 'issuer', 'receipt', 'adapter', 'capture',
                     'lifecycle', 'retirement', 'birth_capture', 'birth_queue',
                     'birth_consumer', 'acquire_gate'):
            setattr(self, name + '_labels', self.composition[name + '_labels'])
        self.bridge_labels = self.receipt_labels
        for pc, words in self.composition['coherent_hooks'].items():
            for index, word in enumerate(words):
                self.patches[pc + 4 * index] = word
        self.clear_events()

    def instruction(self, pc):
        super().instruction(pc)
        if pc == core.ALLOCATOR:
            # The emitted gate tail-transfers with the original JAL's RA.
            # Use the SAME bounded allocator substitute as a linked native
            # call, not a second allocation or a host reconstruction.
            self.external(core.ALLOCATOR)

    def word(self, pc):
        if pc == core.ALLOCATOR:
            return 0x03E00008
        if pc == core.ALLOCATOR + 4:
            return 0
        return super().word(pc)

    def remove_pair(self, pc):
        self.patches.pop(pc, None)
        self.patches.pop(pc + 4, None)

    def invoke_gate_route(self, route):
        if route == 'register_gate':
            self.register()
            return self.r[2], self.r[3]
        if route == 'delete_gate':
            return self.delete_native()
        raise ValueError('unknown native gate route')


class RegistryAcquireGateTests(unittest.TestCase):
    setUpClass = classmethod(previous.BirthConsumerTests.setUpClass.__func__)
    prepared = previous.BirthConsumerTests.prepared
    queued = previous.BirthConsumerTests.queued
    expected = previous.BirthConsumerTests.expected

    def machine(self, **options):
        return RegistryAcquireGateMachine(self.image, **options)

    def test_actual_registration_gate_admits_birth_before_native_allocation(self):
        m = self.machine()
        self.assertEqual(m.register(), 0)
        node = m.allocations[-1]
        self.assertEqual(m.lifecycle_header(), (1, 0, 0, 0))
        self.assertEqual(m.lifecycle_record()[4:6], (node, ENGINE))
        self.assertEqual(m.words_at(CONTROLLER + 0x34, 2), (node, node))
        ordered = (m.acquire_gate_labels['register_gate'], core.ALLOCATOR,
                   core.ALLOCATOR_RETURN, m.receipt_labels['published'])
        self.assertEqual([m.trace.index(pc) for pc in ordered],
                         sorted(m.trace.index(pc) for pc in ordered))
        self.assertEqual(m.calls.count(core.ALLOCATOR), 1)
        self.assertFalse(m.registry_held)

    def test_actual_delete_gate_admits_retirement_and_native_unlink(self):
        m = self.machine()
        self.assertEqual(m.register(), 0)
        node = m.allocations[-1]
        m.clear_events()
        m.delete_native()
        self.assertEqual(m.lifecycle_record()[10:12],
                         (lifecycle.RETIREMENT_SELECTED, 0x439618))
        self.assertIn(node, m.freed)
        self.assertEqual(m.words_at(CONTROLLER + 0x34, 2),
                         (CONTROLLER + 0x34,) * 2)
        self.assertLess(m.trace.index(m.acquire_gate_labels['delete_gate']),
                        m.trace.index(m.retirement_labels['delete_frontier']))
        self.assertEqual([(event[0], event[1]) for event in m.raw_events], [
            (RAW_LOCK, REGISTRY_MUTEX), (RAW_UNLOCK, REGISTRY_MUTEX)])

    def test_raw_zero_still_exports_exact_bcap_fifo_and_bobs(self):
        m = self.machine()
        queued = self.queued(m)
        row = m.lifecycle_record()
        self.assertEqual(m.take(), (OUTPUT, 0))
        self.assertEqual(m.consumer_words(), self.expected(queued, row))
        self.assertEqual(m.transport_count(), 0)
        self.assertEqual(m.paint_events, [])

    def test_positive_gate_restores_all_gprs_hilo_before_displaced_effects(self):
        for route in ('register_gate', 'delete_gate'):
            for populated in (False, True):
                with self.subTest(route=route, populated=populated):
                    m = self.machine()
                    if populated:
                        self.assertEqual(m.register(), 0)
                    snapshots = {}

                    def observe(machine, pc):
                        for name in (route, route + '_replay'):
                            if pc == machine.acquire_gate_labels[name]:
                                snapshots[name] = (machine.r.copy(),
                                                   machine.hi, machine.lo)

                    m.on_instruction = observe
                    m.invoke_gate_route(route)
                    self.assertEqual(set(snapshots), {route, route + '_replay'})
                    self.assertEqual(snapshots[route + '_replay'], snapshots[route])

    def test_registration_replays_allocator_argument_and_original_return_pc(self):
        m = self.machine()
        observations = []

        def observe(machine, pc):
            if pc == core.ALLOCATOR:
                observations.append((machine.r[4], machine.r[31],
                                     machine.r[29], machine.registry_held))

        m.on_instruction = observe
        self.assertEqual(m.register(), 0)
        self.assertEqual(observations,
                         [(28, 0x438A18, STACK - 40, True)])

    def test_delete_replays_taken_and_empty_branch_with_delay_load_exactly_once(self):
        for populated in (False, True):
            with self.subTest(populated=populated):
                m = self.machine()
                if populated:
                    self.assertEqual(m.register(), 0)
                first = m.peek(CONTROLLER + 0x34)
                next_node = m.peek(first)
                destination = (core.DELETE_TAKEN if populated
                               else core.DELETE_FALLTHROUGH)
                branch_pc = m.acquire_gate_labels['delete_gate_replay_branch']
                loads = []

                def observe_access(kind, address, size):
                    if (kind == 'read' and m.current_pc == branch_pc
                            and address == first and size == 4):
                        loads.append(address)

                original = m.tracked_access

                def tracked(kind, address, size):
                    observe_access(kind, address, size)
                    original(kind, address, size)

                m.tracked_access = tracked
                m.r[29], m.r[31] = STACK, RETURN
                m.r[4:6] = CONTROLLER, NAME
                m.clear_events()
                m.run_at(NATIVE_DELETE, destination)
                self.assertEqual(loads, [first])
                self.assertEqual((m.r[16], m.r[17]), (first, next_node))
                self.assertNotIn(0x4395DC, m.trace)
                self.assertTrue(m.registry_held)

    def test_success_leaves_fresh_witness_for_existing_publication_and_retirement(self):
        m = self.machine()
        observed = []

        def observe(machine, pc):
            if pc == machine.acquire_gate_labels['register_gate_replay']:
                observed.append(machine.words_at(machine.r[29] + receipt.TAG, 3))
            if pc == machine.acquire_gate_labels['delete_gate_replay']:
                observed.append(machine.words_at(machine.r[29] + retirement.TAG, 2))

        m.on_instruction = observe
        self.assertEqual(m.register(), 0)
        m.delete_native()
        self.assertEqual(observed, [(receipt.CAPTURED, REGISTRY_MUTEX, 0),
                                    (retirement.CAPTURED, 0)])
        self.assertEqual(m.lifecycle_header(), (1, 0, 0, 0))
        self.assertEqual(m.lifecycle_record()[10], lifecycle.RETIREMENT_SELECTED)

    def test_observed_delete_and_real_node_reuse_mint_new_exact_token(self):
        m = self.machine(capacity=1, lifecycle_capacity=3)
        self.assertEqual(m.register_birth(), (0, SOURCE))
        first = m.birth_output()
        node = first[4]
        m.delete_native()
        old_row = m.lifecycle_record()
        m.reuse_node = node
        self.assertEqual(m.register_birth(output=SOURCE + 48), (0, SOURCE + 48))
        self.assertEqual(m.birth_output(SOURCE + 48)[1:6],
                         (2, CONTROLLER, REGISTRY_MUTEX, node, ENGINE))
        self.assertEqual(m.birth_output(), first)
        self.assertEqual(m.lifecycle_record(), old_row)
        self.assertEqual(m.reused_nodes, [node])

    def test_native_allocation_failure_still_has_original_missing_unlock(self):
        m = self.machine()
        m.fail_allocation = True
        self.assertEqual(m.register_birth(), (MASK, 0))
        self.assertEqual(m.birth_output(), (0,) * 12)
        self.assertEqual(m.lifecycle_header(), (0, 0, 0, 0))
        self.assertEqual([event[0] for event in m.raw_events], [RAW_LOCK])
        self.assertTrue(m.registry_held)

    def test_admitted_allocator_failure_keeps_unstandardized_native_v1(self):
        m = self.machine()
        m.fail_allocation = True
        self.assertEqual(m.register(), MASK)
        # The existing allocator substitute deliberately clobbers caller-saved
        # V1. A passed gate does not normalize later native error returns into
        # a new raw-status ABI; only a gate-denial path defines its diagnostic.
        self.assertEqual(m.r[3], 0xBAD00003)
        self.assertEqual([event[0] for event in m.raw_events], [RAW_LOCK])
        self.assertTrue(m.registry_held)
        self.assertNotIn(m.acquire_gate_labels['register_gate_denied'], m.trace)

    def test_gates_do_not_fix_later_capacity_or_faulted_history_missing_events(self):
        for failure in ('full', 'fault'):
            with self.subTest(failure=failure):
                m = self.machine(lifecycle_capacity=1)
                self.assertEqual(m.register_birth(), (0, SOURCE))
                if failure == 'fault':
                    m.put(LIFECYCLE + lifecycle.FAULT, 1, 4)
                first = m.birth_output()
                self.assertEqual(m.register_birth(output=SOURCE + 48), (0, 0))
                self.assertEqual(m.birth_output(), first)
                self.assertEqual(m.birth_output(SOURCE + 48), (0,) * 12)
                self.assertEqual(m.lifecycle_header(), (1, 1, 0, 0))
                self.assertEqual(len(m.allocations), 2)


if __name__ == '__main__':
    unittest.main()
