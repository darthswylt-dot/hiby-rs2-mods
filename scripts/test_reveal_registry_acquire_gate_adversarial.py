#!/usr/bin/env python3
"""Bounded gate refusals do not authenticate frames or isolate native callers."""

import unittest

import reveal_registry_acquire_gate_mips as core
import reveal_registry_lifecycle_mips as lifecycle
import reveal_registry_receipt_mips as receipt
import reveal_registry_retirement_mips as retirement
import test_reveal_registry_acquire_gate_mips as fixture
from test_reveal_registry_acquire_gate_mips import (
    RegistryAcquireGateMachine, CONTROLLER, REGISTRY_MUTEX, SOURCE,
    INPUT, ENGINE, STACK, RETURN, MASK, RAW_LOCK, RAW_UNLOCK)


class RegistryAcquireGateAdversarialTests(unittest.TestCase):
    setUpClass = classmethod(fixture.RegistryAcquireGateTests.setUpClass.__func__)

    def machine(self, **options):
        return RegistryAcquireGateMachine(self.image, **options)

    def snapshot(self, machine):
        sentinel = CONTROLLER + 0x34
        return (machine.words_at(sentinel, 2), machine.lifecycle_snapshot(),
                machine.header(), machine.binding_header(), machine.owner_header(),
                tuple(machine.allocations), tuple(machine.freed),
                machine.transport_count())

    def watch_denial(self, machine, route, mutation=None):
        marks = []

        def observe(current, pc):
            if pc == current.acquire_gate_labels[route]:
                if mutation is not None:
                    mutation(current)
                marks.append((len(current.reads), len(current.writes),
                              len(current.calls), current.r[29]))

        machine.on_instruction = observe
        return marks

    def assert_private_after_gate(self, machine, marks, route):
        self.assertEqual(len(marks), 1)
        reads, writes, calls, native_sp = marks[0]
        frame = core.REGISTER_FRAME if route == 'register_gate' else core.DELETE_FRAME
        first, end = native_sp - core.FRAME, native_sp + frame
        self.assertEqual(machine.calls[calls:], [])
        self.assertTrue(all(first <= address and address + size <= end
                            for address, size in machine.reads[reads:]))
        self.assertTrue(all(first <= address and address + size <= end
                            for address, _, size in machine.writes[writes:]))

    def test_each_captured_raw_error_refuses_both_native_routes_without_unlock(self):
        for route in ('register_gate', 'delete_gate'):
            for status in (1, 22, 0x82, MASK):
                for held in (False, True):
                    with self.subTest(route=route, status=status, held=held):
                        m = self.machine()
                        if route == 'delete_gate':
                            self.assertEqual(m.register(), 0)
                        before = self.snapshot(m)
                        m.acquire = status
                        m.registry_acquire_failure_holds = held
                        m.clear_events()
                        marks = self.watch_denial(m, route)
                        self.assertEqual(m.invoke_gate_route(route), (MASK, status))
                        self.assert_private_after_gate(m, marks, route)
                        self.assertEqual(self.snapshot(m), before)
                        self.assertEqual(m.registry_held, held)
                        self.assertEqual([(event[0], event[1]) for event in m.raw_events],
                                         [(RAW_LOCK, REGISTRY_MUTEX)])
                        self.assertEqual(m.lifecycle_accesses, [])
                        self.assertEqual(m.cleanup_services, [])

    def test_nonzero_native_v1_is_not_preserved_by_older_bcap_wrapper(self):
        for status in (1, 22, 0x82, MASK):
            with self.subTest(status=status):
                m = self.machine(acquire=status)
                self.assertEqual(m.register_birth(), (MASK, 0))
                self.assertEqual(m.birth_output(), (0,) * 12)
                self.assertEqual(m.lifecycle_header(), (0, 0, 0, 0))
                self.assertEqual(m.allocations, [])
                self.assertEqual([event[0] for event in m.raw_events], [RAW_LOCK])

    def test_missing_or_incoherent_tag_refuses_with_unknown_diagnostic(self):
        for route, tag, captured in (
                ('register_gate', receipt.TAG, receipt.CAPTURED),
                ('delete_gate', retirement.TAG, retirement.CAPTURED)):
            for value in (0, 1, MASK, captured ^ 1):
                with self.subTest(route=route, value=value):
                    m = self.machine()
                    if route == 'delete_gate':
                        self.assertEqual(m.register(), 0)
                    before = self.snapshot(m)
                    m.clear_events()

                    def mutate(current):
                        current.put(current.r[29] + tag, value, 4)

                    marks = self.watch_denial(m, route, mutate)
                    self.assertEqual(m.invoke_gate_route(route), (MASK, 0))
                    self.assert_private_after_gate(m, marks, route)
                    self.assertEqual(self.snapshot(m), before)
                    self.assertTrue(m.registry_held)
                    self.assertEqual([event[0] for event in m.raw_events], [RAW_LOCK])

    def test_wrong_registration_mutex_witness_refuses_without_controller_reload(self):
        for value in (0, 1, REGISTRY_MUTEX + 4, MASK):
            with self.subTest(value=value):
                m = self.machine()
                before = self.snapshot(m)

                def mutate(current):
                    current.put(current.r[29] + receipt.PTR, value, 4)

                marks = self.watch_denial(m, 'register_gate', mutate)
                self.assertEqual(m.invoke_gate_route('register_gate'), (MASK, 0))
                self.assert_private_after_gate(m, marks, 'register_gate')
                self.assertEqual(self.snapshot(m), before)
                self.assertTrue(m.registry_held)

    def test_wrong_controller_scalar_refuses_without_dereferencing_it(self):
        for route, register in (('register_gate', 16), ('delete_gate', 21)):
            for pointer in (0, 1, CONTROLLER + 4, MASK):
                with self.subTest(route=route, pointer=pointer):
                    m = self.machine()
                    if route == 'delete_gate':
                        self.assertEqual(m.register(), 0)
                    before = self.snapshot(m)

                    def mutate(current):
                        current.r[register] = pointer

                    marks = self.watch_denial(m, route, mutate)
                    self.assertEqual(m.invoke_gate_route(route), (MASK, 0))
                    self.assert_private_after_gate(m, marks, route)
                    self.assertEqual(self.snapshot(m), before)
                    self.assertTrue(m.registry_held)

    def test_failure_restores_native_callee_saved_state_sp_ra_and_hilo(self):
        indices = (*range(16, 24), 28, 29, 30, 31)
        for route in ('register_gate', 'delete_gate'):
            m = self.machine()
            if route == 'delete_gate':
                self.assertEqual(m.register(), 0)
            m.acquire = 22
            m.r[29], m.r[31] = STACK, RETURN
            before = tuple(m.r[index] for index in indices)
            gate_hilo = []

            def observe(current, pc):
                if pc == current.acquire_gate_labels[route]:
                    gate_hilo.append((current.hi, current.lo))

            m.on_instruction = observe
            self.assertEqual(m.invoke_gate_route(route), (MASK, 22))
            self.assertEqual(tuple(m.r[index] for index in indices), before)
            self.assertEqual(gate_hilo, [(m.hi, m.lo)])

    def test_missing_fresh_begin_or_raw_capture_redirect_is_refused(self):
        for route in ('register_gate', 'delete_gate'):
            for missing in ('begin', 'raw_call', 'raw_return'):
                with self.subTest(route=route, missing=missing):
                    m = self.machine()
                    if route == 'delete_gate':
                        self.assertEqual(m.register(), 0)
                    before = self.snapshot(m)
                    if missing == 'begin':
                        pc = (receipt.HOOKS['begin'][0] if route == 'register_gate'
                              else retirement.HOOKS['delete_begin'][0])
                    else:
                        pc = receipt.HOOKS[missing][0]
                    m.remove_pair(pc)
                    # Fresh zero frame locals: coherent activation is still
                    # required; a malicious fabricated stale CAPTURED frame
                    # is not authenticated by these scalar witnesses.
                    native_sp = STACK - (40 if route == 'register_gate' else 56)
                    for offset in (0x10, 0x14, 0x18):
                        m.put(native_sp + offset, 0, 4)
                    m.clear_events()
                    marks = self.watch_denial(m, route)
                    self.assertEqual(m.invoke_gate_route(route), (MASK, 0))
                    self.assert_private_after_gate(m, marks, route)
                    self.assertEqual(self.snapshot(m), before)
                    self.assertTrue(m.registry_held)

    def test_demonstrated_raw_error_delete_and_rebirth_gap_is_blocked(self):
        m = self.machine(capacity=1, lifecycle_capacity=3)
        self.assertEqual(m.register_birth(), (0, SOURCE))
        node = m.allocations[-1]
        row = m.lifecycle_record()
        before = self.snapshot(m)
        m.acquire = 22
        self.assertEqual(m.delete_native(), (MASK, 22))
        # Deliberate adversarial continuation, not permitted error recovery:
        # even a caller that ignores the first refusal cannot publish through
        # the second gated body while its fresh acquisition still fails.
        m.reuse_node = node
        self.assertEqual(m.register(), MASK)
        self.assertEqual(m.r[3], 22)
        self.assertEqual(self.snapshot(m), before)
        self.assertEqual(m.lifecycle_record(), row)
        self.assertEqual(m.reused_nodes, [])
        self.assertEqual(m.words_at(CONTROLLER + 0x34, 2), (node, node))

    def test_missing_new_gate_demonstrates_why_both_redirects_are_coherent_premises(self):
        for route in ('register_gate', 'delete_gate'):
            with self.subTest(route=route):
                m = self.machine()
                if route == 'delete_gate':
                    self.assertEqual(m.register(), 0)
                    node = m.allocations[-1]
                m.remove_pair(core.HOOKS[route][0])
                m.acquire = 22
                m.clear_events()
                if route == 'register_gate':
                    self.assertEqual(m.register(), 0)
                    self.assertEqual(len(m.allocations), 1)
                    self.assertEqual(m.lifecycle_header(), (0, 0, 0, 0))
                else:
                    m.delete_native()
                    self.assertIn(node, m.freed)
                    self.assertEqual(m.lifecycle_record()[10],
                                     lifecycle.NO_RETIREMENT_OBSERVED)

    def test_missing_later_retirement_frontier_is_not_repaired_by_acquire_gate(self):
        m = self.machine()
        self.assertEqual(m.register(), 0)
        node = m.allocations[-1]
        row = m.lifecycle_record()
        m.remove_pair(retirement.HOOKS['delete_frontier'][0])
        m.delete_native()
        self.assertIn(node, m.freed)
        self.assertEqual(m.lifecycle_record(), row)
        self.assertEqual(row[10], lifecycle.NO_RETIREMENT_OBSERVED)

    def test_other_native_teardown_route_still_has_its_old_raw_error_gap(self):
        m = self.machine()
        self.assertEqual(m.register(), 0)
        node = m.allocations[-1]
        row = m.lifecycle_record()
        m.acquire = 22
        m.clear_events()
        m.teardown_node_loop()
        self.assertIn(node, m.freed)
        self.assertEqual(m.lifecycle_record(), row)
        self.assertEqual(m.lifecycle_header(), (1, 0, 0, 0))
        self.assertNotIn(m.acquire_gate_labels['delete_gate'], m.trace)
        self.assertNotIn(m.acquire_gate_labels['register_gate'], m.trace)


if __name__ == '__main__':
    unittest.main()
