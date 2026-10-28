#!/usr/bin/env python3
"""Execute field-correlated retirement observations, never native liveness.

Actual4389E0 publication,4395A0 name selection/unlink, the43CB8C..43CBDC
node loop and both outer shutdown loops execute. Raw pthread, strcmp, logging,
node allocation/free and opaque paint/engine/callback cleanup are bounded
substitutes. The teardown fixture deliberately starts after its earlier worker
and paint destruction and stops before its later controller destruction.
These observations certify neither complete deletion nor allocation retention.
"""

import hashlib
import unittest

from build_reveal_bridge_diag import b
import reveal_paint_retirement_mips as owner
import reveal_registry_lifecycle_mips as core
import reveal_registry_lifecycle_stage as stage
import reveal_registry_receipt_mips as receipt
import reveal_registry_retirement_mips as retirement
import test_folderfollow_reveal_static_contract as source
from test_reveal_creation_capture_mips import CreationCaptureMachine
from test_reveal_registry_owner_mips import (
    STATE, BIND_STATE, OWNER_STATE, CODE, CONTROLLER, INPUT, REGISTRY_MUTEX,
    PAINT_MUTEX, RAW_LOCK, RAW_UNLOCK, STACK, RETURN, MASK)


LIFECYCLE, EVENT = 0x1F3A000, 0x1F3B000
ENGINE, NAME, CALLBACK = 0x1F3D000, 0x1F3E000, 0x1F3F000
NATIVE_DELETE = 0x4395A0
OUTER_PATHS = (
    (0x4E3EFC, 0x4E3F18, 0x4E3F48, 0x4E3F5C, 0x4E3EF0),
    (0x51A39C, 0x51A3B8, 0x51A3E8, 0x51A3FC, 0x51A390))


class RegistryLifecycleMachine(CreationCaptureMachine):
    """Real emitted history stores with bounded native ring consumers."""

    def __init__(self, image, *, capacity=16, lifecycle_capacity=16,
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
            PAINT_MUTEX, CODE, LIFECYCLE, capacity=capacity,
            lifecycle_capacity=lifecycle_capacity, owner_capacity=owner_capacity,
            ticket_limit=ticket_limit, queue_capacity=queue_capacity)
        self.code = self.code_bytes = self.composition['code']
        self.labels = self.composition['labels']
        for name in ('owner', 'issuer', 'receipt', 'adapter', 'capture',
                     'lifecycle', 'retirement'):
            setattr(self, name + '_labels', self.composition[name + '_labels'])
        self.bridge_labels = self.receipt_labels
        self.patches = {0x439844: b.addiu(5, 0, owner.ELEMENT_BYTES)}
        if hooks:
            for redirects in (receipt.hook_words(self.receipt_labels),
                              self.composition['release_hooks'],
                              self.composition['retirement_hooks']):
                for pc, words in redirects.items():
                    for index, word in enumerate(words):
                        self.patches[pc + index * 4] = word
        self.lifecycle_capacity = lifecycle_capacity
        self.map(LIFECYCLE, core.memory_bytes(lifecycle_capacity))
        self.map(EVENT, 0x100)
        self.map(ENGINE, 0x100)
        self.map(NAME, 0x100)
        self.bytes(NAME, b'Show No Mercy\0')
        self.put(ENGINE, NAME, 4)
        self.put(INPUT, ENGINE, 4)
        self.put(INPUT + 4, NAME, 4)
        self.lifecycle_accesses, self.lifecycle_requests = [], []
        self.cleanup_services, self.callback_events = [], []
        self.reuse_node = None
        self.reused_nodes = []
        self.clear_events()

    def tracked_access(self, kind, address, size):
        super().tracked_access(kind, address, size)
        if (hasattr(self, 'lifecycle_accesses') and LIFECYCLE <= address
                < LIFECYCLE + core.memory_bytes(self.lifecycle_capacity)):
            self.lifecycle_accesses.append((kind, self.current_pc, address, size,
                                            self.registry_held, self.paint_held))

    def instruction(self, pc):
        if hasattr(self, 'lifecycle_requests'):
            for kind in ('birth', 'retirement'):
                if pc == self.lifecycle_labels['observe_' + kind]:
                    try:
                        event = self.words_at(self.r[5], 8)
                    except AssertionError:
                        event = None
                    self.lifecycle_requests.append(
                        (kind, event, self.registry_held, self.paint_held))
        super().instruction(pc)

    def allocation(self, size):
        if size == 28 and getattr(self, 'reuse_node', None) is not None:
            pointer, self.reuse_node = self.reuse_node, None
            self.reused_nodes.append(pointer)
            return pointer
        return super().allocation(size)

    def external(self, target):
        if target == NATIVE_DELETE:
            self.calls.append(target)
            self.run_at(target, self.r[31])
            return
        if target == 0xA5B600:
            self.calls.append(target)

            def bounded_string(pointer):
                result = bytearray()
                for offset in range(256):
                    value = self.get(pointer + offset, 1)
                    if not value:
                        return bytes(result)
                    result.append(value)
                raise AssertionError('bounded native strcmp exhausted')

            left, right = map(bounded_string, self.r[4:6])
            self.hostile_result((left > right) - (left < right))
            return
        if target in (0x466A80, 0x8B3F00, 0x8B4220, 0x467160, CALLBACK):
            self.calls.append(target)
            self.cleanup_services.append((target, tuple(self.r[4:8]),
                                          self.registry_held))
            if target == 0x466A80:
                self.freed.append(self.r[4])
            if target == CALLBACK:
                self.callback_events.append((tuple(self.r[4:8]),
                                             self.registry_held,
                                             self.lifecycle_snapshot()))
            # The opaque destructors/log/callback do not inspect or establish
            # engine/resource-graph destruction, allocation reuse or retention.
            self.hostile_result(0)
            return
        super().external(target)

    def clear_events(self):
        super().clear_events()
        for name in ('lifecycle_accesses', 'lifecycle_requests',
                     'cleanup_services', 'callback_events', 'reused_nodes'):
            if hasattr(self, name):
                getattr(self, name).clear()

    def lifecycle_header(self):
        return self.words_at(LIFECYCLE, core.HEADER_BYTES // 4)

    def lifecycle_record(self, index=0):
        return self.words_at(
            LIFECYCLE + core.HEADER_BYTES + index * core.RECORD_BYTES,
            core.RECORD_BYTES // 4)

    def lifecycle_snapshot(self):
        return self.words_at(LIFECYCLE,
                             core.memory_bytes(self.lifecycle_capacity) // 4)

    def write_event(self, words=None, address=EVENT, *, site=0x438A5C,
                    node=1, engine=ENGINE):
        words = ((CONTROLLER, REGISTRY_MUTEX, node, engine, 3, RETURN, site, 0)
                 if words is None else words)
        if len(words) != 8:
            raise ValueError('a lifecycle event contains exactly eight words')
        for index, word in enumerate(words):
            self.put(address + index * 4, word, 4)
        return address

    def invoke_observe(self, kind='birth', event=EVENT, *, controller=CONTROLLER,
                       stack=STACK, caller=RETURN):
        self.r[29], self.r[31] = stack, caller
        self.r[4], self.r[5] = controller, event
        self.run_at(self.lifecycle_labels['observe_' + kind], caller)
        return self.r[2], self.r[3]

    def delete_native(self, name=NAME):
        self.r[29], self.r[31] = STACK, RETURN
        self.r[4:6] = CONTROLLER, name
        self.run_at(NATIVE_DELETE, RETURN)
        return self.r[2], self.r[3]

    def teardown_node_loop(self):
        """Only actual registry teardown; no earlier/later graph teardown."""
        self.r[29], self.r[31], self.r[17] = STACK - 0x28, RETURN, CONTROLLER
        self.put(self.r[29] + 0x24, RETURN, 4)
        self.run_at(0x43CB8C, 0x43CBDC)

    def outer_iteration(self, path=0, *, callback=False):
        """One actual outer-loop iteration, before later controller teardown."""
        begin, _, _, after_unlink, after_callback = OUTER_PATHS[path]
        node = self.peek(CONTROLLER + 0x34)
        if node != CONTROLLER + 0x34:
            self.put(node + 0x18, CALLBACK if callback else 0, 4)
        self.r[29], self.r[31] = STACK - 0x38, RETURN
        self.put(self.r[29] + 0x34, RETURN, 4)
        self.r[16], self.r[19] = CONTROLLER, CONTROLLER + 0x34
        self.r[18], self.r[20], self.r[21] = 201, NAME, EVENT
        self.run_at(begin, after_callback if callback else after_unlink)

    def remove_hook(self, name):
        pc, _ = retirement.HOOKS[name]
        self.patches.pop(pc, None)
        self.patches.pop(pc + 4, None)


class RegistryLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = source.SOURCE.read_bytes()
        digest = hashlib.sha256(cls.image).hexdigest()
        if digest != source.SOURCE_SHA256 or len(cls.image) != source.SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: {digest}, size {len(cls.image)}')

    def machine(self, **options):
        return RegistryLifecycleMachine(self.image, **options)

    def birth(self, m):
        self.assertEqual(m.register(), 0)
        return m.allocations[-1]

    def assert_selected(self, m, index, site):
        row = m.lifecycle_record(index)
        self.assertEqual(row[10], core.RETIREMENT_SELECTED)
        self.assertEqual(row[11], site)
        self.assertEqual(row[13], RETURN)
        self.assertEqual(row[14:], (0, 0))
        return row

    def test_actual_native_publication_mints_a_historical_outstanding_row(self):
        m = self.machine()
        node = self.birth(m)
        self.assertEqual(m.lifecycle_header(), (1, 0, 0, 0))
        self.assertEqual(m.lifecycle_record(), (
            core.RECORD_MAGIC, 1, CONTROLLER, REGISTRY_MUTEX, node, ENGINE,
            STACK - 0x28, RETURN, 0x438A5C, 0,
            core.NO_RETIREMENT_OBSERVED, 0, 0, 0, 0, 0))
        self.assertEqual(m.lifecycle_requests, [('birth', (
            CONTROLLER, REGISTRY_MUTEX, node, ENGINE, STACK - 0x28,
            RETURN, 0x438A5C, 0), True, False)])
        self.assertTrue(all(event[-2] and not event[-1]
                            for event in m.lifecycle_accesses))

    def test_actual_name_delete_marks_before_first_native_unlink(self):
        m = self.machine()
        node = self.birth(m)
        birth = m.lifecycle_record()
        moments = []
        cleanup_boundaries = []

        def inspect(machine, pc):
            if pc == machine.lifecycle_labels['observe_retirement']:
                moments.append((machine.words_at(CONTROLLER + 0x34, 2),
                                machine.words_at(node, 2),
                                machine.registry_held))
            if pc in (0x43962C, 0x43963C, 0x439644, 0x43964C):
                cleanup_boundaries.append((pc,
                    machine.words_at(CONTROLLER + 0x34, 2),
                    machine.words_at(node, 2), machine.lifecycle_record()[10]))

        m.on_instruction = inspect
        m.clear_events()
        m.delete_native()
        row = self.assert_selected(m, 0, 0x439618)
        self.assertEqual(row[:10], birth[:10])
        self.assertEqual(row[12], STACK - 0x38)
        self.assertEqual(moments, [((node, node), (CONTROLLER + 0x34,) * 2, True)])
        replay = m.retirement_labels['delete_frontier_replay']
        self.assertEqual((m.word(replay), m.word(replay + 4)),
                         retirement.HOOKS['delete_frontier'][1])
        self.assertIn(replay, m.trace)
        self.assertIn(replay + 4, m.trace)
        self.assertEqual([(address, value, size)
                          for address, value, size in m.writes
                          if address in (CONTROLLER + 0x34, CONTROLLER + 0x38)],
                         [(CONTROLLER + 0x38, CONTROLLER + 0x34, 4),
                          (CONTROLLER + 0x34, CONTROLLER + 0x34, 4)])
        self.assertEqual(cleanup_boundaries, [
            (pc, (CONTROLLER + 0x34,) * 2, (0, 0), 2)
            for pc in (0x43962C, 0x43963C, 0x439644, 0x43964C)])
        self.assertEqual(m.words_at(CONTROLLER + 0x34, 2), (CONTROLLER + 0x34,) * 2)
        self.assertIn(node, m.freed)
        self.assertFalse(m.registry_held)
        self.assertEqual(m.lifecycle_header(), (1, 0, 0, 0))

    def test_checked_actual_delete_and_same_node_allocator_reuse_mint_new_token(self):
        m = self.machine(capacity=1, lifecycle_capacity=3)
        node = self.birth(m)
        old_binding, old_receipt = m.binding_record(), m.record()
        m.delete_native()
        terminal = self.assert_selected(m, 0, 0x439618)
        m.reuse_node = node
        self.assertEqual(self.birth(m), node)
        self.assertEqual(m.reused_nodes, [node])
        self.assertEqual(m.lifecycle_header(), (2, 0, 0, 0))
        self.assertEqual(m.lifecycle_record(), terminal)
        self.assertEqual(m.lifecycle_record(1)[1:6],
                         (2, CONTROLLER, REGISTRY_MUTEX, node, ENGINE))
        self.assertEqual(m.lifecycle_record(1)[10:], (1, 0, 0, 0, 0, 0))
        self.assertEqual(m.binding_record(), old_binding)
        self.assertEqual(m.record(), old_receipt)
        self.assertEqual(m.binding_header()[0], 1)

    def test_full_old_receipt_and_binding_do_not_suppress_birth_or_retirement(self):
        m = self.machine(capacity=1, lifecycle_capacity=3)
        self.birth(m)
        self.birth(m)
        m.delete_native()
        self.assertEqual(m.lifecycle_header(), (2, 0, 0, 0))
        self.assert_selected(m, 0, 0x439618)
        self.assertEqual(m.lifecycle_record(1)[10], core.NO_RETIREMENT_OBSERVED)
        self.assertEqual(m.binding_header()[0], 1)

    def test_actual_teardown_loop_marks_every_node_before_its_unlink(self):
        m = self.machine()
        nodes = [self.birth(m) for _ in range(3)]
        observed = []

        def inspect(machine, pc):
            if pc == machine.lifecycle_labels['observe_retirement']:
                event = machine.words_at(machine.r[5], 8)
                node = event[2]
                next_node, previous = machine.words_at(node, 2)
                observed.append((node, machine.peek(next_node + 4),
                                 machine.peek(previous), machine.registry_held))

        m.on_instruction = inspect
        m.clear_events()
        m.teardown_node_loop()
        self.assertEqual(observed, [(node, node, node, True) for node in nodes])
        for index in range(3):
            row = self.assert_selected(m, index, 0x43CBB0)
            self.assertEqual(row[12], STACK - 0x28)
        self.assertEqual(m.freed, nodes)
        self.assertEqual(m.words_at(CONTROLLER + 0x34, 2), (CONTROLLER + 0x34,) * 2)
        self.assertEqual([event[0] for event in m.raw_events], [RAW_LOCK, RAW_UNLOCK])
        self.assertEqual(m.lifecycle_header(), (3, 0, 0, 0))

    def test_outer_paths_mark_selection_under_r_then_unlink_after_unlock(self):
        for path, (_, site, native_unlink, _, _) in enumerate(OUTER_PATHS):
            with self.subTest(path=path):
                m = self.machine()
                node = self.birth(m)
                moments = []

                def inspect(machine, pc):
                    if pc == machine.lifecycle_labels['observe_retirement']:
                        moments.append((machine.registry_held,
                                        machine.words_at(CONTROLLER + 0x34, 2)))
                    elif pc == native_unlink:
                        moments.append((machine.registry_held,
                                        machine.lifecycle_record()[10]))

                m.on_instruction = inspect
                m.clear_events()
                m.outer_iteration(path)
                self.assertEqual(moments, [(True, (node, node)), (False, 2)])
                row = self.assert_selected(m, 0, site)
                self.assertEqual(row[12], STACK - 0x38)
                self.assertIn(node, m.freed)
                self.assertEqual(m.words_at(CONTROLLER + 0x34, 2),
                                 (CONTROLLER + 0x34,) * 2)
                self.assertTrue(all(event[-2] and not event[-1]
                                    for event in m.lifecycle_accesses))

    def test_outer_callback_may_leave_node_linked_after_terminal_selection(self):
        for path, (_, site, _, _, _) in enumerate(OUTER_PATHS):
            with self.subTest(path=path):
                m = self.machine()
                node = self.birth(m)
                m.clear_events()
                m.outer_iteration(path, callback=True)
                self.assert_selected(m, 0, site)
                self.assertEqual(m.words_at(CONTROLLER + 0x34, 2), (node, node))
                self.assertEqual(m.words_at(node, 2), (CONTROLLER + 0x34,) * 2)
                self.assertEqual(len(m.callback_events), 1)
                self.assertFalse(m.callback_events[0][1])
                self.assertEqual(m.callback_events[0][2][4 + 10], 2)
                self.assertEqual(m.freed, [])

    def test_empty_delete_and_teardown_do_not_invent_retirement_rows(self):
        for operation in ('delete_native', 'teardown_node_loop'):
            with self.subTest(operation=operation):
                m = self.machine()
                getattr(m, operation)()
                self.assertEqual(m.lifecycle_header(), (0, 0, 0, 0))
                self.assertEqual(m.lifecycle_accesses, [])
                self.assertEqual(m.lifecycle_requests, [])

    def test_raw_acquire_failure_can_unlink_but_cannot_touch_lifecycle_history(self):
        for operation in ('delete_native', 'teardown_node_loop'):
            for status in (1, 22, 0x82, MASK):
                with self.subTest(operation=operation, status=status):
                    m = self.machine()
                    self.birth(m)
                    before = m.lifecycle_snapshot()
                    m.acquire = status
                    m.clear_events()
                    getattr(m, operation)()
                    self.assertEqual(m.lifecycle_snapshot(), before)
                    self.assertEqual(m.lifecycle_accesses, [])
                    self.assertEqual(m.lifecycle_requests, [])
                    self.assertEqual(m.words_at(CONTROLLER + 0x34, 2),
                                     (CONTROLLER + 0x34,) * 2)
                    self.assertEqual(m.raw_events[0][-1], status)

    def test_raw_outer_acquire_failure_preserves_missing_observation_gap(self):
        for path in range(2):
            m = self.machine()
            self.birth(m)
            before = m.lifecycle_snapshot()
            m.acquire = 22
            m.clear_events()
            m.outer_iteration(path)
            self.assertEqual(m.lifecycle_snapshot(), before)
            self.assertEqual(m.lifecycle_accesses, [])
            self.assertEqual(m.words_at(CONTROLLER + 0x34, 2),
                             (CONTROLLER + 0x34,) * 2)

    def test_missing_fresh_raw_witness_prevents_history_access(self):
        for missing in ('raw_call', 'raw_return'):
            for operation in ('delete_native', 'teardown_node_loop'):
                with self.subTest(missing=missing, operation=operation):
                    m = self.machine()
                    self.birth(m)
                    before = m.lifecycle_snapshot()
                    m.remove_hook(missing)
                    m.clear_events()
                    getattr(m, operation)()
                    self.assertEqual(m.lifecycle_snapshot(), before)
                    self.assertEqual(m.lifecycle_accesses, [])

    def test_full_lifecycle_history_can_still_select_existing_row(self):
        m = self.machine(lifecycle_capacity=1)
        self.birth(m)
        m.delete_native()
        self.assert_selected(m, 0, 0x439618)
        self.assertEqual(m.lifecycle_header(), (1, 0, 0, 0))

    def test_release_error_does_not_erase_selection_or_add_late_history_accesses(self):
        for operation in ('delete_native', 'teardown_node_loop'):
            m = self.machine()
            self.birth(m)
            m.release = 22
            boundaries = []

            def inspect(machine, target):
                if target == RAW_UNLOCK and machine.r[4] == REGISTRY_MUTEX:
                    boundaries.append(len(machine.lifecycle_accesses))

            m.on_service = inspect
            m.clear_events()
            getattr(m, operation)()
            self.assertEqual(m.lifecycle_record()[10], 2)
            self.assertEqual(boundaries, [len(m.lifecycle_accesses)])
            self.assertEqual(m.raw_events[-1][-1], 22)

    def test_standalone_callbacks_preserve_every_gpr_and_hilo(self):
        for kind, site in (('birth', 0x438A5C), ('retirement', 0x439618)):
            for case in ('success', 'fault', 'bad_schema', 'bad_pointer'):
                with self.subTest(kind=kind, case=case):
                    m = self.machine()
                    m.registry_held = True
                    if kind == 'retirement':
                        m.write_event()
                        m.invoke_observe()
                    m.write_event(site=site)
                    if case == 'fault':
                        m.put(LIFECYCLE + core.FAULT, 1, 4)
                    elif case == 'bad_schema':
                        m.put(EVENT + core.REQUEST_RAW_STATUS, 22, 4)
                    event = EVENT + 1 if case == 'bad_pointer' else EVENT
                    m.r[:] = [0] + [0x55660000 + reg for reg in range(1, 32)]
                    m.r[29], m.r[31], m.r[4], m.r[5] = STACK, RETURN, CONTROLLER, event
                    m.hi, m.lo = 0x12345678, 0xABCDEF01
                    before = m.r.copy(), m.hi, m.lo
                    m.clear_events()
                    m.invoke_observe(kind, event)
                    self.assertEqual((m.r, m.hi, m.lo), before)
                    self.assertEqual(m.raw_events, [])
                    self.assertEqual(m.calls, [])

    def test_native_delete_final_architecture_matches_unobserved_native_path(self):
        for status in (0, 22):
            with self.subTest(status=status):
                native, observed = self.machine(hooks=False), self.machine()
                for m in (native, observed):
                    self.birth(m)
                    m.acquire = status
                    m.clear_events()
                    m.delete_native()
                self.assertEqual((native.r, native.hi, native.lo),
                                 (observed.r, observed.hi, observed.lo))
                self.assertEqual(native.raw_events, observed.raw_events)
                self.assertEqual(native.freed, observed.freed)
                self.assertEqual(native.words_at(CONTROLLER + 0x34, 2),
                                 observed.words_at(CONTROLLER + 0x34, 2))

    def test_each_native_bridge_preserves_all_gprs_and_hilo_except_displaced_effects(self):
        for operation in ('delete', 'teardown', 'outer_a', 'outer_b'):
            with self.subTest(operation=operation):
                m = self.machine()
                self.birth(m)
                if operation == 'delete':
                    pairs = (
                        (0x4395C0, 0x4395C8, {21: ('register', 4), 25: 0x437D20}),
                        (0x439618, 0x439620, {}))
                elif operation == 'teardown':
                    pairs = (
                        (0x43CB8C, 0x43CB94, {4: ('register', 17), 25: 0x437D20}),
                        (0x43CBB0, 0x43CBB8, {}),
                        (0x43CBD4, 0x437DA0,
                         {4: ('register', 17), 31: 0x43CBDC}))
                else:
                    first, frontier = ((0x4E3F00, 0x4E3F18)
                                       if operation == 'outer_a'
                                       else (0x51A3A0, 0x51A3B8))
                    pairs = (
                        (first, 0x437D20, {4: ('register', 16), 31: first + 8}),
                        (frontier, 0x437DA0, {31: frontier + 8}))
                pairs += (
                    (0x466DA8, RAW_LOCK, {31: 0x466DB0}),
                    (0x466DB0, 0x466DB8, {2: 0, 31: 0x437D30}))
                watched = {pc for before, after, _ in pairs for pc in (before, after)}
                snapshots = {}

                def inspect(machine, pc):
                    if pc in watched:
                        snapshots.setdefault(pc, []).append(
                            (machine.r.copy(), machine.hi, machine.lo))

                m.on_instruction = inspect
                m.clear_events()
                if operation == 'delete':
                    m.delete_native()
                elif operation == 'teardown':
                    m.teardown_node_loop()
                else:
                    m.outer_iteration(0 if operation == 'outer_a' else 1)
                for before_pc, after_pc, changes in pairs:
                    with self.subTest(before=hex(before_pc), after=hex(after_pc)):
                        self.assertEqual(len(snapshots.get(before_pc, ())), 1)
                        self.assertEqual(len(snapshots.get(after_pc, ())), 1)
                        before, hi, lo = snapshots[before_pc][0]
                        expected = before.copy()
                        for register, value in changes.items():
                            expected[register] = (before[value[1]]
                                                  if isinstance(value, tuple)
                                                  else value)
                        self.assertEqual(snapshots[after_pc][0], (expected, hi, lo))


if __name__ == '__main__':
    unittest.main()
