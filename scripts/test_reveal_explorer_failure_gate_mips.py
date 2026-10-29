#!/usr/bin/env python3
"""Execute a single saved-return splice and the real native NULL unwind.

The retained bounded explorer slice starts at492908, not opaque491E80. Its
genuine6096-byte frame and caller argument homes are seeded as established by
the native prologue. Actual construction, registration and both native unwind
bodies execute. No Python status latch or simulated caller-abort transition
decides the generated route. Earlier graph allocations/mutations remain.
"""

import struct
import unittest

import reveal_constructor_continuation_gate_mips as parent
import reveal_explorer_failure_gate_mips as core
import reveal_explorer_failure_gate_stage as stage
import test_reveal_constructor_continuation_gate_mips as previous
from test_reveal_constructor_continuation_gate_mips import (
    ConstructorContinuationGateMachine, FIRST, SECOND, ROUTES, NAME_POSTWORK,
    OUTER_VIEW, STATE, BIND_STATE, OWNER_STATE, CONTROLLER, REGISTRY_MUTEX,
    PAINT_MUTEX, CODE, LIFECYCLE, QUEUE, TRANSPORT_MUTEX, FAULT,
    RAW_LOCK, RAW_UNLOCK, STACK, RETURN, MASK, DESCRIPTOR)


EXPLORER_SLICE, EXPLORER_SLICE_END = 0x492908, 0x492930
EXPLORER_RETURN, EXPLORER_NULL = 0x492920, 0x492F84
EXPLORER_FRAME, FIRST_FRAME, PRIVATE_FRAME = 6096, 136, 192
VIEW_SENTINEL = 0xC0FFEE77
SECOND_CALLER_STACK = STACK + 0x6000
EXPLORER_SAVES = {
    **{register: 0x17A8 + 4 * (register - 16) for register in range(16, 24)},
    30: 0x17C8, 31: 0x17CC,
}


class NativeReturnBoundary:
    """End a nested native call at either actual native return destination.

    The outer instruction interpreter must then follow the actual RA, including
    a saved-return diversion. This compares reached PCs only, not V0 or status.
    """

    def __init__(self, *addresses):
        self.addresses = addresses

    def __eq__(self, pc):
        return pc in self.addresses


class ExplorerFailureGateMachine(ConstructorContinuationGateMachine):
    """Real native frame exits; only existing bounded imports are substituted."""

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
                     'birth_consumer', 'acquire_gate',
                     'constructor_continuation_gate', 'explorer_failure_gate'):
            setattr(self, name + '_labels', self.composition[name + '_labels'])
        self.bridge_labels = self.receipt_labels
        for pc, words in self.composition['coherent_hooks'].items():
            for index, word in enumerate(words):
                self.patches[pc + 4 * index] = word
        self.clear_events()

    def external(self, target):
        if target == FIRST:
            self.calls.append(target)
            # The parent fixture's single-return nested-call boundary cannot
            # itself follow a legitimate nonlocal saved-RA return. Stop before
            # executing either reached destination, so the outer interpreter
            # resumes the actual r31 and executes the emitted/native unwind.
            self.run_at(target, NativeReturnBoundary(
                self.r[31], self.explorer_failure_gate_labels['abort_return']))
            return
        return super().external(target)

    def seed_explorer(self, *, caller_stack=STACK, caller=RETURN,
                      view=OUTER_VIEW, sentinel=VIEW_SENTINEL):
        """Supply the retained native frame, not execute opaque explorer setup."""
        explorer_sp = caller_stack - EXPLORER_FRAME
        saved = {register: self.r[register] for register in EXPLORER_SAVES}
        saved[31] = caller
        for register, offset in EXPLORER_SAVES.items():
            self.put(explorer_sp + offset, saved[register], 4)
        data, offset = self.region(DESCRIPTOR, 104)
        self.bytes(explorer_sp + 0x16E4, bytes(data[offset:offset + 104]))
        # Native entry stores arguments into its caller's o32 argument homes.
        # They are independently retained/mapped along with the6096 frame.
        self.put(explorer_sp + 0x17D0, CONTROLLER, 4)
        self.put(view + 0xCC, sentinel, 4)
        self.r[29], self.r[31], self.r[16] = explorer_sp, caller, view
        return dict(sp=explorer_sp, caller_stack=caller_stack,
                    caller=caller, view=view, sentinel=sentinel, saved=saved)

    def run_explorer_slice(self, stop=RETURN):
        self.run_at(EXPLORER_SLICE, stop)
        return self.r[2], self.r[3]

    def remove_generated_splice(self, *, fetch_override=True, prefix_bytes=True):
        """Both copies must be removed to model a genuinely missing splice."""
        code = bytearray(self.code)
        for pc, words in self.composition['explorer_failure_gate_source_words'].items():
            if fetch_override:
                self.remove_pair(pc)
            if prefix_bytes:
                struct.pack_into('<2I', code, pc - CODE, *words)
        self.code = self.code_bytes = bytes(code)


class ExplorerFailureGateTests(unittest.TestCase):
    setUpClass = classmethod(previous.ConstructorContinuationGateTests.setUpClass.__func__)

    def machine(self, **options):
        return ExplorerFailureGateMachine(self.image, **options)

    def assert_null_unwind(self, machine, context):
        self.assertEqual(machine.r[2], 0)
        self.assertEqual(machine.r[29], context['caller_stack'])
        self.assertEqual(machine.r[31], context['caller'])
        for register, value in context['saved'].items():
            self.assertEqual(machine.r[register], value, register)
        self.assertEqual(machine.peek(context['view'] + 0xCC), context['sentinel'])
        self.assertEqual(machine.outer_enable_events, [])
        self.assertIn(parent.FIRST_EPILOGUE, machine.trace)
        self.assertIn(machine.explorer_failure_gate_labels['abort_return'], machine.trace)
        self.assertIn(EXPLORER_NULL, machine.trace)
        self.assertNotIn(EXPLORER_RETURN, machine.trace)
        self.assertNotIn(0x492924, machine.trace)
        self.assertEqual(machine.native_continuations, [])
        self.assertNotIn(NAME_POSTWORK, machine.calls)
        self.assertEqual(machine.freed, [])

    def watch_scope(self, machine):
        marks = []

        def observe(current, pc):
            if pc == current.explorer_failure_gate_labels['scope']:
                marks.append((len(current.reads), len(current.writes),
                              len(current.calls), len(current.constructor_accesses),
                              current.r[29]))

        machine.on_instruction = observe
        return marks

    def assert_private_stop(self, machine, context, marks, *, selected=True):
        self.assertEqual(len(marks), 1)
        reads, writes, calls, accesses, private_sp = marks[0]
        native_sp = context['sp'] - FIRST_FRAME
        self.assertEqual(private_sp, native_sp - PRIVATE_FRAME)
        self.assertEqual(machine.calls[calls:], [])
        self.assertTrue(all(private_sp <= address and address + size <= context['caller_stack']
                            for address, size in machine.reads[reads:]))
        expected = ([(native_sp + 0x84,
                      machine.explorer_failure_gate_labels['abort_return'], 4)]
                    if selected else [])
        self.assertEqual(machine.writes[writes:], expected)
        helper_start = machine.explorer_failure_gate_labels['scope']
        helper_end = CODE + len(machine.code)
        helper = [event for event in machine.constructor_accesses[accesses:]
                  if helper_start <= event[1] < helper_end]
        self.assertEqual([(kind, address, size) for kind, _, address, size in helper],
                         [('read', native_sp + 0x84, 4)]
                         + ([('write', native_sp + 0x84, 4)] if selected else [])
                         + [('read', private_sp + parent.HI, 4)])

    def test_raw_registration_failure_retargets_only_this_explorer_native_return(self):
        m = self.machine(acquire=22)
        context = m.seed_explorer()
        m.clear_events()
        marks = self.watch_scope(m)
        self.assertEqual(m.run_explorer_slice(), (0, 22))
        self.assert_private_stop(m, context, marks)
        self.assert_null_unwind(m, context)
        self.assertEqual(m.allocations, [])
        self.assertEqual(len(m.created_engines), 1)
        self.assertNotEqual(m.created_engines[0], 0)
        self.assertEqual(m.lifecycle_header(), (0, 0, 0, 0))
        self.assertEqual([(event[0], event[1]) for event in m.raw_events],
                         [(RAW_LOCK, REGISTRY_MUTEX)])

    def test_actual_first_constructor_and_both_native_epilogues_execute_in_order(self):
        m = self.machine(acquire=22)
        context = m.seed_explorer()
        m.clear_events()
        self.assertEqual(m.run_explorer_slice(), (0, 22))
        ordered = (FIRST, 0x4389E0,
                   m.constructor_continuation_gate_labels['first_gate'],
                   m.constructor_continuation_gate_labels['first_gate_stopped'],
                   m.explorer_failure_gate_labels['scope'],
                   m.explorer_failure_gate_labels['selected'],
                   parent.FIRST_EPILOGUE,
                   m.explorer_failure_gate_labels['abort_return'], EXPLORER_NULL)
        self.assertEqual([m.trace.index(pc) for pc in ordered],
                         sorted(m.trace.index(pc) for pc in ordered))
        self.assertEqual(m.constructor_entries[0][1:3],
                         (context['sp'], EXPLORER_RETURN))
        self.assert_null_unwind(m, context)

    def test_all_gprs_and_hilo_restore_before_stock_constructor_epilogue(self):
        m = self.machine(acquire=22)
        context = m.seed_explorer()
        snapshots = {}

        def observe(current, pc):
            if pc in (current.constructor_continuation_gate_labels['first_gate'],
                      parent.FIRST_EPILOGUE):
                snapshots[pc] = (current.r.copy(), current.hi, current.lo)
            if pc == current.explorer_failure_gate_labels['abort_return']:
                snapshots['abort'] = (current.r[29], current.r[2],
                                      current.hi, current.lo)

        m.on_instruction = observe
        m.clear_events()
        self.assertEqual(m.run_explorer_slice(), (0, 22))
        gate = m.constructor_continuation_gate_labels['first_gate']
        self.assertEqual(snapshots[gate], snapshots[parent.FIRST_EPILOGUE])
        self.assertEqual(snapshots['abort'], (context['sp'], m.created_engines[0],
                                             *snapshots[gate][1:]))
        self.assertEqual((m.hi, m.lo), snapshots[gate][1:])
        self.assert_null_unwind(m, context)

    def test_no_new_save_frame_is_created_between_parent_scope_and_native_unwind(self):
        m = self.machine(acquire=22)
        context = m.seed_explorer()
        snapshots = []

        def observe(current, pc):
            names = current.explorer_failure_gate_labels
            for name in ('scope', 'selected', 'replay', 'abort_return'):
                if pc == names[name]:
                    snapshots.append((name, current.r[29]))

        m.on_instruction = observe
        m.clear_events()
        m.run_explorer_slice()
        private_sp = context['sp'] - FIRST_FRAME - PRIVATE_FRAME
        self.assertEqual(snapshots,
                         [('scope', private_sp), ('selected', private_sp),
                          ('replay', private_sp), ('abort_return', context['sp'])])
        self.assertEqual(m.r[29], context['caller_stack'])

    def test_native_node_allocation_failure_does_not_invent_an_unlock_or_free(self):
        m = self.machine()
        m.fail_allocation = True
        context = m.seed_explorer()
        m.clear_events()
        marks = self.watch_scope(m)
        self.assertEqual(m.run_explorer_slice(), (0, 0xBAD00003))
        self.assert_private_stop(m, context, marks)
        self.assert_null_unwind(m, context)
        self.assertEqual(m.allocations, [0])
        self.assertTrue(m.registry_held)
        self.assertEqual([event[0] for event in m.raw_events], [RAW_LOCK])
        self.assertEqual(m.freed, [])

    def test_success_still_executes_original_outer_store_and_enable_slice(self):
        m = self.machine()
        context = m.seed_explorer()
        m.clear_events()
        result, _ = m.run_explorer_slice(EXPLORER_SLICE_END)
        engine = m.created_engines[0]
        self.assertEqual(m.peek(OUTER_VIEW + 0xCC), engine)
        self.assertEqual(m.outer_enable_events, [(CONTROLLER, engine)])
        self.assertEqual(len(m.native_continuations), 1)
        self.assertIn(NAME_POSTWORK, m.calls)
        self.assertEqual(m.r[29], context['sp'])
        self.assertNotIn(m.explorer_failure_gate_labels['scope'], m.trace)
        self.assertNotIn(EXPLORER_NULL, m.trace)
        self.assertEqual(m.lifecycle_header(), (1, 0, 0, 0))
        self.assertEqual(result, 0)  # bounded outer enable service's native result

    def test_nonexplorer_first_caller_keeps_original_nonzero_engine_return(self):
        m = self.machine(acquire=22)
        result, raw = m.construct(FIRST)
        self.assertEqual((result, raw), (m.created_engines[0], 22))
        self.assertNotEqual(result, 0)
        self.assertIn(m.explorer_failure_gate_labels['scope'], m.trace)
        self.assertNotIn(m.explorer_failure_gate_labels['selected'], m.trace)
        self.assertNotIn(m.explorer_failure_gate_labels['abort_return'], m.trace)
        self.assertEqual((m.r[29], m.r[31]), (STACK, RETURN))

    def test_second_constructor_is_not_intercepted_by_first_explorer_helper(self):
        m = self.machine(acquire=22)
        result, raw = m.construct(SECOND, caller=EXPLORER_RETURN)
        self.assertEqual((result, raw), (m.created_engines[0], 22))
        self.assertNotIn(m.explorer_failure_gate_labels['scope'], m.trace)
        self.assertIn(m.constructor_continuation_gate_labels['second_gate_stopped'], m.trace)
        self.assertEqual((m.r[29], m.r[31]), (STACK, EXPLORER_RETURN))

    def test_identical_failure_invocations_use_fresh_native_return_slots_not_a_latch(self):
        m = self.machine(acquire=22)
        first = m.seed_explorer()
        m.clear_events()
        self.assertEqual(m.run_explorer_slice(), (0, 22))
        self.assert_null_unwind(m, first)
        m.clear_events()
        direct, raw = m.construct(FIRST)
        self.assertEqual((direct, raw), (m.created_engines[0], 22))
        self.assertNotIn(m.explorer_failure_gate_labels['selected'], m.trace)
        second = m.seed_explorer(caller_stack=SECOND_CALLER_STACK)
        m.clear_events()
        self.assertEqual(m.run_explorer_slice(), (0, 22))
        self.assert_null_unwind(m, second)
        self.assertNotEqual(first['sp'], second['sp'])

    def test_independent_cpu_can_stop_another_real_native_frame_without_shared_failure_state(self):
        m = self.machine(acquire=22)
        first = m.seed_explorer()
        other = m.fork_cpu()
        other_context = other.seed_explorer(caller_stack=SECOND_CALLER_STACK)
        observations = []

        def interleave(current, pc):
            if pc == current.explorer_failure_gate_labels['selected']:
                # Both modeled acquisitions return an error. This adversarial
                # interleaving is not permission to retry/reuse an uncertain
                # instance, or a native scheduler/lifetime proof.
                # Hand the bounded allocator cursor across this serial import
                # interval so independently allocated live engines do not alias.
                other.next_allocation = current.next_allocation
                observations.append(other.run_explorer_slice())
                current.next_allocation = other.next_allocation
                self.assert_null_unwind(other, other_context)

        m.on_instruction = interleave
        m.clear_events()
        other.clear_events()
        self.assertEqual(m.run_explorer_slice(), (0, 22))
        self.assertEqual(observations, [(0, 22)])
        self.assert_null_unwind(m, first)
        self.assertEqual(m.peek(first['sp'] - FIRST_FRAME + 0x84),
                         m.explorer_failure_gate_labels['abort_return'])
        self.assertEqual(m.peek(other_context['sp'] - FIRST_FRAME + 0x84),
                         m.explorer_failure_gate_labels['abort_return'])


if __name__ == '__main__':
    unittest.main()
