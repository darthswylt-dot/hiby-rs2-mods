#!/usr/bin/env python3
"""Execute one bounded destructor continuation and its real native unwind.

The slice begins at493F40 after earlier worker/list/cache and purge/detach
effects. Actual4395A0 and its raw acquisition gate execute. A retained genuine
1208-byte destructor frame is supplied from its native prologue, together with
the independently mapped192-byte private save frame. Resource485320 is one
bounded hostile-ABI substitute for both the native linked call and emitted
unlinked transfer. Successful execution stops at493F58 before later cleanup.
This is neither a destructor-entry fence nor rollback or graph-cleanup proof.
"""

from contextlib import contextmanager
import hashlib
import unittest

import reveal_destructor_continuation_gate_mips as core
import reveal_destructor_continuation_gate_stage as stage
import test_reveal_registry_release_gate_mips as previous
from test_reveal_registry_release_gate_mips import (
    RegistryReleaseGateMachine, STATE, BIND_STATE, OWNER_STATE, CONTROLLER,
    REGISTRY_MUTEX, PAINT_MUTEX, CODE, LIFECYCLE, QUEUE, TRANSPORT_MUTEX,
    FAULT, RAW_LOCK, RAW_UNLOCK, STACK, RETURN, MASK, OUTER_VIEW,
    _fixture_assembly_cache as imported_fixture_assembly_cache,
    _cached_assembler)
from test_reveal_explorer_failure_gate_mips import NativeReturnBoundary
from test_reveal_registry_lifecycle_mips import NAME, NATIVE_DELETE


DESTRUCTOR_SLICE = 0x493F40
DESTRUCTOR_SAVES = {
    **{register: 0x490 + 4 * (register - 16) for register in range(16, 24)},
    30: 0x4B0, 31: 0x4B4,
}
EARLIER_EFFECT_PCS = (0x493EB4, 0x493EC8, 0x493F04,
                      0x493F14, 0x493F2C, 0x493F38)
_ASSEMBLY_CACHE_MODULES = (*previous._ASSEMBLY_CACHE_MODULES, core, stage)


@contextmanager
def _fixture_assembly_cache(enabled):
    """Cache only pure bytes/metadata across the complete serial composition.

    The previous fixture's25 emitter/composer modules and these two new modules
    are wrapped for this construction only. Its constructor is called with its
    own cache disabled so wrappers never nest. Every function is restored even
    when assembly or fixture construction raises; no CPU state is cached.
    """
    originals = []
    with imported_fixture_assembly_cache(enabled):
        try:
            if enabled:
                for module in (core, stage):
                    assemble = module.assemble
                    originals.append((module, assemble))
                    module.assemble = _cached_assembler(assemble)
            yield
        finally:
            for module, assemble in reversed(originals):
                module.assemble = assemble


class DestructorContinuationGateMachine(RegistryReleaseGateMachine):
    """No host-side status latch decides the destructor's emitted route."""

    def __init__(self, image, *, assembly_cache=True, **options):
        with _fixture_assembly_cache(assembly_cache):
            super().__init__(image, assembly_cache=False, **options)
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
                         'constructor_continuation_gate', 'explorer_failure_gate',
                         'registry_release_gate', 'destructor_continuation_gate'):
                setattr(self, name + '_labels', self.composition[name + '_labels'])
            self.bridge_labels = self.receipt_labels
            for pc, words in self.composition['coherent_hooks'].items():
                for index, word in enumerate(words):
                    self.patches[pc + index * 4] = word
            self.destructor_delete_entries = []
            self.resource_deletions, self.resource_entries = [], []
            self.destructor_argument_delays = []
            self.clear_events()

    def plain(self, word):
        if (word == core.RESOURCE_DELAY
                and hasattr(self, 'destructor_argument_delays')
                and (self.current_pc in (0x493F44, 0x493F50)
                     or self.destructor_continuation_gate_labels['gate']
                     <= self.current_pc < CODE + len(self.code))):
            self.destructor_argument_delays.append((self.current_pc, self.r[19]))
        return super().plain(word)

    def instruction(self, pc):
        if pc == NATIVE_DELETE and hasattr(self, 'destructor_delete_entries'):
            self.destructor_delete_entries.append(
                (tuple(self.r[4:8]), self.r[29], self.r[31]))
        super().instruction(pc)
        if pc == core.RESOURCE_DELETE:
            # Exactly the same substitute also handles the stock linked JAL.
            self.external(core.RESOURCE_DELETE)

    def word(self, pc):
        if pc == core.RESOURCE_DELETE:
            return 0x03E00008
        if pc == core.RESOURCE_DELETE + 4:
            return 0
        return super().word(pc)

    def external(self, target):
        if target == core.RESOURCE_DELETE:
            self.calls.append(target)
            self.resource_deletions.append(
                (target, tuple(self.r[4:8]), self.r[29], self.r[31],
                 self.registry_held))
            self.resource_entries.append((self.r.copy(), self.hi, self.lo))
            self.hostile_result(0)
            return
        return super().external(target)

    def clear_events(self):
        super().clear_events()
        for name in ('destructor_delete_entries', 'resource_deletions',
                     'resource_entries', 'destructor_argument_delays'):
            if hasattr(self, name):
                getattr(self, name).clear()

    def seed_destructor(self, *, caller_stack=STACK, caller=RETURN,
                        controller=CONTROLLER, name=NAME, view=OUTER_VIEW):
        """Supply actual prologue save slots; do not execute earlier effects."""
        destructor_sp = caller_stack - core.DESTRUCTOR_FRAME
        saved = {register: self.r[register] for register in DESTRUCTOR_SAVES}
        saved[31] = caller
        for register, offset in DESTRUCTOR_SAVES.items():
            self.put(destructor_sp + offset, saved[register], 4)
        self.destructor_context = dict(
            sp=destructor_sp, caller_stack=caller_stack, caller=caller,
            controller=controller, name=name, view=view, saved=saved,
            gp=self.r[28])
        self.r[29], self.r[31] = destructor_sp, caller
        self.r[16], self.r[17], self.r[19] = view, controller, name
        return self.destructor_context

    def run_destructor_slice(self, stop=None):
        if stop is None:
            stop = NativeReturnBoundary(
                self.destructor_context['caller'], core.CONTINUATION)
        self.run_at(DESTRUCTOR_SLICE, stop)
        return self.r[2], self.r[3]

    def invoke_destructor_gate(self, *, result=MASK, diagnostic=22,
                               controller=CONTROLLER, caller=None):
        """Controlled hook-entry architecture, never malformed-frame recovery."""
        context = self.seed_destructor(controller=controller)
        self.r[2:4] = result, diagnostic
        self.r[31] = core.HOOKS['gate'][0] if caller is None else caller
        self.clear_events()
        self.run_at(core.HOOKS['gate'][0], NativeReturnBoundary(
            context['caller'], core.CONTINUATION))
        return self.r[2], self.r[3]


class DestructorContinuationGateTests(unittest.TestCase):
    setUpClass = classmethod(previous.RegistryReleaseGateTests.setUpClass.__func__)

    def machine(self, **options):
        return DestructorContinuationGateMachine(self.image, **options)

    def watch_gate(self, machine):
        marks, snapshots = [], {}

        def observe(current, pc):
            labels = current.destructor_continuation_gate_labels
            if pc == labels['gate']:
                marks.append((len(current.reads), len(current.writes),
                              len(current.calls), len(current.freed),
                              current.r[29]))
            for name, target in (('gate', labels['gate']),
                                 ('replay', labels['gate_replay']),
                                 ('epilogue', core.EPILOGUE)):
                if pc == target:
                    snapshots[name] = (current.r.copy(), current.hi, current.lo)

        machine.on_instruction = observe
        return marks, snapshots

    def assert_stopped(self, machine, context, marks, snapshots, raw=22):
        self.assertEqual((machine.r[2], machine.r[3]), (MASK, raw))
        self.assertEqual((machine.r[29], machine.r[31]),
                         (context['caller_stack'], context['caller']))
        for register, value in context['saved'].items():
            self.assertEqual(machine.r[register], value, register)
        self.assertEqual(machine.r[28], context['gp'])
        self.assertEqual(snapshots['gate'], snapshots['epilogue'])
        self.assertEqual((machine.hi, machine.lo), snapshots['gate'][1:])
        labels = machine.destructor_continuation_gate_labels
        self.assertIn(labels['gate_stopped'], machine.trace)
        self.assertNotIn(labels['gate_forward'], machine.trace)
        self.assertNotIn(labels['gate_replay'], machine.trace)
        self.assertNotIn(core.CONTINUATION, machine.trace)
        self.assertNotIn(0x493C94, machine.trace)
        self.assertEqual(machine.resource_deletions, [])
        self.assertEqual(machine.cleanup_services, [])
        self.assertEqual(len(marks), 1)
        reads, writes, calls, freed, native_sp = marks[0]
        self.assertEqual(native_sp, context['sp'])
        self.assertEqual(machine.calls[calls:], [])
        self.assertEqual(machine.freed[freed:], [])
        first, end = native_sp - core.FRAME, context['caller_stack']
        self.assertTrue(all(first <= address and address + size <= end
                            for address, size in machine.reads[reads:]))
        self.assertTrue(all(first <= address and address + size <= end
                            for address, _, size in machine.writes[writes:]))
        self.assertNotIn((context['controller'] + 0x24, 4), machine.reads[reads:])
        self.assertEqual(machine.destructor_argument_delays, [(0x493F44, NAME)])
        self.assertEqual(set(machine.trace) & set(EARLIER_EFFECT_PCS), set())

    def assert_forwarded(self, machine, context, snapshots):
        self.assertEqual(snapshots['gate'], snapshots['replay'])
        self.assertEqual(len(machine.resource_entries), 1)
        expected, hi, lo = snapshots['gate']
        expected = expected.copy()
        expected[4] = machine.peek(context['controller'] + 0x24)
        expected[5] = context['name']
        expected[31] = core.CONTINUATION
        self.assertEqual(machine.resource_entries[0], (expected, hi, lo))
        self.assertEqual(machine.calls.count(core.RESOURCE_DELETE), 1)
        self.assertEqual(machine.resource_deletions[0][2:4],
                         (context['sp'], core.CONTINUATION))
        self.assertNotIn(0x493F54, machine.trace)
        self.assertNotIn(core.EPILOGUE, machine.trace)
        self.assertNotIn(machine.destructor_continuation_gate_labels['gate_stopped'],
                         machine.trace)
        self.assertEqual((machine.r[29], machine.r[31]),
                         (context['sp'], core.CONTINUATION))
        self.assertEqual(set(machine.trace) & set(EARLIER_EFFECT_PCS), set())

    def test_actual_raw_acquisition_error_executes_delete_and_destructor_unwinds(self):
        m = self.machine(acquire=22)
        context = m.seed_destructor()
        m.clear_events()
        marks, snapshots = self.watch_gate(m)
        self.assertEqual(m.run_destructor_slice(), (MASK, 22))
        self.assert_stopped(m, context, marks, snapshots)
        self.assertEqual(len(m.destructor_delete_entries), 1)
        self.assertEqual(m.destructor_delete_entries[0][0][:2], (CONTROLLER, NAME))
        self.assertEqual(m.destructor_delete_entries[0][1:], (context['sp'], 0x493F4C))
        self.assertIn(m.acquire_gate_labels['delete_gate_denied'], m.trace)
        self.assertNotIn(m.acquire_gate_labels['delete_gate_replay'], m.trace)
        self.assertEqual([(event[0], event[1], event[-1]) for event in m.raw_events],
                         [(RAW_LOCK, REGISTRY_MUTEX, 22)])
        self.assertEqual(m.freed, [])
        self.assertEqual(m.lifecycle_requests, [])

    def test_actual_zero_delete_restores_architecture_and_replays_resource_call_once(self):
        m = self.machine()
        context = m.seed_destructor()
        m.clear_events()
        _, snapshots = self.watch_gate(m)
        m.run_destructor_slice()
        self.assertEqual(snapshots['gate'][0][2], 0)
        self.assertEqual(snapshots['gate'][0][31], 0x493F4C)
        self.assertEqual(m.destructor_delete_entries[0][0][:2], (CONTROLLER, NAME))
        self.assertEqual(m.destructor_delete_entries[0][1:], (context['sp'], 0x493F4C))
        self.assertEqual([(event[0], event[1], event[-1]) for event in m.raw_events],
                         [(RAW_LOCK, REGISTRY_MUTEX, 0),
                          (RAW_UNLOCK, REGISTRY_MUTEX, 0)])
        # The original controller load is executed once in gate_replay. The
        # original493F54 delay is reproduced in the emitted jump, not revisited.
        loads = [access for access in m.constructor_accesses
                 if access[0] == 'read' and access[2:] == (CONTROLLER + 0x24, 4)]
        self.assertEqual(loads, [('read', m.destructor_continuation_gate_labels[
            'gate_replay'], CONTROLLER + 0x24, 4)])
        self.assertEqual(m.destructor_argument_delays, [
            (0x493F44, NAME),
            (m.destructor_continuation_gate_labels['gate_replay'] + 12, NAME)])
        self.assert_forwarded(m, context, snapshots)

    def test_unlinked_and_original_linked_resource_transfers_use_same_hostile_stub(self):
        hooked, native = self.machine(), self.machine()
        contexts = [machine.seed_destructor() for machine in (hooked, native)]
        native.remove_pair(core.HOOKS['gate'][0])
        for machine in (hooked, native):
            machine.clear_events()
            machine.run_destructor_slice()
        self.assertEqual(hooked.resource_deletions, native.resource_deletions)
        self.assertEqual(hooked.resource_entries, native.resource_entries)
        self.assertEqual((hooked.r, hooked.hi, hooked.lo),
                         (native.r, native.hi, native.lo))
        self.assertEqual(hooked.r[29], contexts[0]['sp'])
        self.assertEqual(hooked.trace.count(core.RESOURCE_DELETE), 1)
        self.assertEqual(native.trace.count(core.RESOURCE_DELETE), 0)
        self.assertEqual(hooked.calls.count(core.RESOURCE_DELETE), 1)
        self.assertEqual(native.calls.count(core.RESOURCE_DELETE), 1)
        self.assertEqual(native.destructor_argument_delays,
                         [(0x493F44, NAME), (0x493F50, NAME)])

    def test_populated_actual_delete_unlinks_before_the_separate_resource_continuation(self):
        m = self.machine()
        self.assertEqual(m.register(), 0)
        node = m.allocations[-1]
        context = m.seed_destructor()
        m.clear_events()
        _, snapshots = self.watch_gate(m)
        m.run_destructor_slice()
        self.assertEqual(snapshots['gate'][0][2], 0)
        self.assert_forwarded(m, context, snapshots)
        self.assertIn(node, m.freed)
        self.assertEqual(m.words_at(CONTROLLER + 0x34, 2),
                         (CONTROLLER + 0x34,) * 2)
        self.assertEqual(len(m.lifecycle_requests), 1)
        self.assertEqual(m.lifecycle_requests[0][0], 'retirement')
        self.assertLess(m.calls.index(0x466A80), m.calls.index(core.RESOURCE_DELETE))

    def test_stop_preserves_all_thirty_saved_gprs_hilo_and_exact_v0_v1(self):
        m = self.machine()
        marks, snapshots = self.watch_gate(m)
        self.assertEqual(m.invoke_destructor_gate(result=0x80000001,
                                                 diagnostic=0x12345678),
                         (0x80000001, 0x12345678))
        self.assertEqual(snapshots['gate'], snapshots['epilogue'])
        self.assertEqual(len(core.SAVE), 30)
        private = m.destructor_context['sp'] - core.FRAME
        for register, offset in core.SAVE.items():
            self.assertEqual(m.words_at(private + offset, 1)[0],
                             snapshots['gate'][0][register], register)
        self.assertEqual(m.words_at(private + core.HI, 2), snapshots['gate'][1:])
        self.assertEqual(m.resource_entries, [])
        self.assertEqual((m.r[29], m.r[31]), (STACK, RETURN))
        self.assertEqual(len(marks), 1)

    def test_foreign_direct_native_delete_keeps_previous_abi_and_architecture(self):
        for status in (0, 22):
            with self.subTest(status=status):
                old = RegistryReleaseGateMachine(self.image, acquire=status)
                m = self.machine(acquire=status)
                self.assertEqual(m.delete_native(), old.delete_native())
                self.assertEqual((m.r, m.hi, m.lo), (old.r, old.hi, old.lo))
                self.assertEqual(m.raw_events, old.raw_events)
                self.assertEqual(m.cleanup_services, old.cleanup_services)
                self.assertEqual(m.freed, old.freed)
                self.assertNotIn(m.destructor_continuation_gate_labels['gate'], m.trace)
                self.assertEqual(m.resource_deletions, [])

    def test_cache_keeps_exact_code_fresh_metadata_state_and_restores_all_functions(self):
        originals = {module: module.assemble for module in _ASSEMBLY_CACHE_MODULES}
        uncached = self.machine(acquire=22, assembly_cache=False)
        cached = self.machine(acquire=22)
        self.assertEqual(cached.code, uncached.code)
        self.assertEqual(len(cached.code), 89640)
        self.assertEqual(hashlib.sha256(cached.code).hexdigest(),
                         '996f66b14285bdb35490b4e4e2cbc380c2ed888a558323ea1828a58ebc246b1c')
        guarded_parent = previous.stage.assemble(
            STATE, BIND_STATE, OWNER_STATE, CONTROLLER, REGISTRY_MUTEX,
            PAINT_MUTEX, CODE, LIFECYCLE, QUEUE, TRANSPORT_MUTEX, FAULT,
            following_code_bytes=500)
        self.assertEqual(cached.code[:89140], guarded_parent['code'])
        self.assertIsNot(cached.composition, uncached.composition)
        self.assertIsNot(cached.destructor_continuation_gate_labels,
                         uncached.destructor_continuation_gate_labels)
        for machine in (cached, uncached):
            machine.seed_destructor()
            machine.clear_events()
        self.assertEqual(cached.run_destructor_slice(), uncached.run_destructor_slice())
        self.assertEqual((cached.r, cached.hi, cached.lo),
                         (uncached.r, uncached.hi, uncached.lo))
        cached.destructor_continuation_gate_labels['host_only_cache_probe'] = 123
        cached.registry_held = True
        fresh = self.machine()
        self.assertNotIn('host_only_cache_probe', fresh.destructor_continuation_gate_labels)
        self.assertFalse(fresh.registry_held)
        self.assertEqual(fresh.raw_events, [])
        fresh.seed_destructor()
        fresh.clear_events()
        fresh.run_destructor_slice()
        self.assertEqual(len(fresh.resource_deletions), 1)
        self.assertEqual(cached.resource_deletions, [])
        with self.assertRaises(ValueError):
            self.machine(capacity=True)
        for module, original in originals.items():
            self.assertIs(module.assemble, original, module.__name__)


if __name__ == '__main__':
    unittest.main()
