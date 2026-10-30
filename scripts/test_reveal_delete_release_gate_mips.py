#!/usr/bin/env python3
"""Execute actual name deletion and its destructor-scoped raw-release stop.

The bounded slice starts at493F40 after prior worker/cache/detach effects.
Native4395A0, the tail-pop callback, both release wrappers and the native
destructor epilogue execute. Only the inherited opaque imports are hostile
bounded substitutes. Genuine retained nonaliasing frames and coherent hooks
are supplied; these tests establish neither stack authentication nor lifetime.
"""

from contextlib import contextmanager
import hashlib
import unittest

import reveal_delete_release_gate_mips as core
import reveal_delete_release_gate_stage as stage
import test_reveal_destructor_continuation_gate_mips as previous
from test_reveal_destructor_continuation_gate_mips import (
    DestructorContinuationGateMachine, STATE, BIND_STATE, OWNER_STATE,
    CONTROLLER, REGISTRY_MUTEX, PAINT_MUTEX, CODE, LIFECYCLE, QUEUE,
    TRANSPORT_MUTEX, FAULT, RAW_LOCK, RAW_UNLOCK, STACK, RETURN, MASK,
    NAME, EARLIER_EFFECT_PCS, _cached_assembler,
    _fixture_assembly_cache as imported_fixture_assembly_cache)
from test_reveal_registry_release_gate_mips import FIRST


DESTRUCTOR = previous.core
PHASES = ('begin', 'release_select', 'raw_release_call', 'raw_release_return')
DELEGATED_PHASES = ('begin', 'raw_release_call', 'raw_release_return', 'complete')
STAGE_ARGS = (STATE, BIND_STATE, OWNER_STATE, CONTROLLER, REGISTRY_MUTEX,
              PAINT_MUTEX, CODE, LIFECYCLE, QUEUE, TRANSPORT_MUTEX, FAULT)
_ASSEMBLY_CACHE_MODULES = (*previous._ASSEMBLY_CACHE_MODULES, core, stage)


@contextmanager
def _fixture_assembly_cache(enabled):
    """Temporarily cache only pure assembly; never CPU state or test results."""
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


class DeleteReleaseGateMachine(DestructorContinuationGateMachine):
    """All release classification and diversion comes from emitted words."""

    def __init__(self, image, *, assembly_cache=True, **options):
        with _fixture_assembly_cache(assembly_cache):
            super().__init__(image, assembly_cache=False, **options)
            selected = {name: options[name] for name in (
                'capacity', 'lifecycle_capacity', 'owner_capacity', 'ticket_limit',
                'queue_capacity') if name in options}
            self.composition = stage.assemble(
                *STAGE_ARGS, transport_capacity=self.peek(QUEUE + 8), **selected)
            self.code = self.code_bytes = self.composition['code']
            self.labels = self.composition['labels']
            for name in ('owner', 'issuer', 'receipt', 'adapter', 'capture',
                         'lifecycle', 'retirement', 'birth_capture', 'birth_queue',
                         'birth_consumer', 'acquire_gate',
                         'constructor_continuation_gate', 'explorer_failure_gate',
                         'registry_release_gate', 'destructor_continuation_gate',
                         'delete_release_gate'):
                setattr(self, name + '_labels', self.composition[name + '_labels'])
            self.bridge_labels = self.receipt_labels
            for pc in self.composition['delete_release_gate_replaced_hooks']:
                self.remove_pair(pc)
            for pc, words in self.composition['coherent_hooks'].items():
                for index, word in enumerate(words):
                    self.patches[pc + index * 4] = word
            self.clear_events()

    def restore_legacy_delete_release_phase(self, phase):
        """Model explicitly unsupported partial activation, not an installer."""
        pc = core.HOOKS[phase][0]
        old = self.composition['delete_release_gate_replaced_hooks'].get(pc)
        self.remove_pair(pc)
        if old is not None:
            for index, word in enumerate(old):
                self.patches[pc + index * 4] = word

    def delete_release_words(self, destructor_sp=None):
        if destructor_sp is None:
            destructor_sp = self.destructor_context['sp']
        return self.words_at(destructor_sp + core.TAG, 3)


class DeleteReleaseGateTests(unittest.TestCase):
    setUpClass = classmethod(previous.DestructorContinuationGateTests.setUpClass.__func__)

    def machine(self, **options):
        return DeleteReleaseGateMachine(self.image, **options)

    def watch_completion(self, machine):
        snapshots, marks = {}, []

        def observe(current, pc):
            targets = {
                'entry': current.delete_release_gate_labels['complete'],
                'legacy': current.destructor_continuation_gate_labels['gate'],
                'replay': current.destructor_continuation_gate_labels['gate_replay'],
                'epilogue': DESTRUCTOR.EPILOGUE,
            }
            for name, target in targets.items():
                if pc == target:
                    snapshots[name] = (current.r.copy(), current.hi, current.lo)
                    if name == 'entry':
                        marks.append((len(current.reads), len(current.writes),
                                      len(current.calls), len(current.freed),
                                      current.r[29]))

        machine.on_instruction = observe
        return marks, snapshots

    def assert_completion_architecture(self, snapshots, result=None):
        expected, hi, lo = snapshots['entry']
        expected = expected.copy()
        if result is not None:
            expected[2:4] = result
        self.assertEqual(snapshots['legacy'], (expected, hi, lo))

    def assert_failed(self, machine, context, marks, snapshots, raw=22):
        self.assertEqual((machine.r[2], machine.r[3]), (MASK, raw))
        self.assertEqual((machine.r[29], machine.r[31]),
                         (context['caller_stack'], context['caller']))
        for register, value in context['saved'].items():
            self.assertEqual(machine.r[register], value, register)
        self.assertEqual(machine.r[28], context['gp'])
        self.assertEqual(snapshots['legacy'], snapshots['epilogue'])
        self.assertEqual((machine.hi, machine.lo), snapshots['legacy'][1:])
        self.assertIn(machine.destructor_continuation_gate_labels['gate_stopped'],
                      machine.trace)
        self.assertNotIn(DESTRUCTOR.CONTINUATION, machine.trace)
        self.assertNotIn(0x493C94, machine.trace)
        self.assertEqual(machine.resource_deletions, [])
        self.assertEqual(len(marks), 1)
        reads, writes, calls, freed, destructor_sp = marks[0]
        self.assertEqual(destructor_sp, context['sp'])
        self.assertEqual(machine.calls[calls:], [])
        self.assertEqual(machine.freed[freed:], [])
        first = destructor_sp - core.FRAME
        self.assertTrue(all(first <= address and address + size <= context['caller_stack']
                            for address, size in machine.reads[reads:]))
        self.assertTrue(all(first <= address and address + size <= context['caller_stack']
                            for address, _, size in machine.writes[writes:]))
        self.assertNotIn((CONTROLLER + 0x24, 4), machine.reads[reads:])
        self.assertEqual(machine.destructor_argument_delays, [(0x493F44, NAME)])
        self.assertEqual(set(machine.trace) & set(EARLIER_EFFECT_PCS), set())
        self.assertEqual(machine.delete_release_words()[0], 0)

    def assert_forwarded(self, machine, context, snapshots):
        self.assert_completion_architecture(snapshots)
        previous.DestructorContinuationGateTests.assert_forwarded(
            self, machine, context,
            {'gate': snapshots['legacy'], 'replay': snapshots['replay']})
        self.assertIn(machine.delete_release_gate_labels['complete_admitted'], machine.trace)
        self.assertEqual(machine.delete_release_words()[0], 0)

    def watch_raw_release(self, machine):
        marks = []

        def observe(current, target):
            if target == RAW_UNLOCK and current.r[4] == REGISTRY_MUTEX:
                marks.append((len(current.reads), len(current.writes),
                              len(current.calls), len(current.freed), current.r[29]))

        machine.on_service = observe
        return marks

    def assert_private_after_raw_release(self, machine, context, marks):
        self.assertEqual(len(marks), 1)
        reads, writes, calls, freed, raw_sp = marks[0]
        self.assertEqual(raw_sp, context['sp'] - 64)
        first = raw_sp - core.FRAME
        self.assertEqual(machine.calls[calls:], [])
        self.assertEqual(machine.freed[freed:], [])
        self.assertTrue(all(first <= address and address + size <= context['caller_stack']
                            for address, size in machine.reads[reads:]))
        self.assertTrue(all(first <= address and address + size <= context['caller_stack']
                            for address, _, size in machine.writes[writes:]))

    def test_empty_ring_actual_zero_replays_resource_once_with_previous_final_abi(self):
        m, old = self.machine(), DestructorContinuationGateMachine(self.image)
        context = m.seed_destructor()
        old.seed_destructor()
        m.clear_events()
        old.clear_events()
        _, snapshots = self.watch_completion(m)
        self.assertEqual(m.run_destructor_slice(), old.run_destructor_slice())
        self.assertEqual((m.r, m.hi, m.lo), (old.r, old.hi, old.lo))
        self.assertEqual(m.raw_events, old.raw_events)
        self.assert_forwarded(m, context, snapshots)
        self.assertIn(0x4395E0, m.trace)
        self.assertNotIn(0x439654, m.trace)
        self.assertEqual(m.trace.count(core.HOOKS['release_select'][0]), 1)
        self.assertEqual(m.delete_release_words(), (0, 0, context['sp'] - 64))
        self.assertFalse(m.registry_held)

    def test_successful_match_and_no_match_both_reach_common_tail(self):
        for matched in (False, True):
            with self.subTest(matched=matched):
                m = self.machine()
                self.assertEqual(m.register(), 0)
                node = m.allocations[-1]
                name = NAME if matched else NAME + 0x40
                if not matched:
                    m.bytes(name, b'Sleep\0')
                context = m.seed_destructor(name=name)
                m.clear_events()
                _, snapshots = self.watch_completion(m)
                m.run_destructor_slice()
                self.assert_forwarded(m, context, snapshots)
                self.assertIn(0x439654, m.trace)
                self.assertEqual(m.trace.count(core.HOOKS['release_select'][0]), 1)
                self.assertEqual(node in m.freed, matched)
                self.assertEqual(len(m.lifecycle_requests), int(matched))
                self.assertEqual(m.words_at(CONTROLLER + 0x34, 2),
                                 (CONTROLLER + 0x34,) * 2 if matched else (node, node))

    def test_actual_release_error_unwinds_with_exact_raw_and_no_post_release_shared_access(self):
        m = self.machine(release=0x82, registry_release_failure_releases=False)
        context = m.seed_destructor()
        m.clear_events()
        marks, snapshots = self.watch_completion(m)
        raw_marks = self.watch_raw_release(m)
        self.assertEqual(m.run_destructor_slice(), (MASK, 0x82))
        self.assert_private_after_raw_release(m, context, raw_marks)
        self.assert_failed(m, context, marks, snapshots, 0x82)
        self.assert_completion_architecture(snapshots, (MASK, 0x82))
        self.assertEqual([(event[0], event[1], event[-1]) for event in m.raw_events],
                         [(RAW_LOCK, REGISTRY_MUTEX, 0), (RAW_UNLOCK, REGISTRY_MUTEX, 0x82)])
        self.assertTrue(m.registry_held)
        self.assertEqual(m.cleanup_services, [])

    def test_populated_release_error_preserves_earlier_native_unlink_and_frees(self):
        m = self.machine()
        self.assertEqual(m.register(), 0)
        node = m.allocations[-1]
        m.release = 22
        context = m.seed_destructor()
        m.clear_events()
        marks, snapshots = self.watch_completion(m)
        raw_marks = self.watch_raw_release(m)
        self.assertEqual(m.run_destructor_slice(), (MASK, 22))
        self.assert_private_after_raw_release(m, context, raw_marks)
        self.assert_failed(m, context, marks, snapshots)
        self.assertIn(node, m.freed)
        self.assertEqual(m.words_at(CONTROLLER + 0x34, 2), (CONTROLLER + 0x34,) * 2)
        self.assertEqual(len(m.lifecycle_requests), 1)
        self.assertEqual(m.lifecycle_requests[0][0], 'retirement')
        self.assertLess(m.trace.index(0x439618), m.trace.index(core.REGISTRY_UNLOCK))
        self.assertTrue(m.cleanup_services)

    def test_acquisition_denial_keeps_exact_existing_error_without_release_evidence(self):
        m = self.machine(acquire=22)
        context = m.seed_destructor()
        m.clear_events()
        marks, snapshots = self.watch_completion(m)
        self.assertEqual(m.run_destructor_slice(), (MASK, 22))
        self.assert_failed(m, context, marks, snapshots)
        self.assert_completion_architecture(snapshots)
        self.assertEqual([(event[0], event[-1]) for event in m.raw_events], [(RAW_LOCK, 22)])
        self.assertNotIn(m.delete_release_gate_labels['release_select'], m.trace)
        self.assertNotIn(m.delete_release_gate_labels['complete_denied'], m.trace)
        self.assertEqual(m.delete_release_words(), (0, MASK, 0))

    def test_fresh_witness_transitions_use_retained_destructor_not_popped_delete_frame(self):
        m = self.machine(release=22)
        context = m.seed_destructor()
        m.clear_events()
        observations = []

        def observe(current, pc):
            labels = current.delete_release_gate_labels
            for phase in PHASES:
                if pc == labels[phase + '_replay']:
                    observations.append((phase, current.r[29], current.delete_release_words()))
            if pc == labels['complete']:
                observations.append(('complete', current.r[29], current.delete_release_words()))
            if pc == current.destructor_continuation_gate_labels['gate']:
                observations.append(('legacy', current.r[29], current.delete_release_words()))

        m.on_instruction = observe
        self.assertEqual(m.run_destructor_slice(), (MASK, 22))
        destructor_sp, raw_sp = context['sp'], context['sp'] - 64
        self.assertEqual(observations, [
            ('begin', destructor_sp - 56, (core.ARMED, MASK, 0)),
            ('release_select', destructor_sp - 56, (core.SELECTED, MASK, 0)),
            ('raw_release_call', raw_sp, (core.ENTERED, MASK, raw_sp)),
            ('raw_release_return', raw_sp, (core.CAPTURED, 22, raw_sp)),
            ('complete', destructor_sp, (core.CAPTURED, 22, raw_sp)),
            ('legacy', destructor_sp, (0, 22, raw_sp))])

    def test_each_dispatcher_restores_all_gprs_hilo_and_select_replays_only_native_loads(self):
        for status in (0, 22):
            with self.subTest(status=status):
                m = self.machine(release=status)
                context = m.seed_destructor()
                m.clear_events()
                snapshots = {}

                def observe(current, pc):
                    labels = current.delete_release_gate_labels
                    legacy = current.composition['delete_release_gate_legacy_entries']
                    for phase in (*PHASES, 'complete'):
                        if pc == labels[phase]:
                            snapshots[phase, 'entry'] = (current.r.copy(), current.hi, current.lo)
                        if phase in PHASES and pc == labels[phase + '_replay']:
                            snapshots[phase, 'replay'] = (current.r.copy(), current.hi, current.lo)
                        if phase in DELEGATED_PHASES and pc == legacy[phase]:
                            snapshots[phase, 'delegate'] = (current.r.copy(), current.hi, current.lo)
                    if pc == 0x439660:
                        snapshots['native'] = (current.r.copy(), current.hi, current.lo)

                m.on_instruction = observe
                m.run_destructor_slice()
                for phase in PHASES:
                    self.assertEqual(snapshots[phase, 'entry'], snapshots[phase, 'replay'])
                    if phase != 'release_select':
                        self.assertEqual(snapshots[phase, 'entry'], snapshots[phase, 'delegate'])
                expected, hi, lo = snapshots['release_select', 'entry']
                expected = expected.copy()
                expected[31] = 0x493F4C
                expected[20] = context['saved'][20]
                self.assertEqual(snapshots['native'], (expected, hi, lo))
                expected, hi, lo = snapshots['complete', 'entry']
                expected = expected.copy()
                if status:
                    expected[2:4] = MASK, status
                self.assertEqual(snapshots['complete', 'delegate'], (expected, hi, lo))

    def test_native_callback_and_raw_import_keep_exact_original_sp_ra_and_one_call(self):
        m = self.machine(release=22)
        context = m.seed_destructor()
        callbacks = []

        def observe(current, pc):
            if pc == core.REGISTRY_UNLOCK:
                callbacks.append((tuple(current.r[4:8]), current.r[29], current.r[31]))

        m.clear_events()
        m.on_instruction = observe
        m.run_destructor_slice()
        self.assertEqual(len(callbacks), 1)
        self.assertEqual(callbacks[0][0][0], CONTROLLER)
        self.assertEqual(callbacks[0][1:], (context['sp'], 0x493F4C))
        self.assertEqual(m.raw_events[-1],
                         (RAW_UNLOCK, REGISTRY_MUTEX, context['sp'] - 64, 0x466DD0, 22))
        self.assertEqual(m.trace.count(core.REGISTRY_UNLOCK), 1)
        self.assertEqual(len([event for event in m.raw_events if event[0] == RAW_UNLOCK]), 1)

    def test_foreign_direct_delete_constructor_and_checked_birth_keep_previous_abi(self):
        for status in (0, 22):
            for route in ('delete', 'constructor', 'birth'):
                with self.subTest(status=status, route=route):
                    old = DestructorContinuationGateMachine(self.image, release=status)
                    m = self.machine(release=status)
                    invoke = {'delete': lambda current: current.delete_native(),
                              'constructor': lambda current: current.construct(FIRST),
                              'birth': lambda current: current.register_birth()}[route]
                    self.assertEqual(invoke(m), invoke(old))
                    self.assertEqual((m.r, m.hi, m.lo), (old.r, old.hi, old.lo))
                    self.assertEqual(m.raw_events, old.raw_events)
                    self.assertEqual(m.freed, old.freed)
                    if route == 'birth':
                        self.assertEqual(m.birth_output(), old.birth_output())
                    self.assertNotIn(m.delete_release_gate_labels['complete'], m.trace)

    def test_cache_preserves_exact_bytes_fresh_state_metadata_and_function_restoration(self):
        originals = {module: module.assemble for module in _ASSEMBLY_CACHE_MODULES}
        uncached = self.machine(release=22, assembly_cache=False)
        cached = self.machine(release=22)
        self.assertEqual(cached.code, uncached.code)
        self.assertEqual(hashlib.sha256(cached.code).digest(), hashlib.sha256(uncached.code).digest())
        self.assertEqual(len(cached.code), 91940)
        self.assertEqual(hashlib.sha256(cached.code).hexdigest(),
                         '332b5cf381ecd46f117651638d992475b8ceed505721f66c8cc1eeecdba58364')
        tail = cached.composition['delete_release_gate_code_bytes']
        guarded_parent = previous.stage.assemble(*STAGE_ARGS, following_code_bytes=tail)
        self.assertEqual(cached.code[:89640], guarded_parent['code'])
        self.assertEqual(cached.composition['delete_release_gate_prefix_code_bytes'], 89640)
        self.assertEqual(len(cached.code), 89640 + tail)
        self.assertIsNot(cached.composition, uncached.composition)
        self.assertIsNot(cached.delete_release_gate_labels, uncached.delete_release_gate_labels)
        for machine in (cached, uncached):
            machine.seed_destructor()
            machine.clear_events()
        self.assertEqual(cached.run_destructor_slice(), uncached.run_destructor_slice())
        self.assertEqual((cached.r, cached.hi, cached.lo), (uncached.r, uncached.hi, uncached.lo))
        cached.delete_release_gate_labels['host_only_cache_probe'] = 123
        cached.registry_held = True
        fresh = self.machine()
        self.assertNotIn('host_only_cache_probe', fresh.delete_release_gate_labels)
        self.assertFalse(fresh.registry_held)
        self.assertEqual(fresh.raw_events, [])
        fresh.seed_destructor()
        fresh.clear_events()
        fresh.run_destructor_slice()
        self.assertEqual(len(fresh.resource_entries), 1)
        self.assertEqual(cached.resource_entries, [])
        with self.assertRaises(ValueError):
            self.machine(capacity=True)
        for module, original in originals.items():
            self.assertIs(module.assemble, original, module.__name__)


if __name__ == '__main__':
    unittest.main()
