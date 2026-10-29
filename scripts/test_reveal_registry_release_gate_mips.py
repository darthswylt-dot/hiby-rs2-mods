#!/usr/bin/env python3
"""Execute constructor-scoped release propagation without graph rollback.

Actual native registration, its release facades/raw wrapper, both constructors
and scoped native explorer exits execute. The four new emitted phases delegate
the old three capture observers with their original architecture. Existing raw,
resource and opaque UI/name imports remain bounded hostile-ABI substitutes.
Genuine retained mapped nonaliasing frames are supplied, not established here.
"""

from contextlib import contextmanager
from copy import deepcopy
from functools import wraps
from importlib import import_module
import hashlib
import unittest

import reveal_constructor_continuation_gate_mips as constructor
import reveal_creation_capture_mips as capture
import reveal_registry_release_gate_mips as core
import reveal_registry_release_gate_stage as stage
import test_reveal_explorer_failure_gate_mips as previous
from test_reveal_birth_capture_mips import OUTPUT as BIRTH_OUTPUT
from test_reveal_explorer_failure_gate_mips import (
    ExplorerFailureGateMachine, FIRST, SECOND, ROUTES, NAME_POSTWORK,
    EXPLORER_SLICE_END, EXPLORER_RETURN, EXPLORER_NULL, SECOND_CALLER_STACK,
    OUTER_VIEW, VIEW_SENTINEL, STATE, BIND_STATE, OWNER_STATE, CONTROLLER,
    REGISTRY_MUTEX, PAINT_MUTEX, CODE, LIFECYCLE, QUEUE, TRANSPORT_MUTEX,
    FAULT, RAW_LOCK, RAW_UNLOCK, STACK, RETURN, MASK)


PHASES = ('release_select', 'raw_release_call', 'raw_release_return')
LEGACY_PHASES = {
    'release_select': 'release_call',
    'raw_release_call': 'raw_release_call',
    'raw_release_return': 'raw_release_return',
}


# Only this fixture's explicit pure emitter/composer chain participates. The
# cache retains deterministic compiled bytes and metadata, never machine state,
# native observations or interpreter results, and cannot decide a release result.
_ASSEMBLY_CACHE_MODULES = tuple(import_module(name) for name in (
    'reveal_paint_retirement_mips',
    'reveal_registry_receipt_mips',
    'reveal_registry_owner_mips',
    'reveal_registry_owner_stage',
    'reveal_owner_carrier_mips',
    'reveal_owner_carrier_stage',
    'reveal_creation_capture_mips',
    'reveal_creation_capture_stage',
    'reveal_registry_lifecycle_mips',
    'reveal_registry_retirement_mips',
    'reveal_registry_lifecycle_stage',
    'reveal_birth_capture_mips',
    'reveal_birth_capture_stage',
    'reveal_birth_queue_mips',
    'reveal_birth_queue_stage',
    'reveal_birth_consumer_mips',
    'reveal_birth_consumer_stage',
    'reveal_registry_acquire_gate_mips',
    'reveal_registry_acquire_gate_stage',
    'reveal_constructor_continuation_gate_mips',
    'reveal_constructor_continuation_gate_stage',
    'reveal_explorer_failure_gate_mips',
    'reveal_explorer_failure_gate_stage',
    'reveal_registry_release_gate_mips',
    'reveal_registry_release_gate_stage',
))
_ASSEMBLY_CACHE = {}


def _assembly_argument_key(value):
    """Keep exact scalar/tuple types, including bool versus int, in every key."""
    kind = type(value)
    if kind in (type(None), bool, int, str, bytes):
        return kind, value
    if kind is tuple:
        return kind, tuple(_assembly_argument_key(item) for item in value)
    # Do not normalize mutable containers, subclasses or other unsupported
    # objects: their original assembler must perform its usual validation.
    raise TypeError('unsupported assembly cache argument type')


def _cached_assembler(assemble):
    @wraps(assemble)
    def cached(*args, **kwargs):
        try:
            key = (assemble, _assembly_argument_key(args),
                   _assembly_argument_key(tuple(sorted(kwargs.items()))))
        except TypeError:
            return assemble(*args, **kwargs)
        if key not in _ASSEMBLY_CACHE:
            # A failing assembly never populates the cache. No stored result
            # escapes: every caller receives fresh mutable labels/metadata.
            _ASSEMBLY_CACHE[key] = assemble(*args, **kwargs)
        return deepcopy(_ASSEMBLY_CACHE[key])

    return cached


@contextmanager
def _fixture_assembly_cache(enabled):
    """Temporarily wrap only pure assembly during serial fixture construction."""
    if not enabled:
        yield
        return
    originals = []
    try:
        for module in _ASSEMBLY_CACHE_MODULES:
            assemble = module.assemble
            originals.append((module, assemble))
            module.assemble = _cached_assembler(assemble)
        yield
    finally:
        for module, assemble in reversed(originals):
            module.assemble = assemble


class RegistryReleaseGateMachine(ExplorerFailureGateMachine):
    """Coherent replacement hooks, never a Python release/status oracle."""

    def __init__(self, image, *, assembly_cache=True, **options):
        with _fixture_assembly_cache(assembly_cache):
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
                         'constructor_continuation_gate', 'explorer_failure_gate',
                         'registry_release_gate'):
                setattr(self, name + '_labels', self.composition[name + '_labels'])
            self.bridge_labels = self.receipt_labels
            # The three old observers are still executed as delegates. Their old
            # fetch overrides must not take priority over the new dispatchers.
            for pc in self.composition['registry_release_gate_replaced_hooks']:
                self.remove_pair(pc)
            for pc, words in self.composition['coherent_hooks'].items():
                for index, word in enumerate(words):
                    self.patches[pc + 4 * index] = word
            self.clear_events()

    def restore_legacy_release_phase(self, name):
        if name == 'complete':
            self.remove_pair(core.HOOKS[name][0])
            return
        pc = core.HOOKS[name][0]
        words = self.composition['registry_release_gate_replaced_hooks'][pc]
        for index, word in enumerate(words):
            self.patches[pc + index * 4] = word

    def release_words(self, native_sp):
        return self.words_at(native_sp + core.TAG, 3)


class RegistryReleaseGateTests(unittest.TestCase):
    setUpClass = classmethod(previous.ExplorerFailureGateTests.setUpClass.__func__)
    assert_null_unwind = previous.ExplorerFailureGateTests.assert_null_unwind

    def machine(self, **options):
        return RegistryReleaseGateMachine(self.image, **options)

    def test_assembly_cache_preserves_code_isolation_typed_keys_and_function_restoration(self):
        originals = {module: module.assemble for module in _ASSEMBLY_CACHE_MODULES}
        uncached = self.machine(release=22, assembly_cache=False)
        cached = self.machine(release=22)
        self.assertEqual(cached.code, uncached.code)
        self.assertEqual(hashlib.sha256(cached.code).hexdigest(),
                         '03ec46d436914eef93a8aa118496608d59df4539926dc6272ff81449e50687de')
        self.assertIsNot(cached.composition, uncached.composition)
        self.assertIsNot(cached.registry_release_gate_labels,
                         uncached.registry_release_gate_labels)
        self.assertEqual(cached.construct(FIRST), uncached.construct(FIRST))
        self.assertEqual(cached.raw_events, uncached.raw_events)
        cached.registry_release_gate_labels['host_only_cache_probe'] = 123
        fresh = self.machine(release=0)
        self.assertNotIn('host_only_cache_probe', fresh.registry_release_gate_labels)
        self.assertEqual(fresh.code, uncached.code)
        self.assertNotEqual(fresh.construct(FIRST)[0], 0)
        self.assertEqual(len(fresh.native_continuations), 1)
        self.assertEqual(cached.native_continuations, [])
        self.assertNotEqual(_assembly_argument_key((True,)),
                            _assembly_argument_key((1,)))
        self.machine(capacity=1)
        with self.assertRaises(ValueError):
            self.machine(capacity=True)
        for module, original in originals.items():
            self.assertIs(module.assemble, original, module.__name__)

    def watch_raw_release(self, machine):
        marks = []

        def observe(current, target):
            if target == RAW_UNLOCK and current.r[4] == REGISTRY_MUTEX:
                marks.append((len(current.reads), len(current.writes),
                              len(current.calls), current.r[29]))

        machine.on_service = observe
        return marks

    def assert_private_after_release(self, machine, marks, caller_stack=STACK):
        self.assertEqual(len(marks), 1)
        reads, writes, calls, raw_sp = marks[0]
        first = raw_sp - core.FRAME
        self.assertEqual(machine.calls[calls:], [])
        self.assertTrue(all(first <= address and address + size <= caller_stack
                            for address, size in machine.reads[reads:]))
        self.assertTrue(all(first <= address and address + size <= caller_stack
                            for address, _, size in machine.writes[writes:]))

    def assert_local_stop(self, machine, constructor_address, raw):
        self.assertEqual(machine.r[2], machine.created_engines[0])
        self.assertNotEqual(machine.r[2], 0)
        self.assertEqual(machine.r[3], raw)
        gate = 'first_gate' if constructor_address == FIRST else 'second_gate'
        self.assertIn(machine.constructor_continuation_gate_labels[gate + '_stopped'],
                      machine.trace)
        self.assertEqual(machine.native_continuations, [])
        self.assertNotIn(NAME_POSTWORK, machine.calls)
        self.assertEqual(machine.freed, [])
        self.assertEqual((machine.r[29], machine.r[31]), (STACK, RETURN))

    def test_both_actual_constructors_admit_raw_zero_and_keep_native_engine_abi(self):
        for address, gate, frame in ROUTES:
            with self.subTest(constructor=hex(address)):
                m = self.machine()
                result, _ = m.construct(address)
                self.assertEqual(result, m.created_engines[0])
                self.assertNotEqual(result, 0)
                self.assertEqual(len(m.native_continuations), 1)
                self.assertIn(NAME_POSTWORK, m.calls)
                self.assertEqual(m.lifecycle_header(), (1, 0, 0, 0))
                native_sp = m.native_entries[0][2] - core.REGISTER_FRAME
                raw_sp = native_sp - core.FACADE_FRAME - core.RAW_FRAME
                self.assertEqual(m.release_words(native_sp), (0, 0, raw_sp))
                self.assertIn(m.registry_release_gate_labels['complete_admitted'], m.trace)
                self.assertNotIn(m.registry_release_gate_labels['complete_denied'], m.trace)
                self.assertFalse(m.registry_held)

    def test_both_constructor_release_errors_reach_existing_local_stops(self):
        for address, gate, frame in ROUTES:
            with self.subTest(constructor=hex(address)):
                m = self.machine(release=22)
                self.assertEqual(m.construct(address), (m.created_engines[0], 22))
                self.assert_local_stop(m, address, 22)
                self.assertIn(m.registry_release_gate_labels['complete_denied'], m.trace)
                self.assertNotIn(m.registry_release_gate_labels['complete_admitted'], m.trace)

    def test_explorer_release_error_executes_actual_null_unwind_without_store_or_enable(self):
        m = self.machine(release=22)
        context = m.seed_explorer()
        m.clear_events()
        marks = self.watch_raw_release(m)
        self.assertEqual(m.run_explorer_slice(), (0, 22))
        self.assert_private_after_release(m, marks, context['caller_stack'])
        self.assert_null_unwind(m, context)
        self.assertEqual(m.lifecycle_header(), (1, 0, 0, 0))
        self.assertEqual(len(m.allocations), 1)

    def test_publication_and_birth_are_not_rolled_back_by_later_release_error(self):
        m = self.machine(release=0x82)
        observations = []

        def observe(current, target):
            if target == RAW_UNLOCK and current.r[4] == REGISTRY_MUTEX:
                observations.append((current.lifecycle_header(),
                                     current.binding_header(),
                                     current.lifecycle_record()[4:6]))

        m.on_service = observe
        result, raw = m.construct(FIRST)
        self.assertEqual(raw, 0x82)
        self.assertEqual(observations[0][0:2], ((1, 0, 0, 0), (1, 0, 0, 0)))
        node = m.allocations[0]
        self.assertEqual(observations[0][2], (node, result))
        self.assertEqual(m.words_at(CONTROLLER + 0x34, 2), (node, node))
        self.assertEqual(m.lifecycle_record()[4:6], (node, result))
        self.assertEqual(m.freed, [])

    def test_original_indirect_callback_and_raw_release_arguments_and_ra_are_unchanged(self):
        m = self.machine(release=22)
        callbacks = []

        def observe(current, pc):
            if pc == core.REGISTRY_UNLOCK:
                callbacks.append((tuple(current.r[4:8]), current.r[29], current.r[31]))

        m.on_instruction = observe
        m.construct(FIRST)
        native_sp = m.native_entries[0][2] - core.REGISTER_FRAME
        raw_sp = native_sp - core.FACADE_FRAME - core.RAW_FRAME
        self.assertEqual(len(callbacks), 1)
        self.assertEqual(callbacks[0][0][0], CONTROLLER)
        self.assertEqual(callbacks[0][1:], (native_sp, 0x438A68))
        self.assertEqual(m.raw_events[-1],
                         (RAW_UNLOCK, REGISTRY_MUTEX, raw_sp, 0x466DD0, 22))

    def test_fresh_selected_entered_captured_witness_is_consumed_before_constructor_gate(self):
        for address, gate, frame in ROUTES:
            with self.subTest(constructor=hex(address)):
                m = self.machine(release=22)
                observations = []

                def observe(current, pc):
                    labels = current.registry_release_gate_labels
                    for phase in PHASES:
                        if pc == labels[phase + '_replay']:
                            native = (current.r[29] if phase == 'release_select'
                                      else current.r[29] + core.FACADE_FRAME + core.RAW_FRAME)
                            actual_native = current.native_entries[0][2] - core.REGISTER_FRAME
                            # Global raw delegates may also replay an unrelated
                            # P release during publication. Observe this exact
                            # registration frame, not that other native route.
                            if native == actual_native:
                                observations.append((phase, current.release_words(native)))
                    if pc == labels['complete']:
                        observations.append(('complete', current.release_words(current.r[29])))
                    if pc == current.constructor_continuation_gate_labels[gate]:
                        native = current.r[29] - core.REGISTER_FRAME
                        observations.append(('constructor', current.release_words(native)))

                m.on_instruction = observe
                m.construct(address)
                native_sp = m.native_entries[0][2] - core.REGISTER_FRAME
                raw_sp = native_sp - core.FACADE_FRAME - core.RAW_FRAME
                self.assertEqual(observations, [
                    ('release_select', (core.SELECTED, MASK, 0)),
                    ('raw_release_call', (core.ENTERED, MASK, raw_sp)),
                    ('raw_release_return', (core.CAPTURED, 22, raw_sp)),
                    ('complete', (core.CAPTURED, 22, raw_sp)),
                    ('constructor', (0, 22, raw_sp))])

    def test_all_three_dispatchers_restore_every_gpr_and_hilo_before_legacy_delegate(self):
        for status in (0, 22):
            for address, gate, frame in ROUTES:
                with self.subTest(status=status, constructor=hex(address)):
                    m = self.machine(release=status)
                    snapshots = {}

                    def observe(current, pc):
                        labels = current.registry_release_gate_labels
                        legacy = current.composition['registry_release_gate_legacy_entries']
                        for phase in PHASES:
                            for suffix, target in (
                                    ('entry', labels[phase]),
                                    ('replay', labels[phase + '_replay']),
                                    ('delegate', legacy[LEGACY_PHASES[phase]])):
                                if pc == target:
                                    snapshots[phase, suffix] = (
                                        current.r.copy(), current.hi, current.lo)

                    m.on_instruction = observe
                    m.construct(address)
                    for phase in PHASES:
                        self.assertEqual(snapshots[phase, 'entry'], snapshots[phase, 'replay'])
                        self.assertEqual(snapshots[phase, 'entry'], snapshots[phase, 'delegate'])

    def test_zero_completion_restores_architecture_before_only_displaced_v0_zero(self):
        m = self.machine()
        snapshots = {}

        def observe(current, pc):
            for name, target in (
                    ('entry', current.registry_release_gate_labels['complete']),
                    ('replay', current.registry_release_gate_labels['complete_replay']),
                    ('native', core.COMPLETE_CONTINUATION)):
                if pc == target:
                    snapshots[name] = (current.r.copy(), current.hi, current.lo)

        m.on_instruction = observe
        m.construct(FIRST)
        self.assertEqual(snapshots['entry'], snapshots['replay'])
        expected, hi, lo = snapshots['entry']
        expected = expected.copy()
        expected[2] = 0
        self.assertEqual(snapshots['native'], (expected, hi, lo))
        self.assertEqual(snapshots['entry'][0][31], constructor.HOOKS['first_gate'][0])

    def test_error_completion_changes_only_v0_v1_then_uses_stock_registration_unwind(self):
        m = self.machine(release=0x82)
        snapshots = {}

        def observe(current, pc):
            for name, target in (
                    ('entry', current.registry_release_gate_labels['complete']),
                    ('native', core.COMPLETE_CONTINUATION)):
                if pc == target:
                    snapshots[name] = (current.r.copy(), current.hi, current.lo)

        m.on_instruction = observe
        m.construct(FIRST)
        expected, hi, lo = snapshots['entry']
        expected = expected.copy()
        expected[2:4] = MASK, 0x82
        self.assertEqual(snapshots['native'], (expected, hi, lo))
        self.assert_local_stop(m, FIRST, 0x82)

    def test_source_ra_delay_load_executes_once_on_normal_and_independent_early_entries(self):
        for address, gate, frame in ROUTES:
            for outcome in ('success', 'release_error', 'acquire_error', 'allocation'):
                with self.subTest(constructor=hex(address), outcome=outcome):
                    m = self.machine(acquire=22 if outcome == 'acquire_error' else 0,
                                     release=22 if outcome == 'release_error' else 0)
                    m.fail_allocation = outcome == 'allocation'
                    m.construct(address)
                    native_sp = m.native_entries[0][2] - core.REGISTER_FRAME
                    loads = [event for event in m.constructor_accesses
                             if event == ('read', 0x438A68, native_sp + 0x24, 4)
                             or event == ('read', 0x438A6C, native_sp + 0x24, 4)]
                    # A jump delay is attributed to its source PC by this
                    # interpreter; the independent native entry uses6C itself.
                    self.assertEqual(len(loads), 1)
                    self.assertEqual(loads[0][1], 0x438A6C if outcome in (
                        'acquire_error', 'allocation') else 0x438A68)
                    self.assertEqual((m.r[29], m.r[31]), (STACK, RETURN))
                    if outcome in ('acquire_error', 'allocation'):
                        self.assertNotIn(m.registry_release_gate_labels['complete'], m.trace)

    def test_after_uncertain_raw_release_only_retained_frames_are_accessed(self):
        for address, gate, frame in ROUTES:
            with self.subTest(constructor=hex(address)):
                m = self.machine(release=22, registry_release_failure_releases=False)
                marks = self.watch_raw_release(m)
                m.construct(address)
                self.assert_private_after_release(m, marks)
                self.assert_local_stop(m, address, 22)
                self.assertTrue(m.registry_held)

    def test_checked_birth_wrapper_raw_zero_keeps_exact_prior_output_and_architecture(self):
        old = ExplorerFailureGateMachine(self.image)
        m = self.machine()
        expected = old.register_birth()
        self.assertEqual(m.register_birth(), expected)
        self.assertEqual(expected, (0, BIRTH_OUTPUT))
        self.assertEqual(m.birth_output(), old.birth_output())
        preserved = (*range(16, 24), 28, 29, 30, 31)
        self.assertEqual(tuple(m.r[r] for r in preserved),
                         tuple(old.r[r] for r in preserved))
        self.assertEqual((m.hi, m.lo), (old.hi, old.lo))
        self.assertNotIn(m.registry_release_gate_labels['complete_classified'], m.trace)

    def test_checked_birth_wrapper_release_error_keeps_exact_prior_denial(self):
        old = ExplorerFailureGateMachine(self.image, release=22)
        m = self.machine(release=22)
        self.assertEqual(old.register_birth(), (MASK, 22))
        self.assertEqual(m.register_birth(), (MASK, 22))
        self.assertEqual(m.birth_output(), (0,) * 12)
        preserved = (*range(16, 24), 28, 29, 30, 31)
        self.assertEqual(tuple(m.r[r] for r in preserved),
                         tuple(old.r[r] for r in preserved))
        self.assertEqual((m.hi, m.lo), (old.hi, old.lo))
        self.assertNotIn(m.registry_release_gate_labels['complete_classified'], m.trace)

    def test_foreign_native_registration_caller_retains_prior_masked_release_abi(self):
        old = ExplorerFailureGateMachine(self.image, release=22)
        m = self.machine(release=22)
        self.assertEqual(m.register(), old.register())
        self.assertEqual(m.r[2], 0)
        self.assertEqual((m.r, m.hi, m.lo), (old.r, old.hi, old.lo))
        self.assertNotIn(m.registry_release_gate_labels['complete_classified'], m.trace)

    def test_paint_error_with_actual_registry_release_zero_is_not_a_registry_release_error(self):
        for field in ('paint_acquire_result', 'paint_release_result'):
            with self.subTest(field=field):
                m = self.machine(**{field: 22})
                result, _ = m.construct(FIRST)
                self.assertEqual(result, m.created_engines[0])
                self.assertEqual(len(m.native_continuations), 1)
                self.assertIn(NAME_POSTWORK, m.calls)
                self.assertEqual(m.raw_events[-1][-1], 0)
                self.assertEqual(m.lifecycle_header(), (1, 0, 0, 0))
                self.assertIn(m.registry_release_gate_labels['complete_admitted'], m.trace)


if __name__ == '__main__':
    unittest.main()
