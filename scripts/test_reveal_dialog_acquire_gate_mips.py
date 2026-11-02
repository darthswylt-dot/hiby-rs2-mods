#!/usr/bin/env python3
"""Execute the dialog's actual direct acquire and pre-graph admission gate.

The cut begins at47C794 with genuine D104 prologue state. Earlier dialog
checks and the +0C worker handshake are premises, not simulated successes.
Actual466DA0/raw/native return instructions and all coherent dispatchers run.
Reached PCs47C7A4 or the native return end the minimal slice, never a host V0
decision. An optional admitted path follows actual47C7C8 into the preceding
bounded callback/W/C/D bodies and stops at47C7D0 before dialog cleanup.
Raw mutex/opaque service outcomes are bounded chosen semantics, not a native
ownership, lifetime, synchronization or successful-unwind certificate.
"""

from contextlib import contextmanager
import hashlib
import unittest

import reveal_dialog_acquire_gate_mips as core
import reveal_dialog_acquire_gate_stage as stage
import test_reveal_refresh_callback_gate_mips as previous
from test_reveal_refresh_callback_gate_mips import (
    RefreshCallbackGateMachine, CALLBACKS, CONTROLLER, REGISTRY_MUTEX,
    PAINT_MUTEX, CODE, QUEUE, RAW_LOCK, RAW_UNLOCK, STACK, RETURN, MASK,
    NAME, STAGE_ARGS, OUTER_VIEW, NativeReturnBoundary, DIALOG, OPERATION,
    _cached_assembler, _fixture_assembly_cache as imported_fixture_assembly_cache)


ACQUIRE, ADMISSION, ADMITTED = 0x47C794, 0x47C79C, 0x47C7A4
DIALOG_EPILOGUE, CALLBACK_RETURN = 0x47C814, 0x47C7D0
PROPERTY, DIALOG_MUTEX, ALTERNATE_MUTEX, WORKER_MUTEX = (
    0x1D04000, 0x1D04100, 0x1D04200, 0x1D04300)
CALLBACK_ENTRIES = {'first': 0x4AEC60, 'second': 0x450D60}
DIALOG_SAVES = {16: 0x5C, 17: 0x60, 31: 0x64}
_ASSEMBLY_CACHE_MODULES = (*previous._ASSEMBLY_CACHE_MODULES, core, stage)


@contextmanager
def _fixture_assembly_cache(enabled):
    """Cache only37 pure assemblers during serial fixture construction."""
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


class DialogAcquireGateMachine(RefreshCallbackGateMachine):
    """No host failure flag selects a dialog admission or native return."""

    def __init__(self, image, *, assembly_cache=True, dialog_acquire=0,
                 dialog_acquire_failure_holds=False, **options):
        with _fixture_assembly_cache(assembly_cache):
            super().__init__(image, assembly_cache=False, **options)
            self.legacy_hooks = dict(self.composition['coherent_hooks'])
            self.legacy_code = self.code
            selected = {name: options[name] for name in (
                'capacity', 'lifecycle_capacity', 'owner_capacity', 'ticket_limit',
                'queue_capacity') if name in options}
            self.composition = stage.assemble(
                *STAGE_ARGS, transport_capacity=self.peek(QUEUE + 8), **selected)
            self.code = self.code_bytes = self.composition['code']
            self.labels = self.composition['labels']
            for name, value in self.composition.items():
                if name.endswith('_labels'):
                    setattr(self, name, value)
            self.bridge_labels = self.receipt_labels
            for pc, words in self.composition['coherent_hooks'].items():
                for index, word in enumerate(words):
                    self.patches[pc + index * 4] = word
            self.map(PROPERTY, 0x100)
            self.dialog_mutexes = (DIALOG_MUTEX, ALTERNATE_MUTEX, WORKER_MUTEX)
            for mutex in self.dialog_mutexes:
                self.map(mutex, 24)
            self.dialog_acquire = dialog_acquire
            self.dialog_acquire_failure_holds = dialog_acquire_failure_holds
            self.mutex_held = {mutex: False for mutex in self.dialog_mutexes}
            self.dialog_raw_events, self.dialog_delay_effects = [], []
            self.dialog_callback_entries, self.dialog_callback_contexts = [], []
            self.clear_events()

    def service(self, target):
        if (not hasattr(self, 'dialog_mutexes')
                or self.r[4] not in self.dialog_mutexes):
            return super().service(target)
        mutex, sp, ra = self.r[4], self.r[29], self.r[31]
        result = self.dialog_acquire & MASK if target == RAW_LOCK else 0
        event = (target, mutex, sp, ra, result)
        self.calls.append(target)
        self.raw_events.append(event)
        self.dialog_raw_events.append(event)
        if target == RAW_LOCK and (result == 0 or self.dialog_acquire_failure_holds):
            self.mutex_held[mutex] = True
        if self.on_service is not None:
            self.on_service(self, target)
        self.hostile_result(result)
        if target == RAW_UNLOCK:
            self.mutex_held[mutex] = False

    def plain(self, word):
        is_delay = (word == 0x8E040010 and self.current_pc == ACQUIRE
                    and hasattr(self, 'dialog_delay_effects'))
        dialog = self.r[16] if is_delay else None
        result = super().plain(word)
        if is_delay:
            self.dialog_delay_effects.append((self.current_pc, dialog, self.r[4]))
        return result

    def external(self, target):
        if target in CALLBACK_ENTRIES.values():
            self.calls.append(target)
            self.dialog_callback_entries.append((target, self.r.copy(), self.hi, self.lo))
            kind = next(kind for kind, entry in CALLBACK_ENTRIES.items() if entry == target)
            context = self.seed_callback(
                kind, caller_stack=self.r[29], caller=self.r[31],
                wrapper_flag=self.dialog_context['wrapper_flag'],
                refresh_flag=self.dialog_context['refresh_flag'])
            self.dialog_callback_contexts.append(context)
            self.run_callback_slice()
            return
        return super().external(target)

    def clear_events(self):
        super().clear_events()
        for name in ('dialog_raw_events', 'dialog_delay_effects',
                     'dialog_callback_entries', 'dialog_callback_contexts'):
            if hasattr(self, name):
                getattr(self, name).clear()

    def seed_dialog(self, *, caller_stack=STACK, caller=RETURN, mutex=DIALOG_MUTEX,
                    callback=None, wrapper_flag=1, refresh_flag=0):
        """Supply retained D104 state after the earlier +0C handshake."""
        dialog_sp = caller_stack - 104
        saved = {register: self.r[register] for register in DIALOG_SAVES}
        saved[31] = caller
        for register, offset in DIALOG_SAVES.items():
            self.put(dialog_sp + offset, saved[register], 4)
        self.bytes(dialog_sp + 0x18, bytes(64))
        for offset, value in ((0x0C, WORKER_MUTEX), (0x10, mutex),
                              (0x3C, PROPERTY), (0x50, OPERATION),
                              (0x58, OPERATION),
                              (0x74, CALLBACK_ENTRIES[callback] if callback else 0)):
            self.put(DIALOG + offset, value, 4)
        self.put(PROPERTY, 0, 4)
        self.put(PROPERTY + 0x50, CONTROLLER, 4)
        self.dialog_context = dict(
            sp=dialog_sp, caller_stack=caller_stack, caller=caller, mutex=mutex,
            saved=saved, callback=callback, wrapper_flag=wrapper_flag,
            refresh_flag=refresh_flag,
            preserved={register: self.r[register]
                       for register in (*range(18, 24), 28, 30)})
        self.r[29], self.r[31], self.r[16] = dialog_sp, caller, DIALOG
        self.r[17] = 0x51515151
        return self.dialog_context

    def run_dialog_acquire(self, stop=None):
        if stop is None:
            stop = NativeReturnBoundary(ADMITTED, self.dialog_context['caller'])
        self.run_at(ACQUIRE, stop)
        return self.r[2], self.r[3]

    def run_dialog_to_callback(self):
        self.run_at(ACQUIRE, NativeReturnBoundary(CALLBACK_RETURN,
                                                 self.dialog_context['caller']))
        return self.r[2], self.r[3]

    def restore_legacy_dialog_phase(self, name):
        pc = core.HOOKS[name][0]
        if pc in self.legacy_hooks:
            for index, word in enumerate(self.legacy_hooks[pc]):
                self.patches[pc + 4 * index] = word
        else:
            self.remove_pair(pc)

    def dialog_witness(self):
        sp = self.dialog_context['sp']
        return tuple(self.words_at(sp + offset, 1)[0]
                     for offset in (core.TAG, core.MUTEX, core.RAW_STATUS))


class DialogAcquireGateTests(unittest.TestCase):
    setUpClass = classmethod(previous.RefreshCallbackGateTests.setUpClass.__func__)

    def machine(self, **options):
        return DialogAcquireGateMachine(self.image, **options)

    def watch_gate(self, machine):
        snapshots, marks = {}, []

        def observe(current, pc):
            targets = {'gate': current.dialog_acquire_gate_labels['gate'],
                       'replay': current.dialog_acquire_gate_labels['gate_replay'],
                       'epilogue': DIALOG_EPILOGUE}
            for name, target in targets.items():
                if pc == target:
                    snapshots[name] = (current.r.copy(), current.hi, current.lo)
                    if name == 'gate':
                        marks.append((len(current.reads), len(current.writes),
                                      len(current.calls), len(current.freed), current.r[29]))

        machine.on_instruction = observe
        return marks, snapshots

    def assert_denied(self, machine, context, marks, snapshots, raw=22):
        self.assertEqual((machine.r[2], machine.r[3]), (MASK, raw))
        self.assertEqual((machine.r[29], machine.r[31]),
                         (context['caller_stack'], context['caller']))
        for register, value in {**context['saved'], **context['preserved']}.items():
            self.assertEqual(machine.r[register], value, register)
        expected, hi, lo = snapshots['gate']
        expected = expected.copy()
        expected[2:4] = MASK, raw
        self.assertEqual(snapshots['epilogue'], (expected, hi, lo))
        self.assertEqual((machine.hi, machine.lo), (hi, lo))
        self.assertNotIn(ADMITTED, machine.trace)
        self.assertNotIn(0x47C7B8, machine.trace)
        self.assertNotIn(CALLBACK_RETURN, machine.trace)
        self.assertEqual(machine.dialog_callback_entries, [])
        self.assertEqual(len(marks), 1)
        reads, writes, calls, freed, sp = marks[0]
        self.assertEqual(sp, context['sp'])
        self.assertEqual(machine.calls[calls:], [])
        self.assertEqual(machine.freed[freed:], [])
        self.assertTrue(all(sp - core.FRAME <= address and address + size <= sp + 104
                            for address, size in machine.reads[reads:]))
        self.assertTrue(all(sp - core.FRAME <= address and address + size <= sp + 104
                            for address, value, size in machine.writes[writes:]))
        self.assertNotIn((DIALOG + 0x3C, 4), machine.reads)
        self.assertNotIn((PROPERTY, 4), machine.reads)
        self.assertEqual(machine.freed, [])
        self.assertEqual(machine.operation_free_entries, [])
        self.assertEqual(machine.dialog_witness()[0], 0)

    def assert_admitted(self, machine, context, snapshots):
        self.assertEqual(snapshots['gate'], snapshots['replay'])
        expected, hi, lo = snapshots['gate']
        expected = expected.copy()
        expected[2], expected[5] = PROPERTY, 0
        self.assertEqual((machine.r, machine.hi, machine.lo), (expected, hi, lo))
        self.assertEqual(machine.r[29], context['sp'])
        self.assertIn(machine.dialog_acquire_gate_labels['gate_admitted'], machine.trace)
        self.assertNotIn(DIALOG_EPILOGUE, machine.trace)
        self.assertEqual(machine.reads.count((DIALOG + 0x3C, 4)), 1)
        self.assertEqual(machine.reads.count((PROPERTY, 4)), 1)
        self.assertEqual(machine.dialog_witness(), (core.ADMITTED, context['mutex'], 0))

    def test_actual_raw_zero_admits_once_preserves_architecture_and_replays_two_graph_loads(self):
        m = self.machine()
        context = m.seed_dialog()
        m.clear_events()
        marks, snapshots = self.watch_gate(m)
        m.run_dialog_acquire()
        self.assert_admitted(m, context, snapshots)
        self.assertEqual(m.dialog_raw_events,
                         [(RAW_LOCK, DIALOG_MUTEX, context['sp'] - 32, 0x466DB0, 0)])
        self.assertTrue(m.mutex_held[DIALOG_MUTEX])
        self.assertEqual(m.dialog_delay_effects, [(ACQUIRE, DIALOG, DIALOG_MUTEX)])
        self.assertEqual(m.reads.count((DIALOG + 0x10, 4)), 1)
        self.assertEqual(m.calls[marks[0][2]:], [])

    def test_actual_nonzero_and_mask_status_deny_without_unlock_for_either_ownership_outcome(self):
        for status in (1, 22, 0x82, MASK):
            for held in (False, True):
                with self.subTest(status=status, held=held):
                    m = self.machine(dialog_acquire=status, dialog_acquire_failure_holds=held)
                    context = m.seed_dialog(callback='first')
                    m.clear_events()
                    marks, snapshots = self.watch_gate(m)
                    self.assertEqual(m.run_dialog_acquire(), (MASK, status))
                    self.assert_denied(m, context, marks, snapshots, raw=status)
                    self.assertEqual(m.mutex_held[DIALOG_MUTEX], held)
                    self.assertEqual(m.dialog_raw_events,
                                     [(RAW_LOCK, DIALOG_MUTEX, context['sp'] - 32,
                                       0x466DB0, status)])

    def test_fresh_native_locals_follow_armed_entered_captured_and_admitted_states(self):
        m = self.machine()
        context = m.seed_dialog()
        m.clear_events()
        observed = {}

        def observe(current, pc):
            for name in ('begin_done', 'raw_call_done', 'raw_return_done', 'gate_replay'):
                if pc == current.dialog_acquire_gate_labels[name]:
                    observed[name] = current.dialog_witness()

        m.on_instruction = observe
        m.run_dialog_acquire()
        self.assertEqual(observed, {
            'begin_done': (core.ARMED, DIALOG_MUTEX, MASK),
            'raw_call_done': (core.ENTERED, DIALOG_MUTEX, context['sp'] - 32),
            'raw_return_done': (core.CAPTURED, DIALOG_MUTEX, 0),
            'gate_replay': (core.ADMITTED, DIALOG_MUTEX, 0)})

    def test_admitted_native_dialog_call_reaches_both_callback_errors_with_dialog_mutex_still_held(self):
        for kind in CALLBACKS:
            for option in ('acquire', 'release'):
                with self.subTest(kind=kind, option=option):
                    m = self.machine(**{option: 22})
                    context = m.seed_dialog(callback=kind)
                    m.clear_events()
                    self.assertEqual(m.run_dialog_to_callback(), (MASK, 22))
                    self.assertEqual((m.r[29], m.r[31]), (context['sp'], CALLBACK_RETURN))
                    self.assertTrue(m.mutex_held[DIALOG_MUTEX])
                    self.assertEqual(len(m.dialog_callback_entries), 1)
                    entry, regs, hi, lo = m.dialog_callback_entries[0]
                    self.assertEqual(entry, CALLBACK_ENTRIES[kind])
                    self.assertEqual(tuple(regs[4:6]), (DIALOG, OPERATION))
                    self.assertEqual((regs[29], regs[31]), (context['sp'], CALLBACK_RETURN))
                    self.assertEqual(len(m.dialog_callback_contexts), 1)
                    self.assertEqual(m.dialog_callback_contexts[0]['caller'], CALLBACK_RETURN)
                    self.assertEqual(m.operation_free_entries, [])
                    self.assertNotIn(0x47C7D4, m.trace)
                    self.assertNotIn(0x47C800, m.trace)
                    self.assertNotIn(0x47C808, m.trace)
                    self.assertEqual(m.dialog_raw_events,
                                     [(RAW_LOCK, DIALOG_MUTEX, context['sp'] - 32,
                                       0x466DB0, 0)])

    def test_foreign_worker_direct_acquire_retains_masked_native_abi_and_no_dialog_witness_writes(self):
        m, old = self.machine(dialog_acquire=22), self.machine(dialog_acquire=22)
        for phase in core.HOOKS:
            old.restore_legacy_dialog_phase(phase)
        contexts = []
        for current in (m, old):
            contexts.append(current.seed_dialog())
            current.r[29], current.r[31], current.r[4] = (
                contexts[-1]['sp'], 0x47C784, WORKER_MUTEX)
            current.clear_events()
            current.run_at(0x466DA0, 0x47C784)
        self.assertEqual((m.r, m.hi, m.lo), (old.r, old.hi, old.lo))
        self.assertEqual(m.r[2], 0)
        self.assertEqual(m.dialog_raw_events, old.dialog_raw_events)
        self.assertEqual(m.dialog_witness(), old.dialog_witness())
        self.assertNotIn(m.dialog_acquire_gate_labels['gate'], m.trace)
        self.assertEqual(m.freed, [])

    def test_foreign_registration_and_deletion_keep_original_results_architecture_and_history(self):
        for option in ({}, {'acquire': 22}, {'release': 0x82}):
            with self.subTest(option=option):
                m, old = self.machine(**option), self.machine(**option)
                for phase in core.HOOKS:
                    old.restore_legacy_dialog_phase(phase)
                self.assertEqual(m.register(), old.register())
                self.assertEqual((m.r, m.hi, m.lo), (old.r, old.hi, old.lo))
                self.assertEqual(m.raw_events, old.raw_events)
                self.assertEqual(m.lifecycle_record(), old.lifecycle_record())
                self.assertEqual(m.delete_native(), old.delete_native())
                self.assertEqual((m.r, m.hi, m.lo), (old.r, old.hi, old.lo))
                self.assertEqual(m.raw_events, old.raw_events)
                self.assertEqual(m.lifecycle_record(), old.lifecycle_record())
                self.assertEqual(m.dialog_raw_events, [])

    def test_gate_failure_without_capture_is_unknown_zero_and_accesses_only_native_private_frames(self):
        m = self.machine()
        context = m.seed_dialog()
        for offset, value in ((core.TAG, 0), (core.MUTEX, DIALOG_MUTEX),
                              (core.RAW_STATUS, 0)):
            m.put(context['sp'] + offset, value, 4)
        m.r[2:4] = 0, MASK
        m.r[31] = ADMISSION
        m.clear_events()
        marks, snapshots = self.watch_gate(m)
        m.run_at(ADMISSION, context['caller'])
        self.assert_denied(m, context, marks, snapshots, raw=0)
        self.assertEqual(m.raw_events, [])
        self.assertEqual(m.calls, [])

    def test_cache_preserves_exact_bytes_fresh_metadata_cpu_state_and_all_assembler_functions(self):
        originals = {module: module.assemble for module in _ASSEMBLY_CACHE_MODULES}
        uncached = self.machine(dialog_acquire=22, assembly_cache=False)
        cached = self.machine(dialog_acquire=22)
        self.assertEqual(cached.code, uncached.code)
        self.assertEqual(hashlib.sha256(cached.code).digest(), hashlib.sha256(uncached.code).digest())
        tail = cached.composition['dialog_acquire_gate_code_bytes']
        self.assertEqual(cached.composition['dialog_acquire_gate_prefix_code_bytes'], 92600)
        self.assertEqual(len(cached.code), 92600 + tail)
        with _fixture_assembly_cache(True):
            guarded = previous.stage.assemble(*STAGE_ARGS, following_code_bytes=tail)
        self.assertEqual(cached.code[:92600], guarded['code'])
        self.assertIsNot(cached.composition, uncached.composition)
        self.assertIsNot(cached.dialog_acquire_gate_labels, uncached.dialog_acquire_gate_labels)
        for current in (cached, uncached):
            current.seed_dialog()
            current.clear_events()
        self.assertEqual(cached.run_dialog_acquire(), uncached.run_dialog_acquire())
        self.assertEqual((cached.r, cached.hi, cached.lo), (uncached.r, uncached.hi, uncached.lo))
        cached.dialog_acquire_gate_labels['host_only_cache_probe'] = 123
        cached.mutex_held[DIALOG_MUTEX] = True
        fresh = self.machine()
        self.assertNotIn('host_only_cache_probe', fresh.dialog_acquire_gate_labels)
        self.assertFalse(fresh.mutex_held[DIALOG_MUTEX])
        self.assertEqual(fresh.dialog_raw_events, [])
        with self.assertRaises(ValueError):
            self.machine(capacity=True)
        self.assertEqual(len(_ASSEMBLY_CACHE_MODULES), 37)
        for module, original in originals.items():
            self.assertIs(module.assemble, original, module.__name__)


if __name__ == '__main__':
    unittest.main()
