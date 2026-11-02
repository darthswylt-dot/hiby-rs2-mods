#!/usr/bin/env python3
"""Follow classified callback returns to one guarded direct raw release.

Actual dialog acquisition and47C7C8 callback invocation run through the
preceding bounded callback/W/C/D bodies. The emitted callback saved-RA rewrite,
native callback epilogue and D104 exit execute; no host V0 test chooses an
error route. Ordinary callbacks stop at their unchanged47C7D0 return. One
opaque47AA20 substitute exposes the missing-splice continuation to47C7DC.

Genuine mapped retained independently nonaliasing live frames, ordinary
initialized M and continuous same-thread ownership through cooperative
callbacks are HARD premises. Observed acquisition zero alone is not proof of
those premises. No worker termination, complete cleanup, native lifetime,
retry/free permission or ownership recovery is simulated.
"""

from contextlib import contextmanager
import hashlib
import struct
import unittest

import reveal_dialog_failure_gate_mips as core
import reveal_dialog_failure_gate_stage as stage
import test_reveal_dialog_acquire_gate_mips as previous
import reveal_refresh_wrapper_gate_mips as wrapper_core
from test_reveal_dialog_acquire_gate_mips import (
    DialogAcquireGateMachine, CALLBACKS, CONTROLLER, REGISTRY_MUTEX,
    CODE, QUEUE, RAW_LOCK, RAW_UNLOCK, STACK, RETURN, MASK,
    STAGE_ARGS, OUTER_VIEW, NativeReturnBoundary, DIALOG, OPERATION,
    DIALOG_MUTEX, ALTERNATE_MUTEX, ACQUIRE, ADMITTED, CALLBACK_RETURN,
    DIALOG_EPILOGUE, _cached_assembler,
    _fixture_assembly_cache as imported_fixture_assembly_cache)


ACQUIRE_CORE = previous.core
REFRESH = previous.previous.REFRESH
CACHE_REMOVE, CACHE_RETURN = 0x47AA20, 0x47C7DC
_ASSEMBLY_CACHE_MODULES = (*previous._ASSEMBLY_CACHE_MODULES, core, stage)


@contextmanager
def _fixture_assembly_cache(enabled, *, cache_new_assembly=True):
    """Cache old37 pure functions; optionally also wrap these two new ones.

    Leaving the new functions unwrapped exercises their actual composition
    and validation under the unchanged37-function parent cache. It does not
    claim to be a fully uncached39-function run or cache CPU/service outcomes.
    """
    originals = []
    with imported_fixture_assembly_cache(enabled):
        try:
            if enabled and cache_new_assembly:
                for module in (core, stage):
                    assemble = module.assemble
                    originals.append((module, assemble))
                    module.assemble = _cached_assembler(assemble)
            yield
        finally:
            for module, assemble in reversed(originals):
                module.assemble = assemble


class DialogFailureGateMachine(DialogAcquireGateMachine):
    """Only the actual classified saved return selects the guarded release."""

    def __init__(self, image, *, assembly_cache=True, cache_new_assembly=True,
                 dialog_release=0, dialog_release_failure_releases=True, **options):
        with _fixture_assembly_cache(assembly_cache,
                                     cache_new_assembly=cache_new_assembly):
            super().__init__(image, assembly_cache=False, **options)
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
            self.dialog_release = dialog_release
            self.dialog_release_failure_releases = dialog_release_failure_releases
            self.direct_release_entries, self.native_cleanup_entries = [], []
            self.clear_events()

    def service(self, target):
        if (target != RAW_UNLOCK or not hasattr(self, 'dialog_mutexes')
                or self.r[4] not in self.dialog_mutexes):
            return super().service(target)
        mutex, sp, ra = self.r[4], self.r[29], self.r[31]
        result, before = self.dialog_release & MASK, self.mutex_held[mutex]
        event = (target, mutex, sp, ra, result)
        self.calls.append(target)
        self.raw_events.append(event)
        self.dialog_raw_events.append(event)
        self.direct_release_entries.append((self.r.copy(), self.hi, self.lo))
        if self.on_service is not None:
            self.on_service(self, target)
        self.hostile_result(result)
        released = result == 0 or self.dialog_release_failure_releases
        self.mutex_held[mutex] = False if released else before

    def external(self, target):
        if target in previous.CALLBACK_ENTRIES.values():
            self.calls.append(target)
            self.dialog_callback_entries.append((target, self.r.copy(), self.hi, self.lo))
            kind = next(kind for kind, entry in previous.CALLBACK_ENTRIES.items()
                        if entry == target)
            caller = self.r[31]
            context = self.seed_callback(
                kind, caller_stack=self.r[29], caller=caller,
                wrapper_flag=self.dialog_context['wrapper_flag'],
                refresh_flag=self.dialog_context['refresh_flag'])
            self.dialog_callback_contexts.append(context)
            self.run_callback_slice(NativeReturnBoundary(
                caller, self.dialog_failure_gate_labels['error_return'], RETURN))
            return
        if target == CACHE_REMOVE:
            self.calls.append(target)
            self.native_cleanup_entries.append((tuple(self.r[4:8]), self.r[29], self.r[31]))
            self.hostile_result(0)
            return
        return super().external(target)

    def clear_events(self):
        super().clear_events()
        for name in ('direct_release_entries', 'native_cleanup_entries'):
            if hasattr(self, name):
                getattr(self, name).clear()

    def run_dialog_failure(self, stop=None):
        self.run_at(ACQUIRE, self.dialog_context['caller'] if stop is None else stop)
        return self.r[2], self.r[3]

    def remove_generated_failure_splice(self, kind=None, *, fetch_override=True,
                                        prefix_bytes=True):
        """The patched prefix and fetch override are separate active copies."""
        code = bytearray(self.code)
        selected = (None if kind is None
                    else self.refresh_callback_gate_labels[kind + '_abort_return'])
        for pc, words in self.composition['dialog_failure_gate_source_words'].items():
            if selected is not None and pc != selected:
                continue
            if fetch_override:
                self.remove_pair(pc)
            if prefix_bytes:
                struct.pack_into('<2I', code, pc - CODE, *words)
        self.code = self.code_bytes = bytes(code)

    def invoke_classified_callback_result(self, kind, *, result=MASK, diagnostic=22):
        """Controlled genuine classified entry after an actual D admission.

        This supplies the earlier callback/W/C prologue saves rather than
        executing their opaque bodies. The parent refresh gate still performs
        its actual classification, and every native return selects its own PC.
        """
        dialog = self.seed_dialog(callback=kind)
        self.clear_events()
        self.run_dialog_acquire()
        callback = self.seed_callback(kind, caller_stack=dialog['sp'],
                                      caller=CALLBACK_RETURN)
        wrapper = self.seed_wrapper(
            caller_stack=callback['sp'], caller=CALLBACKS[kind]['return_pc'],
            view=OUTER_VIEW, descriptor=OPERATION + 0x50,
            wrapper_flag=1, refresh_flag=0)
        self.seed_refresh(caller_stack=wrapper['sp'],
                          caller=wrapper_core.WRAPPER_RETURN)
        self.r[2:4], self.r[31] = (result, diagnostic), REFRESH.HOOKS['gate'][0]
        self.clear_events()
        self.run_at(REFRESH.HOOKS['gate'][0], dialog['caller'])
        return self.r[2], self.r[3]


class DialogFailureGateTests(unittest.TestCase):
    setUpClass = classmethod(previous.DialogAcquireGateTests.setUpClass.__func__)

    def machine(self, **options):
        return DialogFailureGateMachine(self.image, **options)

    def watch_failure(self, machine):
        snapshots, marks = {}, []

        def observe(current, pc):
            labels = current.dialog_failure_gate_labels
            targets = {'first': labels['first_scope'], 'second': labels['second_scope'],
                       'error': labels['error_return'],
                       'released': labels['release_return'], 'epilogue': DIALOG_EPILOGUE}
            for kind, route in CALLBACKS.items():
                targets[kind + '_native_epilogue'] = route['epilogue']
            for name, target in targets.items():
                if pc == target:
                    snapshots[name] = (current.r.copy(), current.hi, current.lo)
                    if name == 'error':
                        snapshots['error_accesses'] = len(current.reads), len(current.writes)
                    for kind, route in CALLBACKS.items():
                        if name == kind + '_native_epilogue':
                            slot = current.r[29] + route['saves'][31]
                            snapshots[kind + '_live_return_slot'] = (
                                slot, current.words_at(slot, 1)[0])
                    if name in ('first', 'second'):
                        marks.append((len(current.reads), len(current.writes),
                                      len(current.calls), len(current.freed), current.r[29]))

        machine.on_instruction = observe
        return marks, snapshots

    def assert_error_exit(self, machine, context, marks, snapshots, *, result=MASK,
                          diagnostic=22, release_status=0, release_attempted=True):
        kind = context['callback']
        labels, route = machine.dialog_failure_gate_labels, CALLBACKS[kind]
        self.assertEqual((machine.r[2], machine.r[3]), (result, diagnostic))
        self.assertEqual((machine.r[29], machine.r[31]),
                         (context['caller_stack'], context['caller']))
        for register, value in {**context['saved'], **context['preserved']}.items():
            self.assertEqual(machine.r[register], value, register)
        self.assertEqual(snapshots['error'], snapshots['epilogue'])
        self.assertEqual((machine.hi, machine.lo), snapshots['error'][1:])
        self.assertEqual(len(marks), 1)
        reads, writes, calls, freed, callback_sp = marks[0]
        self.assertEqual(callback_sp, context['sp'] - route['frame'])
        self.assertEqual(machine.trace.count(labels[kind + '_scope']), 1)
        self.assertEqual(machine.trace.count(labels['error_return']), 1)
        self.assertNotIn(CALLBACK_RETURN, machine.trace)
        self.assertNotIn(0x47C7D4, machine.trace)
        self.assertNotIn(0x47C800, machine.trace)
        self.assertNotIn(0x47C808, machine.trace)
        self.assertEqual(machine.native_cleanup_entries, [])
        self.assertEqual(machine.operation_free_entries, [])
        self.assertEqual(machine.freed[freed:], [])
        self.assertTrue(all(callback_sp - core.FRAME <= address
                            and address + size <= context['caller_stack']
                            for address, size in machine.reads[reads:]))
        self.assertTrue(all(callback_sp - core.FRAME <= address
                            and address + size <= context['caller_stack']
                            for address, value, size in machine.writes[writes:]))
        callback_ra = callback_sp + route['saves'][31]
        self.assertEqual(machine.writes[writes:].count((callback_ra, labels['error_return'], 4)), 1)
        self.assertEqual(snapshots[kind + '_live_return_slot'],
                         (callback_ra, labels['error_return']))
        self.assertEqual(machine.reads[reads:].count((callback_ra, 4)), 2)
        error_reads, error_writes = snapshots['error_accesses']
        self.assertTrue(all(context['sp'] - core.FRAME <= address
                            and address + size <= context['caller_stack']
                            for address, size in machine.reads[error_reads:]))
        self.assertTrue(all(context['sp'] - core.FRAME <= address
                            and address + size <= context['caller_stack']
                            for address, value, size in machine.writes[error_writes:]))
        dialog_ra = context['sp'] + previous.DIALOG_SAVES[31]
        self.assertEqual(machine.words_at(dialog_ra, 1), (context['caller'],))
        self.assertEqual(machine.words_at(DIALOG + 0x58, 1), (OPERATION,))
        if release_attempted:
            self.assertEqual(machine.calls[calls:], [RAW_UNLOCK])
            self.assertEqual(len(machine.direct_release_entries), 1)
            entry = machine.direct_release_entries[0][0]
            self.assertEqual((entry[4], entry[29], entry[31]),
                             (context['mutex'], context['sp'] - core.FRAME,
                              labels['release_return']))
            self.assertEqual(machine.dialog_raw_events[-1],
                             (RAW_UNLOCK, context['mutex'], context['sp'] - core.FRAME,
                              labels['release_return'], release_status))
            for offset in range(0, 16, 4):
                self.assertIn((context['sp'] - core.FRAME + offset,
                               0xD00D0000 + offset, 4), machine.writes[writes:])
        else:
            self.assertEqual(machine.calls[calls:], [])
            self.assertEqual(machine.direct_release_entries, [])

    def test_actual_both_callback_errors_release_captured_mutex_once_and_preserve_exact_result(self):
        for kind in CALLBACKS:
            for option in ('acquire', 'release'):
                with self.subTest(kind=kind, option=option):
                    m = self.machine(**{option: 22})
                    context = m.seed_dialog(callback=kind)
                    m.clear_events()
                    marks, snapshots = self.watch_failure(m)
                    self.assertEqual(m.run_dialog_failure(), (MASK, 22))
                    self.assert_error_exit(m, context, marks, snapshots)
                    self.assertFalse(m.mutex_held[DIALOG_MUTEX])
                    self.assertEqual(m.dialog_witness(), (core.RELEASE_ZERO, DIALOG_MUTEX, 0))
                    self.assertEqual([event[0] for event in m.dialog_raw_events],
                                     [RAW_LOCK, RAW_UNLOCK])

    def test_raw_release_errors_keep_callback_diagnostic_and_record_actual_release_outcome(self):
        for kind in CALLBACKS:
            for status in (1, 22, 0x82, MASK):
                for released in (False, True):
                    with self.subTest(kind=kind, status=status, released=released):
                        m = self.machine(acquire=22, dialog_release=status,
                                         dialog_release_failure_releases=released)
                        context = m.seed_dialog(callback=kind)
                        m.clear_events()
                        marks, snapshots = self.watch_failure(m)
                        self.assertEqual(m.run_dialog_failure(), (MASK, 22))
                        self.assert_error_exit(m, context, marks, snapshots, release_status=status)
                        self.assertEqual(m.mutex_held[DIALOG_MUTEX], not released)
                        self.assertEqual(m.dialog_witness(),
                                         (core.RELEASE_ERROR, DIALOG_MUTEX, status))

    def test_ordinary_native_zero_and_one_callbacks_keep_original_return_and_no_direct_release(self):
        for kind in CALLBACKS:
            for flag in (0, 1):
                with self.subTest(kind=kind, flag=flag):
                    m, old = self.machine(), self.machine()
                    old.remove_generated_failure_splice()
                    context = m.seed_dialog(callback=kind, refresh_flag=flag)
                    old.seed_dialog(callback=kind, refresh_flag=flag)
                    for current in (m, old):
                        current.clear_events()
                    self.assertEqual(m.run_dialog_to_callback(), old.run_dialog_to_callback())
                    self.assertEqual((m.r, m.hi, m.lo), (old.r, old.hi, old.lo))
                    self.assertEqual((m.r[29], m.r[31]), (context['sp'], CALLBACK_RETURN))
                    self.assertEqual(m.raw_events, old.raw_events)
                    self.assertEqual(m.operation_free_entries, old.operation_free_entries)
                    self.assertEqual(m.direct_release_entries, [])
                    self.assertTrue(m.mutex_held[DIALOG_MUTEX])
                    self.assertEqual(m.dialog_witness(), (ACQUIRE_CORE.ADMITTED, DIALOG_MUTEX, 0))
                    self.assertNotIn(m.dialog_failure_gate_labels['error_return'], m.trace)

    def test_hostile_raw_service_homes_registers_and_hilo_restore_entire_callback_architecture(self):
        m = self.machine(release=0x82, dialog_release=22)
        context = m.seed_dialog(callback='first')
        m.clear_events()
        marks, snapshots = self.watch_failure(m)
        m.run_dialog_failure()
        self.assert_error_exit(m, context, marks, snapshots,
                               diagnostic=0x82, release_status=22)
        self.assertNotEqual(snapshots['released'], snapshots['error'])
        self.assertEqual(snapshots['released'][0][2:4], [22, 0xBAD00003])
        self.assertEqual(snapshots['error'][0][2:4], [MASK, 0x82])

    def test_earlier_populated_delete_effects_remain_without_later_dialog_cleanup_or_free(self):
        m = self.machine()
        self.assertEqual(m.register(), 0)
        node = m.allocations[-1]
        m.release = 22
        context = m.seed_dialog(callback='second')
        m.clear_events()
        marks, snapshots = self.watch_failure(m)
        self.assertEqual(m.run_dialog_failure(), (MASK, 22))
        self.assert_error_exit(m, context, marks, snapshots)
        self.assertIn(node, m.freed)
        self.assertNotIn(OPERATION, m.freed)
        self.assertNotIn(DIALOG_MUTEX, m.freed)
        self.assertEqual(m.words_at(CONTROLLER + 0x34, 2), (CONTROLLER + 0x34,) * 2)

    def test_foreign_callback_saved_return_preserves_old_error_exit_and_never_reads_a_dialog_frame(self):
        for kind in CALLBACKS:
            with self.subTest(kind=kind):
                m, old = self.machine(acquire=22), self.machine(acquire=22)
                old.remove_generated_failure_splice()
                context = m.seed_callback(kind)
                old.seed_callback(kind)
                for current in (m, old):
                    current.clear_events()
                marks, snapshots = self.watch_failure(m)
                self.assertEqual(m.run_callback_slice(), old.run_callback_slice())
                self.assertEqual((m.r, m.hi, m.lo), (old.r, old.hi, old.lo))
                self.assertEqual((m.r[2], m.r[3]), (MASK, 22))
                self.assertEqual(m.direct_release_entries, [])
                self.assertNotIn('error', snapshots)
                self.assertEqual(len(marks), 1)
                reads, writes, calls, freed, callback_sp = marks[0]
                self.assertTrue(all(callback_sp - core.FRAME <= address
                                    and address + size <= context['caller_stack']
                                    for address, size in m.reads[reads:]))
                self.assertEqual(m.words_at(context['sp'] + CALLBACKS[kind]['saves'][31], 1),
                                 (RETURN,))

    def test_classified_nonzero_one_and_uninterpreted_v1_are_not_ordinary_native_success(self):
        for kind in CALLBACKS:
            for result, diagnostic in ((1, 0), (1, MASK), (MASK, 0x12345678)):
                with self.subTest(kind=kind, result=result, diagnostic=diagnostic):
                    m = self.machine(dialog_release=0x82)
                    marks, snapshots = self.watch_failure(m)
                    self.assertEqual(m.invoke_classified_callback_result(
                        kind, result=result, diagnostic=diagnostic), (result, diagnostic))
                    self.assert_error_exit(m, m.dialog_context, marks, snapshots,
                                           result=result, diagnostic=diagnostic,
                                           release_status=0x82)

    def test_new_emitters_uncached_equal_cached_bytes_with_unchanged_37_parent_cache(self):
        originals = {module: module.assemble for module in _ASSEMBLY_CACHE_MODULES}
        new_emitters_uncached = self.machine(acquire=22, cache_new_assembly=False)
        cached = self.machine(acquire=22)
        self.assertEqual(cached.code, new_emitters_uncached.code)
        self.assertEqual(hashlib.sha256(cached.code).digest(),
                         hashlib.sha256(new_emitters_uncached.code).digest())
        tail = cached.composition['dialog_failure_gate_code_bytes']
        self.assertEqual(cached.composition['dialog_failure_gate_prefix_code_bytes'], 94232)
        self.assertEqual(len(cached.code), 94232 + tail)
        with _fixture_assembly_cache(True, cache_new_assembly=False):
            guarded = previous.stage.assemble(*STAGE_ARGS, following_code_bytes=tail)
        expected = bytearray(guarded['code'])
        for pc, words in cached.composition['dialog_failure_gate_hooks'].items():
            struct.pack_into('<2I', expected, pc - CODE, *words)
        self.assertEqual(cached.code[:94232], bytes(expected))
        for current in (cached, new_emitters_uncached):
            current.seed_dialog(callback='first')
            current.clear_events()
        self.assertEqual(cached.run_dialog_failure(), new_emitters_uncached.run_dialog_failure())
        self.assertEqual((cached.r, cached.hi, cached.lo),
                         (new_emitters_uncached.r, new_emitters_uncached.hi, new_emitters_uncached.lo))
        cached.dialog_failure_gate_labels['host_only_cache_probe'] = 123
        cached.mutex_held[DIALOG_MUTEX] = True
        fresh = self.machine()
        self.assertNotIn('host_only_cache_probe', fresh.dialog_failure_gate_labels)
        self.assertFalse(fresh.mutex_held[DIALOG_MUTEX])
        self.assertEqual(fresh.direct_release_entries, [])
        with self.assertRaises(ValueError):
            self.machine(capacity=True, cache_new_assembly=False)
        self.assertEqual(len(_ASSEMBLY_CACHE_MODULES), 39)
        for module, original in originals.items():
            self.assertIs(module.assemble, original, module.__name__)


if __name__ == '__main__':
    unittest.main()
