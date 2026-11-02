#!/usr/bin/env python3
"""Execute two actual callback call sites and their native frame exits.

The callback bodies are cut at4AEEDC/450D98, after genuine prologue state
has been supplied. Actual JAL4AD880 establishes the wrapper return; that
function is an explicit bounded substitute using the preceding W/C/D fixture.
The interpreter follows the actual saved returns through C, W and either
callback, including both emitted thunks and native epilogues. No Python V0
test chooses an abort route. Ordinary4AE9A0 and operation-context free remain
hostile bounded services. Earlier callback work and the enclosing dialog's
cleanup/lock obligations are outside this fixture, not certified by it.
"""

from contextlib import contextmanager
import hashlib
import struct
import unittest

import reveal_refresh_callback_gate_mips as core
import reveal_refresh_callback_gate_stage as stage
import test_reveal_refresh_wrapper_gate_mips as previous
from test_reveal_refresh_wrapper_gate_mips import (
    RefreshWrapperGateMachine, CONTROLLER, REGISTRY_MUTEX, PAINT_MUTEX,
    CODE, QUEUE, RAW_LOCK, RAW_UNLOCK, STACK, RETURN, MASK, NAME,
    DESTRUCTOR, STAGE_ARGS, OUTER_VIEW, NativeReturnBoundary, REFRESH,
    WRAPPER_SLICE, WRAPPER_RESET, _cached_assembler,
    _fixture_assembly_cache as imported_fixture_assembly_cache)


WRAPPER_ENTRY, CONTEXT_FREE, CALLBACK_POSTWORK = 0x4AD880, 0x466A80, 0x4AE9A0
DIALOG, OPERATION = 0x1D02000, 0x1D03000
CALLBACKS = {
    'first': dict(slice=0x4AEEDC, call=0x4AEEE0, return_pc=0x4AEEE8,
                  frame=0x14C0, epilogue=0x4AECD8,
                  abort='first_abort_return', selected='selected_first',
                  saves={**{register: 0x14A8 + 4 * (register - 16)
                            for register in range(16, 21)}, 31: 0x14BC}),
    'second': dict(slice=0x450D98, call=0x450D9C, return_pc=0x450DA4,
                   frame=0x28, epilogue=0x450DAC,
                   abort='second_abort_return', selected='selected_second',
                   saves={16: 0x20, 31: 0x24}),
}
_ASSEMBLY_CACHE_MODULES = (*previous._ASSEMBLY_CACHE_MODULES, core, stage)


@contextmanager
def _fixture_assembly_cache(enabled):
    """Cache only35 pure emitters/composers during serial construction."""
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


class RefreshCallbackGateMachine(RefreshWrapperGateMachine):
    """Native saved-return loads, rather than host status, choose all exits."""

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
                         'delete_release_gate', 'refresh_failure_gate',
                         'refresh_wrapper_gate', 'refresh_callback_gate'):
                setattr(self, name + '_labels', self.composition[name + '_labels'])
            self.bridge_labels = self.receipt_labels
            for pc, words in self.composition['coherent_hooks'].items():
                for index, word in enumerate(words):
                    self.patches[pc + index * 4] = word
            self.map(DIALOG, 0x100)
            self.map(OPERATION, 0xCF0)
            self.bounded_wrapper_entries, self.bounded_wrapper_contexts = [], []
            self.callback_postwork_entries, self.operation_free_entries = [], []
            self.clear_events()

    def external(self, target):
        if target == WRAPPER_ENTRY:
            self.calls.append(target)
            self.bounded_wrapper_entries.append((self.r.copy(), self.hi, self.lo))
            caller_sp, caller = self.r[29], self.r[31]
            view, descriptor, mode = self.r[4:7]
            context = self.seed_wrapper(
                caller_stack=caller_sp, caller=caller, view=view,
                descriptor=descriptor, mode=mode,
                controller=self.callback_context['controller'],
                wrapper_flag=self.callback_context['wrapper_flag'],
                refresh_flag=self.callback_context['refresh_flag'])
            self.bounded_wrapper_contexts.append(context)
            self.run_wrapper_slice(NativeReturnBoundary(
                caller, self.refresh_callback_gate_labels['first_abort_return'],
                self.refresh_callback_gate_labels['second_abort_return']))
            return
        if target == CALLBACK_POSTWORK:
            self.calls.append(target)
            self.callback_postwork_entries.append(
                (tuple(self.r[4:8]), self.r[29], self.r[31]))
            self.hostile_result(0)
            return
        if target == CONTEXT_FREE and self.r[4] == OPERATION:
            self.operation_free_entries.append(
                (tuple(self.r[4:8]), self.r[29], self.r[31]))
        return super().external(target)

    def clear_events(self):
        super().clear_events()
        for name in ('bounded_wrapper_entries', 'bounded_wrapper_contexts',
                     'callback_postwork_entries', 'operation_free_entries'):
            if hasattr(self, name):
                getattr(self, name).clear()

    def seed_callback(self, kind='first', *, wrapper_flag=1, refresh_flag=0,
                      caller_stack=STACK, caller=RETURN, controller=CONTROLLER,
                      view=OUTER_VIEW, mode=2):
        """Supply genuine native saves and cut-local state, not an owner lease."""
        route = CALLBACKS[kind]
        callback_sp = caller_stack - route['frame']
        saved = {register: self.r[register] for register in route['saves']}
        saved[31] = caller
        for register, offset in route['saves'].items():
            self.put(callback_sp + offset, saved[register], 4)
        self.put(DIALOG + 0x58, OPERATION, 4)
        self.put(OPERATION, mode, 4)
        self.put(OPERATION + 4, 1, 4)
        self.callback_context = dict(
            kind=kind, sp=callback_sp, caller_stack=caller_stack, caller=caller,
            controller=controller, view=view, mode=mode, saved=saved,
            wrapper_flag=wrapper_flag, refresh_flag=refresh_flag,
            preserved={register: self.r[register]
                       for register in (*range(16, 24), 28, 30)
                       if register not in saved})
        self.r[29], self.r[31], self.r[4] = callback_sp, caller, view
        if kind == 'first':
            self.r[16:21] = DIALOG, OPERATION, view, view + 0x800, mode
        else:
            self.r[16] = OPERATION
        return self.callback_context

    def run_callback_slice(self, stop=None):
        context = self.callback_context
        if stop is None:
            stop = context['caller']
        self.run_at(CALLBACKS[context['kind']]['slice'], stop)
        return self.r[2], self.r[3]

    def invoke_callback_refresh_gate(self, kind='first', *, result=MASK,
                                     diagnostic=22, wrapper_flag=1, refresh_flag=0,
                                     controller=CONTROLLER, return_pc=None):
        """Controlled actual frames; not a malformed-stack/helper-entry API."""
        callback = self.seed_callback(kind, wrapper_flag=wrapper_flag,
                                      refresh_flag=refresh_flag, controller=controller)
        wrapper = self.seed_wrapper(
            caller_stack=callback['sp'], caller=CALLBACKS[kind]['return_pc'],
            view=callback['view'], descriptor=OPERATION + 0x50,
            mode=callback['mode'], controller=controller,
            wrapper_flag=wrapper_flag, refresh_flag=refresh_flag)
        self.seed_refresh(caller_stack=wrapper['sp'], caller=previous.core.WRAPPER_RETURN,
                          controller=controller, view=wrapper['view'], flag=refresh_flag)
        self.r[2:4] = result, diagnostic
        self.r[31] = REFRESH.HOOKS['gate'][0] if return_pc is None else return_pc
        self.clear_events()
        self.run_at(REFRESH.HOOKS['gate'][0], callback['caller'])
        return self.r[2], self.r[3]

    def remove_generated_callback_splice(self, *, fetch_override=True, prefix_bytes=True):
        """Both emitted bytes and fetch override must be removed for baseline."""
        code = bytearray(self.code)
        for pc, words in self.composition['refresh_callback_gate_source_words'].items():
            if fetch_override:
                self.remove_pair(pc)
            if prefix_bytes:
                struct.pack_into('<2I', code, pc - CODE, *words)
        self.code = self.code_bytes = bytes(code)


class RefreshCallbackGateTests(unittest.TestCase):
    setUpClass = classmethod(previous.RefreshWrapperGateTests.setUpClass.__func__)

    def machine(self, **options):
        return RefreshCallbackGateMachine(self.image, **options)

    def watch_scope(self, machine):
        snapshots, marks = {}, []

        def observe(current, pc):
            labels = current.refresh_callback_gate_labels
            targets = {'gate': current.refresh_failure_gate_labels['gate'],
                       'scope': labels['scope'], 'replay': labels['replay'],
                       'refresh_epilogue': REFRESH.EPILOGUE,
                       'wrapper_abort': current.refresh_wrapper_gate_labels['abort_return']}
            for kind, route in CALLBACKS.items():
                targets[kind + '_abort'] = labels[route['abort']]
                targets[kind + '_epilogue'] = route['epilogue']
            for name, target in targets.items():
                if pc == target:
                    snapshots[name] = (current.r.copy(), current.hi, current.lo)
                    if name == 'scope':
                        marks.append((len(current.reads), len(current.writes),
                                      len(current.calls), len(current.freed),
                                      len(current.constructor_accesses), current.r[29]))

        machine.on_instruction = observe
        return marks, snapshots

    def assert_callback_unwind(self, machine, context):
        self.assertEqual((machine.r[29], machine.r[31]),
                         (context['caller_stack'], context['caller']))
        for register, value in {**context['saved'], **context['preserved']}.items():
            self.assertEqual(machine.r[register], value, register)

    def assert_selected_stop(self, machine, context, marks, snapshots, result=MASK, raw=22):
        kind, labels = context['kind'], machine.refresh_callback_gate_labels
        route = CALLBACKS[kind]
        self.assertEqual((machine.r[2], machine.r[3]), (result, raw))
        self.assert_callback_unwind(machine, context)
        self.assertEqual(snapshots['gate'], snapshots['refresh_epilogue'])
        self.assertEqual((machine.hi, machine.lo), snapshots['gate'][1:])
        self.assertEqual(snapshots[kind + '_abort'], snapshots[kind + '_epilogue'])
        self.assertEqual(machine.trace.count(labels['scope']), 1)
        self.assertEqual(machine.trace.count(labels[route['selected']]), 1)
        self.assertEqual(machine.trace.count(labels[route['abort']]), 1)
        self.assertNotIn(route['return_pc'], machine.trace)
        self.assertEqual(machine.operation_free_entries, [])
        self.assertEqual(machine.callback_postwork_entries, [])
        self.assertEqual(machine.wrapper_reset_entries, [])
        self.assertEqual(machine.recreate_entries, [])
        self.assertEqual(machine.offset_entries, [])
        self.assertEqual(machine.words_at(DIALOG + 0x58, 1), (OPERATION,))
        self.assertEqual(len(marks), 1)
        reads, writes, calls, freed, accesses, private_sp = marks[0]
        refresh_sp, wrapper_sp = machine.refresh_context['sp'], machine.wrapper_context['sp']
        self.assertEqual(private_sp, refresh_sp - REFRESH.FRAME)
        self.assertEqual(machine.calls[calls:], [])
        self.assertEqual(machine.freed[freed:], [])
        self.assertTrue(all(private_sp <= address and address + size <= context['caller_stack']
                            for address, size in machine.reads[reads:]))
        expected_writes = [(wrapper_sp + 0x2C, labels[route['abort']], 4),
                           (refresh_sp + 0x484,
                            machine.refresh_wrapper_gate_labels['abort_return'], 4)]
        self.assertEqual(machine.writes[writes:], expected_writes)
        self.assertEqual([(address, size) for access, pc, address, size
                          in machine.constructor_accesses[accesses:] if access == 'write'],
                         [(address, size) for address, value, size in expected_writes])
        self.assertEqual(machine.words_at(wrapper_sp + 0x2C, 1),
                         (labels[route['abort']],))
        ra_slot = context['sp'] + route['saves'][31]
        self.assertEqual(machine.words_at(ra_slot, 1), (context['caller'],))
        self.assertEqual(machine.reads[reads:].count((ra_slot, 4)), 1)
        abort = snapshots[kind + '_abort'][0]
        self.assertEqual((abort[29], abort[31]), (context['sp'], labels[route['abort']]))

    def test_actual_acquire_error_skips_both_callback_continuations_for_all_flags(self):
        for kind in CALLBACKS:
            for wrapper_flag, refresh_flag in ((0, 0), (0, 1), (1, 0), (1, 1)):
                with self.subTest(kind=kind, wrapper=wrapper_flag, refresh=refresh_flag):
                    m = self.machine(acquire=22)
                    context = m.seed_callback(kind, wrapper_flag=wrapper_flag,
                                              refresh_flag=refresh_flag)
                    m.clear_events()
                    marks, snapshots = self.watch_scope(m)
                    self.assertEqual(m.run_callback_slice(), (MASK, 22))
                    self.assert_selected_stop(m, context, marks, snapshots)
                    self.assertEqual([(event[0], event[1], event[-1]) for event in m.raw_events],
                                     [(RAW_LOCK, REGISTRY_MUTEX, 22)])
                    self.assertEqual(m.freed, [])

    def test_actual_release_error_preserves_result_and_uncertain_ownership_through_callbacks(self):
        for kind in CALLBACKS:
            for wrapper_flag, refresh_flag in ((0, 0), (1, 1)):
                with self.subTest(kind=kind, wrapper=wrapper_flag, refresh=refresh_flag):
                    m = self.machine(release=0x82, registry_release_failure_releases=False)
                    context = m.seed_callback(kind, wrapper_flag=wrapper_flag,
                                              refresh_flag=refresh_flag)
                    m.clear_events()
                    marks, snapshots = self.watch_scope(m)
                    self.assertEqual(m.run_callback_slice(), (MASK, 0x82))
                    self.assert_selected_stop(m, context, marks, snapshots, raw=0x82)
                    self.assertTrue(m.registry_held)
                    self.assertEqual([(event[0], event[1], event[-1]) for event in m.raw_events],
                                     [(RAW_LOCK, REGISTRY_MUTEX, 0),
                                      (RAW_UNLOCK, REGISTRY_MUTEX, 0x82)])

    def test_ordinary_zero_and_one_preserve_callback_free_clear_postwork_and_abi(self):
        for kind in CALLBACKS:
            for wrapper_flag, refresh_flag in ((0, 0), (0, 1), (1, 0), (1, 1)):
                with self.subTest(kind=kind, wrapper=wrapper_flag, refresh=refresh_flag):
                    m, old = self.machine(), self.machine()
                    old.remove_generated_callback_splice()
                    context = m.seed_callback(kind, wrapper_flag=wrapper_flag,
                                              refresh_flag=refresh_flag)
                    old.seed_callback(kind, wrapper_flag=wrapper_flag, refresh_flag=refresh_flag)
                    for current in (m, old):
                        current.clear_events()
                    self.assertEqual(m.run_callback_slice(), old.run_callback_slice())
                    self.assert_callback_unwind(m, context)
                    self.assertEqual((m.r, m.hi, m.lo), (old.r, old.hi, old.lo))
                    self.assertEqual(m.raw_events, old.raw_events)
                    self.assertEqual(m.operation_free_entries, old.operation_free_entries)
                    self.assertEqual(m.callback_postwork_entries, old.callback_postwork_entries)
                    self.assertEqual(len(m.operation_free_entries), 1)
                    self.assertEqual(m.operation_free_entries[0][0][0], OPERATION)
                    expected_postwork = int(kind == 'first' and bool(refresh_flag))
                    self.assertEqual(len(m.callback_postwork_entries), expected_postwork)
                    if expected_postwork:
                        args, sp, ra = m.callback_postwork_entries[0]
                        self.assertEqual(args[:3], (OUTER_VIEW, context['sp'] + 0x1438,
                                                   context['sp'] + 0x0AA8))
                        self.assertEqual((sp, ra), (context['sp'], 0x4AEF00))
                    expected_context = 0 if kind == 'first' else OPERATION
                    self.assertEqual(m.words_at(DIALOG + 0x58, 1), (expected_context,))
                    self.assertNotIn(m.refresh_callback_gate_labels['scope'], m.trace)
                    self.assertEqual(m.words_at(m.wrapper_context['sp'] + 0x2C, 1),
                                     (CALLBACKS[kind]['return_pc'],))

    def test_positive_offset_and_wrapper_reset_keep_same_bounded_callback_behavior(self):
        for kind in CALLBACKS:
            with self.subTest(kind=kind):
                m, old = self.machine(), self.machine()
                old.remove_generated_callback_splice()
                context = m.seed_callback(kind)
                old.seed_callback(kind)
                for current in (m, old):
                    current.seed_positive_recreation()
                    current.clear_events()
                self.assertEqual(m.run_callback_slice(), old.run_callback_slice())
                self.assert_callback_unwind(m, context)
                self.assertEqual((m.r, m.hi, m.lo), (old.r, old.hi, old.lo))
                self.assertEqual(m.offset_entries, old.offset_entries)
                self.assertEqual(m.wrapper_reset_entries, old.wrapper_reset_entries)
                self.assertEqual(len(m.offset_entries), 1)
                self.assertEqual(len(m.wrapper_reset_entries), 1)
                self.assertEqual(len(m.operation_free_entries), 1)

    def test_earlier_populated_delete_effects_remain_but_operation_context_is_retained(self):
        for kind in CALLBACKS:
            with self.subTest(kind=kind):
                m = self.machine()
                self.assertEqual(m.register(), 0)
                node = m.allocations[-1]
                m.release = 22
                context = m.seed_callback(kind)
                m.clear_events()
                marks, snapshots = self.watch_scope(m)
                self.assertEqual(m.run_callback_slice(), (MASK, 22))
                self.assert_selected_stop(m, context, marks, snapshots)
                self.assertIn(node, m.freed)
                self.assertNotIn(OPERATION, m.freed)
                self.assertEqual(m.words_at(CONTROLLER + 0x34, 2), (CONTROLLER + 0x34,) * 2)
                self.assertEqual(len(m.lifecycle_requests), 1)
                self.assertTrue(m.cleanup_services)
                self.assertEqual(m.resource_entries, [])

    def test_native_callback_call_delays_supply_actual_nested_wrapper_return_and_arguments(self):
        for kind in CALLBACKS:
            with self.subTest(kind=kind):
                m = self.machine(release=22)
                context = m.seed_callback(kind, wrapper_flag=1, refresh_flag=1, mode=2)
                m.clear_events()
                marks, snapshots = self.watch_scope(m)
                m.run_callback_slice()
                self.assert_selected_stop(m, context, marks, snapshots)
                self.assertEqual(len(m.bounded_wrapper_entries), 1)
                entry = m.bounded_wrapper_entries[0][0]
                route = CALLBACKS[kind]
                self.assertEqual(tuple(entry[4:7]), (OUTER_VIEW, OPERATION + 0x50, 2))
                self.assertEqual((entry[29], entry[31]), (context['sp'], route['return_pc']))
                wrapper = m.bounded_wrapper_contexts[0]
                self.assertEqual((wrapper['sp'], wrapper['caller_stack'], wrapper['caller']),
                                 (context['sp'] - previous.core.WRAPPER_FRAME,
                                  context['sp'], route['return_pc']))
                refresh = m.bounded_refresh_contexts[0]
                self.assertEqual(refresh['caller_stack'], wrapper['sp'])
                self.assertEqual(refresh['caller'], previous.core.WRAPPER_RETURN)
                self.assertEqual(m.bounded_destructor_contexts[0]['caller_stack'], refresh['sp'])
                self.assertEqual(m.calls.count(WRAPPER_ENTRY), 1)

    def test_foreign_wrapper_caller_keeps_prior_wrapper_escape_and_original_saved_return(self):
        foreign = 0x4AEF40
        m, old = self.machine(acquire=22), self.machine(acquire=22)
        old.remove_generated_callback_splice()
        context = m.seed_wrapper(caller=foreign)
        old.seed_wrapper(caller=foreign)
        for current in (m, old):
            current.clear_events()
        marks, snapshots = self.watch_scope(m)
        self.assertEqual(m.run_wrapper_slice(), old.run_wrapper_slice())
        self.assertEqual((m.r[2], m.r[3]), (MASK, 22))
        self.assertEqual((m.r, m.hi, m.lo), (old.r, old.hi, old.lo))
        self.assertEqual((m.r[29], m.r[31]), (STACK, foreign))
        self.assertEqual(m.words_at(context['sp'] + 0x2C, 1), (foreign,))
        self.assertEqual(snapshots['gate'], snapshots['refresh_epilogue'])
        self.assertEqual(len(marks), 1)
        self.assertEqual(m.writes[marks[0][1]:],
                         [(m.refresh_context['sp'] + 0x484,
                           m.refresh_wrapper_gate_labels['abort_return'], 4)])
        for route in CALLBACKS.values():
            self.assertNotIn(m.refresh_callback_gate_labels[route['abort']], m.trace)

    def test_cache_preserves_exact_code_metadata_cpu_separation_and_all_function_identities(self):
        originals = {module: module.assemble for module in _ASSEMBLY_CACHE_MODULES}
        uncached = self.machine(acquire=22, assembly_cache=False)
        cached = self.machine(acquire=22)
        self.assertEqual(cached.code, uncached.code)
        tail = cached.composition['refresh_callback_gate_code_bytes']
        self.assertEqual(len(cached.code), 92500 + tail)
        self.assertEqual(hashlib.sha256(cached.code).hexdigest(),
                         hashlib.sha256(uncached.code).hexdigest())
        with _fixture_assembly_cache(True):
            guarded = previous.stage.assemble(*STAGE_ARGS, following_code_bytes=tail)
        expected = bytearray(guarded['code'])
        for pc, words in cached.composition['refresh_callback_gate_hooks'].items():
            struct.pack_into('<2I', expected, pc - CODE, *words)
        self.assertEqual(cached.code[:92500], bytes(expected))
        self.assertEqual(cached.composition['refresh_callback_gate_prefix_code_bytes'], 92500)
        self.assertIsNot(cached.composition, uncached.composition)
        self.assertIsNot(cached.refresh_callback_gate_labels, uncached.refresh_callback_gate_labels)
        for current in (cached, uncached):
            current.seed_callback('first')
            current.clear_events()
        self.assertEqual(cached.run_callback_slice(), uncached.run_callback_slice())
        self.assertEqual((cached.r, cached.hi, cached.lo), (uncached.r, uncached.hi, uncached.lo))
        cached.refresh_callback_gate_labels['host_only_cache_probe'] = 123
        cached.registry_held = True
        fresh = self.machine()
        self.assertNotIn('host_only_cache_probe', fresh.refresh_callback_gate_labels)
        self.assertFalse(fresh.registry_held)
        self.assertEqual(fresh.raw_events, [])
        fresh.seed_callback('second', refresh_flag=1)
        fresh.clear_events()
        fresh.run_callback_slice()
        self.assertEqual(len(fresh.operation_free_entries), 1)
        with self.assertRaises(ValueError):
            self.machine(capacity=True)
        self.assertEqual(len(_ASSEMBLY_CACHE_MODULES), 35)
        for module, original in originals.items():
            self.assertIs(module.assemble, original, module.__name__)


if __name__ == '__main__':
    unittest.main()
