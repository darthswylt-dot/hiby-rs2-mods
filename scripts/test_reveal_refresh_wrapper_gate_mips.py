#!/usr/bin/env python3
"""Execute the selected wrapper's saved-return diversion and native unwind.

Actual4AD8D8 calls an explicit bounded refresh substitute. Its genuine C1160
frame is seeded, the preceding bounded D1208 substitute and actual deletion
run, and the native C epilogue chooses its actual saved return. The enclosing
interpreter then follows that RA, including the generated abort thunk and
actual W48 native suffix. No host V0 test decides a return or abort route.

Inherited destructor/recreation/offset substitutes stay unchanged.4ACE40 is a
bounded hostile substitute on ordinary or baseline wrapper continuations.
Earlier W/C/D bodies and higher callbacks are not executed or certified; the
frames and coherent redirects are HARD premises, not authenticated objects.
"""

from contextlib import contextmanager
import hashlib
import struct
import unittest

import reveal_refresh_wrapper_gate_mips as core
import reveal_refresh_wrapper_gate_stage as stage
import test_reveal_refresh_failure_gate_mips as previous
from test_reveal_refresh_failure_gate_mips import (
    RefreshFailureGateMachine, CONTROLLER, REGISTRY_MUTEX, PAINT_MUTEX,
    CODE, QUEUE, RAW_LOCK, RAW_UNLOCK, STACK, RETURN, MASK, NAME,
    DESTRUCTOR, STAGE_ARGS, OUTER_VIEW, NativeReturnBoundary,
    _cached_assembler, _fixture_assembly_cache as imported_fixture_assembly_cache)


REFRESH = previous.core
WRAPPER_SLICE, REFRESH_ENTRY, WRAPPER_RESET = 0x4AD8D8, 0x4ACBC0, 0x4ACE40
WRAPPER_SAVES = {16: 0x1C, 17: 0x20, 18: 0x24, 19: 0x28, 31: 0x2C}
_ASSEMBLY_CACHE_MODULES = (*previous._ASSEMBLY_CACHE_MODULES, core, stage)


@contextmanager
def _fixture_assembly_cache(enabled):
    """Cache only pure33-module assembly during serial fixture construction."""
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


class RefreshWrapperGateMachine(RefreshFailureGateMachine):
    """Actual C saved RA, never a Python failure flag, selects the W exit."""

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
                         'refresh_wrapper_gate'):
                setattr(self, name + '_labels', self.composition[name + '_labels'])
            self.bridge_labels = self.receipt_labels
            for pc, words in self.composition['coherent_hooks'].items():
                for index, word in enumerate(words):
                    self.patches[pc + index * 4] = word
            self.bounded_refresh_entries, self.bounded_refresh_contexts = [], []
            self.wrapper_reset_entries, self.wrapper_refresh_delays = [], []
            self.clear_events()

    def plain(self, word):
        if (hasattr(self, 'wrapper_refresh_delays') and word == 0x02002021
                and self.current_pc == WRAPPER_SLICE):
            self.wrapper_refresh_delays.append((self.current_pc, self.r[16]))
        return super().plain(word)

    def external(self, target):
        if target == REFRESH_ENTRY:
            self.calls.append(target)
            self.bounded_refresh_entries.append((self.r.copy(), self.hi, self.lo))
            caller_sp, caller, view = self.r[29], self.r[31], self.r[4]
            context = self.seed_refresh(
                caller_stack=caller_sp, caller=caller, view=view,
                controller=self.wrapper_context['controller'],
                flag=self.wrapper_context['refresh_flag'])
            self.bounded_refresh_contexts.append(context)
            self.run_refresh_slice(NativeReturnBoundary(
                caller, self.refresh_wrapper_gate_labels['abort_return']))
            return
        if target == WRAPPER_RESET:
            self.calls.append(target)
            self.wrapper_reset_entries.append(
                (tuple(self.r[4:8]), self.r[29], self.r[31]))
            self.hostile_result(0)
            return
        return super().external(target)

    def clear_events(self):
        super().clear_events()
        for name in ('bounded_refresh_entries', 'bounded_refresh_contexts',
                     'wrapper_reset_entries', 'wrapper_refresh_delays'):
            if hasattr(self, name):
                getattr(self, name).clear()

    def seed_wrapper(self, *, wrapper_flag=1, refresh_flag=0,
                     caller_stack=STACK, caller=RETURN, controller=CONTROLLER,
                     view=OUTER_VIEW, descriptor=NAME, mode=2):
        """Seed genuine W48 save slots; begin after its earlier opaque body."""
        wrapper_sp = caller_stack - core.WRAPPER_FRAME
        saved = {register: self.r[register] for register in WRAPPER_SAVES}
        saved[31] = caller
        for register, offset in WRAPPER_SAVES.items():
            self.put(wrapper_sp + offset, saved[register], 4)
        self.wrapper_context = dict(
            sp=wrapper_sp, caller_stack=caller_stack, caller=caller,
            controller=controller, view=view, descriptor=descriptor, mode=mode,
            wrapper_flag=wrapper_flag, refresh_flag=refresh_flag, saved=saved,
            preserved={register: self.r[register]
                       for register in (*range(20, 24), 28, 30)})
        self.r[29], self.r[31] = wrapper_sp, caller
        self.r[16:20] = view, descriptor, mode, wrapper_flag
        return self.wrapper_context

    def run_wrapper_slice(self, stop=None):
        if stop is None:
            stop = self.wrapper_context['caller']
        self.run_at(WRAPPER_SLICE, stop)
        return self.r[2], self.r[3]

    def invoke_wrapper_refresh_gate(self, *, result=MASK, diagnostic=22,
                                    wrapper_flag=1, refresh_flag=0,
                                    controller=CONTROLLER, return_pc=None):
        """Controlled genuine W/C frames; not an arbitrary helper-entry API."""
        wrapper = self.seed_wrapper(wrapper_flag=wrapper_flag, refresh_flag=refresh_flag,
                                    controller=controller)
        self.seed_refresh(caller_stack=wrapper['sp'], caller=core.WRAPPER_RETURN,
                          controller=controller, view=wrapper['view'], flag=refresh_flag)
        self.r[2:4] = result, diagnostic
        self.r[31] = REFRESH.HOOKS['gate'][0] if return_pc is None else return_pc
        self.clear_events()
        self.run_at(REFRESH.HOOKS['gate'][0], wrapper['caller'])
        return self.r[2], self.r[3]

    def remove_generated_wrapper_splice(self, *, fetch_override=True, prefix_bytes=True):
        """Remove both copies for a genuinely missing generated splice."""
        code = bytearray(self.code)
        for pc, words in self.composition['refresh_wrapper_gate_source_words'].items():
            if fetch_override:
                self.remove_pair(pc)
            if prefix_bytes:
                struct.pack_into('<2I', code, pc - CODE, *words)
        self.code = self.code_bytes = bytes(code)


class RefreshWrapperGateTests(unittest.TestCase):
    setUpClass = classmethod(previous.RefreshFailureGateTests.setUpClass.__func__)

    def machine(self, **options):
        return RefreshWrapperGateMachine(self.image, **options)

    def watch_scope(self, machine):
        snapshots, marks = {}, []

        def observe(current, pc):
            labels = current.refresh_wrapper_gate_labels
            targets = {'gate': current.refresh_failure_gate_labels['gate'],
                       'scope': labels['scope'], 'replay': labels['replay'],
                       'refresh_epilogue': REFRESH.EPILOGUE,
                       'abort': labels['abort_return'],
                       'wrapper_epilogue': core.WRAPPER_EPILOGUE}
            for name, target in targets.items():
                if pc == target:
                    snapshots[name] = (current.r.copy(), current.hi, current.lo)
                    if name == 'scope':
                        marks.append((len(current.reads), len(current.writes),
                                      len(current.calls), len(current.freed),
                                      len(current.constructor_accesses), current.r[29]))

        machine.on_instruction = observe
        return marks, snapshots

    def assert_wrapper_unwind(self, machine, context):
        self.assertEqual((machine.r[29], machine.r[31]),
                         (context['caller_stack'], context['caller']))
        for register, value in {**context['saved'], **context['preserved']}.items():
            self.assertEqual(machine.r[register], value, register)

    def assert_selected_stop(self, machine, context, marks, snapshots, result=MASK, raw=22):
        self.assertEqual((machine.r[2], machine.r[3]), (result, raw))
        self.assert_wrapper_unwind(machine, context)
        self.assertEqual(snapshots['gate'], snapshots['refresh_epilogue'])
        self.assertEqual((machine.hi, machine.lo), snapshots['gate'][1:])
        self.assertIn(machine.refresh_wrapper_gate_labels['selected'], machine.trace)
        self.assertEqual(machine.trace.count(machine.refresh_wrapper_gate_labels['scope']), 1)
        self.assertEqual(machine.trace.count(machine.refresh_wrapper_gate_labels['abort_return']), 1)
        self.assertIn(core.WRAPPER_EPILOGUE, machine.trace)
        self.assertNotIn(core.WRAPPER_RETURN, machine.trace)
        self.assertNotIn(0x4AD900, machine.trace)
        self.assertNotIn(REFRESH.FALLTHROUGH, machine.trace)
        self.assertEqual(machine.wrapper_reset_entries, [])
        self.assertEqual(machine.recreate_entries, [])
        self.assertEqual(machine.offset_entries, [])
        self.assertEqual(machine.refresh_delay_effects, [])
        self.assertEqual(len(marks), 1)
        reads, writes, calls, freed, accesses, private_sp = marks[0]
        refresh_sp = machine.refresh_context['sp']
        self.assertEqual(private_sp, refresh_sp - REFRESH.FRAME)
        self.assertEqual(machine.calls[calls:], [])
        self.assertEqual(machine.freed[freed:], [])
        self.assertTrue(all(private_sp <= address and address + size <= context['caller_stack']
                            for address, size in machine.reads[reads:]))
        rewritten = [(refresh_sp + 0x484, machine.refresh_wrapper_gate_labels['abort_return'], 4)]
        self.assertEqual(machine.writes[writes:], rewritten)
        helper_writes = [(kind, address, size) for kind, pc, address, size
                         in machine.constructor_accesses[accesses:]
                         if kind == 'write']
        self.assertEqual(helper_writes, [('write', refresh_sp + 0x484, 4)])
        self.assertEqual(machine.words_at(context['sp'] + 0x2C, 1), (context['caller'],))
        self.assertEqual(machine.words_at(refresh_sp + 0x484, 1),
                         (machine.refresh_wrapper_gate_labels['abort_return'],))
        self.assertEqual(machine.reads[reads:].count((context['sp'] + 0x2C, 4)), 1)
        abort, hi, lo = snapshots['abort']
        expected = abort.copy()
        expected[31] = context['caller']
        self.assertEqual(snapshots['wrapper_epilogue'], (expected, hi, lo))
        self.assertEqual((abort[29], abort[31]),
                         (context['sp'], machine.refresh_wrapper_gate_labels['abort_return']))

    def test_actual_acquire_error_skips_wrapper_work_for_both_native_flags(self):
        for wrapper_flag in (0, 1):
            for refresh_flag in (0, 1):
                with self.subTest(wrapper_flag=wrapper_flag, refresh_flag=refresh_flag):
                    m = self.machine(acquire=22)
                    context = m.seed_wrapper(wrapper_flag=wrapper_flag, refresh_flag=refresh_flag)
                    m.clear_events()
                    marks, snapshots = self.watch_scope(m)
                    self.assertEqual(m.run_wrapper_slice(), (MASK, 22))
                    self.assert_selected_stop(m, context, marks, snapshots)
                    self.assertEqual([(event[0], event[1], event[-1]) for event in m.raw_events],
                                     [(RAW_LOCK, REGISTRY_MUTEX, 22)])
                    self.assertEqual(m.freed, [])

    def test_actual_release_error_preserves_raw_result_through_all_native_unwinds(self):
        for wrapper_flag in (0, 1):
            for refresh_flag in (0, 1):
                with self.subTest(wrapper_flag=wrapper_flag, refresh_flag=refresh_flag):
                    m = self.machine(release=0x82, registry_release_failure_releases=False)
                    context = m.seed_wrapper(wrapper_flag=wrapper_flag, refresh_flag=refresh_flag)
                    m.clear_events()
                    marks, snapshots = self.watch_scope(m)
                    self.assertEqual(m.run_wrapper_slice(), (MASK, 0x82))
                    self.assert_selected_stop(m, context, marks, snapshots, raw=0x82)
                    self.assertTrue(m.registry_held)
                    self.assertEqual([(event[0], event[1], event[-1]) for event in m.raw_events],
                                     [(RAW_LOCK, REGISTRY_MUTEX, 0),
                                      (RAW_UNLOCK, REGISTRY_MUTEX, 0x82)])

    def test_positive_zero_and_one_keep_exact_native_wrapper_abi_and_normal_reset(self):
        for wrapper_flag in (0, 1):
            for refresh_flag in (0, 1):
                with self.subTest(wrapper_flag=wrapper_flag, refresh_flag=refresh_flag):
                    m, old = self.machine(), self.machine()
                    context = m.seed_wrapper(wrapper_flag=wrapper_flag, refresh_flag=refresh_flag)
                    old.seed_wrapper(wrapper_flag=wrapper_flag, refresh_flag=refresh_flag)
                    old.remove_generated_wrapper_splice()
                    for current in (m, old):
                        current.clear_events()
                    self.assertEqual(m.run_wrapper_slice(), old.run_wrapper_slice())
                    self.assertEqual(m.r[2], refresh_flag)
                    self.assert_wrapper_unwind(m, context)
                    self.assertEqual((m.r, m.hi, m.lo), (old.r, old.hi, old.lo))
                    self.assertEqual(m.raw_events, old.raw_events)
                    self.assertEqual(m.recreate_entries, old.recreate_entries)
                    self.assertEqual(m.wrapper_reset_entries, old.wrapper_reset_entries)
                    self.assertEqual(len(m.recreate_entries), int(not refresh_flag))
                    reset = int(bool(wrapper_flag) and not refresh_flag)
                    self.assertEqual(len(m.wrapper_reset_entries), reset)
                    if reset:
                        self.assertEqual(m.wrapper_reset_entries[0][0][0], context['view'])
                        self.assertEqual(m.wrapper_reset_entries[0][1:], (context['sp'], 0x4AD8FC))
                    self.assertNotIn(m.refresh_wrapper_gate_labels['scope'], m.trace)
                    self.assertEqual(m.words_at(m.refresh_context['sp'] + 0x484, 1),
                                     (core.WRAPPER_RETURN,))

    def test_positive_offset_continuation_and_wrapper_reset_match_same_bounded_baseline(self):
        m, old = self.machine(), self.machine()
        context = m.seed_wrapper(wrapper_flag=1, refresh_flag=0)
        old.seed_wrapper(wrapper_flag=1, refresh_flag=0)
        old.remove_generated_wrapper_splice()
        for current in (m, old):
            current.seed_positive_recreation()
            current.clear_events()
        self.assertEqual(m.run_wrapper_slice(), old.run_wrapper_slice())
        self.assertEqual(m.r[2], 0)
        self.assert_wrapper_unwind(m, context)
        self.assertEqual((m.r, m.hi, m.lo), (old.r, old.hi, old.lo))
        self.assertEqual(m.recreate_entries, old.recreate_entries)
        self.assertEqual(m.offset_entries, old.offset_entries)
        self.assertEqual(m.wrapper_reset_entries, old.wrapper_reset_entries)
        self.assertEqual(len(m.recreate_entries), 1)
        self.assertEqual(len(m.offset_entries), 1)
        self.assertEqual(len(m.wrapper_reset_entries), 1)
        self.assertNotIn(m.refresh_wrapper_gate_labels['scope'], m.trace)

    def test_earlier_populated_delete_effects_are_not_rolled_back_by_wrapper_exit(self):
        m = self.machine()
        self.assertEqual(m.register(), 0)
        node = m.allocations[-1]
        m.release = 22
        context = m.seed_wrapper()
        m.clear_events()
        marks, snapshots = self.watch_scope(m)
        self.assertEqual(m.run_wrapper_slice(), (MASK, 22))
        self.assert_selected_stop(m, context, marks, snapshots)
        self.assertIn(node, m.freed)
        self.assertEqual(m.words_at(CONTROLLER + 0x34, 2), (CONTROLLER + 0x34,) * 2)
        self.assertEqual(len(m.lifecycle_requests), 1)
        self.assertTrue(m.cleanup_services)
        self.assertEqual(m.resource_entries, [])

    def test_foreign_actual_refresh_outer_return_is_not_retargeted(self):
        foreign_return = 0x4AEC24
        for option in ('acquire', 'release'):
            with self.subTest(option=option):
                m, old = self.machine(**{option: 22}), self.machine(**{option: 22})
                old.remove_generated_wrapper_splice()
                context = m.seed_refresh(caller=foreign_return)
                old.seed_refresh(caller=foreign_return)
                for current in (m, old):
                    current.clear_events()
                marks, snapshots = self.watch_scope(m)
                self.assertEqual(m.run_refresh_slice(foreign_return), (MASK, 22))
                self.assertEqual(old.run_refresh_slice(foreign_return), (MASK, 22))
                self.assertEqual((m.r, m.hi, m.lo), (old.r, old.hi, old.lo))
                self.assertEqual(m.words_at(context['sp'] + 0x484, 1), (foreign_return,))
                self.assertNotIn(m.refresh_wrapper_gate_labels['selected'], m.trace)
                self.assertNotIn(m.refresh_wrapper_gate_labels['abort_return'], m.trace)
                self.assertEqual(snapshots['gate'], snapshots['refresh_epilogue'])
                self.assertEqual(m.writes[marks[0][1]:], [])
                self.assertEqual(m.wrapper_reset_entries, [])
                self.assertEqual((m.r[29], m.r[31]), (STACK, foreign_return))

    def test_native_wrapper_call_delay_and_genuine_nested_frames_keep_their_original_abi(self):
        m = self.machine(release=22)
        context = m.seed_wrapper(wrapper_flag=1, refresh_flag=1)
        m.clear_events()
        marks, snapshots = self.watch_scope(m)
        m.run_wrapper_slice()
        self.assert_selected_stop(m, context, marks, snapshots)
        self.assertEqual(len(m.bounded_refresh_entries), 1)
        refresh_entry = m.bounded_refresh_entries[0][0]
        self.assertEqual((refresh_entry[4], refresh_entry[29], refresh_entry[31]),
                         (context['view'], context['sp'], core.WRAPPER_RETURN))
        nested = m.bounded_refresh_contexts[0]
        self.assertEqual((nested['sp'], nested['caller_stack'], nested['caller']),
                         (context['sp'] - REFRESH.REFRESH_FRAME, context['sp'], core.WRAPPER_RETURN))
        for register in (16, 17, 18, 19, 20):
            self.assertEqual(snapshots['abort'][0][register], nested['saved'][register], register)
        self.assertEqual(m.wrapper_refresh_delays, [(WRAPPER_SLICE, context['view'])])
        self.assertEqual(m.calls.count(REFRESH_ENTRY), 1)
        child = m.bounded_destructor_contexts[0]
        self.assertEqual(child['caller_stack'], nested['sp'])
        self.assertEqual(m.raw_events[-1],
                         (RAW_UNLOCK, REGISTRY_MUTEX, child['sp'] - 64, 0x466DD0, 22))

    def test_cache_preserves_exact_bytes_fresh_state_metadata_and_restores_all_functions(self):
        originals = {module: module.assemble for module in _ASSEMBLY_CACHE_MODULES}
        uncached = self.machine(acquire=22, assembly_cache=False)
        cached = self.machine(acquire=22)
        self.assertEqual(cached.code, uncached.code)
        self.assertEqual(len(cached.code), 92500)
        self.assertEqual(hashlib.sha256(cached.code).hexdigest(),
                         'b10314826317ea55438b21abcb4de04825346d3c593c132ec6cdd7921b74e696')
        tail = cached.composition['refresh_wrapper_gate_code_bytes']
        guarded = previous.stage.assemble(*STAGE_ARGS, following_code_bytes=tail)
        expected = bytearray(guarded['code'])
        for pc, words in cached.composition['refresh_wrapper_gate_hooks'].items():
            struct.pack_into('<2I', expected, pc - CODE, *words)
        self.assertEqual(cached.code[:92444], bytes(expected))
        self.assertEqual(cached.composition['refresh_wrapper_gate_prefix_code_bytes'], 92444)
        self.assertEqual(tail, 56)
        self.assertIsNot(cached.composition, uncached.composition)
        self.assertIsNot(cached.refresh_wrapper_gate_labels, uncached.refresh_wrapper_gate_labels)
        for current in (cached, uncached):
            current.seed_wrapper()
            current.clear_events()
        self.assertEqual(cached.run_wrapper_slice(), uncached.run_wrapper_slice())
        self.assertEqual((cached.r, cached.hi, cached.lo), (uncached.r, uncached.hi, uncached.lo))
        cached.refresh_wrapper_gate_labels['host_only_cache_probe'] = 123
        cached.registry_held = True
        fresh = self.machine()
        self.assertNotIn('host_only_cache_probe', fresh.refresh_wrapper_gate_labels)
        self.assertFalse(fresh.registry_held)
        self.assertEqual(fresh.raw_events, [])
        fresh.seed_wrapper(refresh_flag=1)
        fresh.clear_events()
        self.assertEqual(fresh.run_wrapper_slice()[0], 1)
        self.assertEqual(cached.wrapper_reset_entries, [])
        with self.assertRaises(ValueError):
            self.machine(capacity=True)
        for module, original in originals.items():
            self.assertIs(module.assemble, original, module.__name__)


if __name__ == '__main__':
    unittest.main()
