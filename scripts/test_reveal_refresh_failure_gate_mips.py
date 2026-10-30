#!/usr/bin/env python3
"""Execute the ordinary Files caller's real return gate and native epilogue.

Native4ACD8C calls an EXPLICIT bounded destructor substitute: its genuine
1208-byte frame is seeded, actual493F40 name deletion and existing gates run,
and its success continuation493F58 is unconditionally replaced with a jump to
native493C94/epilogue. Earlier destructor work and its opaque success tail are
not executed or certified. No host status oracle chooses the refresh route.

The real1160-byte refresh frame and pure unwind execute. Recreation491E80 and
offset8B43C0 are bounded hostile substitutes; their native caller instructions
run only with deliberately mapped fixture data. No higher callback, caller
coordination, native lifetime, rollback or complete UI behavior is simulated.
"""

from contextlib import contextmanager
import hashlib
import unittest

from build_reveal_bridge_diag import b
import reveal_refresh_failure_gate_mips as core
import reveal_refresh_failure_gate_stage as stage
import test_reveal_delete_release_gate_mips as previous
from test_reveal_delete_release_gate_mips import (
    DeleteReleaseGateMachine, STATE, BIND_STATE, OWNER_STATE, CONTROLLER,
    REGISTRY_MUTEX, PAINT_MUTEX, CODE, LIFECYCLE, QUEUE, TRANSPORT_MUTEX,
    FAULT, RAW_LOCK, RAW_UNLOCK, STACK, RETURN, MASK, NAME, DESTRUCTOR,
    EARLIER_EFFECT_PCS, STAGE_ARGS, _cached_assembler,
    _fixture_assembly_cache as imported_fixture_assembly_cache)
from test_reveal_destructor_continuation_gate_mips import DESTRUCTOR_SLICE
from test_reveal_explorer_failure_gate_mips import NativeReturnBoundary
from test_reveal_constructor_continuation_gate_mips import OUTER_VIEW


REFRESH_SLICE, DESTRUCTOR_ENTRY = 0x4ACD8C, 0x493AC0
RECREATE, OFFSET_SETTER = 0x491E80, 0x8B43C0
SCROLL = OUTER_VIEW + 0x1000
REFRESH_SAVES = {**{register: 0x470 + 4 * (register - 16)
                    for register in range(16, 21)}, 31: 0x484}
_ASSEMBLY_CACHE_MODULES = (*previous._ASSEMBLY_CACHE_MODULES, core, stage)


@contextmanager
def _fixture_assembly_cache(enabled):
    """Cache pure31-module composition only during serial construction."""
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


class RefreshFailureGateMachine(DeleteReleaseGateMachine):
    """Identical bounded destructor/recreation substitutes with or without gate."""

    def __init__(self, image, *, assembly_cache=True, recreate_result=0, **options):
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
                         'delete_release_gate', 'refresh_failure_gate'):
                setattr(self, name + '_labels', self.composition[name + '_labels'])
            self.bridge_labels = self.receipt_labels
            for pc, words in self.composition['coherent_hooks'].items():
                for index, word in enumerate(words):
                    self.patches[pc + index * 4] = word
            self.map(SCROLL, 0x100)
            self.recreate_result = recreate_result
            self.bounded_destructor_entries, self.bounded_destructor_contexts = [], []
            self.recreate_entries, self.offset_entries = [], []
            self.refresh_delay_effects, self.refresh_destructor_delays = [], []
            self.clear_events()

    def word(self, pc):
        # This unconditional bounded substitute is identical for baseline and
        # gated machines. It never inspects or branches on the destructor V0.
        if pc == DESTRUCTOR.CONTINUATION:
            return b.j_type(2, 0x493C94)
        if pc == DESTRUCTOR.CONTINUATION + 4:
            return 0
        return super().word(pc)

    def plain(self, word):
        if hasattr(self, 'refresh_delay_effects'):
            labels = self.refresh_failure_gate_labels
            if (word == core.REFRESH_DELAY and self.current_pc in (
                    core.HOOKS['gate'][0], labels['gate_replay_branch'])):
                self.refresh_delay_effects.append((self.current_pc, self.r[2]))
            if word == 0x02002021 and self.current_pc == REFRESH_SLICE:
                self.refresh_destructor_delays.append((self.current_pc, self.r[16]))
        return super().plain(word)

    def external(self, target):
        if target == DESTRUCTOR_ENTRY:
            self.calls.append(target)
            self.bounded_destructor_entries.append((self.r.copy(), self.hi, self.lo))
            caller_sp, caller, view, controller = self.r[29], self.r[31], self.r[4], self.r[18]
            context = self.seed_destructor(caller_stack=caller_sp, caller=caller,
                                           view=view, controller=controller, name=NAME)
            self.bounded_destructor_contexts.append(context)
            # Both success and denial reach this original caller through the
            # actual native destructor epilogue. No host V0 test picks an exit.
            self.run_at(DESTRUCTOR_SLICE, caller)
            return
        if target in (RECREATE, OFFSET_SETTER):
            self.calls.append(target)
            entry = (tuple(self.r[4:8]), self.r[29], self.r[31])
            if target == RECREATE:
                self.recreate_entries.append(entry)
                self.hostile_result(self.recreate_result)
            else:
                self.offset_entries.append(entry)
                self.hostile_result(0)
            return
        return super().external(target)

    def clear_events(self):
        super().clear_events()
        for name in ('bounded_destructor_entries', 'bounded_destructor_contexts',
                     'recreate_entries', 'offset_entries', 'refresh_delay_effects',
                     'refresh_destructor_delays'):
            if hasattr(self, name):
                getattr(self, name).clear()

    def seed_refresh(self, *, flag=0, caller_stack=STACK, caller=RETURN,
                     controller=CONTROLLER, view=OUTER_VIEW, offset=7):
        """Seed genuine prologue slots; omit the earlier opaque caller body."""
        refresh_sp = caller_stack - core.REFRESH_FRAME
        saved = {register: self.r[register] for register in REFRESH_SAVES}
        saved[31] = caller
        for register, slot in REFRESH_SAVES.items():
            self.put(refresh_sp + slot, saved[register], 4)
        self.put(refresh_sp + 0x464, offset, 4)
        self.put(view + 0xD4, controller, 4)
        self.refresh_context = dict(
            sp=refresh_sp, caller_stack=caller_stack, caller=caller,
            controller=controller, view=view, flag=flag, offset=offset,
            saved=saved, preserved={register: self.r[register]
                                    for register in (*range(21, 24), 28, 30)})
        self.r[29], self.r[31] = refresh_sp, caller
        self.r[16], self.r[17], self.r[18], self.r[20] = (
            view, view + 0x3DD8, controller, flag)
        return self.refresh_context

    def seed_positive_recreation(self, *, view=OUTER_VIEW):
        """Bound only the native offset caller; establish no object ownership."""
        self.recreate_result = view
        self.put(view + 0xCC, SCROLL, 4)
        self.put(view + 0x60, 3, 4)
        self.put(view + 0x4C, 8, 4)
        self.put(SCROLL + 0x10, 0, 4)
        self.put(SCROLL + 0x50, CONTROLLER, 4)

    def run_refresh_slice(self, stop=None):
        if stop is None:
            stop = NativeReturnBoundary(self.refresh_context['caller'], core.FALLTHROUGH)
        self.run_at(REFRESH_SLICE, stop)
        return self.r[2], self.r[3]

    def invoke_refresh_gate(self, *, result=MASK, diagnostic=22, flag=0,
                            controller=CONTROLLER, return_pc=None):
        context = self.seed_refresh(flag=flag, controller=controller)
        self.r[2:4] = result, diagnostic
        self.r[31] = core.HOOKS['gate'][0] if return_pc is None else return_pc
        self.clear_events()
        self.run_at(core.HOOKS['gate'][0], NativeReturnBoundary(
            context['caller'], core.FALLTHROUGH))
        return self.r[2], self.r[3]


class RefreshFailureGateTests(unittest.TestCase):
    setUpClass = classmethod(previous.DeleteReleaseGateTests.setUpClass.__func__)

    def machine(self, **options):
        return RefreshFailureGateMachine(self.image, **options)

    def watch_gate(self, machine):
        snapshots, marks = {}, []

        def observe(current, pc):
            labels = current.refresh_failure_gate_labels
            targets = {'gate': labels['gate'], 'replay': labels['gate_replay'],
                       'epilogue': core.EPILOGUE, 'fallthrough': core.FALLTHROUGH,
                       'destructor_epilogue': DESTRUCTOR.EPILOGUE}
            for name, target in targets.items():
                if pc == target:
                    snapshots[name] = (current.r.copy(), current.hi, current.lo)
                    if name == 'gate':
                        marks.append((len(current.reads), len(current.writes),
                                      len(current.calls), len(current.freed), current.r[29]))

        machine.on_instruction = observe
        return marks, snapshots

    def assert_native_unwind(self, machine, context):
        self.assertEqual((machine.r[29], machine.r[31]),
                         (context['caller_stack'], context['caller']))
        for register, value in {**context['saved'], **context['preserved']}.items():
            self.assertEqual(machine.r[register], value, register)

    def assert_stopped(self, machine, context, marks, snapshots, result=MASK, raw=22):
        self.assertEqual((machine.r[2], machine.r[3]), (result, raw))
        self.assert_native_unwind(machine, context)
        self.assertEqual(snapshots['gate'], snapshots['epilogue'])
        self.assertEqual((machine.hi, machine.lo), snapshots['gate'][1:])
        self.assertIn(machine.refresh_failure_gate_labels['gate_stopped'], machine.trace)
        self.assertNotIn(machine.refresh_failure_gate_labels['gate_forward'], machine.trace)
        self.assertNotIn(machine.refresh_failure_gate_labels['gate_replay'], machine.trace)
        self.assertNotIn(core.FALLTHROUGH, machine.trace)
        self.assertNotIn(0x4ACCE0, machine.trace)
        self.assertNotIn(core.HOOKS['gate'][0] + 4, machine.trace)
        self.assertEqual(machine.recreate_entries, [])
        self.assertEqual(machine.offset_entries, [])
        self.assertEqual(machine.refresh_delay_effects, [])
        self.assertEqual(len(marks), 1)
        reads, writes, calls, freed, refresh_sp = marks[0]
        self.assertEqual(refresh_sp, context['sp'])
        self.assertEqual(machine.calls[calls:], [])
        self.assertEqual(machine.freed[freed:], [])
        first, end = refresh_sp - core.FRAME, context['caller_stack']
        self.assertTrue(all(first <= address and address + size <= end
                            for address, size in machine.reads[reads:]))
        self.assertTrue(all(first <= address and address + size <= end
                            for address, _, size in machine.writes[writes:]))
        self.assertEqual(set(machine.trace) & set(EARLIER_EFFECT_PCS), set())

    def assert_forwarded_boundary(self, machine, context, snapshots):
        self.assertEqual(snapshots['gate'], snapshots['replay'])
        expected, hi, lo = snapshots['gate']
        expected = expected.copy()
        expected[2] = 1
        destination = 'epilogue' if context['flag'] else 'fallthrough'
        if context['flag']:
            self.assertEqual(snapshots[destination], (expected, hi, lo))
            self.assert_native_unwind(machine, context)
        else:
            # The interpreter stops immediately before this reached native PC.
            self.assertEqual((machine.r, machine.hi, machine.lo), (expected, hi, lo))
            self.assertEqual((machine.r[29], machine.r[31]),
                             (context['sp'], snapshots['gate'][0][31]))
        self.assertEqual(machine.refresh_delay_effects,
                         [(machine.refresh_failure_gate_labels['gate_replay_branch'],
                           snapshots['gate'][0][2])])
        self.assertNotIn(core.HOOKS['gate'][0] + 4, machine.trace)
        self.assertNotIn(machine.refresh_failure_gate_labels['gate_stopped'], machine.trace)

    def test_actual_acquisition_denial_survives_both_native_unwinds_and_s4_flags(self):
        for flag in (0, 1):
            with self.subTest(flag=flag):
                m = self.machine(acquire=22)
                context = m.seed_refresh(flag=flag)
                m.clear_events()
                marks, snapshots = self.watch_gate(m)
                self.assertEqual(m.run_refresh_slice(), (MASK, 22))
                self.assert_stopped(m, context, marks, snapshots)
                self.assertIn(m.acquire_gate_labels['delete_gate_denied'], m.trace)
                self.assertIn(DESTRUCTOR.EPILOGUE, m.trace)
                self.assertEqual([(event[0], event[1], event[-1]) for event in m.raw_events],
                                 [(RAW_LOCK, REGISTRY_MUTEX, 22)])
                self.assertEqual(m.resource_entries, [])
                self.assertEqual(m.freed, [])

    def test_actual_release_error_reaches_refresh_before_forced_success_delay(self):
        for flag in (0, 1):
            with self.subTest(flag=flag):
                m = self.machine(release=0x82, registry_release_failure_releases=False)
                context = m.seed_refresh(flag=flag)
                m.clear_events()
                marks, snapshots = self.watch_gate(m)
                self.assertEqual(m.run_refresh_slice(), (MASK, 0x82))
                self.assert_stopped(m, context, marks, snapshots, raw=0x82)
                self.assertTrue(m.registry_held)
                self.assertEqual([(event[0], event[1], event[-1]) for event in m.raw_events],
                                 [(RAW_LOCK, REGISTRY_MUTEX, 0),
                                  (RAW_UNLOCK, REGISTRY_MUTEX, 0x82)])
                self.assertEqual(m.resource_entries, [])

    def test_zero_results_replay_branch_delay_once_with_exact_previous_architecture(self):
        for flag in (0, 1):
            with self.subTest(flag=flag):
                m, old = self.machine(), self.machine()
                context = m.seed_refresh(flag=flag)
                old.seed_refresh(flag=flag)
                old.remove_pair(core.HOOKS['gate'][0])
                for current in (m, old):
                    current.clear_events()
                _, snapshots = self.watch_gate(m)
                self.assertEqual(m.run_refresh_slice(), old.run_refresh_slice())
                self.assert_forwarded_boundary(m, context, snapshots)
                self.assertEqual((m.r, m.hi, m.lo), (old.r, old.hi, old.lo))
                self.assertEqual(m.raw_events, old.raw_events)
                self.assertEqual(m.resource_entries, old.resource_entries)
                self.assertEqual(old.refresh_delay_effects, [(0x4ACD94, 0)])
                self.assertEqual(m.recreate_entries, [])
                self.assertEqual(m.offset_entries, [])
                self.assertEqual(len(m.resource_entries), 1)
                self.assertIn(0x493C94, m.trace)

    def test_zero_fallthrough_executes_native_recreation_call_and_null_unwind(self):
        m, old = self.machine(), self.machine()
        context = m.seed_refresh(flag=0)
        old.seed_refresh(flag=0)
        old.remove_pair(core.HOOKS['gate'][0])
        for current in (m, old):
            current.clear_events()
        self.assertEqual(m.run_refresh_slice(RETURN), old.run_refresh_slice(RETURN))
        self.assert_native_unwind(m, context)
        self.assertEqual((m.r, m.hi, m.lo), (old.r, old.hi, old.lo))
        self.assertEqual(m.recreate_entries, old.recreate_entries)
        self.assertEqual(len(m.recreate_entries), 1)
        arguments, refresh_sp, caller = m.recreate_entries[0]
        self.assertEqual(arguments[:3], (CONTROLLER, context['sp'] + 0x420,
                                        context['sp'] + 0x20))
        self.assertEqual((refresh_sp, caller), (context['sp'], 0x4ACDAC))
        self.assertEqual(m.offset_entries, [])
        self.assertEqual((m.r[2], m.r[3]), (0, context['offset']))

    def test_mapped_positive_recreation_runs_one_native_offset_caller_with_previous_abi(self):
        m, old = self.machine(), self.machine()
        context = m.seed_refresh(flag=0)
        old.seed_refresh(flag=0)
        old.remove_pair(core.HOOKS['gate'][0])
        for current in (m, old):
            current.seed_positive_recreation()
            current.clear_events()
        self.assertEqual(m.run_refresh_slice(RETURN), old.run_refresh_slice(RETURN))
        self.assert_native_unwind(m, context)
        self.assertEqual((m.r, m.hi, m.lo), (old.r, old.hi, old.lo))
        self.assertEqual(m.recreate_entries, old.recreate_entries)
        self.assertEqual(m.offset_entries, old.offset_entries)
        self.assertEqual(len(m.recreate_entries), 1)
        self.assertEqual(m.offset_entries,
                         [((SCROLL, context['sp'] + 0x460, 0, 0x20002),
                           context['sp'], 0x4ACDF8)])
        self.assertEqual(m.words_at(context['sp'] + 0x464, 1), (0,))

    def test_populated_delete_error_keeps_earlier_unlink_and_free_before_refresh_stop(self):
        m = self.machine()
        self.assertEqual(m.register(), 0)
        node = m.allocations[-1]
        m.release = 22
        context = m.seed_refresh()
        m.clear_events()
        marks, snapshots = self.watch_gate(m)
        self.assertEqual(m.run_refresh_slice(), (MASK, 22))
        self.assert_stopped(m, context, marks, snapshots)
        self.assertIn(node, m.freed)
        self.assertEqual(m.words_at(CONTROLLER + 0x34, 2), (CONTROLLER + 0x34,) * 2)
        self.assertEqual(len(m.lifecycle_requests), 1)
        self.assertTrue(m.cleanup_services)
        self.assertEqual(m.resource_entries, [])

    def test_gate_snapshot_restores_all_thirty_gprs_hilo_before_native_unwind(self):
        m = self.machine()
        marks, snapshots = self.watch_gate(m)
        self.assertEqual(m.invoke_refresh_gate(result=0x80000001, diagnostic=0x12345678),
                         (0x80000001, 0x12345678))
        self.assert_stopped(m, m.refresh_context, marks, snapshots,
                            result=0x80000001, raw=0x12345678)
        self.assertEqual(len(core.SAVE), 30)
        private = m.refresh_context['sp'] - core.FRAME
        for register, offset in core.SAVE.items():
            self.assertEqual(m.words_at(private + offset, 1)[0],
                             snapshots['gate'][0][register], register)
        self.assertEqual(m.words_at(private + core.HI, 2), snapshots['gate'][1:])
        self.assertEqual(m.bounded_destructor_entries, [])

    def test_bounded_destructor_preserves_real_caller_callee_slots_sp_ra_and_delay(self):
        m = self.machine(release=22)
        context = m.seed_refresh(flag=1)
        m.clear_events()
        _, snapshots = self.watch_gate(m)
        m.run_refresh_slice()
        self.assertEqual(len(m.bounded_destructor_entries), 1)
        entry, _, _ = m.bounded_destructor_entries[0]
        self.assertEqual((entry[4], entry[29], entry[31]),
                         (context['view'], context['sp'], 0x4ACD94))
        child = m.bounded_destructor_contexts[0]
        self.assertEqual((child['sp'], child['caller_stack'], child['caller']),
                         (context['sp'] - DESTRUCTOR.DESTRUCTOR_FRAME,
                          context['sp'], 0x4ACD94))
        for register, value in child['saved'].items():
            self.assertEqual(snapshots['gate'][0][register], value, register)
        self.assertEqual((snapshots['gate'][0][18], snapshots['gate'][0][31]),
                         (CONTROLLER, 0x4ACD94))
        self.assertEqual(m.refresh_destructor_delays, [(REFRESH_SLICE, context['view'])])
        self.assertNotIn(DESTRUCTOR_ENTRY, m.trace)
        self.assertIn(DESTRUCTOR_SLICE, m.trace)
        self.assertEqual(m.calls.count(DESTRUCTOR_ENTRY), 1)
        self.assertEqual(m.raw_events[-1],
                         (RAW_UNLOCK, REGISTRY_MUTEX, child['sp'] - 64, 0x466DD0, 22))

    def test_cache_keeps_identical_bytes_fresh_metadata_state_and_restores_functions(self):
        originals = {module: module.assemble for module in _ASSEMBLY_CACHE_MODULES}
        uncached = self.machine(acquire=22, assembly_cache=False)
        cached = self.machine(acquire=22)
        self.assertEqual(cached.code, uncached.code)
        self.assertEqual(hashlib.sha256(cached.code).digest(), hashlib.sha256(uncached.code).digest())
        self.assertEqual(len(cached.code), 92444)
        self.assertEqual(hashlib.sha256(cached.code).hexdigest(),
                         '88c32e213641ce6731c4e6eeef00f7fbf2487cef4976d061e27ec1c682e46d85')
        tail = cached.composition['refresh_failure_gate_code_bytes']
        guarded_parent = previous.stage.assemble(*STAGE_ARGS, following_code_bytes=tail)
        self.assertEqual(cached.code[:91940], guarded_parent['code'])
        self.assertEqual(cached.composition['refresh_failure_gate_prefix_code_bytes'], 91940)
        self.assertEqual(len(cached.code), 91940 + tail)
        self.assertIsNot(cached.composition, uncached.composition)
        self.assertIsNot(cached.refresh_failure_gate_labels, uncached.refresh_failure_gate_labels)
        for current in (cached, uncached):
            current.seed_refresh()
            current.clear_events()
        self.assertEqual(cached.run_refresh_slice(), uncached.run_refresh_slice())
        self.assertEqual((cached.r, cached.hi, cached.lo), (uncached.r, uncached.hi, uncached.lo))
        cached.refresh_failure_gate_labels['host_only_cache_probe'] = 123
        cached.registry_held = True
        fresh = self.machine()
        self.assertNotIn('host_only_cache_probe', fresh.refresh_failure_gate_labels)
        self.assertFalse(fresh.registry_held)
        self.assertEqual(fresh.raw_events, [])
        fresh.seed_refresh(flag=1)
        fresh.clear_events()
        self.assertEqual(fresh.run_refresh_slice()[0], 1)
        self.assertEqual(cached.recreate_entries, [])
        with self.assertRaises(ValueError):
            self.machine(capacity=True)
        for module, original in originals.items():
            self.assertIs(module.assemble, original, module.__name__)


if __name__ == '__main__':
    unittest.main()
