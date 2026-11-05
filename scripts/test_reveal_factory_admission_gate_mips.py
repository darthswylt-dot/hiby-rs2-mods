#!/usr/bin/env python3
"""Execute bounded admission to47D720 and its actual native return paths.

Actual factory prologue, NULL checks, lookup dispatch, existing-result path
and both F568 epilogues execute. Lookup is a bounded hostile-ABI service.
An explicit fixed PC cut at47D78C supplies a created H and jumps to47D8F0,
identically with/without the new hooks. Registration, initializer, view update
and startup are bounded services, not allocation/publication/thread proofs.
No host V0 decision selects an emitted admission or exit route.

The complete composed bytes include all preceding coherent hooks. Only43
unchanged parent assemblers are memoized; the two new assemblers stay
unwrapped. Native execution state/results are never cached. Q-only epochs
and deterministic separate-stack interleavings model emitted instructions,
not hardware cache ordering, arbitrary callers or native scheduling.
"""

from contextlib import contextmanager
import hashlib
from pathlib import Path
import unittest

from build_reveal_bridge_diag import b
import reveal_factory_admission_gate_mips as core
import reveal_factory_admission_gate_stage as stage
import reveal_worker_terminal_tail_mips as worker_core
import reveal_worker_terminal_tail_stage as worker_stage
import test_reveal_dialog_retention_gate_mips as previous


IMAGE = Path(__file__).resolve().parents[1] / 'artifacts/import-20261001/hiby_player_02fd.bin'
SOURCE_SHA256 = '02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87'
STAGE_ARGS = previous.STAGE_ARGS
GUARD, STACK, SECOND_STACK, RETURN, MASK = (
    previous.GUARD, previous.STACK, previous.SECOND_STACK, previous.RETURN, previous.MASK)
NAME, CONTROLLER, DIALOG, OPERATION = (
    previous.NAME, previous.CONTROLLER, previous.DIALOG, previous.OPERATION)
ENTRY, ENTER_RESUME, CREATED_CUT, CREATED_RESUME = 0x47D720, 0x47D728, 0x47D78C, 0x47D8F0
LOOKUP, REGISTER, INITIALIZER, VIEW_UPDATE, STARTUP = (
    0x47CA40, 0x47C9E0, 0x6000040, 0x43BD00, 0x47C840)
EARLY_LEAVE, CREATED_LEAVE = 0x47D77C, 0x47D93C
FREE = 0x466A80
_ASSEMBLY_CACHE_MODULES = (*previous._ASSEMBLY_CACHE_MODULES, worker_core, worker_stage)


@contextmanager
def _fixture_assembly_cache(enabled=True):
    """Cache43 unchanged pure parents, never the new core/stage or execution."""
    originals = []
    with previous._fixture_assembly_cache(enabled):
        try:
            if enabled:
                for module in (worker_core, worker_stage):
                    original = module.assemble
                    originals.append((module, original))
                    module.assemble = previous._cached_assembler(original)
            yield
        finally:
            for module, original in reversed(originals):
                module.assemble = original


class FactoryAdmissionGateMachine(previous.DialogRetentionGateMachine):
    def __init__(self, image, *, retry_limit=8, hooked=True, lookup_mode='existing'):
        if lookup_mode not in ('existing', 'created'):
            raise ValueError('unknown bounded factory fixture mode')
        with _fixture_assembly_cache():
            super().__init__(image, assembly_cache=False, retry_limit=retry_limit)
            composition = stage.assemble(
                *STAGE_ARGS, guard_address=GUARD, retry_limit=retry_limit,
                transport_capacity=self.peek(previous.QUEUE + 8))
        self.composition = composition
        self.code = self.code_bytes = composition['code']
        self.labels = composition['labels']
        for name, labels in composition.items():
            if name.endswith('_labels'):
                setattr(self, name, labels)
        for pc, pair in composition['coherent_hooks'].items():
            for index, word in enumerate(pair):
                self.patches[pc + index * 4] = word
        if not hooked:
            self.remove_factory_hooks()
        self.lookup_mode = lookup_mode
        self.factory_events, self.created_cuts = [], []
        self.on_factory_service = None
        self.factory_context = None
        self.put(DIALOG + 0x70, INITIALIZER, 4)
        self.put(DIALOG + 0x4C, OPERATION, 4)
        self.clear_events()

    def remove_factory_hooks(self):
        for pc, pair in core.HOOKS.values():
            self.remove_pair(pc)

    def word(self, pc):
        if pc == CREATED_CUT:
            return b.j_type(2, CREATED_RESUME)
        if pc == CREATED_CUT + 4:
            return 0
        return super().word(pc)

    def instruction(self, pc):
        super().instruction(pc)
        if pc == CREATED_CUT:
            # This fixed substitute is reached only by the native lookup-miss
            # branch. It neither examines host V0 nor chooses an exit from it.
            # Actual allocation, graph construction and publication are not run.
            self.created_cuts.append((pc, self.r[29]))
            self.put(self.r[29] + 0x218, DIALOG, 4)
            self.r[4], self.r[3], self.r[2] = self.r[29] + 0x218, DIALOG, 0x47C740

    def external(self, target):
        if target == ENTRY:
            # Used by the two real caller JAL sites. Preserve actual RA/SP,
            # then let the enclosing interpreter execute their continuations.
            self.calls.append(target)
            caller = self.r[31]
            self.run_at(target, caller)
            return
        if target in (LOOKUP, REGISTER, INITIALIZER, VIEW_UPDATE, STARTUP):
            self.calls.append(target)
            self.factory_events.append((target, tuple(self.r[4:8]), self.r[29],
                                        self.r[31], self.guard_value()))
            if target == LOOKUP:
                found = self.lookup_mode == 'existing'
                self.put(self.r[5], DIALOG if found else 0, 4)
                result = int(found)
            else:
                result = 0
            if self.on_factory_service is not None:
                self.on_factory_service(self, target)
            self.hostile_result(result)
            return
        return super().external(target)

    def clear_events(self):
        super().clear_events()
        for name in ('factory_events', 'created_cuts'):
            if hasattr(self, name):
                getattr(self, name).clear()

    def run_factory(self, *, stack=STACK, caller=RETURN, name=NAME,
                    controller=CONTROLLER, stop=None):
        self.r[29], self.r[31] = stack, caller
        self.r[4:8] = (name, controller, 2000, 0)
        self.factory_context = dict(stack=stack, caller=caller,
                                    registers=self.r.copy(), hi=self.hi, lo=self.lo)
        self.run_at(ENTRY, caller if stop is None else stop)
        return self.r[2], self.r[3]


class FactoryAdmissionGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = IMAGE.read_bytes()
        if len(cls.image) != 7133528 or hashlib.sha256(cls.image).hexdigest() != SOURCE_SHA256:
            raise AssertionError('factory fixture requires the preserved 02fd source')
        cls._original_parents = tuple((module, module.assemble)
                                      for module in _ASSEMBLY_CACHE_MODULES)
        cls._new_assemblers = core.assemble, stage.assemble
        cls._parent_cache = _fixture_assembly_cache()
        cls._parent_cache.__enter__()
        cls.addClassCleanup(cls._restore_parent_cache)

    @classmethod
    def _restore_parent_cache(cls):
        try:
            cls._parent_cache.__exit__(None, None, None)
        finally:
            for module, original in cls._original_parents:
                if module.assemble is not original:
                    raise AssertionError('unrestored factory parent: ' + module.__name__)
            if (core.assemble is not cls._new_assemblers[0]
                    or stage.assemble is not cls._new_assemblers[1]):
                raise AssertionError('factory core/stage was wrapped')

    def machine(self, **options):
        return FactoryAdmissionGateMachine(self.image, **options)

    def assert_native_restoration(self, machine, *, stack=STACK, caller=RETURN):
        self.assertEqual((machine.r[29], machine.r[31]), (stack, caller))
        context = machine.factory_context
        for register in (*range(16, 24), 28, 30):
            self.assertEqual(machine.r[register], context['registers'][register], register)

    def assert_refused(self, machine, *, stack=STACK):
        self.assertEqual((machine.r[2], machine.r[3]), (0, 0))
        self.assert_native_restoration(machine, stack=stack)
        self.assertEqual(machine.factory_events, [])
        self.assertEqual(machine.created_cuts, [])
        self.assertEqual(machine.calls, [])
        self.assertNotIn(ENTER_RESUME, machine.trace)
        self.assertTrue(all(address == GUARD or stack - core.FRAME <= address
                            and address + size <= stack
                            for address, size in machine.reads))

    def test_entry_preserves_actual_inputs_hi_lo_and_stamps_unused_native_padding(self):
        machine = self.machine()
        machine.clear_events()
        machine.run_factory(stop=ENTER_RESUME)
        before = machine.factory_context['registers'].copy()
        before[29] -= core.FACTORY_FRAME
        self.assertEqual((machine.r, machine.hi, machine.lo),
                         (before, machine.factory_context['hi'], machine.factory_context['lo']))
        self.assertEqual(machine.words_at(machine.r[29] + core.OWNER, 1), (core.OWNERSTAMP,))
        self.assertEqual(machine.words_at(machine.r[29] + 0x234, 1), (RETURN,))
        self.assertEqual(machine.guard_value(), core.BUSY)
        self.assertEqual(machine.factory_events, [])
        self.assertEqual(machine.r[29] + core.OWNER,
                         STACK - core.FRAME + core.FUTURE_OWNER)

    def test_busy_quarantine_and_unknown_states_refuse_before_native_inputs_or_lookup(self):
        for state in (core.BUSY, core.QUARANTINED, 3, MASK):
            with self.subTest(state=state):
                machine = self.machine()
                machine.put(GUARD, state, 4)
                machine.clear_events()
                machine.run_factory(name=0xDEAD0000, controller=0xDEAD0004)
                self.assert_refused(machine)
                self.assertEqual(machine.guard_value(), state)
                self.assertEqual(machine.guard_atomic_events[0][0], 'll')
                self.assertFalse(any(event[0] == 'sc' for event in machine.guard_atomic_events))

    def test_entry_sc_exhaustion_is_bounded_without_claim_or_native_frame(self):
        machine = self.machine(retry_limit=2)
        machine.guard_sc_failures = 2
        machine.clear_events()
        machine.run_factory()
        self.assert_refused(machine)
        self.assertEqual(machine.guard_value(), core.READY)
        self.assertEqual(sum(event[0] == 'sc' for event in machine.guard_atomic_events), 2)

    def test_existing_result_runs_native_lookup_and_early_exit_once(self):
        native, machine = self.machine(hooked=False), self.machine()
        native.clear_events()
        machine.clear_events()
        native.run_factory()
        machine.run_factory()
        self.assertEqual((machine.r, machine.hi, machine.lo), (native.r, native.hi, native.lo))
        self.assertEqual(machine.r[2], DIALOG)
        self.assert_native_restoration(machine)
        self.assertEqual([event[0] for event in machine.factory_events], [LOOKUP])
        self.assertEqual(machine.factory_events[0][1], (NAME, STACK - 568 + 0x214, 2000, 0))
        self.assertEqual(machine.factory_events[0][4], core.BUSY)
        self.assertIn(EARLY_LEAVE, machine.trace)
        self.assertNotIn(CREATED_LEAVE, machine.trace)
        self.assertEqual(machine.guard_value(), core.READY)
        self.assertEqual(machine.words_at(STACK - 568 + core.OWNER, 1), (0,))

    def test_native_null_argument_branches_keep_results_without_lookup(self):
        for options in ({'name': 0}, {'controller': 0}):
            with self.subTest(options=options):
                native, machine = self.machine(hooked=False), self.machine()
                native.clear_events()
                machine.clear_events()
                native.run_factory(**options)
                machine.run_factory(**options)
                self.assertEqual((machine.r, machine.hi, machine.lo), (native.r, native.hi, native.lo))
                self.assertEqual(machine.r[2], 0)
                self.assertEqual(machine.factory_events, [])
                self.assertIn(EARLY_LEAVE, machine.trace)
                self.assertEqual(machine.guard_value(), core.READY)
                self.assert_native_restoration(machine)

    def test_created_slice_keeps_the_claim_through_initializer_and_startup_return(self):
        native = self.machine(hooked=False, lookup_mode='created')
        machine = self.machine(lookup_mode='created')
        native.clear_events()
        machine.clear_events()
        native.run_factory()
        machine.run_factory()
        self.assertEqual((machine.r, machine.hi, machine.lo), (native.r, native.hi, native.lo))
        self.assertEqual(machine.r[2], DIALOG)
        self.assert_native_restoration(machine)
        self.assertEqual([event[0] for event in machine.factory_events],
                         [LOOKUP, REGISTER, INITIALIZER, VIEW_UPDATE, STARTUP])
        self.assertTrue(all(event[4] == core.BUSY for event in machine.factory_events))
        self.assertEqual(machine.created_cuts, [(CREATED_CUT, STACK - 568)])
        self.assertEqual(machine.guard_value(), core.READY)
        self.assertIn(CREATED_LEAVE, machine.trace)
        self.assertNotIn(EARLY_LEAVE, machine.trace)
        self.assertEqual(machine.words_at(DIALOG + 0x6C, 1), (0x47C740,))
        self.assertEqual(machine.words_at(DIALOG + 0x48, 1), (CONTROLLER,))

    def test_nested_factory_and_existing_poll_cannot_borrow_the_factory_claim(self):
        owner, nested = self.machine(), self.machine()
        nested.attach_shared(owner)
        attempts = []

        def reenter(current, target):
            if target == LOOKUP:
                nested.clear_events()
                nested.run_factory(stack=SECOND_STACK)
                self.assert_refused(nested, stack=SECOND_STACK)
                nested.clear_events()
                nested.run_outer('poll', stack=SECOND_STACK)
                self.assertEqual((nested.r[2], nested.r[3]), (MASK, 0))
                self.assertEqual(nested.list_events, [])
                self.assertEqual(nested.outer_dialog_entries, [])
                self.assertEqual(nested.calls, [])
                attempts.append(current.guard_value())

        owner.on_factory_service = reenter
        owner.clear_events()
        owner.run_factory()
        self.assertEqual(attempts, [core.BUSY])
        self.assertEqual(owner.guard_value(), core.READY)
        self.assertEqual(owner.r[2], DIALOG)

    def test_shared_competing_entry_invalidates_the_first_reservation(self):
        first, second = self.machine(), self.machine()
        second.attach_shared(first)
        injected = []

        def interleave(current, pc):
            if not injected and previous.guard_instruction(current, pc, 0x38):
                injected.append(pc)
                second.clear_events()
                second.run_factory(stack=SECOND_STACK, stop=ENTER_RESUME)

        first.on_instruction = interleave
        first.clear_events()
        first.run_factory()
        self.assertEqual(len(injected), 1)
        self.assert_refused(first)
        self.assertEqual(second.guard_value(), core.BUSY)
        self.assertEqual(second.r[29], SECOND_STACK - 568)
        self.assertTrue(any(event[0] == 'sc' and not event[3]
                            for event in first.guard_atomic_events))

    def test_error_published_during_factory_preserves_result_and_terminal_quarantine(self):
        for mode in ('existing', 'created'):
            with self.subTest(mode=mode):
                machine = self.machine(lookup_mode=mode)
                fault_service = INITIALIZER if mode == 'created' else LOOKUP

                def fault(current, target):
                    if target == fault_service:
                        current.put(GUARD, core.QUARANTINED, 4)

                machine.on_factory_service = fault
                machine.clear_events()
                machine.run_factory()
                self.assertEqual(machine.r[2], DIALOG)
                self.assertEqual(machine.guard_value(), core.QUARANTINED)
                self.assert_native_restoration(machine)
                if mode == 'created':
                    startup = [event for event in machine.factory_events if event[0] == STARTUP]
                    self.assertEqual(len(startup), 1)
                    self.assertEqual(startup[0][4], core.QUARANTINED)
                # This external fault injection deliberately lies outside
                # serialized genuine consumer entry. It cannot undo the body.
                machine.clear_events()
                machine.on_factory_service = None
                machine.run_factory()
                self.assert_refused(machine)
                self.assertEqual(machine.guard_value(), core.QUARANTINED)

    def test_fault_between_leave_ll_sc_is_never_reopened(self):
        machine, fault = self.machine(), self.machine()
        fault.attach_shared(machine)
        injected = []

        def interleave(current, pc):
            if (current.factory_events and not injected
                    and previous.guard_instruction(current, pc, 0x38)):
                injected.append(len(current.writes))
                fault.put(GUARD, core.QUARANTINED, 4)

        machine.on_instruction = interleave
        machine.clear_events()
        machine.run_factory()
        self.assertEqual(len(injected), 1)
        self.assertEqual(machine.r[2], DIALOG)
        self.assertEqual(machine.guard_value(), core.QUARANTINED)
        self.assertFalse(any(address == GUARD and value == core.READY
                             for address, value, size in machine.writes[injected[0]:]))
        self.assertTrue(any(event[0] == 'sc' and not event[3]
                            for event in machine.guard_atomic_events))

    def test_leave_sc_exhaustion_quarantines_without_faking_factory_failure(self):
        for mode, tail in (('existing', EARLY_LEAVE), ('created', CREATED_LEAVE)):
            with self.subTest(mode=mode):
                machine = self.machine(retry_limit=2, lookup_mode=mode)

                def fail_release(current, pc):
                    if pc == tail:
                        current.guard_sc_failures = 2

                machine.on_instruction = fail_release
                machine.clear_events()
                machine.run_factory()
                self.assertEqual(machine.r[2], DIALOG)
                self.assertEqual(machine.guard_value(), core.QUARANTINED)
                self.assert_native_restoration(machine)
                self.assertEqual(machine.freed, [])

    def test_missing_current_frame_stamp_cannot_release_another_owner(self):
        for mode, tail in (('existing', EARLY_LEAVE), ('created', CREATED_LEAVE)):
            with self.subTest(mode=mode):
                machine = self.machine(lookup_mode=mode)
                marks = []

                def erase_stamp(current, pc):
                    if pc == tail:
                        current.put(current.r[29] + core.OWNER, 0, 4)
                        marks.append((len(current.reads), len(current.writes)))

                machine.on_instruction = erase_stamp
                machine.clear_events()
                machine.run_factory()
                self.assertEqual(len(marks), 1)
                reads, writes = marks[0]
                self.assertNotIn((GUARD, 4), machine.reads[reads:])
                self.assertFalse(any(address == GUARD for address, value, size in machine.writes[writes:]))
                self.assertEqual(machine.guard_value(), core.BUSY)
                self.assertEqual(machine.r[2], DIALOG)
                self.assert_native_restoration(machine)

    def test_missing_entry_hook_restores_lookup_while_quarantined(self):
        machine = self.machine()
        machine.remove_pair(ENTRY)
        machine.put(GUARD, core.QUARANTINED, 4)
        machine.clear_events()
        machine.run_factory()
        self.assertEqual([event[0] for event in machine.factory_events], [LOOKUP])
        self.assertEqual(machine.r[2], DIALOG)
        self.assertEqual(machine.guard_value(), core.QUARANTINED)
        self.assertNotIn(machine.factory_admission_gate_labels['enter'], machine.trace)

    def test_other_factories_remain_outside_this_gate(self):
        machine = self.machine()
        machine.put(GUARD, core.QUARANTINED, 4)
        for pc in (0x47D180, 0x47D4A0, 0x47D960, 0x47DCE0):
            self.assertNotIn(pc, machine.composition['coherent_hooks'])
        machine.r[29], machine.r[31] = STACK, RETURN
        machine.run_at(0x47D4A0, 0x47D4A8)
        self.assertEqual(machine.r[29], STACK - 568)
        self.assertEqual(machine.guard_value(), core.QUARANTINED)

    def test_checked_selection_caller_uses_real_null_return_then_overwrites_result(self):
        machine = self.machine()
        caller_sp = STACK - 568
        caller_saved = {16: 0x51000010, 17: 0x51000011, 18: 0x51000012, 31: RETURN}
        for register, offset in ((16, 0x228), (17, 0x22C), (18, 0x230), (31, 0x234)):
            machine.put(caller_sp + offset, caller_saved[register], 4)
        machine.r[29], machine.r[4], machine.r[5], machine.r[6] = (
            caller_sp, NAME, CONTROLLER, 0)
        machine.put(GUARD, core.QUARANTINED, 4)
        machine.clear_events()
        machine.run_at(0x4A4EAC, RETURN)
        self.assertEqual((machine.r[29], machine.r[31], machine.r[2]), (STACK, RETURN, 1))
        for register in (16, 17, 18):
            self.assertEqual(machine.r[register], caller_saved[register])
        self.assertEqual(machine.calls, [ENTRY])
        self.assertEqual(machine.factory_events, [])
        self.assertIn(0x4A4EB4, machine.trace)
        self.assertIn(0x4A4A24, machine.trace)
        self.assertEqual(machine.guard_value(), core.QUARANTINED)

    def test_checked_cleanup_caller_discards_null_and_frees_its_prior_context(self):
        machine = self.machine()
        caller_sp = STACK - 40
        caller_saved = {16: 0x52000010, 17: 0x52000011, 31: RETURN}
        for register, offset in ((16, 0x1C), (17, 0x20), (31, 0x24)):
            machine.put(caller_sp + offset, caller_saved[register], 4)
        machine.r[29], machine.r[16], machine.r[4], machine.r[5], machine.r[6] = (
            caller_sp, DIALOG, NAME, CONTROLLER, 2000)
        machine.put(DIALOG + 0x58, OPERATION, 4)
        machine.put(GUARD, core.QUARANTINED, 4)
        machine.clear_events()
        machine.run_at(0x4EC450, RETURN)
        self.assertEqual((machine.r[29], machine.r[31]), (STACK, RETURN))
        self.assertEqual((machine.r[16], machine.r[17]), (caller_saved[16], caller_saved[17]))
        self.assertEqual(machine.calls, [ENTRY, FREE])
        self.assertEqual(machine.factory_events, [])
        self.assertEqual(machine.freed, [OPERATION])
        self.assertEqual(machine.words_at(DIALOG + 0x58, 1), (0,))
        self.assertIn(0x4EC458, machine.trace)
        self.assertEqual(machine.guard_value(), core.QUARANTINED)


if __name__ == '__main__':
    unittest.main()
