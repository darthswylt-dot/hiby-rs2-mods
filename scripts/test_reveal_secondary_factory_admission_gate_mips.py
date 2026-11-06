#!/usr/bin/env python3
"""Execute47D4A0 admission, its checked wrapper and upper continuation.

The actual secondary factory entry, incoming fifth-argument load, NULL check,
lookup and both F568 returns execute. A fixed cut47D508->47D69C supplies a
created H identically with/without the secondary hooks; allocation and graph
construction remain opaque. Registration/initializer/view/startup and wrapper
UI services are explicit hostile-ABI substitutes, not thread/lifetime proofs.

Actual4F8760 instructions and the sole upper JAL4A326C execute. The upper F56
frame is supplied before that call rather than running its earlier widget
logic. Separate-stack Q interleavings use the inherited shared epoch model;
they do not model target cache ordering or arbitrary computed callers.
Only45 public parent assemblers are memoized. Their default emission remains
unchanged after the shared-emitter refactor. The two new public
functions and the shared private emitter stay unwrapped; CPU/service outcomes
and execution state are never cached.
"""

from contextlib import contextmanager
import hashlib
import unittest

from build_reveal_bridge_diag import b
import reveal_secondary_factory_admission_gate_mips as core
import reveal_secondary_factory_admission_gate_stage as stage
import test_reveal_factory_admission_gate_mips as previous
from test_reveal_dialog_retention_gate_mips import _cached_assembler, guard_instruction


IMAGE, SOURCE_SHA256, STAGE_ARGS = previous.IMAGE, previous.SOURCE_SHA256, previous.STAGE_ARGS
GUARD, STACK, SECOND_STACK, RETURN, MASK = (
    previous.GUARD, previous.STACK, previous.SECOND_STACK, previous.RETURN, previous.MASK)
NAME, CONTROLLER, DIALOG, OPERATION = (
    previous.NAME, previous.CONTROLLER, previous.DIALOG, previous.OPERATION)
LOOKUP, REGISTER, INITIALIZER, VIEW_UPDATE, STARTUP = (
    previous.LOOKUP, previous.REGISTER, previous.INITIALIZER, previous.VIEW_UPDATE, previous.STARTUP)
ENTRY, ENTER_RESUME, CREATED_CUT, CREATED_RESUME = 0x47D4A0, 0x47D4A8, 0x47D508, 0x47D69C
EARLY_LEAVE, CREATED_LEAVE = 0x47D4F8, 0x47D6E8
WRAPPER, UPPER_CALL = 0x4F8760, 0x4A326C
UI_START, UI_FLAG, UPPER_UI, UPPER_CLOSE = 0x4771A0, 0x477180, 0x477600, 0x469180
BB1C, BB20, WIDGET, WIDGET_CONTEXT = 0xB8BB1C, 0xB8BB20, 0x1D06000, 0x1D06100
FLAG = 0x1D05000
_ASSEMBLY_CACHE_MODULES = (*previous._ASSEMBLY_CACHE_MODULES, previous.core, previous.stage)


@contextmanager
def _fixture_assembly_cache(enabled=True):
    """Cache45 public parents without wrapping the shared private emitter."""
    originals = []
    with previous._fixture_assembly_cache(enabled):
        try:
            if enabled:
                for module in (previous.core, previous.stage):
                    original = module.assemble
                    originals.append((module, original))
                    module.assemble = _cached_assembler(original)
            yield
        finally:
            for module, original in reversed(originals):
                module.assemble = original


class SecondaryFactoryAdmissionGateMachine(previous.FactoryAdmissionGateMachine):
    def __init__(self, image, *, retry_limit=8, hooked=True, lookup_mode='existing'):
        with _fixture_assembly_cache():
            super().__init__(image, retry_limit=retry_limit, lookup_mode=lookup_mode)
            composition = stage.assemble(
                *STAGE_ARGS, guard_address=GUARD, retry_limit=retry_limit,
                transport_capacity=self.peek(previous.previous.QUEUE + 8))
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
            self.remove_secondary_hooks()
        self.wrapper_events = []
        self.map(BB1C, 4)
        self.map(BB20, 4)
        self.map(FLAG, 4)
        self.map(WIDGET, 0x100)
        self.map(WIDGET_CONTEXT, 0x100)
        self.put(WIDGET + 0xCC, WIDGET_CONTEXT, 4)
        self.put(WIDGET + 0xD4, CONTROLLER, 4)
        self.put(WIDGET_CONTEXT + 0x38, 0x13579BDF, 4)
        self.clear_events()

    def remove_secondary_hooks(self):
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
            self.created_cuts.append((pc, self.r[29]))
            self.put(self.r[29] + 0x218, DIALOG, 4)
            self.r[4], self.r[3], self.r[2] = self.r[29] + 0x218, DIALOG, 0x47C740

    def external(self, target):
        if target in (ENTRY, WRAPPER):
            self.calls.append(target)
            caller = self.r[31]
            self.run_at(target, caller)
            return
        if target in (UI_START, UI_FLAG, UPPER_UI, UPPER_CLOSE):
            self.calls.append(target)
            self.wrapper_events.append((target, tuple(self.r[4:8]), self.r[29],
                                        self.r[31], self.guard_value()))
            self.hostile_result(0)
            return
        return super().external(target)

    def clear_events(self):
        super().clear_events()
        if hasattr(self, 'wrapper_events'):
            self.wrapper_events.clear()

    def run_secondary(self, *, stack=STACK, caller=RETURN, name=NAME,
                      controller=CONTROLLER, fifth=OPERATION, sixth=0x13579BDF,
                      stop=None):
        self.put(stack + 0x10, fifth, 4)
        self.put(stack + 0x14, sixth, 4)
        self.r[29], self.r[31] = stack, caller
        self.r[4:8] = (name, 0, controller, 2000)
        self.factory_context = dict(stack=stack, caller=caller,
                                    registers=self.r.copy(), hi=self.hi, lo=self.lo)
        self.run_at(ENTRY, caller if stop is None else stop)
        return self.r[2], self.r[3]

    def run_wrapper(self, *, stack=STACK, caller=RETURN):
        self.r[29], self.r[31] = stack, caller
        self.r[4:8] = (0, CONTROLLER, 0x13579BDF, FLAG)
        self.factory_context = dict(stack=stack, caller=caller,
                                    registers=self.r.copy(), hi=self.hi, lo=self.lo)
        self.run_at(WRAPPER, caller)
        return self.r[2]


class SecondaryFactoryAdmissionGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = IMAGE.read_bytes()
        if len(cls.image) != 7133528 or hashlib.sha256(cls.image).hexdigest() != SOURCE_SHA256:
            raise AssertionError('secondary factory fixture requires the preserved source')
        cls._original_parents = tuple((module, module.assemble)
                                      for module in _ASSEMBLY_CACHE_MODULES)
        cls._new_assemblers = core.assemble, stage.assemble
        cls._private_emitter = previous.core._assemble
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
                    raise AssertionError('unrestored secondary parent: ' + module.__name__)
            if (core.assemble is not cls._new_assemblers[0]
                    or stage.assemble is not cls._new_assemblers[1]
                    or previous.core._assemble is not cls._private_emitter):
                raise AssertionError('new secondary function/private emitter was wrapped')

    def machine(self, **options):
        return SecondaryFactoryAdmissionGateMachine(self.image, **options)

    assert_native_restoration = previous.FactoryAdmissionGateTests.assert_native_restoration

    def assert_refused(self, machine, *, stack=STACK):
        self.assertEqual((machine.r[2], machine.r[3]), (0, 0))
        self.assert_native_restoration(machine, stack=stack)
        self.assertEqual(machine.factory_events, [])
        self.assertEqual(machine.created_cuts, [])
        self.assertEqual(machine.calls, [])
        self.assertNotIn(ENTER_RESUME, machine.trace)
        self.assertTrue(all(address == GUARD or stack - 192 <= address
                            and address + size <= stack
                            for address, size in machine.reads))

    def test_entry_preserves_s1_inputs_hi_lo_and_separate_incoming_argument_homes(self):
        machine = self.machine()
        machine.clear_events()
        machine.run_secondary(stop=ENTER_RESUME)
        before = machine.factory_context['registers'].copy()
        before[29] -= 568
        self.assertEqual((machine.r, machine.hi, machine.lo),
                         (before, machine.factory_context['hi'], machine.factory_context['lo']))
        self.assertEqual(machine.words_at(STACK + 0x10, 2), (OPERATION, 0x13579BDF))
        self.assertEqual(machine.words_at(STACK - 568 + 0x224, 1), (before[17],))
        self.assertEqual(machine.words_at(STACK - 568 + 0x21C, 1), (core.OWNERSTAMP,))
        machine.run_at(ENTER_RESUME, 0x47D4C4)
        self.assertEqual(machine.r[17], OPERATION)  # Actual LW S1,F+248.
        self.assertIn((STACK + 0x10, 4), machine.reads)
        # The created-body cut does not execute this sixth-argument load.
        # Exercise that exact native word separately under the real F568 SP.
        machine.run_at(0x47D608, 0x47D60C)
        self.assertEqual(machine.r[4], 0x13579BDF)
        self.assertIn((STACK + 0x14, 4), machine.reads)
        self.assertEqual(machine.words_at(STACK + 0x10, 2), (OPERATION, 0x13579BDF))
        self.assertEqual(machine.guard_value(), core.BUSY)
        self.assertEqual(machine.factory_events, [])

    def test_busy_quarantine_unknown_and_exhausted_entry_refuse_before_inputs(self):
        for state in (core.BUSY, core.QUARANTINED, 3, MASK):
            with self.subTest(state=state):
                machine = self.machine()
                machine.put(GUARD, state, 4)
                machine.clear_events()
                machine.run_secondary(name=0xDEAD0000, controller=0xDEAD0004)
                self.assert_refused(machine)
                self.assertEqual(machine.guard_value(), state)
                self.assertEqual(machine.words_at(STACK + 0x10, 2), (OPERATION, 0x13579BDF))
        machine = self.machine(retry_limit=2)
        machine.guard_sc_failures = 2
        machine.clear_events()
        machine.run_secondary()
        self.assert_refused(machine)
        self.assertEqual(machine.guard_value(), core.READY)
        self.assertEqual(sum(event[0] == 'sc' for event in machine.guard_atomic_events), 2)

    def test_existing_lookup_result_and_native_early_return_match_without_the_new_hooks(self):
        native, machine = self.machine(hooked=False), self.machine()
        native.clear_events()
        machine.clear_events()
        native.run_secondary()
        machine.run_secondary()
        self.assertEqual((machine.r, machine.hi, machine.lo), (native.r, native.hi, native.lo))
        self.assertEqual(machine.r[2], DIALOG)
        self.assert_native_restoration(machine)
        self.assertEqual([event[0] for event in machine.factory_events], [LOOKUP])
        self.assertEqual(machine.factory_events[0][4], core.BUSY)
        self.assertIn(EARLY_LEAVE, machine.trace)
        self.assertEqual(machine.guard_value(), core.READY)
        self.assertEqual(machine.words_at(STACK - 568 + 0x21C, 1), (0,))

    def test_native_null_name_still_claims_then_releases_through_its_real_epilogue(self):
        native, machine = self.machine(hooked=False), self.machine()
        native.clear_events()
        machine.clear_events()
        native.run_secondary(name=0)
        machine.run_secondary(name=0)
        self.assertEqual((machine.r, machine.hi, machine.lo), (native.r, native.hi, native.lo))
        self.assertEqual(machine.r[2], 0)
        self.assertEqual(machine.factory_events, [])
        self.assertEqual(machine.guard_value(), core.READY)
        self.assert_native_restoration(machine)

    def test_created_slice_preserves_result_and_holds_q_through_bounded_startup(self):
        native = self.machine(hooked=False, lookup_mode='created')
        machine = self.machine(lookup_mode='created')
        native.clear_events()
        machine.clear_events()
        native.run_secondary()
        machine.run_secondary()
        self.assertEqual((machine.r, machine.hi, machine.lo), (native.r, native.hi, native.lo))
        self.assertEqual(machine.r[2], DIALOG)
        self.assert_native_restoration(machine)
        self.assertEqual(machine.created_cuts, [(CREATED_CUT, STACK - 568)])
        self.assertEqual([event[0] for event in machine.factory_events],
                         [LOOKUP, REGISTER, INITIALIZER, VIEW_UPDATE, STARTUP])
        self.assertTrue(all(event[4] == core.BUSY for event in machine.factory_events))
        self.assertIn(CREATED_LEAVE, machine.trace)
        self.assertEqual(machine.words_at(DIALOG + 0x48, 1), (CONTROLLER,))
        self.assertEqual(machine.guard_value(), core.READY)

    def test_preceding_factory_remains_guarded_in_the_new_composition(self):
        machine = self.machine()
        machine.clear_events()
        machine.run_factory()
        self.assertEqual(machine.r[2], DIALOG)
        self.assertEqual(machine.guard_value(), core.READY)
        self.assertIn(machine.factory_admission_gate_labels['enter'], machine.trace)
        machine.put(GUARD, core.QUARANTINED, 4)
        machine.clear_events()
        machine.run_factory()
        self.assertEqual((machine.r[2], machine.r[3]), (0, 0))
        self.assertEqual(machine.factory_events, [])
        self.assertNotIn(previous.ENTER_RESUME, machine.trace)

    def test_each_factory_refuses_while_the_other_holds_the_shared_claim(self):
        for secondary_owner in (False, True):
            with self.subTest(secondary_owner=secondary_owner):
                owner, nested = self.machine(), self.machine()
                nested.attach_shared(owner)
                if secondary_owner:
                    owner.run_secondary(stop=ENTER_RESUME)
                    nested.clear_events()
                    nested.run_factory(stack=SECOND_STACK)
                else:
                    owner.run_factory(stop=previous.ENTER_RESUME)
                    nested.clear_events()
                    nested.run_secondary(stack=SECOND_STACK)
                self.assertEqual(owner.guard_value(), core.BUSY)
                self.assertEqual((nested.r[2], nested.r[3]), (0, 0))
                self.assertEqual(nested.factory_events, [])
                self.assertEqual((nested.r[29], nested.r[31]), (SECOND_STACK, RETURN))

    def test_competing_different_factory_entry_invalidates_secondary_reservation(self):
        first, second = self.machine(), self.machine()
        second.attach_shared(first)
        interleaved = []

        def compete(current, pc):
            if not interleaved and guard_instruction(current, pc, 0x38):
                interleaved.append(pc)
                second.run_factory(stack=SECOND_STACK, stop=previous.ENTER_RESUME)

        first.on_instruction = compete
        first.clear_events()
        first.run_secondary()
        self.assert_refused(first)
        self.assertEqual(len(interleaved), 1)
        self.assertEqual(second.guard_value(), core.BUSY)
        self.assertTrue(any(event[0] == 'sc' and not event[3]
                            for event in first.guard_atomic_events))

    def test_quarantine_between_leave_ll_sc_is_never_cleared(self):
        machine, fault = self.machine(), self.machine()
        fault.attach_shared(machine)
        interleaved = []

        def publish_fault(current, pc):
            if current.factory_events and not interleaved and guard_instruction(current, pc, 0x38):
                interleaved.append(len(current.writes))
                fault.put(GUARD, core.QUARANTINED, 4)

        machine.on_instruction = publish_fault
        machine.clear_events()
        machine.run_secondary()
        self.assertEqual(len(interleaved), 1)
        self.assertEqual(machine.r[2], DIALOG)
        self.assertEqual(machine.guard_value(), core.QUARANTINED)
        self.assertFalse(any(address == GUARD and value == core.READY
                             for address, value, size in machine.writes[interleaved[0]:]))

    def test_exit_sc_exhaustion_keeps_the_actual_native_result(self):
        for mode, tail in (('existing', EARLY_LEAVE), ('created', CREATED_LEAVE)):
            with self.subTest(mode=mode):
                machine = self.machine(retry_limit=2, lookup_mode=mode)

                def exhaust(current, pc):
                    if pc == tail:
                        current.guard_sc_failures = 2

                machine.on_instruction = exhaust
                machine.clear_events()
                machine.run_secondary()
                self.assertEqual(machine.r[2], DIALOG)
                self.assertEqual(machine.guard_value(), core.QUARANTINED)
                self.assert_native_restoration(machine)

    def test_the_other_factory_stamp_does_not_authorize_secondary_release(self):
        for mode, tail in (('existing', EARLY_LEAVE), ('created', CREATED_LEAVE)):
            with self.subTest(mode=mode):
                machine = self.machine(lookup_mode=mode)
                marks = []

                def replace_stamp(current, pc):
                    if pc == tail:
                        current.put(current.r[29] + 0x21C, previous.core.OWNERSTAMP, 4)
                        marks.append((len(current.reads), len(current.writes)))

                machine.on_instruction = replace_stamp
                machine.clear_events()
                machine.run_secondary()
                self.assertEqual(len(marks), 1)
                reads, writes = marks[0]
                self.assertNotIn((GUARD, 4), machine.reads[reads:])
                self.assertFalse(any(address == GUARD for address, value, size in machine.writes[writes:]))
                self.assertEqual(machine.guard_value(), core.BUSY)
                self.assertEqual(machine.r[2], DIALOG)

    def test_missing_secondary_entry_hook_reaches_lookup_while_quarantined(self):
        machine = self.machine()
        machine.remove_pair(ENTRY)
        machine.put(GUARD, core.QUARANTINED, 4)
        machine.clear_events()
        machine.run_secondary()
        self.assertEqual([event[0] for event in machine.factory_events], [LOOKUP])
        self.assertEqual(machine.r[2], DIALOG)
        self.assertEqual(machine.guard_value(), core.QUARANTINED)
        self.assertNotIn(machine.secondary_factory_admission_gate_labels['enter'], machine.trace)

    def test_fault_in_initializer_does_not_cancel_already_admitted_startup(self):
        machine = self.machine(lookup_mode='created')

        def publish_fault(current, target):
            if target == INITIALIZER:
                current.put(GUARD, core.QUARANTINED, 4)

        machine.on_factory_service = publish_fault
        machine.clear_events()
        machine.run_secondary()
        startup = [event for event in machine.factory_events if event[0] == STARTUP]
        self.assertEqual(len(startup), 1)
        self.assertEqual(startup[0][4], core.QUARANTINED)
        self.assertEqual(machine.r[2], DIALOG)
        self.assertEqual(machine.guard_value(), core.QUARANTINED)
        machine.on_factory_service = None
        machine.clear_events()
        machine.run_secondary()
        self.assert_refused(machine)

    def test_actual_wrapper_null_branch_skips_h_flag_but_keeps_its_ui_calls(self):
        machine = self.machine()
        machine.put(GUARD, core.QUARANTINED, 4)
        machine.put(DIALOG + 0x5C, 0xA5A5A5A5, 4)
        machine.clear_events()
        self.assertEqual(machine.run_wrapper(), 0)
        self.assert_native_restoration(machine)
        self.assertEqual(machine.factory_events, [])
        self.assertEqual([event[0] for event in machine.wrapper_events], [UI_START, UI_FLAG])
        self.assertNotIn(0x4F87D0, machine.trace)
        self.assertEqual(machine.words_at(DIALOG + 0x5C, 1), (0xA5A5A5A5,))
        self.assertEqual(machine.words_at(BB1C, 1), (FLAG,))
        self.assertEqual(machine.guard_value(), core.QUARANTINED)

    def test_actual_wrapper_nonnull_branch_keeps_its_native_h_flag_write(self):
        machine = self.machine()
        machine.put(DIALOG + 0x5C, 0, 4)
        machine.clear_events()
        self.assertEqual(machine.run_wrapper(), DIALOG)
        self.assertEqual(machine.words_at(DIALOG + 0x5C, 1), (1,))
        self.assertIn(0x4F87D0, machine.trace)
        self.assertEqual([event[0] for event in machine.factory_events], [LOOKUP])
        self.assertEqual([event[0] for event in machine.wrapper_events], [UI_START, UI_FLAG])
        self.assert_native_restoration(machine)
        self.assertEqual(machine.guard_value(), core.READY)

    def test_actual_upper_jal_and_ui_continuation_discard_the_null_wrapper_result(self):
        machine = self.machine()
        caller_sp = STACK - 56
        caller_saved = {register: 0x55000000 + register for register in range(16, 20)}
        for register, offset in ((16, 0x24), (17, 0x28), (18, 0x2C), (19, 0x30)):
            machine.put(caller_sp + offset, caller_saved[register], 4)
        machine.put(caller_sp + 0x34, RETURN, 4)
        machine.r[29], machine.r[16], machine.r[7] = caller_sp, WIDGET, 0xB90000
        machine.put(GUARD, core.QUARANTINED, 4)
        machine.clear_events()
        machine.run_at(0x4A325C, RETURN)
        self.assertEqual((machine.r[29], machine.r[31], machine.r[2]), (STACK, RETURN, 1))
        for register, value in caller_saved.items():
            self.assertEqual(machine.r[register], value)
        self.assertEqual(machine.factory_events, [])
        self.assertEqual([event[0] for event in machine.wrapper_events],
                         [UI_START, UI_FLAG, UPPER_UI, UPPER_CLOSE])
        for pc in (UPPER_CALL, 0x4F87C0, 0x4F87C8, 0x4A3274, 0x4A3294, 0x4A3128):
            self.assertIn(pc, machine.trace)
        self.assertNotIn(0x4F87D0, machine.trace)
        self.assertEqual(machine.guard_value(), core.QUARANTINED)

    def test_violated_callee_abi_is_not_repaired_inside_the_opaque_created_body(self):
        machine = self.machine(lookup_mode='created')

        def violate_abi(current, target):
            if target == LOOKUP:
                current.r[16] = 0xDEAD0000

        machine.on_factory_service = violate_abi
        machine.clear_events()
        machine.run_secondary()
        self.assertEqual(machine.words_at(DIALOG + 0x48, 1), (0xDEAD0000,))
        view = [event for event in machine.factory_events if event[0] == VIEW_UPDATE]
        self.assertEqual(view[0][1][0], 0xDEAD0000)
        self.assert_native_restoration(machine)
        self.assertEqual(machine.guard_value(), core.READY)


if __name__ == '__main__':
    unittest.main()
