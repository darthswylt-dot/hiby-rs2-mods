#!/usr/bin/env python3
"""Adverse opt-in raw13C witnesses, not native lifetime or recovery authority.

Hostile mutations below exercise bounded scalar/route rejection. They do not
authenticate a wholly forged valid private stack, provide a retained native
object lease, authorize a second unlock, or simulate a real thread scheduler.
"""

import hashlib
import unittest

from build_reveal_bridge_diag import b
import reveal_creation_capture_mips as capture
import reveal_creation_capture_stage as stage
import reveal_registry_receipt_mips as receipt
import test_folderfollow_reveal_static_contract as source
import test_reveal_registry_release_mips as fixture


TRAMPOLINE = 0x1FC0000


class ReleaseAdversarialMachine(fixture.RegistryReleaseMachine):
    """A native-tail trampoline and both ambiguous raw release outcomes."""

    def __init__(self, image, **options):
        super().__init__(image, **options)
        self.registry_release_failure_releases = True
        self.patches[TRAMPOLINE] = b.j_type(2, 0x437DA0)
        self.patches[TRAMPOLINE + 4] = 0

    def external(self, target):
        if target == TRAMPOLINE:
            self.calls.append(target)
            self.run_at(target, self.r[31])
            return
        super().external(target)

    def service(self, target):
        pointer, before = self.r[4], self.registry_held
        super().service(target)
        if (target == fixture.RAW_UNLOCK and pointer == fixture.REGISTRY_MUTEX
                and self.release != 0
                and not self.registry_release_failure_releases):
            self.registry_held = before


class RegistryReleaseAdversarialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = source.SOURCE.read_bytes()
        digest = hashlib.sha256(cls.image).hexdigest()
        if digest != source.SOURCE_SHA256 or len(cls.image) != source.SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: {digest}, size {len(cls.image)}')

    def machine(self, **options):
        return ReleaseAdversarialMachine(self.image, **options)

    def output_writes(self, machine):
        return [event for event in machine.output_accesses
                if event[0] == 'write'
                and fixture.CODE <= event[1] < fixture.CODE + len(machine.code)]

    def assert_empty_output(self, machine, output=fixture.OUTPUT):
        self.assertEqual(machine.outwords(output), (0,) * 8)
        self.assertEqual(self.output_writes(machine), [])

    def private_address(self, offset):
        return fixture.STACK - capture.FRAME + offset

    def test_late_actual_callback_change_denies_even_with_unchanged_controller_slot(self):
        m = self.machine()

        def mutate(machine, pc):
            if pc == 0x438A60:
                self.assertEqual(machine.peek(fixture.CONTROLLER + 0x278), 0x437DA0)
                machine.r[25] = TRAMPOLINE

        m.on_instruction = mutate
        self.assertEqual(m.invoke_register(), (fixture.MASK, 0))
        self.assert_empty_output(m)
        self.assertIn(TRAMPOLINE, m.trace)
        self.assertEqual(m.raw_events[-1][0:2],
                         (fixture.RAW_UNLOCK, fixture.REGISTRY_MUTEX))
        self.assertEqual(m.raw_events[-1][-1], 0)
        self.assertEqual(m.binding_header()[0], 1)

    def test_late_actual_raw_argument_change_is_not_replaced_by_a_controller_lookup(self):
        m = self.machine()
        foreign = fixture.REGISTRY_MUTEX + 0x100

        def mutate(machine, pc):
            if pc == 0x466DC8:
                machine.r[4] = foreign

        m.on_instruction = mutate
        self.assertEqual(m.invoke_register(), (fixture.MASK, 0))
        self.assert_empty_output(m)
        self.assertEqual(m.raw_events[-1][1], foreign)
        self.assertTrue(m.registry_held)
        self.assertEqual(len([e for e in m.raw_events
                              if e[0] == fixture.RAW_UNLOCK
                              and e[1] == fixture.REGISTRY_MUTEX]), 0)

    def test_wrong_saved_native_lower_or_upper_return_pc_denies_call_scope(self):
        raw_sp = fixture.STACK - capture.FRAME - capture.NATIVE_FRAME - 0x40
        for offset, expected in ((0x1C, 0x437DB0), (0x3C, 0x438A68),
                                 (0x64, None)):
            with self.subTest(offset=offset):
                m = self.machine()
                actual = m.capture_labels['native_return'] if expected is None else expected

                def mutate(machine, pc):
                    if pc == 0x466DC8:
                        machine.put(raw_sp + offset, actual + 4, 4)

                def restore(machine, target):
                    if target == fixture.RAW_UNLOCK and machine.r[4] == fixture.REGISTRY_MUTEX:
                        machine.put(raw_sp + offset, actual, 4)

                m.on_instruction, m.on_service = mutate, restore
                self.assertEqual(m.invoke_register(), (fixture.MASK, 0))
                self.assert_empty_output(m)

    def test_wrong_saved_native_lower_or_upper_return_pc_denies_return_scope(self):
        raw_sp = fixture.STACK - capture.FRAME - capture.NATIVE_FRAME - 0x40
        for offset, expected in ((0x1C, 0x437DB0), (0x3C, 0x438A68),
                                 (0x64, None)):
            with self.subTest(offset=offset):
                m = self.machine()
                actual = m.capture_labels['native_return'] if expected is None else expected

                def mutate(machine, pc):
                    if pc == 0x466DD0:
                        machine.put(raw_sp + offset, actual + 4, 4)
                    elif pc == machine.capture_labels['raw_release_return_done']:
                        machine.put(raw_sp + offset, actual, 4)

                m.on_instruction = mutate
                self.assertEqual(m.invoke_register(), (fixture.MASK, 0))
                self.assert_empty_output(m)

    def test_wrong_actual_raw_return_ra_denies_before_status_capture(self):
        m = self.machine()

        def mutate(machine, pc):
            if pc == 0x466DD0:
                machine.r[31] = 0x466DD8

        m.on_instruction = mutate
        self.assertEqual(m.invoke_register(), (fixture.MASK, 0))
        self.assert_empty_output(m)

    def test_foreign_actual_controller_denies_call_and_return_observers(self):
        for point in (0x466DC8, 0x466DD0):
            with self.subTest(point=point):
                m = self.machine()

                def mutate(machine, pc):
                    if pc == point:
                        machine.r[16] = fixture.CONTROLLER + 0x1000

                m.on_instruction = mutate
                self.assertEqual(m.invoke_register(), (fixture.MASK, 0))
                self.assert_empty_output(m)

    def test_altered_selected_native_mutex_or_dirty_status_denies_raw_call(self):
        native_sp = fixture.STACK - capture.FRAME - capture.NATIVE_FRAME
        mutations = ((capture.RELEASE_NATIVE_SP, native_sp + 8),
                     (capture.RELEASE_MUTEX, fixture.REGISTRY_MUTEX + 4),
                     (capture.RELEASE_STATUS, 0),
                     (capture.RELEASE_TAG, capture.RELEASE_CAPTURED))
        for offset, value in mutations:
            with self.subTest(offset=offset):
                m = self.machine()

                def mutate(machine, pc):
                    if pc == 0x466DC8:
                        machine.put(self.private_address(offset), value, 4)

                m.on_instruction = mutate
                self.assertEqual(m.invoke_register(), (fixture.MASK, 0))
                self.assert_empty_output(m)

    def test_altered_selected_native_raw_sp_or_mutex_denies_return_capture(self):
        native_sp = fixture.STACK - capture.FRAME - capture.NATIVE_FRAME
        mutations = ((capture.RELEASE_NATIVE_SP, native_sp + 8),
                     (capture.RELEASE_RAW_SP, native_sp - 0x38),
                     (capture.RELEASE_MUTEX, fixture.REGISTRY_MUTEX + 4),
                     (capture.RELEASE_TAG, capture.RELEASE_ARMED))
        for offset, value in mutations:
            with self.subTest(offset=offset):
                m = self.machine()

                def mutate(machine, pc):
                    if pc == 0x466DD0:
                        machine.put(self.private_address(offset), value, 4)

                m.on_instruction = mutate
                self.assertEqual(m.invoke_register(), (fixture.MASK, 0))
                self.assert_empty_output(m)

    def test_duplicate_observer_cannot_certify_a_second_selection_call_or_return(self):
        for name in ('release_call', 'raw_release_call', 'raw_release_return'):
            with self.subTest(name=name):
                m = self.machine()
                repeated = []

                def repeat(machine, pc):
                    if pc != machine.capture_labels[name + '_done'] or repeated:
                        return
                    repeated.append(True)
                    registers, hi, lo = machine.r.copy(), machine.hi, machine.lo
                    # Reexecute only the observer up to its restore label.
                    # No duplicate native callback/raw-unlock is authorized.
                    frame = machine.r[29]
                    original = {register: machine.peek(frame + offset)
                                for register, offset in capture.SINK_SAVE.items()}
                    for register, value in original.items():
                        machine.r[register] = value
                    machine.r[29] = frame + capture.SINK_FRAME
                    machine.run_at(machine.capture_labels[name], pc)
                    machine.r[:], machine.hi, machine.lo = registers, hi, lo

                m.on_instruction = repeat
                self.assertEqual(m.invoke_register(), (fixture.MASK, 0))
                self.assertEqual(repeated, [True])
                self.assert_empty_output(m)
                self.assertEqual(len([e for e in m.raw_events
                                      if e[0] == fixture.RAW_UNLOCK
                                      and e[1] == fixture.REGISTRY_MUTEX]), 1)

    def test_missing_any_release_hook_never_falls_back_to_historical_flag(self):
        for name in ('release_call', 'raw_release_call', 'raw_release_return'):
            with self.subTest(name=name):
                m = self.machine()
                m.remove_release_hook(name)
                self.assertEqual(m.invoke_register(), (fixture.MASK, 0))
                self.assert_empty_output(m)
                self.assertEqual(m.binding_header()[0], 1)

    def test_raw_release_error_has_exact_status_with_either_ambiguous_ownership(self):
        for held in (False, True):
            for status in (1, 22, 0x82, fixture.MASK):
                with self.subTest(held=held, status=status):
                    m = self.machine(release=status)
                    m.registry_release_failure_releases = not held
                    self.assertEqual(m.invoke_register(), (fixture.MASK, status))
                    self.assertEqual(m.registry_held, held)
                    self.assert_empty_output(m)
                    self.assertEqual(m.binding_header(), (1, 0, 0, 0))
                    self.assertEqual(m.private_release()[0:2], (0, status))
                    self.assertEqual(m.freed, [])

    def test_uncertain_release_has_no_late_controller_or_shared_state_accesses(self):
        for held in (False, True):
            with self.subTest(held=held):
                m = self.machine(release=22)
                m.registry_release_failure_releases = not held
                boundaries = []

                def observe(machine, target):
                    if target == fixture.RAW_UNLOCK and machine.r[4] == fixture.REGISTRY_MUTEX:
                        boundaries.append((len(machine.reads), len(machine.writes)))

                m.on_service = observe
                self.assertEqual(m.invoke_register(), (fixture.MASK, 22))
                self.assertEqual(len(boundaries), 1)
                reads, writes = boundaries[0]
                extents = ((fixture.CONTROLLER, receipt.CONTROLLER_BYTES),
                           (fixture.BIND_STATE, m.composition['binding_memory_bytes']),
                           (fixture.OWNER_STATE, m.composition['owner_memory_bytes']),
                           (fixture.STATE, m.composition['receipt_memory_bytes']))
                for address, _ in m.reads[reads:]:
                    self.assertFalse(any(start <= address < start + size
                                         for start, size in extents))
                for address, _, _ in m.writes[writes:]:
                    self.assertFalse(any(start <= address < start + size
                                         for start, size in extents))

    def test_previous_same_stack_zero_cannot_survive_a_later_failed_release(self):
        m = self.machine()
        self.assertEqual(m.invoke_register(), (0, fixture.OUTPUT))
        first = m.outwords()
        second = fixture.OUTPUT + capture.OUTPUT_BYTES
        m.release = 22
        m.clear_events()
        self.assertEqual(m.invoke_register(output=second), (fixture.MASK, 22))
        self.assert_empty_output(m, second)
        self.assertEqual(m.outwords(), first)
        m.release = 0
        m.remove_release_hook('raw_release_return')
        third = second + capture.OUTPUT_BYTES
        m.clear_events()
        self.assertEqual(m.invoke_register(output=third), (fixture.MASK, 0))
        self.assert_empty_output(m, third)

    def test_foreign_valid_wrapper_copy_cannot_replace_selected_native_frame(self):
        m = self.machine()
        original = fixture.STACK - capture.FRAME
        foreign = original - 0x1000
        boundaries = []

        def mutate(machine, pc):
            if pc != 0x466DC8:
                return
            copied = machine.words_at(original, capture.FRAME // 4)
            for index, word in enumerate(copied):
                machine.put(foreign + index * 4, word, 4)
            machine.put(original + capture.RELEASE_NATIVE_SP,
                        foreign - capture.NATIVE_FRAME, 4)
            boundaries.append((len(machine.reads), len(machine.writes), copied))

        m.on_instruction = mutate
        self.assertEqual(m.invoke_register(), (fixture.MASK, 0))
        self.assert_empty_output(m)
        self.assertEqual(len(boundaries), 1)
        reads, writes, copied = boundaries[0]
        self.assertFalse(any(foreign <= address < foreign + capture.FRAME
                             for address, _ in m.reads[reads:]))
        self.assertFalse(any(foreign <= address < foreign + capture.FRAME
                             for address, _, _ in m.writes[writes:]))
        self.assertEqual(m.words_at(foreign, capture.FRAME // 4), copied)

    def test_controller_mutation_during_raw_release_does_not_retarget_or_trigger_rereads(self):
        m = self.machine()
        boundaries = []

        def mutate(machine, target):
            if target != fixture.RAW_UNLOCK or machine.r[4] != fixture.REGISTRY_MUTEX:
                return
            for offset in (0x13C, 0x148, 0x274, 0x278, 0x284, 0x288):
                machine.put(fixture.CONTROLLER + offset, 0xF00D0000 + offset, 4)
            boundaries.append((len(machine.reads), len(machine.writes)))

        m.on_service = mutate
        self.assertEqual(m.invoke_register(), (0, fixture.OUTPUT))
        self.assertEqual(m.outwords()[1], capture.REGISTRY_RELEASE_OBSERVED)
        self.assertEqual(m.raw_events[-1][1], fixture.REGISTRY_MUTEX)
        reads, writes = boundaries[0]
        self.assertFalse(any(fixture.CONTROLLER <= address < fixture.CONTROLLER + receipt.CONTROLLER_BYTES
                             for address, _ in m.reads[reads:]))
        self.assertFalse(any(fixture.CONTROLLER <= address < fixture.CONTROLLER + receipt.CONTROLLER_BYTES
                             for address, _, _ in m.writes[writes:]))

    def test_failed_raw_acquire_keeps_original_native_unchecked_link_writes_not_a_pair(self):
        m = self.machine(acquire=22)
        self.assertEqual(m.invoke_register(), (0, 0))
        self.assert_empty_output(m)
        node = m.allocations[0]
        self.assertEqual(m.words_at(node + 8, 5), fixture.DESCRIPTOR)
        self.assertEqual(m.words_at(fixture.CONTROLLER + 0x34, 2), (node, node))
        self.assertEqual(m.binding_header()[0], 0)
        self.assertEqual(m.private_release()[0:2], (0, 0))

    def test_every_output_word_dirtied_after_actual_release_is_not_overwritten(self):
        for word in range(8):
            with self.subTest(word=word):
                m = self.machine()
                dirty = 0xD17A0000 + word

                def mutate(machine, pc):
                    if pc == 0x466DD0:
                        machine.put(fixture.OUTPUT + word * 4, dirty, 4)

                m.on_instruction = mutate
                self.assertEqual(m.invoke_register(), (0, 0))
                expected = [0] * 8
                expected[word] = dirty
                self.assertEqual(m.outwords(), tuple(expected))
                self.assertEqual(self.output_writes(m), [])
                self.assertEqual(m.private_release()[0:2], (0, 0))

    def test_expanded_full_code_and_shared_extents_exclude_source_output_and_frame(self):
        prototype = self.machine()
        extents = ((fixture.CODE, len(prototype.code)),
                   (fixture.STATE, prototype.composition['receipt_memory_bytes']),
                   (fixture.BIND_STATE, prototype.composition['binding_memory_bytes']),
                   (fixture.OWNER_STATE, prototype.composition['owner_memory_bytes']),
                   (fixture.CONTROLLER, receipt.CONTROLLER_BYTES),
                   (fixture.REGISTRY_MUTEX, receipt.MUTEX_BYTES),
                   (fixture.PAINT_MUTEX, receipt.MUTEX_BYTES),
                   (receipt.NATIVE_RX[0], receipt.NATIVE_RX[1] - receipt.NATIVE_RX[0]))
        for start, size in extents:
            for field in ('descriptor', 'output', 'stack'):
                with self.subTest(start=start, field=field):
                    m = self.machine()
                    address = ((start + size - 8) & ~7 if field == 'stack'
                               else start + size - 4)
                    argument = address + capture.FRAME if field == 'stack' else address
                    self.assertEqual(m.invoke_register(**{field: argument}), (fixture.MASK, 0))
                    self.assertEqual(m.native_entries, [])
                    self.assertEqual(m.raw_events, [])
                    self.assertEqual(m.writes, [])

    def test_new_release_observer_code_itself_is_protected_not_just_old_prefix(self):
        for label in ('release_call', 'raw_release_call', 'raw_release_return'):
            for field in ('descriptor', 'output', 'stack'):
                with self.subTest(label=label, field=field):
                    m = self.machine()
                    address = m.capture_labels[label]
                    argument = (address & ~7) + capture.FRAME if field == 'stack' else address
                    self.assertEqual(m.invoke_register(**{field: argument}), (fixture.MASK, 0))
                    self.assertEqual(m.native_entries, [])
                    self.assertEqual(m.writes, [])

    def test_exactly_adjacent_output_remains_accepted_with_expanded_checked_rx(self):
        for side in ('before', 'after'):
            with self.subTest(side=side):
                m = self.machine()
                output = fixture.CODE - capture.OUTPUT_BYTES if side == 'before' else fixture.CODE + len(m.code)
                m.map(output, capture.OUTPUT_BYTES)
                self.assertEqual(m.invoke_register(output=output), (0, output))
                self.assertEqual(m.outwords(output)[1], capture.REGISTRY_RELEASE_OBSERVED)

    def test_checked_option_accepts_only_exact_booleans_in_module_and_composer(self):
        arguments = (fixture.STATE, fixture.BIND_STATE, fixture.OWNER_STATE,
                     fixture.CONTROLLER, fixture.REGISTRY_MUTEX,
                     fixture.PAINT_MUTEX, fixture.CODE)
        for value in (None, 0, 1, -1, 'true', (), [], {}, 0.0, 1.0):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    capture.assemble(*arguments, checked_registry_release=value)
                with self.assertRaises(ValueError):
                    stage.assemble(*arguments, checked_registry_release=value)

    def test_default_and_explicit_false_keep_exact_bytes_and_historical_semantics(self):
        arguments = (fixture.STATE, fixture.BIND_STATE, fixture.OWNER_STATE,
                     fixture.CONTROLLER, fixture.REGISTRY_MUTEX,
                     fixture.PAINT_MUTEX, fixture.CODE)
        default = stage.assemble(*arguments)
        self.assertEqual(default, stage.assemble(*arguments, checked_registry_release=False))
        self.assertEqual(len(default['code']), 22676)
        self.assertEqual(hashlib.sha256(default['code']).hexdigest(),
                         '90be0fdb56fa349782d7a5b89009661ca26484ad1beed25fb8628ddfc2383da5')
        m = self.machine(checked_registry_release=False, release=22)
        self.assertEqual(m.invoke_register(), (0, fixture.OUTPUT))
        self.assertEqual(m.outwords()[1], capture.HISTORICAL_RELEASE_UNOBSERVED)
        self.assertEqual(default['release_hooks'], {})

    def test_hook_descriptor_rejects_partial_checked_labels_but_default_is_empty(self):
        m = self.machine()
        checked_labels = dict(m.capture_labels)
        self.assertEqual(len(capture.hook_words(checked_labels)), 3)
        for missing in ('release_call', 'raw_release_call', 'raw_release_return'):
            with self.subTest(missing=missing):
                incomplete = dict(checked_labels)
                del incomplete[missing]
                with self.assertRaises(ValueError):
                    capture.hook_words(incomplete)
        self.assertEqual(capture.hook_words({'register': fixture.CODE}), {})


if __name__ == '__main__':
    unittest.main()
