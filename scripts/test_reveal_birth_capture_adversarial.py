#!/usr/bin/env python3
"""Deny malformed owned birth handoffs without latest-row reconstruction."""

import unittest

import reveal_birth_capture_mips as core
import reveal_creation_capture_mips as capture
import reveal_registry_lifecycle_mips as lifecycle
import test_reveal_birth_capture_mips as fixture
from test_reveal_birth_capture_mips import (
    BirthCaptureMachine, OUTPUT, LIFECYCLE, ENGINE, CONTROLLER, REGISTRY_MUTEX,
    PAINT_MUTEX, CODE, INPUT, STATE, BIND_STATE, OWNER_STATE, RAW_LOCK,
    RAW_UNLOCK, STACK, RETURN, MASK)


class BirthCaptureAdversarialTests(unittest.TestCase):
    setUpClass = classmethod(fixture.BirthCaptureTests.setUpClass.__func__)

    def machine(self, **options):
        return BirthCaptureMachine(self.image, **options)

    def assert_empty_output(self, machine, output=OUTPUT):
        self.assertEqual(machine.birth_output(output), (0,) * 12)
        self.assertFalse(any(event[0] == 'write' and output <= event[2] < output + 48
                             for event in machine.birth_output_accesses))

    def test_every_initial_dirty_output_word_denies_before_native_or_store(self):
        for index in range(12):
            with self.subTest(word=index):
                m = self.machine()
                m.put(OUTPUT + 4 * index, 0xD1700000 + index, 4)
                before = m.birth_output()
                m.clear_events()
                self.assertEqual(m.register_birth(), (MASK, 0))
                self.assertEqual(m.birth_output(), before)
                self.assertEqual(m.native_entries, [])
                self.assertEqual(m.raw_events, [])
                self.assertEqual(m.writes, [])

    def test_every_late_dirty_output_word_prevents_all_emitted_output_stores(self):
        for index in range(12):
            with self.subTest(word=index):
                m = self.machine()
                dirty = 0xA11C0000 + index

                def mutate(machine, target):
                    if target == RAW_LOCK and machine.r[4] == REGISTRY_MUTEX:
                        machine.put(OUTPUT + 4 * index, dirty, 4)

                m.on_service = mutate
                self.assertEqual(m.register_birth(), (0, 0))
                expected = [0] * 12
                expected[index] = dirty
                self.assertEqual(m.birth_output(), tuple(expected))
                self.assertFalse(any(event[0] == 'write'
                    and CODE <= event[1] < CODE + len(m.code)
                    for event in m.birth_output_accesses))
                self.assertEqual(m.lifecycle_header(), (1, 0, 0, 0))

    def test_repeated_same_output_is_never_overwritten_or_reused(self):
        m = self.machine()
        self.assertEqual(m.register_birth(), (0, OUTPUT))
        before = m.birth_output()
        m.clear_events()
        self.assertEqual(m.register_birth(), (MASK, 0))
        self.assertEqual(m.birth_output(), before)
        self.assertEqual(m.native_entries, [])
        self.assertEqual(m.birth_output_writes(), [])

    def test_all_fixed_data_and_generated_RX_aliases_deny_before_save_or_native(self):
        protected = (STATE, BIND_STATE, OWNER_STATE, LIFECYCLE, CONTROLLER,
                     REGISTRY_MUTEX, PAINT_MUTEX, 0x4389E0, CODE)
        m = self.machine()
        protected += (CODE + len(m.code) - 4,)
        for address in protected:
            for argument in ('descriptor', 'output', 'stack'):
                with self.subTest(address=hex(address), argument=argument):
                    m = self.machine()
                    value = address + core.FRAME if argument == 'stack' else address
                    self.assertEqual(m.register_birth(**{argument: value}), (MASK, 0))
                    self.assertEqual(m.native_entries, [])
                    self.assertEqual(m.raw_events, [])
                    self.assertEqual(m.writes, [])

    def test_invalid_and_wrapping_extents_deny_without_access(self):
        cases = ({'controller': 0}, {'controller': CONTROLLER + 4},
                 {'descriptor': 0}, {'descriptor': INPUT + 1},
                 {'descriptor': 0xFFFFFFFC}, {'output': 0},
                 {'output': OUTPUT + 1}, {'output': 0xFFFFFFFC},
                 {'stack': 0}, {'stack': core.FRAME - 8}, {'stack': STACK + 4},
                 {'output': INPUT}, {'descriptor': STACK - core.FRAME},
                 {'output': STACK - core.FRAME + 4})
        for arguments in cases:
            with self.subTest(arguments=arguments):
                m = self.machine()
                self.assertEqual(m.register_birth(**arguments), (MASK, 0))
                self.assertEqual(m.native_entries, [])
                self.assertEqual(m.raw_events, [])
                self.assertEqual(m.writes, [])

    def test_descriptor_is_owned_before_any_hostile_raw_service(self):
        m = self.machine()
        original = m.words_at(INPUT, 5)

        def mutate(machine, target):
            if target == RAW_LOCK and machine.r[4] == REGISTRY_MUTEX:
                for index, word in enumerate(original):
                    machine.put(INPUT + 4 * index, word ^ MASK, 4)

        m.on_service = mutate
        self.assertEqual(m.register_birth(), (0, OUTPUT))
        self.assertEqual(m.words_at(m.allocations[-1] + 8, 5), original)
        self.assertEqual(m.birth_output()[5], original[0])

    def test_missing_birth_observer_cannot_adopt_a_previous_same_stack_token(self):
        m = self.machine()
        self.assertEqual(m.register_birth(), (0, OUTPUT))
        first = m.birth_output()
        for pc in (0x438A58, 0x438A5C):
            m.patches.pop(pc, None)
        m.clear_events()
        self.assertEqual(m.register_birth(output=OUTPUT + 48), (0, 0))
        self.assert_empty_output(m, OUTPUT + 48)
        self.assertEqual(m.birth_output(), first)
        self.assertEqual(m.birth_sink_requests, [])

    def test_each_missing_checked_release_observer_refuses_even_with_captured_token(self):
        for pc in (0x438A60, 0x466DC8, 0x466DD0):
            with self.subTest(missing=hex(pc)):
                m = self.machine()
                m.patches.pop(pc, None)
                m.patches.pop(pc + 4, None)
                self.assertEqual(m.register_birth(), (MASK, 0))
                self.assert_empty_output(m)
                self.assertEqual(m.lifecycle_header(), (1, 0, 0, 0))

    def test_wrong_event_scalars_and_token_never_export_despite_committed_row(self):
        replacements = ((0, CONTROLLER + 4), (4, REGISTRY_MUTEX + 4),
                        (16, STACK), (20, RETURN),
                        (24, lifecycle.PUBLICATION_SITE + 4), (28, 22))
        for offset, value in replacements:
            with self.subTest(offset=offset):
                m = self.machine()

                def mutate(machine, pc):
                    if pc == machine.birth_capture_labels['birth_sink']:
                        machine.put(machine.r[5] + offset, value, 4)

                m.on_instruction = mutate
                self.assertEqual(m.register_birth(), (0, 0))
                self.assert_empty_output(m)
                self.assertEqual(m.lifecycle_header(), (1, 0, 0, 0))
        for value in (0, 17, 0x80000000, MASK):
            with self.subTest(token=value):
                m = self.machine()

                def mutate_token(machine, pc):
                    if pc == machine.birth_capture_labels['birth_sink']:
                        machine.r[6] = value

                m.on_instruction = mutate_token
                self.assertEqual(m.register_birth(), (0, 0))
                self.assert_empty_output(m)

    def test_foreign_identical_event_is_rejected_before_its_memory_is_read(self):
        m = self.machine()
        foreign, boundaries = 0x1F3B000, []

        def mutate(machine, pc):
            if pc == machine.birth_capture_labels['birth_sink']:
                copied = machine.words_at(machine.r[5], 8)
                for index, word in enumerate(copied):
                    machine.put(foreign + 4 * index, word, 4)
                machine.r[5] = foreign
                boundaries.append(len(machine.reads))

        m.on_instruction = mutate
        self.assertEqual(m.register_birth(), (0, 0))
        self.assert_empty_output(m)
        self.assertEqual(len(boundaries), 1)
        self.assertFalse(any(foreign <= address < foreign + 32
                             for address, _ in m.reads[boundaries[0]:]))

    def test_equal_armed_foreign_frame_cannot_receive_current_native_event(self):
        m = self.machine()
        outer = STACK - core.FRAME
        foreign, boundaries = STACK - 0x1000, []

        def mutate(machine, pc):
            if pc == machine.birth_capture_labels['birth_sink']:
                copied = machine.words_at(outer, core.FRAME // 4)
                for index, word in enumerate(copied):
                    machine.put(foreign + 4 * index, word, 4)
                machine.put(machine.r[5] + lifecycle.REQUEST_NATIVE_SP,
                            foreign - capture.FRAME - capture.NATIVE_FRAME, 4)
                boundaries.append((len(machine.reads), len(machine.writes), copied))

        m.on_instruction = mutate
        self.assertEqual(m.register_birth(), (0, 0))
        self.assert_empty_output(m)
        self.assertEqual(len(boundaries), 1)
        reads, writes, copied = boundaries[0]
        self.assertFalse(any(foreign <= address < foreign + core.FRAME
                             for address, _ in m.reads[reads:]))
        self.assertFalse(any(foreign <= address < foreign + core.FRAME
                             for address, _, _ in m.writes[writes:]))
        self.assertEqual(m.words_at(foreign, core.FRAME // 4), copied)

    def test_wrong_old_capture_output_or_saved_return_cannot_bind_outer_frame(self):
        for offset, value in ((capture.OUTPUT_PTR, OUTPUT),
                              (capture.SAVE[31], RETURN)):
            with self.subTest(slot=offset):
                m = self.machine()
                inner = STACK - core.FRAME - capture.FRAME
                saved = []

                def mutate(machine, pc):
                    if pc == machine.birth_capture_labels['birth_sink'] and not saved:
                        saved.append(machine.peek(inner + offset))
                        machine.put(inner + offset, value, 4)
                    elif pc == machine.birth_capture_labels['birth_sink_restore'] and saved:
                        machine.put(inner + offset, saved[0], 4)

                m.on_instruction = mutate
                self.assertEqual(m.register_birth(), (0, 0))
                self.assert_empty_output(m)
                self.assertEqual(len(saved), 1)

    def test_same_scope_duplicate_callback_poison_prevents_output_and_preserves_first_token(self):
        m = self.machine()
        entry, repeated, captured = [], [], []
        outer = STACK - core.FRAME

        def repeat(machine, pc):
            if pc == machine.birth_capture_labels['birth_sink'] and not entry:
                entry.append((machine.r.copy(), machine.hi, machine.lo))
            elif pc == machine.birth_capture_labels['birth_sink_restore'] and not repeated:
                repeated.append(True)
                captured.append(machine.words_at(outer + core.TOKEN, 9))
                registers, hi, lo = machine.r.copy(), machine.hi, machine.lo
                arguments, entry_hi, entry_lo = entry[0]
                machine.r[:], machine.hi, machine.lo = arguments, entry_hi, entry_lo
                machine.run_at(machine.birth_capture_labels['birth_sink'], arguments[31])
                self.assertEqual(machine.words_at(outer + core.TOKEN, 9), captured[0])
                machine.r[:], machine.hi, machine.lo = registers, hi, lo

        m.on_instruction = repeat
        self.assertEqual(m.register_birth(), (0, 0))
        self.assert_empty_output(m)
        self.assertEqual(repeated, [True])
        self.assertEqual(captured[0][0], 1)

    def test_actual_sink_preserves_all_GPRs_and_hilo(self):
        for invalid in (False, True):
            with self.subTest(invalid=invalid):
                m = self.machine()
                entry, returned = [], []

                def inspect(machine, pc):
                    if pc == machine.birth_capture_labels['birth_sink'] and not entry:
                        if invalid:
                            machine.r[6] = 0
                        entry.append((machine.r.copy(), machine.hi, machine.lo))
                    elif entry and pc == entry[0][0][31] and not returned:
                        returned.append((machine.r.copy(), machine.hi, machine.lo))

                m.on_instruction = inspect
                self.assertEqual(m.register_birth(), (0, 0 if invalid else OUTPUT))
                self.assertEqual(returned, entry)

    def test_raw_release_error_never_rechecks_dirty_external_output(self):
        m = self.machine(release=22)
        boundaries = []

        def mutate(machine, target):
            if target == RAW_UNLOCK and machine.r[4] == REGISTRY_MUTEX:
                machine.put(OUTPUT + 44, 0xD1700044, 4)
                boundaries.append(len(machine.birth_output_accesses))

        m.on_service = mutate
        self.assertEqual(m.register_birth(), (MASK, 22))
        self.assertEqual(boundaries, [len(m.birth_output_accesses)])
        self.assertEqual(m.birth_output()[-1], 0xD1700044)
        self.assertFalse(any(event[0] == 'write' and CODE <= event[1] < CODE + len(m.code)
                             for event in m.birth_output_accesses))


if __name__ == '__main__':
    unittest.main()
