#!/usr/bin/env python3
"""Adverse emitted creation capture, not native lifetime or release authority.

Pairs used positively below come only from actual emitted owned output stores.
Deliberately malformed private contexts exercise scalar fail-closed checks;
they do not authenticate arbitrary fabricated frames or remove stack premises.
"""

import hashlib
import unittest

import reveal_creation_capture_mips as capture
import reveal_paint_retirement_mips as owner
import reveal_registry_owner_mips as bindings
import reveal_registry_owner_stage as old_creation
import test_folderfollow_reveal_static_contract as source
import test_reveal_creation_capture_mips as fixture


class CreationCaptureAdversarialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = source.SOURCE.read_bytes()
        digest = hashlib.sha256(cls.image).hexdigest()
        if digest != source.SOURCE_SHA256 or len(cls.image) != source.SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: {digest}, size {len(cls.image)}')

    def machine(self, **options):
        return fixture.CreationCaptureMachine(self.image, **options)

    def output_writes(self, machine):
        return [event for event in machine.output_accesses
                if event[0] == 'write'
                and fixture.CODE <= event[1] < fixture.CODE + len(machine.code)]

    def assert_empty_output(self, machine, output=fixture.OUTPUT):
        self.assertEqual(machine.outwords(output), (0,) * 8)
        self.assertEqual(self.output_writes(machine), [])

    def test_every_dirty_output_word_denies_before_native_entry_or_overwrite(self):
        for word in range(8):
            with self.subTest(word=word):
                m = self.machine()
                m.put(fixture.OUTPUT + word * 4, 0xD1A70000 + word, 4)
                before = m.outwords()
                m.clear_events()
                self.assertEqual(m.invoke_register(), (fixture.MASK, 0))
                self.assertEqual(m.outwords(), before)
                self.assertEqual(m.native_entries, [])
                self.assertEqual(m.raw_events, [])
                self.assertEqual(self.output_writes(m), [])

    def test_every_output_word_dirtied_after_preflight_refuses_publication(self):
        for word in range(8):
            with self.subTest(word=word):
                m = self.machine()
                dirty = 0xA11C0000 + word

                def mutate(machine, target):
                    if target == fixture.RAW_LOCK and machine.r[4] == fixture.REGISTRY_MUTEX:
                        machine.put(fixture.OUTPUT + word * 4, dirty, 4)

                m.on_service = mutate
                self.assertEqual(m.invoke_register(), (0, 0))
                expected = [0] * 8
                expected[word] = dirty
                self.assertEqual(m.outwords(), tuple(expected))
                self.assertEqual(m.binding_header()[0], 1)
                self.assertEqual(self.output_writes(m), [])

    def test_wrong_owned_request_scope_cannot_export_even_after_binding_commit(self):
        mutations = ((bindings.REQUEST_CONTROLLER, fixture.CONTROLLER + 4),
                     (bindings.REQUEST_REGISTRY_MUTEX, fixture.REGISTRY_MUTEX + 4),
                     (bindings.REQUEST_SITE, bindings.PUBLICATION_SITE + 4),
                     (bindings.REQUEST_RAW_STATUS, 22),
                     (bindings.REQUEST_CALLER, fixture.RETURN))
        for offset, value in mutations:
            with self.subTest(offset=offset):
                m = self.machine()

                def mutate(machine, pc):
                    if pc == machine.capture_labels['sink']:
                        machine.put(machine.r[5] + offset, value, 4)

                m.on_instruction = mutate
                self.assertEqual(m.invoke_register(), (0, 0))
                self.assertEqual(m.binding_header()[0], 1)
                self.assert_empty_output(m)

    def test_wrong_native_sp_does_not_adopt_an_adjacent_or_wrapped_context(self):
        for replacement in (fixture.STACK - capture.FRAME - capture.NATIVE_FRAME + 8,
                            0xFFFFFFF8):
            with self.subTest(native_sp=replacement):
                m = self.machine()

                def mutate(machine, pc):
                    if pc == machine.capture_labels['sink']:
                        machine.put(machine.r[5] + bindings.REQUEST_NATIVE_SP,
                                    replacement, 4)

                m.on_instruction = mutate
                self.assertEqual(m.invoke_register(), (0, 0))
                self.assert_empty_output(m)

    def test_changed_armed_controller_or_engine_context_does_not_export(self):
        mutations = ((capture.ARMED_TAG, 0),
                     (capture.PINNED_U, fixture.CONTROLLER + 4),
                     (capture.DESCRIPTOR, fixture.ENGINE ^ 4))
        for offset, value in mutations:
            with self.subTest(offset=offset):
                m = self.machine()

                def mutate(machine, pc):
                    if pc == machine.capture_labels['sink']:
                        machine.put(fixture.STACK - capture.FRAME + offset, value, 4)

                m.on_instruction = mutate
                self.assertEqual(m.invoke_register(), (0, 0))
                self.assert_empty_output(m)

    def test_dirty_private_capture_fields_are_not_overwritten_by_sink(self):
        for offset in capture.CAPTURE_FIELDS:
            with self.subTest(offset=offset):
                m = self.machine()
                address = fixture.STACK - capture.FRAME + offset

                def mutate(machine, pc):
                    if pc == machine.capture_labels['sink']:
                        machine.put(address, 0x1234ABCD, 4)

                m.on_instruction = mutate
                self.assertEqual(m.invoke_register(), (0, 0))
                self.assertEqual(m.words_at(address, 1), (0x1234ABCD,))
                self.assert_empty_output(m)
        # These individual corruptions are detected. A fully forged valid
        # private frame/request is explicitly outside the capture contract.

    def test_invalid_pair_and_receipt_values_at_sink_do_not_export(self):
        for field, value in (('sequence', 0), ('sequence', 17),
                             ('owner', 0), ('owner', 0x80000000),
                             ('receipt', 0), ('receipt', 1025)):
            with self.subTest(field=field, value=value):
                m = self.machine()

                def mutate(machine, pc):
                    if pc == machine.capture_labels['sink']:
                        if field == 'sequence':
                            machine.r[6] = value
                        elif field == 'owner':
                            machine.r[7] = value
                        else:
                            machine.put(machine.r[5] + bindings.REQUEST_RECEIPT_SEQUENCE,
                                        value, 4)

                m.on_instruction = mutate
                self.assertEqual(m.invoke_register(), (0, 0))
                self.assert_empty_output(m)

    def test_reentrant_sink_at_wrong_depth_cannot_replace_the_captured_pair(self):
        m = self.machine()
        repeated = []

        def repeat(machine, pc):
            if pc != machine.capture_labels['sink_restore'] or repeated:
                return
            repeated.append(True)
            base = fixture.STACK - capture.FRAME
            before = machine.words_at(base + capture.ARMED_TAG, 7)
            registers, hi, lo = machine.r.copy(), machine.hi, machine.lo
            # Reenter only on a separate valid mapped private fixture stack.
            # The negative call receives actual event args, not a recovered row.
            machine.invoke_sink(machine.r[5], sequence=machine.r[18],
                                owner_ticket=machine.r[19],
                                stack=fixture.STACK - 0x1000)
            self.assertEqual(machine.words_at(base + capture.ARMED_TAG, 7), before)
            machine.r[:], machine.hi, machine.lo = registers, hi, lo

        m.on_instruction = repeat
        self.assertEqual(m.invoke_register(), (0, fixture.OUTPUT))
        self.assertEqual(repeated, [True])
        self.assertEqual(m.outwords()[4:7], (1, 1, 1))
        self.assertEqual(len(self.output_writes(m)), 8)

    def test_consumed_frame_cannot_be_reused_by_a_later_direct_sink(self):
        m = self.machine()
        self.assertEqual(m.invoke_register(), (0, fixture.OUTPUT))
        before = m.outwords()
        pair = before[4:6]
        m.write_request(m.issue_requests[-1])
        m.clear_events()
        actual_sink_sp = (fixture.STACK - capture.FRAME - capture.NATIVE_FRAME
                          - fixture.receipt.FRAME - bindings.FRAME)
        m.invoke_sink(sequence=pair[0], owner_ticket=pair[1],
                      stack=actual_sink_sp)
        self.assertEqual(m.outwords(), before)
        self.assertEqual(self.output_writes(m), [])

    def test_missing_fresh_receipt_cannot_export_a_previous_same_stack_pair(self):
        m = self.machine()
        self.assertEqual(m.invoke_register(), (0, fixture.OUTPUT))
        before = m.outwords()
        for pc in (0x438A58, 0x438A5C):
            m.patches.pop(pc, None)
        second = fixture.OUTPUT + capture.OUTPUT_BYTES
        m.clear_events()
        self.assertEqual(m.invoke_register(output=second), (0, 0))
        self.assert_empty_output(m, second)
        self.assertEqual(m.outwords(), before)
        self.assertEqual(m.binding_header()[0], 1)

    def test_runtime_source_output_and_frame_aliases_deny_without_native_action(self):
        protected = (fixture.STATE, fixture.BIND_STATE, fixture.OWNER_STATE,
                     fixture.CONTROLLER, fixture.REGISTRY_MUTEX,
                     fixture.PAINT_MUTEX, 0x4389E0,
                     fixture.CODE, fixture.CODE + 4)
        for address in protected:
            for field in ('descriptor', 'output', 'stack'):
                with self.subTest(address=address, field=field):
                    m = self.machine()
                    arguments = {field: address + capture.FRAME
                                 if field == 'stack' else address}
                    self.assertEqual(m.invoke_register(**arguments), (fixture.MASK, 0))
                    self.assertEqual(m.native_entries, [])
                    self.assertEqual(m.raw_events, [])
                    self.assertEqual(m.writes, [])

    def test_source_output_and_private_frame_cannot_overlap_each_other(self):
        for arguments in ({'output': fixture.INPUT + 16},
                          {'output': fixture.STACK - capture.FRAME},
                          {'descriptor': fixture.STACK - capture.FRAME + 8}):
            with self.subTest(arguments=arguments):
                m = self.machine()
                self.assertEqual(m.invoke_register(**arguments), (fixture.MASK, 0))
                self.assertEqual(m.native_entries, [])
                self.assertEqual(m.writes, [])

    def test_complete_rx_and_private_state_tails_are_excluded_not_only_their_starts(self):
        prototype = self.machine()
        extents = ((fixture.CODE, len(prototype.code)),
                   (fixture.STATE, prototype.composition['receipt_memory_bytes']),
                   (fixture.BIND_STATE, prototype.composition['binding_memory_bytes']),
                   (fixture.OWNER_STATE, prototype.composition['owner_memory_bytes']),
                   (fixture.CONTROLLER, capture.receipt.CONTROLLER_BYTES),
                   (fixture.REGISTRY_MUTEX, capture.receipt.MUTEX_BYTES),
                   (fixture.PAINT_MUTEX, capture.receipt.MUTEX_BYTES),
                   (capture.receipt.NATIVE_RX[0],
                    capture.receipt.NATIVE_RX[1] - capture.receipt.NATIVE_RX[0]))
        for start, length in extents:
            for field in ('descriptor', 'output', 'stack'):
                with self.subTest(start=start, length=length, field=field):
                    m = self.machine()
                    address = start + length - (8 if field == 'stack' else 4)
                    arguments = {field: address + capture.FRAME
                                 if field == 'stack' else address}
                    self.assertEqual(m.invoke_register(**arguments), (fixture.MASK, 0))
                    self.assertEqual(m.native_entries, [])
                    self.assertEqual(m.writes, [])

    def test_owned_output_exactly_adjacent_to_full_rx_extent_is_not_an_overlap(self):
        for side in ('before', 'after'):
            with self.subTest(side=side):
                m = self.machine()
                output = (fixture.CODE - capture.OUTPUT_BYTES if side == 'before'
                          else fixture.CODE + len(m.code))
                m.map(output, capture.OUTPUT_BYTES)
                self.assertEqual(m.invoke_register(output=output), (0, output))
                self.assertEqual(m.outwords(output)[4:7], (1, 1, 1))

    def test_invalid_stack_extents_and_wrapping_arguments_deny_before_stores(self):
        for arguments in ({'stack': 0}, {'stack': capture.FRAME - 8},
                          {'stack': fixture.STACK + 4},
                          {'descriptor': 0xFFFFFFF0},
                          {'output': 0xFFFFFFF0}):
            with self.subTest(arguments=arguments):
                m = self.machine()
                self.assertEqual(m.invoke_register(**arguments), (fixture.MASK, 0))
                self.assertEqual(m.native_entries, [])
                self.assertEqual(m.writes, [])

    def test_changed_pinned_routes_deny_before_native_or_output_writes(self):
        for offset in (0x13C, 0x148, 0x274, 0x278, 0x284, 0x288):
            with self.subTest(offset=offset):
                m = self.machine()
                m.put(fixture.CONTROLLER + offset, 0x12345678, 4)
                m.clear_events()
                self.assertEqual(m.invoke_register(), (fixture.MASK, 0))
                self.assertEqual(m.native_entries, [])
                self.assert_empty_output(m)

    def test_raw_paint_errors_quarantine_without_export_for_each_status(self):
        for field in ('paint_acquire_result', 'paint_release_result'):
            for status in (1, 22, 0x82, fixture.MASK):
                with self.subTest(field=field, status=status):
                    m = self.machine(**{field: status})
                    self.assertEqual(m.invoke_register(), (0, 0))
                    self.assert_empty_output(m)
                    self.assertEqual(m.binding_header(), (0, 1, status, 0))
                    self.assertEqual(m.owner_state(owner.OWNER_COUNT),
                                     int(field == 'paint_release_result'))

    def test_raw_registry_release_error_cannot_upgrade_historical_flags(self):
        for status in (1, 22, 0x82, fixture.MASK):
            with self.subTest(status=status):
                m = self.machine(release=status)
                boundaries = []

                def at_service(machine, target):
                    if target == fixture.RAW_UNLOCK and machine.r[4] == fixture.REGISTRY_MUTEX:
                        boundaries.append((len(machine.binding_accesses),
                                           len(machine.owner_accesses),
                                           len(machine.journal_accesses)))

                m.on_service = at_service
                self.assertEqual(m.invoke_register(), (0, fixture.OUTPUT))
                self.assertEqual(m.outwords()[1], capture.HISTORICAL_RELEASE_UNOBSERVED)
                self.assertEqual(m.outwords()[4:8], (1, 1, 1, 0))
                self.assertEqual(boundaries, [(len(m.binding_accesses),
                                               len(m.owner_accesses),
                                               len(m.journal_accesses))])
                # Output is independently owned caller memory. No shared
                # quarantine/write follows an uncertain native13C release.

    def test_after_native_return_export_never_reads_generation_tables(self):
        m = self.machine()
        boundaries = []

        def at_return(machine, pc):
            if pc == machine.capture_labels['native_return']:
                boundaries.append((len(machine.binding_accesses),
                                   len(machine.owner_accesses),
                                   len(machine.journal_accesses)))

        m.on_instruction = at_return
        self.assertEqual(m.invoke_register(), (0, fixture.OUTPUT))
        self.assertEqual(boundaries, [(len(m.binding_accesses),
                                       len(m.owner_accesses),
                                       len(m.journal_accesses))])
        self.assertEqual(m.captured_carriers, [])

    def test_owned_old_output_survives_equal_engine_replacement_but_not_retirement(self):
        m = self.machine()
        self.assertEqual(m.invoke_register(), (0, fixture.OUTPUT))
        first = m.outwords()
        old = first[4:6]
        self.assertEqual(m.retire(old[1]), (1, 0))
        second = fixture.OUTPUT + capture.OUTPUT_BYTES
        self.assertEqual(m.invoke_register(output=second), (0, second))
        new = m.outwords(second)[4:6]
        self.assertNotEqual(old, new)
        self.assertEqual(m.outwords(), first)
        # Positive producer calls explicitly trust this fixture's real-zero
        # services, not the exported RELEASE_UNOBSERVED flag as a lease.
        self.assertEqual(m.publish_payload(old), (0, 0))
        self.assertGreater(m.publish_payload(new)[0], new[1])
        self.assertEqual(m.captured_carriers, [])

    def test_failed_native_and_sink_denial_preserve_callee_saved_abi(self):
        for failure in ('allocation', 'sink'):
            with self.subTest(failure=failure):
                m = self.machine()
                saved = {r: 0x77400000 + r for r in (*range(16, 24), 28, 30)}
                for register, value in saved.items():
                    m.r[register] = value
                m.hi, m.lo = 0x1234ABCD, 0x76543210
                if failure == 'allocation':
                    m.fail_allocation = True
                else:
                    def mutate(machine, pc):
                        if pc == machine.capture_labels['sink']:
                            machine.r[6] = 0
                    m.on_instruction = mutate
                self.assertEqual(m.invoke_register(),
                                 (fixture.MASK if failure == 'allocation' else 0, 0))
                self.assertEqual({r: m.r[r] for r in saved}, saved)
                self.assertEqual((m.r[29], m.r[31]), (fixture.STACK, fixture.RETURN))
                self.assertEqual((m.hi, m.lo), (0x1234ABCD, 0x76543210))

    def test_closed_faulted_or_quarantined_instance_never_exports_a_new_pair(self):
        for address in (fixture.OWNER_STATE + owner.CLOSED,
                        fixture.OWNER_STATE + owner.FAULT,
                        fixture.BIND_STATE + bindings.QUARANTINE):
            with self.subTest(address=address):
                m = self.machine()
                m.put(address, 1, 4)
                m.clear_events()
                self.assertEqual(m.invoke_register(), (0, 0))
                self.assert_empty_output(m)
                self.assertEqual(m.binding_header()[0], 0)

    def test_a_different_valid_armed_frame_cannot_receive_this_invocations_pair(self):
        m = self.machine()
        original = fixture.STACK - capture.FRAME
        foreign = fixture.STACK - 0x1000
        seen = []

        def replace_context(machine, pc):
            if pc != machine.capture_labels['sink']:
                return
            copied = machine.words_at(original, capture.FRAME // 4)
            for index, word in enumerate(copied):
                machine.put(foreign + index * 4, word, 4)
            machine.put(machine.r[5] + bindings.REQUEST_NATIVE_SP,
                        foreign - capture.NATIVE_FRAME, 4)
            seen.append((len(machine.reads), len(machine.writes), copied))

        m.on_instruction = replace_context
        self.assertEqual(m.invoke_register(), (0, 0))
        self.assertEqual(len(seen), 1)
        reads, writes, copied = seen[0]
        self.assertFalse(any(foreign <= address < foreign + capture.FRAME
                             for address, _ in m.reads[reads:]))
        self.assertFalse(any(foreign <= address < foreign + capture.FRAME
                             for address, _, _ in m.writes[writes:]))
        self.assertEqual(m.words_at(foreign, capture.FRAME // 4), copied)
        self.assert_empty_output(m)
        # Same U/engine/ARMED and zero capture slots are not enough: the
        # native frame must match this exact receipt/issuer nested stack.

    def test_foreign_identical_request_is_rejected_before_its_memory_is_read(self):
        m = self.machine()
        boundaries = []

        def replace_request(machine, pc):
            if pc != machine.capture_labels['sink']:
                return
            copied = machine.words_at(machine.r[5], bindings.REQUEST_BYTES // 4)
            machine.write_request(copied)
            machine.r[5] = fixture.REQUEST
            boundaries.append((len(machine.reads), len(machine.writes), copied))

        m.on_instruction = replace_request
        self.assertEqual(m.invoke_register(), (0, 0))
        self.assertEqual(len(boundaries), 1)
        reads, writes, copied = boundaries[0]
        end = fixture.REQUEST + bindings.REQUEST_BYTES
        self.assertFalse(any(fixture.REQUEST <= address < end
                             for address, _ in m.reads[reads:]))
        self.assertFalse(any(fixture.REQUEST <= address < end
                             for address, _, _ in m.writes[writes:]))
        self.assertEqual(m.words_at(fixture.REQUEST, len(copied)), copied)
        self.assertEqual(m.binding_header()[0], 1)
        self.assert_empty_output(m)
        # Identical values are not the current issuer's actual owned copy.
        # The pointer must match its exact private snapshot position.

    def test_sink_preserves_every_gpr_and_hilo_on_capture_and_denial(self):
        for denied in (False, True):
            with self.subTest(denied=denied):
                m = self.machine()
                snapshots = []

                def inspect(machine, pc):
                    if pc == machine.capture_labels['sink']:
                        if denied:
                            machine.put(machine.r[5] + bindings.REQUEST_CALLER,
                                        fixture.RETURN, 4)
                        snapshots.append((machine.r[31], machine.r.copy(),
                                          machine.hi, machine.lo))
                    elif snapshots and pc == snapshots[0][0]:
                        _, registers, hi, lo = snapshots[0]
                        self.assertEqual(machine.r, registers)
                        self.assertEqual((machine.hi, machine.lo), (hi, lo))
                        snapshots.append('returned')

                m.on_instruction = inspect
                self.assertEqual(m.invoke_register(),
                                 (0, 0 if denied else fixture.OUTPUT))
                self.assertEqual(len(snapshots), 2)
                self.assertEqual(snapshots[-1], 'returned')

    def test_invalid_commit_callback_descriptors_deny_and_none_keeps_old_bytes(self):
        arguments = (fixture.BIND_STATE, fixture.OWNER_STATE, fixture.CONTROLLER,
                     fixture.REGISTRY_MUTEX, fixture.PAINT_MUTEX,
                     0x1E90000, fixture.CODE)
        for descriptor in ((), (1, 2), [0x1EA0000, 0x1EA0000, 4],
                           (True, 0x1EA0000, 4),
                           (0x1EA0000, 0x1EA0000, True),
                           (0x1EA0001, 0x1EA0000, 8),
                           (0x1EA0004, 0x1EA0000, 4),
                           (0x1EA0000, 0x1EA0000, 0),
                           (0xFFFFFFFC, 0xFFFFFFFC, 8),
                           (fixture.BIND_STATE, fixture.BIND_STATE, 4),
                           (0x4389E0, 0x4389E0, 4),
                           (fixture.CODE, fixture.CODE, 4),
                           (0x1E90000, 0x1E90000, 4)):
            with self.subTest(descriptor=descriptor):
                with self.assertRaises(ValueError):
                    bindings.assemble(*arguments, commit_callback=descriptor)
        self.assertEqual(bindings.assemble(*arguments),
                         bindings.assemble(*arguments, commit_callback=None))
        old = old_creation.assemble(
            fixture.STATE, fixture.BIND_STATE, fixture.OWNER_STATE,
            fixture.CONTROLLER, fixture.REGISTRY_MUTEX, fixture.PAINT_MUTEX,
            fixture.CODE)
        self.assertEqual(len(old['code']), 16216)
        self.assertEqual(hashlib.sha256(old['code']).hexdigest(),
                         'ed9777609d63c0a2b58605d3c33fa11cf04c78861f915439296cdb99292f00bd')

    def test_protected_code_descriptor_requires_exact_tuple_extent_and_full_fragment(self):
        arguments = (fixture.STATE, fixture.BIND_STATE, fixture.OWNER_STATE,
                     fixture.CONTROLLER, fixture.REGISTRY_MUTEX,
                     fixture.PAINT_MUTEX, fixture.CODE)
        for descriptor in ((), (fixture.CODE,), [fixture.CODE, 0x10000],
                           (True, 0x10000), (fixture.CODE, True),
                           (fixture.CODE + 1, 0x10000), (fixture.CODE, 0),
                           (fixture.CODE, 4), (0xFFFFFFFC, 8),
                           (fixture.STATE, 0x100), (0x4389E0, 0x100),
                           (fixture.CODE + 4, 0x10000)):
            with self.subTest(descriptor=descriptor):
                with self.assertRaises(ValueError):
                    capture.assemble(*arguments, protected_code=descriptor)


if __name__ == '__main__':
    unittest.main()
