#!/usr/bin/env python3
"""Native counterexamples: a historical BIRTH link is not a payload lease.

Use the existing ActionLinkMachine without changing its code or production
hooks. Original ELF list constructors/copy/move/removal, action selection and
fanout, explorer, paint getter/consumer, redraw wrapper and four BIRTH input
loads execute. Registry/name lookup, memory/mutex services and scheduling are
the predecessor's explicit bounded stubs. The native worker stops after its
documented drain/exit; no device, full scheduler or concurrent lifetime is
modelled. Mutations are deterministic fixture interleavings, not a claim that
each one occurs on hardware. Nested removals execute the actual native method.
The purge-specific subclass also executes439780/4396C0 and its actual13C
mutex callbacks; string comparison and registry-node cleanup are explicit
bounded services. Injecting purge while148 is held explores a lock-protocol
counterexample, not native scheduling or simultaneous-thread reachability.

The renderer is not consumed here: the native rectangle copy/queued BIRTH and
the strict combined owned-buffer decoder are enough to expose this boundary.
All currentness, coherent-payload, retained-record and UI flags stay false.
"""

import unittest

import decode_reveal_action_link as action_decoder
import decode_reveal_action_link_stage as combined_decoder
import decode_reveal_queue_birth as birth_decoder
import reveal_action_link_mips as core
import test_reveal_action_link_stage as prior


ORIGINAL, REPLACEMENT = (1, 16, 8, 8), (101, 202, 303, 404)
LOADS = (0x8B42C4, 0x8B42C8, 0x8B42CC, 0x8B42D0)
PURGE_LOCK = 0x1F20400


class PurgeMachine(prior.ActionLinkMachine):
    """Execute the inspected purge, without simulating native node lifetime."""

    def __init__(self, image, meta):
        super().__init__(image, meta)
        self.purge_locked = False
        self.purge_lock_events, self.purge_cleanup = [], []
        self.put(prior.CONTROLLER + 0x13C, PURGE_LOCK, 4)
        self.put(prior.CONTROLLER + 0x274, 0x437D20, 4)
        self.put(prior.CONTROLLER + 0x278, 0x437DA0, 4)

    def string(self, address):
        data = bytearray()
        for index in range(64):
            value = self.peek(address + index, 1)
            if not value:
                return bytes(data)
            data.append(value)
        raise AssertionError('unterminated bounded purge name')

    def external(self, target):
        if target in (0x437D20, 0x437DA0, 0x4396C0):
            self.calls.append(target)
            self.run_at(target, self.r[31])
            return
        if target in (0x466DA0, 0x466DC0) and self.r[4] == PURGE_LOCK:
            acquiring = target == 0x466DA0
            if self.purge_locked == acquiring:
                raise AssertionError('unpaired native purge mutex')
            self.purge_locked = acquiring
            self.purge_lock_events.append((acquiring, self.paint_locked, self.r[31]))
            # Keep the predecessor's actual mutex-service log and hostile ABI.
            super().external(target)
            return
        if target == 0xA5B600:
            if self.r[31] not in (0x4397F0, 0x439718):
                raise AssertionError('unexpected purge comparison site')
            self.calls.append(target)
            left, right = self.string(self.r[4]), self.string(self.r[5])
            self.hostile_result((left > right) - (left < right))
            return
        if target == 0x8B0760:
            # Registry cleanup is intentionally not a node destructor or lease.
            self.calls.append(target)
            self.purge_cleanup.append(tuple(self.r[4:6]))
            self.hostile_result(0)
            return
        super().external(target)


class RevealPaintPayloadNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        prior.RevealActionLinkStageTests.setUpClass()
        cls.fixture = prior.RevealActionLinkStageTests()

    def machine(self, **options):
        return self.fixture.machine(**options)

    def purge_machine(self):
        return PurgeMachine(self.fixture.image, self.fixture.meta)

    @staticmethod
    def nested_stock(machine, target, *arguments):
        # A separately scheduled native operation uses the producer stack,
        # never the suspended consumer's frame or partially loaded registers.
        registers, hi, lo, pc = machine.r.copy(), machine.hi, machine.lo, machine.pc
        try:
            return machine.stock(target, *arguments)
        finally:
            machine.r, machine.hi, machine.lo, machine.pc = registers, hi, lo, pc

    def prepared(self, *, count=1, **options):
        machine = self.machine(**options)
        for _ in range(count):
            machine.post()
        machine.dispatch_actions()
        record = machine.element(machine.paint_list)
        self.assertEqual(machine.words_at(record + 0xC, 4), ORIGINAL)
        machine.read_events.clear()
        machine.trace.clear()
        return machine, record

    @staticmethod
    def write_rect(machine, record, values=REPLACEMENT):
        for index, value in enumerate(values):
            machine.put(record + 0xC + index * 4, value, 4)

    def at_instruction(self, machine, site, mutation):
        hits = []

        def observe(pc):
            if pc == site and not hits:
                self.assertFalse(machine.paint_locked)
                hits.append(pc)
                mutation(machine)

        machine.on_instruction = observe
        return hits

    def after_unlock(self, machine, mutation):
        hits = []

        def mutate(observed):
            self.assertFalse(observed.paint_locked)
            self.assertTrue(observed.paint_getter_active)
            hits.append(0x4399F8)
            # Disable before invoking any nested native removal/unlock.
            observed.after_paint_unlock = None
            mutation(observed)

        machine.after_paint_unlock = mutate
        return hits

    def combined(self, machine):
        return combined_decoder.decode(
            machine.memory(machine.meta['buffer'], machine.meta['memory_bytes']),
            **{name: machine.meta[name] for name in prior.CAPACITIES})

    def births(self, machine):
        return birth_decoder.decode(machine.raw_birth(), capacity=machine.meta['birth_capacity'])

    def assert_no_authority(self, result):
        for flag in action_decoder.AUTHORITY_FLAGS:
            self.assertIs(result[flag], False, flag)
        if 'decision' in result:
            self.assertEqual(result['decision'], 'deny')
        for flag in ('native_record_lease_proven', 'native_payload_coherence_proven',
                     'source_playback_identity_proven', 'universal_playback_coverage_proven'):
            if flag in result:
                self.assertIs(result[flag], False, flag)

    def assert_valid_history(self, machine, *, associated=True):
        result = self.combined(machine)
        self.assert_no_authority(result)
        observed = result['action_link_observation']
        self.assert_no_authority(observed)
        self.assertEqual(result['historical_notification_birth_associated'], associated)
        self.assertFalse(result['historical_notification_renderer_associated'])
        self.assertFalse(result['playback_identity_proven'])
        for association in result['notification_birth_associations']:
            self.assert_no_authority(association)
        for request in result['queue_birth_observation']['requests']:
            self.assert_no_authority(request)
        return result

    def assert_native_copy(self, machine, expected, *, flags_before=None, metadata=0):
        self.assertEqual(len(machine.queue()), 1)
        payload = machine.queue()[0][1]
        self.assertEqual(machine.quad(payload[0]), expected)
        self.assertEqual(payload[1], metadata)
        self.assertEqual(machine.count(machine.paint_list), 0)
        self.assertFalse(machine.action_locked or machine.paint_locked)
        self.assertEqual(machine.r[29], prior.CONSUMER_STACK)
        if flags_before is not None:
            self.assertEqual(machine.peek(prior.NODE + 0x3C), flags_before)

    def geometry_case(self, site, expected):
        machine, record = self.prepared()
        flags_before = machine.peek(prior.NODE + 0x3C)
        hit = self.at_instruction(machine, site,
                                  lambda observed: self.write_rect(observed, record))
        machine.process_paint()
        self.assertEqual(hit, [site])
        self.assert_native_copy(machine, expected, flags_before=flags_before)
        result = self.assert_valid_history(machine)
        events = result['action_link_observation']['events']
        self.assertEqual([event['kind'] for event in events], list(range(1, 7)))
        self.assertEqual(events[-1]['birth'], 1)
        self.assertEqual(events[-2]['parent'], 4)
        self.assertEqual(events[-1]['input'], record + 0xC)
        self.assertEqual([event['metadata'] for event in self.births(machine)['events']], [0, 0, 0])
        return machine, record, result

    def test_unchanged_native_copy_is_only_historical_observation(self):
        machine, _ = self.prepared()
        flags_before = machine.peek(prior.NODE + 0x3C)
        machine.process_paint()
        self.assert_native_copy(machine, ORIGINAL, flags_before=flags_before)
        result = self.assert_valid_history(machine)
        self.assertTrue(result['notification_birth_associations'][0]['observed_source_to_birth_chain'])
        entries = {pc: ra for pc, ra, _, _ in machine.native_entries}
        self.assertEqual(entries[0x459840], 0x43C970)
        self.assertEqual(entries[0x8B4280], 0x45987C)
        self.assertEqual(entries[0x8B3CC0], 0x8B42F0)

    def test_geometry_change_after_getter_unlock_is_not_inherited_scalar_mismatch(self):
        machine, record = self.prepared()
        flags_before = machine.peek(prior.NODE + 0x3C)
        hits = self.after_unlock(machine, lambda observed: self.write_rect(observed, record))
        machine.process_paint()
        self.assertEqual(len(hits), 1)
        self.assert_native_copy(machine, REPLACEMENT, flags_before=flags_before)
        result = self.assert_valid_history(machine)
        self.assertEqual(result['action_link_observation']['counter'], 6)

    def test_geometry_change_after_actual_birth_precedes_every_input_load(self):
        machine, _, result = self.geometry_case(0x8B4294, REPLACEMENT)
        self.assertLess(machine.trace.index(0x8B4294), machine.trace.index(LOADS[0]))
        self.assertEqual(result['notification_birth_associations'][0]['birth'], 1)

    def test_allocation_return_does_not_freeze_the_borrowed_rectangle(self):
        self.geometry_case(0x8B42B8, REPLACEMENT)

    def test_mutation_at_first_native_lw_copies_four_new_words(self):
        self.geometry_case(LOADS[0], REPLACEMENT)

    def test_mutation_at_second_native_lw_copies_old_x_and_three_new_words(self):
        self.geometry_case(LOADS[1], (ORIGINAL[0], *REPLACEMENT[1:]))

    def test_mutation_at_third_native_lw_copies_two_old_and_two_new_words(self):
        self.geometry_case(LOADS[2], (*ORIGINAL[:2], *REPLACEMENT[2:]))

    def test_mutation_at_fourth_native_lw_copies_three_old_and_new_height(self):
        self.geometry_case(LOADS[3], (*ORIGINAL[:3], REPLACEMENT[3]))

    def test_mutation_after_four_lws_before_first_store_cannot_change_loaded_values(self):
        machine, _, _ = self.geometry_case(0x8B42D4, ORIGINAL)
        self.assertLess(machine.trace.index(LOADS[-1]), machine.trace.index(0x8B42D4))

    def test_mutation_after_first_store_cannot_rewrite_other_loaded_values(self):
        self.geometry_case(0x8B42DC, ORIGINAL)

    def test_change_then_restore_before_first_lw_is_not_detected_or_freshness_proof(self):
        machine, record = self.prepared()
        changed = self.after_unlock(machine, lambda observed: self.write_rect(observed, record))
        restored = self.at_instruction(machine, LOADS[0],
            lambda observed: self.write_rect(observed, record, ORIGINAL))
        machine.process_paint()
        self.assertEqual((len(changed), len(restored)), (1, 1))
        self.assert_native_copy(machine, ORIGINAL)
        self.assert_valid_history(machine)

    def test_postunlock_tail_replacement_never_restamps_parent_even_with_new_geometry(self):
        machine, record = self.prepared()

        def mutate(observed):
            self.write_rect(observed, record)
            observed.put(record + 0x20, 0xFFFFFFFF, 4)

        self.after_unlock(machine, mutate)
        machine.process_paint()
        self.assert_native_copy(machine, REPLACEMENT)
        result = self.assert_valid_history(machine)
        observed = result['action_link_observation']
        self.assertEqual(observed['events'][-2]['parent'], 4)
        self.assertEqual(observed['associations'][0]['source'], 1)

    def test_metadata_mismatch_still_faults_link_while_native_geometry_and_metadata_proceed(self):
        machine, record = self.prepared()

        def mutate(observed):
            self.write_rect(observed, record)
            observed.put(record + 0x1C, 0x12345678, 4)

        self.after_unlock(machine, mutate)
        machine.process_paint()
        self.assert_native_copy(machine, REPLACEMENT, metadata=0x12345678)
        self.assertEqual(machine.peek(machine.meta['action_link_buffer']), core.FAULT)
        with self.assertRaises(ValueError):
            self.combined(machine)
        births = self.births(machine)
        self.assertEqual([event['metadata'] for event in births['events']], [0x12345678] * 3)
        self.assert_no_authority(births)

    def test_engine_mismatch_still_faults_link_without_suppressing_native_call(self):
        machine, record = self.prepared()
        other_engine = 0x2900000
        machine.map(other_engine, 0x54)
        machine.bytes(other_engine, machine.memory(prior.NODE, 0x54))
        machine.extra_engines.add(other_engine)

        def mutate(observed):
            self.write_rect(observed, record)
            observed.put(record + 8, other_engine, 4)

        self.after_unlock(machine, mutate)
        machine.process_paint()
        self.assertEqual(machine.peek(machine.meta['action_link_buffer']), core.FAULT)
        with self.assertRaises(ValueError):
            self.combined(machine)
        births = self.births(machine)
        self.assertEqual([event['engine'] for event in births['events']], [other_engine] * 3)
        self.assertEqual(machine.queue(), [])  # original NODE has no new queued copy
        self.assertEqual(machine.quad(births['events'][1]['copy']), REPLACEMENT)
        self.assertEqual(machine.count(machine.paint_list), 0)
        self.assert_no_authority(births)

    def test_zero_parent_under_lock_cannot_be_repaired_by_geometry_or_pointer_match(self):
        machine, record = self.prepared()
        machine.put(record + 0x20, 0, 4)
        self.after_unlock(machine, lambda observed: self.write_rect(observed, record))
        machine.process_paint()
        self.assert_native_copy(machine, REPLACEMENT)
        result = self.assert_valid_history(machine, associated=False)
        self.assertEqual(result['action_link_observation']['counter'], 4)
        self.assertEqual(result['action_link_observation']['unassociated_births'], [1])

    def test_identical_next_record_moves_into_selected_address_and_is_removed_again(self):
        machine, record = self.prepared(count=2)
        second = machine.element(machine.paint_list, 1)
        self.assertEqual(machine.words_at(record, 8), machine.words_at(second, 8))
        self.assertEqual((machine.peek(record + 32), machine.peek(second + 32)), (5, 8))
        replacements = []

        def remove_head(observed):
            observed.stock(0x439960, prior.CONTROLLER, 0)
            self.assertEqual(observed.count(observed.paint_list), 1)
            self.assertEqual(observed.element(observed.paint_list), record)
            replacements.append(observed.words_at(record, 9))

        self.after_unlock(machine, remove_head)
        machine.process_paint()
        self.assertEqual(replacements[0][-1], 8)
        self.assertEqual(machine.trace.count(0x439960), 2)
        self.assert_native_copy(machine, ORIGINAL)
        result = self.assert_valid_history(machine)
        observed = result['action_link_observation']
        self.assertEqual(observed['events'][-2]['parent'], 5)
        self.assertEqual([(item['source'], item['birth']) for item in observed['associations']], [(1, 1)])
        self.assertEqual(observed['unassociated_sources'], [2])

    def test_different_next_geometry_can_be_consumed_under_the_original_selected_parent(self):
        machine, record = self.prepared(count=2)
        second = machine.element(machine.paint_list, 1)
        self.write_rect(machine, second)
        self.after_unlock(machine,
            lambda observed: observed.stock(0x439960, prior.CONTROLLER, 0))
        machine.process_paint()
        self.assert_native_copy(machine, REPLACEMENT)
        result = self.assert_valid_history(machine)
        self.assertEqual(result['action_link_observation']['events'][-2]['parent'], 5)
        self.assertEqual(result['notification_birth_associations'][0]['source'], 1)
        self.assertEqual(machine.element(machine.paint_list), record)

    def test_actual_native_removal_between_rectangle_lws_copies_torn_two_record_geometry(self):
        for loaded in (1, 2, 3):
            with self.subTest(words_loaded_before_removal=loaded):
                machine, record = self.prepared(count=2)
                self.write_rect(machine, machine.element(machine.paint_list, 1))
                removed = []

                def remove_head(observed):
                    self.nested_stock(observed, 0x439960, prior.CONTROLLER, 0)
                    self.assertEqual(observed.count(observed.paint_list), 1)
                    self.assertEqual(observed.element(observed.paint_list), record)
                    removed.append(observed.words_at(record, 9))

                hits = self.at_instruction(machine, LOADS[loaded], remove_head)
                machine.process_paint()
                expected = (*ORIGINAL[:loaded], *REPLACEMENT[loaded:])
                self.assertEqual(hits, [LOADS[loaded]])
                self.assertEqual(removed[0][-1], 8)
                self.assertEqual(machine.trace.count(0x439960), 2)
                self.assert_native_copy(machine, expected)
                result = self.assert_valid_history(machine)
                self.assertEqual(result['action_link_observation']['events'][-2]['parent'], 5)
                self.assertEqual(result['notification_birth_associations'][0]['source'], 1)
                self.assertEqual(result['action_link_observation']['unassociated_sources'], [2])

    def purge_after_freeze_case(self, *, while_paint_locked):
        machine = self.purge_machine()
        machine.post()
        machine.dispatch_actions()
        record = machine.element(machine.paint_list)
        machine.purge_lock_events.clear()
        hits = []

        def purge(observed):
            self.assertEqual(observed.paint_locked, while_paint_locked)
            self.assertTrue(observed.paint_getter_active)
            # Selection's private parent has already been published, but the
            # native caller has not yet loaded record+8 after getter return.
            before = self.combined(observed)['action_link_observation']['events']
            self.assertEqual(before[-1]['kind'], core.PAINT_DELIVERY)
            self.assertEqual(before[-1]['parent'], 4)
            self.nested_stock(observed, 0x439780, prior.CONTROLLER, prior.gap.NAME)
            self.assertEqual(observed.count(observed.paint_list), 0)
            self.assertEqual(observed.words_at(record, 9), (0,) * 9)
            hits.append(True)

        if while_paint_locked:
            def at_unlock(pc):
                if pc == 0x4399F0 and not hits:
                    purge(machine)
            machine.on_instruction = at_unlock
        else:
            self.after_unlock(machine, purge)
        machine.process_paint()
        self.assertEqual(hits, [True])
        self.assertEqual(machine.purge_lock_events,
                         [(True, while_paint_locked, 0x437D30),
                          (False, while_paint_locked, 0x437DB0)])
        self.assertEqual(machine.purge_cleanup, [(0, prior.NODE)])
        self.assertFalse(machine.purge_locked or machine.paint_locked)
        self.assertEqual(machine.queue(), [])
        self.assertEqual(machine.count(machine.paint_list), 0)
        self.assertEqual(machine.r[29], prior.CONSUMER_STACK)
        for site in (0x439780, 0x4396C0, 0x437D20, 0x437DA0, 0x455900, 0x439960):
            self.assertIn(site, machine.trace)
        self.assertNotIn(0x459840, machine.trace)
        result = self.assert_valid_history(machine, associated=False)
        self.assertEqual([event['kind'] for event in result['action_link_observation']['events']],
                         list(range(1, 6)))
        self.assertEqual(result['action_link_observation']['events'][-1]['parent'], 4)
        self.assertEqual(result['queue_birth_observation']['events'], [])
        return machine

    def test_actual_name_purge_after_getter_unlock_removes_head_not_frozen_parent(self):
        self.purge_after_freeze_case(while_paint_locked=False)

    def test_actual_name_purge_uses13c_while_getter148_is_held_in_bounded_interleaving(self):
        # Feasible lock identities are not evidence of actual thread overlap.
        self.purge_after_freeze_case(while_paint_locked=True)

    def test_empty_list_at_getter_has_no_birth_and_no_stale_parent(self):
        machine = self.machine()
        self.assertEqual(machine.process_paint(), 0)
        self.assertEqual(machine.queue(), [])
        self.assertEqual(machine.count(machine.paint_list), 0)
        result = self.assert_valid_history(machine, associated=False)
        self.assertEqual(result['action_link_observation']['events'], [])
        self.assertEqual(result['queue_birth_observation']['events'], [])
        self.assertNotIn(0x459840, machine.trace)

    def test_engine_becoming_null_after_unlock_removes_head_without_birth(self):
        machine, record = self.prepared()
        self.after_unlock(machine, lambda observed: observed.put(record + 8, 0, 4))
        machine.process_paint()
        self.assertEqual(machine.queue(), [])
        self.assertEqual(machine.count(machine.paint_list), 0)
        result = self.assert_valid_history(machine, associated=False)
        self.assertEqual([event['kind'] for event in result['action_link_observation']['events']],
                         [1, 2, 3, 4, 5])
        self.assertEqual(result['queue_birth_observation']['events'], [])
        self.assertNotIn(0x459840, machine.trace)

    def test_removing_only_head_after_selection_zeroes_engine_and_skips_birth(self):
        machine, record = self.prepared()
        removed, removal_results = [], []
        machine.on_instruction = lambda pc: removal_results.append(machine.r[2]) if pc == 0x43998C else None

        def remove_head(observed):
            observed.stock(0x439960, prior.CONTROLLER, 0)
            removed.append(observed.count(observed.paint_list))

        self.after_unlock(machine, remove_head)
        machine.process_paint()
        self.assertEqual(removed, [0])
        self.assertEqual(machine.trace.count(0x439960), 2)
        self.assertEqual(removal_results, [0, 0xFFFFFFFE])  # actual method rejects the empty second removal
        self.assertEqual(machine.words_at(record, 9), (0,) * 9)
        self.assertEqual(machine.queue(), [])
        self.assertEqual(machine.count(machine.paint_list), 0)
        self.assertFalse(machine.action_locked or machine.paint_locked)
        self.assertEqual(machine.r[29], prior.CONSUMER_STACK)
        self.assertNotIn(0x459840, machine.trace)
        result = self.assert_valid_history(machine, associated=False)
        self.assertEqual([event['kind'] for event in result['action_link_observation']['events']],
                         list(range(1, 6)))
        self.assertEqual(result['queue_birth_observation']['events'], [])

    def test_full_diagnostics_do_not_freeze_geometry_or_suppress_native_removal(self):
        machine, record = self.prepared(action_link_capacity=4)
        self.after_unlock(machine, lambda observed: self.write_rect(observed, record))
        machine.process_paint()
        self.assert_native_copy(machine, REPLACEMENT)
        self.assertEqual(machine.peek(machine.meta['action_link_buffer']), core.FAULT)
        with self.assertRaises(ValueError):
            self.combined(machine)
        self.assert_no_authority(self.births(machine))

    def test_faulted_diagnostics_do_not_freeze_geometry_or_suppress_native_birth(self):
        machine = self.machine()
        machine.put(machine.meta['action_link_buffer'], core.FAULT, 4)
        machine.post()
        machine.dispatch_actions()
        record = machine.element(machine.paint_list)
        self.after_unlock(machine, lambda observed: self.write_rect(observed, record))
        machine.process_paint()
        self.assert_native_copy(machine, REPLACEMENT)
        with self.assertRaises(ValueError):
            self.combined(machine)
        self.assertEqual(len(self.births(machine)['events']), 3)
        self.assert_no_authority(self.births(machine))

    def test_retry_exhaustion_does_not_freeze_geometry_or_suppress_native_birth(self):
        machine = self.machine()
        machine.sc_failures = 8
        machine.post()
        machine.dispatch_actions()
        record = machine.element(machine.paint_list)
        self.after_unlock(machine, lambda observed: self.write_rect(observed, record))
        machine.process_paint()
        self.assert_native_copy(machine, REPLACEMENT)
        self.assertEqual(machine.peek(machine.meta['action_link_buffer']), core.FAULT)
        with self.assertRaises(ValueError):
            self.combined(machine)
        self.assert_no_authority(self.births(machine))

    def test_output_explains_separate_rectangle_loads_and_current_index_removal(self):
        machine, _ = self.prepared()
        machine.process_paint()
        result = self.assert_valid_history(machine)
        for limitations in (result['limitations'], result['action_link_observation']['limitations']):
            text = ' '.join(limitations)
            self.assertIn('after BIRTH', text)
            self.assertIn('rectangle words', text)
            self.assertTrue('torn' in text or 'tear' in text)
            self.assertIn('index zero', text)


if __name__ == '__main__':
    unittest.main()
