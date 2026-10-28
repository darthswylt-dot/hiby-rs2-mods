#!/usr/bin/env python3
"""Exact-token historical comparison contracts, never native lifetime proof.

Only the pinned local vendor source supplies native facts. The new consumer
has no native-pointer, painting, cleanup or installer authority; coherent
coverage, retained storage and whole-instance raw-error isolation are premises.
"""

import hashlib
import struct
import unittest

from build_reveal_bridge_diag import b
import reveal_birth_consumer_mips as consumer
import reveal_birth_consumer_stage as stage
import reveal_birth_queue_mips as queue
import reveal_birth_queue_stage as queue_stage
import reveal_registry_lifecycle_mips as lifecycle
import reveal_registry_owner_mips as bindings
import test_reveal_birth_queue_contract as preceding
import test_reveal_deferred_queue_contract as native


ARGS, LIFECYCLE = preceding.ARGS, preceding.LIFECYCLE
Q, T, FAULT = preceding.Q, preceding.T, preceding.FAULT
STAGE_ARGS = preceding.STAGE_ARGS
CORE_ARGS = (*ARGS[:6], LIFECYCLE, 0x1ED0000,
             Q, T, FAULT, 0x1E82000, 0x1E81000)


class BirthConsumerContractTests(unittest.TestCase):
    setUpClass = classmethod(native.DeferredQueueContractTests.setUpClass.__func__)
    words = native.DeferredQueueContractTests.words
    branch = native.DeferredQueueContractTests.branch
    direct = native.DeferredQueueContractTests.direct

    @staticmethod
    def generated_words(code, base, first, last):
        start, end = first - base, last - base
        return struct.unpack('<' + 'I' * ((end - start) // 4), code[start:end])

    def core_words(self, first, last):
        code, labels = consumer.assemble(*CORE_ARGS)
        return self.generated_words(code, CORE_ARGS[7], labels[first], labels[last])

    def test_pinned_raw_mutex_imports_and_forced_zero_facades_remain_distinct(self):
        native.DeferredQueueContractTests.test_raw_endpoints_jump_to_relocated_pthread_lock_and_unlock(self)
        native.DeferredQueueContractTests.test_native_facades_replace_both_actual_raw_results_with_zero(self)
        self.assertEqual((consumer.RAW_LOCK, consumer.RAW_UNLOCK),
                         (0xA5B960, 0xA5B830))

    def test_controller_initializer_and_callbacks_bind_the_pinned_R_helpers(self):
        self.words(0x439A64, [0x3C020043, 0x24427D20, 0xAE020274,
                              0x3C020043, 0x24427DA0, 0x0C119B58,
                              0xAE020278])
        self.words(0x437D28, [0x0C119B68, 0x8C84013C])
        self.words(0x437DA8, [0x0C119B70, 0x8C84013C])
        self.assertEqual((bindings.REGISTRY_LOCK, bindings.REGISTRY_UNLOCK),
                         (0x437D20, 0x437DA0))

    def test_selected_retirement_can_precede_unlocked_unlink_and_is_not_dead(self):
        self.assertEqual((lifecycle.NO_RETIREMENT_OBSERVED,
                          lifecycle.RETIREMENT_SELECTED), (1, 2))
        for selection, unlink in ((0x4E3F18, 0x4E3F48),
                                  (0x51A3B8, 0x51A3E8)):
            with self.subTest(selection=hex(selection)):
                self.words(selection, [0x0320F809, 0])
                self.words(unlink, [0xAC620004])
                self.assertLess(selection + 8, unlink)
        # A later snapshot of either observed state is not current liveness.

    def test_native_get_and_remove_are_extraction_not_completion(self):
        native.DeferredQueueContractTests.test_get_returns_borrowed_head_without_copy_or_lock(self)
        native.DeferredQueueContractTests.test_remove_moves_spare_slots_in_last_live_chunk_not_only_live_bytes(self)
        self.assertEqual(queue.ENVELOPE_BYTES, 84)
        self.assertEqual(9 * queue.ENVELOPE_BYTES, 756)

    def test_BOBS100_preserves_the_exact_BQ84_body_and_appends_only_observations(self):
        self.assertEqual((consumer.ENVELOPE_BYTES, consumer.OUTPUT_BYTES), (84, 100))
        self.assertEqual(consumer.OUTPUT_MAGIC, int.from_bytes(b'BOBS', 'little'))
        self.assertNotEqual(consumer.OUTPUT_MAGIC, queue.READY_MAGIC)
        self.assertEqual((consumer.OBSERVATION_STATE, consumer.RETIREMENT_SITE,
                          consumer.RETIREMENT_SP, consumer.RETIREMENT_CALLER),
                         (84, 88, 92, 96))
        self.assertEqual(consumer.RETIREMENT_CALLER + 4, consumer.OUTPUT_BYTES)

    def test_private_output_and_saved_architecture_fit_the_exact_combined_frames(self):
        self.assertEqual((consumer.FRAME, consumer.COMBINED_FRAME, consumer.PRIVATE),
                         (192, 416, 0x10))
        self.assertEqual(consumer.COMBINED_FRAME, consumer.FRAME + queue.FRAME)
        self.assertEqual(consumer.PRIVATE + consumer.OUTPUT_BYTES, consumer.RESULT)
        self.assertEqual((consumer.RESULT, consumer.RAW, consumer.OUTPUT_PTR,
                          consumer.MATCH, consumer.HI, consumer.LO),
                         (0x74, 0x78, 0x7C, 0x80, 0x84, 0x88))
        offsets = {consumer.RESULT, consumer.RAW, consumer.OUTPUT_PTR,
                   consumer.MATCH, consumer.HI, consumer.LO, *consumer.SAVE.values()}
        self.assertEqual(len(offsets), 17)
        self.assertEqual(consumer.SAVE, {register: 0x8C + index * 4
                                       for index, register in enumerate(
                                           (*range(16, 24), 28, 30, 31))})
        self.assertTrue(all(consumer.RESULT <= offset < consumer.FRAME for offset in offsets))

    def test_only_the_typed_pop_then_fresh_raw_R_services_are_called(self):
        code, labels = consumer.assemble(*CORE_ARGS)
        words = struct.unpack('<' + 'I' * (len(code) // 4), code)
        calls = [((word & 0x3FFFFFF) << 2) for word in words if word >> 26 == 3]
        self.assertEqual(calls, [CORE_ARGS[11], consumer.RAW_LOCK, consumer.RAW_UNLOCK])
        self.assertFalse(any(word >> 26 == 0 and word & 63 == 9 for word in words))
        self.assertLess(labels['before_pop'], labels['after_pop'])
        self.assertLess(labels['after_pop'], labels['before_lock'])
        self.assertLess(labels['history_snapshot_done'], labels['after_release'])
        self.assertLess(labels['after_release'], labels['before_export'])
        for entry in ('dispatch', 'paint', 'query_live', 'unlink', 'free', 'requeue'):
            self.assertNotIn(entry, labels)

    def test_complete_combined_frame_preflight_and_twenty_five_initial_zeros_precede_save(self):
        words = self.core_words('take', 'save_frame')
        self.assertIn(b.i_type(11, 29, 8, consumer.COMBINED_FRAME), words)
        self.assertIn(b.addiu(11, 29, -consumer.COMBINED_FRAME), words)
        self.assertFalse(any(word >> 26 == 43 for word in words))
        initial = self.core_words('output_frame_ok', 'save_frame')
        loads = [word for word in initial if word >> 26 == 35]
        self.assertEqual(loads, [b.lw(8, offset, 5)
                                 for offset in range(0, consumer.OUTPUT_BYTES, 4)])
        saved = self.core_words('save_frame', 'before_pop')
        for offset in range(0, consumer.OUTPUT_BYTES, 4):
            self.assertIn(b.sw(0, consumer.PRIVATE + offset, 29), saved)

    def test_pop_error_and_empty_checks_precede_any_BQ_read_or_R_service(self):
        words = self.core_words('after_pop', 'snapshot_done')
        self.assertEqual(words[0], b.sw(3, consumer.RAW, 29))
        self.assertEqual((words[1] >> 26, (words[1] >> 21) & 31), (5, 3))
        self.assertEqual((words[3] >> 26, (words[3] >> 21) & 31), (4, 2))
        first_read = next(index for index, word in enumerate(words) if word >> 26 == 35)
        self.assertGreater(first_read, 7)
        self.assertFalse(any(word >> 26 == 3 for word in words))
        for offset in (0, queue.TOKEN, queue.CONTROLLER, queue.REGISTRY_MUTEX,
                       queue.CALLER, queue.SITE, queue.STATUS, queue.NATIVE_RESULT,
                       queue.RELEASE_STATUS, queue.ENGINE):
            register = 14 if offset == queue.TOKEN else 8
            self.assertIn(b.lw(register, consumer.PRIVATE + offset, 29), words)
        self.assertEqual({(word >> 21) & 31 for word in words
                          if word >> 26 in (32, 33, 35, 36, 37, 40, 41, 43)}, {29})

    def test_fresh_R_error_branches_before_controller_or_history_reads(self):
        words = self.core_words('after_lock', 'history_admitted')
        self.assertEqual(words[0], b.sw(2, consumer.RAW, 29))
        self.assertEqual((words[1] >> 26, (words[1] >> 21) & 31), (5, 2))
        self.assertEqual(words[2], 0)
        for offset in (0x13C, 0x274, 0x278):
            self.assertIn(b.lw(8, offset, 4), words)
        self.assertFalse(any(word >> 26 == 3 for word in words))

    def test_whole_history_validation_includes_headers_rows_states_uniqueness_and_tail(self):
        header = self.core_words('history_admitted', 'rows')
        for offset in (lifecycle.FAULT, lifecycle.RESERVED0, lifecycle.RESERVED1):
            self.assertIn(b.lw(8, offset, 20), header)
        self.assertIn(b.lw(21, lifecycle.COUNT, 20), header)
        row = self.core_words('rows', 'row_outstanding')
        for offset in (lifecycle.MAGIC, lifecycle.TOKEN, lifecycle.CONTROLLER,
                       lifecycle.MUTEX, lifecycle.SITE, lifecycle.STATUS,
                       lifecycle.RESERVED2, lifecycle.RESERVED3, lifecycle.STATE,
                       lifecycle.RETIREMENT_SITE):
            self.assertIn(b.lw(8, offset, 22), row)
        self.assertIn(b.addiu(9, 0, lifecycle.NO_RETIREMENT_OBSERVED), row)
        self.assertIn(b.ori(9, 9, lifecycle.RETIREMENT_SELECTED), row)
        outstanding = self.core_words('row_outstanding', 'earlier_rows')
        for offset in (lifecycle.RETIREMENT_SITE, lifecycle.RETIREMENT_SP,
                       lifecycle.RETIREMENT_CALLER):
            self.assertIn(b.lw(8, offset, 22), outstanding)
        uniqueness = self.core_words('earlier_rows', 'earlier_rows_done')
        self.assertIn(b.lw(8, lifecycle.STATE, 24), uniqueness)
        self.assertIn(b.lw(8, lifecycle.NODE, 24), uniqueness)
        tail = self.core_words('unused_tail', 'unused_tail_done')
        self.assertIn(b.lw(8, 0, 22), tail)
        self.assertLess(tail.index(b.addiu(19, 19, -1)),
                        tail.index(b.addiu(22, 22, 4)))

    def test_exact_queued_token_selects_one_row_then_every_birth_word_is_compared(self):
        selection = self.core_words('row_done', 'row_next')
        self.assertEqual(selection[0], b.lw(8, consumer.PRIVATE + queue.TOKEN, 29))
        self.assertIn(b.sw(22, consumer.MATCH, 29), selection)
        matching = self.core_words('unused_tail_done', 'selected_match')
        self.assertEqual(matching[0], b.lw(16, consumer.MATCH, 29))
        for offset in range(lifecycle.TOKEN, lifecycle.STATE, 4):
            pair = (b.lw(8, offset, 16), b.lw(9, consumer.PRIVATE + offset, 29))
            self.assertTrue(any(matching[index:index + 2] == pair
                                for index in range(len(matching) - 1)))
        self.assertFalse(any(word >> 26 == 3 for word in matching))

    def test_history_is_never_written_and_only_selected_observation_words_are_copied(self):
        words = self.core_words('history_admitted', 'history_snapshot_done')
        writes = [word for word in words if word >> 26 in (40, 41, 43)]
        self.assertTrue(writes)
        self.assertEqual({(word >> 21) & 31 for word in writes}, {29})
        snapshot = self.core_words('selected_match', 'history_snapshot_done')
        for source, target in ((lifecycle.STATE, consumer.OBSERVATION_STATE),
                               (lifecycle.RETIREMENT_SITE, consumer.RETIREMENT_SITE),
                               (lifecycle.RETIREMENT_SP, consumer.RETIREMENT_SP),
                               (lifecycle.RETIREMENT_CALLER, consumer.RETIREMENT_CALLER)):
            pair = (b.lw(8, source, 16), b.sw(8, consumer.PRIVATE + target, 29))
            self.assertTrue(any(snapshot[index:index + 2] == pair
                                for index in range(len(snapshot) - 1)))
        self.assertNotIn('schema_fault', consumer.assemble(*CORE_ARGS)[1])

    def test_raw_R_release_error_continuation_accesses_only_private_frame(self):
        words = self.core_words('after_release', 'release_succeeded')
        self.assertFalse(any(word >> 26 == 3 for word in words))
        self.assertEqual({(word >> 21) & 31 for word in words
                          if word >> 26 in (32, 33, 35, 36, 37, 40, 41, 43)}, {29})
        self.assertIn(b.sw(2, consumer.RAW, 29), words)
        self.assertIn(b.sw(0, consumer.RESULT, 29), words)

    def test_second_twenty_five_zero_check_precedes_owned_body_and_magic_last(self):
        words = self.core_words('before_export', 'restore')
        first_write = next(index for index, word in enumerate(words)
                           if word >> 26 == 43 and (word >> 21) & 31 == 16)
        for offset in range(0, consumer.OUTPUT_BYTES, 4):
            self.assertIn(b.lw(8, offset, 16), words[:first_write])
        output_offsets = [word & 0xFFFF for word in words
                          if word >> 26 == 43 and (word >> 21) & 31 == 16]
        self.assertEqual(output_offsets, [*range(4, 100, 4), 0])
        for offset in range(4, consumer.OUTPUT_BYTES, 4):
            pair = (b.lw(8, consumer.PRIVATE + offset, 29), b.sw(8, offset, 16))
            self.assertTrue(any(words[index:index + 2] == pair
                                for index in range(len(words) - 1)))
        self.assertFalse(any(word >> 26 == 3 for word in words))
        self.assertEqual({(word >> 21) & 31 for word in words
                          if word >> 26 in (32, 33, 35, 36, 37, 40, 41, 43)},
                         {16, 29})

    def test_default_zero_following_RX_keeps_the_complete_BQ84_composition(self):
        baseline = queue_stage.assemble(*STAGE_ARGS)
        explicit = queue_stage.assemble(*STAGE_ARGS, following_code_bytes=0)
        self.assertEqual(explicit, baseline)
        self.assertEqual(len(baseline['code']), 81344)
        self.assertEqual(hashlib.sha256(baseline['code']).hexdigest(),
                         '95ced6cf23eeda0a1db56f0461d5a5dd331bdc0fa6bfd4b431e937fb799b80d9')

    def test_following_RX_is_strict_and_protected_without_appending_bytes(self):
        baseline = queue_stage.assemble(*STAGE_ARGS)
        extended = queue_stage.assemble(*STAGE_ARGS, following_code_bytes=4)
        self.assertEqual(len(extended['code']), len(baseline['code']))
        self.assertEqual(extended['labels'], baseline['labels'])
        self.assertEqual(extended['coherent_hooks'], baseline['coherent_hooks'])
        self.assertEqual(extended['protected_code_extent'],
                         (ARGS[6], len(extended['code']) + 4))
        self.assertNotEqual(extended['code'], baseline['code'])
        for following in (True, False, None, -4, 1, 2, 3, 1.0, '4', 0x100000000):
            with self.subTest(following=following), self.assertRaises(ValueError):
                queue_stage.assemble(*STAGE_ARGS, following_code_bytes=following)

    def test_all_thirteen_preceding_composition_hashes_are_preserved(self):
        preceding.BirthQueueContractTests.test_all_twelve_preceding_composition_hashes_are_preserved(self)
        baseline = queue_stage.assemble(*STAGE_ARGS)
        self.assertEqual((len(baseline['code']),
                          hashlib.sha256(baseline['code']).hexdigest()),
                         (81344,
                          '95ced6cf23eeda0a1db56f0461d5a5dd331bdc0fa6bfd4b431e937fb799b80d9'))

    def test_strict_historical_capacity_options(self):
        for option in ('capacity', 'lifecycle_capacity', 'owner_capacity'):
            for capacity in (True, False, 0, -1, 1025, 16.0, '16', None):
                with self.subTest(option=option, capacity=capacity), self.assertRaises(ValueError):
                    consumer.assemble(*CORE_ARGS, **{option: capacity})
        for option in ('queue_capacity', 'ticket_limit'):
            for capacity in (True, False, 0, -1, 0x80000000, 16.0, '16', None):
                with self.subTest(option=option, capacity=capacity), self.assertRaises(ValueError):
                    stage.assemble(*STAGE_ARGS, **{option: capacity})
        for capacity in (True, False, 0, -1, 1, 9, 11, 10241, 10250,
                         40.0, '40', None):
            with self.subTest(transport_capacity=capacity), self.assertRaises(ValueError):
                stage.assemble(*STAGE_ARGS, transport_capacity=capacity)

    def test_strict_addresses_reject_boolean_unaligned_wrapping_and_fixed_aliases(self):
        for index in range(len(CORE_ARGS)):
            invalid = (True, False, 0, -4, 1, 0x400000)
            if index != 10:  # Four-byte fault storage may end exactly at2**32.
                invalid += (0xFFFFFFFC,)
            for address in invalid:
                args = list(CORE_ARGS)
                args[index] = address
                with self.subTest(index=index, address=address), self.assertRaises(ValueError):
                    consumer.assemble(*args)
        for index, alias in ((6, Q), (8, T), (8, FAULT), (9, Q), (9, FAULT),
                             (10, Q), (10, T), (11, Q), (12, LIFECYCLE),
                             (11, CORE_ARGS[12]), (12, CORE_ARGS[11]),
                             (11, CORE_ARGS[7]), (12, CORE_ARGS[7])):
            args = list(CORE_ARGS)
            args[index] = alias
            with self.subTest(index=index, alias=alias), self.assertRaises(ValueError):
                consumer.assemble(*args)

    def test_four_byte_fault_has_exact_highest_unsigned_endpoint(self):
        args = list(CORE_ARGS)
        args[10] = 0xFFFFFFFC
        emitted, labels = consumer.assemble(*args)
        baseline, baseline_labels = consumer.assemble(*CORE_ARGS)
        self.assertEqual((len(emitted), labels), (len(baseline), baseline_labels))

    def test_protected_RX_requires_complete_core_and_both_named_external_entries(self):
        for protected in ([], (), (True, 4), (CORE_ARGS[7], True),
                          (CORE_ARGS[7], 0), (CORE_ARGS[7], 3),
                          (CORE_ARGS[7], 4), (CORE_ARGS[11], 4),
                          (CORE_ARGS[12], 4), (0x400000, 0x2000000),
                          (0x1E80000, 0x10000000)):
            with self.subTest(protected=protected), self.assertRaises(ValueError):
                consumer.assemble(*CORE_ARGS, protected_code=protected)
        raw, labels = consumer.assemble(*CORE_ARGS)
        protected = (CORE_ARGS[12], CORE_ARGS[7] + len(raw) - CORE_ARGS[12])
        guarded, guarded_labels = consumer.assemble(*CORE_ARGS, protected_code=protected)
        self.assertEqual((len(raw), labels), (len(guarded), guarded_labels))

    def test_stage_extends_full_RX_through_the_entire_prefix_and_consumer(self):
        result = stage.assemble(*STAGE_ARGS)
        self.assertTrue(result['registry_release_checked'])
        self.assertTrue(result['birth_capture_historical_only'])
        self.assertTrue(result['birth_queue_historical_only'])
        self.assertTrue(result['birth_consumer_historical_only'])
        full = (ARGS[6], len(result['code']))
        self.assertEqual(result['protected_code_extent'], full)
        self.assertEqual(len(result['coherent_hooks']), 16)
        self.assertEqual(set(result['coherent_hooks']),
                         set(queue_stage.assemble(*STAGE_ARGS)['coherent_hooks']))
        tail = result['birth_consumer_code_bytes']
        prefix = result['birth_consumer_prefix_code_bytes']
        self.assertEqual(prefix + tail, len(result['code']))
        self.assertEqual(prefix, 81344)
        self.assertEqual((tail, len(result['code'])), (3700, 85044))
        self.assertEqual(hashlib.sha256(result['code']).hexdigest(),
                         '765759c2a2ee7a29a2f6d7f0b9af90496d4ef0510a5d1fe809c6bb6fbd9db71f')
        labels = result['birth_consumer_labels']
        self.assertEqual(labels['take'], ARGS[6] + prefix)
        self.assertEqual(result['labels']['birth_consumer_take'], labels['take'])
        core_args = (*ARGS[:6], LIFECYCLE, labels['take'], Q, T, FAULT,
                     result['birth_queue_labels']['pop'],
                     result['capture_labels']['native_return'])
        provisional, provisional_labels = consumer.assemble(*core_args)
        guarded, guarded_labels = consumer.assemble(*core_args, protected_code=full)
        self.assertEqual((len(provisional), provisional_labels),
                         (len(guarded), guarded_labels))
        self.assertEqual((len(guarded), guarded_labels), (tail, labels))
        self.assertEqual(guarded, result['code'][prefix:])
        parent = queue_stage.assemble(*STAGE_ARGS, following_code_bytes=tail)
        self.assertEqual(parent['code'], result['code'][:prefix])
        self.assertEqual(parent['protected_code_extent'], full)
        self.assertEqual(parent['coherent_hooks'], result['coherent_hooks'])


if __name__ == '__main__':
    unittest.main()
