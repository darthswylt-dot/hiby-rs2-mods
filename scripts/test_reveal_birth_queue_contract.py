#!/usr/bin/env python3
"""Typed historical-birth FIFO contracts, never live/native-use authority.

The pinned source supplies native width/chunk/copy semantics, not initialized
mutexes, mapped/retained heap ownership, coherent writers or complete lifecycle
coverage. No firmware, native hook, player or network operation is performed.
"""

import hashlib
import struct
import unittest

from build_reveal_bridge_diag import b
import reveal_birth_capture_mips as capture
import reveal_birth_capture_stage as capture_stage
import reveal_birth_queue_mips as queue
import reveal_birth_queue_stage as stage
import reveal_registry_lifecycle_mips as lifecycle
import reveal_registry_lifecycle_stage as lifecycle_stage
import test_reveal_birth_capture_contract as preceding
import test_reveal_deferred_queue_contract as native


ARGS = preceding.ARGS
LIFECYCLE = preceding.LIFECYCLE
Q, T, FAULT = 0x1FF2000, 0x1F20700, 0x1F20800
STAGE_ARGS = (*ARGS, LIFECYCLE, Q, T, FAULT)
CORE_ARGS = (*ARGS[:6], LIFECYCLE, 0x1ED0000,
             Q, T, FAULT, 0x1E81000)


class BirthQueueContractTests(unittest.TestCase):
    setUpClass = classmethod(native.DeferredQueueContractTests.setUpClass.__func__)
    words = native.DeferredQueueContractTests.words
    branch = native.DeferredQueueContractTests.branch
    direct = native.DeferredQueueContractTests.direct

    @staticmethod
    def generated_words(code, base, first, last):
        start, end = first - base, last - base
        return struct.unpack('<' + 'I' * ((end - start) // 4), code[start:end])

    def core_words(self, first, last):
        code, labels = queue.assemble(*CORE_ARGS)
        return self.generated_words(code, CORE_ARGS[7], labels[first], labels[last])

    def test_native_factory_is_dynamic_width_and_rounds_to_ten_slots(self):
        native.DeferredQueueContractTests.test_factory_has_dynamic_width_and_rounds_capacity_to_ten_slots(self)
        self.assertEqual((queue.QUEUE_BYTES, queue.ENVELOPE_BYTES), (56, 84))
        # A separate width84 queue is required; a stock queue is not widened.
        self.words(0x4BAAEC, [0x24040010, 0x0C115B98,
                              0x24050010, 0x10400030, 0xAE02001C])

    def test_native_method_bindings_leave_header_plus_four_uninitialized(self):
        native.DeferredQueueContractTests.test_constructor_binds_methods_without_initializing_header_plus_four(self)
        words = self.core_words('enqueue_after_lock', 'before_append')
        self.assertIn(b.lw(8, 0x10, 11), words)
        self.assertIn(b.lw(8, 0x14, 11), words)
        self.assertIn(b.lw(8, 0x08, 11), words)
        self.assertNotIn(b.lw(8, 4, 11), words)

    def test_native_append_can_grow_and_returns_previous_index_after_copy(self):
        native.DeferredQueueContractTests.test_append_full_boundary_uses_actual_capacity_and_can_enter_growth(self)
        native.DeferredQueueContractTests.test_append_copies_body_before_count_and_returns_previous_index(self)
        words = self.core_words('enqueue_after_lock', 'before_append')
        self.assertIn(b.lw(8, queue.OLD_COUNT, 29), words)
        self.assertIn(b.ori(9, 9, 40), words)
        # The wrapper's equality branch refuses a full queue before APPEND.
        self.assertEqual(words[-1], 0)
        self.assertEqual(words[-2] >> 26, 4)

    def test_native_get_is_borrowed_and_remove_touches_spare_slot_bytes(self):
        native.DeferredQueueContractTests.test_get_returns_borrowed_head_without_copy_or_lock(self)
        native.DeferredQueueContractTests.test_remove_moves_spare_slots_in_last_live_chunk_not_only_live_bytes(self)
        # Count1 still shifts9 spare width84 slots: complete chunk retention
        # is a premise, not only retention of the currently live84 bytes.
        self.assertEqual(9 * queue.ENVELOPE_BYTES, 756)

    def test_raw_mutex_facades_do_not_substitute_for_actual_status(self):
        native.DeferredQueueContractTests.test_raw_endpoints_jump_to_relocated_pthread_lock_and_unlock(self)
        native.DeferredQueueContractTests.test_native_facades_replace_both_actual_raw_results_with_zero(self)
        self.assertEqual((queue.RAW_LOCK, queue.RAW_UNLOCK),
                         (0xA5B960, 0xA5B830))

    def test_BQ84_is_a_separate_type_with_exact_BCAP_body_and_owned_payload(self):
        self.assertEqual((queue.CAPTURE_BYTES, queue.PAYLOAD_BYTES,
                          queue.PAYLOAD, queue.ENVELOPE_BYTES), (48, 36, 48, 84))
        self.assertEqual(queue.READY_MAGIC, int.from_bytes(b'BQ84', 'little'))
        self.assertEqual(queue.CONSUMED_MAGIC, int.from_bytes(b'BCNS', 'little'))
        self.assertNotEqual(queue.READY_MAGIC, capture.OUTPUT_MAGIC)
        self.assertEqual((queue.TOKEN, queue.CONTROLLER, queue.REGISTRY_MUTEX,
                          queue.NODE, queue.ENGINE, queue.NATIVE_SP, queue.CALLER,
                          queue.SITE, queue.STATUS, queue.NATIVE_RESULT,
                          queue.RELEASE_STATUS), tuple(range(4, 48, 4)))
        self.assertEqual(queue.PAYLOAD_ENGINE, 8)

    def test_transport_calls_only_native_FIFO_and_raw_T_not_registry_or_paint(self):
        code, labels = queue.assemble(*CORE_ARGS)
        words = struct.unpack('<' + 'I' * (len(code) // 4), code)
        calls = [((word & 0x3FFFFFF) << 2) for word in words if word >> 26 == 3]
        self.assertEqual(calls, [queue.RAW_LOCK, queue.APPEND,
                                 queue.RAW_LOCK, queue.GET, queue.REMOVE,
                                 queue.RAW_UNLOCK])
        self.assertFalse(any(word >> 26 == 0 and word & 63 == 9 for word in words))
        self.assertLess(labels['enqueue'], labels['pop'])
        self.assertNotIn('dispatch', labels)
        self.assertNotIn('query_live', labels)

    def test_complete_input_snapshot_and_schema_precede_consumption_and_raw_T(self):
        code, labels = queue.assemble(*CORE_ARGS)
        before = self.generated_words(code, CORE_ARGS[7], labels['enqueue'],
                                      labels['enqueue_snapshot_done'])
        for offset in range(0, queue.CAPTURE_BYTES, 4):
            pair = (b.lw(8, offset, 5), b.sw(8, queue.PRIVATE + offset, 29))
            self.assertTrue(any(before[index:index + 2] == pair
                                for index in range(len(before) - 1)))
        for offset in range(0, queue.PAYLOAD_BYTES, 4):
            pair = (b.lw(8, offset, 6),
                    b.sw(8, queue.PRIVATE + queue.PAYLOAD + offset, 29))
            self.assertTrue(any(before[index:index + 2] == pair
                                for index in range(len(before) - 1)))
        self.assertLess(labels['enqueue_snapshot_done'], labels['enqueue_schema_valid'])
        self.assertLess(labels['enqueue_schema_valid'], labels['enqueue_source_consumed'])
        self.assertLess(labels['enqueue_source_consumed'], labels['enqueue_before_lock'])
        consumed = self.generated_words(code, CORE_ARGS[7],
                                        labels['enqueue_schema_valid'],
                                        labels['enqueue_source_consumed'])
        self.assertEqual(consumed[-2:], (b.sw(8, 0, 16), queue.SYNC))

    def test_schema_checks_fixed_provenance_but_does_not_follow_historical_words(self):
        words = self.core_words('enqueue_snapshot_done', 'enqueue_schema_valid')
        offsets = (0, queue.CONTROLLER, queue.REGISTRY_MUTEX, queue.CALLER,
                   queue.SITE, queue.STATUS, queue.NATIVE_RESULT,
                   queue.RELEASE_STATUS, queue.TOKEN, queue.ENGINE,
                   queue.PAYLOAD + queue.PAYLOAD_ENGINE)
        for offset in offsets:
            register = 14 if offset == queue.TOKEN else (
                9 if offset == queue.PAYLOAD + queue.PAYLOAD_ENGINE else 8)
            self.assertIn(b.lw(register, queue.PRIVATE + offset, 29), words)
        self.assertNotIn(b.lw(8, queue.PRIVATE + queue.NODE, 29), words)
        self.assertNotIn(b.lw(8, queue.PRIVATE + queue.NATIVE_SP, 29), words)
        self.assertEqual({(word >> 21) & 31 for word in words
                          if word >> 26 in (32, 33, 35, 36, 37, 40, 41, 43)}, {29})

    def test_pop_copies_every_borrowed_word_before_remove(self):
        code, labels = queue.assemble(*CORE_ARGS)
        words = self.generated_words(code, CORE_ARGS[7], labels['head_output_ok'],
                                     labels['pop_snapshot_done'])
        expected = tuple(word for offset in range(0, queue.ENVELOPE_BYTES, 4)
                         for word in (b.lw(8, offset, 5),
                                      b.sw(8, queue.PRIVATE + offset, 29)))
        self.assertEqual(words, expected)
        self.assertLess(labels['pop_snapshot_done'], labels['pop_schema_valid'])
        self.assertEqual(labels['pop_schema_valid'], labels['before_remove'])
        self.assertLess(labels['after_remove'], labels['before_release'])

    def test_twenty_one_zero_words_precede_save_and_second_check_precedes_export(self):
        code, labels = queue.assemble(*CORE_ARGS)
        initial = self.generated_words(code, CORE_ARGS[7], labels['pop'],
                                       labels['pop_before_lock'])
        first_save = initial.index(b.sw(16, queue.SAVE[16], 29))
        for offset in range(0, queue.ENVELOPE_BYTES, 4):
            self.assertIn(b.lw(8, offset, 5), initial[:first_save])
        export = self.generated_words(code, CORE_ARGS[7], labels['before_export'],
                                      labels['restore'])
        first_write = next(index for index, word in enumerate(export)
                           if word >> 26 == 43 and (word >> 21) & 31 == 16)
        for offset in range(0, queue.ENVELOPE_BYTES, 4):
            self.assertIn(b.lw(8, offset, 16), export[:first_write])
        output_offsets = [word & 0xFFFF for word in export
                          if word >> 26 == 43 and (word >> 21) & 31 == 16]
        self.assertEqual(output_offsets, [*range(4, 84, 4), 0])
        self.assertFalse(any(word >> 26 == 3 for word in export))
        self.assertEqual({(word >> 21) & 31 for word in export
                          if word >> 26 in (32, 33, 35, 36, 37, 40, 41, 43)},
                         {16, 29})

    def test_release_error_continuation_accesses_only_private_frame(self):
        words = self.core_words('after_release', 'release_succeeded')
        self.assertFalse(any(word >> 26 == 3 for word in words))
        self.assertEqual({(word >> 21) & 31 for word in words
                          if word >> 26 in (32, 33, 35, 36, 37, 40, 41, 43)}, {29})
        self.assertIn(b.sw(0, queue.RESULT, 29), words)
        self.assertIn(b.sw(2, queue.RAW, 29), words)

    def test_transport_storage_offsets_fit_private_frame(self):
        self.assertEqual((queue.FRAME, queue.PRIVATE), (224, 0x10))
        self.assertEqual(queue.PRIVATE + queue.ENVELOPE_BYTES, queue.RESULT)
        offsets = {queue.RESULT, queue.RAW, queue.OLD_COUNT, queue.REMOVED,
                   queue.OUTPUT_PTR, queue.HI, queue.LO, *queue.SAVE.values()}
        self.assertEqual(len(offsets), 18)
        self.assertTrue(all(queue.RESULT <= offset < queue.FRAME for offset in offsets))

    def test_strict_native_capacity_and_historical_capacity_options(self):
        for capacity in (True, False, 0, -1, 1, 9, 11, 10241, 10250,
                         40.0, '40', None):
            with self.subTest(capacity=capacity), self.assertRaises(ValueError):
                queue.assemble(*CORE_ARGS, transport_capacity=capacity)
        for option in ('capacity', 'lifecycle_capacity', 'owner_capacity'):
            for capacity in (True, False, 0, -1, 1025, 16.0, '16', None):
                with self.subTest(option=option, capacity=capacity), self.assertRaises(ValueError):
                    queue.assemble(*CORE_ARGS, **{option: capacity})

    def test_stage_rejects_invalid_transport_extents_and_signed_options(self):
        for index in (8, 9, 10):
            invalid_addresses = (True, False, 0, -4, 1, 0x400000,
                                 ARGS[0], ARGS[3], ARGS[4], LIFECYCLE)
            if index != 10:  # The four-byte fault may end exactly at2**32.
                invalid_addresses += (0xFFFFFFFC,)
            for address in invalid_addresses:
                args = list(STAGE_ARGS)
                args[index] = address
                with self.subTest(index=index, address=address), self.assertRaises(ValueError):
                    stage.assemble(*args)
        for index, address in ((8, T), (8, FAULT), (9, Q), (9, FAULT), (10, Q), (10, T)):
            args = list(STAGE_ARGS)
            args[index] = address
            with self.subTest(index=index, alias=address), self.assertRaises(ValueError):
                stage.assemble(*args)
        for option in ('queue_capacity', 'ticket_limit'):
            for value in (True, False, 0, -1, 0x80000000, 1.0, '16', None):
                with self.subTest(option=option, value=value), self.assertRaises(ValueError):
                    stage.assemble(*STAGE_ARGS, **{option: value})

    def test_strict_data_and_native_return_addresses(self):
        for index in (6, 7, 8, 9, 10, 11):
            invalid_addresses = (True, False, 0, -4, 1, 0x400000,
                                 ARGS[0], ARGS[3], ARGS[4])
            if index != 10:  # Larger extents wrap; native RX labels leave region.
                invalid_addresses += (0xFFFFFFFC,)
            for address in invalid_addresses:
                args = list(CORE_ARGS)
                args[index] = address
                with self.subTest(index=index, address=address), self.assertRaises(ValueError):
                    queue.assemble(*args)

    def test_highest_aligned_four_byte_fault_has_a_valid_exact_unsigned_endpoint(self):
        args = list(CORE_ARGS)
        args[10] = 0xFFFFFFFC
        emitted, labels = queue.assemble(*args)
        baseline, baseline_labels = queue.assemble(*CORE_ARGS)
        self.assertEqual((len(emitted), labels), (len(baseline), baseline_labels))
        stage_args = list(STAGE_ARGS)
        stage_args[10] = 0xFFFFFFFC
        result = stage.assemble(*stage_args)
        baseline_stage = stage.assemble(*STAGE_ARGS)
        self.assertEqual(len(result['code']), len(baseline_stage['code']))
        self.assertEqual(result['coherent_hooks'], baseline_stage['coherent_hooks'])

    def test_strict_protected_RX_contains_whole_core_and_named_native_return(self):
        for protected in ([], (), (True, 4), (0x1ED0000, True),
                          (0x1ED0000, 0), (0x1ED0000, 3),
                          (0x1ED0000, 4), (0x1E81000, 4),
                          (0x400000, 0x2000000), (0x1E80000, 0x10000000)):
            with self.subTest(protected=protected), self.assertRaises(ValueError):
                queue.assemble(*CORE_ARGS, protected_code=protected)
        raw, labels = queue.assemble(*CORE_ARGS)
        protected = (CORE_ARGS[11], CORE_ARGS[7] + len(raw) - CORE_ARGS[11])
        guarded, guarded_labels = queue.assemble(*CORE_ARGS, protected_code=protected)
        self.assertEqual((len(raw), labels), (len(guarded), guarded_labels))

    def test_parent_following_RX_options_are_strict_and_empty_preserves_defaults(self):
        for parent in (capture_stage, lifecycle_stage):
            baseline = parent.assemble(*ARGS, LIFECYCLE)
            explicit = parent.assemble(*ARGS, LIFECYCLE,
                                       following_code_bytes=0, extra_protected_data=())
            self.assertEqual(explicit, baseline)
            extended = parent.assemble(*ARGS, LIFECYCLE, following_code_bytes=4)
            self.assertEqual(len(extended['code']), len(baseline['code']))
            self.assertEqual(extended['labels'], baseline['labels'])
            self.assertEqual(extended['protected_code_extent'],
                             (ARGS[6], len(extended['code']) + 4))
            for following in (True, False, None, -4, 2, 1.0, '4', 0x100000000):
                with self.subTest(parent=parent.__name__, following=following), self.assertRaises(ValueError):
                    parent.assemble(*ARGS, LIFECYCLE, following_code_bytes=following)
            for extra in ([], ((True, 4),), ((Q, True),), ((Q, 0),),
                          ((Q, 2),), ((Q + 1, 4),), ((ARGS[0], 4),),
                          ((0x400000, 4),), ((Q, 4), (Q, 4))):
                with self.subTest(parent=parent.__name__, extra=extra), self.assertRaises(ValueError):
                    parent.assemble(*ARGS, LIFECYCLE, extra_protected_data=extra)

    def test_stage_protects_exact_full_RX_and_reproduces_two_pass_core(self):
        result = stage.assemble(*STAGE_ARGS)
        full = (ARGS[6], len(result['code']))
        self.assertEqual(result['protected_code_extent'], full)
        self.assertTrue(result['registry_release_checked'])
        self.assertEqual(len(result['coherent_hooks']), 16)
        tail_bytes = result['birth_queue_code_bytes']
        prefix_bytes = len(result['code']) - tail_bytes
        self.assertEqual((prefix_bytes, tail_bytes, len(result['code'])),
                         (74724, 6620, 81344))
        self.assertEqual(hashlib.sha256(result['code']).hexdigest(),
                         '95ced6cf23eeda0a1db56f0461d5a5dd331bdc0fa6bfd4b431e937fb799b80d9')
        labels = result['birth_queue_labels']
        self.assertEqual(labels['enqueue'], ARGS[6] + prefix_bytes)
        core_args = (*ARGS[:6], LIFECYCLE, labels['enqueue'], Q, T, FAULT,
                     result['capture_labels']['native_return'])
        provisional, provisional_labels = queue.assemble(*core_args)
        guarded, guarded_labels = queue.assemble(*core_args, protected_code=full)
        self.assertEqual((len(provisional), provisional_labels),
                         (len(guarded), guarded_labels))
        self.assertEqual((len(guarded), guarded_labels), (tail_bytes, labels))
        self.assertEqual(guarded, result['code'][prefix_bytes:])
        prefix = capture_stage.assemble(
            *ARGS, LIFECYCLE, following_code_bytes=tail_bytes,
            extra_protected_data=((Q, queue.QUEUE_BYTES), (T, queue.MUTEX_BYTES),
                                  (FAULT, 4)))
        self.assertEqual(prefix['code'], result['code'][:prefix_bytes])
        self.assertEqual(prefix['protected_code_extent'], full)
        self.assertEqual(prefix['coherent_hooks'], result['coherent_hooks'])

    def test_all_twelve_preceding_composition_hashes_are_preserved(self):
        preceding.BirthCaptureContractTests.test_omitted_callback_preserves_core_and_all_eleven_prior_compositions(self)
        result = capture_stage.assemble(*ARGS, LIFECYCLE)
        self.assertEqual(len(result['code']), 65796)
        self.assertEqual(hashlib.sha256(result['code']).hexdigest(),
                         '76a95966f8e35f8053408b9a7cd0c472cabd0fed53ea9f1234af261a07331cb7')


if __name__ == '__main__':
    unittest.main()
