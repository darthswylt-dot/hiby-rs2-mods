#!/usr/bin/env python3
"""Pinned exact birth-event handoff; neither liveness nor native authority.

The native source, private invocation shape, explicit post-commit callback and
full RX guards are contracts. Equal historical addresses, a BCAP token or a
healthy observer are not a continuous lifetime proof. No hooks are installed.
"""

import hashlib
import struct
import unittest

from build_reveal_bridge_diag import b
import reveal_birth_capture_mips as capture
import reveal_birth_capture_stage as stage
import reveal_creation_capture_mips as checked
import reveal_registry_birth_stage as birth
import reveal_registry_lifecycle_mips as lifecycle
import reveal_registry_lifecycle_stage as lifecycle_stage
import reveal_registry_receipt_mips as receipt
import test_reveal_registry_birth_contract as previous


ARGS = previous.BASE_ARGS
LIFECYCLE = 0x1F3A000


class BirthCaptureContractTests(unittest.TestCase):
    setUpClass = classmethod(previous.RegistryBirthContractTests.setUpClass.__func__)
    words = previous.RegistryBirthContractTests.words

    @staticmethod
    def generated_words(result, first, last):
        start = first - result['code_base']
        end = last - result['code_base']
        return struct.unpack('<' + 'I' * ((end - start) // 4),
                             result['code'][start:end])

    def test_native_registration_frame_and_final_commit_are_pinned(self):
        self.words(0x4389F0, [0x27BDFFD8, 0xAFBF0024,
                              0xAFB10020, 0xAFB0001C])
        self.words(0x438A48, [0x8E030038, 0xAE020038,
                              0xAC450000, 0xAC430004,
                              0xAC620000, 0x8E190278,
                              0x0320F809, 0x02002021])
        self.assertEqual(checked.NATIVE_REGISTER, 0x4389E0)
        self.assertEqual(checked.NATIVE_FRAME, 40)
        self.assertEqual(lifecycle.PUBLICATION_SITE, 0x438A5C)
        self.assertEqual(receipt.HOOKS['published'],
                         (0x438A58, (0xAC620000, 0x8E190278)))

    def test_raw_release_and_native_forced_zero_are_not_interchangeable(self):
        self.words(0x437DA0, [0x27BDFFE0, 0xAFBF001C,
                              0x0C119B70, 0x8C84013C])
        self.words(0x466DC0, [0x27BDFFE0, 0xAFBF001C,
                              0x0C296E0C, 0,
                              0x8FBF001C, 0x00001021,
                              0x03E00008, 0x27BD0020])
        self.words(0x438A60, [0x0320F809, 0x02002021,
                              0x00001021, 0x8FBF0024])
        self.assertEqual(checked.HOOKS['release_call'][0], 0x438A60)
        self.assertEqual(checked.HOOKS['raw_release_call'][0], 0x466DC8)
        self.assertEqual(checked.HOOKS['raw_release_return'][0], 0x466DD0)

    def test_checked_capture_checks_release_before_optional_GCAP_issuance(self):
        code, labels = checked.assemble(*ARGS, checked_registry_release=True)
        result = dict(code=code, code_base=ARGS[6])
        words = self.generated_words(result, labels['native_return'],
                                     labels['register_restore'])
        # Fresh raw-release capture is consumed before native-zero or issuer
        # fields are considered. A missing owner pair is not a release error.
        self.assertEqual(words[:3],
                         (b.sw(2, checked.NATIVE_RESULT, 29),
                          b.lw(8, checked.RELEASE_TAG, 29),
                          b.sw(0, checked.RELEASE_TAG, 29)))
        self.assertLess(words.index(b.lw(8, checked.RELEASE_STATUS, 29)),
                        words.index(b.lw(8, checked.CAPTURE_MAGIC, 29)))
        restore = self.generated_words(result, labels['register_restore'],
                                       labels['release_failed'])
        self.assertEqual(restore[-5:-3],
                         (b.lw(2, checked.NATIVE_RESULT, 29),
                          b.lw(3, checked.EXPORTED_PTR, 29)))
        before = self.generated_words(result, labels['register'], labels['native_return'])
        self.assertIn(b.sw(0, checked.EXPORTED_PTR, 29), before)

    def test_output_is_separate_BCAP48_not_an_extended_native_descriptor(self):
        self.assertEqual(capture.OUTPUT_MAGIC, int.from_bytes(b'BCAP', 'little'))
        self.assertNotEqual(capture.OUTPUT_MAGIC, checked.OUTPUT_MAGIC)
        self.assertEqual((capture.DESCRIPTOR_BYTES, capture.OUTPUT_BYTES), (20, 48))
        self.assertEqual((capture.OUTPUT_TOKEN, capture.OUTPUT_EVENT,
                          capture.OUTPUT_NATIVE_RESULT, capture.OUTPUT_RELEASE_STATUS),
                         (4, 8, 40, 44))
        self.assertEqual(capture.OUTPUT_EVENT + lifecycle.REQUEST_BYTES, 40)
        self.assertEqual(capture.OUTPUT_RELEASE_STATUS + 4, capture.OUTPUT_BYTES)

    def test_exact_private_nested_invocation_offsets_are_pinned(self):
        self.assertEqual((lifecycle.FRAME, receipt.FRAME, checked.NATIVE_FRAME,
                          checked.FRAME, capture.FRAME), (192, 192, 40, 160, 192))
        self.assertEqual(lifecycle.SNAPSHOT, 0x90)
        self.assertEqual(checked.SAVE[31], 0x70)
        self.assertEqual(checked.OUTPUT_PTR, 0x24)
        self.assertEqual((capture.GCAP, capture.DESCRIPTOR, capture.OUTPUT_PTR,
                          capture.CONTROLLER, capture.TAG, capture.TOKEN,
                          capture.EVENT), (0x10, 0x30, 0x44, 0x48, 0x4C, 0x50, 0x54))
        self.assertEqual(capture.GCAP + checked.OUTPUT_BYTES, capture.DESCRIPTOR)
        self.assertEqual(capture.DESCRIPTOR + checked.DESCRIPTOR_BYTES,
                         capture.OUTPUT_PTR)
        self.assertEqual(capture.EVENT + lifecycle.REQUEST_BYTES,
                         capture.NATIVE_RESULT)
        self.assertEqual(len({capture.ARMED, capture.CONSUMED,
                              capture.CAPTURED, capture.INVALID}), 4)

    def test_birth_sink_has_all_GPR_and_HI_LO_save_slots(self):
        self.assertEqual(capture.SINK_FRAME, 192)
        self.assertEqual(set(capture.SINK_SAVE), set(range(1, 32)) - {29})
        offsets = set(capture.SINK_SAVE.values())
        self.assertEqual(len(offsets), 30)
        self.assertFalse(offsets & {capture.SINK_HI, capture.SINK_LO})
        self.assertTrue(all(0x10 <= offset < capture.SINK_FRAME
                            for offset in (*offsets, capture.SINK_HI,
                                           capture.SINK_LO)))
        self.assertLess(max(capture.SAVE.values()), capture.FRAME)

    def test_optional_callback_runs_after_exact_new_row_and_count_commit(self):
        base, target = 0x1EB0000, 0x1EC0000
        code, labels = lifecycle.assemble(
            LIFECYCLE, ARGS[3], ARGS[4], base,
            birth_commit_callback=(target, target, 4))
        words = struct.unpack('<' + 'I' * (len(code) // 4), code)
        callback_index = (labels['birth_commit_callback'] - base) // 4
        self.assertEqual(words[callback_index - 3:callback_index],
                         (b.sw(8, lifecycle.MAGIC, 22), lifecycle.SYNC,
                          b.sw(21, lifecycle.COUNT, 20)))
        self.assertEqual(words[callback_index:callback_index + 6],
                         (b.lui(4, ARGS[3] >> 16), b.ori(4, 4, ARGS[3] & 0xFFFF),
                          b.addiu(5, 29, lifecycle.SNAPSHOT), b.move(6, 21),
                          b.j_type(3, target), 0))
        self.assertEqual(sum(word == b.j_type(3, target) for word in words), 1)
        retirement_index = (labels['retirement_commit'] - base) // 4
        self.assertLess(callback_index, retirement_index)
        self.assertFalse(any(word >> 26 == 3 for word in words[retirement_index:]))

    def test_omitted_callback_preserves_core_and_all_eleven_prior_compositions(self):
        args = (LIFECYCLE, ARGS[3], ARGS[4], 0x1EB0000)
        code, labels = lifecycle.assemble(*args)
        explicit, explicit_labels = lifecycle.assemble(*args, birth_commit_callback=None)
        self.assertEqual(len(code), 2104)  # Standalone: no four extra data extents.
        self.assertEqual((code, labels), (explicit, explicit_labels))
        self.assertNotIn('birth_commit_callback', labels)
        previous.RegistryBirthContractTests.test_omitted_birth_callback_preserves_all_nine_preceding_compositions(self)
        result = birth.assemble(*ARGS, 0x1F38000)
        self.assertEqual(len(result['code']), 28088)
        self.assertEqual(hashlib.sha256(result['code']).hexdigest(),
                         '0d40bc5bba95d1458af0cd79a7957377a034969fc45ff98fba27c495e3ce07b0')
        result = lifecycle_stage.assemble(*ARGS, LIFECYCLE)
        self.assertEqual(result['lifecycle_code_bytes'], 2488)
        self.assertEqual(len(result['code']), 58572)
        self.assertEqual(hashlib.sha256(result['code']).hexdigest(),
                         'bfdee94f95de5d0b0a861dcfe18bb7ad8980f1a3df1556ae76532cd8c687b974')
        explicit = lifecycle_stage.assemble(
            *ARGS, LIFECYCLE, birth_commit_callback=None, following_code_bytes=0)
        self.assertEqual(result, explicit)

    def test_commit_callback_is_a_strict_disjoint_native_region_RX_tuple(self):
        args = (LIFECYCLE, ARGS[3], ARGS[4], 0x1EB0000)
        for callback in ([], (), (True, 0x1EC0000, 4),
                         (0x1EC0000, True, 4), (0x1EC0000, 0x1EC0000, True),
                         (0x1EC0000, 0x1EC0000, 0),
                         (0x1EC0000, 0x1EC0000, 2),
                         (0x1EC0001, 0x1EC0000, 4),
                         (0x1EC0004, 0x1EC0000, 4),
                         (0x1EC0000, 0x1EC0001, 4),
                         (0xFFFFFFC, 0xFFFFFFC, 8),
                         (0x400000, 0x400000, 4),
                         (LIFECYCLE, LIFECYCLE, 4),
                         (ARGS[3], ARGS[3], 4),
                         (ARGS[4], ARGS[4], 4),
                         (0x1EB0000, 0x1EB0000, 4)):
            with self.subTest(callback=callback), self.assertRaises(ValueError):
                lifecycle.assemble(*args, birth_commit_callback=callback)

    def test_following_RX_length_is_strict_and_not_appended_to_stage_bytes(self):
        for value in (True, False, None, -4, 2, 1.0, '4', 0x100000000):
            with self.subTest(following=value), self.assertRaises(ValueError):
                lifecycle_stage.assemble(*ARGS, LIFECYCLE, following_code_bytes=value)
        baseline = lifecycle_stage.assemble(*ARGS, LIFECYCLE)
        following = lifecycle_stage.assemble(*ARGS, LIFECYCLE, following_code_bytes=4)
        self.assertEqual(len(following['code']), len(baseline['code']))
        self.assertEqual(following['labels'], baseline['labels'])
        self.assertEqual(following['protected_code_extent'],
                         (ARGS[6], len(following['code']) + 4))

    def test_callback_must_fit_exact_advertised_following_tail(self):
        result = stage.assemble(*ARGS, LIFECYCLE)
        tail_bytes = result['birth_capture_code_bytes']
        tail_base = result['birth_capture_labels']['register_birth']
        callback = (result['birth_capture_labels']['birth_sink'], tail_base, tail_bytes)
        prefix = lifecycle_stage.assemble(
            *ARGS, LIFECYCLE, birth_commit_callback=callback,
            following_code_bytes=tail_bytes)
        self.assertEqual(prefix['code'], result['code'][:tail_base - ARGS[6]])
        self.assertEqual(prefix['protected_code_extent'], result['protected_code_extent'])
        for replacement, following in ((callback, 0), (callback, tail_bytes - 4),
                                       ((callback[0], tail_base - 4, tail_bytes + 4),
                                        tail_bytes),
                                       ((callback[0], tail_base, tail_bytes + 4),
                                        tail_bytes)):
            with self.subTest(callback=replacement, following=following), self.assertRaises(ValueError):
                lifecycle_stage.assemble(
                    *ARGS, LIFECYCLE, birth_commit_callback=replacement,
                    following_code_bytes=following)

    def test_new_stage_protects_exact_full_RX_and_reproduces_two_pass_core(self):
        result = stage.assemble(*ARGS, LIFECYCLE)
        self.assertTrue(result['birth_capture_historical_only'])
        self.assertTrue(result['registry_release_checked'])
        self.assertEqual(result['birth_capture_output_bytes'], 48)
        protected = (ARGS[6], len(result['code']))
        self.assertEqual(result['protected_code_extent'], protected)
        prefix_bytes, tail_bytes = (result['birth_capture_prefix_code_bytes'],
                                    result['birth_capture_code_bytes'])
        self.assertEqual(prefix_bytes + tail_bytes, len(result['code']))
        self.assertEqual((prefix_bytes, tail_bytes, len(result['code'])),
                         (58692, 7104, 65796))
        self.assertEqual(hashlib.sha256(result['code']).hexdigest(),
                         '76a95966f8e35f8053408b9a7cd0c472cabd0fed53ea9f1234af261a07331cb7')
        labels = result['birth_capture_labels']
        self.assertEqual(labels['register_birth'], ARGS[6] + prefix_bytes)
        self.assertEqual(result['labels']['birth_capture_birth_sink'], labels['birth_sink'])
        args = (*ARGS[:6], LIFECYCLE, labels['register_birth'],
                result['capture_labels']['register'],
                result['capture_labels']['native_return'])
        provisional, first_labels = capture.assemble(*args)
        guarded, final_labels = capture.assemble(*args, protected_code=protected)
        self.assertEqual(len(provisional), len(guarded))
        self.assertEqual((first_labels, final_labels), (labels, labels))
        self.assertEqual(guarded, result['code'][prefix_bytes:])
        self.assertEqual(len(result['coherent_hooks']), 16)

    def test_explicit_wrapper_calls_checked_capture_once_and_returns_privately(self):
        result = stage.assemble(*ARGS, LIFECYCLE)
        labels = result['birth_capture_labels']
        first = labels['register_birth']
        end = ARGS[6] + len(result['code'])
        words = self.generated_words(result, first, end)
        calls = [word for word in words if word >> 26 == 3]
        self.assertEqual(calls, [b.j_type(3, result['capture_labels']['register'])])
        after = self.generated_words(result, labels['capture_return'], labels['early_denied'])
        self.assertFalse(any(word >> 26 == 3 or
                             (word >> 26 == 0 and word & 63 == 9)
                             for word in after))
        memory_bases = {(word >> 21) & 31 for word in after
                        if word >> 26 in (32, 33, 35, 36, 37, 40, 41, 43)}
        self.assertEqual(memory_bases, {16, 29})
        self.assertEqual(after[:3],
                         (b.sw(2, capture.NATIVE_RESULT, 29),
                          b.sw(3, capture.RETURN_V1, 29),
                          b.i_type(5, 2, 0,
                                   (labels['restore'] - labels['capture_return'] - 12) // 4)))

    def test_initial_and_late_output_guards_check_all_twelve_words(self):
        result = stage.assemble(*ARGS, LIFECYCLE)
        labels = result['birth_capture_labels']
        before = self.generated_words(result, labels['register_birth'], labels['capture_call'])
        first_save = before.index(b.sw(16, capture.SAVE[16], 29))
        self.assertFalse(any(word >> 26 in (40, 41, 43) for word in before[:first_save]))
        for offset in range(0, capture.OUTPUT_BYTES, 4):
            self.assertIn(b.lw(8, offset, 6), before[:first_save])
        after = self.generated_words(result, labels['capture_return'], labels['restore'])
        first_output_write = next(index for index, word in enumerate(after)
                                  if word >> 26 == 43 and (word >> 21) & 31 == 16)
        for offset in range(0, capture.OUTPUT_BYTES, 4):
            self.assertIn(b.lw(8, offset, 16), after[:first_output_write])
        output_stores = [(word & 0xFFFF) for word in after
                         if word >> 26 == 43 and (word >> 21) & 31 == 16]
        self.assertEqual(output_stores, [4, *range(8, 40, 4), 40, 44, 0])

    def test_capture_label_and_protected_RX_configuration_is_strict(self):
        args = (*ARGS[:6], LIFECYCLE, 0x1ED0000, 0x1E81000, 0x1E81004)
        for index in (7, 8, 9):
            for value in (True, False, 0, -4, 1, 0xFFFFFFFC, 0x400000,
                          LIFECYCLE, ARGS[0], ARGS[3], ARGS[4]):
                changed = list(args)
                changed[index] = value
                with self.subTest(index=index, address=value), self.assertRaises(ValueError):
                    capture.assemble(*changed)
        equal_labels = (*args[:9], args[8])
        with self.assertRaises(ValueError):
            capture.assemble(*equal_labels)
        for protected in ([], (True, 4), (0x1ED0000, True),
                          (0x1ED0000, 4), (0x400000, 0x1000000),
                          (0x1E80000, 3), (0x1E80000, 0)):
            with self.subTest(protected=protected), self.assertRaises(ValueError):
                capture.assemble(*args, protected_code=protected)

    def test_new_stage_rejects_invalid_state_addresses_and_capacity_types(self):
        for value in (True, False, 0, -4, 1, 0xFFFFFFFC, 0x400000, *ARGS):
            with self.subTest(address=value), self.assertRaises(ValueError):
                stage.assemble(*ARGS, value)
        for option in ('capacity', 'lifecycle_capacity', 'owner_capacity'):
            for value in (True, False, 0, -1, 1025, 1.0, '16', None):
                with self.subTest(option=option, value=value), self.assertRaises(ValueError):
                    stage.assemble(*ARGS, LIFECYCLE, **{option: value})


if __name__ == '__main__':
    unittest.main()
