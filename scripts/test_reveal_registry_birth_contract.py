#!/usr/bin/env python3
"""Pinned native boundaries for historical birth observation, not liveness.

Four known unlink/free paths are deliberately recorded here. Their encoded
instructions do not prove exhaustive alias, computed-call or cleanup coverage.
No hook installation, firmware mutation, device or network access occurs.
"""

import hashlib
import unittest

import reveal_creation_capture_stage as creation
import reveal_deferred_envelope_stage as envelope
import reveal_deferred_queue_stage as queue
import reveal_constructor_capture_stage as constructor
import reveal_owner_carrier_stage as carrier
import reveal_paint_retirement_mips as owners
import reveal_registry_birth_mips as birth
import reveal_registry_birth_stage as stage
import reveal_registry_identity_stage as identity
import reveal_registry_owner_mips as bindings
import reveal_registry_receipt_mips as receipt
import reveal_retained_operations_stage as retained
import test_folderfollow_reveal_static_contract as source


BASE_ARGS = (0x1F50000, 0x1F80000, 0x1F70000, 0x1800000,
             0x1F20300, 0x1F20200, 0x1E80000)
TRANSPORT_ARGS = (*BASE_ARGS, 0x1FF0000, 0x1F20400, 0x1FE0000)
RETAINED_ARGS = (*TRANSPORT_ARGS, 0x1F40000, 0x1FF1000, 0x1F20500)
BIRTH, INTENT = 0x1F60000, 0x1F20600


class RegistryBirthContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.elf = source.Elf32(source.SOURCE)
        digest = hashlib.sha256(cls.elf.data).hexdigest()
        if digest != source.SOURCE_SHA256 or len(cls.elf.data) != source.SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: SHA-256 {digest}, '
                                 f'size {len(cls.elf.data)}')
        cls.jumps, cls.branches = {}, {}
        for start, end in cls.elf.executable_ranges():
            for pc in range(start, end, 4):
                word = cls.elf.word(pc)
                opcode = word >> 26
                if opcode in (2, 3):
                    cls.jumps[pc] = (((pc + 4) & 0xF0000000)
                                     | ((word & 0x3FFFFFF) << 2))
                elif (opcode in (1, 4, 5, 6, 7, 20, 21, 22, 23)
                      or (opcode in (16, 17, 18, 19)
                          and (word >> 21) & 31 == 8)):
                    immediate = word & 0xFFFF
                    if immediate & 0x8000:
                        immediate -= 0x10000
                    cls.branches[pc] = (pc + 4 + immediate * 4) & 0xFFFFFFFF

    def words(self, start, expected):
        for index, word in enumerate(expected):
            pc = start + index * 4
            with self.subTest(pc=f'{pc:#x}'):
                self.assertEqual(self.elf.word(pc), word)

    def test_birth_uses_the_actual28_byte_allocation(self):
        self.words(0x438A10, [0x0C119A78, 0x2404001C,
                              0x10400019, 0x26050034])
        self.words(0x438A20, [0x8E230004, 0xAC43000C,
                              0x8E230000, 0xAC430008,
                              0x8E230010, 0xAC430018,
                              0x8E23000C, 0xAC430014,
                              0x8E230008, 0xAC430010])
        # All five non-link words are descriptor fields, not an incarnation ID.

    def test_final_publication_store_precedes_native_unlock_selection(self):
        self.words(0x438A48, [0x8E030038, 0xAE020038,
                              0xAC450000, 0xAC430004,
                              0xAC620000, 0x8E190278,
                              0x0320F809, 0x02002021])
        self.assertEqual(receipt.HOOKS['published'],
                         (0x438A58, (0xAC620000, 0x8E190278)))
        # A passive callback observes an already linked node; refusal cannot
        # veto or roll back the native birth.

    def test_controller_initializer_sets_registry_callbacks_and_self_links(self):
        self.words(0x439A64, [0x3C020043, 0x24427D20, 0xAE020274,
                              0x3C020043, 0x24427DA0, 0x0C119B58,
                              0xAE020278])
        self.words(0x439ADC, [0x26030034, 0x02002021,
                              0xAE030034, 0xAE030038])
        # Initialization/reinitialization must remain outside any purported
        # continuous live-generation claim; this prototype provides none.

    def test_acquisition_facades_mask_the_actual_raw_result(self):
        self.words(0x437D20, [0x27BDFFE0, 0xAFBF001C,
                              0x0C119B68, 0x8C84013C,
                              0x8FBF001C, 0x03E00008, 0x27BD0020])
        self.words(0x466DA0, [0x27BDFFE0, 0xAFBF001C,
                              0x0C296E58, 0,
                              0x8FBF001C, 0x00001021,
                              0x03E00008, 0x27BD0020])
        self.assertEqual(self.jumps[0x466DA8], 0xA5B960)
        # The native facade's forced zero is not a fresh raw-zero witness.

    def test_registration_has_only_three_unused_non_home_scalar_slots(self):
        self.words(0x4389F0, [0x27BDFFD8, 0xAFBF0024,
                              0xAFB10020, 0xAFB0001C])
        accesses = self.stack_offsets(0x4389F0, 0x438A90)
        self.assertEqual(accesses, {0x1C, 0x20, 0x24})
        self.assertEqual(set(range(0x10, 0x28, 4)) - accesses,
                         {0x10, 0x14, 0x18})
        # Those locals already carry the per-invocation acquisition receipt.

    def stack_offsets(self, start, end):
        return {word & 0xFFFF
                for pc in range(start, end, 4)
                for word in (self.elf.word(pc),)
                if word >> 26 in (32, 33, 35, 36, 37, 40, 41, 43)
                and (word >> 21) & 31 == 29}

    def test_name_delete_has_a56_byte_frame_and_one_native_R_scope(self):
        self.words(0x4395A0, [0x27BDFFC8, 0xAFB50030, 0xAFB4002C,
                              0xAFB30028, 0xAFB10020, 0xAFB0001C,
                              0xAFBF0034, 0xAFB20024,
                              0x8C990274, 0x0080A821, 0x00A0A021,
                              0x0320F809, 0x24930034])
        self.assertEqual(self.stack_offsets(0x4395A0, 0x439680),
                         {0x1C, 0x20, 0x24, 0x28, 0x2C, 0x30, 0x34})
        self.words(0x439670, [0x02A02021, 0x8FB50030,
                              0x03200008, 0x27BD0038])
        # Its actual callback return is4395D4. A shadow observer could classify
        # that saved return chain, but it would not repair unchecked failures.

    def test_name_delete_unlinks_before_name_queue_engine_and_node_destruction(self):
        self.words(0x439610, [0x8E020004, 0x8E030000,
                              0xAC620004, 0xAC430000, 0xAE000000,
                              0x12400003, 0xAE000004,
                              0x0C119AA0, 0x02402021,
                              0x8E020008, 0x24050001,
                              0x0C22CFC0, 0x8C440034,
                              0x0C22D088, 0x8E040008,
                              0x0C119AA0, 0x02002021])
        # First unlink439618: U=s5, node=s0, next=v1, previous=v0.

    def test_controller_teardown_has_a40_byte_frame_and_only_two_free_locals(self):
        self.words(0x43CB20, [0x27BDFFD8, 0xAFBF0024,
                              0xAFB1001C, 0xAFB20020, 0xAFB00018,
                              0x00808821])
        self.words(0x43CB8C, [0x8E390274, 0x02202021,
                              0x0320F809, 0x26320034])
        accesses = self.stack_offsets(0x43CB20, 0x43CC74)
        self.assertEqual(accesses, {0x18, 0x1C, 0x20, 0x24})
        self.assertEqual(set(range(0x10, 0x28, 4)) - accesses, {0x10, 0x14})
        # Actual acquisition-callback return43CB9C. There is no third spare
        # non-home local to invent for a future per-call guard.

    def test_controller_teardown_bypasses_name_delete_and_frees_nodes(self):
        self.words(0x43CB9C, [0x8E220034, 0x1052000B, 0x8C500000,
                              0x8C430004, 0x00402021,
                              0xAE030004, 0xAC700000, 0xAC400000,
                              0x0C119AA0, 0xAC400004,
                              0x02001021, 0x1642FFF7, 0x8E100000])
        self.words(0x43CBD0, [0x8E390278, 0x0320F809, 0x02202021])
        self.assertFalse(any(0x43CB20 <= pc < 0x43CC74 and target == 0x4395A0
                             for pc, target in self.jumps.items()))
        # First unlink43CBB0: U=s1, node=v0/A0, next=s0, previous=v1.

    def test_first_outer_teardown_releases_R_before_callback_or_direct_unlink(self):
        self.words(0x4E3EFC, [0x8E190274, 0x0320F809, 0x02002021,
                              0x8E110034, 0x02002021, 0x12330014,
                              0x8E190278, 0x0320F809, 0])
        self.words(0x4E3F20, [0x8E390018, 0x1720FFF0, 0x02A02021])
        self.words(0x4E3EE8, [0x0320F809, 0x8E240014])
        self.words(0x4E3F3C, [0x8E220004, 0x8E230000, 0x02202021,
                              0xAC620004, 0xAC430000, 0xAE200000,
                              0x0C119AA0, 0xAE200004])
        # Raw-zero acquisition earlier in this loop is not current R ownership
        # at its first direct unlink4E3F48; that path is natively unlocked.

    def test_second_outer_teardown_releases_R_before_callback_or_direct_unlink(self):
        self.words(0x51A39C, [0x8E190274, 0x0320F809, 0x02002021,
                              0x8E110034, 0x02002021, 0x12330014,
                              0x8E190278, 0x0320F809, 0])
        self.words(0x51A3C0, [0x8E390018, 0x1720FFF0, 0x02A02021])
        self.words(0x51A388, [0x0320F809, 0x8E240014])
        self.words(0x51A3DC, [0x8E220004, 0x8E230000, 0x02202021,
                              0xAC620004, 0xAC430000, 0xAE200000,
                              0x0C119AA0, 0xAE200004])
        # First unlink51A3E8 likewise precedes the separate43CB20 loop.

    def test_both_outer_paths_call_controller_teardown_only_after_their_own_loop(self):
        self.words(0x4E3F6C, [0x0C119B78, 0x8E040290,
                              0x0C10F2C8, 0x02002021])
        self.words(0x51A404, [0x0320F809, 0, 0x0C10F2C8, 0x02002021])
        self.assertEqual({pc for pc, target in self.jumps.items()
                          if target == 0x43CB20}, {0x4E3F74, 0x51A40C})
        # Covering43CB20 alone misses already executed unlink/free operations.

    def test_raw_wrapper_saved_return_chain_distinguishes_the_native_scopes(self):
        self.words(0x437D28, [0x0C119B68, 0x8C84013C])
        self.words(0x466DA0, [0x27BDFFE0, 0xAFBF001C])
        self.assertEqual(0x437D28 + 8, 0x437D30)
        self.assertEqual(0x4395CC + 8, 0x4395D4)
        self.assertEqual(0x43CB94 + 8, 0x43CB9C)
        self.assertEqual(0x20 + 0x1C, 0x3C)
        self.assertEqual(0x20 + 0x20, 0x40)
        # At raw-wrapper SP=W: W+1C=437D30, W+3C is the native return,
        # native SP=W+40. Tags/return PCs classify genuine routes, not forged
        # stacks, ordinary-mutex semantics or continuous native retention.

    def test_no_encoded_jump_or_relative_branch_enters_the_two_word_hook_pairs(self):
        for site in (0x438A58, 0x4395C0, 0x43CB8C, 0x439618, 0x43CBB0):
            with self.subTest(site=f'{site:#x}'):
                self.assertEqual({pc for pc, target in self.jumps.items()
                                  if target in (site, site + 4)}, set())
                self.assertEqual({pc for pc, target in self.branches.items()
                                  if target in (site, site + 4)}, set())
        # Bounded encoded absence does not classify JR/JALR destinations.

    def test_native_node_interior_pointer_escapes_the_checked_ring_scope(self):
        self.words(0x43B190, [0x8E990278, 0x0320F809, 0x02802021,
                              0x8FBF002C, 0x26020008])
        self.words(0x43B218, [0x0C10EC48, 0, 0x10400002,
                              0x24030001, 0xAC430004])
        self.words(0x43B258, [0x8C590010, 0x13200006, 0,
                              0x8C44000C, 0x10800003, 0,
                              0x03200008, 0x27BD0020])
        # This API exposes node+8 after unlock; callbacks and escaped aliases
        # are independent coverage/lifetime gates, not solved by birth history.

    def test_registration_sources_are_two_constructors_not_a_publication_veto(self):
        self.assertEqual({pc for pc, target in self.jumps.items()
                          if target == 0x4389E0}, {0x43AE8C, 0x43B030})
        self.words(0x43AE94, [0x0C1467E8, 0x02202021,
                              0x8FA20050, 0x0C10DFB8, 0x8C440000])
        self.words(0x438A58, [0xAC620000, 0x8E190278,
                              0x0320F809, 0x02002021, 0x00001021])
        # Native publication and constructor continuation do not depend on a
        # bounded append-only historical observer accepting a new record.

    def test_birth_callback_configuration_is_a_strict_disjoint_RX_tuple(self):
        args = (BASE_ARGS[0], BASE_ARGS[3], BASE_ARGS[4], BASE_ARGS[6])
        for callback in ([], (), (True, 0x1E90000, 4),
                         (0x1E90000, True, 4), (0x1E90000, 0x1E90000, True),
                         (0x1E90000, 0x1E90000, 0),
                         (0x1E90000, 0x1E90000, 2),
                         (0x1E90001, 0x1E90000, 4),
                         (0x1E90004, 0x1E90000, 4),
                         (0x1E90000, 0x1E90001, 4),
                         (0xFFFFFFC, 0xFFFFFFC, 8),
                         (0x400000, 0x400000, 4),
                         (BASE_ARGS[0], BASE_ARGS[0], 4),
                         (BASE_ARGS[3], BASE_ARGS[3], 4),
                         (BASE_ARGS[4], BASE_ARGS[4], 4),
                         (BASE_ARGS[6], BASE_ARGS[6], 4)):
            with self.subTest(callback=callback), self.assertRaises(ValueError):
                receipt.assemble(*args, birth_callback=callback)
        for first, second in (((0x1E90000, 0x1E90000, 8),
                                (0x1E90004, 0x1E90004, 4)),
                              ((0x1E90004, 0x1E90004, 4),
                                (0x1E90000, 0x1E90000, 8))):
            with self.subTest(first=first, second=second), self.assertRaises(ValueError):
                receipt.assemble(*args, publication_callback=first,
                                 birth_callback=second)
        receipt.assemble(*args,
                         publication_callback=(0x1E90000, 0x1E90000, 4),
                         birth_callback=(0x1E91000, 0x1E91000, 4))

    def test_birth_stage_rejects_bad_state_addresses_and_strict_capacities(self):
        for address in (True, False, 0, -4, 1, 0xFFFFFFFC, 0x400000,
                        BASE_ARGS[0], BASE_ARGS[1], BASE_ARGS[2], BASE_ARGS[3],
                        BASE_ARGS[4], BASE_ARGS[5], BASE_ARGS[6]):
            with self.subTest(address=address), self.assertRaises(ValueError):
                stage.assemble(*BASE_ARGS, address)
        for option in ('capacity', 'birth_capacity', 'owner_capacity'):
            for value in (True, False, 0, -1, 1025, 1.0, '16', None):
                with self.subTest(option=option, value=value), self.assertRaises(ValueError):
                    stage.assemble(*BASE_ARGS, BIRTH, **{option: value})

    def test_birth_stage_guards_its_exact_full_RX_with_stable_two_pass_layout(self):
        result = stage.assemble(*BASE_ARGS, BIRTH)
        self.assertTrue(result['birth_history_only'])
        self.assertTrue(result['registry_release_checked'])
        self.assertEqual(result['protected_code_extent'],
                         (BASE_ARGS[6], len(result['code'])))
        prefix_bytes, tail_bytes = (result['birth_prefix_code_bytes'],
                                    result['birth_code_bytes'])
        self.assertEqual(prefix_bytes + tail_bytes, len(result['code']))
        self.assertEqual(result['birth_memory_bytes'], birth.memory_bytes(16))
        core_args = (BIRTH, BASE_ARGS[3], BASE_ARGS[4], BASE_ARGS[6] + prefix_bytes)
        core_options = dict(extra_protected_data=(
            (BASE_ARGS[0], receipt.memory_bytes(16)),
            (BASE_ARGS[1], bindings.memory_bytes(16)),
            (BASE_ARGS[2], owners.memory_bytes(16)),
            (BASE_ARGS[5], receipt.MUTEX_BYTES)))
        provisional, labels = birth.assemble(*core_args, **core_options)
        guarded, guarded_labels = birth.assemble(
            *core_args, **core_options, protected_code=result['protected_code_extent'])
        self.assertEqual(len(provisional), len(guarded))
        self.assertEqual(labels, guarded_labels)
        self.assertEqual(guarded, result['code'][prefix_bytes:])
        self.assertEqual(labels, result['birth_labels'])
        self.assertEqual(labels['observe'], result['labels']['birth_observe'])

    def test_creation_accepts_birth_callbacks_only_in_its_advertised_protected_tail(self):
        for callback, following in (((0x1E90000, 0x1E90000, 4), 0),
                                    ((BASE_ARGS[6], BASE_ARGS[6], 4), 4),
                                    ((BASE_ARGS[6] + 16, BASE_ARGS[6] + 16, 4), 64),
                                    ((BASE_ARGS[0], BASE_ARGS[0], 4), 0x100000)):
            with self.subTest(callback=callback, following=following), self.assertRaises(ValueError):
                creation.assemble(*BASE_ARGS, checked_registry_release=True,
                                  birth_callback=callback,
                                  following_code_bytes=following)
        result = stage.assemble(*BASE_ARGS, BIRTH)
        tail_start = BASE_ARGS[6] + result['birth_prefix_code_bytes']
        options = dict(checked_registry_release=True,
                       extra_protected_data=((BIRTH, birth.memory_bytes(16)),),
                       following_code_bytes=result['birth_code_bytes'],
                       birth_callback=(result['birth_labels']['observe'],
                                       tail_start, result['birth_code_bytes']))
        accepted = creation.assemble(*BASE_ARGS, **options)
        self.assertEqual(accepted['code'], result['code'][:result['birth_prefix_code_bytes']])
        self.assertEqual(accepted['protected_code_extent'], result['protected_code_extent'])
        options['following_code_bytes'] -= 4
        with self.assertRaises(ValueError):
            creation.assemble(*BASE_ARGS, **options)

    def test_omitted_birth_callback_preserves_all_nine_preceding_compositions(self):
        cases = (
            ('carrier', carrier.assemble, BASE_ARGS, {}, 18416,
             'b085c15d00bff87ebb8211a574b5921a12f20030de42e7c7e7bbe426dae74394'),
            ('creation', creation.assemble, BASE_ARGS, {}, 22676,
             '90be0fdb56fa349782d7a5b89009661ca26484ad1beed25fb8628ddfc2383da5'),
            ('checked creation', creation.assemble, BASE_ARGS,
             {'checked_registry_release': True}, 25716,
             '3c7b26a00fbd17bcd6c86719c21fa7ee5120ecaefcce1b4d9d6fb14332e6721c'),
            ('envelope', envelope.assemble, BASE_ARGS, {}, 30224,
             '49687ac90583cc610cbca3bb1c12dc96c6bbed02fe4ba67ad64d2deaa8410df3'),
            ('queue', queue.assemble, TRANSPORT_ARGS, {}, 34200,
             '27c7d0fbad229b65ca81d4b0f9caf3d0581f8ba8a6ba599cf77f574dcc6fdd8b'),
            ('constructor', constructor.assemble, TRANSPORT_ARGS, {}, 40076,
             '3bf7a75351ea9c91d2ff629d1a24f6deb478a918b2fa2696217f8c250c000693'),
            ('retained', retained.assemble, RETAINED_ARGS, {}, 55164,
             '8217a5c2c4a091c73892b76a5f95ae0d178b866e6253ffffb89bc6fad333acb8'),
            ('cleanup intent', retained.assemble, RETAINED_ARGS,
             {'cleanup_intent_address': INTENT}, 58948,
             '1ec55000c87c58bedabd5e4f545ed665955b42f845c3efc4aea82e13949f54e0'),
            ('identity observation', identity.assemble, (*RETAINED_ARGS, INTENT), {}, 64948,
             '195de8d83670ed24f4301a2d01b78f3bd4e59f0efcfa6a5509101603b4dbcc1a'))
        for name, assemble, args, options, size, expected_sha in cases:
            with self.subTest(composition=name):
                result = assemble(*args, **options)
                self.assertEqual(len(result['code']), size)
                self.assertEqual(hashlib.sha256(result['code']).hexdigest(), expected_sha)


if __name__ == '__main__':
    unittest.main()
