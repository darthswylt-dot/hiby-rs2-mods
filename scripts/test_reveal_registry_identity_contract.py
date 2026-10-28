#!/usr/bin/env python3
"""Pinned reasons why a current registry address match is not an incarnation.

The explicit offline observer does not install a stock hook or authorize native
unlink/free. Source checks describe bounded encoded native bodies, not every
computed caller or an allocation lease. Missing/changed02fd bytes are errors.
"""

import hashlib
import struct
import unittest

import reveal_registry_identity_stage as identity
import reveal_registry_owner_mips as bindings
import reveal_registry_receipt_mips as receipt
import reveal_retained_operations_stage as retained
import test_folderfollow_reveal_static_contract as source


BASE_ARGS = (0x1F50000, 0x1F80000, 0x1F70000, 0x1800000,
             0x1F20300, 0x1F20200, 0x1E80000,
             0x1FF0000, 0x1F20400, 0x1FE0000)
LEDGER, QUEUE, MUTEX, INTENT = 0x1F40000, 0x1FF1000, 0x1F20500, 0x1F20600
RETAINED_ARGS = (*BASE_ARGS, LEDGER, QUEUE, MUTEX)
ARGS = (*RETAINED_ARGS, INTENT)
RETAINED_SHA256 = '8217a5c2c4a091c73892b76a5f95ae0d178b866e6253ffffb89bc6fad333acb8'
INTENT_SHA256 = '1ec55000c87c58bedabd5e4f545ed665955b42f845c3efc4aea82e13949f54e0'


class RegistryIdentityContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.elf = source.Elf32(source.SOURCE)
        digest = hashlib.sha256(cls.elf.data).hexdigest()
        if digest != source.SOURCE_SHA256 or len(cls.elf.data) != source.SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: SHA-256 {digest}, '
                                 f'size {len(cls.elf.data)}')

    def words(self, start, expected):
        for index, word in enumerate(expected):
            pc = start + index * 4
            with self.subTest(pc=f'{pc:#x}'):
                self.assertEqual(self.elf.word(pc), word)

    def test_native_registry_node_allocation_is28_bytes_not12(self):
        self.words(0x438A10, [0x0C119A78, 0x2404001C,
                              0x10400019, 0x26050034])
        # A12-byte read view contains links/engine only. It is not the actual
        # native allocation width or proof that a historical address is live.

    def test_all_five_native_node_scalars_come_from_the_descriptor_not_a_birth_counter(self):
        self.words(0x438A20, [0x8E230004, 0xAC43000C,
                              0x8E230000, 0xAC430008,
                              0x8E230010, 0xAC430018,
                              0x8E23000C, 0xAC430014,
                              0x8E230008, 0xAC430010])
        # The remaining words0/4 are links below. No spare word in this pinned
        #28-byte representation supplies an independently issued incarnation.

    def test_controller_initializes_both_links_to_the_U34_sentinel(self):
        self.words(0x439ADC, [0x26030034, 0x02002021,
                              0xAE030034, 0xAE030038])
        # The sentinel has two links, not a node+8 engine field.

    def test_complete_birth_observation_is_after_the_final_native_link_store(self):
        self.words(0x438A48, [0x8E030038, 0xAE020038,
                              0xAC450000, 0xAC430004,
                              0xAC620000, 0x8E190278,
                              0x0320F809, 0x02002021])
        self.assertEqual(receipt.HOOKS['published'],
                         (0x438A58, (0xAC620000, 0x8E190278)))
        self.assertEqual(bindings.PUBLICATION_SITE, 0x438A5C)
        # Fresh checked rawR is still a separate premise. Later equal addresses
        # cannot reconstruct continuous retention from this creation event.

    def test_immutable_binding_row_records_history_not_a_live_node_generation(self):
        self.assertEqual(bindings.RECORD_BYTES, 48)
        self.assertEqual((bindings.MAGIC, bindings.SEQUENCE, bindings.OWNER,
                          bindings.CONTROLLER, bindings.REGISTRY_MUTEX,
                          bindings.NODE, bindings.ENGINE, bindings.NATIVE_SP,
                          bindings.CALLER, bindings.SITE, bindings.RAW_STATUS,
                          bindings.RECEIPT_SEQUENCE), tuple(range(0, 48, 4)))
        self.assertEqual(bindings.memory_bytes(16), 16 + 16 * 48)
        # The sequence is stored in this append-only side table, not in the
        # native node. No matching current field binds it to that incarnation.

    def test_native_delete_chooses_first_equal_name_not_a_captured_node(self):
        self.words(0x4395D4, [0x8EB00034, 0x16130006, 0x8E110000])
        self.words(0x4395F4, [0x8E020008, 0x02802021,
                              0x8C520000, 0x0C296D80,
                              0x02402821, 0x1440FFF7, 0])
        # Neither GCAP's issuance pair nor an expected engine is an input to
        # this name comparison. The observer therefore never calls this body.

    def test_native_unlink_precedes_name_queue_engine_and_node_frees(self):
        self.words(0x439610, [0x8E020004, 0x8E030000,
                              0xAC620004, 0xAC430000, 0xAE000000,
                              0x12400003, 0xAE000004,
                              0x0C119AA0, 0x02402021,
                              0x8E020008, 0x24050001,
                              0x0C22CFC0, 0x8C440034,
                              0x0C22D088, 0x8E040008,
                              0x0C119AA0, 0x02002021])
        # A live-generation sidecar would have to tombstone before439618,
        # not only at the later engine or node allocator service.

    def test_controller_teardown_independently_unlinks_and_frees_registry_nodes(self):
        self.words(0x43CB9C, [0x8E220034, 0x1052000B, 0x8C500000,
                              0x8C430004, 0x00402021,
                              0xAE030004, 0xAC700000, 0xAC400000,
                              0x0C119AA0, 0xAC400004,
                              0x02001021, 0x1642FFF7, 0x8E100000])
        # This destructive loop never calls4395A0: covering only that facade
        # would miss an encoded native node-free path and permit stale history.

    def test_controller_teardown_uses_the_same_masking_registry_callbacks(self):
        self.words(0x43CB8C, [0x8E390274, 0x02202021,
                              0x0320F809, 0x26320034])
        self.words(0x43CBD0, [0x8E390278, 0x0320F809, 0x02202021])
        self.words(0x466DB0, [0x8FBF001C, 0x00001021])
        self.words(0x466DD0, [0x8FBF001C, 0x00001021])
        # Facade zero is not observed raw acquisition/release success. This
        # observer uses direct checked raw services rather than these facades.

    def test_issuance_denial_is_not_a_native_publication_veto(self):
        self.words(0x438A58, [0xAC620000, 0x8E190278,
                              0x0320F809, 0x02002021,
                              0x00001021, 0x8FBF0024])
        self.words(0x43AE94, [0x0C1467E8, 0x02202021,
                              0x8FA20050, 0x0C10DFB8, 0x8C440000])
        # The receipt/issuer callback is after the final publication store;
        # refusing a full historical table cannot undo or veto that birth.
        # The outer constructor also ignores actual registration's result.

    def test_zero_default_tail_preserves_the55164_byte_retained_composition(self):
        default = retained.assemble(*RETAINED_ARGS)
        explicit = retained.assemble(*RETAINED_ARGS, following_code_bytes=0)
        self.assertEqual(default['code'], explicit['code'])
        self.assertEqual(default['labels'], explicit['labels'])
        self.assertEqual(len(default['code']), 55164)
        self.assertEqual(hashlib.sha256(default['code']).hexdigest(), RETAINED_SHA256)

    def test_zero_default_tail_preserves_the58948_byte_cleanup_intent_composition(self):
        default = retained.assemble(*RETAINED_ARGS, cleanup_intent_address=INTENT)
        explicit = retained.assemble(*RETAINED_ARGS, cleanup_intent_address=INTENT,
                                     following_code_bytes=0)
        self.assertEqual(default['code'], explicit['code'])
        self.assertEqual(default['labels'], explicit['labels'])
        self.assertEqual(len(default['code']), 58948)
        self.assertEqual(hashlib.sha256(default['code']).hexdigest(), INTENT_SHA256)

    def test_retained_tail_is_a_strict_aligned_integer_and_extends_protection_only(self):
        for value in (True, False, -4, 1, 2, 3, 1.0, '4', None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                retained.assemble(*RETAINED_ARGS, following_code_bytes=value)
        for intent in (None, INTENT):
            with self.subTest(cleanup_intent_address=intent):
                default = retained.assemble(*RETAINED_ARGS, cleanup_intent_address=intent)
                tailed = retained.assemble(*RETAINED_ARGS, cleanup_intent_address=intent,
                                          following_code_bytes=4)
                self.assertEqual(len(default['code']), len(tailed['code']))
                self.assertEqual(default['labels'], tailed['labels'])
                self.assertEqual(tailed['protected_code_extent'],
                                 (BASE_ARGS[6], len(tailed['code']) + 4))

    def test_identity_composition_protects_its_full_rx_and_has_a_bounded_walk(self):
        result = identity.assemble(*ARGS)
        self.assertEqual(result['protected_code_extent'],
                         (BASE_ARGS[6], len(result['code'])))
        self.assertEqual(result['retained_prefix_code_bytes']
                         + result['identity_code_bytes'], len(result['code']))
        entry = result['identity_labels']['audit_identity']
        self.assertEqual(result['labels']['identity_audit_identity'], entry)
        self.assertGreaterEqual(entry, BASE_ARGS[6] + result['retained_prefix_code_bytes'])
        self.assertLess(entry, BASE_ARGS[6] + len(result['code']))
        for value in (True, False, 0, -1, 1025, 1.0, '64', None):
            with self.subTest(max_nodes=value), self.assertRaises(ValueError):
                identity.assemble(*ARGS, max_nodes=value)

    def test_identity_fragment_has_no_encoded_native_lookup_unlink_or_free_calls(self):
        result = identity.assemble(*ARGS)
        tail = result['code'][result['retained_prefix_code_bytes']:]
        for entry in (0x4395A0, 0x439780, 0x43CB20, 0x43A0C0, 0x43B120,
                      0x485DE0, 0x8B0760, 0x8B4220, 0x466A80, 0x8B0D20):
            with self.subTest(forbidden_native_entry=f'{entry:#x}'):
                encoded = struct.pack('<I', 0x0C000000 | (entry >> 2))
                materialized = struct.pack('<II', 0x3C190000 | (entry >> 16),
                                           0x37390000 | (entry & 0xFFFF))
                self.assertNotIn(encoded, tail)
                self.assertNotIn(materialized, tail)
        # This bounded encoded absence does not classify arbitrary native
        # computed calls or certify an allocation lease elsewhere.


if __name__ == '__main__':
    unittest.main()
