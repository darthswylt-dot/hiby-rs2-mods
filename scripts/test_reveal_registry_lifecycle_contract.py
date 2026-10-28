#!/usr/bin/env python3
"""Pinned local retirement frontiers, not complete lifetime interception."""

import hashlib
import unittest

import reveal_creation_capture_stage as creation
import reveal_registry_birth_stage as birth
import reveal_registry_lifecycle_mips as lifecycle
import reveal_registry_lifecycle_stage as stage
import reveal_registry_retirement_mips as bridges
import reveal_registry_receipt_mips as receipt
import test_reveal_registry_birth_contract as previous


ARGS = previous.BASE_ARGS
LIFECYCLE = 0x1F3A000


class RegistryLifecycleContractTests(unittest.TestCase):
    setUpClass = classmethod(previous.RegistryBirthContractTests.setUpClass.__func__)

    def test_every_retirement_redirect_replays_exact_hash_pinned_native_words(self):
        self.assertEqual(len(bridges.HOOKS), 11)
        for name, (pc, expected) in bridges.HOOKS.items():
            with self.subTest(hook=name):
                self.assertEqual(tuple(self.elf.word(pc + 4 * i) for i in range(2)),
                                 expected)
                self.assertFalse(any(target in (pc, pc + 4)
                                     for target in self.jumps.values()))
                self.assertFalse(any(target in (pc, pc + 4)
                                     for target in self.branches.values()))

    def test_frontiers_precede_unlinks_and_outer_release_is_not_deletion(self):
        self.assertEqual(set(lifecycle.RETIREMENT_SITES),
                         {0x439618, 0x43CBB0, 0x4E3F18, 0x51A3B8})
        self.assertEqual(tuple(self.elf.word(pc) for pc in (0x439618, 0x43CBB0)),
                         (0xAC620004, 0xAE030004))
        for selected, unlink in ((0x4E3F18, 0x4E3F48), (0x51A3B8, 0x51A3E8)):
            with self.subTest(site=hex(selected)):
                self.assertEqual(self.elf.word(selected), 0x0320F809)
                self.assertEqual(self.elf.word(selected + 4), 0)
                self.assertEqual(self.elf.word(unlink), 0xAC620004)
                self.assertLess(selected + 8, unlink)

    def test_two_scope_locals_are_outside_argument_homes_and_native_saved_words(self):
        self.assertEqual((bridges.TAG, bridges.RAW_STATUS), (0x10, 0x14))
        for first, last in ((0x4395A0, 0x439680), (0x43CB20, 0x43CC74),
                            (0x4E3EA0, 0x4E3FA8), (0x51A340, 0x51A440)):
            offsets = {word & 0xFFFF for pc in range(first, last, 4)
                       for word in (self.elf.word(pc),)
                       if word >> 26 in (32, 33, 35, 36, 37, 40, 41, 43)
                       and (word >> 21) & 31 == 29}
            with self.subTest(start=hex(first)):
                self.assertFalse({bridges.TAG, bridges.RAW_STATUS} & offsets)

    def test_exact_full_generated_RX_is_guarded_and_all_hooks_compose_coherently(self):
        result = stage.assemble(*ARGS, LIFECYCLE)
        self.assertTrue(result['lifecycle_observation_only'])
        self.assertTrue(result['registry_release_checked'])
        self.assertEqual(result['protected_code_extent'], (ARGS[6], len(result['code'])))
        p, c, r = (result['lifecycle_prefix_code_bytes'],
                   result['lifecycle_code_bytes'], result['retirement_code_bytes'])
        self.assertEqual(p + c + r, len(result['code']))
        self.assertEqual(result['lifecycle_labels']['observe_birth'], ARGS[6] + p)
        self.assertEqual(result['retirement_labels']['delete_begin'], ARGS[6] + p + c)
        old_hooks = receipt.hook_words(result['receipt_labels'])
        new_hooks = result['retirement_hooks']
        self.assertEqual(len(new_hooks), 11)
        overlap = set(old_hooks) & set(new_hooks)
        self.assertEqual(overlap, {0x466DA8, 0x466DB0})
        for pc in overlap:
            self.assertNotEqual(old_hooks[pc], new_hooks[pc])
        combined = {**old_hooks, **result['release_hooks'], **new_hooks}
        self.assertEqual(len(combined), 16)

    def test_creation_prefix_has_exact_tail_guard_and_state_exclusion(self):
        result = stage.assemble(*ARGS, LIFECYCLE)
        p, c = result['lifecycle_prefix_code_bytes'], result['lifecycle_code_bytes']
        prefix = creation.assemble(
            *ARGS, checked_registry_release=True,
            extra_protected_data=((LIFECYCLE, result['lifecycle_memory_bytes']),),
            following_code_bytes=c + result['retirement_code_bytes'],
            birth_callback=(result['lifecycle_labels']['observe_birth'], ARGS[6] + p, c))
        self.assertEqual(prefix['code'], result['code'][:p])
        self.assertEqual(prefix['labels'], {key: value for key, value in result['labels'].items()
                                         if not key.startswith(('lifecycle_', 'retirement_'))})

    def test_new_ledger_configuration_rejects_invalid_types_extents_and_aliases(self):
        for value in (True, False, 0, -1, 1.0, 1025, None):
            with self.subTest(capacity=value), self.assertRaises(ValueError):
                stage.assemble(*ARGS, LIFECYCLE, lifecycle_capacity=value)
        for value in (0, True, 1, 0xFFFFFFFC, 0x400000, *ARGS):
            with self.subTest(address=value), self.assertRaises(ValueError):
                stage.assemble(*ARGS, value)
        defaults = (LIFECYCLE, ARGS[3], ARGS[4], ARGS[6])
        for value in (None, [], ((True, 4),), ((0, 4),), ((0x1F3B000, True),),
                      ((0x1F3B000, 0),), ((0x1F3B000, 3),), ((LIFECYCLE, 4),)):
            with self.subTest(extra=value), self.assertRaises(ValueError):
                lifecycle.assemble(*defaults, extra_protected_data=value)
        for value in ([], (True, 4), (ARGS[6], 4), (0x400000, 0x1000000)):
            with self.subTest(protected=value), self.assertRaises(ValueError):
                lifecycle.assemble(*defaults, protected_code=value)

    def test_all_ten_preceding_composition_hashes_remain_unchanged(self):
        previous.RegistryBirthContractTests.test_omitted_birth_callback_preserves_all_nine_preceding_compositions(self)
        result = birth.assemble(*ARGS, 0x1F38000)
        self.assertEqual(len(result['code']), 28088)
        self.assertEqual(hashlib.sha256(result['code']).hexdigest(),
                         '0d40bc5bba95d1458af0cd79a7957377a034969fc45ff98fba27c495e3ce07b0')

    def test_bridge_RX_tuples_and_full_protected_extent_are_strict(self):
        args = (ARGS[3], ARGS[4], 0x1EB0000)
        options = dict(callback=(0x1EA0000, 0x1EA0000, 4),
                       fallback=(0x1E90000, 0x1E90004, 0x1E90000, 8))
        for key, values in (
                ('callback', (None, [], (True, 0x1EA0000, 4),
                              (0x1EA0000, 0x1EA0000, 0),
                              (0x1EA0004, 0x1EA0000, 4),
                              (0x1E90000, 0x1E90000, 4))),
                ('fallback', (None, [], (True, 0x1E90004, 0x1E90000, 8),
                              (0x1E90000, 0x1E90008, 0x1E90000, 8),
                              (0x400000, 0x400004, 0x400000, 8))),
                ('protected_code', ([], (True, 4), (0x1EB0000, 4),
                                    (0x1EB0000, True)))):
            for value in values:
                with self.subTest(option=key, value=value), self.assertRaises(ValueError):
                    bridges.assemble(*args, **dict(options, **{key: value}))

    def test_wrapping_raw_native_frame_refuses_before_wrapped_private_local_read(self):
        import test_reveal_registry_lifecycle_mips as fixture

        for name, stop in (('raw_call', receipt.RAW_LOCK), ('raw_return', 0x466DB8)):
            with self.subTest(route=name):
                m = fixture.RegistryLifecycleMachine(self.elf.data)
                raw_sp = 0xFFFFFFC0
                m.map(raw_sp - bridges.FRAME, bridges.FRAME + 0x40)
                m.put(raw_sp + 0x1C, 0x437D30, 4)
                m.put(raw_sp + 0x3C, 0x4395D4, 4)
                m.r[29], m.r[4], m.r[21] = raw_sp, ARGS[4], ARGS[3]
                m.clear_events()
                m.run_at(m.retirement_labels[name], stop)
                self.assertIn(m.receipt_labels[name], m.trace)
                self.assertFalse(any(address < 0x40 for address, _ in m.reads))
                self.assertEqual(m.lifecycle_accesses, [])
                self.assertEqual(m.calls, [])


if __name__ == '__main__':
    unittest.main()
