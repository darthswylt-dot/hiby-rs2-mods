#!/usr/bin/env python3
"""Pin the second factory's checked NULL chain and distinct atomic scope.

Only encoded native callers are covered:47D4A0 ->4F8760 ->4A326C. The wrapper
checks NULL, then the upper caller discards it. Unknown computed callers,
native/import progress, existing H aliases and in-flight cancellation remain
outside this optional admission stage.
"""

from contextlib import contextmanager
from copy import deepcopy
import hashlib
import struct
import unittest

from build_reveal_bridge_diag import b
import reveal_factory_admission_gate_mips as primary
import reveal_factory_admission_gate_stage as parent_stage
import reveal_secondary_factory_admission_gate_mips as gates
import reveal_secondary_factory_admission_gate_stage as stage
import reveal_registry_receipt_mips as receipt
import test_reveal_factory_admission_gate_contract as preceding
import test_reveal_factory_admission_gate_mips as parent_fixture
import test_reveal_registry_birth_contract as native


STAGE_ARGS, GUARD, CORE_ARGS = preceding.STAGE_ARGS, preceding.GUARD, preceding.CORE_ARGS
PARENT_BYTES, PARENT_SHA256 = preceding.GATED_BYTES, preceding.GATED_SHA256
GATE_BYTES, GATED_BYTES = 1336, 101836
GATED_SHA256 = '193532af1c92cc1b454184bbc95e7bbe77e1e07ff2ed8b3a70bbfa654a45b0ff'
GUARDED_PARENT_SHA256 = '2ebeeeff65ae19a2d2cf92c70cae269c4ebce12a59483fc2291608d3cc4c80db'
FACTORY, EARLY, CREATED = 0x47D4A0, 0x47D4F8, 0x47D6E8
PARENT_MODULES = (*parent_fixture._ASSEMBLY_CACHE_MODULES, primary, parent_stage)


@contextmanager
def parent_cache():
    """Cache45 parent public assemblers; leave new/private emitters intact."""
    originals = []
    with parent_fixture._fixture_assembly_cache(True):
        try:
            for module in (primary, parent_stage):
                original = module.assemble
                originals.append((module, original))
                module.assemble = parent_fixture.previous._cached_assembler(original)
            yield
        finally:
            for module, original in reversed(originals):
                module.assemble = original


class SecondaryFactoryAdmissionGateContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        native.RegistryBirthContractTests.setUpClass.__func__(cls)
        cls._canonical_outputs = {}
        cls._parent_functions = tuple((module, module.assemble) for module in PARENT_MODULES)
        cls._new_functions = gates.assemble, stage.assemble, primary._assemble
        cls._cache = parent_cache()
        cls._cache.__enter__()
        cls.addClassCleanup(cls._finish_cache)

    @classmethod
    def _finish_cache(cls):
        try:
            cls._cache.__exit__(None, None, None)
        finally:
            for module, function in cls._parent_functions:
                if module.assemble is not function:
                    raise AssertionError('parent assembler not restored: ' + module.__name__)
            if (gates.assemble, stage.assemble, primary._assemble) != cls._new_functions:
                raise AssertionError('new secondary or generic private emitter was replaced')

    words = native.RegistryBirthContractTests.words

    @classmethod
    def canonical(cls, name):
        """Deep-copy three valid snapshots; cache no CPU state or outcomes."""
        if name not in cls._canonical_outputs:
            if name == 'parent_default':
                result = parent_stage.assemble(*STAGE_ARGS, guard_address=GUARD)
            elif name == 'parent_guarded':
                tail = len(gates.assemble(*CORE_ARGS)[0])
                result = parent_stage.assemble(*STAGE_ARGS, guard_address=GUARD,
                                               following_code_bytes=tail)
            elif name == 'stage_default':
                result = stage.assemble(*STAGE_ARGS, guard_address=GUARD)
            else:
                raise ValueError('unknown canonical configuration')
            cls._canonical_outputs[name] = deepcopy(result)
        return deepcopy(cls._canonical_outputs[name])

    @staticmethod
    def unpack(code):
        return struct.unpack('<' + 'I' * (len(code) // 4), code)

    def test_native_secondary_entry_saves_S1_and_two_late_tails_are_exact(self):
        self.words(FACTORY, [0x27BDFDC8, 0xAFB10224, 0xAFBF0234,
                             0xAFB40230, 0xAFB3022C, 0xAFB20228, 0xAFB00220])
        self.words(0x47D4E8, [0x8FBF0234, 0x8FB40230, 0x8FB3022C,
                             0x8FB20228, 0x8FB10224, 0x8FB00220,
                             0x03E00008, 0x27BD0238])
        self.words(0x47D6D4, [0x8FBF0234, 0x8FA20218, 0x8FB40230, 0x8FB3022C,
                             0x8FB20228, 0x8FB10224, 0x8FB00220,
                             0x03E00008, 0x27BD0238])
        self.assertEqual(gates.HOOKS,
                         {'enter': (FACTORY, (0x27BDFDC8, 0xAFB10224)),
                          'early_leave': (EARLY, (0x8FB10224, 0x8FB00220)),
                          'created_leave': (CREATED, (0x8FB10224, 0x8FB00220))})
        self.assertNotEqual(gates.HOOKS['enter'][1], primary.HOOKS['enter'][1])

    def test_secondary_frame_preserves_incoming_arguments_and_unused_stamp_word(self):
        memory, derived = set(), set()
        for pc in range(FACTORY, 0x47D708, 4):
            word = self.elf.word(pc)
            if (word >> 21) & 31 != 29:
                continue
            if word >> 26 in (32, 33, 35, 36, 37, 40, 41, 43):
                memory.add(word & 0xFFFF)
            if word >> 26 in (8, 9) and (word >> 16) & 31 != 29:
                derived.add(word & 0xFFFF)
        self.assertEqual(memory, {0x214, 0x218, 0x220, 0x224, 0x228, 0x22C,
                                  0x230, 0x234, 0x248, 0x24C})
        self.assertEqual(derived, {0x18, 0xB0, 0x1B4, 0x214, 0x218})
        self.words(0x47D4BC, [0x8FB10248, 0xAFA00218])
        self.words(0x47D608, [0x8FA4024C])
        self.words(0x47D508, [0x00002821, 0x240601FC, 0x0C296F18, 0x27A40018])
        self.assertEqual((0x248 - 568, 0x24C - 568), (0x10, 0x14))
        self.assertEqual((gates.FRAME, gates.FACTORY_FRAME, gates.OWNER, gates.FUTURE_OWNER),
                         (192, 568, 0x21C, 0xA4))
        self.assertEqual(192 - 568 + 0x21C, 0xA4)
        self.assertGreater(0xA4, 0x8C + 3)
        # Neither caller's incoming fifth/sixth argument overlaps private
        # saves or future F+21C. Buffer/import bounds are separate premises.

    def test_encoded_entry_tail_and_wrapper_census_does_not_prove_computed_callers(self):
        refs = {pc: target for pc, target in self.jumps.items()
                if FACTORY <= target < 0x47D708 or target == 0x4F8760}
        self.assertEqual(refs, {0x4F87C0: FACTORY, 0x4A326C: 0x4F8760})
        branch_targets = {target for target in self.branches.values()
                          if FACTORY <= target < 0x47D708}
        self.assertEqual(branch_targets, {0x47D700, 0x47D508, 0x47D58C, 0x47D5D4,
                                         0x47D6F8, 0x47D62C, 0x47D6BC, 0x47D61C,
                                         0x47D4E8})
        self.assertEqual({pc for pc in range(FACTORY, 0x47D708, 4)
                          if self.elf.word(pc) == 0x03E00008}, {0x47D500, 0x47D6F0})
        for target in (FACTORY + 4, EARLY, EARLY + 4, CREATED, CREATED + 4,
                       EARLY + 8, CREATED + 8):
            self.assertNotIn(target, set(self.jumps.values()))
            self.assertNotIn(target, branch_targets)

    def test_direct_wrapper_checks_NULL_and_returns_the_same_saved_pointer(self):
        self.words(0x4F87C0, [0x0C11F528, 0xAFA20024, 0x10400002,
                             0x24030001, 0xAC43005C])
        self.assertEqual(self.branches[0x4F87C8], 0x4F87D4)
        self.words(0x4F87D4, [0x3C0500B9, 0x3C0300B9, 0x24040001,
                             0x24A5BB20, 0xAC70BB1C, 0x0C11DC68, 0xAFA20040,
                             0x24040001, 0x0C11DC60, 0x00002821])
        self.words(0x4F87FC, [0x8FBF004C, 0x8FA20040, 0x8FB00048,
                             0x03E00008, 0x27BD0050])
        # F+40 is a local pointer save in the wrapper's80-byte frame. The
        # NULL path still performs its ordinary UI/global side effects.

    def test_wrapper_UI_facades_do_not_forward_factory_result_as_an_argument(self):
        self.words(0x477180, [0x3C0300B9, 0x00801021, 0x8C64A9F0,
                             0x00A03021, 0x0811DBF8, 0x00402821])
        self.words(0x4771A0, [0x3C0300B9, 0x00801021, 0x8C64A9F0,
                             0x00A03021, 0x0811DB88, 0x00402821])
        # Both replace V0 from A0=1 and rebuild A2 from A1 before their
        # native tail-call. Saved F+40 is restored only after those calls.

    def test_only_upper_direct_caller_discards_return_before_native_registration(self):
        self.words(0x4A326C, [0x0C13E1D8, 0x24E7B5E0, 0x3C04004A,
                             0x24841800, 0x02002821, 0x00003021,
                             0x0C11DD80, 0x24070017, 0x0C11A460, 0,
                             0x1000FFA0, 0x8FBF0034])
        self.words(0x477600, [0x24E80064, 0x24E3000A, 0x3C0200B9,
                             0x24E70036, 0x2442A9FC])
        self.words(0x4A3118, [0x8FB30030, 0x8FB2002C, 0x8FB10028,
                             0x8FB00024, 0x24020001, 0x03E00008, 0x27BD0038])
        self.assertEqual(self.branches[0x4A3294], 0x4A3118)
        # All four477600 arguments are assigned without returned V0, which
        # the native leaf itself overwrites at477608. No H propagates upward.

    def test_initializer_publishes_H_and_installs_a_later_unguarded_alias(self):
        self.words(0x4F8770, [0x3C020050, 0x00801821, 0x24428620,
                             0x27A40020, 0xAFA40010, 0xAFA20020])
        self.words(0x4F878C, [0x3C020050, 0xAFB00048, 0x24428540])
        self.words(0x4F87AC, [0xAFA00028])
        self.words(0x4F865C, [0x02202821, 0x0C1164C8, 0x00408021,
                             0x3C050050, 0x02002021, 0x0C116540, 0x24A586A0])
        self.words(0x459500, [0x10800004, 0, 0xAC850138, 0x03E00008, 0x00001021])
        self.words(0x4F86E8, [0x0C1164D0, 0x00A02021, 0x00402021,
                             0x0C11F428, 0x24050001])
        # The setter stores a handler, not an immediate callback. Later
        # widget47D0A0 access and opaque485DE0 progress remain outside Q.

    def test_native_lookup_registration_and_startup_still_have_no_rollback_or_time_bound(self):
        self.words(0x47D4D8, [0x0C11F290, 0x00E09821, 0x10400009, 0x8FA20214])
        self.words(0x47D69C, [0x0C11F278, 0xAC62006C, 0x8FA40218,
                             0x8C990070, 0x13200003, 0xAC900048,
                             0x0320F809, 0x8C85004C])
        self.words(0x47D6BC, [0x27A501B4, 0x02002021, 0x0C10EF40,
                             0x24060001, 0x0C11F210, 0x8FA40218])
        self.words(0x47C8C8, [0x8E040008, 0x0C119B68, 0xAE020000])
        # Callback-published quarantine after entry does not cancel the
        # native body, whose later creation/launch cannot be rolled back.

    def test_secondary_configuration_changes_only_scope_stamp_and_native_replay_words(self):
        old_code, old_labels = primary.assemble(*CORE_ARGS)
        code, labels = gates.assemble(*CORE_ARGS)
        self.assertEqual(labels, old_labels)
        self.assertEqual(len(code), preceding.GATE_BYTES)
        self.assertEqual(gates.OWNERSTAMP, int.from_bytes(b'QF4A', 'little'))
        self.assertNotEqual(gates.OWNERSTAMP, primary.OWNERSTAMP)
        expected = bytearray(old_code)
        edits = {labels['enter_claimed'] + 4: b.lui(8, gates.OWNERSTAMP >> 16),
                 labels['enter_replay'] + 4: 0xAFB10224,
                 labels['enter_replay'] + 8: b.j_type(2, FACTORY + 8)}
        save_size = 4 * len(preceding.FactoryAdmissionGateContractTests.saved_words())
        for name in ('early_leave', 'created_leave'):
            edits[labels[name] + save_size + 4] = b.lui(9, gates.OWNERSTAMP >> 16)
            edits[labels[name + '_replay'] + 8] = b.j_type(2, gates.HOOKS[name][0] + 8)
        for pc, word in edits.items():
            struct.pack_into('<I', expected, pc - CORE_ARGS[2], word)
        self.assertEqual(code, bytes(expected))
        self.assertEqual(sum(a != b for a, b in zip(self.unpack(code), self.unpack(old_code))), 7)
        # The same unwrapped generic emitter must implement the unchanged
        # atomic policy with this distinct prologue, stamp and return scope.

    def test_secondary_hooks_reject_invalid_targets_and_leave_primary_sites_distinct(self):
        _, labels = gates.assemble(*CORE_ARGS)
        hooks = gates.hook_words(labels)
        self.assertEqual(set(hooks), {FACTORY, EARLY, CREATED})
        self.assertFalse(set(hooks) & {pc for pc, pair in primary.HOOKS.values()})
        for name, (pc, pair) in gates.HOOKS.items():
            self.assertEqual(hooks[pc], (b.j_type(2, labels[name]), 0))
            for value in (True, False, None, 0, -4, 1, 1.0, '16', 0x10000000):
                with self.subTest(name=name, target=value), self.assertRaises(ValueError):
                    gates.hook_words(dict(labels, **{name: value}))

    def test_new_variant_validates_guard_data_aliases_and_complete_helper_RX(self):
        code, labels = gates.assemble(*CORE_ARGS)
        for index, value in ((0, GUARD), (1, GUARD), (2, GUARD),
                              (3, CORE_ARGS[0] + receipt.CONTROLLER_BYTES - 4),
                              (3, CORE_ARGS[1] + receipt.MUTEX_BYTES - 4),
                              (3, CORE_ARGS[2] + len(code) - 4)):
            args = list(CORE_ARGS)
            args[index] = value
            with self.subTest(role=index, value=value), self.assertRaises(ValueError):
                gates.assemble(*args)
        for index in range(4):
            for value in (True, None, 1, 0x100000000):
                args = list(CORE_ARGS)
                args[index] = value
                with self.subTest(role=index, value=value), self.assertRaises(ValueError):
                    gates.assemble(*args)
        for protected in ((CORE_ARGS[2], len(code) - 4), (CORE_ARGS[2] + 4, len(code)),
                          (CORE_ARGS[2], True), (0x400000, 0x2000000)):
            with self.subTest(protected=protected), self.assertRaises(ValueError):
                gates.assemble(*CORE_ARGS, protected_code=protected)
        self.assertEqual(gates.assemble(*CORE_ARGS,
                                        protected_code=(CORE_ARGS[2], len(code))), (code, labels))

    def test_new_variant_checks_extra_extents_and_jump_region_end(self):
        code, labels = gates.assemble(*CORE_ARGS)
        for extra in ([], ((0xFFFFFFFC, 8),), ((True, 4),), ((0x1F90000, True),),
                      ((0x400000, 4),), ((GUARD, 4),),
                      ((CORE_ARGS[2] + len(code) - 4, 4),)):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                gates.assemble(*CORE_ARGS, extra_protected_data=extra)
        args = list(CORE_ARGS)
        args[2] = 0x10000000 - len(code)
        self.assertEqual(len(gates.assemble(*args)[0]), len(code))
        args[2] += 4
        with self.assertRaises(ValueError):
            gates.assemble(*args)

    def test_new_variant_retry_configuration_is_strict_without_changing_scope_layout(self):
        code, labels = gates.assemble(*CORE_ARGS)
        for limit in (1, 64):
            changed, changed_labels = gates.assemble(*CORE_ARGS, retry_limit=limit)
            self.assertEqual((len(changed), changed_labels), (len(code), labels))
            self.assertNotEqual(changed, code)
        for limit in (True, False, None, 0, 65, 1.0, '8'):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                gates.assemble(*CORE_ARGS, retry_limit=limit)
            with self.subTest(stage_limit=limit), self.assertRaises(ValueError):
                stage.assemble(*STAGE_ARGS, guard_address=GUARD, retry_limit=limit)

    def test_primary_default_composition_remains_exact_after_generic_refactor(self):
        parent = self.canonical('parent_default')
        self.assertEqual((len(parent['code']), hashlib.sha256(parent['code']).hexdigest()),
                         (PARENT_BYTES, PARENT_SHA256))
        self.assertEqual(parent_stage.assemble(*STAGE_ARGS, guard_address=GUARD,
                                               following_code_bytes=0), parent)

    def test_new_stage_preserves_guarded_parent_and_appends_secondary_core_without_splices(self):
        result, parent = self.canonical('stage_default'), self.canonical('parent_guarded')
        self.assertEqual(result['secondary_factory_admission_gate_prefix_code_bytes'], PARENT_BYTES)
        self.assertEqual(result['code'][:PARENT_BYTES], parent['code'])
        size = result['secondary_factory_admission_gate_code_bytes']
        self.assertEqual((size, len(result['code'])), (GATE_BYTES, GATED_BYTES))
        self.assertEqual(hashlib.sha256(result['code']).hexdigest(), GATED_SHA256)
        self.assertEqual(hashlib.sha256(parent['code']).hexdigest(), GUARDED_PARENT_SHA256)
        self.assertEqual(result['protected_code_extent'], (STAGE_ARGS[6], PARENT_BYTES + size))
        code, labels = gates.assemble(STAGE_ARGS[3], STAGE_ARGS[4],
                                      STAGE_ARGS[6] + PARENT_BYTES, GUARD,
                                      protected_code=result['protected_code_extent'])
        self.assertEqual((result['code'][PARENT_BYTES:], result['secondary_factory_admission_gate_labels']),
                         (code, labels))
        self.assertEqual(result['secondary_factory_admission_gate_source_words'],
                         {pc: pair for pc, pair in gates.HOOKS.values()})
        for name, address in labels.items():
            self.assertEqual(result['labels']['secondary_factory_admission_gate_' + name], address)
        self.assertEqual((labels['enter'], labels['early_leave'], labels['created_leave']),
                         (0x1E98894, 0x1E98AA4, 0x1E98C38))

    def test_secondary_metadata_identifies_the_checked_transitive_chain_and_keeps_limits(self):
        result, parent = self.canonical('stage_default'), self.canonical('parent_default')
        hooks = gates.hook_words(result['secondary_factory_admission_gate_labels'])
        self.assertEqual(result['secondary_guarded_factory_address'], FACTORY)
        self.assertEqual(result['secondary_factory_refusal_direct_callers_checked'], (0x4F87C0,))
        self.assertEqual(result['secondary_factory_refusal_wrapper_callers_checked'], (0x4A326C,))
        self.assertEqual(result['guarded_factory_addresses'], (0x47D720, FACTORY))
        self.assertIs(result['known_secondary_factory_admission_guarded'], True)
        for flag in ('all_dialog_factories_guarded', 'factory_body_runtime_bounded',
                     'factory_refusal_universal_caller_safety_proven',
                     'native_factory_cleanup_rolled_back', 'dialog_ownership_proven',
                     'raw_release_proven', 'native_lifetime_proven', 'worker_termination_proven'):
            self.assertIs(result[flag], False)
        self.assertEqual((len(result['native_coherent_hooks']), len(result['generated_coherent_hooks']),
                          len(result['coherent_hooks'])), (39, 7, 46))
        self.assertEqual(result['native_coherent_hooks'], {**parent['native_coherent_hooks'], **hooks})
        self.assertEqual(result['generated_coherent_hooks'], parent['generated_coherent_hooks'])
        self.assertEqual(result['coherent_hooks'], {**parent['coherent_hooks'], **hooks})
        self.assertEqual(result['factory_admission_gate_hooks'], parent['factory_admission_gate_hooks'])
        for flag in ('known_factory_admission_guarded', 'unconfirmed_dialog_unlock_suppressed',
                     'known_dialog_outer_frees_guarded', 'guard_runtime_reset_supported',
                     'worker_buffer_free_authority_proven'):
            self.assertIs(result[flag], parent[flag])

    def test_following_RX_and_independent_required_guard_use_the_actual_new_stage(self):
        baseline = self.canonical('stage_default')
        changed = stage.assemble(*STAGE_ARGS, guard_address=GUARD, following_code_bytes=4)
        self.assertEqual((len(changed['code']), changed['labels'], changed['coherent_hooks']),
                         (len(baseline['code']), baseline['labels'], baseline['coherent_hooks']))
        self.assertEqual(changed['protected_code_extent'], (STAGE_ARGS[6], len(baseline['code']) + 4))
        self.assertNotEqual(changed['code'], baseline['code'])
        with self.assertRaises(TypeError):
            stage.assemble(*STAGE_ARGS)
        for following in (True, None, -4, 1, 1.0, '4'):
            with self.subTest(following=following), self.assertRaises(ValueError):
                stage.assemble(*STAGE_ARGS, guard_address=GUARD, following_code_bytes=following)
        for address, following in ((STAGE_ARGS[6] + len(baseline['code']) - 4, 0),
                                   (STAGE_ARGS[6] + len(baseline['code']), 4),
                                   (STAGE_ARGS[-1], 0)):
            with self.subTest(guard=address), self.assertRaises(ValueError):
                stage.assemble(*STAGE_ARGS, guard_address=address, following_code_bytes=following)

    def test_named_snapshots_and_cache_exits_restore_all45_public_parents_and_private_emitter(self):
        first, second = self.canonical('stage_default'), self.canonical('stage_default')
        first['coherent_hooks'].clear()
        first['labels']['snapshot_only'] = 0
        self.assertEqual(self.canonical('stage_default'), second)
        self.assertEqual(len(second['coherent_hooks']), 46)
        self.assertEqual(len(self._parent_functions), 45)
        self.assertEqual(len(set(module for module, _ in self._parent_functions)), 45)
        outer = tuple((module, module.assemble) for module in PARENT_MODULES)
        with self.assertRaisesRegex(RuntimeError, 'secondary cache restoration probe'):
            with parent_cache():
                for module, function in outer:
                    self.assertIsNot(module.assemble, function)
                self.assertEqual((gates.assemble, stage.assemble, primary._assemble), self._new_functions)
                raise RuntimeError('secondary cache restoration probe')
        for module, function in outer:
            self.assertIs(module.assemble, function)
        self.assertEqual((gates.assemble, stage.assemble, primary._assemble), self._new_functions)


if __name__ == '__main__':
    unittest.main()
