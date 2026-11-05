#!/usr/bin/env python3
"""Pin admission of one NULL-tolerant factory, not all dialog creation.

The two encoded callers of47D720 do not use its returned H. Other factories
have callers which dereference a NULL result. Atomic Q admission serializes
this one body with the preceding protected consumers; it cannot bound native
callbacks, undo a publication or certify all aliases and native lifetimes.
"""

from contextlib import contextmanager
from copy import deepcopy
import hashlib
import struct
import unittest

from build_reveal_bridge_diag import b
import reveal_factory_admission_gate_mips as gates
import reveal_factory_admission_gate_stage as stage
import reveal_worker_terminal_tail_mips as worker_core
import reveal_worker_terminal_tail_stage as parent_stage
import reveal_registry_receipt_mips as receipt
import test_reveal_worker_terminal_tail_contract as preceding
import test_reveal_dialog_retention_gate_mips as retention_fixture
import test_reveal_registry_birth_contract as native


STAGE_ARGS, GUARD = preceding.STAGE_ARGS, preceding.GUARD
CORE_ARGS = (STAGE_ARGS[3], STAGE_ARGS[4], 0x1EE0000, GUARD)
PARENT_BYTES = 99164
PARENT_SHA256 = '6449ade76e68805fd8857f7a2f9346e5605b3ba04de42bbc71e962fff3b8d4c0'
GATE_BYTES, GATED_BYTES = 1336, 100500
GATED_SHA256 = 'b885d43ec36a534a0bd0d3c9957a51df7eb274266533c309fde0901a5d5f572a'
GUARDED_PARENT_SHA256 = 'a61f33f9bf5e83949926e0d81d97f3e30aef3ef6720265def58afc97e78c46fb'
FACTORY, EARLY, CREATED = 0x47D720, 0x47D77C, 0x47D93C
PARENT_MODULES = (*retention_fixture._ASSEMBLY_CACHE_MODULES, worker_core, parent_stage)


@contextmanager
def parent_cache():
    """Wrap43 unchanged pure emitters, never the new factory functions."""
    originals = []
    with retention_fixture._fixture_assembly_cache(True):
        try:
            for module in (worker_core, parent_stage):
                original = module.assemble
                originals.append((module, original))
                module.assemble = retention_fixture._cached_assembler(original)
            yield
        finally:
            for module, original in reversed(originals):
                module.assemble = original


class FactoryAdmissionGateContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        native.RegistryBirthContractTests.setUpClass.__func__(cls)
        cls._canonical_outputs = {}
        cls._parent_functions = tuple((module, module.assemble) for module in PARENT_MODULES)
        cls._new_functions = gates.assemble, stage.assemble
        cls._cache = parent_cache()
        cls._cache.__enter__()
        cls.addClassCleanup(cls._finish_cache)

    @classmethod
    def _finish_cache(cls):
        try:
            cls._cache.__exit__(None, None, None)
        finally:
            for module, original in cls._parent_functions:
                if module.assemble is not original:
                    raise AssertionError('parent assembler identity not restored: ' + module.__name__)
            if (gates.assemble, stage.assemble) != cls._new_functions:
                raise AssertionError('new factory functions were replaced')

    words = native.RegistryBirthContractTests.words

    @classmethod
    def canonical(cls, name):
        """Deep-copy three named outputs under only43 parent assembly caches."""
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

    @staticmethod
    def saved_words():
        return (b.addiu(29, 29, -192),
                *(b.sw(register, offset, 29) for register, offset in gates.SAVE.items()),
                b.r_type(0, 0, 8, 0x10), b.sw(8, 0x88, 29),
                b.r_type(0, 0, 8, 0x12), b.sw(8, 0x8C, 29), b.addiu(23, 29, 192))

    @staticmethod
    def restored_words(denied=False):
        return (b.lw(8, 0x88, 29), b.r_type(8, 0, 0, 0x11),
                b.lw(8, 0x8C, 29), b.r_type(8, 0, 0, 0x13),
                *(b.lw(register, offset, 29) for register, offset in gates.SAVE.items()
                  if not denied or register not in (2, 3)),
                *((b.move(2, 0), b.move(3, 0)) if denied else ()),
                b.addiu(29, 29, 192))

    @staticmethod
    def branch(pc, op, rs, rt, target):
        return b.i_type(op, rs, rt, (target - (pc + 4)) // 4)

    def test_native_entry_and_two_pure_tail_pairs_are_exact(self):
        self.words(FACTORY, [0x27BDFDC8, 0xAFBF0234, 0xAFB40230, 0xAFB3022C,
                             0xAFB20228, 0xAFB10224, 0xAFB00220])
        self.words(0x47D76C, [0x8FBF0234, 0x8FB40230, 0x8FB3022C,
                             0x8FB20228, 0x8FB10224, 0x8FB00220,
                             0x03E00008, 0x27BD0238])
        self.words(0x47D928, [0x8FBF0234, 0x8FA20218, 0x8FB40230, 0x8FB3022C,
                             0x8FB20228, 0x8FB10224, 0x8FB00220,
                             0x03E00008, 0x27BD0238])
        self.assertEqual(gates.HOOKS,
                         {'enter': (FACTORY, (0x27BDFDC8, 0xAFBF0234)),
                          'early_leave': (EARLY, (0x8FB10224, 0x8FB00220)),
                          'created_leave': (CREATED, (0x8FB10224, 0x8FB00220))})

    def test_the_factory_has_only_two_returns_and_both_cross_the_selected_tail(self):
        returns = {pc for pc in range(FACTORY, 0x47D954, 4)
                   if self.elf.word(pc) == 0x03E00008}
        self.assertEqual(returns, {0x47D784, 0x47D944})
        self.words(0x47D740, [0x10800082, 0xAFA00214, 0x10A00080, 0x00A08021])
        self.words(0x47D764, [0x10400009, 0x8FA20214])
        self.words(0x47D870, [0x10400036, 0x8FA60218])
        self.words(0x47D94C, [0x1000FF87, 0x00001021])
        self.assertEqual(self.branches[0x47D94C], 0x47D76C)
        # The common tails are reached after RA/S4/S3/S2 and actual V0 have
        # already been restored. Replay leaves only JR and SP+=568.

    def test_stamp_word_is_unused_and_future_private_padding_is_disjoint(self):
        memory, derived = set(), set()
        for pc in range(FACTORY, 0x47D954, 4):
            word = self.elf.word(pc)
            if (word >> 21) & 31 != 29:
                continue
            if word >> 26 in (32, 33, 35, 36, 37, 40, 41, 43):
                memory.add(word & 0xFFFF)
            if word >> 26 in (8, 9) and (word >> 16) & 31 != 29:
                derived.add(word & 0xFFFF)
        self.assertEqual(memory, {0x214, 0x218, 0x220, 0x224, 0x228, 0x22C, 0x230, 0x234})
        self.assertEqual(derived, {0x18, 0xB0, 0x1B4, 0x214, 0x218})
        self.assertEqual((gates.FRAME, gates.OWNER, gates.FUTURE_OWNER), (192, 0x21C, 0xA4))
        self.assertEqual(192 - 568 + 0x21C, 0xA4)
        self.assertGreater(0xA4, 0x8C + 3)
        self.assertLessEqual(0xA4 + 4, 192)
        self.assertEqual(gates.OWNERSTAMP, int.from_bytes(b'QF72', 'little'))
        self.words(0x47D78C, [0x00002821, 0x240601FC, 0x0C296F18, 0x27A40018])
        # The memset buffer is[18,214); F+214/218 are scalar locals and F+21C
        # is padding. A native/import callee overrunning its buffer is still
        # outside this stack/call-ABI premise, not excluded by this census.

    def test_encoded_entries_have_no_interior_hook_or_delay_bypass(self):
        direct = {pc: target for pc, target in self.jumps.items()
                  if FACTORY <= target < 0x47D954}
        self.assertEqual(direct, {0x4A4EAC: FACTORY, 0x4EC450: FACTORY})
        targets = {target for target in self.branches.values()
                   if FACTORY <= target < 0x47D954}
        self.assertEqual(targets, {0x47D94C, 0x47D78C, 0x47D7F8,
                                  0x47D840, 0x47D910, 0x47D76C})
        for target in (FACTORY + 4, EARLY, EARLY + 4, CREATED, CREATED + 4,
                       EARLY + 8, CREATED + 8):
            self.assertNotIn(target, set(self.jumps.values()))
            self.assertNotIn(target, targets)
        # Encoded references are a bounded census, not frame authentication
        # or exclusion of other computed/foreign entries.

    def test_both_known_callers_discard_factory_result_before_returning(self):
        self.words(0x4A4EAC, [0x0C11F5C8, 0x27A70020, 0x1000FED8, 0x8FBF0234])
        self.words(0x4A4A18, [0x8FB20230, 0x8FB1022C, 0x8FB00228,
                             0x24020001, 0x03E00008, 0x27BD0238])
        self.assertEqual(self.branches[0x4A4EB4], 0x4A4A18)
        self.words(0x4EC450, [0x0C11F5C8, 0x00003821, 0x0C119AA0, 0x8E040058,
                             0xAE000058, 0x8FBF0024, 0x8FB10020,
                             0x8FB0001C, 0x27BD0028, 0x03E00008, 0])
        # The latter frees its pre-existing S0 context; S0 is not copied
        # from factory V0. That pre-existing context lifetime is not proved.

    def test_other_factories_have_real_NULL_dereference_counterexamples(self):
        self.words(0x45336C, [0x0C11F460, 0xAFA20024, 0x8E030008,
                             0x00402021, 0x24050004, 0x0C11F428, 0xAC430050])
        self.words(0x4A4F1C, [0x0C11F460, 0xAFA20010, 0x24030001,
                             0x3C04004A, 0xAC43005C])
        self.words(0x5091A8, [0x0C11F658, 0xAFA20010, 0x24040048,
                             0x0C119A78, 0x00408821])
        self.words(0x5091E0, [0xAE300058])
        self.words(0x50BAB4, [0x0C11F658, 0xAFA20024, 0x24040004,
                             0x0C119A78, 0x00408021])
        self.words(0x50BAD8, [0xAE020058])
        counts = {entry: sum(target == entry for target in self.jumps.values())
                  for entry in (0x47D180, 0x47D4A0, FACTORY, 0x47D960, 0x47DCE0)}
        self.assertEqual(counts, {0x47D180: 51, 0x47D4A0: 1, FACTORY: 2,
                                  0x47D960: 157, 0x47DCE0: 21})

    def test_lookup_can_reuse_H_and_inner_registration_does_not_gate_launch(self):
        self.words(0x47D750, [0x27A50214, 0x00808821, 0x00C09821,
                             0x0C11F290, 0x00E09021, 0x10400009, 0x8FA20214])
        self.words(0x47CAD0, [0xAEB10000])
        self.words(0x47D8F0, [0x0C11F278, 0xAC62006C, 0x8FA40218,
                             0x8C990070, 0x13200003, 0xAC900048,
                             0x0320F809, 0x8C85004C])
        self.words(0x47D910, [0x27A501B4, 0x02002021, 0x0C10EF40,
                             0x24060001, 0x0C11F210, 0x8FA40218])
        # Registration's status is ignored. Admission must precede lookup,
        # allocation and this opaque initializer/launch sequence. A callback
        # which never returns can keep the new Q claim BUSY indefinitely.

    def test_hook_inventory_targets_and_original_pairs_are_strict(self):
        _, labels = gates.assemble(*CORE_ARGS)
        hooks = gates.hook_words(labels)
        self.assertEqual(set(hooks), {FACTORY, EARLY, CREATED})
        for name, (pc, words) in gates.HOOKS.items():
            self.assertEqual(hooks[pc], (b.j_type(2, labels[name]), 0))
            self.words(pc, words)
            for value in (True, False, None, 0, -4, 1, 1.0, '16', 0x10000000, 0x100000000):
                with self.subTest(label=name, target=value), self.assertRaises(ValueError):
                    gates.hook_words(dict(labels, **{name: value}))

    def test_core_adds_no_services_and_uses_bounded_atomics_for_each_scope(self):
        code, labels = gates.assemble(*CORE_ARGS)
        words = self.unpack(code)
        self.assertFalse(any(word >> 26 == 3 or word >> 26 == 0 and word & 63 == 9
                             for word in words))
        self.assertIn(0xF, words)
        for name, end_name in (('enter', 'early_leave'), ('early_leave', 'created_leave'),
                               ('created_leave', None)):
            end = len(code) if end_name is None else labels[end_name] - CORE_ARGS[2]
            piece = self.unpack(code[labels[name] - CORE_ARGS[2]:end])
            self.assertTrue(any(word >> 26 == 0x30 for word in piece), name)
            self.assertTrue(any(word >> 26 == 0x38 for word in piece), name)
        # Services execute only after admitted native entry. The finite retry
        # loop bounds this gate's atomic attempts, not the native factory body.

    def test_entry_preserves_state_and_stamps_only_after_an_actual_READY_claim(self):
        code, labels = gates.assemble(*CORE_ARGS)
        words, saved = self.unpack(code), self.saved_words()
        self.assertEqual(words[:len(saved)], saved)
        retry = labels['enter_retry'] - CORE_ARGS[2]
        self.assertEqual(self.unpack(code[retry:retry + 28]),
                         (b.i_type(0x30, 20, 8, 0),
                          self.branch(labels['enter_retry'] + 4, 5, 8, 0, labels['enter_denied']), 0,
                          b.addiu(9, 0, 1), b.i_type(0x38, 20, 9, 0),
                          self.branch(labels['enter_retry'] + 20, 5, 9, 0, labels['enter_claimed']), 0))
        start, end = (labels['enter_claimed'] - CORE_ARGS[2],
                      labels['enter_replay'] - CORE_ARGS[2])
        self.assertEqual(self.unpack(code[start:end]),
                         (0xF, b.lui(8, gates.OWNERSTAMP >> 16),
                          b.ori(8, 8, gates.OWNERSTAMP & 0xFFFF), b.sw(8, 0xA4, 29),
                          *self.restored_words()))
        start = labels['enter_replay'] - CORE_ARGS[2]
        self.assertEqual(self.unpack(code[start:start + 16]),
                         (0x27BDFDC8, 0xAFBF0234, b.j_type(2, FACTORY + 8), 0))

    def test_refusal_restores_the_original_frame_and_returns_exact_NULL_pair(self):
        code, labels = gates.assemble(*CORE_ARGS)
        start, end = (labels['enter_denied'] - CORE_ARGS[2],
                      labels['early_leave'] - CORE_ARGS[2])
        self.assertEqual(self.unpack(code[start:end]),
                         (*self.restored_words(denied=True), b.r_type(31, 0, 0, 8), 0))
        self.assertEqual(len(gates.SAVE), 30)
        self.assertEqual(set(gates.SAVE), set(range(1, 32)) - {29})
        self.assertEqual((min(gates.SAVE.values()), max(gates.SAVE.values())), (0x10, 0x84))
        # Only V0/V1 change. The native F568 prologue has not run, and the
        # original A0/A1 may be invalid without authorizing an object read.

    def test_leaves_consume_current_stamp_and_clear_only_BUSY_with_bounded_SC(self):
        code, labels = gates.assemble(*CORE_ARGS)
        for name in ('early_leave', 'created_leave'):
            start = labels[name] - CORE_ARGS[2]
            save = self.saved_words()
            self.assertEqual(self.unpack(code[start:start + 4 * len(save)]), save)
            scope = labels[name] + 4 * len(save)
            expected = (b.lw(8, 0x21C, 23), b.lui(9, gates.OWNERSTAMP >> 16),
                        b.ori(9, 9, gates.OWNERSTAMP & 0xFFFF),
                        self.branch(scope + 12, 5, 8, 9, labels[name + '_done']), 0,
                        b.sw(0, 0x21C, 23), b.lui(20, GUARD >> 16),
                        b.ori(20, 20, GUARD & 0xFFFF), b.addiu(12, 0, 8), 0xF)
            begin = scope - CORE_ARGS[2]
            self.assertEqual(self.unpack(code[begin:begin + 4 * len(expected)]), expected)
            retry = labels[name + '_retry']
            expected = (b.i_type(0x30, 20, 8, 0), b.addiu(9, 0, 1),
                        self.branch(retry + 8, 5, 8, 9, labels[name + '_done']), 0,
                        b.move(9, 0), b.i_type(0x38, 20, 9, 0),
                        self.branch(retry + 24, 5, 9, 0, labels[name + '_done']), 0,
                        b.addiu(12, 12, -1),
                        self.branch(retry + 36, 5, 12, 0, retry), 0,
                        b.addiu(8, 0, 2), 0xF, b.sw(8, 0, 20), 0xF)
            begin, end = retry - CORE_ARGS[2], labels[name + '_done'] - CORE_ARGS[2]
            self.assertEqual(self.unpack(code[begin:end]), expected)
        # A non-BUSY value bypasses SC. Only owner exhaustion writes Q=2;
        # missing stamps bypass all Q accesses. No ordinary SW opens Q=0.

    def test_both_leaves_preserve_actual_results_and_replay_only_pure_native_suffixes(self):
        code, labels = gates.assemble(*CORE_ARGS)
        for name in ('early_leave', 'created_leave'):
            start, end = (labels[name + '_done'] - CORE_ARGS[2],
                          labels[name + '_replay'] - CORE_ARGS[2])
            self.assertEqual(self.unpack(code[start:end]), (0xF, *self.restored_words()))
            start = labels[name + '_replay'] - CORE_ARGS[2]
            self.assertEqual(self.unpack(code[start:start + 16]),
                             (0x8FB10224, 0x8FB00220,
                              b.j_type(2, gates.HOOKS[name][0] + 8), 0))
        # No classification from V0/V1 and no fabricated NULL after native
        # allocation/publication: those effects cannot be rolled back here.

    def test_primary_role_types_and_full_static_extents_are_strict(self):
        for index in range(4):
            invalid = (True, False, None, 0, -4, 1, 1.0, '16', 0x400000, 0x100000000)
            if index != 3:
                invalid += (0xFFFFFFFC,)
            for value in invalid:
                args = list(CORE_ARGS)
                args[index] = value
                with self.subTest(role=index, value=value), self.assertRaises(ValueError):
                    gates.assemble(*args)
        for index, value in ((0, CORE_ARGS[1]), (1, CORE_ARGS[0]), (3, CORE_ARGS[0]),
                              (3, CORE_ARGS[1]), (3, CORE_ARGS[2]),
                              (0, CORE_ARGS[2] - receipt.CONTROLLER_BYTES + 4),
                              (1, CORE_ARGS[2] - receipt.MUTEX_BYTES + 4)):
            args = list(CORE_ARGS)
            args[index] = value
            with self.subTest(role=index, overlap=value), self.assertRaises(ValueError):
                gates.assemble(*args)

    def test_extra_regions_exclude_native_code_fixed_roles_and_the_complete_tail(self):
        code, labels = gates.assemble(*CORE_ARGS)
        baseline = code, labels
        self.assertEqual(gates.assemble(*CORE_ARGS, extra_protected_data=((0xFFFFFFFC, 4),)), baseline)
        for extra in (None, [], ((True, 4),), ((0x1F90000, True),),
                      ((0x1F90000, 0),), ((0x1F90000, 3),), ((0xFFFFFFFC, 8),),
                      ((0x400000, 4),), ((CORE_ARGS[0] + receipt.CONTROLLER_BYTES - 4, 4),),
                      ((CORE_ARGS[1] + receipt.MUTEX_BYTES - 4, 4),), ((GUARD, 4),),
                      ((CORE_ARGS[2] + len(code) - 4, 4),),
                      ((0x1F90000, 8), (0x1F90004, 4))):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                gates.assemble(*CORE_ARGS, extra_protected_data=extra)

    def test_complete_protected_code_and_native_jump_region_boundaries_are_strict(self):
        code, labels = gates.assemble(*CORE_ARGS)
        size, baseline = len(code), (code, labels)
        self.assertEqual(gates.assemble(*CORE_ARGS, protected_code=(CORE_ARGS[2], size)), baseline)
        for protected in ([], (), (True, size), (CORE_ARGS[2], True), (CORE_ARGS[2], 0),
                          (CORE_ARGS[2], 3), (CORE_ARGS[2], size - 4),
                          (CORE_ARGS[2] + 4, size), (0x400000, 0x2000000), (GUARD, 4)):
            with self.subTest(protected=protected), self.assertRaises(ValueError):
                gates.assemble(*CORE_ARGS, protected_code=protected)
        args = list(CORE_ARGS)
        args[2] = 0x10000000 - size
        self.assertEqual(len(gates.assemble(*args)[0]), size)
        args[2] += 4
        with self.assertRaises(ValueError):
            gates.assemble(*args)

    def test_retry_limits_are_strict_and_do_not_change_gate_layout(self):
        default, labels = gates.assemble(*CORE_ARGS)
        for limit in (1, 64):
            code, changed = gates.assemble(*CORE_ARGS, retry_limit=limit)
            self.assertEqual((len(code), changed), (len(default), labels))
            self.assertNotEqual(code, default)
        for limit in (True, False, None, 0, -1, 65, 1.0, '8'):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                gates.assemble(*CORE_ARGS, retry_limit=limit)
            with self.subTest(stage_limit=limit), self.assertRaises(ValueError):
                stage.assemble(*STAGE_ARGS, guard_address=GUARD, retry_limit=limit)

    def test_default_parent_hash_and_explicit_zero_following_remain_unchanged(self):
        parent = self.canonical('parent_default')
        self.assertEqual((len(parent['code']), hashlib.sha256(parent['code']).hexdigest()),
                         (PARENT_BYTES, PARENT_SHA256))
        self.assertEqual(parent_stage.assemble(*STAGE_ARGS, guard_address=GUARD,
                                               following_code_bytes=0), parent)

    def test_composition_preserves_the_guarded_parent_and_appends_only_this_core(self):
        result, parent = self.canonical('stage_default'), self.canonical('parent_guarded')
        size = result['factory_admission_gate_code_bytes']
        self.assertEqual(result['factory_admission_gate_prefix_code_bytes'], PARENT_BYTES)
        self.assertEqual((size, len(result['code'])), (GATE_BYTES, GATED_BYTES))
        self.assertEqual(hashlib.sha256(result['code']).hexdigest(), GATED_SHA256)
        self.assertEqual(hashlib.sha256(parent['code']).hexdigest(), GUARDED_PARENT_SHA256)
        self.assertEqual(result['code'][:PARENT_BYTES], parent['code'])
        self.assertEqual(len(result['code']), PARENT_BYTES + size)
        self.assertEqual(result['protected_code_extent'], (STAGE_ARGS[6], PARENT_BYTES + size))
        emitted, labels = gates.assemble(STAGE_ARGS[3], STAGE_ARGS[4],
                                         STAGE_ARGS[6] + PARENT_BYTES, GUARD,
                                         protected_code=result['protected_code_extent'])
        self.assertEqual(result['code'][PARENT_BYTES:], emitted)
        self.assertEqual(result['factory_admission_gate_labels'], labels)
        self.assertEqual(result['factory_admission_gate_source_words'],
                         {pc: pair for pc, pair in gates.HOOKS.values()})
        for name, address in labels.items():
            self.assertEqual(result['labels']['factory_admission_gate_' + name], address)

    def test_metadata_limits_admission_to_one_factory_and_its_two_direct_callers(self):
        result, parent = self.canonical('stage_default'), self.canonical('parent_default')
        hooks = gates.hook_words(result['factory_admission_gate_labels'])
        self.assertEqual(result['guarded_factory_address'], FACTORY)
        self.assertEqual(result['factory_refusal_direct_callers_checked'], (0x4A4EAC, 0x4EC450))
        self.assertIs(result['known_factory_admission_guarded'], True)
        for flag in ('all_dialog_factories_guarded', 'factory_body_runtime_bounded',
                     'factory_refusal_universal_caller_safety_proven',
                     'native_factory_cleanup_rolled_back'):
            self.assertIs(result[flag], False)
        self.assertEqual((len(result['native_coherent_hooks']), len(result['generated_coherent_hooks']),
                          len(result['coherent_hooks'])), (36, 7, 43))
        self.assertEqual(result['native_coherent_hooks'], {**parent['native_coherent_hooks'], **hooks})
        self.assertEqual(result['generated_coherent_hooks'], parent['generated_coherent_hooks'])
        self.assertEqual(result['coherent_hooks'], {**parent['coherent_hooks'], **hooks})
        for flag in ('dialog_ownership_proven', 'raw_release_proven', 'native_lifetime_proven',
                     'partial_graph_cleanup_proven', 'destructor_entry_fenced',
                     'guard_runtime_reset_supported', 'worker_termination_proven',
                     'worker_terminal_release_proven', 'worker_buffer_free_authority_proven',
                     'unconfirmed_dialog_unlock_suppressed', 'known_dialog_outer_frees_guarded'):
            self.assertIs(result[flag], parent[flag])

    def test_following_RX_is_protected_without_being_appended_and_guard_is_required(self):
        baseline = self.canonical('stage_default')
        result = stage.assemble(*STAGE_ARGS, guard_address=GUARD, following_code_bytes=4)
        self.assertEqual((len(result['code']), result['labels'], result['coherent_hooks']),
                         (len(baseline['code']), baseline['labels'], baseline['coherent_hooks']))
        self.assertEqual(result['protected_code_extent'],
                         (STAGE_ARGS[6], len(baseline['code']) + 4))
        self.assertNotEqual(result['code'], baseline['code'])
        for value in (True, False, None, -4, 1, 2, 3, 1.0, '4'):
            with self.subTest(following=value), self.assertRaises(ValueError):
                stage.assemble(*STAGE_ARGS, guard_address=GUARD, following_code_bytes=value)
        with self.assertRaises(TypeError):
            stage.assemble(*STAGE_ARGS)
        for address, following in ((STAGE_ARGS[6] + len(baseline['code']) - 4, 0),
                                   (STAGE_ARGS[6] + len(baseline['code']), 4),
                                   (STAGE_ARGS[-1], 0)):
            with self.subTest(guard=address), self.assertRaises(ValueError):
                stage.assemble(*STAGE_ARGS, guard_address=address, following_code_bytes=following)

    def test_named_snapshots_and_nested_parent_cache_restore_all_temporary_identities(self):
        first, second = self.canonical('stage_default'), self.canonical('stage_default')
        first['coherent_hooks'].clear()
        first['labels']['snapshot_only'] = 0
        self.assertEqual(self.canonical('stage_default'), second)
        self.assertEqual(len(second['coherent_hooks']), 43)
        self.assertEqual(len(self._parent_functions), 43)
        self.assertEqual(len(set(module for module, _ in self._parent_functions)), 43)
        outer = tuple((module, module.assemble) for module in PARENT_MODULES)
        with self.assertRaisesRegex(RuntimeError, 'factory cache restoration probe'):
            with parent_cache():
                for module, function in outer:
                    self.assertIsNot(module.assemble, function)
                self.assertEqual((gates.assemble, stage.assemble), self._new_functions)
                raise RuntimeError('factory cache restoration probe')
        for module, function in outer:
            self.assertIs(module.assemble, function)
        self.assertEqual((gates.assemble, stage.assemble), self._new_functions)


if __name__ == '__main__':
    unittest.main()
