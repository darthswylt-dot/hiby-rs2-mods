#!/usr/bin/env python3
"""Check full caller inventories and run actual native NULL continuations.

Factory, allocator, configurator and copy outcomes are explicit bounded
substitutes. Each actual caller JAL and delay executes; surrounding native
frame/context state is supplied. NULL faults below are conditional consequences
of a proposed refusal policy, not observed player crashes. No assembler runs.
"""

from copy import deepcopy
import json
import unittest

import factory_null_audit as audit
from test_reveal_lineage_stage import LineageMachine, STACK, RETURN, MASK


CONTEXT, HANDLE, ALLOCATION, STATE = 0x1D02000, 0x1D04000, 0x1D05000, 0x1F20900
ALLOCATOR, COPY, CONFIGURATOR = 0x4669E0, 0xA5B6E0, 0x47D0A0
FREE = 0x466A80
DISPATCH_CALLBACK = 0x4A6F60


class NullFault(RuntimeError):
    def __init__(self, pc, address, operation):
        self.pc, self.address, self.operation = pc, address, operation
        super().__init__(f'{operation} at {address:#x} from instruction {pc:#x}')


class NullCallerMachine(LineageMachine):
    """Reuse instruction helpers only; no builder or other test fixture runs."""
    def __init__(self, image, *, factory_result=0, allocation_result=ALLOCATION):
        super().__init__(image.data, dict(code_base=0x1E80000, buffer=STATE,
                                         code_offset=len(image.data), labels={}, memory_bytes=4))
        self.elf = image
        self.factory_result, self.allocation_result = factory_result, allocation_result
        self.fetch_pc = self.executing_pc = None
        self.accesses, self.fp = [], {20: 0}
        self.map(CONTEXT, 0x200)
        self.map(HANDLE, 0x200)
        self.map(ALLOCATION, 0x100)
        self.r[16] = CONTEXT
        self.put(CONTEXT + 8, 0x13572468, 4)
        self.put(CONTEXT + 0x10, 0x24681357, 4)
        self.put(HANDLE + 0x58, ALLOCATION, 4)
        self.calls.clear()
        self.reads.clear()
        self.writes.clear()

    def word(self, pc):
        self.fetch_pc = pc
        return self.elf.word(pc)

    def get(self, address, size):
        try:
            self.region(address, size)
        except AssertionError:
            raise NullFault(self.executing_pc, address, 'read') from None
        if hasattr(self, 'accesses'):
            self.accesses.append(('read', self.executing_pc, address, size))
        return super().get(address, size)

    def put(self, address, value, size):
        try:
            self.region(address, size)
        except AssertionError:
            raise NullFault(self.executing_pc, address, 'write') from None
        if hasattr(self, 'accesses'):
            self.accesses.append(('write', self.executing_pc, address, size))
        return super().put(address, value, size)

    def plain(self, word):
        self.executing_pc = self.fetch_pc
        op, rs, rt, immediate = word >> 26, (word >> 21) & 31, (word >> 16) & 31, word & 0xFFFF
        signed = immediate - 0x10000 if immediate & 0x8000 else immediate
        if op == 0x28:
            self.put((self.r[rs] + signed) & MASK, self.r[rt] & 0xFF, 1)
        elif op == 0x35:
            # The518780 return restores one double; no FP arithmetic, FCSR,
            # pipeline, exceptions or earlier floating-point body is modeled.
            self.fp[rt] = self.get((self.r[rs] + signed) & MASK, 8)
        else:
            return super().plain(word)

    def external(self, target):
        self.calls.append(target)
        if target in audit.FACTORIES or target == DISPATCH_CALLBACK:
            self.hostile_result(self.factory_result)
        elif target == ALLOCATOR:
            self.hostile_result(self.allocation_result)
        elif target == COPY:
            target_address, source_address, size = self.r[4:7]
            data, offset = self.region(source_address, size)
            self.bytes(target_address, bytes(data[offset:offset + size]))
            self.hostile_result(target_address)
        elif target == CONFIGURATOR:
            self.hostile_result(0)
        elif target == FREE:
            # Execute the actual NULL leaf: free(NULL) does not overwrite V0.
            # The allocator and non-NULL free body are outside this fixture.
            if self.r[4] != 0:
                raise AssertionError('only the native free(NULL) leaf is bounded here')
            self.run_at(target, self.r[31])
        else:
            raise AssertionError(f'unbounded audit service {target:#x}')

    def frame(self, size, ra_offset):
        self.r[29] = STACK - size
        self.put(self.r[29] + ra_offset, RETURN, 4)
        return self.r[29]


class FactoryNullEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = audit.source_image()
        cls.census = audit.direct_callers(cls.image)
        cls.documents = [json.loads(path.read_text(encoding='utf-8')) for path in audit.MANIFESTS]

    def test_all_three_manifests_cover_every_one_of_229_encoded_callers(self):
        reports = [audit.verify_manifest(document, self.image, self.census)
                   for document in self.documents]
        self.assertEqual({int(item['factory'], 16): item['encoded_direct_callers']
                          for item in reports}, audit.FACTORIES)
        self.assertEqual(sum(item['encoded_direct_callers'] for item in reports), 229)
        self.assertTrue(all(item['all_encoded_callers_listed'] for item in reports))
        self.assertFalse(any(item['universal_refusal_safety_proven'] or item['runtime_guard_added']
                             for item in reports))

    def test_stale_source_hash_and_instruction_evidence_are_rejected(self):
        document = deepcopy(self.documents[0])
        document['source_sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            audit.verify_manifest(document, self.image, self.census)
        document = deepcopy(self.documents[0])
        document['callers'][0]['evidence'][0]['word'] = '0xFFFFFFFF'
        with self.assertRaises(ValueError):
            audit.verify_manifest(document, self.image, self.census)

    def test_omitted_duplicate_or_invented_callers_are_rejected(self):
        for mode in ('omit', 'duplicate', 'invent'):
            with self.subTest(mode=mode):
                document = deepcopy(self.documents[0])
                if mode == 'omit':
                    document['callers'].pop()
                elif mode == 'duplicate':
                    document['callers'].append(deepcopy(document['callers'][0]))
                else:
                    document['callers'][0]['callsite'] = '0x00400000'
                with self.assertRaises(ValueError):
                    audit.verify_manifest(document, self.image, self.census)

    def test_unexplained_or_unknown_classifications_and_bad_hex_are_rejected(self):
        for key, value in (('classification', 'safe'), ('classification', []),
                           ('notes', ''), ('notes', '   '), ('notes', True),
                           ('callsite', True)):
            with self.subTest(key=key):
                document = deepcopy(self.documents[0])
                document['callers'][0][key] = value
                with self.assertRaises(ValueError):
                    audit.verify_manifest(document, self.image, self.census)

    def test_invented_or_empty_instruction_records_cannot_satisfy_evidence_requirements(self):
        for mode in ('scalars', 'missing_word', 'duplicate', 'unrelated'):
            with self.subTest(mode=mode):
                document = deepcopy(self.documents[0])
                row = document['callers'][0]
                if mode == 'scalars':
                    row['evidence'] = [1, 2]
                elif mode == 'missing_word':
                    row['evidence'][0].pop('word')
                elif mode == 'duplicate':
                    row['evidence'] = [deepcopy(row['evidence'][0]) for _ in range(2)]
                else:
                    # Real words from another caller do not document this call.
                    row['evidence'] = deepcopy(document['callers'][1]['evidence'])
                with self.assertRaises(ValueError):
                    audit.verify_manifest(document, self.image, self.census)

    def test_known_unchecked_factory_returns_are_not_labeled_discarded(self):
        rows = {audit.hex_word(row['callsite']): row for document in self.documents
                for row in document['callers']}
        for site in (0x45336C, 0x4A4F1C, 0x4AF958, 0x4AFC74, 0x4CF1F4,
                     0x5091A8, 0x50BAB4, 0x5270A0):
            with self.subTest(site=hex(site)):
                self.assertEqual(rows[site]['classification'], 'null_dereference')

    def test_guarded_class_requires_explicit_local_closure(self):
        for key in ('null_guard_observed', 'null_path_locally_closed'):
            for value in (None, False, 1):
                with self.subTest(key=key, value=value):
                    document = deepcopy(self.documents[1])
                    row = next(row for row in document['callers']
                               if row['classification'] == 'null_guarded')
                    row[key] = value
                    with self.assertRaises(ValueError):
                        audit.verify_manifest(document, self.image, self.census)

    def test_guarded_metadata_cannot_name_an_unrelated_or_opposite_branch(self):
        for site, key, value in ((0x453A0C, 'null_guard_pc', '0x453a0c'),
                                  (0x453A0C, 'null_continuation', '0x453a1c'),
                                  (0x4A33A8, 'null_continuation', '0x4a3118')):
            with self.subTest(site=hex(site), key=key):
                document = deepcopy(self.documents[1])
                row = next(row for row in document['callers']
                           if audit.hex_word(row['callsite']) == site)
                self.assertEqual(row['classification'], 'null_guarded')
                row[key] = value
                with self.assertRaises(ValueError):
                    audit.verify_manifest(document, self.image, self.census)

    def test_unresolved_requires_a_pinned_indirect_frontier(self):
        for mode in ('missing', 'kind', 'ordinary_call', 'word'):
            with self.subTest(mode=mode):
                document = deepcopy(self.documents[1])
                row = next(row for row in document['callers']
                           if row['classification'] == 'unresolved')
                boundary = row['unresolved_boundary']
                if mode == 'missing':
                    row.pop('unresolved_boundary')
                elif mode == 'kind':
                    boundary['kind'] = 'probably_safe'
                elif mode == 'ordinary_call':
                    boundary['pc'] = row['callsite']
                    boundary['word'] = f"{self.image.word(audit.hex_word(row['callsite'])):#x}"
                else:
                    boundary['word'] = '0x00000000'
                with self.assertRaises(ValueError):
                    audit.verify_manifest(document, self.image, self.census)


class GuardedNullCallerMachine(NullCallerMachine):
    """Actual guarded caller paths; UI cleanup/query bodies stay bounded."""
    def __init__(self, image, **options):
        super().__init__(image, **options)
        self.map(0xB80000, 0x20000)
        self.map(CONTEXT + 0x200, 0x200)
        self.ui_calls = []

    def external(self, target):
        if target in (0x477600, 0x469240, 0x4691E0, 0x469540, 0x474380,
                      0x485DE0, 0xA5B440):
            self.calls.append(target)
            self.ui_calls.append((target, tuple(self.r[4:8])))
            if target == 0x477600:
                # The actual short setter overwrites V0 before its table stores.
                self.run_at(target, self.r[31])
            elif target == 0xA5B440:
                # Supplied old source bytes, not a returned factory pointer.
                for offset in range(self.r[6]):
                    self.put(self.r[4] + offset, self.get(self.r[5] + offset, 1), 1)
                self.hostile_result(self.r[4])
            else:
                self.hostile_result(0)
        else:
            super().external(target)


class NativeNullGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = audit.source_image()

    def test_two_NULL_exits_return_without_entering_the_nonnull_body(self):
        for site, size, ra, positive, result in (
                (0x453A0C, 760, 0x2F4, 0x453A1C, 0),
                (0x50049C, 56, 0x34, 0x5004AC, 1)):
            with self.subTest(site=hex(site)):
                machine = GuardedNullCallerMachine(self.image)
                machine.frame(size, ra)
                machine.r[4] = CONTEXT
                if site == 0x50049C:
                    machine.r[16] = 0xB90000  # Actual LUI S0 at500444.
                    machine.put(0xB8BB2C, 0x12345678, 4)
                machine.run_at(site, RETURN)
                self.assertEqual((machine.r[2], machine.r[29], machine.r[31]),
                                 (result, STACK, RETURN))
                self.assertEqual(machine.calls, [0x47D960])
                self.assertFalse(any(address == HANDLE + 0x5C
                                     for address, _, _ in machine.writes))
                if site == 0x50049C:
                    self.assertEqual(machine.get(0xB8BB2C, 4), 0)
                control = GuardedNullCallerMachine(self.image, factory_result=HANDLE)
                control.frame(size, ra)
                control.r[4] = CONTEXT
                control.run_at(site, positive)
                self.assertEqual(control.r[2], HANDLE)

    def test_two_NULL_cleanup_paths_use_old_context_and_return_one(self):
        for site in (0x4A33A8, 0x4A33D8):
            for old_s2 in (0, CONTEXT + 0x100):
                for result in (0, HANDLE):
                    with self.subTest(site=hex(site), old_s2=old_s2, result=result):
                        machine = GuardedNullCallerMachine(self.image, factory_result=result)
                        machine.frame(56, 0x34)
                        machine.r[17], machine.r[18] = CONTEXT, old_s2
                        machine.run_at(site, RETURN)
                        self.assertEqual((machine.r[2], machine.r[29], machine.r[31]),
                                         (1, STACK, RETURN))
                        if result:
                            self.assertEqual(machine.calls, [0x47D960])
                        else:
                            targets = [target for target, _ in machine.ui_calls]
                            self.assertIn(0x477600, targets)
                            self.assertIn(0x474380, targets)
                            self.assertEqual(0x469240 in targets,
                                             site == 0x4A33A8 and old_s2 != 0)
                            setters = [args for target, args in machine.ui_calls
                                       if target == 0x477600]
                            expected = ([(0x4A12C0, 0, 0, 27)] if old_s2 else [])
                            expected += [(0x4A13E0, 0, 0, 24)]
                            if site == 0x4A33D8:
                                expected = [(0x4A1660, 0, CONTEXT, 25)]
                            self.assertEqual(setters, expected)
                            for target, args in machine.ui_calls:
                                if target == 0x469240:
                                    self.assertEqual(args[0], old_s2)
                                elif target in (0x4691E0, 0x469540):
                                    self.assertEqual(args[0], CONTEXT)
                                elif target == 0xA5B440:
                                    self.assertEqual(args[:3], (0xB8B168, CONTEXT, 680))
                                elif target == 0x474380:
                                    self.assertEqual(args[:3], (320, 1, 0))
                            self.assertEqual(machine.get(0xB8B170, 4), 0x13572468)

    def test_NULL_skips_the_H_field_store_but_keeps_the_native_setter_and_return(self):
        for result in (0, HANDLE):
            with self.subTest(result=result):
                machine = GuardedNullCallerMachine(self.image, factory_result=result)
                machine.frame(48, 0x2C)
                machine.r[17] = CONTEXT
                machine.run_at(0x52B320, RETURN)
                self.assertEqual((machine.r[2], machine.r[29], machine.r[31]),
                                 (0, STACK, RETURN))
                self.assertEqual(machine.calls, [0x47D960, 0x477600])
                self.assertEqual(machine.get(HANDLE + 0x5C, 4), CONTEXT if result else 0)
                self.assertEqual(machine.get(0xB8A9FC + 136 * 4, 4), 0x52A4E0)


class NativeNullContinuationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = audit.source_image()

    def machine(self, **options):
        return NullCallerMachine(self.image, **options)

    def assert_fault(self, machine, start, stop, pc, address, operation):
        with self.assertRaises(NullFault) as failed:
            machine.run_at(start, stop)
        self.assertEqual((failed.exception.pc, failed.exception.address, failed.exception.operation),
                         (pc, address, operation))

    def test_d180_delay_store_faults_before_configurator_can_reject_NULL(self):
        bad = self.machine()
        bad.frame(72, 0x44)
        self.assert_fault(bad, 0x45336C, RETURN, 0x453384, 0x50, 'write')
        self.assertEqual(bad.calls, [0x47D180])
        good = self.machine(factory_result=HANDLE)
        good.frame(72, 0x44)
        good.run_at(0x45336C, RETURN)
        self.assertEqual((good.r[29], good.r[31]), (STACK, RETURN))
        self.assertEqual(good.get(HANDLE + 0x50, 4), 0x13572468)
        self.assertEqual(good.calls, [0x47D180, CONFIGURATOR])

    def test_d180_immediate_flag_store_requires_a_nonnull_result(self):
        bad = self.machine()
        self.assert_fault(bad, 0x4A4F1C, 0x4A4F30, 0x4A4F2C, 0x5C, 'write')
        good = self.machine(factory_result=HANDLE)
        good.run_at(0x4A4F1C, 0x4A4F30)
        self.assertEqual(good.get(HANDLE + 0x5C, 4), 1)

    def test_d180_context_reads_fault_before_the_later_context_check(self):
        for site, fault_pc in ((0x4AF958, 0x4AF964), (0x4AFC74, 0x4AFC80),
                                (0x4CF1F4, 0x4CF200)):
            with self.subTest(site=hex(site)):
                bad = self.machine()
                self.assert_fault(bad, site, fault_pc + 4, fault_pc, 0x58, 'read')
                good = self.machine(factory_result=HANDLE)
                good.run_at(site, fault_pc + 4)
                self.assertEqual(good.r[2], ALLOCATION)

    def test_d180_allocation_failure_still_executes_its_branch_delay_NULL_store(self):
        for allocation in (0, ALLOCATION):
            with self.subTest(allocation=allocation):
                bad = self.machine(allocation_result=allocation)
                bad.r[2] = CONTEXT + 0x4200  # The call's original global-clear delay is valid.
                self.assert_fault(bad, 0x5270A0, 0x5270BC, 0x5270B8, 0x58, 'write')
                self.assertEqual(bad.calls, [0x47D180, ALLOCATOR])
                good = self.machine(factory_result=HANDLE, allocation_result=allocation)
                good.r[2] = CONTEXT + 0x4200
                # A failed allocation branches to5270F0 after the same store.
                stop = 0x5270F0 if allocation == 0 else 0x5270BC
                good.run_at(0x5270A0, stop)
                self.assertEqual(good.get(HANDLE + 0x58, 4), allocation)

    def test_d960_later_successful_allocation_writes_through_saved_NULL_handle(self):
        for site, fault_pc, stop in ((0x5091A8, 0x5091E0, 0x5091E4),
                                     (0x50BAB4, 0x50BAD8, 0x50BADC)):
            with self.subTest(site=hex(site)):
                bad = self.machine()
                self.assert_fault(bad, site, stop, fault_pc, 0x58, 'write')
                self.assertEqual(bad.calls[:2], [0x47D960, ALLOCATOR])
                good = self.machine(factory_result=HANDLE)
                good.run_at(site, stop)
                self.assertEqual(good.get(HANDLE + 0x58, 4), ALLOCATION)

    def test_d960_allocation_failure_can_hide_that_NULL_result_is_unsafe(self):
        for site, stop in ((0x5091A8, 0x5091E4), (0x50BAB4, 0x50BAEC)):
            with self.subTest(site=hex(site)):
                machine = self.machine(allocation_result=0)
                machine.run_at(site, stop)
                self.assertEqual(machine.calls, [0x47D960, ALLOCATOR])
                self.assertFalse(any(address == 0x58 for address, _, _ in machine.writes))

    def test_dce0_discarded_case_replaces_result_with_preexisting_context_field(self):
        for result in (0, HANDLE):
            with self.subTest(result=result):
                machine = self.machine(factory_result=result)
                machine.run_at(0x43C594, 0x43C5A0)
                self.assertEqual(machine.r[2], 0x24681357)
                self.assertEqual(machine.calls, [0x47DCE0])

    def test_d960_native_free_NULL_preserves_factory_result_until_caller_return(self):
        for site in (0x435168, 0x4351DC):
            for result in (0, HANDLE):
                with self.subTest(site=hex(site), result=result):
                    machine = self.machine(factory_result=result)
                    machine.frame(80, 0x4C)
                    machine.put(CONTEXT + 0x58, 0, 4)
                    machine.run_at(site, RETURN)
                    self.assertEqual((machine.r[2], machine.r[29], machine.r[31]),
                                     (result, STACK, RETURN))
                    self.assertEqual(machine.calls, [0x47D960, FREE])
                    self.assertEqual(machine.get(CONTEXT + 0x58, 4), 0)

    def test_d960_skipping_free_also_propagates_factory_result_to_caller(self):
        for site in (0x4AEB74, 0x4AEBD4):
            for result in (0, HANDLE):
                with self.subTest(site=hex(site), result=result):
                    machine = self.machine(factory_result=result)
                    machine.frame(1168, 0x48C)
                    machine.put(CONTEXT + 0x58, 0, 4)
                    machine.run_at(site, RETURN)
                    self.assertEqual((machine.r[2], machine.r[29], machine.r[31]),
                                     (result, STACK, RETURN))
                    self.assertEqual(machine.calls, [0x47D960])
                    self.assertEqual(machine.get(CONTEXT + 0x58, 4), 0)

    def test_dce0_four_wrappers_really_return_NULL_to_their_upper_callers(self):
        for site, size, ra in ((0x49A6D8, 3288, 0xCD4), (0x4A7080, 1160, 0x484),
                               (0x4A8278, 80, 0x4C), (0x5188CC, 72, 0x3C)):
            with self.subTest(site=hex(site)):
                machine = self.machine()
                frame = machine.frame(size, ra)
                if site == 0x5188CC:
                    machine.put(frame + 0x40, 0x123456789ABCDEF0, 8)
                machine.run_at(site, RETURN)
                self.assertEqual((machine.r[2], machine.r[29], machine.r[31]), (0, STACK, RETURN))
                self.assertEqual(machine.calls, [0x47DCE0])
                if site == 0x5188CC:
                    self.assertEqual(machine.fp[20], 0x123456789ABCDEF0)

    def test_known_controller_dispatcher_discards_a_NULL_callback_result(self):
        for result in (0, HANDLE):
            with self.subTest(result=result):
                machine = self.machine(factory_result=result)
                machine.frame(32, 0x1C)
                machine.r[25] = DISPATCH_CALLBACK
                machine.run_at(0x50A13C, RETURN)
                self.assertEqual((machine.r[2], machine.r[29], machine.r[31]), (1, STACK, RETURN))
                self.assertEqual(machine.calls, [DISPATCH_CALLBACK])


class CallbackBindingEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = audit.source_image()
        cls.documents = [json.loads(path.read_text(encoding='utf-8')) for path in audit.MANIFESTS]
        cls.binding = json.loads(audit.CALLBACK_BINDINGS.read_text(encoding='utf-8'))
        cls.inventory = audit.literal_callback_store_inventory(cls.image)

    def verify(self, document):
        return audit.verify_callback_bindings(document, self.image, self.documents, self.inventory)

    def test_selected_assignments_cover_all_ten_computed_consumers_without_promotion(self):
        report = self.verify(self.binding)
        self.assertEqual((report['computed_consumers'], report['local_frontiers'],
                          report['selected_assignment_candidates']), (10, 4, 4))
        self.assertEqual(report['target_behaviors'], {'native_value_kill': 3, 'opaque_before_kill': 1})
        self.assertFalse(report['runtime_binding_proven'] or report['closed_write_set_proven']
                         or report['classification_promoted'] or report['universal_refusal_safety_proven'])

    def test_source_inventory_cannot_be_promoted_to_runtime_binding(self):
        for flag in ('runtime_binding_proven', 'closed_write_set_proven',
                     'universal_refusal_safety_proven', 'classification_promoted'):
            for value in (True, None, 0):
                with self.subTest(flag=flag, value=value):
                    document = deepcopy(self.binding)
                    document[flag] = value
                    with self.assertRaises(ValueError):
                        self.verify(document)
        document = deepcopy(self.binding)
        document['publication_and_lifetime']['execution_ordering_proven'] = True
        with self.assertRaises(ValueError):
            self.verify(document)

    def test_omitted_or_moved_consumers_and_stale_store_census_are_rejected(self):
        for mode in ('omitted', 'duplicate', 'wrong_slot', 'census'):
            with self.subTest(mode=mode):
                document = deepcopy(self.binding)
                row = document['consumer_frontiers'][0]
                if mode == 'omitted':
                    row['consumers'].pop()
                elif mode == 'duplicate':
                    row['consumers'].append(row['consumers'][0])
                elif mode == 'wrong_slot':
                    row['slot'] = '0x274'
                else:
                    document['literal_store_inventory']['0x24']['sw_count'] -= 1
                with self.assertRaises(ValueError):
                    self.verify(document)

    def test_false_targets_stale_words_and_missing_constructor_fragments_are_rejected(self):
        for mode in ('target', 'word', 'constructor', 'source'):
            with self.subTest(mode=mode):
                document = deepcopy(self.binding)
                row = document['selected_assignment_candidates'][0]
                if mode == 'target':
                    row['target'] = '0x4557e0'
                elif mode == 'word':
                    row['evidence'][0]['word'] = '0x00000000'
                elif mode == 'constructor':
                    row['evidence'].pop(0)
                else:
                    document['source_sha256'] = '0' * 64
                with self.assertRaises(ValueError):
                    self.verify(document)


class CallbackCut(RuntimeError):
    def __init__(self, kind, target):
        self.kind, self.target = kind, target
        super().__init__(f'{kind} at {target:#x}')


class CallbackBindingMachine(NullCallerMachine):
    """Native assignment/dispatch fragments, with explicit body/import cuts."""
    def __init__(self, image):
        super().__init__(image)
        self.map(CONTEXT + 0x200, 0x200)
        self.map(0xADF000, 0x1000)
        self.fp[0] = 0  # Supplied raw SWC1 source, no FP arithmetic/FCSR model.

    def plain(self, word):
        if word >> 26 == 57:
            self.executing_pc = self.fetch_pc
            rs, rt, immediate = (word >> 21) & 31, (word >> 16) & 31, word & 0xFFFF
            signed = immediate - 0x10000 if immediate & 0x8000 else immediate
            self.put((self.r[rs] + signed) & MASK, self.fp[rt] & MASK, 4)
        else:
            super().plain(word)

    def external(self, target):
        self.calls.append(target)
        if target in (0x4557C0, 0x45B100, 0x466AC0):
            self.run_at(target, self.r[31])
        elif target == 0x4E4A60:
            self.run_at(target, 0x4E4A70)
            raise CallbackCut('native_value_kill', 0x4E4A6C)
        elif target in (0x437D20, 0x466DA0):
            self.run_at(target, self.r[31])
        elif target == 0xA5B960:
            # Stop at external entry; actual PLT words are pinned separately.
            raise CallbackCut('import_entry', target)
        elif target == 0:
            raise CallbackCut('unassigned_target', target)
        else:
            raise AssertionError(f'unbounded callback target {target:#x}')


class NativeCallbackBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = audit.source_image()
        cls.binding = json.loads(audit.CALLBACK_BINDINGS.read_text(encoding='utf-8'))

    def assigned(self, name):
        row = next(row for row in self.binding['selected_assignment_candidates'] if row['id'] == name)
        machine = CallbackBindingMachine(self.image)
        machine.r[16] = CONTEXT
        machine.run_at(audit.hex_word(row['materialization_pc']), audit.hex_word(row['store_pc']) + 4)
        self.assertEqual(machine.get(CONTEXT + audit.hex_word(row['slot']), 4),
                         audit.hex_word(row['target']))
        return machine

    def test_list_assignment_and_actual_method_kill_both_incoming_values(self):
        for incoming in (0, HANDLE):
            with self.subTest(incoming=incoming):
                machine = self.assigned('list_clear')
                machine.put(CONTEXT + 0xC, 123, 4)
                machine.r[4], machine.r[2] = CONTEXT, incoming
                native_pcs = []
                machine.before_instruction = native_pcs.append
                machine.run_at(0x4A6E60, 0x4A6E78)
                self.assertEqual((machine.r[2], machine.get(CONTEXT + 0xC, 4)), (0, 0))
                # This stock list body is internal to the inherited runner.
                self.assertIn(0x4557C0, native_pcs)
                # The control trace records JR, while its delay runs in plain().
                self.assertIn(0x4557CC, native_pcs)

    def test_changed_slot_invalidates_constructor_only_target_inference(self):
        for incoming in (0, HANDLE):
            with self.subTest(incoming=incoming):
                machine = self.assigned('list_clear')
                # Deliberate fixture mutation, not a claimed hardware writer.
                machine.put(CONTEXT + 0x24, 0x466AC0, 4)
                machine.put(CONTEXT + 0xC, 123, 4)
                machine.r[4], machine.r[2] = CONTEXT, incoming
                machine.run_at(0x4A6E60, 0x4A6E78)
                self.assertEqual((machine.r[2], machine.get(CONTEXT + 0xC, 4)), (incoming, 123))
                self.assertEqual(machine.calls, [0x466AC0])

    def test_same_offset_candidates_have_different_actual_value_frontiers(self):
        for incoming in (0, HANDLE):
            with self.subTest(incoming=incoming):
                known = self.assigned('other_widget_field')
                known.put(CONTEXT + 0x1B0, 0x24681357, 4)
                known.r[4], known.r[5], known.r[2] = CONTEXT, CONTEXT + 0x100, incoming
                known.run_at(0x43B120, 0x43B158)
                self.assertEqual(known.r[2], 0x24681357)
                self.assertEqual(known.calls, [0x45B100])
                opaque = self.assigned('ui_lock')
                opaque.put(CONTEXT + 0x13C, ALLOCATION, 4)
                opaque.r[4], opaque.r[5], opaque.r[2] = CONTEXT, CONTEXT + 0x100, incoming
                with self.assertRaises(CallbackCut) as cut:
                    opaque.run_at(0x43B120, 0x43B158)
                self.assertEqual((cut.exception.kind, cut.exception.target, opaque.r[2]),
                                 ('import_entry', 0xA5B960, incoming))
                self.assertEqual(opaque.calls, [0x437D20, 0x466DA0, 0xA5B960])

    def test_pending_publication_is_readable_before_assignment_and_bound_targets_kill_later(self):
        pending = CallbackBindingMachine(self.image)
        pending.put(0xADF20C, CONTEXT, 4)
        pending.r[4] = CONTEXT + 0x100
        pending.run_at(0x43CFE0, 0x43D02C)
        self.assertEqual(pending.get(0xADF208, 4), CONTEXT)
        pending.run_at(0x43D200, RETURN)
        self.assertEqual((pending.r[2], pending.get(CONTEXT + 0x2A4, 4)), (CONTEXT, 0))
        # An explicitly supplied reentry cut, not proof of real scheduling.
        pending.r[4:7] = [CONTEXT, CONTEXT + 0x100, CONTEXT + 0x110]
        pending.r[2] = HANDLE
        with self.assertRaises(CallbackCut) as cut:
            pending.run_at(0x4E5320, 0x4E5364)
        self.assertEqual((cut.exception.kind, cut.exception.target, pending.r[2]),
                         ('unassigned_target', 0, HANDLE))
        for start, stop in ((0x4E5320, 0x4E5364), (0x4E5560, 0x4E5598)):
            for incoming in (0, HANDLE):
                with self.subTest(start=hex(start), incoming=incoming):
                    machine = self.assigned('property_object')
                    machine.put(CONTEXT + 0x294, 0x31415926, 4)
                    machine.r[4:7] = [CONTEXT, CONTEXT + 0x100, CONTEXT + 0x110]
                    machine.r[2] = incoming
                    with self.assertRaises(CallbackCut) as cut:
                        machine.run_at(start, stop)
                    self.assertEqual((cut.exception.kind, cut.exception.target, machine.r[2]),
                                     ('native_value_kill', 0x4E4A6C, 0x31415926))
                    self.assertEqual(machine.calls, [0x4E4A60])


class UiLifecycleMachine(CallbackBindingMachine):
    """Run the phase edges with explicit cuts for resource and service bodies."""
    def __init__(self, image, *, initializer_result=0, destroy_result=0):
        super().__init__(image)
        self.map(0xA90000, 0x1000)
        self.initializer_result = initializer_result
        self.destroy_result = destroy_result
        self.phases, self.releases = [], []

    def external(self, target):
        self.calls.append(target)
        if target == 0x4E4DE0:
            return_pc = self.r[31]
            self.phases.append(('initializer_entry', self.get(CONTEXT + 0x2A4, 4)))
            self.run_at(target, 0x4E4E40)
            # Supply the middle initialization outcome. The actual prefix has
            # assigned the callback and the actual suffix restores the frame.
            self.r[2] = self.initializer_result & MASK
            self.run_at(0x4E4F8C, return_pc)
            self.phases.append(('initializer_return', self.r[2]))
        elif target == 0x4E4AC0:
            self.phases.append(('loop_adapter', self.get(CONTEXT + 0x2A4, 4)))
            self.run_at(target, self.r[31])
        elif target == 0x43C980:
            # The adapter reached its real event-loop call. Observe the getter
            # at this cut, without supplying an input event or running the loop.
            self.run_at(0x43D200, self.r[31])
            self.phases.append(('loop_getter', self.r[2]))
            self.hostile_result(0)
        elif target == 0x4E3EA0:
            self.phases.append(('destructor_entry', self.r[4]))
            self.hostile_result(0)
        elif target == 0xA5BC60:
            destination, value, size = self.r[4:7]
            if value or size not in (0x40, 0x104):
                raise AssertionError('unexpected initializer clear')
            self.bytes(destination, bytes(size))
            self.hostile_result(destination)
        elif target == 0x466D60:
            self.hostile_result(ALLOCATION)
        elif target in (0x466DE0, 0x43D4C0):
            self.run_at(target, self.r[31])
        elif target == 0xA5B0F0:
            self.phases.append(('raw_destroy', self.r[4]))
            self.hostile_result(self.destroy_result)
        elif target == FREE:
            self.releases.append((self.r[4], self.get(0xADF208, 4)))
            self.hostile_result(0)
        elif target == 0x43CB20:
            self.phases.append(('base_cleanup', self.r[4]))
            self.hostile_result(0)
        elif target in (0x423980, 0x467160, 0x466F80, 0x448200):
            self.hostile_result(0)
        else:
            raise AssertionError(f'unbounded lifecycle service {target:#x}')


class NativeUiLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = audit.source_image()

    def test_driver_assigns_callback_before_own_loop_and_always_calls_destructor(self):
        for window in (0, CONTEXT + 0x100):
            for result in (0, -5):
                with self.subTest(window=window, supplied_initializer_result=result):
                    machine = UiLifecycleMachine(self.image, initializer_result=result)
                    machine.put(0xADF208, CONTEXT, 4)
                    machine.put(CONTEXT + 0x2C, window, 4)
                    machine.r[4] = CONTEXT
                    machine.run_at(0x4E3E40, RETURN)
                    machine.r[4] = CONTEXT
                    machine.run_at(0x4E3DE0, RETURN)
                    expected = [('initializer_entry', 0), ('initializer_return', result & MASK),
                                ('loop_adapter', 0x4E4A60)]
                    if window:
                        expected.append(('loop_getter', CONTEXT))
                    expected.append(('destructor_entry', CONTEXT))
                    self.assertEqual(machine.phases, expected)
                    self.assertEqual(machine.get(CONTEXT + 0x290, 4), ALLOCATION)
                    self.assertEqual((machine.r[2], machine.r[29], machine.r[31]),
                                     (0, STACK, RETURN))

    def test_resource_release_precedes_replacement_and_exit_can_skip_replacement(self):
        for status in (0, 16):
            for exit_flag, pending in ((0, 0), (0, CONTEXT + 0x100), (1, CONTEXT + 0x100)):
                with self.subTest(raw_destroy_status=status, exit_flag=exit_flag, pending=pending):
                    machine = UiLifecycleMachine(self.image, destroy_result=status)
                    machine.put(0xADF208, CONTEXT, 4)
                    machine.put(CONTEXT + 0x290, ALLOCATION, 4)
                    machine.frame(56, 0x34)
                    machine.r[16] = CONTEXT
                    machine.run_at(0x4E3F6C, RETURN)
                    self.assertEqual(machine.phases, [('raw_destroy', ALLOCATION),
                                                      ('base_cleanup', CONTEXT)])
                    self.assertEqual(machine.releases, [(ALLOCATION, CONTEXT)])
                    machine.run_at(0x43D200, RETURN)
                    self.assertEqual((machine.r[2], machine.get(CONTEXT + 0x290, 4)),
                                     (CONTEXT, ALLOCATION))

                    machine.frame(64, 0x3C)
                    machine.r[16] = machine.r[22] = machine.r[23] = 0xAE0000
                    machine.r[2] = 0  # Value returned by the actual phase driver.
                    machine.put(0xADF20C, pending, 4)
                    machine.put(0xADF214, exit_flag, 4)
                    machine.run_at(0x43D06C, RETURN if exit_flag else 0x43D084)
                    self.assertEqual(machine.get(0xADF208, 4), CONTEXT if exit_flag else pending)
                    self.assertEqual(machine.get(0xADF20C, 4), pending if exit_flag else 0)
                    if exit_flag:
                        self.assertEqual(machine.calls[-2:], [0x466F80, 0x448200])

    def test_shutdown_clears_active_before_generic_object_release(self):
        machine = UiLifecycleMachine(self.image)
        for root in (0xADF208, 0xADF20C, 0xADF210):
            machine.put(root, CONTEXT, 4)
        machine.put(0xA90F98, CONTEXT, 4)
        machine.put(0xA90F9C, 0x94B400, 4)
        machine.run_at(0x43D140, RETURN)
        self.assertEqual(machine.releases, [(CONTEXT, 0)])
        self.assertEqual(machine.calls, [0x43D4C0, FREE])
        self.assertEqual([machine.get(root, 4) for root in (0xADF208, 0xADF20C, 0xADF210)],
                         [0, 0, 0])
        self.assertEqual((machine.r[29], machine.r[31]), (STACK, RETURN))


if __name__ == '__main__':
    unittest.main()
