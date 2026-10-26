#!/usr/bin/env python3
"""Execute receipt-bound historical owner issuance, not a native lifetime lease.

Actual registry, receipt and checked owner instructions execute. Raw pthread
services and allocation use the bounded hostile-ABI fixture. No device, image
builder, native scheduler, cleanup continuation or producer admission is used.
"""

import hashlib
import unittest

import reveal_paint_retirement_mips as owner
import reveal_registry_owner_stage as stage
import reveal_registry_receipt_mips as receipt
import test_folderfollow_reveal_static_contract as source
from test_reveal_registry_receipt_mips import (
    RegistryReceiptMachine, STATE, CODE, CONTROLLER, INPUT, REGISTRY_MUTEX,
    PAINT_MUTEX, ENGINE, DESCRIPTOR, RAW_LOCK, RAW_UNLOCK, STACK, RETURN, MASK)


OWNER_STATE, BIND_STATE, REQUEST = 0x1F70000, 0x1F80000, 0x1F90000


class RegistryOwnerMachine(RegistryReceiptMachine):
    """Native registration with a composed in-memory, non-installable observer."""

    def __init__(self, image, *, capacity=16, owner_capacity=16,
                 ticket_limit=owner.MAX_TICKET, acquire=0, release=0,
                 paint_acquire_result=0, paint_release_result=0, hooks=True):
        super().__init__(image, capacity=capacity, acquire=acquire, release=release,
                         hooks=False)
        self.composition = stage.assemble(
            STATE, BIND_STATE, OWNER_STATE, CONTROLLER, REGISTRY_MUTEX, PAINT_MUTEX,
            CODE, capacity=capacity, owner_capacity=owner_capacity,
            ticket_limit=ticket_limit)
        self.code = self.composition['code']
        self.code_bytes = self.code
        self.labels = self.composition['labels']
        self.owner_labels = self.composition['owner_labels']
        self.issuer_labels = self.composition['issuer_labels']
        self.receipt_labels = self.composition['receipt_labels']
        self.bridge_labels = self.receipt_labels
        self.owner_capacity = owner_capacity
        self.map(OWNER_STATE, self.composition['owner_memory_bytes'])
        self.map(BIND_STATE, self.composition['binding_memory_bytes'])
        self.map(REQUEST, 36)
        self.put(CONTROLLER + 0x284, owner.LOCK, 4)
        self.put(CONTROLLER + 0x288, owner.UNLOCK, 4)
        self.patches = {}
        if hooks:
            for pc, words in receipt.hook_words(self.receipt_labels).items():
                for index, word in enumerate(words):
                    self.patches[pc + index * 4] = word
        self.paint_acquire_result = paint_acquire_result
        self.paint_release_result = paint_release_result
        self.paint_acquire_failure_holds = False
        self.paint_release_failure_releases = True
        self.paint_held = False
        self.paint_events = []
        self.binding_accesses, self.owner_accesses = [], []
        self.issue_requests = []
        self.on_issue = None
        self.reads.clear()
        self.writes.clear()
        self.calls.clear()

    def instruction(self, pc):
        if hasattr(self, 'issuer_labels') and pc == self.issuer_labels['issue']:
            # Observational snapshots bypass instruction reads and must not
            # make the fixture dereference an invalid request on an early-deny
            # path which the emitted callback itself correctly rejects.
            try:
                snapshot = self.words_at(self.r[5], 9)
            except AssertionError:
                snapshot = None
            self.issue_requests.append(snapshot)
            if self.on_issue is not None:
                self.on_issue(self)
        super().instruction(pc)

    def tracked_access(self, kind, address, size):
        if not hasattr(self, 'binding_accesses'):
            return
        event = (kind, self.current_pc, address, size,
                 self.registry_held, self.paint_held)
        if BIND_STATE <= address < BIND_STATE + self.composition['binding_memory_bytes']:
            self.binding_accesses.append(event)
        if OWNER_STATE <= address < OWNER_STATE + self.composition['owner_memory_bytes']:
            self.owner_accesses.append(event)

    def get(self, address, size):
        self.tracked_access('read', address, size)
        return super().get(address, size)

    def put(self, address, value, size):
        self.tracked_access('write', address, size)
        return super().put(address, value, size)

    def service(self, target):
        pointer, service_sp, service_ra = self.r[4], self.r[29], self.r[31]
        if pointer != PAINT_MUTEX:
            return super().service(target)
        result = (self.paint_acquire_result if target == RAW_LOCK
                  else self.paint_release_result)
        self.calls.append(target)
        event = (target, pointer, service_sp, service_ra, result & MASK)
        self.raw_events.append(event)
        self.paint_events.append(event)
        if target == RAW_LOCK and (result == 0 or self.paint_acquire_failure_holds):
            self.paint_held = True
        if self.on_service is not None:
            self.on_service(self, target)
        self.hostile_result(result)
        if (target == RAW_UNLOCK
                and (result == 0 or self.paint_release_failure_releases)):
            self.paint_held = False

    def binding_header(self):
        return self.words_at(BIND_STATE, 4)

    def binding_record(self, index=0):
        return self.words_at(BIND_STATE + 16 + index * 48, 12)

    def owner_header(self):
        return self.words_at(OWNER_STATE, owner.HEADER_BYTES // 4)

    def owner_record(self, index=0):
        return self.words_at(OWNER_STATE + owner.HEADER_BYTES + index * owner.OWNER_BYTES,
                             owner.OWNER_BYTES // 4)

    def write_request(self, words):
        if len(words) != 9:
            raise ValueError('fixture issue request must contain nine words')
        for index, word in enumerate(words):
            self.put(REQUEST + index * 4, word, 4)
        return REQUEST

    def request_words(self):
        return self.words_at(REQUEST, 9)

    def invoke_issue(self, request=REQUEST, *, controller=CONTROLLER,
                     stack=STACK, caller=RETURN):
        self.r[29], self.r[31], self.r[4], self.r[5] = stack, caller, controller, request
        self.run_at(self.issuer_labels['issue'], caller)
        return self.r[2], self.r[3]

    def invoke_owner(self, label, *args, controller=CONTROLLER,
                     stack=STACK, caller=RETURN):
        self.r[29], self.r[31] = stack, caller
        self.r[4:5 + len(args)] = (controller, *args)
        self.run_at(self.owner_labels[label], caller)
        return self.r[2], self.r[3]


class RegistryOwnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = source.SOURCE.read_bytes()
        digest = hashlib.sha256(cls.image).hexdigest()
        if digest != source.SOURCE_SHA256 or len(cls.image) != source.SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: {digest}, size {len(cls.image)}')

    def machine(self, **options):
        return RegistryOwnerMachine(self.image, **options)

    def assert_no_issue_state(self, machine):
        self.assertEqual(machine.binding_accesses, [])
        self.assertEqual(machine.owner_accesses, [])
        self.assertEqual(machine.binding_header(), (0, 0, 0, 0))
        self.assertEqual(machine.owner_header(), (0,) * (owner.HEADER_BYTES // 4))

    def test_completed_native_publication_records_one_historical_owner_binding(self):
        m = self.machine()
        self.assertEqual(m.register(), 0)
        self.assertEqual(m.header(), (1, 0, 0, 0))
        self.assertEqual(m.binding_header(), (1, 0, 0, 0))
        binding = m.binding_record()
        self.assertNotEqual(binding[0], 0)
        self.assertEqual(binding[1:], (1, 1, CONTROLLER, REGISTRY_MUTEX,
                                      m.allocations[0], ENGINE, STACK - 0x28,
                                      RETURN, 0x438A5C, 0, 1))
        self.assertEqual(m.owner_record(), (1, ENGINE, 0, 0))
        self.assertEqual(m.owner_header()[owner.SERIAL // 4], 1)
        self.assertEqual(m.owner_header()[owner.OWNER_COUNT // 4], 1)
        self.assertFalse(m.registry_held)
        self.assertFalse(m.paint_held)

    def test_native_architectural_results_and_registry_links_are_unchanged(self):
        for acquire, release in ((0, 0), (22, 0), (0, MASK)):
            with self.subTest(acquire=acquire, release=release):
                stock = self.machine(acquire=acquire, release=release, hooks=False)
                observed = self.machine(acquire=acquire, release=release)
                self.assertEqual(stock.register(), observed.register())
                self.assertEqual((stock.r, stock.hi, stock.lo),
                                 (observed.r, observed.hi, observed.lo))
                self.assertEqual(stock.words_at(CONTROLLER + 0x34, 2),
                                 observed.words_at(CONTROLLER + 0x34, 2))
                self.assertEqual(stock.words_at(stock.allocations[0], 7),
                                 observed.words_at(observed.allocations[0], 7))
                self.assertEqual(stock.raw_events,
                                 [event for event in observed.raw_events
                                  if event[1] != PAINT_MUTEX])

    def test_equal_engine_words_issue_distinct_nonreused_generations(self):
        m = self.machine()
        self.assertEqual(m.register(), 0)
        first = m.binding_record()
        self.assertEqual(m.register(), 0)
        self.assertEqual(m.binding_record(), first)
        self.assertEqual(m.binding_header(), (2, 0, 0, 0))
        second = m.binding_record(1)
        self.assertEqual(second[1:3], (2, 2))
        self.assertNotEqual(first[5], second[5])
        self.assertEqual(first[6], second[6])
        self.assertEqual(m.owner_record(0), (1, ENGINE, 0, 0))
        self.assertEqual(m.owner_record(1), (2, ENGINE, 0, 0))

    def test_each_state_access_uses_its_required_guard_order(self):
        m = self.machine()
        self.assertEqual(m.register(), 0)
        self.assertTrue(m.journal_accesses)
        self.assertTrue(m.binding_accesses)
        self.assertTrue(m.owner_accesses)
        self.assertTrue(all(event[-1] for event in m.journal_accesses))
        self.assertTrue(all(event[-2] for event in m.binding_accesses))
        self.assertTrue(all(event[-2] and event[-1] for event in m.owner_accesses))
        self.assertEqual([(event[0], event[1]) for event in m.raw_events],
                         [(RAW_LOCK, REGISTRY_MUTEX), (RAW_LOCK, PAINT_MUTEX),
                          (RAW_UNLOCK, PAINT_MUTEX), (RAW_UNLOCK, REGISTRY_MUTEX)])

    def test_paint_raw_services_receive_the_pinned_captured_mutex(self):
        m = self.machine()
        self.assertEqual(m.register(), 0)
        self.assertEqual([event[1] for event in m.paint_events], [PAINT_MUTEX] * 2)
        for target, pointer, stack, return_pc, status in m.paint_events:
            self.assertEqual(stack % 8, 0)
            self.assertTrue(CODE <= return_pc < CODE + len(m.code))
            self.assertEqual(status, 0)

    def test_registry_raw_errors_deny_all_owner_and_binding_access(self):
        for status in (1, 22, 0x82, MASK):
            with self.subTest(status=status):
                m = self.machine(acquire=status)
                self.assertEqual(m.register(), 0)
                self.assertEqual(len(m.allocations), 1)
                self.assertEqual(m.paint_events, [])
                self.assert_no_issue_state(m)

    def test_outer_unlock_error_does_not_turn_historical_binding_into_release_proof(self):
        for status in (1, 22, MASK):
            with self.subTest(status=status):
                m = self.machine(release=status)
                self.assertEqual(m.register(), 0)
                self.assertEqual(m.binding_header(), (1, 0, 0, 0))
                self.assertEqual(m.binding_record()[-2:], (0, 1))
                self.assertEqual(m.raw_events[-1][-1], status)
                self.assertEqual(m.freed, [])

    def test_closed_owner_kernel_cannot_issue_a_new_binding(self):
        m = self.machine()
        m.put(OWNER_STATE + owner.CLOSED, 1, 4)
        m.owner_accesses.clear()
        self.assertEqual(m.register(), 0)
        self.assertEqual(m.binding_header()[0], 0)
        self.assertEqual(m.owner_header()[owner.OWNER_COUNT // 4], 0)
        self.assertEqual(m.owner_header()[owner.SERIAL // 4], 0)

    def test_full_owner_table_does_not_claim_a_second_generation(self):
        m = self.machine(owner_capacity=1)
        self.assertEqual(m.register(), 0)
        first = m.binding_record()
        self.assertEqual(m.register(), 0)
        self.assertEqual(m.binding_record(), first)
        self.assertEqual(m.binding_header()[0], 1)
        self.assertEqual(m.owner_header()[owner.OWNER_COUNT // 4], 1)
        self.assertEqual(m.owner_header()[owner.SERIAL // 4], 1)

    def test_full_binding_table_does_not_allocate_an_unrecordable_owner(self):
        m = self.machine(capacity=1)
        self.assertEqual(m.register(), 0)
        first = m.binding_record()
        m.paint_events.clear()
        self.assertEqual(m.register(), 0)
        self.assertEqual(m.binding_record(), first)
        self.assertEqual(m.binding_header()[0], 1)
        self.assertEqual(m.paint_events, [])
        self.assertEqual(m.owner_header()[owner.OWNER_COUNT // 4], 1)

    def test_native_allocation_failure_never_enters_owner_issuer(self):
        m = self.machine()
        m.fail_allocation = True
        self.assertEqual(m.register(), MASK)
        self.assertTrue(m.registry_held)  # native defect deliberately preserved
        self.assertEqual(m.issue_requests, [])
        self.assertEqual(m.paint_events, [])
        self.assert_no_issue_state(m)

    def test_foreign_controller_is_not_bound_even_when_stock_publication_succeeds(self):
        m = self.machine()
        foreign = CONTROLLER + 0x1000
        m.map(foreign, 0x28C)
        m.configure_controller(foreign)
        self.assertEqual(m.register(controller=foreign), 0)
        self.assertEqual(m.paint_events, [])
        self.assert_no_issue_state(m)

    def test_null_native_arguments_do_not_access_generation_state(self):
        for arguments in ({'controller': 0}, {'descriptor': 0}):
            with self.subTest(arguments=arguments):
                m = self.machine()
                self.assertEqual(m.register(**arguments), MASK)
                self.assertEqual(m.raw_events, [])
                self.assert_no_issue_state(m)

    def test_exact_request_snapshot_is_forwarded_not_a_latest_raw_pointer_lookup(self):
        m = self.machine()
        self.assertEqual(m.register(), 0)
        self.assertEqual(m.issue_requests,
                         [(CONTROLLER, REGISTRY_MUTEX, m.allocations[0], ENGINE,
                           STACK - 0x28, RETURN, 0x438A5C, 0, 1)])
        first = m.issue_requests[0]
        self.assertEqual(m.register(), 0)
        self.assertEqual(m.issue_requests[0], first)
        self.assertEqual(m.issue_requests[1][-1], 2)
        self.assertNotEqual(m.issue_requests[0][2], m.issue_requests[1][2])

    def test_no_engine_name_mutex_storage_ui_or_free_operation(self):
        m = self.machine()
        self.assertEqual(m.register(), 0)
        for address, size in m.reads:
            for start, length in ((ENGINE, 0x100), (DESCRIPTOR[1], 0x100),
                                  (REGISTRY_MUTEX, 24), (PAINT_MUTEX, 24)):
                self.assertFalse(start <= address < start + length)
        self.assertEqual(m.freed, [])
        self.assertFalse(any(target in m.calls for target in
                             (0x466A80, 0x8B4220, 0x8B3F00, 0x4395A0, 0x43CB20)))

    def test_passive_default_receipt_bytes_are_unchanged(self):
        code, labels = receipt.assemble(STATE, CONTROLLER, REGISTRY_MUTEX, CODE)
        self.assertEqual(len(code), 2196)
        self.assertEqual(hashlib.sha256(code).hexdigest(),
                         'cce29e67b8a80688a5ed4c1f6dd83799cff15df71e7c5e2072607938ae815ff7')
        explicit, explicit_labels = receipt.assemble(
            STATE, CONTROLLER, REGISTRY_MUTEX, CODE, publication_callback=None)
        self.assertEqual((explicit, explicit_labels), (code, labels))

    def test_default_and_unpinned_checked_owner_bytes_are_unchanged(self):
        # Both byte goldens were independently checked against the committed
        # f79ca66 source. Running this test requires no git or network access.
        for checked, size, expected in (
                (False, 10824,
                 'b0b07d89e0643272907cc2f512f4f3f24b816bcbb95cabb280b09945cc7214b4'),
                (True, 12120,
                 'dd358973bf729a22eb48c9744dd0775e1a3a8e27a87dc02137ac8692037b4237')):
            with self.subTest(checked=checked):
                code, labels = owner.assemble(STATE, 0x1700000, CODE,
                                              checked_mutex=checked)
                self.assertEqual(len(code), size)
                self.assertEqual(hashlib.sha256(code).hexdigest(), expected)
                explicit, explicit_labels = owner.assemble(
                    STATE, 0x1700000, CODE, checked_mutex=checked,
                    expected_mutex_address=None)
                self.assertEqual((explicit, explicit_labels), (code, labels))

    def test_paint_raw_errors_preserve_complete_native_architectural_results(self):
        for field in ('paint_acquire_result', 'paint_release_result'):
            for status in (1, 22, MASK):
                with self.subTest(field=field, status=status):
                    stock = self.machine(hooks=False)
                    observed = self.machine(**{field: status})
                    self.assertEqual(stock.register(), observed.register())
                    self.assertEqual((stock.r, stock.hi, stock.lo),
                                     (observed.r, observed.hi, observed.lo))
                    self.assertEqual(stock.words_at(CONTROLLER + 0x34, 2),
                                     observed.words_at(CONTROLLER + 0x34, 2))
                    self.assertEqual(stock.words_at(stock.allocations[0], 7),
                                     observed.words_at(observed.allocations[0], 7))
                    self.assertEqual(observed.binding_header(), (0, 1, status, 0))

    def test_issuer_preserves_every_register_and_hilo_on_success_error_and_denial(self):
        cases = ('success', 'acquire_error', 'unlock_error', 'closed', 'quarantine')
        for case in cases:
            with self.subTest(case=case):
                options = ({'paint_acquire_result': 22} if case == 'acquire_error'
                           else {'paint_release_result': MASK} if case == 'unlock_error'
                           else {})
                m = self.machine(**options)
                if case == 'closed':
                    m.put(OWNER_STATE + owner.CLOSED, 1, 4)
                if case == 'quarantine':
                    m.put(BIND_STATE + 4, 1, 4)
                snapshots, return_pc = [], []

                def capture(machine, pc):
                    if pc == machine.issuer_labels['issue']:
                        snapshots.append((machine.r.copy(), machine.hi, machine.lo))
                        return_pc.append(machine.r[31])
                    elif return_pc and pc == return_pc[0]:
                        snapshots.append((machine.r.copy(), machine.hi, machine.lo))

                m.on_instruction = capture
                self.assertEqual(m.register(), 0)
                self.assertEqual(len(snapshots), 2)
                self.assertEqual(snapshots[1], snapshots[0])

    def test_publication_callback_descriptor_requires_a_disjoint_bounded_code_extent(self):
        start = CODE - 0x1000
        invalid = (
            False, 1, [], (), (start, start), (start, start, 16, 0),
            [start, start, 16], (True, start, 16), (start, start, 16.0),
            (start - 4, start, 16), (start + 16, start, 16),
            (start + 2, start, 16), (start, 0, 16),
            (start, start + 2, 16), (start, start, 0),
            (start, start, -4), (start, start, 14),
            (0xFFFFFF0, 0xFFFFFF0, 32),
            (STATE, STATE, 4), (CONTROLLER, CONTROLLER, 4),
            (REGISTRY_MUTEX, REGISTRY_MUTEX, 4),
            (receipt.NATIVE_RX[0], receipt.NATIVE_RX[0], 4),
            (CODE, CODE, 4), (CODE + 2000, CODE + 2000, 4),
            (CODE - 4, CODE - 4, 8),
        )
        for callback in invalid:
            with self.subTest(callback=callback), self.assertRaises(ValueError):
                receipt.assemble(STATE, CONTROLLER, REGISTRY_MUTEX, CODE,
                                 publication_callback=callback)
        # Entry can be an interior instruction, but must fit wholly inside
        # the separately declared generated callback extent.
        code, labels = receipt.assemble(
            STATE, CONTROLLER, REGISTRY_MUTEX, CODE,
            publication_callback=(start + 4, start, 16))
        self.assertGreater(len(code), 2196)
        self.assertIn('published', labels)

    def test_pinned_owner_mutex_configuration_rejects_invalid_or_overlapping_extents(self):
        with self.assertRaises(ValueError):
            owner.assemble(STATE, CONTROLLER, CODE, expected_mutex_address=PAINT_MUTEX)
        valid, _ = owner.assemble(STATE, CONTROLLER, CODE, checked_mutex=True,
                                  expected_mutex_address=PAINT_MUTEX)
        invalid = (False, True, 0, -4, 'mutex', 1.0, PAINT_MUTEX + 1,
                   0xFFFFFFEC, STATE, STATE + owner.memory_bytes() - 4,
                   CONTROLLER, CONTROLLER + owner.CONTROLLER_BYTES - 4,
                   CODE, CODE - 20, CODE + len(valid) - 4)
        for pointer in invalid:
            with self.subTest(pointer=pointer), self.assertRaises(ValueError):
                owner.assemble(STATE, CONTROLLER, CODE, checked_mutex=True,
                               expected_mutex_address=pointer)


if __name__ == '__main__':
    unittest.main()
