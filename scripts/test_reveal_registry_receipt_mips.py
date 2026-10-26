#!/usr/bin/env python3
"""Execute four passive receipt bridges and original registry/mutex bodies.

The pinned native4389E0,437D20/DA0 and466DA0/DC0 instructions execute. Only
allocation and raw pthread services are bounded hostile-ABI stubs. A successful
raw result presupposes a live initialized ordinary mutex and real service
semantics; this is not a scheduler, allocation lease or hardware simulation.
No image, owner ticket, destructor, device operation or UI action is produced.
"""

import hashlib
import struct
import unittest

import reveal_registry_receipt_mips as core
import test_folderfollow_reveal_static_contract as source
from test_reveal_lineage_stage import LineageMachine, STACK, RETURN, MASK


STATE, CODE, CONTROLLER = 0x1F50000, 0x1E80000, 0x1800000
INPUT, REGISTRY_MUTEX, PAINT_MUTEX = 0x1F60000, 0x1F20300, 0x1F20200
ENGINE, NATIVE = 0x87654321, {0x437D20, 0x437DA0, 0x437CE0, 0x437D60,
                             0x466DA0, 0x466DC0}
RAW_LOCK, RAW_UNLOCK = 0xA5B960, 0xA5B830
DESCRIPTOR = (ENGINE, 0x87654325, 0x12345678, 0x87654329, 0x8765432D)


class RegistryReceiptMachine(LineageMachine):
    """Actual native registry links plus emitted bridges, not a journal oracle."""

    def __init__(self, image, *, capacity=16, acquire=0, release=0, hooks=True):
        self.capacity = capacity
        self.code_bytes, self.bridge_labels = core.assemble(
            STATE, CONTROLLER, REGISTRY_MUTEX, CODE, capacity=capacity)
        super().__init__(image, {'code_base': CODE, 'buffer': STATE,
                                 'code_offset': len(image), 'labels': {},
                                 'memory_bytes': core.memory_bytes(capacity)})
        self.code, self.labels = self.code_bytes, self.bridge_labels
        self.patches = {}
        if hooks:
            for pc, words in core.hook_words(self.labels).items():
                for index, word in enumerate(words):
                    self.patches[pc + index * 4] = word
        self.map(CONTROLLER, 0x28C)
        self.map(INPUT, 20)
        self.configure_controller(CONTROLLER)
        for index, word in enumerate(DESCRIPTOR):
            self.put(INPUT + index * 4, word, 4)
        self.acquire, self.release = acquire, release
        self.fail_allocation = False
        self.registry_held = False
        self.raw_events, self.allocations, self.journal_accesses = [], [], []
        self.trace, self.on_instruction, self.on_service = [], None, None
        self.current_pc = None
        self.before_instruction = self.instruction
        self.reads.clear()
        self.writes.clear()
        self.calls.clear()

    def configure_controller(self, address):
        for offset, value in ((0x34, address + 0x34), (0x38, address + 0x34),
                              (0x13C, REGISTRY_MUTEX), (0x148, PAINT_MUTEX),
                              (0x274, 0x437D20), (0x278, 0x437DA0)):
            self.put(address + offset, value, 4)

    def instruction(self, pc):
        self.current_pc = pc
        self.trace.append(pc)
        if self.on_instruction is not None:
            self.on_instruction(self, pc)
        # A bridge deliberately tail-calls the raw service with native466DB0
        # asRA. The interpreter's ordinary linked native call uses external;
        # this unlinked transfer executes the same hostile service here.
        if pc in (RAW_LOCK, RAW_UNLOCK):
            self.service(pc)

    def word(self, pc):
        if pc in self.patches:
            return self.patches[pc]
        if pc in (RAW_LOCK, RAW_UNLOCK):
            return 0x03E00008  # fixture service returns through its suppliedRA
        if pc in (RAW_LOCK + 4, RAW_UNLOCK + 4):
            return 0
        return super().word(pc)

    def get(self, address, size):
        if hasattr(self, 'journal_accesses') and STATE <= address < STATE + core.memory_bytes(self.capacity):
            self.journal_accesses.append(('read', self.current_pc, address, size,
                                          self.registry_held))
        return super().get(address, size)

    def put(self, address, value, size):
        if hasattr(self, 'journal_accesses') and STATE <= address < STATE + core.memory_bytes(self.capacity):
            self.journal_accesses.append(('write', self.current_pc, address, size,
                                          self.registry_held))
        return super().put(address, value, size)

    def service(self, target):
        pointer, service_sp, service_ra = self.r[4], self.r[29], self.r[31]
        result = self.acquire if target == RAW_LOCK else self.release
        self.calls.append(target)
        self.raw_events.append((target, pointer, service_sp, service_ra, result & MASK))
        if target == RAW_LOCK and pointer == REGISTRY_MUTEX and result == 0:
            self.registry_held = True
        if self.on_service is not None:
            self.on_service(self, target)
        self.hostile_result(result)
        if target == RAW_UNLOCK and pointer == REGISTRY_MUTEX:
            # Nonzero unlock has ambiguous ownership in reality. This fixture
            # chooses release, and does not turn the journal into a free lease.
            self.registry_held = False

    def external(self, target):
        if target in NATIVE:
            self.calls.append(target)
            self.run_at(target, self.r[31])
        elif target in (RAW_LOCK, RAW_UNLOCK):
            self.service(target)
        elif target == 0x4669E0:
            self.calls.append(target)
            if self.r[4] != 28:
                raise AssertionError('native registry allocation width changed')
            pointer = 0 if self.fail_allocation else self.allocation(28)
            self.allocations.append(pointer)
            self.hostile_result(pointer)
        else:
            raise AssertionError('unexpected native service ' + hex(target))

    def register(self, *, controller=CONTROLLER, descriptor=INPUT,
                 stack=STACK, caller=RETURN):
        self.r[29], self.r[31], self.r[4], self.r[5] = stack, caller, controller, descriptor
        self.last_before = self.r.copy(), self.hi, self.lo
        self.run_at(0x4389E0, caller)
        return self.r[2]

    def words_at(self, address, count):
        data, offset = self.region(address, count * 4)
        return struct.unpack_from('<' + 'I' * count, data, offset)

    def header(self):
        return self.words_at(STATE, 4)

    def record(self, index=0):
        return self.words_at(STATE + core.HEADER_BYTES + index * core.RECORD_BYTES, 10)

    def carrier(self, stack=STACK):
        return self.words_at(stack - 0x28 + 0x10, 3)


class RegistryReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = source.SOURCE.read_bytes()
        digest = hashlib.sha256(cls.image).hexdigest()
        if digest != source.SOURCE_SHA256 or len(cls.image) != source.SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: {digest}, size {len(cls.image)}')

    def machine(self, **options):
        return RegistryReceiptMachine(self.image, **options)

    def assert_native_node(self, m, pointer, *, previous=CONTROLLER + 0x34):
        self.assertEqual(m.words_at(pointer, 7), (CONTROLLER + 0x34, previous, *DESCRIPTOR))

    def assert_no_journal_access(self, m):
        self.assertEqual(m.journal_accesses, [])
        self.assertEqual(m.header(), (0, 0, 0, 0))

    def test_success_executes_native_facades_and_records_completed_publication(self):
        m = self.machine()
        self.assertEqual(m.register(), 0)
        node = m.allocations[0]
        self.assert_native_node(m, node)
        self.assertEqual(m.words_at(CONTROLLER + 0x34, 2), (node, node))
        self.assertEqual(m.header(), (1, 0, 0, 0))
        self.assertEqual(m.record(), (core.RECORD_MAGIC, 1, CONTROLLER, REGISTRY_MUTEX,
                                      node, ENGINE, STACK - 0x28, RETURN, 0x438A5C, 0))
        self.assertEqual(m.carrier()[0], 0)
        self.assertFalse(m.registry_held)
        self.assertTrue(all(access[-1] for access in m.journal_accesses))
        for pc in (0x4389E0, 0x437D20, 0x466DA0, 0x466DB8,
                   0x437DA0, 0x466DC0, 0x466DD4):
            self.assertIn(pc, m.trace)

    def test_real_raw_failure_is_not_the_native_forced_zero_success(self):
        for status in (1, 22, 0x82, MASK):
            with self.subTest(status=status):
                m = self.machine(acquire=status)
                self.assertEqual(m.register(), 0)
                self.assert_native_node(m, m.allocations[0])
                self.assertEqual(m.raw_events[0][-1], status)
                self.assertIn(0x466DB8, m.trace)
                self.assert_no_journal_access(m)
                self.assertEqual(m.carrier()[0], 0)

    def test_actual_native_and_bridge_paths_have_identical_final_abi(self):
        for acquire, release in ((0, 0), (22, 0), (0, MASK)):
            with self.subTest(acquire=acquire, release=release):
                native = self.machine(acquire=acquire, release=release, hooks=False)
                patched = self.machine(acquire=acquire, release=release)
                self.assertEqual(native.register(), patched.register())
                self.assertEqual((native.r, native.hi, native.lo),
                                 (patched.r, patched.hi, patched.lo))
                self.assertEqual(native.raw_events, patched.raw_events)
                self.assertEqual(native.words_at(CONTROLLER + 0x34, 2),
                                 patched.words_at(CONTROLLER + 0x34, 2))
                self.assertEqual(native.words_at(native.allocations[0], 7),
                                 patched.words_at(patched.allocations[0], 7))

    def test_allocator_failure_preserves_native_missing_unlock_without_receipt(self):
        m = self.machine()
        m.fail_allocation = True
        self.assertEqual(m.register(), MASK)
        self.assertEqual(m.words_at(CONTROLLER + 0x34, 2),
                         (CONTROLLER + 0x34, CONTROLLER + 0x34))
        self.assertEqual([event[0] for event in m.raw_events], [RAW_LOCK])
        self.assertTrue(m.registry_held)
        self.assert_no_journal_access(m)

    def test_equal_engine_words_produce_separate_immutable_receipts_not_owner_tickets(self):
        m = self.machine()
        self.assertEqual(m.register(), 0)
        first = m.record()
        self.assertEqual(m.register(), 0)
        self.assertEqual(m.header(), (2, 0, 0, 0))
        self.assertEqual(m.record(0), first)
        second = m.record(1)
        self.assertEqual(second[1:4], (2, CONTROLLER, REGISTRY_MUTEX))
        self.assertNotEqual(second[4], first[4])
        self.assertEqual(second[5], first[5])
        self.assert_native_node(m, m.allocations[1], previous=m.allocations[0])

    def test_fresh_begin_overwrites_stale_success_after_previous_allocation_failure(self):
        m = self.machine()
        m.fail_allocation = True
        self.assertEqual(m.register(), MASK)
        m.registry_held = False  # external reset of the bounded fake service only
        m.fail_allocation, m.acquire = False, 22
        self.assertEqual(m.register(), 0)
        self.assert_no_journal_access(m)
        self.assertEqual(m.carrier()[0], 0)

    def test_missing_raw_call_or_return_hook_cannot_manufacture_capture(self):
        for name in ('raw_call', 'raw_return'):
            with self.subTest(name=name):
                m = self.machine()
                pc = core.HOOKS[name][0]
                del m.patches[pc]
                del m.patches[pc + 4]
                self.assertEqual(m.register(), 0)
                self.assert_no_journal_access(m)
                self.assertEqual(m.carrier()[0], 0)

    def test_mismatched_actual_mutex_does_not_write_shared_journal(self):
        m = self.machine()
        m.put(CONTROLLER + 0x13C, REGISTRY_MUTEX + 0x100, 4)
        self.assertEqual(m.register(), 0)
        self.assertEqual(m.raw_events[0][1], REGISTRY_MUTEX + 0x100)
        self.assert_no_journal_access(m)

    def test_mismatched_lock_callback_cannot_arm_even_with_raw_zero(self):
        m = self.machine()
        m.put(CONTROLLER + 0x274, 0x437CE0, 4)
        self.assertEqual(m.register(), 0)
        self.assertEqual(m.raw_events[0][1], PAINT_MUTEX)
        self.assert_no_journal_access(m)

    def test_mismatched_unlock_callback_cannot_arm(self):
        m = self.machine()
        m.put(CONTROLLER + 0x278, 0x437D60, 4)
        self.assertEqual(m.register(), 0)
        self.assert_no_journal_access(m)

    def test_foreign_controller_native_registration_has_no_bound_journal_effect(self):
        m = self.machine()
        foreign = CONTROLLER + 0x1000
        m.map(foreign, 0x28C)
        m.configure_controller(foreign)
        self.assertEqual(m.register(controller=foreign), 0)
        self.assert_no_journal_access(m)
        self.assertEqual(m.words_at(foreign + 0x34, 2), (m.allocations[0], m.allocations[0]))

    def test_native_null_arguments_never_enter_bridges_or_services(self):
        for arguments in ({'controller': 0}, {'descriptor': 0}):
            with self.subTest(arguments=arguments):
                m = self.machine()
                self.assertEqual(m.register(**arguments), MASK)
                self.assertEqual(m.raw_events, [])
                self.assertEqual(m.allocations, [])
                self.assert_no_journal_access(m)

    def test_nonzero_unlock_does_not_revoke_earlier_publication_receipt(self):
        for status in (1, 22, MASK):
            with self.subTest(status=status):
                m = self.machine(release=status)
                self.assertEqual(m.register(), 0)
                self.assertEqual(m.header(), (1, 0, 0, 0))
                self.assertEqual(m.record()[-1], 0)
                self.assertEqual(m.raw_events[-1][-1], status)
                self.assertTrue(all(access[-1] for access in m.journal_accesses))

    def test_no_borrowed_engine_name_or_mutex_storage_dereference(self):
        m = self.machine()
        self.assertEqual(m.register(), 0)
        for address, size in m.reads:
            self.assertFalse(ENGINE <= address < ENGINE + 0x100)
            self.assertFalse(REGISTRY_MUTEX <= address < REGISTRY_MUTEX + 24)
            self.assertFalse(DESCRIPTOR[1] <= address < DESCRIPTOR[1] + 0x100)
        self.assertEqual(m.freed, [])

    def test_raw_service_preserves_native_sp_ra_and_cannot_overwrite_carrier_homes(self):
        m = self.machine()
        self.assertEqual(m.register(), 0)
        self.assertEqual(m.raw_events[0][1:4],
                         (REGISTRY_MUTEX, STACK - 0x28 - 0x40, 0x466DB0))
        self.assertEqual(m.raw_events[1][1:4],
                         (REGISTRY_MUTEX, STACK - 0x28 - 0x40, 0x466DD0))
        self.assertEqual(m.words_at(STACK - 0x28 - 0x40, 4),
                         tuple(0xD00D0000 + offset for offset in range(0, 16, 4)))
        self.assertEqual(m.record()[-1], 0)

    def test_each_bridge_preserves_all_registers_except_its_displaced_native_effects(self):
        m = self.machine()
        snapshots = {}
        watched = {0x438A00, 0x438A08, 0x466DA8, RAW_LOCK,
                   0x466DB0, 0x466DB8, 0x438A58, 0x438A60}

        def capture(machine, pc):
            if pc in watched:
                snapshots[pc] = machine.r.copy(), machine.hi, machine.lo

        m.on_instruction = capture
        self.assertEqual(m.register(), 0)
        for start, end, changes in ((0x438A00, 0x438A08,
                                     {16: CONTROLLER, 25: 0x437D20}),
                                    (0x466DA8, RAW_LOCK,
                                     {31: 0x466DB0}),
                                    (0x466DB0, 0x466DB8,
                                     {2: 0, 31: 0x437D30}),
                                    (0x438A58, 0x438A60,
                                     {25: 0x437DA0})):
            with self.subTest(bridge=hex(start)):
                expected, hi, lo = snapshots[start]
                for register, value in changes.items():
                    expected[register] = value
                self.assertEqual(snapshots[end], (expected, hi, lo))

    def test_final_native_store_precedes_observer_and_record_commit_precedes_count(self):
        m = self.machine()
        moments = []

        def capture(machine, pc):
            if pc in (0x438A58, machine.labels['published_saved']):
                moments.append((pc, machine.words_at(CONTROLLER + 0x34, 2),
                                machine.header(), len(machine.journal_accesses)))

        m.on_instruction = capture
        self.assertEqual(m.register(), 0)
        node = m.allocations[0]
        self.assertEqual(moments[0], (0x438A58, (CONTROLLER + 0x34, node),
                                       (0, 0, 0, 0), 0))
        self.assertEqual(moments[1], (m.labels['published_saved'], (node, node),
                                       (0, 0, 0, 0), 0))
        shared_writes = [(address, value) for address, value, _ in m.writes
                         if STATE <= address < STATE + core.memory_bytes(m.capacity)]
        self.assertEqual(shared_writes[-2:],
                         [(STATE + core.HEADER_BYTES + core.MAGIC, core.RECORD_MAGIC),
                          (STATE + core.COUNT, 1)])

    def test_published_carrier_is_single_use_even_when_observer_is_replayed(self):
        m = self.machine()
        self.assertEqual(m.register(), 0)
        original = m.header(), m.record()
        m.r[29], m.r[16], m.r[2], m.r[3] = (
            STACK - 0x28, CONTROLLER, m.allocations[0], CONTROLLER + 0x34)
        m.journal_accesses.clear()
        m.run_at(m.labels['published'], 0x438A60)
        self.assertEqual(m.journal_accesses, [])
        self.assertEqual((m.header(), m.record()), original)

    def test_unsupported_partial_redirects_can_consume_historical_stack_receipt(self):
        # Documentary counterexample, not an allowed installation/recovery:
        # all four coherent redirects are a premise. A prior native allocation
        # failure skips publication and leavesCAPTURED in its dead stack frame.
        m = self.machine()
        m.fail_allocation = True
        self.assertEqual(m.register(), MASK)
        self.assertEqual(m.carrier(), (core.CAPTURED, REGISTRY_MUTEX, 0))
        # Deliberately leave only the publication redirect and reuse that same
        # stack after an external fake-service ownership reset. There is now
        # no fresh begin/call/return protocol and no guard proof for this call.
        for name in ('begin', 'raw_call', 'raw_return'):
            pc = core.HOOKS[name][0]
            del m.patches[pc]
            del m.patches[pc + 4]
        m.registry_held, m.fail_allocation, m.acquire = False, False, 22
        self.assertEqual(m.register(), 0)
        self.assertEqual(m.raw_events[-2][-1], 22)
        self.assertEqual(m.header(), (1, 0, 0, 0))
        self.assertEqual(m.record()[-1], 0)  # historical, not this call's22
        self.assertTrue(m.journal_accesses)
        self.assertTrue(all(not access[-1] for access in m.journal_accesses))


if __name__ == '__main__':
    unittest.main()
