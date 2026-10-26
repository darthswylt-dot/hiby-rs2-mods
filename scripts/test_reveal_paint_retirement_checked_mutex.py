#!/usr/bin/env python3
"""Raw pthread-status fixture for the optional checked44-byte prototype.

The two raw pthread services are bounded hostile-ABI stubs, not replacements
at the native status-erasing facades. An initialized ordinary/nonrobust mutex,
its retained allocation and complete native/service stack remain premises.
Error cases intentionally model ambiguous ownership/release as well: external
quarantine, not an internal retry/free/rollback, is required after any raw error.
No native queue writer, destructor, device or UI is changed by this fixture.
"""

import hashlib
import unittest

import reveal_paint_retirement_mips as core
import test_reveal_paint_retirement_mips as prior


STATE, CODE, INPUT = prior.STATE, prior.CODE, prior.INPUT
STACK, CONTROLLER, RETURN, MASK = prior.STACK, prior.CONTROLLER, prior.RETURN, prior.MASK
PAYLOAD, PAINT_LOCK = prior.PAYLOAD, prior.prior.prior.PAINT_LOCK
DEFAULT_SHA256 = 'b0b07d89e0643272907cc2f512f4f3f24b816bcbb95cabb280b09945cc7214b4'


class CheckedMutexMachine(prior.RetirementMachine):
    """Execute checked helper instructions and actual native segmented lists."""

    def __init__(self, image, meta, *, capacity=64, owner_capacity=16,
                 ticket_limit=core.MAX_TICKET, element_bytes=core.ELEMENT_BYTES):
        super().__init__(image, meta, capacity=capacity, owner_capacity=owner_capacity,
                         ticket_limit=ticket_limit, element_bytes=element_bytes)
        self.handoff_code, self.handoff_labels = core.assemble(
            STATE, CONTROLLER, CODE, capacity=capacity, owner_capacity=owner_capacity,
            ticket_limit=ticket_limit, checked_mutex=True)
        self.owner_capacity = owner_capacity
        self.raw_acquire_result = self.raw_release_result = 0
        self.acquire_failure_holds = False
        self.release_failure_releases = True
        self.raw_mutex_events = []
        self.before_raw_unlock = self.after_raw_unlock = None
        self.after_raw_unlock_write_index = None
        self.after_raw_unlock_read_index = None

    def external(self, target):
        if target not in (core.RAW_LOCK, core.RAW_UNLOCK):
            return super().external(target)
        self.calls.append(target)
        pointer, acquiring = self.r[4], target == core.RAW_LOCK
        result = self.raw_acquire_result if acquiring else self.raw_release_result
        self.raw_mutex_events.append((acquiring, pointer, result & MASK))
        self.lock_events.append((acquiring, pointer, self.r[31]))
        if acquiring:
            if self.paint_locked:
                raise AssertionError('nested raw acquisition in fixture')
            if not result or self.acquire_failure_holds:
                self.paint_locked = True
            if not result and self.on_locked is not None:
                self.on_locked(self)
        else:
            if not self.paint_locked:
                raise AssertionError('raw unlock without fixture ownership')
            if self.before_raw_unlock is not None:
                self.before_raw_unlock(self)
            if not result or self.release_failure_releases:
                self.paint_locked = False
        self.hostile_result(result)
        if not acquiring:
            self.after_raw_unlock_write_index = len(self.writes)
            self.after_raw_unlock_read_index = len(self.read_events)
            if self.after_raw_unlock is not None:
                self.after_raw_unlock(self)


class CheckedMutexTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        prior.RetirementTests.setUpClass()
        cls.image, cls.meta = prior.RetirementTests.image, prior.RetirementTests.meta

    def machine(self, **options):
        return CheckedMutexMachine(self.image, self.meta, **options)

    @staticmethod
    def input(machine, words=PAYLOAD):
        for index, word in enumerate(words):
            machine.put(INPUT + index * 4, word, 4)

    def assert_no_shared_access(self, machine):
        self.assertFalse(any(STATE <= address < STATE + core.memory_bytes(machine.owner_capacity)
                             or INPUT <= address < INPUT + core.PAYLOAD_BYTES
                             or machine.paint_list <= address < machine.paint_list + core.LIST_BYTES
                             for _, address, _, _, _ in machine.read_events))
        self.assertTrue(all(STACK - core.FRAME <= address < STACK
                            for address, _, _ in machine.writes))
        for target in (core.APPEND, core.GET, core.REMOVE, core.RAW_UNLOCK):
            self.assertNotIn(target, machine.calls)

    def test_default_emission_is_byte_identical(self):
        expected, labels = core.assemble(STATE, CONTROLLER, CODE)
        explicit, explicit_labels = core.assemble(STATE, CONTROLLER, CODE, checked_mutex=False)
        self.assertEqual(len(expected), 10824)
        self.assertEqual(hashlib.sha256(expected).hexdigest(), DEFAULT_SHA256)
        self.assertEqual((explicit, explicit_labels), (expected, labels))

    def test_mode_requires_literal_bool(self):
        for value in (None, 0, 1, 'true', [], object()):
            with self.subTest(value=value), self.assertRaises(ValueError):
                core.assemble(STATE, CONTROLLER, CODE, checked_mutex=value)

    def test_direct_raw_calls_require_the_native_jump_region(self):
        with self.assertRaises(ValueError):
            core.assemble(STATE, CONTROLLER, 0x11E80000, checked_mutex=True)

    def test_success_uses_raw_services_not_status_erasing_facades(self):
        m = self.machine()
        owner = m.open_ticket()
        self.assertEqual(owner, 1)
        self.assertEqual(m.publish(owner), (2, 0))
        self.assertEqual(m.claim(), (STATE + core.COPY, 2))
        self.assertEqual(m.retire(owner), (1, 0))
        self.assertEqual(m.complete(2), (3, 0))
        self.assertEqual(m.drained(owner), (1, 0))
        self.assertFalse(m.paint_locked)
        for target in (core.RAW_LOCK, core.RAW_UNLOCK):
            self.assertIn(target, m.calls)
        for target in (core.APPEND, core.GET, core.REMOVE):
            self.assertIn(target, m.trace)
        for target in (core.LOCK, core.UNLOCK, 0x466DA0, 0x466DC0):
            self.assertNotIn(target, m.calls)
            self.assertNotIn(target, m.trace)

    def test_all_eight_entries_return_actual_raw_acquisition_error_without_shared_access(self):
        for label, args in (('open_owner', (PAYLOAD[2],)), ('publish', (INPUT, 1)),
                            ('claim', ()), ('complete', (1, 1)), ('retire', (1,)),
                            ('drained', (1,)), ('cancel', ()), ('close', ())):
            for status in (1, 7, MASK):
                with self.subTest(label=label, status=status):
                    m = self.machine()
                    self.input(m)
                    m.raw_acquire_result = status
                    m.read_events.clear()
                    m.writes.clear()
                    self.assertEqual(m.invoke(label, *args), (0, status))
                    self.assert_no_shared_access(m)
                    self.assertEqual(m.raw_mutex_events, [(True, PAINT_LOCK, status)])

    def test_nonzero_acquire_does_not_guess_unlock_even_if_service_retains_guard(self):
        m = self.machine()
        m.raw_acquire_result, m.acquire_failure_holds = 0x82, True
        m.read_events.clear()
        m.writes.clear()
        self.assertEqual(m.open_owner(), (0, 0x82))
        self.assertTrue(m.paint_locked)
        self.assert_no_shared_access(m)
        self.assertNotIn(core.RAW_UNLOCK, m.calls)
        # The test deliberately does not reuse this externally quarantined instance.

    def test_failed_acquire_cannot_read_or_repair_existing_corrupt_state(self):
        m = self.machine()
        m.put(STATE + core.OWNER_COUNT, MASK, 4)
        m.raw_acquire_result = 5
        m.read_events.clear()
        m.writes.clear()
        self.assertEqual(m.invoke('close'), (0, 5))
        self.assert_no_shared_access(m)
        self.assertEqual(m.peek(STATE + core.OWNER_COUNT), MASK)

    def test_failed_unlock_returns_raw_status_without_rollback_or_latch(self):
        for status in (1, 7, MASK):
            with self.subTest(status=status):
                m = self.machine()
                m.raw_release_result = status
                self.assertEqual(m.open_owner(), (0, status))
                self.assertEqual(m.owner(0), (1, PAYLOAD[2], 0, 0))
                self.assertEqual(m.state(core.SERIAL), 1)
                self.assertEqual(m.state(core.OWNER_COUNT), 1)
                self.assertEqual(m.state(core.FAULT), 0)
                self.assertFalse(m.paint_locked)
                late = m.writes[m.after_raw_unlock_write_index:]
                self.assertTrue(all(STACK - core.FRAME <= address < STACK
                                    for address, _, _ in late))
                late_reads = m.read_events[m.after_raw_unlock_read_index:]
                self.assertTrue(all(STACK - core.FRAME <= address < STACK
                                    for _, address, _, _, _ in late_reads))

    def test_failed_unlock_does_not_assume_it_released_the_guard(self):
        m = self.machine()
        m.raw_release_result, m.release_failure_releases = 6, False
        self.assertEqual(m.open_owner(), (0, 6))
        self.assertTrue(m.paint_locked)
        self.assertEqual(m.state(core.FAULT), 0)
        self.assertEqual(m.state(core.SERIAL), 1)
        self.assertEqual(len(m.raw_mutex_events), 2)
        self.assertTrue(all(STACK - core.FRAME <= address < STACK
                            for address, _, _ in m.writes[m.after_raw_unlock_write_index:]))
        self.assertTrue(all(STACK - core.FRAME <= address < STACK
                            for _, address, _, _, _ in m.read_events[m.after_raw_unlock_read_index:]))

    def test_all_eight_entries_return_actual_unlock_error_without_late_shared_access(self):
        for label in ('open_owner', 'publish', 'claim', 'complete', 'retire',
                      'drained', 'cancel', 'close'):
            for released in (False, True):
                with self.subTest(label=label, released=released):
                    m = self.machine()
                    owner = m.open_ticket()
                    nonce = m.publish(owner)[0]
                    m.claim()
                    if label == 'drained':
                        m.retire(owner)
                        m.complete(nonce)
                    self.input(m)
                    args = {'open_owner': (PAYLOAD[2],), 'publish': (INPUT, owner),
                            'claim': (), 'complete': (nonce, 1), 'retire': (owner,),
                            'drained': (owner,), 'cancel': (), 'close': ()}[label]
                    m.raw_release_result = MASK
                    m.release_failure_releases = released
                    self.assertEqual(m.invoke(label, *args), (0, MASK))
                    self.assertEqual(m.paint_locked, not released)
                    self.assertEqual(m.state(core.FAULT), 0)
                    self.assertTrue(all(STACK - core.FRAME <= address < STACK
                                        for address, _, _ in m.writes[m.after_raw_unlock_write_index:]))
                    self.assertTrue(all(STACK - core.FRAME <= address < STACK
                                        for _, address, _, _, _ in m.read_events[m.after_raw_unlock_read_index:]))

    def test_publish_side_effect_survives_failed_unlock(self):
        m = self.machine()
        owner = m.open_ticket()
        m.raw_release_result = 9
        self.assertEqual(m.publish(owner), (0, 9))
        self.assertEqual(m.count(m.paint_list), 1)
        self.assertEqual(m.words_at(m.head(), 11), (*PAYLOAD, 2, owner))
        self.assertEqual(m.state(core.FAULT), 0)

    def test_completion_side_effect_survives_failed_unlock(self):
        m = self.machine()
        owner = m.open_ticket()
        m.publish(owner)
        m.claim()
        m.raw_release_result = 11
        self.assertEqual(m.complete(2), (0, 11))
        self.assertEqual(m.count(m.paint_list), 0)
        self.assertEqual(m.state(core.ACTIVE), 0)
        self.assertEqual(m.state(core.FAULT), 0)

    def test_retirement_side_effects_survive_failed_unlock(self):
        m = self.machine()
        owner = m.open_ticket()
        m.publish(owner)
        m.raw_release_result = 13
        self.assertEqual(m.retire(owner), (0, 13))
        self.assertEqual(m.owner(0)[2], 1)
        self.assertEqual(m.count(m.paint_list), 0)
        self.assertEqual(m.state(core.FAULT), 0)

    def test_snapshot_pointer_is_used_for_unlock_after_controller_field_changes(self):
        m = self.machine()
        alternate = PAINT_LOCK + 0x100
        m.on_locked = lambda machine: machine.put(CONTROLLER + 0x148, alternate, 4)
        self.assertEqual(m.open_owner(), (1, 0))
        self.assertEqual(m.raw_mutex_events, [(True, PAINT_LOCK, 0), (False, PAINT_LOCK, 0)])
        pointer_reads = [event for event in m.read_events if event[1] == CONTROLLER + 0x148]
        self.assertEqual(len(pointer_reads), 1)
        self.assertEqual(m.peek(CONTROLLER + 0x148), alternate)

    def test_null_unaligned_or_wrapping_mutex_pointer_denies_before_save_or_raw_call(self):
        for pointer in (0, PAINT_LOCK + 1, 0xFFFFFFEC, 0xFFFFFFFC):
            with self.subTest(pointer=hex(pointer)):
                m = self.machine()
                m.put(CONTROLLER + 0x148, pointer, 4)
                m.writes.clear()
                self.assertEqual(m.open_owner(), (0, 0))
                self.assertEqual(m.writes, [])
                self.assertEqual(m.raw_mutex_events, [])

    def test_mutex_aliases_state_controller_or_frame_are_denied_before_save(self):
        for pointer in (STATE - 20, STATE, STATE + core.memory_bytes() - 4,
                        CONTROLLER - 20, CONTROLLER + 0x148,
                        STACK - core.FRAME - 20, STACK - core.FRAME,
                        STACK - 4):
            with self.subTest(pointer=hex(pointer)):
                m = self.machine()
                m.put(CONTROLLER + 0x148, pointer, 4)
                m.writes.clear()
                self.assertEqual(m.open_owner(), (0, 0))
                self.assertEqual(m.writes, [])
                self.assertEqual(m.raw_mutex_events, [])

    def test_mutex_adjacency_and_inclusive_word_endpoint_are_allowed(self):
        for pointer in (STATE - core.MUTEX_BYTES, STATE + core.memory_bytes(),
                        CONTROLLER - core.MUTEX_BYTES, CONTROLLER + core.CONTROLLER_BYTES,
                        STACK - core.FRAME - core.MUTEX_BYTES, STACK,
                        0xFFFFFFE8):
            with self.subTest(pointer=hex(pointer)):
                m = self.machine()
                m.put(CONTROLLER + 0x148, pointer, 4)
                self.assertEqual(m.open_owner(), (1, 0))
                self.assertEqual([event[1] for event in m.raw_mutex_events], [pointer, pointer])
        # Services intentionally model pointers as scalars; this is not a
        # claim that any adjacent/endpoint allocation is mapped/initialized.

    def test_callback_fingerprints_still_gate_raw_calls(self):
        for offset, value in ((0x284, core.LOCK + 4), (0x288, core.UNLOCK + 4)):
            with self.subTest(offset=offset):
                m = self.machine()
                m.put(CONTROLLER + offset, value, 4)
                m.writes.clear()
                self.assertEqual(m.open_owner(), (0, 0))
                self.assertEqual(m.writes, [])
                self.assertEqual(m.raw_mutex_events, [])

    def test_hostile_raw_abi_preserves_saved_registers_stack_and_hi_lo(self):
        for acquire, release in ((0, 0), (7, 0), (0, 9)):
            with self.subTest(acquire=acquire, release=release):
                m = self.machine()
                saved = {register: 0x52300000 + register for register in range(16, 24)}
                for register, value in saved.items():
                    m.r[register] = value
                m.hi, m.lo = 0x12345678, 0xABCDEF01
                m.raw_acquire_result, m.raw_release_result = acquire, release
                m.open_owner()
                self.assertEqual({register: m.r[register] for register in saved}, saved)
                self.assertEqual((m.r[29], m.r[31]), (STACK, RETURN))
                self.assertEqual((m.hi, m.lo), (0x12345678, 0xABCDEF01))

    def test_successful_all_eight_entries_preserve_abi_and_guard_state_source_reads(self):
        for label in ('open_owner', 'publish', 'claim', 'complete', 'retire',
                      'drained', 'cancel', 'close'):
            with self.subTest(label=label):
                m = self.machine()
                owner = m.open_ticket()
                nonce = m.publish(owner)[0]
                if label != 'claim':
                    m.claim()
                if label == 'drained':
                    m.retire(owner)
                    m.complete(nonce)
                self.input(m)
                args = {'open_owner': (PAYLOAD[2],), 'publish': (INPUT, owner),
                        'claim': (), 'complete': (nonce, 1), 'retire': (owner,),
                        'drained': (owner,), 'cancel': (), 'close': ()}[label]
                saved = {register: 0x54100000 + register
                         for register in (*range(16, 24), 28, 30)}
                for register, value in saved.items():
                    m.r[register] = value
                m.hi, m.lo = 0x55AA55AA, 0xAA55AA55
                m.read_events.clear()
                result = m.invoke(label, *args)
                self.assertNotEqual(result[0], 0)
                self.assertEqual({register: m.r[register] for register in saved}, saved)
                self.assertEqual((m.r[29], m.r[31]), (STACK, RETURN))
                self.assertEqual((m.hi, m.lo), (0x55AA55AA, 0xAA55AA55))
                reads = [(address, locked) for _, address, _, _, locked in m.read_events
                         if STATE <= address < STATE + core.memory_bytes()
                         or INPUT <= address < INPUT + core.PAYLOAD_BYTES]
                self.assertTrue(reads)
                self.assertTrue(all(locked for _, locked in reads))
                if label in ('cancel', 'close', 'retire'):
                    self.assertEqual(m.count(m.paint_list), 1)
                    self.assertEqual(m.state(core.ACTIVE), nonce)
                    self.assertEqual(m.state(core.CANCELLED), 1)
                self.assertFalse(m.paint_locked)


if __name__ == '__main__':
    unittest.main()
