#!/usr/bin/env python3
"""Run coherent copy/scalar snapshots with native consumer continuations."""

import unittest

import factory_null_audit as audit
import reveal_tidal_compound_snapshot_mips as compound
import reveal_tidal_request_identity_mips as identity
import reveal_tidal_response_reader_bridge_mips as session
from test_factory_d180_tidal_response_lifecycle import (
    NEW_DATA, NEW_FOLLOWUP, NEW_RESPONSE, OLD_RESPONSE, RESPONSE_DATA, SESSION,
)
from test_factory_null_audit import RETURN, STACK
from test_reveal_tidal_response_pair_mips import PairMachine
from test_reveal_tidal_response_reader_bridge_mips import CODE_BASE, MUTEX


TOP, AUTHENTICATED_API = STACK + 0x1000, 0x8C0DD8
OLD_TEXT, NEW_TEXT = b'old snapshot', b'new snapshot'
OLD_ID, NEW_ID = 1017, 2031
# First site, frame bytes, S0 save, RA save, API call, incremented register.
UPPERS = ((compound.SNAPSHOTS[0], 0x3E0, 0x3C8, 0x3DC, 0x4AB10C, 18),
          (compound.SNAPSHOTS[1], 0x498, 0x480, 0x494, 0x4AB6B0, 17))


class CompoundMachine(PairMachine):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.bytes(RESPONSE_DATA, OLD_TEXT + b'\0')
        self.bytes(NEW_DATA, NEW_TEXT + b'\0')
        self.put(OLD_RESPONSE + 4, OLD_ID, 4)
        self.put(NEW_RESPONSE + 4, NEW_ID, 4)
        self.snapshot_calls, self.api_inputs = [], []

    def string(self, address, capacity=256):
        result = bytearray()
        for index in range(capacity):
            value = self.get(address + index, 1)
            if not value:
                return bytes(result)
            result.append(value)
        raise AssertionError('unterminated bounded fixture string')

    def external(self, target):
        if target == compound.STRLEN:
            if not self.held:
                raise AssertionError('snapshot length query outside the shared mutex')
            self.snapshot_calls.append((target, tuple(self.r[4:7])))
            self.calls.append(target)
            self.hostile_result(len(self.string(self.r[4])))
        elif target == compound.COPY:
            if not self.held:
                raise AssertionError('snapshot copy outside the shared mutex')
            destination, source, count = self.r[4:7]
            self.snapshot_calls.append((target, (destination, source, count)))
            self.calls.append(target)
            self.bytes(destination, bytes(self.get(source + index, 1) for index in range(count)))
            self.hostile_result(destination)
        elif target == AUTHENTICATED_API:
            if self.held:
                raise AssertionError('authenticated API ran under the snapshot mutex')
            self.api_inputs.append((self.string(self.r[4], compound.CAPACITY), self.r[5], self.r[7]))
            self.calls.append(target)
            self.hostile_result(0)
        else:
            super().external(target)

    def seed_upper(self, upper):
        row, size, saved_s0, saved_ra, _, _ = upper
        frame = TOP - size
        self.r[29], self.r[31] = frame, row[1]
        for index in range(5):
            self.put(frame + saved_s0 + index * 4, 0x55000000 + index, 4)
        self.put(frame + saved_ra, RETURN, 4)
        destination = frame + compound.BUFFER_OFFSET
        self.bytes(destination, bytes(compound.CAPACITY))
        self.put(destination - 4, 0xAABBCCDD, 4)
        self.put(destination + compound.CAPACITY, 0x12345678, 4)
        return frame, destination


class NativeTidalCompoundSnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = audit.source_image()
        cls.code, cls.patches = compound.assemble(MUTEX, CODE_BASE)

    def machine(self, **options):
        return CompoundMachine(self.image, self.code, self.patches, **options)

    def assert_native_error_return(self, machine, upper, error):
        expected = 0xFFFFFFFF if upper[0][0] == 'lower' else 0
        self.assertEqual((machine.r[2], machine.r[3]), (expected, error))
        self.assertEqual((machine.r[29], machine.r[31]), (TOP, RETURN))
        self.assertEqual(machine.r[16:21], [0x55000000 + index for index in range(5)])
        self.assertEqual(machine.api_inputs, [])
        self.assertNotIn(0x474380, machine.calls)

    def test_twenty_four_redirects_pin_both_original_call_sequences_and_native_buffers(self):
        prefix, patches = compound.qr.assemble(MUTEX, CODE_BASE)
        self.assertEqual(len(self.patches), 24)
        self.assertEqual(self.code[:len(prefix)], prefix)
        self.assertEqual({site: value for site, value in self.patches.items()
                          if site not in {row[1] for row in compound.SNAPSHOTS}}, patches)
        for _, site, original, second, second_pair, _ in compound.SNAPSHOTS:
            self.assertEqual(original, (self.image.word(site), self.image.word(site + 4)))
            self.assertEqual(self.patches[site][0], original)
            self.assertEqual(second_pair, (self.image.word(second), self.image.word(second + 4)))
            self.assertNotIn(second, self.patches)
        # Both exact native routes zero 128 bytes at SP+334 before the calls.
        self.assertEqual((self.image.word(0x4AB004), self.image.word(0x4AB01C),
                          self.image.word(0x4AB02C)),
                         (0x24060080, 0x27A40334, 0x0C296F18))
        self.assertEqual((self.image.word(0x4AB498), self.image.word(0x4AB5D4),
                          self.image.word(0x4AB5D8)),
                         (0x27A40334, 0x0C296F18, 0x24060080))

    def test_success_preserves_the_full_abi_and_replays_the_second_delay_once(self):
        for upper in UPPERS:
            with self.subTest(site=hex(upper[0][1])):
                machine = self.machine()
                frame, destination = machine.seed_upper(upper)
                before, hi, lo = machine.r.copy(), machine.hi, machine.lo
                second = upper[0][3]
                machine.run_at(upper[0][1], second + 8)
                expected = before.copy()
                expected[2], expected[3], expected[4], expected[31] = OLD_ID, 0, destination, second + 8
                expected[upper[5]] = (expected[upper[5]] + 4) & 0xFFFFFFFF
                self.assertEqual((machine.r, machine.hi, machine.lo), (expected, hi, lo))
                self.assertEqual(machine.string(destination), OLD_TEXT)
                self.assertEqual(machine.get(destination + len(OLD_TEXT), 1), 0)
                self.assertEqual(machine.snapshot_calls[-1],
                                 (compound.COPY, (destination, RESPONSE_DATA, len(OLD_TEXT) + 1)))
                self.assertEqual(machine.mutex_events,
                                 [(session.LOCK, MUTEX, 0), (session.UNLOCK, MUTEX, 0)])
                self.assertEqual(machine.r[29], frame)
                machine.run_at(second + 8, upper[4] + 8)
                self.assertEqual(machine.api_inputs, [(OLD_TEXT, OLD_ID, expected[upper[5]])])

    def test_replacement_after_unlock_cannot_mix_the_private_copy_and_scalar(self):
        for upper in UPPERS:
            with self.subTest(site=hex(upper[0][1])):
                machine = self.machine()
                _, destination = machine.seed_upper(upper)
                observations = []

                def replace_after_unlock():
                    machine.on_release = None
                    writer = machine.fork_cpu()
                    writer.on_release = None
                    writer.seed_worker()
                    writer.run_at(identity.WORK_BEGIN, identity.WORK_END)
                    observations.append((machine.slots(), machine.string(destination)))

                machine.on_release = replace_after_unlock
                machine.run_at(upper[0][1], upper[4] + 8)
                self.assertEqual(observations, [((NEW_RESPONSE, NEW_FOLLOWUP), OLD_TEXT)])
                self.assertEqual(machine.api_inputs[0][:2], (OLD_TEXT, OLD_ID))
                self.assertEqual(machine.get(NEW_RESPONSE + 4, 4), NEW_ID)
                self.assertEqual(machine.slots()[0], NEW_RESPONSE)

    def test_empty_text_and_length_127_include_nul_without_touching_the_capacity_canary(self):
        for length in (0, 127):
            for upper in UPPERS:
                with self.subTest(length=length, site=hex(upper[0][1])):
                    machine = self.machine()
                    _, destination = machine.seed_upper(upper)
                    text = b'x' * length
                    machine.bytes(RESPONSE_DATA, text + b'\0')
                    machine.run_at(upper[0][1], upper[0][3] + 8)
                    self.assertEqual(machine.r[2:4], [OLD_ID, 0])
                    self.assertEqual(machine.string(destination), text)
                    self.assertEqual(machine.get(destination + length, 1), 0)
                    self.assertEqual(machine.get(destination - 4, 4), 0xAABBCCDD)
                    self.assertEqual(machine.get(destination + compound.CAPACITY, 4), 0x12345678)
                    self.assertEqual(machine.snapshot_calls[-1][1][2], length + 1)

    def test_length_128_missing_primary_or_null_text_skip_the_api_via_native_pure_tails(self):
        for kind, error in (('long', 75), ('empty_primary', 61), ('null_text', 22)):
            for upper in UPPERS:
                with self.subTest(kind=kind, site=hex(upper[0][1])):
                    machine = self.machine()
                    _, destination = machine.seed_upper(upper)
                    if kind == 'long':
                        machine.bytes(RESPONSE_DATA, b'x' * 128 + b'\0')
                    elif kind == 'empty_primary':
                        machine.put(SESSION + 0x18, 0, 4)
                    else:
                        machine.put(OLD_RESPONSE + 8, 0, 4)
                    before_hi, before_lo = machine.hi, machine.lo
                    machine.run_at(upper[0][1], RETURN)
                    self.assert_native_error_return(machine, upper, error)
                    self.assertEqual((machine.hi, machine.lo), (before_hi, before_lo))
                    self.assertEqual(machine.get(MUTEX + session.PHASE, 4), session.READY)
                    self.assertFalse(any(target == compound.COPY for target, _ in machine.snapshot_calls))
                    self.assertEqual(bytes(machine.get(destination + n, 1) for n in range(128)), bytes(128))

    def test_unavailable_closing_and_mismatched_binding_never_call_libc_or_the_api(self):
        for kind, error in (('new', 11), ('failed', 22), ('closing', 116), ('global', 116)):
            for upper in UPPERS:
                with self.subTest(kind=kind, site=hex(upper[0][1])):
                    machine = self.machine()
                    machine.seed_upper(upper)
                    if kind == 'new':
                        machine.put(MUTEX + session.PHASE, session.NEW, 4)
                    elif kind == 'failed':
                        machine.put(MUTEX + session.INIT_ERROR, 22, 4)
                        machine.put(MUTEX + session.PHASE, session.FAILED, 4)
                    elif kind == 'closing':
                        machine.put(MUTEX + session.LIFECYCLE, session.CLOSING, 4)
                    else:
                        machine.put(session.SESSION_SLOT, SESSION + 0x600, 4)
                    machine.run_at(upper[0][1], RETURN)
                    self.assert_native_error_return(machine, upper, error)
                    self.assertEqual(machine.snapshot_calls, [])
                    if kind in ('new', 'failed'):
                        self.assertEqual(machine.mutex_events, [])

    def test_raw_errors_quarantine_without_guessed_unlock_and_keep_a_completed_copy(self):
        for acquire, release in ((22, 0), (0, 1)):
            for upper in UPPERS:
                with self.subTest(acquire=acquire, release=release, site=hex(upper[0][1])):
                    machine = self.machine(acquire=acquire, release=release)
                    _, destination = machine.seed_upper(upper)
                    hi, lo = machine.hi, machine.lo
                    machine.run_at(upper[0][1], RETURN)
                    self.assert_native_error_return(machine, upper, acquire or release)
                    self.assertEqual((machine.hi, machine.lo), (hi, lo))
                    self.assertEqual(machine.get(MUTEX + session.PHASE, 4), session.FAILED)
                    self.assertEqual(machine.get(MUTEX + session.INIT_ERROR, 4), acquire or release)
                    expected = [(session.LOCK, MUTEX, acquire)]
                    if not acquire:
                        expected.append((session.UNLOCK, MUTEX, release))
                    self.assertEqual(machine.mutex_events, expected)
                    self.assertEqual(machine.string(destination), b'' if acquire else OLD_TEXT)
                    self.assertEqual(machine.held, bool(release))

    def test_raw_unlock_failure_overrides_a_capacity_policy_error(self):
        for upper in UPPERS:
            with self.subTest(site=hex(upper[0][1])):
                machine = self.machine(release=1)
                machine.seed_upper(upper)
                machine.bytes(RESPONSE_DATA, b'x' * 128 + b'\0')
                machine.run_at(upper[0][1], RETURN)
                self.assert_native_error_return(machine, upper, 1)
                self.assertEqual(machine.get(MUTEX + session.PHASE, 4), session.FAILED)
                self.assertFalse(any(target == compound.COPY for target, _ in machine.snapshot_calls))


if __name__ == '__main__':
    unittest.main()
