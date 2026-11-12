#!/usr/bin/env python3
"""Run coherent snapshots into the native S4/S3-preserving continuations."""

import unittest

import factory_null_audit as audit
import reveal_tidal_preserved_snapshots_mips as snapshot
import reveal_tidal_request_identity_mips as identity
import reveal_tidal_response_reader_bridge_mips as session
from test_factory_d180_tidal_response_lifecycle import NEW_FOLLOWUP, NEW_RESPONSE, OLD_RESPONSE, RESPONSE_DATA, SESSION
from test_factory_null_audit import RETURN
from test_reveal_tidal_compound_snapshot_mips import CompoundMachine, TOP, OLD_TEXT, OLD_ID, NEW_ID
from test_reveal_tidal_response_reader_bridge_mips import CODE_BASE, MUTEX


# Spec, native frame, saved S0/RA, first comparison call, scalar-save register.
UPPERS = ((snapshot.SNAPSHOTS[0], 0xCD0, 0xCB8, 0xCCC, 0x4AAC64, 20),
          (snapshot.SNAPSHOTS[1], 0x498, 0x480, 0x494, 0x4AB314, 19))
COMPARE = 0x41FEC0


class PreservedMachine(CompoundMachine):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.compare_inputs = []

    def external(self, target):
        if target == COMPARE:
            if self.held:
                raise AssertionError('native comparison ran under the snapshot mutex')
            self.compare_inputs.append(tuple(self.r[4:6]))
            self.calls.append(target)
            self.hostile_result(1)
        else:
            super().external(target)

    def seed_preserved(self, upper):
        spec, size, saved_s0, saved_ra, _, _ = upper
        frame = TOP - size
        self.r[29], self.r[31] = frame, spec[1]
        for index in range(5):
            self.put(frame + saved_s0 + index * 4, 0x55000000 + index, 4)
        self.put(frame + saved_ra, RETURN, 4)
        destination = frame + spec[5]
        self.bytes(destination, bytes(snapshot.CAPACITY))
        self.put(destination - 4, 0xAABBCCDD, 4)
        self.put(destination + snapshot.CAPACITY, 0x12345678, 4)
        return frame, destination


class NativeTidalPreservedSnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = audit.source_image()
        cls.code, cls.patches = snapshot.assemble(MUTEX, CODE_BASE)

    def machine(self, **options):
        return PreservedMachine(self.image, self.code, self.patches, **options)

    def assert_error(self, machine, error):
        self.assertEqual((machine.r[2], machine.r[3], machine.r[29], machine.r[31]), (0, error, TOP, RETURN))
        self.assertEqual(machine.r[16:21], [0x55000000 + index for index in range(5)])
        self.assertEqual(machine.compare_inputs, [])
        self.assertEqual(machine.api_inputs, [])
        self.assertNotIn(0x474380, machine.calls)

    def test_forty_one_hooks_pin_source_pairs_zeroed_buffers_and_pure_return_zero_tails(self):
        self.assertEqual(len(self.patches), 41)
        prefix, patches = snapshot.disposal.assemble(MUTEX, CODE_BASE)
        self.assertEqual(self.code[:len(prefix)], prefix)
        self.assertEqual({site: value for site, value in self.patches.items()
                          if site not in {row[1] for row in snapshot.SNAPSHOTS}}, patches)
        for spec, _, _, saved_ra, _, _ in UPPERS:
            _, site, original, second, second_pair, _, failure = spec
            self.assertEqual(original, (self.image.word(site), self.image.word(site + 4)))
            self.assertEqual(second_pair, (self.image.word(second), self.image.word(second + 4)))
            self.assertEqual(self.patches[site][0], original)
            self.assertNotIn(second, self.patches)
            self.assertEqual(self.image.word(failure), 0x8FBF0000 | saved_ra)
        self.assertEqual((self.image.word(0x4AAC18), self.image.word(0x4AAC20), self.image.word(0x4AAC24)),
                         (0x27A40BAC, 0x0C296F18, 0x24060080))
        self.assertEqual((self.image.word(0x4AB2D4), self.image.word(0x4AB2DC), self.image.word(0x4AB2E0)),
                         (0x27A403B4, 0x0C296F18, 0x24060080))

    def test_success_preserves_abi_and_native_continuation_keeps_the_scalar_in_s4_or_s3(self):
        for upper in UPPERS:
            with self.subTest(site=hex(upper[0][1])):
                machine = self.machine()
                _, destination = machine.seed_preserved(upper)
                before, hi, lo = machine.r.copy(), machine.hi, machine.lo
                spec = upper[0]
                machine.run_at(spec[1], spec[3] + 8)
                expected = before.copy()
                expected[2], expected[3], expected[4], expected[31] = OLD_ID, 0, destination, spec[3] + 8
                self.assertEqual((machine.r, machine.hi, machine.lo), (expected, hi, lo))
                self.assertEqual(machine.string(destination), OLD_TEXT)
                self.assertEqual(machine.snapshot_calls[-1][1], (destination, RESPONSE_DATA, len(OLD_TEXT) + 1))
                machine.run_at(spec[3] + 8, upper[4] + 8)
                self.assertEqual(machine.r[upper[5]], OLD_ID)
                self.assertEqual(len(machine.compare_inputs), 1)
                self.assertFalse(machine.held)

    def test_replacement_after_unlock_cannot_change_the_private_text_or_preserved_scalar(self):
        for upper in UPPERS:
            with self.subTest(site=hex(upper[0][1])):
                machine = self.machine()
                _, destination = machine.seed_preserved(upper)
                observed = []

                def replace_pair():
                    machine.on_release = None
                    writer = machine.fork_cpu()
                    writer.on_release = None
                    writer.seed_worker()
                    writer.run_at(identity.WORK_BEGIN, identity.WORK_END)
                    observed.append((machine.slots(), machine.string(destination)))

                machine.on_release = replace_pair
                machine.run_at(upper[0][1], upper[4] + 8)
                self.assertEqual(observed, [((NEW_RESPONSE, NEW_FOLLOWUP), OLD_TEXT)])
                self.assertEqual(machine.r[upper[5]], OLD_ID)
                self.assertEqual(machine.get(NEW_RESPONSE + 4, 4), NEW_ID)
                self.assertEqual(machine.string(destination), OLD_TEXT)

    def test_empty_text_and_length_127_copy_the_terminator_inside_native_capacity(self):
        for length in (0, 127):
            for upper in UPPERS:
                with self.subTest(length=length, site=hex(upper[0][1])):
                    machine = self.machine()
                    _, destination = machine.seed_preserved(upper)
                    machine.bytes(RESPONSE_DATA, b'x' * length + b'\0')
                    machine.run_at(upper[0][1], upper[0][3] + 8)
                    self.assertEqual(machine.string(destination), b'x' * length)
                    self.assertEqual(machine.get(destination + length, 1), 0)
                    self.assertEqual(machine.get(destination - 4, 4), 0xAABBCCDD)
                    self.assertEqual(machine.get(destination + snapshot.CAPACITY, 4), 0x12345678)

    def test_long_or_absent_data_skip_all_opaque_continuations_via_pure_native_tails(self):
        for kind, error in (('capacity', 75), ('primary', 61), ('text', 22)):
            for upper in UPPERS:
                with self.subTest(kind=kind, site=hex(upper[0][1])):
                    machine = self.machine()
                    _, destination = machine.seed_preserved(upper)
                    if kind == 'capacity':
                        machine.bytes(RESPONSE_DATA, b'x' * 128 + b'\0')
                    elif kind == 'primary':
                        machine.put(SESSION + 0x18, 0, 4)
                    else:
                        machine.put(OLD_RESPONSE + 8, 0, 4)
                    hi, lo = machine.hi, machine.lo
                    machine.run_at(upper[0][1], RETURN)
                    self.assert_error(machine, error)
                    self.assertEqual((machine.hi, machine.lo), (hi, lo))
                    self.assertEqual(bytes(machine.get(destination + offset, 1) for offset in range(128)), bytes(128))
                    self.assertFalse(any(target == snapshot.COPY for target, _ in machine.snapshot_calls))

    def test_unready_closing_or_mismatched_binding_never_reads_response_data(self):
        for kind, error in (('new', 11), ('failed', 22), ('closing', 116), ('global', 116)):
            for upper in UPPERS:
                with self.subTest(kind=kind, site=hex(upper[0][1])):
                    machine = self.machine()
                    machine.seed_preserved(upper)
                    if kind == 'new':
                        machine.put(MUTEX + session.PHASE, session.NEW, 4)
                    elif kind == 'failed':
                        machine.put(MUTEX + session.PHASE, session.FAILED, 4)
                        machine.put(MUTEX + session.INIT_ERROR, 22, 4)
                    elif kind == 'closing':
                        machine.put(MUTEX + session.LIFECYCLE, session.CLOSING, 4)
                    else:
                        machine.put(session.SESSION_SLOT, SESSION + 0x800, 4)
                    machine.run_at(upper[0][1], RETURN)
                    self.assert_error(machine, error)
                    self.assertEqual(machine.snapshot_calls, [])

    def test_raw_errors_quarantine_and_never_run_native_comparison_after_a_copy(self):
        for upper in UPPERS:
            for acquire, release in ((22, 0), (0, 1)):
                with self.subTest(site=hex(upper[0][1]), acquire=acquire, release=release):
                    machine = self.machine(acquire=acquire, release=release)
                    _, destination = machine.seed_preserved(upper)
                    machine.run_at(upper[0][1], RETURN)
                    self.assert_error(machine, acquire or release)
                    self.assertEqual(machine.get(MUTEX + session.PHASE, 4), session.FAILED)
                    self.assertEqual(machine.string(destination), b'' if acquire else OLD_TEXT)
                    self.assertEqual(machine.mutex_events, [(session.LOCK, MUTEX, acquire)] +
                                     ([(session.UNLOCK, MUTEX, release)] if not acquire else []))


if __name__ == '__main__':
    unittest.main()
