#!/usr/bin/env python3
"""Exercise the selected native getter/API branch and both retained exits."""

import unittest

import factory_null_audit as audit
import reveal_tidal_direct_reader_span_mips as direct
import reveal_tidal_response_cleanup_mips as cleanup
import reveal_tidal_request_identity_mips as identity
import reveal_tidal_response_reader_bridge_mips as session
from test_factory_d180_tidal_response_lifecycle import (
    NEW_RESPONSE, NEW_FOLLOWUP, OLD_RESPONSE, OLD_FOLLOWUP, RESPONSE_DATA, SESSION,
)
from test_factory_null_audit import RETURN, STACK
from test_reveal_tidal_response_reader_bridge_mips import CODE_BASE, MUTEX
from test_reveal_tidal_retained_readers_mips import APP, LIST, RESULT, RetainedMachine


TOP, SERVICE, AFTER_SERVICE = STACK + 0x1000, 0x8BE6FC, 0x48E05C
SEARCH = APP + 0x1000


class DirectMachine(RetainedMachine):
    def __init__(self, *args, result=RESULT, **kwargs):
        super().__init__(*args, **kwargs)
        self.result = result
        self.direct_calls = []
        self.postprocessing = []
        self.on_direct_call = None
        self.bytes(SEARCH, b'query\0')

    def seed_native(self):
        self.r[29], self.r[31] = TOP, RETURN
        self.run_at(direct.ENTRY, direct.ENTRY + 8)
        frame = self.r[29]
        for index in range(8):
            self.put(frame + 0x54C + index * 4, 0x55000000 + index, 4)
        self.put(frame + 0x56C, RETURN, 4)
        self.r[16:20] = [LIST, APP, SEARCH, LIST]
        self.bytes(frame + 0x438, b'type\0')
        self.put(frame + 0x540, 200, 4)
        return frame

    def external(self, target):
        if target == SERVICE:
            if self.held or not self.get(MUTEX + session.BORROWS, 4):
                raise AssertionError('direct service must retain its input outside the mutex')
            frame = self.r[29]
            arguments = (*self.r[4:8], *(self.get(frame + offset, 4) for offset in (0x10, 0x14, 0x18)))
            self.direct_calls.append(arguments)
            self.calls.append(target)
            if self.on_direct_call is not None:
                self.on_direct_call()
            self.put(arguments[-1], 200, 4)
            self.hostile_result(self.result)
        else:
            if target in (0x467160, 0x8CBD6C) and hasattr(self, 'postprocessing'):
                self.postprocessing.append((target, self.r[4], self.get(MUTEX + session.BORROWS, 4), self.held))
            super().external(target)


class NativeTidalDirectReaderSpanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = audit.source_image()
        cls.code, cls.patches = direct.assemble(MUTEX, CODE_BASE)

    def machine(self, **options):
        return DirectMachine(self.image, self.code, self.patches, **options)

    def assert_returned(self, machine, value, diagnostic):
        self.assertEqual((machine.r[2], machine.r[3]), (value & 0xFFFFFFFF, diagnostic))
        self.assertEqual((machine.r[29], machine.r[31]), (TOP, RETURN))
        self.assertEqual(machine.r[16:24], [0x55000000 + index for index in range(8)])

    def test_thirty_seven_hooks_pin_native_pairs_and_free_frame_words(self):
        self.assertEqual(len(self.patches), 37)
        for site, original in direct.HOOKS:
            self.assertEqual(original, (self.image.word(site), self.image.word(site + 4)))
            self.assertEqual(self.patches[site][0], original)
        sizes = {0x20: 1, 0x24: 1, 0x28: 1, 0x21: 2, 0x25: 2, 0x29: 2,
                 0x23: 4, 0x2B: 4, 0x31: 4, 0x39: 4, 0x35: 8, 0x3D: 8}
        for pc in range(direct.ENTRY, 0x48E2F8, 4):
            word = self.image.word(pc)
            op, rs, offset = word >> 26, word >> 21 & 31, word & 0xFFFF
            offset -= 0x10000 if offset & 0x8000 else 0
            if rs == 29 and op in sizes:
                self.assertFalse(offset < direct.POINTER + 4 and direct.TOKEN < offset + sizes[op], hex(pc))
            if rs == 29 and op == 9:
                self.assertNotIn(offset, (direct.TOKEN, direct.POINTER), hex(pc))
        self.assertEqual(self.image.word(0x8BE854), 0xAEB10000)  # One status word, no token overlap.

    def test_both_exit_gates_cut_every_encoded_normal_return(self):
        begin, end = direct.ENTRY, 0x48E2F8
        exits = {site for site, _ in direct.EXITS}

        def reachable(blocked=()):
            seen, pending = set(), [begin]
            while pending:
                pc = pending.pop()
                if pc in seen or pc in blocked:
                    continue
                self.assertTrue(begin <= pc < end, hex(pc))
                seen.add(pc)
                word = self.image.word(pc)
                op, rs, rt = word >> 26, word >> 21 & 31, word >> 16 & 31
                indirect = op == 0 and word & 63 in (8, 9)
                if op not in (1, 2, 3, 4, 5, 6, 7) and not indirect:
                    pending.append(pc + 4)
                    continue
                # The pinned native body contains no control transfer in a delay slot.
                delay = self.image.word(pc + 4)
                self.assertNotIn(delay >> 26, (1, 2, 3, 4, 5, 6, 7))
                self.assertFalse(delay >> 26 == 0 and delay & 63 in (8, 9))
                if indirect:
                    if word & 63 == 9:
                        pending.append(pc + 8)  # Selected normal callee returns are a premise.
                    else:
                        self.assertEqual(word, 0x03E00008)
                elif op == 3:
                    pending.append(pc + 8)
                elif op == 2:
                    pending.append(((pc + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2))
                else:
                    offset = word & 0xFFFF
                    offset -= 0x10000 if offset & 0x8000 else 0
                    if not (op == 5 and rs == rt):
                        pending.append(pc + 4 + offset * 4)
                    if not (op == 4 and rs == rt):
                        pending.append(pc + 8)
            return seen

        returns = {pc for pc in reachable() if self.image.word(pc) == 0x03E00008}
        self.assertEqual(returns, {0x48DA0C, 0x48DB10})
        self.assertTrue(exits <= reachable())
        self.assertTrue(returns.isdisjoint(reachable(exits)))

    def test_getter_retains_through_the_seven_argument_service_and_each_native_exit(self):
        for exit_site, _ in direct.EXITS:
            with self.subTest(exit=hex(exit_site)):
                machine = self.machine()
                frame = machine.seed_native()
                machine.run_at(direct.BEGIN, AFTER_SERVICE)
                self.assertEqual(machine.get(MUTEX + session.BORROWS, 4), 1)
                self.assertEqual(machine.get(frame + direct.TOKEN, 4), 1)
                self.assertEqual(machine.get(frame + direct.POINTER, 4), SESSION)
                self.assertEqual(machine.direct_calls,
                                 [(RESPONSE_DATA, 0x9B8B54, SEARCH, frame + 0x438,
                                   999, 0, frame + 0x540)])
                self.assertEqual(machine.r[2], RESULT)
                self.assertFalse(machine.held)
                machine.r[18] = 7
                hi, lo = machine.hi, machine.lo
                machine.run_at(exit_site, RETURN)
                self.assert_returned(machine, 7, 0)
                self.assertEqual((machine.hi, machine.lo), (hi, lo))
                self.assertEqual(machine.get(MUTEX + session.BORROWS, 4), 0)
                self.assertEqual(machine.get(frame + direct.TOKEN, 4), 0)
                self.assertEqual(machine.get(frame + direct.POINTER, 4), 0)

    def test_null_primary_follows_the_native_early_branch_without_losing_its_claim(self):
        machine = self.machine()
        machine.seed_native()
        machine.put(SESSION + 0x18, 0, 4)
        machine.run_at(direct.BEGIN, 0x48D94C)
        self.assertEqual(machine.direct_calls, [])
        self.assertEqual(machine.get(MUTEX + session.BORROWS, 4), 1)
        machine.r[18] = 0
        machine.run_at(direct.EXITS[1][0], RETURN)
        self.assert_returned(machine, 0, 0)
        self.assertEqual(machine.get(MUTEX + session.BORROWS, 4), 0)

    def test_native_postprocessing_and_owned_result_release_complete_before_unpin(self):
        for kind in ('primary_empty', 'service_null', 'owned_result'):
            with self.subTest(kind=kind):
                machine = self.machine(result=0 if kind == 'service_null' else RESULT)
                frame = machine.seed_native()
                if kind == 'primary_empty':
                    machine.put(SESSION + 0x18, 0, 4)
                machine.run_at(direct.BEGIN, RETURN)
                self.assert_returned(machine, 0, 0)
                self.assertEqual(machine.get(MUTEX + session.BORROWS, 4), 0)
                self.assertEqual(machine.get(frame + direct.TOKEN, 4), 0)
                self.assertEqual(machine.get(frame + direct.POINTER, 4), 0)
                self.assertEqual(machine.get(APP + 0xBCC, 4), 200)
                self.assertTrue(machine.postprocessing)
                self.assertTrue(all(count == 1 and not held for _, _, count, held in machine.postprocessing))
                expected_release = RESULT if kind == 'owned_result' else 0
                self.assertEqual(machine.response_releases, [expected_release])
                self.assertEqual(len(machine.direct_calls), 0 if kind == 'primary_empty' else 1)

    def test_unrelated_paths_preserve_the_native_epilogue_without_protocol_calls(self):
        for exit_site, _ in direct.EXITS:
            with self.subTest(exit=hex(exit_site)):
                guarded, native = self.machine(), self.machine()
                for machine in (guarded, native):
                    machine.seed_native()
                    machine.put(MUTEX + session.PHASE, session.FAILED, 4)
                    machine.put(MUTEX + session.BORROWS, 3, 4)
                    machine.r[18] = 5
                native.replacements.pop(exit_site)
                native.replacements.pop(exit_site + 4)
                for machine in (guarded, native):
                    machine.run_at(exit_site, RETURN)
                    self.assertEqual(machine.mutex_events, [])
                    self.assertEqual(machine.get(MUTEX + session.BORROWS, 4), 3)
                self.assertEqual((guarded.r, guarded.hi, guarded.lo), (native.r, native.hi, native.lo))

    def test_reentry_of_the_same_activation_does_not_increment_its_count_again(self):
        machine = self.machine()
        machine.seed_native()
        for _ in range(2):
            machine.run_at(direct.BEGIN, direct.BEGIN + 8)
            self.assertEqual(machine.r[2], SESSION)
            self.assertEqual(machine.r[31], direct.BEGIN + 8)
            self.assertEqual(machine.get(MUTEX + session.BORROWS, 4), 1)
        machine.r[18] = 0
        machine.run_at(direct.EXITS[0][0], RETURN)
        self.assertEqual(machine.get(MUTEX + session.BORROWS, 4), 0)

    def test_close_and_cleanup_refuse_reclamation_inside_the_direct_service(self):
        machine = self.machine()
        machine.seed_native()
        observed = []

        def try_reclamation():
            for close, _, _ in session.CLOSE_SITES:
                closer = machine.fork_cpu()
                closer.seed_native_frame()
                closer.run_at(close, RETURN)
                self.assertEqual((closer.r[2], closer.r[3]), (0xFFFFFFFF, 16))
                self.assertEqual(closer.teardown_events, [])
            disposer = machine.fork_cpu()
            disposer.r[29] = STACK + 0x4000
            self.assertEqual(disposer.stock(cleanup.ENTRY), 0xFFFFFFFF)
            self.assertEqual(disposer.r[3], 16)
            observed.append(machine.slots())

        machine.on_direct_call = try_reclamation
        machine.run_at(direct.BEGIN, AFTER_SERVICE)
        self.assertEqual(observed, [(OLD_RESPONSE, OLD_FOLLOWUP)])

    def test_pair_replacement_after_exit_unlock_precedes_only_stack_restoration(self):
        machine = self.machine()
        machine.seed_native()
        machine.run_at(direct.BEGIN, AFTER_SERVICE)
        machine.r[18] = 3

        def replace_after_unlock():
            machine.on_release = None
            writer = machine.fork_cpu()
            writer.on_release = None
            writer.seed_worker()
            writer.run_at(identity.WORK_BEGIN, identity.WORK_END + 8)
            self.assertEqual(writer.response_releases, [OLD_RESPONSE, OLD_FOLLOWUP])

        machine.on_release = replace_after_unlock
        machine.run_at(direct.EXITS[0][0], RETURN)
        self.assert_returned(machine, 3, 0)
        self.assertEqual(machine.slots(), (NEW_RESPONSE, NEW_FOLLOWUP))

    def test_protocol_refusal_and_counter_exhaustion_use_a_pure_error_epilogue(self):
        for kind, error in (('new', 11), ('closing', 116), ('global', 116),
                            ('cleanup', 16), ('overflow', 75)):
            with self.subTest(kind=kind):
                machine = self.machine()
                machine.seed_native()
                if kind == 'new':
                    machine.put(MUTEX + session.PHASE, session.NEW, 4)
                elif kind == 'closing':
                    machine.put(MUTEX + session.LIFECYCLE, session.CLOSING, 4)
                elif kind == 'global':
                    machine.put(session.SESSION_SLOT, SESSION + 0x600, 4)
                elif kind == 'cleanup':
                    machine.put(MUTEX + session.WRITER, cleanup.OWNER_BIT | 1, 4)
                else:
                    machine.put(MUTEX + session.BORROWS, direct.MAX_BORROWS, 4)
                machine.run_at(direct.BEGIN, RETURN)
                self.assert_returned(machine, -1, error)
                self.assertEqual(machine.direct_calls, [])
                self.assertEqual(machine.response_releases, [])
                self.assertNotIn(0x477180, machine.calls)

    def test_raw_begin_and_exit_errors_keep_actual_count_effects_and_do_not_repeat_release(self):
        for stage in ('begin', 'exit'):
            for acquire, release in ((22, 0), (0, 1)):
                with self.subTest(stage=stage, acquire=acquire, release=release):
                    machine = self.machine()
                    machine.seed_native()
                    if stage == 'exit':
                        machine.run_at(direct.BEGIN, AFTER_SERVICE)
                    machine.acquire_result, machine.release_result = acquire, release
                    machine.run_at(direct.BEGIN if stage == 'begin' else direct.EXITS[1][0], RETURN)
                    self.assert_returned(machine, -1, acquire or release)
                    expected = (0 if acquire else 1) if stage == 'begin' else (1 if acquire else 0)
                    self.assertEqual(machine.get(MUTEX + session.BORROWS, 4), expected)
                    self.assertEqual(machine.get(MUTEX + session.PHASE, 4), session.FAILED)
                    self.assertEqual(machine.response_releases, [])
                    self.assertEqual(len(machine.direct_calls), 0 if stage == 'begin' else 1)


if __name__ == '__main__':
    unittest.main()
