#!/usr/bin/env python3
"""Run known native outer entries with a shared quarantine word.

Native O48 prologues/list dispatch/calls and O/D frame exits execute. List
methods and earlier D work are bounded substitutes. After the actual first
D cleanup call, an unconditional fixture cut skips the opaque remaining D
cleanup to47C810; this is identical for baseline and new code and never
chooses a path from V0. It does not certify complete dialog destruction.

Q-only LL/SC uses an explicit shared epoch. Other parent LL/SC instructions
retain their old model. Shared-H/Q interleavings have separate machine stacks;
they demonstrate emitted instruction behavior, not hardware memory ordering,
quiescent activation, complete alias coverage or native lifetime.
"""

from contextlib import contextmanager
import struct
import unittest

from build_reveal_bridge_diag import b
import reveal_dialog_retention_gate_mips as core
import reveal_dialog_retention_gate_stage as stage
import test_reveal_dialog_failure_gate_mips as previous
from test_reveal_dialog_failure_gate_mips import (
    DialogFailureGateMachine, CALLBACKS, CONTROLLER, CODE, QUEUE,
    RAW_LOCK, RAW_UNLOCK, STACK, RETURN, MASK, STAGE_ARGS, DIALOG,
    OPERATION, DIALOG_MUTEX, ACQUIRE, NativeReturnBoundary,
    _cached_assembler, _fixture_assembly_cache as imported_fixture_assembly_cache)


GUARD, GLOBAL, LIST, CELL = 0x1F20900, 0xB8AEB8, 0x1D04400, 0x1D04500
COUNT, GET, REMOVE, POST = 0x6000000, 0x6000010, 0x6000020, 0x6000030
NAME = previous.previous.previous.NAME
SECOND_STACK = STACK + 0x6000
OUTERS = {
    'poll': dict(entry=0x47CC20, return_pc=0x47CC94, epilogue=0x47CCD0,
                 tail=0x47CCD8, saves={16: 0x1C, 17: 0x20, 18: 0x24, 19: 0x28, 31: 0x2C}),
    'close': dict(entry=0x47CF80, return_pc=0x47D00C, epilogue=0x47D034,
                  tail=0x47D03C, saves={16: 0x18, 17: 0x1C, 18: 0x20,
                                      19: 0x24, 20: 0x28, 31: 0x2C})}
_ASSEMBLY_CACHE_MODULES = (*previous._ASSEMBLY_CACHE_MODULES, core, stage)


class SharedGuard:
    def __init__(self):
        self.data, self.epoch = bytearray(4), 0


@contextmanager
def _fixture_assembly_cache(enabled, *, cache_new_assembly=True):
    originals = []
    with imported_fixture_assembly_cache(enabled):
        try:
            if enabled and cache_new_assembly:
                for module in (core, stage):
                    original = module.assemble
                    originals.append((module, original))
                    module.assemble = _cached_assembler(original)
            yield
        finally:
            for module, original in reversed(originals):
                module.assemble = original


class DialogRetentionGateMachine(DialogFailureGateMachine):
    def __init__(self, image, *, assembly_cache=True, cache_new_assembly=True,
                 retry_limit=8, **options):
        with _fixture_assembly_cache(assembly_cache, cache_new_assembly=cache_new_assembly):
            super().__init__(image, assembly_cache=False, **options)
            self.parent_hooks = dict(self.composition['coherent_hooks'])
            selected = {name: options[name] for name in (
                'capacity', 'lifecycle_capacity', 'owner_capacity', 'ticket_limit',
                'queue_capacity') if name in options}
            self.composition = stage.assemble(
                *STAGE_ARGS, guard_address=GUARD, retry_limit=retry_limit,
                transport_capacity=self.peek(QUEUE + 8), **selected)
            self.code = self.code_bytes = self.composition['code']
            self.labels = self.composition['labels']
            for name, value in self.composition.items():
                if name.endswith('_labels'):
                    setattr(self, name, value)
            self.bridge_labels = self.receipt_labels
            for pc, words in self.composition['coherent_hooks'].items():
                for index, word in enumerate(words):
                    self.patches[pc + 4 * index] = word
            self.map(GUARD, 4)
            self.shared_guard, self.q_reservation = SharedGuard(), None
            self.regions[GUARD] = self.shared_guard.data
            self.guard_sc_failures, self.guard_atomic_events = 0, []
            self.map(GLOBAL, 4)
            self.map(LIST, 0x100)
            self.map(CELL, 4)
            self.list_events, self.post_events, self.outer_dialog_entries = [], [], []
            self.facade_events, self.facade_prelude_active = [], False
            self.configure_outer()
            self.clear_events()

    def put(self, address, value, size):
        result = super().put(address, value, size)
        if hasattr(self, 'shared_guard') and address < GUARD + 4 and GUARD < address + size:
            self.shared_guard.epoch += 1
        return result

    def plain(self, word):
        op, rs, rt, imm = word >> 26, (word >> 21) & 31, (word >> 16) & 31, word & 0xFFFF
        simm = imm - 65536 if imm & 0x8000 else imm
        if (hasattr(self, 'shared_guard') and op in (0x30, 0x38)
                and (self.r[rs] + simm) & MASK == GUARD):
            if op == 0x30:
                self.r[rt] = self.get(GUARD, 4)
                self.q_reservation = GUARD, self.shared_guard.epoch
                self.guard_atomic_events.append(('ll', self.current_pc, self.r[rt]))
            else:
                success = self.q_reservation == (GUARD, self.shared_guard.epoch)
                self.q_reservation = None
                if self.guard_sc_failures:
                    self.guard_sc_failures -= 1
                    success = False
                value = self.r[rt]
                if success:
                    self.put(GUARD, value, 4)
                self.r[rt] = int(success)
                self.guard_atomic_events.append(('sc', self.current_pc, value, success))
            self.r[0] = 0
            return
        if op == 0x28:
            # Native completion flags use SB; preserve its byte width rather
            # than treating the adjacent flags as a synthetic host update.
            self.put((self.r[rs] + simm) & MASK, self.r[rt] & 0xFF, 1)
            self.r[0] = 0
            return
        return super().plain(word)

    def word(self, pc):
        if pc == 0x47C7DC:
            return b.j_type(2, 0x47C810)
        if pc == 0x47C7E0:
            return 0
        return super().word(pc)

    def service(self, target):
        if (getattr(self, 'facade_prelude_active', False)
                and self.r[4] == DIALOG_MUTEX):
            acquire, release = self.dialog_acquire, self.dialog_release
            self.dialog_acquire = self.dialog_release = 0
            try:
                return super().service(target)
            finally:
                self.dialog_acquire, self.dialog_release = acquire, release
        return super().service(target)

    def external(self, target):
        if target == OUTERS['close']['entry']:
            # The facade supplies the actual F SP/47D084 RA. Run the native
            # child entry/borrow/epilogue; the outer interpreter follows RA.
            self.calls.append(target)
            self.run_at(target, self.r[31])
            return
        if target == 0x47C9A0:
            self.calls.append(target)
            self.facade_events.append((target, tuple(self.r[4:8]), self.r[29], self.r[31]))
            self.facade_prelude_active = True
            try:
                self.run_at(target, self.r[31])
            finally:
                self.facade_prelude_active = False
            return
        if target == 0x466E20:
            self.calls.append(target)
            self.facade_events.append((target, tuple(self.r[4:8]), self.r[29], self.r[31]))
            self.hostile_result(0)
            return
        if target in (COUNT, GET, REMOVE, POST):
            self.calls.append(target)
            event = (target, tuple(self.r[4:8]), self.r[29], self.r[31])
            (self.post_events if target == POST else self.list_events).append(event)
            self.hostile_result(self.list_count if target == COUNT else CELL if target == GET else 0)
            return
        if target == 0x47C740:
            self.calls.append(target)
            caller_sp, caller = self.r[29], self.r[31]
            self.outer_dialog_entries.append((self.r.copy(), self.hi, self.lo))
            self.seed_dialog(caller_stack=caller_sp, caller=caller,
                             callback=self.outer_callback, refresh_flag=self.outer_refresh_flag)
            labels = self.dialog_retention_gate_labels
            self.run_at(ACQUIRE, NativeReturnBoundary(
                caller, labels['first_outer_return'], labels['second_outer_return'], RETURN))
            return
        return super().external(target)

    def configure_outer(self, *, callback='first', refresh_flag=0, count=1):
        self.outer_callback, self.outer_refresh_flag, self.list_count = callback, refresh_flag, count
        self.put(GLOBAL, LIST, 4)
        for offset, value in ((0x30, COUNT), (0x2C, GET), (0x20, REMOVE)):
            self.put(LIST + offset, value, 4)
        self.put(CELL, DIALOG, 4)
        for offset, value, size in ((0x10, DIALOG_MUTEX, 4),
                                    (0x6C, 0x47C740, 4), (0x7C, POST, 4),
                                    (0x24, NAME, 4), (0x1C, 1, 1), (0x1D, 0, 1)):
            self.put(DIALOG + offset, value, size)

    def attach_shared(self, other):
        self.shared_guard = other.shared_guard
        self.regions[GUARD] = other.regions[GUARD]
        self.regions[DIALOG] = other.regions[DIALOG]
        self.q_reservation = None

    def guard_value(self):
        return self.words_at(GUARD, 1)[0]

    def clear_events(self):
        super().clear_events()
        for name in ('guard_atomic_events', 'list_events', 'post_events', 'outer_dialog_entries',
                     'facade_events'):
            if hasattr(self, name):
                getattr(self, name).clear()

    def run_outer(self, kind='poll', *, stack=STACK, caller=RETURN, null=False, stop=None):
        self.outer_context = dict(kind=kind, stack=stack, caller=caller,
                                  registers=self.r.copy(), hi=self.hi, lo=self.lo)
        self.r[29], self.r[31] = stack, caller
        self.r[4] = 0 if null else NAME
        self.run_at(OUTERS[kind]['entry'], caller if stop is None else stop)
        return self.r[2], self.r[3]

    def run_facade(self, *, stack=STACK, caller=RETURN):
        self.r[29], self.r[31], self.r[4] = stack, caller, DIALOG
        self.run_at(0x47D060, caller)
        return self.r[2], self.r[3]

    def restore_retention_hook(self, pc):
        code = bytearray(self.code)
        sources = self.composition['dialog_retention_gate_source_words']
        if pc in sources:
            self.remove_pair(pc)
            struct.pack_into('<2I', code, pc - CODE, *sources[pc])
            self.code = self.code_bytes = bytes(code)
        elif pc in self.parent_hooks:
            for index, word in enumerate(self.parent_hooks[pc]):
                self.patches[pc + 4 * index] = word
        else:
            self.remove_pair(pc)


def guard_instruction(machine, pc, operation):
    word = machine.word(pc)
    if word >> 26 != operation:
        return False
    rs, imm = (word >> 21) & 31, word & 65535
    return (machine.r[rs] + (imm - 65536 if imm & 32768 else imm)) & MASK == GUARD


class DialogRetentionGateTests(unittest.TestCase):
    setUpClass = classmethod(previous.DialogFailureGateTests.setUpClass.__func__)

    def machine(self, **options):
        return DialogRetentionGateMachine(self.image, **options)

    def assert_retained(self, machine, kind, *, raw=22):
        self.assertEqual((machine.r[2], machine.r[3]), (MASK, raw))
        self.assertEqual((machine.r[29], machine.r[31]), (STACK, RETURN))
        for register in (*range(16, 24), 28, 30):
            self.assertEqual(machine.r[register], machine.outer_context['registers'][register], register)
        self.assertEqual(machine.guard_value(), core.QUARANTINED)
        self.assertNotIn(DIALOG, machine.freed)
        self.assertNotIn(OPERATION, machine.freed)
        self.assertEqual(machine.post_events, [])
        self.assertFalse(any(event[0] == REMOVE for event in machine.list_events))
        self.assertEqual(machine.words_at(DIALOG + 0x1C, 1)[0] & 0xFFFF, 1)
        self.assertEqual(machine.direct_release_entries, [])
        self.assertNotIn(OUTERS[kind]['return_pc'], machine.trace)
        self.assertEqual(machine.words_at(STACK - 48 + 0x10, 1), (0,))

    def assert_denied_before_objects(self, machine, *, stack=STACK):
        self.assertEqual((machine.r[2], machine.r[3]), (MASK, 0))
        self.assertEqual((machine.r[29], machine.r[31]), (stack, RETURN))
        self.assertEqual(machine.calls, [])
        self.assertEqual(machine.list_events, [])
        self.assertEqual(machine.outer_dialog_entries, [])
        self.assertFalse(any(DIALOG <= address < DIALOG + 0x100 or address == GLOBAL
                             for address, size in machine.reads))

    def test_callback_errors_retain_both_known_outer_objects_without_unconfirmed_unlock(self):
        for kind in OUTERS:
            for callback in CALLBACKS:
                for option in ('acquire', 'release'):
                    with self.subTest(kind=kind, callback=callback, option=option):
                        m = self.machine(**{option: 22})
                        m.configure_outer(callback=callback)
                        m.clear_events()
                        m.run_outer(kind)
                        self.assert_retained(m, kind)
                        self.assertTrue(m.mutex_held[DIALOG_MUTEX])

    def test_dialog_acquisition_errors_retain_outer_for_both_chosen_ownership_outcomes(self):
        for kind in OUTERS:
            for status in (1, 22, 0x82, MASK):
                for held in (False, True):
                    with self.subTest(kind=kind, status=status, held=held):
                        m = self.machine(dialog_acquire=status, dialog_acquire_failure_holds=held)
                        m.clear_events()
                        m.run_outer(kind)
                        self.assert_retained(m, kind, raw=status)
                        self.assertEqual(m.mutex_held[DIALOG_MUTEX], held)
                        self.assertEqual(m.dialog_callback_entries, [])

    def test_normal_known_entries_execute_outer_cleanup_and_clear_only_busy(self):
        for kind in OUTERS:
            for flag in (0, 1):
                with self.subTest(kind=kind, flag=flag):
                    m = self.machine()
                    m.configure_outer(refresh_flag=flag)
                    m.clear_events()
                    self.assertEqual(m.run_outer(kind)[0], 0)
                    self.assertEqual(m.guard_value(), core.READY)
                    self.assertEqual(m.freed.count(DIALOG), 1)
                    self.assertEqual(sum(event[0] == REMOVE for event in m.list_events), 1)
                    self.assertEqual(len(m.post_events), int(kind == 'poll'))
                    self.assertEqual(m.words_at(DIALOG + 0x1C, 1)[0] & 0xFFFF, 0x100)
                    self.assertEqual((m.r[29], m.r[31]), (STACK, RETURN))

    def test_empty_list_paths_have_real_owner_stamp_and_release_guard_without_object_reads(self):
        for kind in OUTERS:
            with self.subTest(kind=kind):
                m = self.machine()
                m.configure_outer(count=0)
                m.clear_events()
                m.run_outer(kind)
                self.assertEqual(m.guard_value(), core.READY)
                self.assertEqual(m.freed, [])
                self.assertFalse(any(DIALOG <= address < DIALOG + 0x100 for address, size in m.reads))
                self.assertEqual(m.words_at(STACK - 48 + 0x10, 1), (0,))

    def test_null_close_keeps_native_architecture_and_never_reads_guard_or_allocates_outer_frame(self):
        m = self.machine()
        m.put(GUARD, core.QUARANTINED, 4)
        before, hi, lo = m.r.copy(), m.hi, m.lo
        before[4], before[29], before[31] = 0, STACK, RETURN
        m.clear_events()
        m.run_outer('close', null=True)
        self.assertEqual((m.r, m.hi, m.lo), (before, hi, lo))
        self.assertEqual(m.guard_value(), core.QUARANTINED)
        self.assertNotIn((GUARD, 4), m.reads)
        self.assertEqual(m.calls, [])

    def test_repeat_and_other_known_entry_are_blocked_before_any_retained_object_access(self):
        m = self.machine(acquire=22)
        m.clear_events()
        m.run_outer('poll')
        self.assert_retained(m, 'poll')
        for kind in ('poll', 'close'):
            m.clear_events()
            m.run_outer(kind)
            self.assert_denied_before_objects(m)
            self.assertEqual(m.guard_value(), core.QUARANTINED)

    def test_busy_guard_denies_both_entries_without_changing_other_owners_state(self):
        for kind in OUTERS:
            m = self.machine()
            m.put(GUARD, core.BUSY, 4)
            m.clear_events()
            m.run_outer(kind)
            self.assert_denied_before_objects(m)
            self.assertEqual(m.guard_value(), core.BUSY)

    def test_shared_guard_reentry_during_service_is_denied_then_owner_fault_stays_latched(self):
        owner, reentrant = self.machine(acquire=22), self.machine()
        reentrant.attach_shared(owner)
        entered = []

        def service(current, target):
            if target == RAW_LOCK and current.r[4] == DIALOG_MUTEX:
                reentrant.clear_events()
                reentrant.run_outer('close', stack=SECOND_STACK)
                entered.append((reentrant.r[2], reentrant.r[3]))

        owner.on_service = service
        owner.clear_events()
        owner.run_outer('poll')
        self.assert_retained(owner, 'poll')
        self.assertEqual(entered, [(MASK, 0)])
        self.assert_denied_before_objects(reentrant, stack=SECOND_STACK)
        self.assertEqual(reentrant.guard_value(), core.QUARANTINED)

    def test_new_emitters_uncached_match_cached_under_unchanged_39_parent_cache(self):
        originals = {module: module.assemble for module in _ASSEMBLY_CACHE_MODULES}
        plain = self.machine(acquire=22, cache_new_assembly=False)
        cached = self.machine(acquire=22)
        self.assertEqual(plain.code, cached.code)
        for current in (plain, cached):
            current.clear_events()
        self.assertEqual(plain.run_outer(), cached.run_outer())
        self.assertEqual((plain.r, plain.hi, plain.lo), (cached.r, cached.hi, cached.lo))
        self.assertIsNot(plain.dialog_retention_gate_labels, cached.dialog_retention_gate_labels)
        cached.dialog_retention_gate_labels['host_probe'] = 123
        fresh = self.machine()
        self.assertNotIn('host_probe', fresh.dialog_retention_gate_labels)
        self.assertEqual(fresh.guard_value(), core.READY)
        self.assertEqual(len(_ASSEMBLY_CACHE_MODULES), 41)
        with self.assertRaises(ValueError):
            self.machine(retry_limit=True, cache_new_assembly=False)
        for module, original in originals.items():
            self.assertIs(module.assemble, original, module.__name__)

    def test_facade_normal_path_borrows_claim_and_releases_once_after_real_prelock(self):
        m = self.machine()
        m.clear_events()
        self.assertEqual(m.run_facade()[0], 0)
        self.assertEqual(m.guard_value(), core.READY)
        self.assertEqual((m.r[29], m.r[31]), (STACK, RETURN))
        self.assertEqual(m.freed.count(DIALOG), 1)
        self.assertEqual([event[0] for event in m.facade_events], [0x47C9A0, 0x466E20])
        self.assertEqual(m.facade_events[0][1][0], DIALOG)
        self.assertEqual(m.facade_events[1][1][0], 10)
        self.assertEqual([event[0] for event in m.dialog_raw_events],
                         [RAW_LOCK, RAW_UNLOCK, RAW_LOCK])
        self.assertEqual(m.words_at(STACK - 32 + 0x10, 1), (0,))
        self.assertEqual(m.words_at(STACK - 32 - 48 + 0x10, 1), (0,))

    def test_facade_child_fault_preserves_original_result_and_holds_quarantine_through_both_tails(self):
        for denied in (False, True):
            m = self.machine(**({'dialog_acquire': 22} if denied else {'acquire': 22}))
            marks = []

            def observe(current, pc):
                name = 'deny_entry' if denied else 'callback_entry'
                if pc == current.dialog_retention_gate_labels[name]:
                    marks.append(len(current.dialog_raw_events))

            m.on_instruction = observe
            m.clear_events()
            self.assertEqual(m.run_facade(), (MASK, 22))
            self.assertEqual((m.r[29], m.r[31]), (STACK, RETURN))
            self.assertEqual(m.guard_value(), core.QUARANTINED)
            self.assertNotIn(DIALOG, m.freed)
            self.assertNotIn(OPERATION, m.freed)
            self.assertEqual(marks, [3])
            self.assertEqual(len(m.dialog_raw_events), 3)
            self.assertEqual([event[0] for event in m.dialog_raw_events],
                             [RAW_LOCK, RAW_UNLOCK, RAW_LOCK])
            self.assertFalse(any(event[0] == REMOVE for event in m.list_events))
            self.assertEqual(m.words_at(STACK - 32 + 0x10, 1), (0,))
            self.assertEqual(m.words_at(STACK - 32 - 48 + 0x10, 1), (0,))


if __name__ == '__main__':
    unittest.main()
