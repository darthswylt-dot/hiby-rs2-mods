#!/usr/bin/env python3
"""Run emitted reader entry hooks against native Tidal reader bodies."""

import copy
import threading
import unittest

import factory_null_audit as audit
import reveal_tidal_response_reader_bridge_mips as bridge
from test_factory_d180_tidal_response_lifecycle import (
    COPY_OUTPUT, COPY_RESPONSE, COPY_TEXT, HAS_RESPONSE, OLD_RESPONSE,
    RESPONSE_DATA, SESSION, TidalCopyMachine,
)
from test_factory_null_audit import COPY, FREE, RETURN, STACK


CODE_BASE, MUTEX = 0xC71308, 0x1D09000
COPY_BODY = 0x4B1628
NATIVE_TOP = STACK + 0x2000
TEARDOWN_SERVICES = frozenset((
    0x448280, 0x457300, 0x457420, 0x475340, 0x437660, 0x46D480,
    0x8B3F80, 0x473220, 0x472960, 0x4797E0, 0x467300, 0x4556E0,
    0x441440, 0x440A60, 0xA5BEC0, 0x8B1180, 0x466980,
))


class ReaderBridgeMachine(TidalCopyMachine):
    def __init__(self, image, code, patches, *, acquire=0, release=0, init=0, initialize=True):
        super().__init__(image, code=code, patches=patches, code_base=CODE_BASE)
        self.map(MUTEX, bridge.CONTROL_BYTES)
        self.acquire_result, self.release_result = acquire, release
        self.init_result = init
        self.held = False
        self.mutex_events, self.response_reads = [], []
        self.init_events, self.startup_events = [], []
        self.teardown_events = []
        self.teardown_phases = []
        self.blocking_mutex = threading.Lock()
        self.on_acquire = self.on_string = self.on_teardown = None
        self.map(SESSION - 4, 4)
        self.put(SESSION - 4, 0x40, 4)
        if initialize:
            registers, hi, lo = self.r.copy(), self.hi, self.lo
            self.acquire_result = self.release_result = 0
            self.native_frame = self.seed_native_frame()
            self.put(bridge.SESSION_SLOT, 0, 4)
            self.run_at(bridge.INIT_SITE, bridge.INIT_SITE + 8)
            if self.get(MUTEX + bridge.PHASE, 4) == bridge.READY:
                self.run_at(bridge.PUBLISH_SITES[0][0], bridge.PUBLISH_SITES[0][0] + 8)
            self.r, self.hi, self.lo = registers, hi, lo
            self.acquire_result, self.release_result = acquire, release
            self.calls.clear()
            self.mutex_events.clear()

    def seed_native_frame(self, *, session=SESSION, top=NATIVE_TOP):
        frame = top - bridge.NATIVE_FRAME
        self.put(frame + 0x34, RETURN, 4)
        for index in range(4):
            self.put(frame + 0x24 + index * 4, 0x55000000 + index, 4)
        self.r[29], self.r[31], self.r[17], self.r[19] = frame, RETURN, session, 0xB90000
        return frame

    def fork_cpu(self):
        other = copy.copy(self)
        other.r = self.r.copy()
        for name, value in vars(self).items():
            if isinstance(value, list) and name != 'r':
                setattr(other, name, [])
        other.held = False
        other.before_instruction = other.on_acquire = other.on_string = other.on_teardown = None
        return other

    def get(self, address, size):
        if hasattr(self, 'response_reads') and address in (SESSION + 0x18, OLD_RESPONSE + 8):
            self.response_reads.append((address, self.held))
        return super().get(address, size)

    def word(self, pc):
        # The bridges tail-call these bounded services with the native RA.
        if pc in (0x46CA60, 0x448280, 0x457300):
            self.external(pc)
            self.fetch_pc = pc
            return 0x03E00008
        if pc in (0x46CA64, 0x448284, 0x457304):
            self.fetch_pc = pc
            return 0
        return super().word(pc)

    def external(self, target):
        if target == bridge.RAW_INIT:
            if self.r[4:6] != [MUTEX, 0]:
                raise AssertionError('wrong raw mutex initializer arguments')
            self.calls.append(target)
            self.init_events.append(self.init_result)
            self.startup_events.append(('init', self.get(MUTEX + bridge.PHASE, 4)))
            self.hostile_result(self.init_result)
        elif target in (0x700540, 0x46CA60):
            self.calls.append(target)
            self.startup_events.append((target, self.get(MUTEX + bridge.PHASE, 4),
                                        self.get(bridge.SESSION_SLOT, 4)))
            self.hostile_result(0)
        elif target in (bridge.LOCK, bridge.UNLOCK):
            if self.r[4] != MUTEX:
                raise AssertionError('wrong shared-session mutex')
            self.calls.append(target)
            result = self.acquire_result if target == bridge.LOCK else self.release_result
            self.mutex_events.append((target, self.r[4], result))
            if target == bridge.LOCK and result == 0:
                if self.on_acquire is not None:
                    self.on_acquire()
                if not self.blocking_mutex.acquire(timeout=3):
                    raise AssertionError('bounded mutex acquisition timed out')
                self.held = True
            self.hostile_result(result)
            if target == bridge.UNLOCK and result == 0:
                self.held = False
                self.blocking_mutex.release()
        elif target in TEARDOWN_SERVICES:
            if self.held:
                raise AssertionError('native teardown ran while holding the session mutex')
            self.calls.append(target)
            self.teardown_events.append(target)
            self.teardown_phases.append(self.get(MUTEX + bridge.LIFECYCLE, 4))
            if self.on_teardown is not None:
                self.on_teardown(target)
            self.hostile_result(0)
        elif target == FREE:
            if self.held:
                raise AssertionError('native teardown ran while holding the session mutex')
            self.teardown_events.append(target)
            self.teardown_phases.append(self.get(MUTEX + bridge.LIFECYCLE, 4))
            super().external(target)
        elif target == COPY_BODY:
            self.calls.append(target)
            self.run_at(target, self.r[31])
        else:
            if target in (0xA5B4E0, COPY) and not self.held:
                raise AssertionError('borrowed response data used without the mutex')
            if target == 0xA5B4E0 and self.on_string is not None:
                self.on_string()
            super().external(target)


class NativeTidalReaderBridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = audit.source_image()
        cls.code, cls.patches = bridge.assemble(MUTEX, CODE_BASE)

    def machine(self, **options):
        return ReaderBridgeMachine(self.image, self.code, self.patches, **options)

    def assert_returned(self, machine, saved, result):
        self.assertEqual(machine.r[16:24], saved)
        self.assertEqual((machine.r[2], machine.r[29], machine.r[31]), (result, STACK, RETURN))

    def test_entry_redirects_match_both_pinned_native_pairs(self):
        for _, site, original, _, _ in bridge.READERS:
            self.assertEqual(original, (self.image.word(site), self.image.word(site + 4)))
            self.assertEqual(self.patches[site][0], original)
        self.assertEqual(bridge.INIT_PAIR,
                         (self.image.word(bridge.INIT_SITE), self.image.word(bridge.INIT_SITE + 4)))
        self.assertEqual(self.patches[bridge.INIT_SITE][0], bridge.INIT_PAIR)
        for site, original, _ in (*bridge.PUBLISH_SITES, *bridge.CLOSE_SITES,
                                   (bridge.FINISH_SITE, bridge.FINISH_PAIR, 0)):
            self.assertEqual(original, (self.image.word(site), self.image.word(site + 4)))
            self.assertEqual(self.patches[site][0], original)
        self.assertEqual(len(self.patches), 8)
        for mutex, code in ((MUTEX + 1, CODE_BASE), (MUTEX, 0x4B1620),
                            (MUTEX, MUTEX), (0x4B1620, CODE_BASE)):
            with self.subTest(mutex=mutex, code=code), self.assertRaises(ValueError):
                bridge.assemble(mutex, code)

    def test_initializer_preserves_native_registers_and_runs_once(self):
        for init_result, phase in ((0, bridge.READY), (22, bridge.FAILED)):
            with self.subTest(init_result=init_result):
                machine = self.machine(init=init_result, initialize=False)
                before, hi, lo = machine.r.copy(), machine.hi, machine.lo
                before[4] = 0x9CF4D4  # Original LUI/addiu continuation.
                for _ in range(2):
                    machine.run_at(bridge.INIT_SITE, bridge.INIT_SITE + 8)
                    self.assertEqual((machine.r, machine.hi, machine.lo), (before, hi, lo))
                self.assertEqual(machine.init_events, [init_result])
                self.assertEqual(machine.get(MUTEX + bridge.PHASE, 4), phase)
                self.assertEqual(machine.get(MUTEX + bridge.INIT_ERROR, 4), init_result)

    def test_startup_initializes_before_native_session_publication(self):
        machine = self.machine(initialize=False)
        machine.put(bridge.SESSION_SLOT, 0, 4)
        machine.r[17] = SESSION
        machine.run_at(bridge.INIT_SITE, 0x475460)
        self.assertEqual(machine.startup_events,
                         [('init', bridge.INITIALIZING),
                          (0x700540, bridge.READY, 0),
                          (0x46CA60, bridge.READY, SESSION)])

    def test_initializer_retries_reservation_loss_and_skips_an_active_initializer(self):
        machine = self.machine(initialize=False)
        machine.sc_failures = 1
        machine.run_at(bridge.INIT_SITE, bridge.INIT_SITE + 8)
        self.assertEqual(machine.sc_failures, 0)
        self.assertEqual(machine.init_events, [0])
        self.assertEqual(machine.get(MUTEX + bridge.PHASE, 4), bridge.READY)

        busy = self.machine(initialize=False)
        busy.put(MUTEX + bridge.PHASE, bridge.INITIALIZING, 4)
        busy.run_at(bridge.INIT_SITE, bridge.INIT_SITE + 8)
        self.assertEqual(busy.init_events, [])
        self.assertEqual(busy.get(MUTEX + bridge.PHASE, 4), bridge.INITIALIZING)

    def test_readers_refuse_incomplete_or_failed_initialization(self):
        for phase, error, expected in ((bridge.NEW, 0, 11), (bridge.INITIALIZING, 0, 11),
                                       (bridge.FAILED, 22, 22)):
            for site, result in ((COPY_RESPONSE, 0xFFFFFFFF), (HAS_RESPONSE, 0)):
                with self.subTest(phase=phase, site=hex(site)):
                    machine = self.machine(initialize=False)
                    machine.put(MUTEX + bridge.PHASE, phase, 4)
                    machine.put(MUTEX + bridge.INIT_ERROR, error, 4)
                    saved = machine.r[16:24]
                    machine.stock(site, COPY_OUTPUT)
                    self.assert_returned(machine, saved, result)
                    self.assertEqual(machine.r[3], expected)
                    self.assertEqual(machine.mutex_events, [])
                    self.assertEqual(machine.response_reads, [])

    def test_ready_mutex_with_unpublished_session_returns_empty_under_lock(self):
        for site in (COPY_RESPONSE, HAS_RESPONSE):
            with self.subTest(site=hex(site)):
                machine = self.machine(initialize=False)
                machine.run_at(bridge.INIT_SITE, bridge.INIT_SITE + 8)
                machine.put(bridge.SESSION_SLOT, 0, 4)
                saved = machine.r[16:24]
                machine.stock(site, COPY_OUTPUT)
                self.assert_returned(machine, saved, 0)
                self.assertEqual(machine.r[3], 0)
                self.assertEqual(machine.mutex_events, [(bridge.LOCK, MUTEX, 0), (bridge.UNLOCK, MUTEX, 0)])
                self.assertEqual(machine.response_reads, [])

    def test_copy_runs_the_native_body_under_the_captured_mutex(self):
        native = TidalCopyMachine(self.image)
        guarded = self.machine()
        saved = guarded.r[16:24]
        for machine in (native, guarded):
            self.assertEqual(machine.stock(COPY_RESPONSE, COPY_OUTPUT), 0)
        for offset in range(len(COPY_TEXT) + 1):
            self.assertEqual(guarded.get(COPY_OUTPUT + offset, 1), native.get(COPY_OUTPUT + offset, 1))
        self.assertEqual(guarded.mutex_events, [(bridge.LOCK, MUTEX, 0), (bridge.UNLOCK, MUTEX, 0)])
        self.assertTrue(guarded.response_reads)
        self.assertTrue(all(held for _, held in guarded.response_reads))
        self.assertFalse(guarded.held)
        self.assert_returned(guarded, saved, 0)

    def test_presence_and_empty_response_keep_native_results(self):
        for present in (False, True):
            for site, argument, result in ((HAS_RESPONSE, 0, int(present)), (COPY_RESPONSE, COPY_OUTPUT, 0)):
                with self.subTest(present=present, site=hex(site)):
                    machine = self.machine()
                    machine.put(SESSION + 0x18, OLD_RESPONSE if present else 0, 4)
                    saved = machine.r[16:24]
                    machine.stock(site, argument)
                    self.assert_returned(machine, saved, result)
                    self.assertTrue(all(held for _, held in machine.response_reads))
                    if not present and site == COPY_RESPONSE:
                        self.assertEqual(machine.get(COPY_OUTPUT, 1), 0xCC)

    def test_null_destination_uses_native_leaf_without_acquisition(self):
        machine = self.machine()
        saved = machine.r[16:24]
        machine.stock(COPY_RESPONSE, 0)
        self.assertEqual(machine.mutex_events, [])
        self.assertEqual(machine.r[3], 0)
        self.assert_returned(machine, saved, 0xFFFFFFFF)

    def test_raw_acquire_error_returns_without_reading_or_unlocking(self):
        for site, failure in ((COPY_RESPONSE, 0xFFFFFFFF), (HAS_RESPONSE, 0)):
            with self.subTest(site=hex(site)):
                machine = self.machine(acquire=22)
                saved = machine.r[16:24]
                machine.stock(site, COPY_OUTPUT)
                self.assertEqual(machine.r[3], 22)
                self.assertEqual(machine.mutex_events, [(bridge.LOCK, MUTEX, 22)])
                self.assertEqual(machine.response_reads, [])
                self.assertEqual(machine.get(COPY_OUTPUT, 1), 0xCC)
                self.assert_returned(machine, saved, failure)

    def test_raw_unlock_error_reports_failure_after_the_native_effect(self):
        for site, failure in ((COPY_RESPONSE, 0xFFFFFFFF), (HAS_RESPONSE, 0)):
            with self.subTest(site=hex(site)):
                machine = self.machine(release=1)
                saved = machine.r[16:24]
                machine.stock(site, COPY_OUTPUT)
                self.assertEqual(machine.r[3], 1)
                self.assertEqual(machine.mutex_events, [(bridge.LOCK, MUTEX, 0), (bridge.UNLOCK, MUTEX, 1)])
                self.assertTrue(all(held for _, held in machine.response_reads))
                self.assertTrue(machine.held)
                if site == COPY_RESPONSE:
                    self.assertEqual(machine.get(COPY_OUTPUT, 1), COPY_TEXT[0])
                self.assert_returned(machine, saved, failure)


class NativeTidalSessionLifetimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = audit.source_image()
        cls.code, cls.patches = bridge.assemble(MUTEX, CODE_BASE)

    def machine(self, **options):
        return ReaderBridgeMachine(self.image, self.code, self.patches, **options)

    def state(self, machine):
        return tuple(machine.get(MUTEX + offset, 4) for offset in
                     (bridge.PHASE, bridge.BOUND_SESSION, bridge.GENERATION, bridge.LIFECYCLE))

    def assert_native_return(self, machine, top=NATIVE_TOP):
        self.assertEqual((machine.r[29], machine.r[31]), (top, RETURN))
        self.assertEqual(machine.r[16:20], [0x55000000 + index for index in range(4)])

    def test_native_cfg_cannot_skip_the_session_lifecycle_cuts(self):
        """Bounded native CFG, assuming each JAL callee returns normally to PC+8.

        This checks caller instruction paths, not callee side effects, nonlocal
        exits, or callbacks that enter the middle of this native function.
        """
        begin, end, native_free, native_return = 0x4753E0, 0x4758C8, 0x475808, 0x47582C

        def reachable(blocked=()):
            seen, expanded, pending = set(), set(), [begin]
            while pending:
                pc = pending.pop()
                if pc in blocked or pc in expanded:
                    continue
                self.assertTrue(begin <= pc < end, f'CFG edge outside native function: {pc:#x}')
                seen.add(pc)
                expanded.add(pc)
                word = self.image.word(pc)
                op, rs, rt = word >> 26, word >> 21 & 31, word >> 16 & 31
                # Fail closed if this pinned body gains an unsupported transfer.
                self.assertIn(op, (0, 1, 2, 3, 4, 5, 6, 7, 9, 15, 35, 43))
                indirect = op == 0 and word & 63 in (8, 9)
                if op not in (1, 2, 3, 4, 5, 6, 7) and not indirect:
                    pending.append(pc + 4)
                    continue
                delay = pc + 4
                if delay in blocked:
                    continue
                self.assertLess(delay, end)
                delay_word = self.image.word(delay)
                self.assertIn(delay_word >> 26, (0, 9, 15, 35, 43))
                self.assertFalse(delay_word >> 26 == 0 and delay_word & 63 in (8, 9))
                seen.add(delay)
                if indirect:
                    self.assertEqual(word, 0x03E00008)  # The sole supported indirect exit is JR RA.
                elif op == 3:
                    pending.append(pc + 8)  # Normal callee return is the explicit premise.
                elif op == 2:
                    pending.append(((pc + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2))
                else:
                    offset = word & 0xFFFF
                    offset -= 0x10000 if offset & 0x8000 else 0
                    target = pc + 4 + offset * 4
                    if op == 1:
                        self.assertIn(rt, (0, 1))  # BLTZ/BGEZ; no branch-and-link is modeled.
                    if not (op == 5 and rs == rt):
                        pending.append(target)
                    if not (op == 4 and rs == rt):
                        pending.append(pc + 8)
            return seen

        all_paths = reachable()
        closes = {site for site, _, _ in bridge.CLOSE_SITES}
        self.assertTrue({native_free, native_return, bridge.FINISH_SITE, *closes} <= all_paths)
        self.assertEqual({pc for pc in all_paths if self.image.word(pc) == 0x03E00008},
                         {native_return})
        for blocked in ({bridge.INIT_SITE}, *({site} for site, _, _ in bridge.PUBLISH_SITES), closes):
            with self.subTest(blocked=sorted(blocked)):
                self.assertTrue({native_free, native_return}.isdisjoint(reachable(blocked)))
        before_finish = reachable({bridge.FINISH_SITE})
        self.assertIn(native_free, before_finish)
        self.assertNotIn(native_return, before_finish)

    def test_repeat_publication_uses_the_same_native_frame_generation(self):
        machine = self.machine()
        frame = machine.seed_native_frame()
        self.assertEqual(machine.get(frame + bridge.TOKEN, 4), 1)
        self.assertEqual(machine.get(frame + bridge.STAMP, 4), bridge.FRAME_MAGIC)
        site = bridge.PUBLISH_SITES[1][0]
        machine.run_at(site, site + 8)
        self.assertEqual(self.state(machine), (bridge.READY, SESSION, 1, bridge.LIVE))
        self.assertEqual(machine.get(frame + bridge.TOKEN, 4), 1)
        self.assertEqual(machine.get(frame + 0x18, 4), 0)
        self.assertEqual(machine.mutex_events, [(bridge.LOCK, MUTEX, 0), (bridge.UNLOCK, MUTEX, 0)])

    def test_both_native_close_routes_keep_binding_until_after_free_and_reset(self):
        for site, _, _ in bridge.CLOSE_SITES:
            with self.subTest(site=hex(site)):
                machine = self.machine()
                frame = machine.seed_native_frame()
                machine.run_at(site, RETURN)
                self.assertEqual(machine.releases, [SESSION])
                self.assertEqual(machine.raw_releases, [SESSION - 4])
                self.assertEqual(machine.teardown_events[-2:], [FREE, 0x466980])
                self.assertEqual(set(machine.teardown_phases), {bridge.CLOSING})
                self.assertEqual(self.state(machine), (bridge.READY, 0, 1, bridge.EMPTY))
                self.assertEqual(machine.get(bridge.SESSION_SLOT, 4), 0)
                self.assertEqual(machine.get(frame + bridge.TOKEN, 4), 0)
                self.assert_native_return(machine)

    def test_raw_close_errors_skip_all_native_teardown_and_quarantine_readers(self):
        for site, _, _ in bridge.CLOSE_SITES:
            for acquire, release, expected_life in ((22, 0, bridge.LIVE), (0, 1, bridge.CLOSING)):
                with self.subTest(site=hex(site), acquire=acquire, release=release):
                    machine = self.machine(acquire=acquire, release=release)
                    machine.seed_native_frame()
                    machine.run_at(site, RETURN)
                    self.assert_native_return(machine)
                    error = acquire or release
                    self.assertEqual((machine.r[2], machine.r[3]), (0xFFFFFFFF, error))
                    self.assertEqual(self.state(machine), (bridge.FAILED, SESSION, 1, expected_life))
                    self.assertEqual(machine.get(bridge.SESSION_SLOT, 4), SESSION)
                    self.assertEqual(machine.teardown_events, [])
                    self.assertEqual(machine.releases, [])
                    calls = machine.mutex_events.copy()
                    machine.r[29] = STACK
                    machine.stock(COPY_RESPONSE, COPY_OUTPUT)
                    self.assertEqual(machine.r[3], error)
                    self.assertEqual(machine.response_reads, [])
                    self.assertEqual(machine.mutex_events, calls)

    def test_reader_rechecks_lifetime_when_close_wins_before_acquisition(self):
        machine = self.machine()
        closer = machine.fork_cpu()
        closer.seed_native_frame()
        site = bridge.CLOSE_SITES[0][0]

        def close_first():
            machine.on_acquire = None
            closer.run_at(site, site + 8)

        machine.on_acquire = close_first
        self.assertEqual(machine.stock(COPY_RESPONSE, COPY_OUTPUT), 0)
        self.assertEqual(machine.r[3], 0)
        self.assertEqual(machine.response_reads, [])
        self.assertEqual(machine.get(COPY_OUTPUT, 1), 0xCC)
        self.assertEqual(self.state(machine), (bridge.READY, SESSION, 1, bridge.CLOSING))

    def test_close_waits_for_the_active_native_string_copy(self):
        machine = self.machine()
        closer = machine.fork_cpu()
        closer.seed_native_frame()
        entered, release_reader, requested = threading.Event(), threading.Event(), threading.Event()
        failures = []

        def hold_string():
            entered.set()
            if not release_reader.wait(3):
                raise AssertionError('reader was not released')

        def capture(operation):
            try:
                operation()
            except BaseException as error:
                failures.append(error)

        machine.on_string, closer.on_acquire = hold_string, requested.set
        site = bridge.CLOSE_SITES[0][0]
        reader = threading.Thread(target=capture, args=(lambda: machine.stock(COPY_RESPONSE, COPY_OUTPUT),))
        closing = threading.Thread(target=capture, args=(lambda: closer.run_at(site, site + 8),))
        reader.start()
        try:
            self.assertTrue(entered.wait(2))
            closing.start()
            self.assertTrue(requested.wait(2))
            self.assertEqual(self.state(machine), (bridge.READY, SESSION, 1, bridge.LIVE))
            self.assertEqual(closer.teardown_events, [])
        finally:
            release_reader.set()
            reader.join(4)
            if closing.ident is not None:
                closing.join(4)
        self.assertFalse(reader.is_alive() or closing.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(bytes(machine.get(COPY_OUTPUT + n, 1) for n in range(len(COPY_TEXT))), COPY_TEXT)
        self.assertEqual(self.state(machine), (bridge.READY, SESSION, 1, bridge.CLOSING))
        self.assertTrue(all(held for _, held in machine.response_reads))
        self.assertFalse(machine.held or closer.held)

    def test_reader_rejects_a_global_pointer_outside_the_bound_session(self):
        machine = self.machine()
        machine.put(bridge.SESSION_SLOT, SESSION + 0x600, 4)
        self.assertEqual(machine.stock(COPY_RESPONSE, COPY_OUTPUT), 0xFFFFFFFF)
        self.assertEqual(machine.r[3], 116)
        self.assertEqual(machine.response_reads, [])
        self.assertEqual(machine.get(bridge.SESSION_SLOT, 4), SESSION + 0x600)
        self.assertEqual(self.state(machine), (bridge.READY, SESSION, 1, bridge.LIVE))

    def test_new_publication_is_denied_until_native_allocator_reset_finishes(self):
        machine = self.machine()
        machine.seed_native_frame()
        site = bridge.CLOSE_SITES[0][0]
        machine.run_at(site, site + 8)
        replacement = machine.fork_cpu()
        replacement.seed_native_frame(session=SESSION + 0x600, top=NATIVE_TOP + 0x400)
        replacement.run_at(bridge.INIT_SITE, bridge.INIT_SITE + 8)
        replacement.run_at(bridge.PUBLISH_SITES[0][0], RETURN)
        self.assertEqual((replacement.r[2], replacement.r[3]), (0xFFFFFFFF, 116))
        self.assertEqual(replacement.startup_events, [])
        self.assertEqual(replacement.teardown_events, [])
        self.assertEqual(self.state(machine), (bridge.READY, SESSION, 1, bridge.CLOSING))
        self.assertEqual(machine.get(bridge.SESSION_SLOT, 4), SESSION)
        machine.run_at(site + 8, RETURN)
        self.assertEqual(self.state(machine), (bridge.READY, 0, 1, bridge.EMPTY))

    def test_delayed_old_token_cannot_close_a_reallocated_session_at_the_same_address(self):
        machine = self.machine()
        old_frame = machine.seed_native_frame()
        site = bridge.CLOSE_SITES[0][0]
        machine.run_at(site, RETURN)
        new_top = NATIVE_TOP + 0x400
        new_frame = machine.seed_native_frame(top=new_top)
        machine.run_at(bridge.INIT_SITE, bridge.INIT_SITE + 8)
        publish = bridge.PUBLISH_SITES[0][0]
        machine.run_at(publish, publish + 8)
        self.assertEqual(self.state(machine), (bridge.READY, SESSION, 2, bridge.LIVE))
        self.assertEqual(machine.get(new_frame + bridge.TOKEN, 4), 2)
        # Supply the saved token of a delayed invocation, before its earlier finish cleared it.
        machine.seed_native_frame()
        machine.put(old_frame + bridge.TOKEN, 1, 4)
        events, frees = machine.teardown_events.copy(), machine.releases.copy()
        machine.run_at(site, RETURN)
        self.assertEqual((machine.r[2], machine.r[3]), (0xFFFFFFFF, 116))
        self.assertEqual(self.state(machine), (bridge.READY, SESSION, 2, bridge.LIVE))
        self.assertEqual(machine.get(bridge.SESSION_SLOT, 4), SESSION)
        self.assertEqual((machine.teardown_events, machine.releases), (events, frees))

    def test_generation_exhaustion_refuses_publication_without_wrapping(self):
        machine = self.machine(initialize=False)
        frame = machine.seed_native_frame()
        machine.put(bridge.SESSION_SLOT, 0, 4)
        machine.run_at(bridge.INIT_SITE, bridge.INIT_SITE + 8)
        machine.put(MUTEX + bridge.GENERATION, bridge.MAX_GENERATION, 4)
        machine.run_at(bridge.PUBLISH_SITES[0][0], RETURN)
        self.assertEqual((machine.r[2], machine.r[3]), (0xFFFFFFFF, 75))
        self.assertEqual(self.state(machine), (bridge.READY, 0, bridge.MAX_GENERATION, bridge.EMPTY))
        self.assertEqual(machine.get(frame + bridge.TOKEN, 4), 0)
        self.assertEqual(machine.get(bridge.SESSION_SLOT, 4), 0)
        self.assertEqual(machine.startup_events, [('init', bridge.INITIALIZING)])
        self.assertEqual(machine.teardown_events, [])

    def test_raw_publication_errors_never_continue_to_the_native_service(self):
        for acquire, release in ((22, 0), (0, 1)):
            with self.subTest(acquire=acquire, release=release):
                machine = self.machine(initialize=False)
                machine.seed_native_frame()
                machine.put(bridge.SESSION_SLOT, 0, 4)
                machine.run_at(bridge.INIT_SITE, bridge.INIT_SITE + 8)
                machine.acquire_result, machine.release_result = acquire, release
                machine.run_at(bridge.PUBLISH_SITES[0][0], RETURN)
                self.assertEqual((machine.r[2], machine.r[3]), (0xFFFFFFFF, acquire or release))
                self.assertEqual(machine.get(MUTEX + bridge.PHASE, 4), bridge.FAILED)
                self.assertEqual(machine.get(bridge.SESSION_SLOT, 4), 0 if acquire else SESSION)
                self.assertEqual(machine.startup_events, [('init', bridge.INITIALIZING)])
                self.assertEqual(machine.teardown_events, [])

    def test_raw_finish_errors_quarantine_after_the_single_native_free(self):
        for acquire, release in ((22, 0), (0, 1)):
            with self.subTest(acquire=acquire, release=release):
                machine = self.machine()
                machine.seed_native_frame()

                def fail_after_reset(target):
                    if target == 0x466980:
                        machine.acquire_result, machine.release_result = acquire, release

                machine.on_teardown = fail_after_reset
                machine.run_at(bridge.CLOSE_SITES[0][0], RETURN)
                self.assertEqual(machine.releases, [SESSION])
                self.assertEqual((machine.r[2], machine.r[3]), (0xFFFFFFFF, acquire or release))
                self.assertEqual(machine.get(MUTEX + bridge.PHASE, 4), bridge.FAILED)
                self.assert_native_return(machine)
                machine.r[29] = STACK
                self.assertEqual(machine.stock(COPY_RESPONSE, COPY_OUTPUT), 0xFFFFFFFF)
                self.assertEqual(machine.response_reads, [])
                self.assertEqual(machine.releases, [SESSION])


if __name__ == '__main__':
    unittest.main()
