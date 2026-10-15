#!/usr/bin/env python3
"""Execute the actual intermediate ELF hooks; no device/stock concurrency proof."""
import struct
import unittest

import build_reveal_guard_stage as stage
from folderfollow_reveal_guard_mips import FAULT, WRITER_MASK
from verify_reveal_guard_stage import verify
from test_folderfollow_reveal_static_contract import SOURCE
from test_reveal_bridge_hooks import HookMachine, STACK, RETURN

PLAYER, ITEM = 0xADD368, 0xADD468


class StageMachine(HookMachine):
    def __init__(self, image, meta):
        self.image, self.meta = image, meta
        self.base, self.state = meta['code_base'], meta['buffer']
        self.code = image[meta['code_offset']:]
        self.labels = meta['labels']
        self.words = struct.unpack('<%dI' % (len(self.code) // 4), self.code)
        self.regions, self.reads, self.writes = {}, [], []
        self.version, self.reservation = 0, None
        self.before_instruction = None
        self.map(self.state, meta['memory_bytes'])
        self.map(0x2000000, 0x6000)
        self.map(PLAYER, 0x1E68)
        self.r = [0] + [0x11000000 + reg for reg in range(1, 32)]
        self.r[29], self.r[31] = STACK, RETURN
        self.hi, self.lo = 0x13579BDF, 0x2468ACE0
        self.calls, self.sc_failures = [], 0
        self.callback = None

    def put(self, address, value, size):
        # Inspect state without adding an emulated CPU read.
        data, offset = self.region(self.state, 4)
        phase = int.from_bytes(data[offset:offset + 4], 'little')
        self.writes.append((address, value, size, phase))
        super().put(address, value, size)
        self.version += 1

    def plain(self, word):
        rs, rt, rd = (word >> 21) & 31, (word >> 16) & 31, (word >> 11) & 31
        op = word >> 26
        imm = word & 0xFFFF
        imm -= 0x10000 if imm & 0x8000 else 0
        address = (self.r[rs] + imm) & 0xFFFFFFFF
        if op == 0x30:
            self.r[rt] = self.get(address, 4)
            self.reservation = (address, self.version)
        elif op == 0x38:
            success = self.reservation == (address, self.version)
            self.reservation = None
            if self.sc_failures:
                self.sc_failures -= 1
                success = False
            if success:
                self.put(address, self.r[rt], 4)
            self.r[rt] = int(success)
        elif op == 0 and word & 63 == 2:
            self.r[rd] = self.r[rt] >> ((word >> 6) & 31)
        elif word >> 26 == 0 and word & 63 == 0x2B:
            self.r[rd] = int(self.r[rs] < self.r[rt])
        else:
            return super().plain(word)
        self.r[0] = 0

    def run_at(self, pc, stop):
        for _ in range(20000):
            if pc == stop:
                return
            if not self.base <= pc < self.base + len(self.code) or pc % 4:
                raise AssertionError('unexpected transfer ' + hex(pc))
            if self.before_instruction is not None:
                self.before_instruction(pc)
            i = (pc - self.base) // 4
            word = self.words[i]
            op, rs, rt = word >> 26, (word >> 21) & 31, (word >> 16) & 31
            if op in (4, 5):
                taken = (self.r[rs] == self.r[rt]) == (op == 4)
                imm = word & 0xFFFF
                imm -= 0x10000 if imm & 0x8000 else 0
                self.plain(self.words[i + 1])
                pc = pc + 4 + imm * 4 if taken else pc + 8
            elif op in (2, 3) or word == 0x03E00008:
                target = (((pc + 4) & 0xF0000000) | ((word & 0x3FFFFFF) << 2)
                          if op in (2, 3) else self.r[31])
                if op == 3:
                    self.r[31] = pc + 8
                self.plain(self.words[i + 1])
                if op == 3 and not self.base <= target < self.base + len(self.code):
                    self.external(target)
                    pc = self.r[31]
                else:
                    pc = target
            else:
                self.plain(word)
                pc += 4
        raise AssertionError('unbounded execution')

    def site(self, name):
        pc, _, label = stage.hook_inventory(self.meta.get('grouped', False),
                                           self.meta.get('fast_grouped', False))[name]
        word, delay = struct.unpack_from('<2I', self.image, pc - stage.BASE)
        target = ((pc + 4) & 0xF0000000) | ((word & 0x3FFFFFF) << 2)
        self.assert_target = target
        if word >> 26 == 3:
            self.r[31] = pc + 8
        self.plain(delay)
        stop = {'prepare': 0x429F00, 'cue': 0x42AB98,
                'fast_scope_exit': 0x42CB68}.get(label, pc + 8)
        self.run_at(target, stop)


class GuardStageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SOURCE.read_bytes()
        cls.golden, _ = stage.normalize_source(cls.source)
        cls.image, cls.meta = stage.build(cls.source)

    def machine(self):
        return StageMachine(self.image, self.meta)

    def test_verifier_admits_only_intermediate_non_active_image(self):
        report = verify(self.source, self.image)
        self.assertFalse(report['autoscroll'])
        self.assertEqual(report['stage'], 'mutation-guard-only')
        self.assertEqual(report['hardware'], 'UNTESTED')
        self.assertEqual(report['memory_bytes'], 4)
        self.assertTrue(report['missing_contracts'])
        for enable in (True, 1, None, 'yes'):
            with self.assertRaises(ValueError):
                stage.build(self.source, enable_reveal=enable)

    def test_reproducible_and_all_original_hooks_checked(self):
        image, meta = stage.build(self.golden)
        self.assertEqual(image, self.image)
        self.assertEqual(meta['labels'], self.meta['labels'])
        self.assertEqual(len(stage.HOOKS), 9)
        for pc, expected, _ in stage.HOOKS.values():
            self.assertEqual(struct.unpack_from('<2I', self.golden, pc - stage.BASE), expected)

    def test_timer_old_cave_and_ui_code_are_unchanged(self):
        spans = ((stage.b.CAVE_OFFSET, stage.b.CAVE_CAPACITY),
                 (stage.b.CALLBACK_HI_OFFSET, 4), (stage.b.CALLBACK_LO_OFFSET, 4),
                 (0x499C20 - stage.BASE, 0x380), (0x8B43C0 - stage.BASE, 0x300))
        for off, size in spans:
            self.assertEqual(self.image[off:off + size], self.golden[off:off + size])

    def test_tampering_at_hook_code_header_padding_or_other_byte_rejected(self):
        points = [pc - stage.BASE for pc, _, _ in stage.HOOKS.values()]
        points += [self.meta['code_offset'], self.meta['memsize_offset'],
                   self.meta['phdr_offset'] + 24, len(self.golden), 0x500]
        for offset in points:
            with self.subTest(offset=hex(offset)):
                bad = bytearray(self.image)
                bad[offset] ^= 1
                with self.assertRaises(ValueError):
                    verify(self.source, bytes(bad))
        for bad in (self.image[:-1], self.image + b'\0'):
            with self.assertRaises(ValueError):
                verify(self.source, bad)
        with self.assertRaises(ValueError):
            stage.build(self.image)

    def test_every_linked_site_preserves_arguments_delay_and_result_abi(self):
        for name, (pc, _, label) in stage.HOOKS.items():
            if label not in ('copy', 'zero'):
                continue
            with self.subTest(name=name):
                m = self.machine()
                m.r[4:7] = [PLAYER if name == 'initialize' else ITEM,
                             0x1800000 if label == 'copy' else 0,
                             0x1E68 if name == 'initialize' else 0xA88]
                m.r[16] = PLAYER
                m.r[2] = 0xAE0000 if name == 'clear' else 1
                args = m.r[4:7].copy()
                before_saved = m.r[16:24].copy()

                def original(target):
                    self.assertEqual(target, stage.MEMCPY if label == 'copy' else stage.MEMSET)
                    self.assertEqual(m.r[4:7], args)
                    self.assertEqual(m.get(m.state, 4), WRITER_MASK | 1)
                    if name == 'initialize':
                        self.assertEqual(m.get(STACK + 0x1C, 4), PLAYER)
                    if name == 'general_mode3':
                        self.assertEqual(m.get(PLAYER + 0xBA8, 4), 1)
                    if name == 'clear':
                        self.assertEqual(m.get(0xADE9BC, 2), 0)
                    # Source is intentionally unmapped: wrapper must not read it.
                    m.hostile_result(args[0])

                m.callback = original
                m.site(name)
                expected, hi, lo = m.after_call
                expected[29], expected[31] = STACK, pc + 8
                self.assertEqual((m.r, m.hi, m.lo), (expected, hi, lo))
                self.assertEqual(m.r[16:24], before_saved)
                self.assertEqual(m.calls, [stage.MEMCPY if label == 'copy' else stage.MEMSET])
                self.assertEqual(m.get(m.state, 4), 1)
                self.assertFalse(any(0x1800000 <= address < 0x1800A88 for address, _ in m.reads))

    def test_inline_stores_run_once_after_begin_and_preserve_all_registers(self):
        for name in ('prepare', 'cue'):
            for initial in (0, FAULT):
                with self.subTest(name=name, initial=initial):
                    m = self.machine()
                    m.put(m.state, initial, 4)
                    m.r[16], m.r[18] = PLAYER, 17
                    before = (m.r.copy(), m.hi, m.lo)
                    m.writes.clear()
                    m.site(name)
                    self.assertEqual((m.r, m.hi, m.lo), before)
                    writes = [w for w in m.writes if PLAYER <= w[0] < PLAYER + 0x1E68]
                    phase = FAULT if initial else WRITER_MASK | 1
                    self.assertEqual(writes, ([(PLAYER + 0x104, 0, 2, phase),
                                              (PLAYER + 0x144C, 0, 2, phase)]
                                             if name == 'prepare' else
                                             [(PLAYER + 0x524, 17, 4, phase)]))
                    self.assertEqual(m.calls, [])
                    self.assertEqual(m.get(m.state, 4), FAULT if initial else 1)

    def test_overlap_during_original_call_cannot_restore_ready(self):
        m = self.machine()
        m.r[4:7] = [ITEM, 0x1800000, 0xA88]
        def original(target):
            self.assertEqual(m.get(m.state, 4), WRITER_MASK | 1)
            m.put(m.state, FAULT, 4)  # Other guarded writer has reported overlap.
            m.hostile_result(ITEM)
        m.callback = original
        m.site('general_recopy')
        self.assertEqual(m.get(m.state, 4), FAULT)
        self.assertEqual(m.calls, [stage.MEMCPY])

    def test_retry_exhaustion_never_suppresses_original_call(self):
        m = self.machine()
        m.r[4:7] = [ITEM, 0x1800000, 0xA88]
        m.sc_failures = 8
        def original(target):
            self.assertEqual(m.get(m.state, 4), FAULT)
            m.hostile_result(ITEM)
        m.callback = original
        m.site('fast')
        self.assertEqual(m.calls, [stage.MEMCPY])
        self.assertEqual(m.get(m.state, 4), FAULT)

    def test_general_intermediate_clear_and_recopies_are_distinct_mutations(self):
        m = self.machine()
        for ticket, name in enumerate(('prepare', 'general', 'general_recopy', 'general_mode3'), 1):
            m.r[4:7], m.r[16], m.r[2] = [ITEM, 0x1800000, 0xA88], PLAYER, 1
            m.callback = lambda target: m.hostile_result(ITEM)
            m.site(name)
            self.assertEqual(m.get(m.state, 4), ticket)
        # Deliberately NOT interpreted as four track transitions by this stage.
        self.assertEqual(m.calls, [stage.MEMCPY] * 3)


if __name__ == '__main__':
    unittest.main()
