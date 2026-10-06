#!/usr/bin/env python3
"""Execute geometry-core instruction bytes; no firmware/device integration.

The small independent interpreter models instruction/delay-slot arithmetic,
not CPU timing, pipeline hazards, threads, exceptions or hardware ownership.
"""

import random
import struct
import unittest

from folderfollow_reveal_mips import build_geometry
from folderfollow_reveal_model import Geometry, minimal_reveal


MASK = 0xFFFFFFFF


def signed(word):
    return word - (1 << 32) if word & (1 << 31) else word


class Machine:
    def __init__(self, values, base=0x988040):
        raw = build_geometry()
        self.words = struct.unpack('<%dI' % (len(raw) // 4), raw)
        self.base = base
        self.r = [0] + [0xC0110000 + i for i in range(1, 32)]
        self.r[4:8] = [value & MASK for value in values[:4]]
        self.r[29], self.r[31] = 0x2001000, 0xDEAD0000
        self.before = self.r.copy()
        self.stack_word = values[4] & MASK
        self.reads = []
        self.hi, self.lo = 0xBAD0BAD0, 0xDEADC0DE

    def plain(self, word):
        op = word >> 26
        rs, rt, rd = (word >> 21) & 31, (word >> 16) & 31, (word >> 11) & 31
        imm = word & 0xFFFF
        simm = imm - 0x10000 if imm & 0x8000 else imm
        fn = word & 63
        if word == 0:
            return
        if op == 9:
            self.r[rt] = (self.r[rs] + simm) & MASK
        elif op == 11:
            self.r[rt] = int(self.r[rs] < (simm & MASK))
        elif op == 35:
            address = (self.r[rs] + simm) & MASK
            if address != self.before[29] + 16:
                raise AssertionError(f'non-argument memory access {address:#x}')
            self.reads.append(address)
            self.r[rt] = self.stack_word
        elif op == 0 and fn == 0x21:
            self.r[rd] = (self.r[rs] + self.r[rt]) & MASK
        elif op == 0 and fn == 0x23:
            self.r[rd] = (self.r[rs] - self.r[rt]) & MASK
        elif op == 0 and fn in (0x2A, 0x2B):
            a, b = self.r[rs], self.r[rt]
            if fn == 0x2A:
                a, b = signed(a), signed(b)
            self.r[rd] = int(a < b)
        elif op == 0 and fn == 0x19:
            product = self.r[rs] * self.r[rt]
            self.hi, self.lo = (product >> 32) & MASK, product & MASK
        elif op == 0 and fn in (0x10, 0x12):
            self.r[rd] = self.hi if fn == 0x10 else self.lo
        else:
            raise AssertionError(f'unsupported plain instruction {word:08X}')
        self.r[0] = 0

    def fetch(self, pc):
        offset = pc - self.base
        if offset < 0 or offset % 4 or offset // 4 >= len(self.words):
            raise AssertionError(f'execution left core at {pc:#x}')
        return self.words[offset // 4]

    def run(self):
        pc = self.base
        for _ in range(120):
            if pc == self.before[31]:
                for register in (0, 1, *range(3, 8), *range(14, 32)):
                    if self.r[register] != self.before[register]:
                        raise AssertionError(f'preserved register {register} changed')
                if len(self.reads) > 1:
                    raise AssertionError('fifth argument read more than once')
                return signed(self.r[2])
            word = self.fetch(pc)
            op, rs, rt = word >> 26, (word >> 21) & 31, (word >> 16) & 31
            imm = word & 0xFFFF
            simm = imm - 0x10000 if imm & 0x8000 else imm
            if op in (1, 4, 5, 6):
                if op == 1:
                    if rt not in (0, 1):
                        raise AssertionError('unsupported REGIMM')
                    taken = (signed(self.r[rs]) < 0) if rt == 0 else (signed(self.r[rs]) >= 0)
                elif op == 4:
                    taken = self.r[rs] == self.r[rt]
                elif op == 5:
                    taken = self.r[rs] != self.r[rt]
                else:
                    if rt != 0:
                        raise AssertionError('noncanonical BLEZ')
                    taken = signed(self.r[rs]) <= 0
                self.plain(self.fetch(pc + 4))  # Always execute delay slot.
                pc = pc + 4 + simm * 4 if taken else pc + 8
            elif op == 0 and word & 63 == 8:
                if rs != 31:
                    raise AssertionError('non-return indirect jump')
                target = self.r[rs]
                self.plain(self.fetch(pc + 4))
                pc = target
            else:
                self.plain(word)
                pc += 4
        raise AssertionError('execution budget exceeded')


class GeometryCoreTests(unittest.TestCase):
    def compare(self, values, base=0x988040):
        expected = minimal_reveal(values[0], values[1], Geometry(values[4], values[2], values[3]))
        result = Machine(values, base).run()
        self.assertEqual(result, -1 if expected is None else expected, values)

    def test_observed_dimensions_and_last_row(self):
        for values in ((3, 13, 80, 260, 0), (5, 13, 80, 260, 0),
                       (12, 13, 80, 260, 0), (0, 13, 80, 260, 220),
                       (3, 13, 80, 260, 60), (1, 2, 80, 260, 0)):
            with self.subTest(values=values):
                self.compare(values)

    def test_signed_and_unsigned_bounds(self):
        cases = (
            (-1, 13, 80, 260, 0), (13, 13, 80, 260, 0),
            (0, 0, 80, 260, 0), (0, -1, 80, 260, 0),
            (0, 513, 80, 260, 0), (0, 512, 80, 260, 0),
            (0, 13, 0, 260, 0), (0, 13, -1, 260, 0),
            (0, 13, 80, -1, 0), (0, 13, 80, 79, 0),
            (5, 13, 80, 260, -28), (5, 13, 80, 260, 781),
            (0, 1, 0x7FFFFFFF, 0x7FFFFFFF, 0),
            (0, 2, 0x40000000, 0x40000000, 0),  # signed overflow
            (0, 4, 0x40000000, 0x40000000, 0),  # high product != 0
            (0, 512, 0x7FFFFFFF, 0x7FFFFFFF, 0),
            (0, 1, -0x80000000, 1, 0),
            (0, 1, 1, -0x80000000, 0),
            (0, 1, 1, 1, -0x80000000),
        )
        for values in cases:
            with self.subTest(values=values):
                self.compare(values)

    def test_exhaustive_small_viewports(self):
        for count in range(1, 9):
            for pitch in range(1, 5):
                for height in range(pitch, pitch * 3 + 1):
                    for y in range(-1, max(0, count * pitch - height) + 2):
                        for row in range(-1, count + 1):
                            self.compare((row, count, pitch, height, y))

    def test_deterministic_large_valid_and_boundary_cases(self):
        rng = random.Random(0x525332)
        for _ in range(2000):
            count = rng.randint(1, 512)
            pitch = rng.randint(1, 0x7FFFFFFF // count)
            height = rng.randint(pitch, 0x7FFFFFFF)
            limit = max(0, count * pitch - height)
            y = rng.choice((0, limit, limit + 1, -1, rng.randint(0, limit)))
            # limit+1 is always representable because height >= 1.
            self.compare((rng.randint(0, count - 1), count, pitch, height, y))

    def test_deterministic_arbitrary_signed_inputs(self):
        rng = random.Random(0x988040)
        for _ in range(2000):
            self.compare(tuple(signed(rng.getrandbits(32)) for _ in range(5)))

    def test_position_independent_at_several_bases(self):
        for base in (0, 0x400000, 0x988040, 0x11001000):
            for values in ((5, 13, 80, 260, 0), (0, 13, 80, 260, 220),
                           (0, 513, 80, 260, 0)):
                self.compare(values, base)

    def test_instruction_allowlist_and_nop_delay_slots(self):
        raw = build_geometry()
        self.assertEqual(raw, build_geometry())
        self.assertEqual(len(raw) % 4, 0)
        self.assertLess(len(raw), 0x200)  # Component budget, not free cave space.
        words = struct.unpack('<%dI' % (len(raw) // 4), raw)
        reads = []
        for i, word in enumerate(words):
            op, fn = word >> 26, word & 63
            # Fail closed even for instructions never reached in a test case:
            # no stores, coprocessors, calls, traps or absolute/unknown jumps.
            self.assertIn(op, (0, 1, 4, 5, 6, 9, 11, 35))
            if op == 0 and word:
                self.assertIn(fn, (8, 0x10, 0x12, 0x19, 0x21, 0x23, 0x2A, 0x2B))
                if fn == 8:
                    self.assertEqual(word, 0x03E00008)  # only jr ra
            if op == 1:
                self.assertIn((word >> 16) & 31, (0, 1))  # no branch-and-link
            if op == 6:
                self.assertEqual((word >> 16) & 31, 0)
            if op == 35:
                reads.append(word)
            if op in (1, 4, 5, 6) or (op == 0 and fn == 8):
                self.assertEqual(words[i + 1], 0)
            if op in (1, 4, 5, 6):
                offset = word & 0xFFFF
                if offset & 0x8000:
                    offset -= 0x10000
                self.assertTrue(0 <= i + 1 + offset < len(words))
        self.assertEqual(reads, [0x8FA80010])  # lw t0,16(sp), no pointer reads


if __name__ == '__main__':
    unittest.main()
