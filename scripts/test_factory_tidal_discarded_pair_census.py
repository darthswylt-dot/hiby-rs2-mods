#!/usr/bin/env python3
"""Pin the local discarded-result and dead-buffer observations in 49A2E0.

The CFG treats direct/indirect linked calls as ordinary returns to PC+8 and
does not analyze their effects or retained aliases. Stack-address census means
encoded ADDIU from the unchanged native SP, not whole-program alias closure.
In particular, copy/libc callbacks receive the destination pointer and must
obey their ordinary nonretaining ABI before unused-buffer elimination is valid.
"""

import unittest

import factory_null_audit as audit


BEGIN, END, BUFFER, CAPACITY = 0x49A2E0, 0x49A758, 0xBAC, 128
PAIRS = ((0x49A3D0, 0x49A3D8, 0x49A3E0), (0x49A5E4, 0x49A5EC, 0x49A5F4))
FORMATIONS = {0x49A384, 0x49A3D4, 0x49A598, 0x49A5E8}


class NativeTidalDiscardedPairCensusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = audit.source_image()

    def reachable(self, start, blocked=()):
        """Caller CFG only: linked callees are assumed to return normally."""
        seen, expanded, pending = set(), set(), [start]
        while pending:
            pc = pending.pop()
            if pc in expanded or pc in blocked:
                continue
            self.assertTrue(BEGIN <= pc < END, f'edge outside native function: {pc:#x}')
            seen.add(pc)
            expanded.add(pc)
            word = self.image.word(pc)
            op, rs, rt, fn = word >> 26, word >> 21 & 31, word >> 16 & 31, word & 63
            transfer = op in (1, 2, 3, 4, 5, 6, 7) or op == 0 and fn in (8, 9)
            self.assertNotIn(op, (16, 17, 18, 19, 20, 21, 22, 23))  # No opaque/likely branch support.
            if not transfer:
                pending.append(pc + 4)
                continue
            if pc + 4 in blocked:
                continue
            seen.add(pc + 4)
            if op == 3 or op == 0 and fn == 9:
                pending.append(pc + 8)
            elif op == 0:
                self.assertEqual(word, 0x03E00008)
            elif op == 2:
                pending.append(((pc + 4) & 0xF0000000) | ((word & 0x3FFFFFF) << 2))
            else:
                if op == 1:
                    self.assertIn(rt, (0, 1))
                offset = word & 65535
                offset -= 65536 if offset & 32768 else 0
                if not (op == 5 and rs == rt):
                    pending.append(pc + 4 + offset * 4)
                if not (op == 4 and rs == rt):
                    pending.append(pc + 8)
        return seen

    def test_frame_and_all_encoded_copy_field_calls_have_the_local_return_overwrites(self):
        self.assertEqual(self.image.word(BEGIN), 0x27BDF328)  # Native frame CD8 bytes.
        saves = {0x49A2E4: 0xAFB30CC4, 0x49A2E8: 0xAFB10CBC, 0x49A2F8: 0xAFB00CB8,
                 0x49A308: 0xAFB40CC8, 0x49A30C: 0xAFB20CC0, 0x49A310: 0xAFBF0CD4,
                 0x49A314: 0xAFB60CD0, 0x49A318: 0xAFB50CCC}
        for pc, word in saves.items():
            self.assertEqual(self.image.word(pc), word)
        copies = {pc for pc in range(BEGIN, END, 4) if self.image.word(pc) == 0x0C12C588}
        fields = {pc for pc in range(BEGIN, END, 4) if self.image.word(pc) == 0x0C12C5A8}
        self.assertEqual(copies, {row[0] for row in PAIRS})
        self.assertEqual(fields, {row[1] for row in PAIRS})
        for copy, field, overwrite in PAIRS:
            self.assertEqual(field, copy + 8)
            self.assertEqual(overwrite, field + 8)
            self.assertEqual(self.image.word(copy + 4), 0x27A40BAC)
            self.assertEqual(self.image.word(field + 4), 0)
            self.assertEqual(self.image.word(overwrite), 0x8E0200CC)  # LW V0,+CC(S0), no old-V0 source.
        # The first result crosses only JAL/NOP and this known getter prefix;
        # GET_SESSION's LUI kills incoming V0 before any getter/body reads it.
        self.assertEqual([self.image.word(pc) for pc in (0x4B16A0, 0x4B16A4, 0x4B16A8, 0x4B16AC, 0x475320)],
                         [0x27BDFFE0, 0xAFBF001C, 0x0C11D4C8, 0, 0x3C0200B9])

    def test_exact_native_stack_buffer_address_census_has_only_clear_and_copy_destinations(self):
        formations, direct_memory = set(), set()
        memory_ops = (0x20, 0x21, 0x23, 0x24, 0x25, 0x28, 0x29, 0x2B, 0x31, 0x35, 0x39, 0x3D)
        for pc in range(BEGIN, END, 4):
            word = self.image.word(pc)
            op, rs, rt, imm = word >> 26, word >> 21 & 31, word >> 16 & 31, word & 65535
            if op == 9 and rs == 29 and imm == BUFFER:
                self.assertEqual(rt, 4)  # Every exact address goes directly to A0.
                formations.add(pc)
            if op in memory_ops and rs == 29 and BUFFER <= imm < BUFFER + CAPACITY:
                direct_memory.add(pc)
            if op == 0:
                self.assertNotIn(29, (rs, rt))  # No register arithmetic constructs SP aliases.
        self.assertEqual(formations, FORMATIONS)
        self.assertEqual(direct_memory, set())
        self.assertEqual([self.image.word(pc) for pc in (0x49A384, 0x49A388, 0x49A38C, 0x49A390)],
                         [0x27A40BAC, 0x00002821, 0x0C296F18, 0x24060080])
        self.assertEqual([self.image.word(pc) for pc in (0x49A598, 0x49A59C, 0x49A5A0, 0x49A5A4)],
                         [0x27A40BAC, 0x00002821, 0x0C296F18, 0x24060080])

    def test_normal_continuations_never_use_the_old_buffer_before_any_recopy(self):
        complete = self.reachable(BEGIN)
        self.assertTrue({pc for row in PAIRS for pc in row} <= complete)
        after_first = self.reachable(PAIRS[0][2])
        after_second = self.reachable(PAIRS[1][2])
        self.assertEqual(after_first & FORMATIONS, set())
        self.assertEqual(after_second & FORMATIONS, {0x49A384, 0x49A3D4})
        # The second route can enter the first route, but the full clear call
        # dominates that later copy. This does not analyze any callee's aliases.
        before_clear = self.reachable(PAIRS[1][2], blocked={0x49A38C})
        self.assertTrue({0x49A3D0, 0x49A3D4}.isdisjoint(before_clear))


if __name__ == '__main__':
    unittest.main()
