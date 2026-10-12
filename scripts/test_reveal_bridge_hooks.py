#!/usr/bin/env python3
"""Execute passive bridge hooks with hostile ABI stubs and bounded memory.

This is not a CPU, thread, loader or stock-object-lifetime simulator. It
checks emitted instructions, delay slots, memory ranges and wrapper ABI only.
"""

import struct
import unittest

import build_reveal_bridge_diag as bridge
from decode_reveal_bridge_diag import decode, summary
from test_folderfollow_active_view_rebuild import Machine as BasicMachine


MASK = 0xFFFFFFFF
BUFFER, CODE, STACK, RETURN = 0xBD4000, 0xC70000, 0x2003000, 0xDEAD0000


class HookMachine(BasicMachine):
    def __init__(self):
        # Reuse only the elementary instruction/memory helpers, not another
        # builder's fixtures or control-flow interpreter.
        self.regions = {}
        self.reads = []
        self.map(BUFFER, bridge.MEMORY_BYTES)
        self.map(0x2000000, 0x6000)
        self.code, self.labels = bridge.assemble(BUFFER, CODE)
        self.words = struct.unpack('<%dI' % (len(self.code) // 4), self.code)
        self.r = [0] + [0x11000000 + r for r in range(1, 32)]
        self.r[29], self.r[31] = STACK, RETURN
        self.hi, self.lo = 0x13579BDF, 0x2468ACE0
        self.calls, self.exports = [], []
        self.sc_failures = 0
        self.callback = None
        self.write_results = []

    def get(self, address, size):
        if size > 1 and address % size:
            raise AssertionError('unaligned read')
        self.reads.append((address, size))
        return super().get(address, size)

    def put(self, address, value, size):
        if size > 1 and address % size:
            raise AssertionError('unaligned write')
        super().put(address, value, size)

    def plain(self, word):
        op = word >> 26
        rs, rt, rd = (word >> 21) & 31, (word >> 16) & 31, (word >> 11) & 31
        imm = word & 0xFFFF
        simm = imm - 0x10000 if imm & 0x8000 else imm
        fn = word & 63
        if word == 15:  # SYNC semantics checked structurally, not simulated.
            return
        if op == 0 and fn == 0:
            self.r[rd] = (self.r[rt] << ((word >> 6) & 31)) & MASK
        elif op == 0 and fn in (0x10, 0x12):
            self.r[rd] = self.hi if fn == 0x10 else self.lo
        elif op == 0 and fn in (0x11, 0x13):
            if fn == 0x11:
                self.hi = self.r[rs]
            else:
                self.lo = self.r[rs]
        elif op == 11:
            self.r[rt] = int(self.r[rs] < (simm & MASK))
        elif op == 12:
            self.r[rt] = self.r[rs] & imm
        elif op == 0x30:
            self.r[rt] = self.get((self.r[rs] + simm) & MASK, 4)
        elif op == 0x38:
            if self.sc_failures:
                self.sc_failures -= 1
                self.r[rt] = 0
            else:
                self.put((self.r[rs] + simm) & MASK, self.r[rt], 4)
                self.r[rt] = 1
        else:
            return super().plain(word)
        self.r[0] = 0

    def hostile_result(self, result):
        # O32 callees may overwrite all four outgoing argument-home words.
        for offset in range(0, 16, 4):
            self.put(self.r[29] + offset, 0xD00D0000 + offset, 4)
        for reg in bridge.VOLATILE:
            if reg != 31:
                self.r[reg] = 0xBAD00000 + reg
        self.r[2] = result & MASK
        self.hi, self.lo = 0xABCD1234, 0x4321DCBA
        self.after_call = (self.r.copy(), self.hi, self.lo)

    def external(self, target):
        self.calls.append(target)
        if self.callback is not None:
            self.callback(target)
        elif target == bridge.b.ORIGINAL_CALLBACK:
            self.hostile_result(0x13579)
        elif target == bridge.WRITE:
            if self.r[4] != 9:
                raise AssertionError('wrong diagnostic descriptor')
            data, offset = self.region(self.r[5], self.r[6])
            self.exports.append(bytes(data[offset:offset + self.r[6]]))
            result = self.write_results.pop(0) if self.write_results else self.r[6]
            self.hostile_result(result)
        else:
            raise AssertionError('unexpected external call ' + hex(target))

    def run_hook(self, label, stop):
        pc = self.labels[label]
        for _ in range(50000):
            if pc == stop:
                return
            if not CODE <= pc < CODE + len(self.code) or pc % 4:
                raise AssertionError('unexpected transfer ' + hex(pc))
            index = (pc - CODE) // 4
            word = self.words[index]
            op, rs, rt = word >> 26, (word >> 21) & 31, (word >> 16) & 31
            if op in (4, 5):
                taken = (self.r[rs] == self.r[rt]) == (op == 4)
                offset = word & 0xFFFF
                offset -= 0x10000 if offset & 0x8000 else 0
                self.plain(self.words[index + 1])
                pc = pc + 4 + offset * 4 if taken else pc + 8
            elif op in (2, 3) or (op == 0 and word & 63 in (8, 9)):
                target = (((pc + 4) & 0xF0000000) | ((word & 0x3FFFFFF) << 2)
                          if op in (2, 3) else self.r[rs])
                linked = op == 3 or (op == 0 and word & 63 == 9)
                if linked:
                    rd = 31 if op == 3 else (word >> 11) & 31
                    self.r[rd] = pc + 8
                self.plain(self.words[index + 1])
                if linked and not CODE <= target < CODE + len(self.code):
                    self.external(target)
                    pc = self.r[31]
                else:
                    pc = target
            else:
                self.plain(word)
                pc += 4
        raise AssertionError('execution budget exceeded')

    def record(self, index=0):
        address = BUFFER + bridge.HEADER + index * bridge.RECORD
        data, offset = self.region(address, bridge.RECORD)
        return bytes(data[offset:offset + bridge.RECORD])


class BridgeHookTests(unittest.TestCase):
    def assert_preserved(self, machine, before):
        self.assertEqual((machine.r, machine.hi, machine.lo), before)

    def export_trace(self, machine):
        """Use the emitted timer, including its final status, not pack fixtures."""
        machine.callback = None
        machine.r[29], machine.r[31] = STACK, RETURN
        machine.run_hook('timer', RETURN)
        machine.run_hook('timer', RETURN)
        records = list(decode(b''.join(machine.exports)))
        self.assertEqual(records[-1]['kind'], 'status')
        self.assertEqual(records[-1]['reserved'], records[-1]['drained'])
        return records, summary(records)

    def test_touch_null_and_noncontact_have_no_extra_reads(self):
        for raw_type in (None, 0, 1, 4, 0xFFFFFFFF):
            with self.subTest(raw_type=raw_type):
                m = HookMachine()
                m.r[4], m.r[5] = 0, 0x1800000
                if raw_type is not None:
                    m.r[4] = 0x1900000  # Deliberately unmapped G.
                    m.map(m.r[5], 8 if raw_type == 1 else 4)
                    m.put(m.r[5], raw_type, 4)
                before = (m.r.copy(), m.hi, m.lo)
                m.run_hook('touch', 0x8B4EB4 if raw_type is None else 0x8B4CC8)
                self.assert_preserved(m, before)
                self.assertEqual(m.get(BUFFER, 4), 0)
                self.assertEqual(m.calls, [])

    def test_touch_contact_records_only_borrowed_scalars(self):
        for raw_type in (2, 3):
            m = HookMachine()
            m.r[4], m.r[5] = 0x1800000, 0x1900000
            m.map(m.r[4], 4)
            m.put(m.r[4], 1, 4)
            m.map(m.r[5], 28)
            m.put(m.r[5], raw_type, 4)
            m.put(m.r[5] + 8, 70, 4)
            m.put(m.r[5] + 12, 90, 4)
            before = (m.r.copy(), m.hi, m.lo)
            m.run_hook('touch', 0x8B4CC8)
            self.assert_preserved(m, before)
            header = struct.unpack_from('<16I', m.record())
            self.assertEqual(header[2], 7)
            self.assertEqual(header[7:11], (raw_type, 1, 70, 90))
            self.assertEqual(m.get(m.r[4], 4), 1)

    def test_playback_preserves_result_and_never_rereads_source(self):
        for caller in (0x42AC14, 0x42CBE4, 0x42CD64):
            m = HookMachine()
            source = 0x1800000
            m.map(source, 0xA88)
            m.wide(source + 4, 'a:\\Slayer\\song.flac')
            m.put(source + 0x424, 5, 4)
            m.r[4:7], m.r[31] = [0xADD468, source, 0xA88], caller

            def memcpy(target):
                self.assertEqual(target, bridge.MEMCPY)
                self.assertEqual(m.r[4:7], [0xADD468, source, 0xA88])
                del m.regions[source]
                m.hostile_result(0xADD468)

            m.callback = memcpy
            m.run_hook('playback', caller)
            expected, hi, lo = m.after_call
            expected[29], expected[31] = STACK, caller
            self.assert_preserved(m, (expected, hi, lo))
            self.assertEqual(m.calls, [bridge.MEMCPY])
            first, second = (struct.unpack_from('<16I', m.record(i)) for i in (0, 1))
            self.assertEqual((first[2], first[12], second[2], second[5]), (5, 5, 6, 0))
            self.assertEqual((first[4], second[4], first[11], second[11]), (STACK, STACK, caller, caller))

    def test_unaligned_playback_skips_pointer_reads_but_calls_original(self):
        m = HookMachine()
        m.r[4:7] = [0xADD468, 0x1800001, 0xA88]
        m.callback = lambda target: m.hostile_result(0xADD468)
        m.run_hook('playback', RETURN)
        self.assertEqual(m.calls, [bridge.MEMCPY])
        self.assertFalse(any(0x1800000 <= address < 0x1801000 for address, _ in m.reads))

    def test_full_queue_still_calls_playback_original_exactly_once(self):
        m = HookMachine()
        m.put(BUFFER, bridge.CAPACITY, 4)
        m.r[4:7] = [0xADD468, 0x1800000, 0xA88]  # Source deliberately unmapped.
        m.callback = lambda target: m.hostile_result(0xADD468)
        m.run_hook('playback', RETURN)
        expected, hi, lo = m.after_call
        expected[29], expected[31] = STACK, RETURN
        self.assert_preserved(m, (expected, hi, lo))
        self.assertEqual(m.calls, [bridge.MEMCPY])
        self.assertEqual(m.get(BUFFER, 4), bridge.CAPACITY)
        self.assertEqual(m.get(BUFFER + 8, 4), 1)

    def test_fill_append_original_frame_and_postcall_registers(self):
        m = HookMachine()
        list_address = 0x1800000
        m.map(list_address, 0x20)
        m.put(STACK + 0xACC, 0x6F8BF4, 4)
        m.put(STACK + 0xAD8, 0, 4)
        m.wide(STACK + 0x24, 'a:\\Slayer\\song.flac')
        m.put(STACK + 0x444, 7, 4)
        m.r[4:6] = [list_address, STACK + 0x20]
        m.r[17], m.r[22], m.r[23] = 0, list_address, 0
        m.r[25], m.r[31] = 0x455DA0, 0x6ED6F0

        def append(target):
            self.assertEqual(target, 0x455DA0)
            self.assertEqual(m.r[4:6], [list_address, STACK + 0x20])
            m.put(list_address + 12, 1, 4)
            m.hostile_result(0)

        m.callback = append
        m.run_hook('row', 0x6ED6F0)
        expected, hi, lo = m.after_call
        expected[29], expected[31] = STACK, 0x6ED6F0
        self.assert_preserved(m, (expected, hi, lo))
        self.assertEqual(m.calls, [0x455DA0])
        header = struct.unpack_from('<16I', m.record())
        self.assertEqual((header[2], header[4], header[10], header[12], header[14]),
                         (2, STACK, 0, 7, 1))

    def test_copy_stops_at_260th_code_unit_and_marks_long_path(self):
        for length in (259, 260):
            m = HookMachine()
            source = 0x1800000
            m.map(source, 0xA88)
            m.bytes(source + 4, ('x' * length).encode('utf-16le'))
            m.r[4:7] = [0xADD468, source, 0xA88]
            m.callback = lambda target: m.hostile_result(0xADD468)
            m.run_hook('playback', RETURN)
            header = struct.unpack_from('<16I', m.record())
            self.assertEqual(header[13], int(length == 260))
            path_reads = [(address, size) for address, size in m.reads
                          if source + 4 <= address < source + 0x424]
            self.assertEqual(path_reads, [(source + 4 + i * 2, 2) for i in range(260)])

    def test_reset_and_close_replay_displaced_prologues(self):
        for label, size, saved_reg, offset in (('reset', 72, 31, 0x44), ('close', 1208, 17, 0x494)):
            m = HookMachine()
            m.r[4] = m.r[5] = 0
            expected = m.r.copy()
            expected[29] -= size
            m.run_hook(label, bridge.HOOKS[label][0] + 8)
            self.assertEqual(m.r, expected)
            self.assertEqual(m.get(STACK - size + offset, 4), expected[saved_reg])
            self.assertEqual((m.hi, m.lo), (0x13579BDF, 0x2468ACE0))

    def test_refresh_uses_current_invocation_without_nested_list_reads(self):
        m = HookMachine()
        view, viewport = 0x1800000, 0x1900000
        m.map(view, 0x4000)
        m.map(viewport, 0x20)
        m.put(view + 0x40, 2, 4)
        m.put(view + 0x4C, 80, 4)
        m.put(view + 0x64, 0xFFFFFFFF, 4)  # Numeric token, unmapped.
        m.wide(view + 0x3DD8, 'a:\\Slayer\\*')
        m.put(viewport + 0x10, 260, 4)
        m.put(viewport + 0x18, 220, 4)
        m.put(STACK + 0xED4, RETURN, 4)
        m.r[16], m.r[17] = view, viewport
        expected = m.r.copy()
        expected[22], expected[2] = 260, 80
        m.run_hook('refresh', 0x499CBC)
        self.assertEqual(m.r, expected)
        self.assertEqual((m.hi, m.lo), (0x13579BDF, 0x2468ACE0))
        header = struct.unpack_from('<16I', m.record())
        self.assertEqual(header[4:11], (view, viewport, 0xFFFFFFFF, 2, 220, 80, 260))
        self.assertEqual(m.calls, [])

    def test_reservation_failure_still_preserves_original_touch(self):
        for full in (False, True):
            m = HookMachine()
            m.r[4], m.r[5] = 0x1800000, 0x1900000
            m.map(m.r[4], 4)
            m.map(m.r[5], 28)
            m.put(m.r[5], 2, 4)
            if full:
                m.put(BUFFER, bridge.CAPACITY, 4)
            else:
                m.sc_failures = 8
            before = (m.r.copy(), m.hi, m.lo)
            m.run_hook('touch', 0x8B4CC8)
            self.assert_preserved(m, before)
            self.assertEqual(m.get(BUFFER + (8 if full else 12), 4), 1)

    def test_timer_is_bounded_and_preserves_callback_result(self):
        m = HookMachine()
        for _ in range(10):
            m.run_hook('reset', 0x491248)
            m.r[29] = STACK
        before = m.r.copy()
        m.run_hook('timer', RETURN)
        self.assertEqual(m.calls.count(bridge.b.ORIGINAL_CALLBACK), 1)
        self.assertEqual(len(m.exports), 9)  # One status and at most eight records.
        self.assertEqual(m.get(BUFFER + 4, 4), 8)
        self.assertEqual(m.r[2], 0x13579)
        self.assertEqual(m.r[16:24], before[16:24])
        self.assertEqual(m.r[29], STACK)

    def test_short_write_disables_drain_but_not_original_timer(self):
        m = HookMachine()
        m.write_results = [7]
        m.run_hook('timer', RETURN)
        m.run_hook('timer', RETURN)
        self.assertEqual(m.calls.count(bridge.b.ORIGINAL_CALLBACK), 2)
        self.assertEqual(len(m.exports), 1)
        self.assertEqual(m.get(BUFFER + 16, 4), 1)

    def test_decoder_accepts_actual_playback_and_timer_bytes(self):
        m = HookMachine()
        source = 0x1800000
        path = 'a:\\Slayer\\Evil has no boundaries.flac'
        m.map(source, 0xA88)
        m.wide(source + 4, path)
        m.put(source + 0x424, 3, 4)
        m.r[4:7], m.r[31] = [0xADD468, source, 0xA88], 0x42AC14

        def memcpy(target):
            self.assertEqual(target, bridge.MEMCPY)
            del m.regions[source]
            m.hostile_result(0xADD468)

        m.callback = memcpy
        m.run_hook('playback', 0x42AC14)
        records, report = self.export_trace(m)
        self.assertEqual([row['kind'] for row in records],
                         ['status', 'playback_begin', 'playback_end', 'status'])
        self.assertTrue(report['accepted_prefix'], report)
        self.assertEqual(len(report['playback_copies']), 1)
        pair = report['playback_copies'][0]
        self.assertTrue(pair['accepted_pair'], pair)
        self.assertEqual(pair['source_identity'], {'path': path, 'cue': 3})
        self.assertEqual(pair['return_value'], 0xADD468)

    def test_decoder_preserves_but_rejects_actual_unreadable_capture(self):
        m = HookMachine()
        m.r[4:7], m.r[31] = [0xADD468, 0x1800001, 0xA88], 0x42CD64
        m.callback = lambda target: m.hostile_result(0xADD468)
        m.run_hook('playback', 0x42CD64)
        records, report = self.export_trace(m)
        self.assertTrue(report['accepted_prefix'], report)
        begin = next(row for row in records if row['kind'] == 'playback_begin')
        self.assertEqual((begin['path'], begin['truncated']), ('', 1))
        pair = report['playback_copies'][0]
        self.assertFalse(pair['accepted_pair'], pair)
        self.assertIn('invalid playback begin', pair['errors'])
        self.assertEqual(m.calls.count(bridge.MEMCPY), 1)
        self.assertFalse(any(0x1800000 <= address < 0x1801000 for address, _ in m.reads))

    def test_decoder_accepts_actual_complete_two_row_fill_window(self):
        m = HookMachine()
        list_address, folder_address = 0x1800000, 0x1900000
        folder = 'a:\\Slayer\\*'
        paths = ['a:\\Slayer\\first.flac', 'a:\\Slayer\\second.flac']
        m.map(list_address, 0x20)
        m.map(folder_address, 0x208)
        m.wide(folder_address, folder)
        m.put(STACK + 0xACC, 0x6F8BF4, 4)
        m.put(STACK + 0xAD8, 0, 4)
        m.put(STACK + 0xAE4, folder_address, 4)
        m.r[16], m.r[17], m.r[22], m.r[23] = 0x1700000, 2, list_address, 0
        m.run_hook('begin', 0x6ED62C)

        def append(target):
            self.assertEqual(target, 0x455DA0)
            self.assertEqual(m.r[4:6], [list_address, STACK + 0x20])
            count = m.get(list_address + 12, 4)
            m.put(list_address + 12, count + 1, 4)
            m.hostile_result(count)

        m.callback = append
        for ordinal, path in enumerate(paths):
            m.wide(STACK + 0x24, path)
            m.put(STACK + 0x444, ordinal + 7, 4)
            m.r[4:6], m.r[17] = [list_address, STACK + 0x20], ordinal
            m.r[25], m.r[31] = 0x455DA0, 0x6ED6F0
            m.run_hook('row', 0x6ED6F0)
        m.r[2], m.r[4], m.r[17], m.r[31] = 101, m.r[16], 2, 0x6ED70C
        m.run_hook('terminal', 0x5C31C0)
        m.r[2], m.r[31] = 2, 0x6F8BF4
        m.run_hook('end', 0x6ED7DC)
        records, report = self.export_trace(m)
        self.assertTrue(report['accepted_prefix'], report)
        self.assertEqual([row['kind'] for row in records],
                         ['status', 'begin', 'row', 'row', 'terminal', 'end', 'status'])
        self.assertEqual(report['unmatched_producer_events'], [])
        self.assertEqual(len(report['producer_windows']), 1)
        window = report['producer_windows'][0]
        self.assertTrue(window['accepted_completed_window'], window)
        self.assertEqual(window['folder'], folder)
        self.assertEqual(window['mapping'],
                         [{'index': i, 'path': path, 'cue': i + 7} for i, path in enumerate(paths)])
        self.assertEqual(m.calls.count(0x455DA0), 2)


if __name__ == '__main__':
    unittest.main()
