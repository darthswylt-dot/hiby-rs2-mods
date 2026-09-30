#!/usr/bin/env python3
"""Mock instruction execution, patch scope and strict telemetry decoder tests."""
import struct
import unittest
from collections import Counter
import build_folderfollow_scroll_diag as d
from decode_folderfollow_scroll_diag import decode
from test_folderfollow_active_view_rebuild import Machine

b = d.b


class Probe(Machine):
    def __init__(self, name='vg_listview_explorer'):
        super().__init__(name=name)
        del self.regions[0xADD46C]
        self.map(0xADD468, 0xA88)
        self.wide(0xADD46C, 'a:\\Slayer\\song.flac')
        self.put(0xADD88C, 7, 4)
        self.map(0xBAD7B0, 4)
        self.calls, self.records = [], []
        self.write_result = d.SIZE
        self.clock_result = 0
        self.change_cue = False
        self.words = struct.unpack('<%dI' % (len(d.build_wrapper()) // 4), d.build_wrapper())

    def call(self, target):
        self.calls.append(target)
        a0, a1, a2 = self.r[4:7]
        result = 0
        if target == b.MEMSET_PLT:
            assert (a1, a2) == (0, d.SIZE)
            self.bytes(a0, bytes(a2))
        elif target == b.STRNCPY_PLT:
            raw = bytearray()
            for i in range(a2):
                value = self.get(a1 + i, 1)
                if not value: break
                raw.append(value)
            self.bytes(a0, raw.ljust(a2, b'\0'))
        elif target == b.WIDE_COPY:
            # Match 0x41FB80: reads one code unit ahead, then appends NUL.
            i, value = 0, self.get(a1, 2)
            while value and i < a2:
                self.put(a0 + 2 * i, value, 2)
                i += 1
                value = self.get(a1 + 2 * i, 2)
            self.put(a0 + 2 * i, 0, 2)
            result = a0
            if self.change_cue and a1 == 0xADD46C:
                self.put(0xADD88C, 8, 4)
        elif target == b.CLOCK_GETTIME_PLT:
            assert a0 == 1
            if self.clock_result == 0:
                self.bytes(a1, struct.pack('<II', 123, 456))
            result = self.clock_result
        elif target == b.WRITE_PLT:
            assert (a0, a2) == (9, d.SIZE)
            raw, offset = self.region(a1, a2)
            self.records.append(bytes(raw[offset:offset + a2]))
            result = self.write_result
        else:
            return super().call(target)
        for register in (*range(2, 16), 24, 25):
            self.r[register] = 0xBAD00000 + register
        self.r[2] = result

    def snapshot(self):
        before = {a: bytes(v) for a, v in self.regions.items() if a != 0x2000000}
        self.run()
        assert before == {a: bytes(v) for a, v in self.regions.items() if a != 0x2000000}
        assert self.calls[0] == b.ORIGINAL_CALLBACK
        return list(decode(self.records[-1]))[0]


class Tests(unittest.TestCase):
    def test_fields_and_suffix(self):
        for name in ('vg_listview_explorer', 'vg_listview_explorer##1'):
            m = Probe(name)
            for slot, address, fields in (
                (0x78, 0x1300000, {0x5A0: 99}),
                (0xCC, 0x1400000, {0x18: 80, 0x10: 240, 0x20: 520}),
                (0x3B68, 0x1500000, {0x1D4: 12, 0x1DC: 4, 0x1E0: 10}),
            ):
                m.map(address, 0x600)
                m.put(m.view + slot, address, 4)
                for off, value in fields.items(): m.put(address + off, value, 4)
            m.put(m.view + 0x4C, 40, 4)
            m.map(0x1600000, 0x600)
            m.put(0xBAD7B0, 0x1600000, 4)
            m.put(0x1600538, 3, 4)
            row = m.snapshot()
            for key, value in {'explorer_valid': 1, 'pitch': 40, 'scroll_y': 80,
                               'working_index': 99, 'cache_start': 4, 'sort': 3,
                               'cue_before': 7, 'cue_after': 7, 'name': name}.items():
                self.assertEqual(row[key], value)

    def test_null_children(self):
        row = Probe().snapshot()
        for key in ('viewport', 'internal', 'cache_owner', 'database'):
            self.assertEqual(row[key], 0)

    def test_non_explorer_has_no_explorer_reads(self):
        m = Probe('now_playing')
        m.map(m.view, 64)
        m.bytes(m.view, b'now_playing\0')
        self.assertEqual(m.snapshot()['explorer_valid'], 0)

    def test_null_context_controller_view(self):
        for which in ('context', 'controller', 'view'):
            m = Probe()
            if which == 'context': m.context = 0
            elif which == 'controller': m.put(m.context + 0x3C, 0, 4)
            else: m.view = 0
            self.assertEqual(m.snapshot()['explorer_valid'], 0)

    def test_decoder_rejects_damage(self):
        m = Probe(); m.snapshot()
        raw = m.records[0]
        for broken in (raw[:-1], b'BAD!' + raw[4:], raw[:4] + struct.pack('<I', 2) + raw[8:]):
            with self.assertRaises(ValueError): list(decode(broken))

    def test_bounded_strings_and_terminators(self):
        m = Probe()
        m.bytes(m.view + 0x3824, b'K' * 64)
        m.bytes(m.view + 0x3DD8, ('Ж' * 260).encode('utf-16le'))
        m.bytes(0xADD46C, ('Я' * 260).encode('utf-16le'))
        row = m.snapshot()
        self.assertEqual(row['lookup_key'], 'K' * 63)
        self.assertEqual(row['folder'], 'Ж' * 259)
        self.assertEqual(row['playback'], 'Я' * 259)
        self.assertEqual(row['cue_after'], 7)

    def test_write_and_clock_errors_preserve_original_return(self):
        for value in (-1, 0, 17, d.SIZE):
            m = Probe(); m.write_result = value; m.clock_result = -1
            row = m.snapshot()
            self.assertEqual(row['return'], 0x13579)
            self.assertEqual(row['time'], (0, 0))
            self.assertEqual(m.calls.count(b.WRITE_PLT), 1)

    def test_cue_race_is_flagged(self):
        m = Probe(); m.change_cue = True; m.run()
        row = list(decode(m.records[-1]))[0]
        self.assertTrue(row['cue_changed_during_copy'])

    def test_signed_values_and_repeated_records(self):
        m = Probe(); m.put(0xADD88C, 0xFFFFFFFE, 4)
        for _ in range(20): m.snapshot()
        rows = list(decode(b''.join(m.records)))
        self.assertEqual(len(rows), 20)
        self.assertTrue(all(row['cue_before'] == -2 for row in rows))

    def test_record_layout(self):
        spans = [(pos, pos + 4) for pos in d.FIELDS.values()]
        spans += [(pos, pos + size) for pos, size, _ in d.STRINGS.values()]
        spans.sort()
        self.assertTrue(all(0x20 <= start < end <= d.SIZE for start, end in spans))
        self.assertTrue(all(a[1] <= b[0] for a, b in zip(spans, spans[1:])))
        self.assertLessEqual(0x40 + d.SIZE, 0x5E0)

    def test_static_calls_stores_and_patch_scope(self):
        words = struct.unpack('<%dI' % (len(d.build_wrapper()) // 4), d.build_wrapper())
        calls = Counter((w & 0x3FFFFFF) << 2 for w in words if w >> 26 == 3)
        self.assertEqual(calls, Counter({b.ORIGINAL_CALLBACK: 1, b.GET_CURRENT_VIEW: 1,
            b.MEMSET_PLT: 1, b.CLOCK_GETTIME_PLT: 1, b.STRNCPY_PLT: 2,
            d.STRNCMP: 1, b.WIDE_COPY: 2, b.WRITE_PLT: 1}))
        for i, word in enumerate(words):
            op, rs = word >> 26, (word >> 21) & 31
            if op == 0x2B:
                self.assertIn(rs, (b.SP, b.S1))
                self.assertLess(word & 65535, d.FRAME if rs == b.SP else d.SIZE)
            if op in (3, 4, 5): self.assertEqual(words[i + 1], 0)
            if op in (4, 5):
                rel = word & 65535
                if rel & 32768: rel -= 65536
                self.assertTrue(0 <= i + 1 + rel < len(words))


if __name__ == '__main__': unittest.main()
