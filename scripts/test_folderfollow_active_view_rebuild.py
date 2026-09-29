#!/usr/bin/env python3
"""Execute wrapper instructions against mocked stock calls, without hardware.

This checks register flow, gating and repeat suppression. It does not model
stock navigation internals, concurrency, timing or device memory lifetimes.
"""

import struct
import unittest

import build_folderfollow_saved_path_rebuild as b


class Machine:
    def __init__(self, name="vg_listview_explorer", folder="a:\\old\\*",
                 playback="a:\\new\\song.flac"):
        self.regions = {}
        self.context, self.controller, self.view = 0x1000000, 0x1100000, 0x1200000
        self.map(self.context, 0x400)
        self.put(self.context + 0x3C, self.controller, 4)
        self.map(0x2000000, 0x4000)
        self.map(b.EXPLORER_VIEW_TYPE, 64)
        self.bytes(b.EXPLORER_VIEW_TYPE, b"vg_listview_explorer\0")
        self.map(b.PLAYBACK_PATH, 0x208)
        self.wide(b.PLAYBACK_PATH, playback)
        self.set_view(name, folder)
        self.marker = ""
        self.rebuilds = []
        self.words = struct.unpack("<%dI" % (len(b.build_wrapper(active_type_gate=True)) // 4),
                                   b.build_wrapper(active_type_gate=True))

    def map(self, address, size):
        self.regions[address] = bytearray(size)

    def region(self, address, size):
        for start, data in self.regions.items():
            if start <= address and address + size <= start + len(data):
                return data, address - start
        raise AssertionError(f"unmapped access {address:#x}, size {size}")

    def bytes(self, address, value):
        data, offset = self.region(address, len(value))
        data[offset:offset + len(value)] = value

    def get(self, address, size):
        data, offset = self.region(address, size)
        return int.from_bytes(data[offset:offset + size], "little")

    def put(self, address, value, size):
        self.bytes(address, (value & ((1 << (size * 8)) - 1)).to_bytes(size, "little"))

    def wide(self, address, value):
        self.bytes(address, value.encode("utf-16le") + b"\0\0")

    def string(self, address, unit=2):
        raw = bytearray()
        for i in range(1024):
            value = self.get(address + i * unit, unit)
            if not value:
                return raw.decode("utf-16le" if unit == 2 else "ascii")
            raw.extend(value.to_bytes(unit, "little"))
        raise AssertionError("unterminated string")

    def set_view(self, name, folder):
        self.map(self.view, 0x4000)
        self.bytes(self.view, name.encode("ascii") + b"\0")
        self.wide(self.view + 0x3DD8, folder)

    def call(self, target):
        a0, a1, a2 = self.r[4:7]
        result = 0
        if target == b.ORIGINAL_CALLBACK:
            assert (a0, a1) == (10, self.context)
            result = 0x13579
        elif target == b.GET_CURRENT_VIEW:
            assert a0 == self.controller
            self.put(a1, self.view, 4)
        elif target == b.STRNCMP_PLT:
            assert a2 == 20
            result = int(self.string(a0, 1)[:a2] != self.string(a1, 1)[:a2])
        elif target == b.WIDE_COPY:
            self.wide(a0, self.string(a1)[:a2])
        elif target == b.PROPERTY_GET:
            assert (a0, a2) == (11, 512)
            self.wide(a1, self.marker)
        elif target == b.WIDE_COMPARE:
            result = int(self.string(a0) != self.string(a1))
        elif target == b.PROPERTY_SET:
            assert a0 == 11
            self.marker = self.string(a1)
        elif target == b.STOCK_STORAGE_OPEN:
            assert a0 == self.controller
            root = self.string(a1)
            self.rebuilds.append((self.marker, root))
            self.marker = ""  # stock consumes and clears property 11
            del self.regions[self.view]  # old-pointer access must now fail
            self.view += 0x10000
            self.set_view("vg_listview_explorer", root)
        else:
            raise AssertionError(f"unexpected call {target:#x}")
        # Exercise caller-saved register discipline, not friendly stub values.
        for register in range(2, 16):
            self.r[register] = 0xBAD00000 + register
        self.r[24] = self.r[25] = 0xBAD02425
        self.r[2] = result

    def plain(self, word):
        op, rs, rt, rd = word >> 26, (word >> 21) & 31, (word >> 16) & 31, (word >> 11) & 31
        imm = word & 0xFFFF
        signed = imm - 0x10000 if imm & 0x8000 else imm
        address = (self.r[rs] + signed) & 0xFFFFFFFF
        if word == 0:
            return
        if op == 0 and word & 63 == 0x21:
            self.r[rd] = (self.r[rs] + self.r[rt]) & 0xFFFFFFFF
        elif op == 9:
            self.r[rt] = address
        elif op == 15:
            self.r[rt] = imm << 16
        elif op == 13:
            self.r[rt] = self.r[rs] | imm
        elif op in (0x23, 0x25):
            self.r[rt] = self.get(address, 4 if op == 0x23 else 2)
        elif op in (0x2B, 0x29):
            self.put(address, self.r[rt], 4 if op == 0x2B else 2)
        else:
            raise AssertionError(f"unsupported instruction {word:08x}")
        self.r[0] = 0

    def run(self):
        self.r = [0] * 32
        self.r[4:6] = [10, self.context]
        self.r[16:24] = list(range(0xCA110000, 0xCA110008))
        self.r[29], self.r[31] = 0x2003000, 0xDEAD0000
        saved = self.r[16:24]
        pc = 0
        for _ in range(10000):
            word = self.words[pc]
            op, rs, rt = word >> 26, (word >> 21) & 31, (word >> 16) & 31
            if op in (4, 5):
                take = (self.r[rs] == self.r[rt]) == (op == 4)
                imm = word & 0xFFFF
                imm = imm - 0x10000 if imm & 0x8000 else imm
                self.plain(self.words[pc + 1])
                pc = pc + 1 + imm if take else pc + 2
            elif op == 3:
                self.r[31] = b.CAVE_VADDR + (pc + 2) * 4
                self.plain(self.words[pc + 1])
                self.call((word & 0x03FFFFFF) << 2)
                pc += 2
            elif op == 0 and word & 63 == 8:
                assert self.r[rs] == 0xDEAD0000
                self.plain(self.words[pc + 1])
                assert self.r[2] == 0x13579
                assert self.r[29] == 0x2003000 and self.r[16:24] == saved
                return
            else:
                self.plain(word)
                pc += 1
        raise AssertionError("wrapper did not return")


class ActiveViewTests(unittest.TestCase):
    def test_both_explorer_names_and_repeat_suppression(self):
        for name in ("vg_listview_explorer", "vg_listview_explorer##1"):
            with self.subTest(name=name):
                m = Machine(name=name)
                for _ in range(10):
                    m.run()
                self.assertEqual(m.rebuilds, [("a:\\new\\song.flac", "a:\\*")])
                self.assertEqual(m.marker, "a:\\new\\*")
                m.wide(b.PLAYBACK_PATH, "b:\\Sleep\\Part 1.flac")
                m.run()
                self.assertEqual(m.rebuilds[-1], ("b:\\Sleep\\Part 1.flac", "b:\\*"))
                self.assertEqual(len(m.rebuilds), 2)

    def test_matching_active_path_never_rebuilds(self):
        m = Machine(folder="a:\\new\\*", name="vg_listview_explorer##1")
        m.run()
        self.assertEqual(m.rebuilds, [])

    def test_ineligible_screens_and_paths(self):
        for name in ("vg_listview_main_explorer", "playing_plane"):
            m = Machine(name=name)
            m.run()
            self.assertEqual(m.rebuilds, [])
        for path in ("", "no_separator.flac"):
            m = Machine(playback=path)
            m.run()
            self.assertEqual(m.rebuilds, [])
        m = Machine()
        m.view = 0
        m.run()
        self.assertEqual(m.rebuilds, [])

    def test_existing_attempt_marker_blocks_rebuild(self):
        m = Machine()
        m.marker = "a:\\new\\*"
        m.run()
        self.assertEqual(m.rebuilds, [])


if __name__ == "__main__":
    unittest.main()
