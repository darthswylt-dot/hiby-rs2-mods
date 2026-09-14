#!/usr/bin/env python3
"""Small dependency-free ELF32/MIPS inspection helper for the RS2 player.

This is intentionally not a complete disassembler.  It decodes the integer,
branch, load/store, and jump instructions needed to audit the property
dispatchers in the firmware 1.4 hiby_player executable.
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path


REG = (
    "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3",
    "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
    "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
    "t8", "t9", "k0", "k1", "gp", "sp", "fp", "ra",
)


def sx16(value: int) -> int:
    return value - 0x10000 if value & 0x8000 else value


class Elf32:
    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        if self.data[:4] != b"\x7fELF" or self.data[4] != 1:
            raise ValueError("expected ELF32")
        self.endian = "<" if self.data[5] == 1 else ">"
        self.entry = self.u32(0x18)
        phoff = self.u32(0x1C)
        phentsize = self.u16(0x2A)
        phnum = self.u16(0x2C)
        self.loads: list[tuple[int, int, int, int, int]] = []
        for index in range(phnum):
            off = phoff + index * phentsize
            p_type, p_offset, p_vaddr, _, p_filesz, p_memsz, p_flags, _ = struct.unpack_from(
                self.endian + "8I", self.data, off
            )
            if p_type == 1:
                self.loads.append((p_vaddr, p_offset, p_filesz, p_memsz, p_flags))

    def u16(self, off: int) -> int:
        return struct.unpack_from(self.endian + "H", self.data, off)[0]

    def u32(self, off: int) -> int:
        return struct.unpack_from(self.endian + "I", self.data, off)[0]

    def va_to_off(self, va: int) -> int:
        for vaddr, offset, filesz, _, _ in self.loads:
            if vaddr <= va < vaddr + filesz:
                return offset + va - vaddr
        raise ValueError(f"virtual address 0x{va:X} is not file-backed")

    def word(self, va: int) -> int:
        return self.u32(self.va_to_off(va))

    def executable_ranges(self):
        for vaddr, _, filesz, _, flags in self.loads:
            if flags & 1:
                yield vaddr, vaddr + filesz


def decode(pc: int, word: int) -> str:
    op = word >> 26
    rs = (word >> 21) & 31
    rt = (word >> 16) & 31
    rd = (word >> 11) & 31
    sa = (word >> 6) & 31
    fn = word & 63
    imm = word & 0xFFFF
    simm = sx16(imm)
    if word == 0:
        return "nop"
    if op == 0:
        three = {0x20: "add", 0x21: "addu", 0x22: "sub", 0x23: "subu",
                 0x24: "and", 0x25: "or", 0x26: "xor", 0x27: "nor",
                 0x2A: "slt", 0x2B: "sltu"}
        shifts = {0x00: "sll", 0x02: "srl", 0x03: "sra"}
        if fn in three:
            return f"{three[fn]} {REG[rd]},{REG[rs]},{REG[rt]}"
        if fn in shifts:
            return f"{shifts[fn]} {REG[rd]},{REG[rt]},{sa}"
        if fn in (0x04, 0x06, 0x07):
            return f"{ {4:'sllv',6:'srlv',7:'srav'}[fn]} {REG[rd]},{REG[rt]},{REG[rs]}"
        if fn == 0x08:
            return f"jr {REG[rs]}"
        if fn == 0x09:
            return f"jalr {REG[rd]},{REG[rs]}"
        if fn in (0x10, 0x12):
            return f"{'mfhi' if fn == 0x10 else 'mflo'} {REG[rd]}"
        if fn in (0x18, 0x19, 0x1A, 0x1B):
            return f"{ {0x18:'mult',0x19:'multu',0x1A:'div',0x1B:'divu'}[fn]} {REG[rs]},{REG[rt]}"
        return f"special(fn=0x{fn:X})"
    if op in (2, 3):
        target = ((pc + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)
        return f"{'jal' if op == 3 else 'j'} 0x{target:X}"
    if op in (4, 5, 6, 7):
        name = {4: "beq", 5: "bne", 6: "blez", 7: "bgtz"}[op]
        target = pc + 4 + simm * 4
        if op in (6, 7):
            return f"{name} {REG[rs]},0x{target:X}"
        return f"{name} {REG[rs]},{REG[rt]},0x{target:X}"
    if op == 1:
        target = pc + 4 + simm * 4
        name = {0: "bltz", 1: "bgez", 16: "bltzal", 17: "bgezal"}.get(rt, f"regimm{rt}")
        return f"{name} {REG[rs]},0x{target:X}"
    immops = {8: "addi", 9: "addiu", 10: "slti", 11: "sltiu"}
    if op in immops:
        return f"{immops[op]} {REG[rt]},{REG[rs]},{simm}"
    if op in (12, 13, 14):
        return f"{ {12:'andi',13:'ori',14:'xori'}[op]} {REG[rt]},{REG[rs]},0x{imm:X}"
    if op == 15:
        return f"lui {REG[rt]},0x{imm:X}"
    memops = {32: "lb", 33: "lh", 35: "lw", 36: "lbu", 37: "lhu",
              40: "sb", 41: "sh", 43: "sw", 49: "lwc1", 57: "swc1"}
    if op in memops:
        return f"{memops[op]} {REG[rt]},{simm:+#x}({REG[rs]})"
    return f"word 0x{word:08X}"


def dump(elf: Elf32, start: int, end: int) -> None:
    for pc in range(start, end, 4):
        word = elf.word(pc)
        print(f"0x{pc:08X}: {word:08X}  {decode(pc, word)}")


def jal_xrefs(elf: Elf32, target: int, context: int) -> None:
    matches = []
    for start, end in elf.executable_ranges():
        for pc in range(start, end & ~3, 4):
            word = elf.word(pc)
            if word >> 26 == 3:
                dest = ((pc + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)
                if dest == target:
                    matches.append(pc)
    for pc in matches:
        print(f"\n# jal xref at 0x{pc:X}")
        dump(elf, max(pc - context * 4, 0), pc + (context + 2) * 4)
    print(f"\n# {len(matches)} xrefs to 0x{target:X}")


def table(elf: Elf32, base: int, count: int) -> None:
    for index in range(count):
        print(f"{index:3d}: 0x{elf.word(base + index * 4):08X}")


def word_xrefs(elf: Elf32, value: int) -> None:
    matches = []
    for vaddr, offset, filesz, _, flags in elf.loads:
        for relative in range(0, filesz & ~3, 4):
            if elf.u32(offset + relative) == value:
                matches.append((vaddr + relative, flags))
    for address, flags in matches:
        print(f"0x{address:08X}  segment_flags=0x{flags:X}")
    print(f"\n# {len(matches)} file-backed aligned words equal 0x{value:08X}")


def mem_imm_xrefs(elf: Elf32, immediate: int, context: int) -> None:
    wanted = immediate & 0xFFFF
    matches = []
    memory_ops = {32, 33, 35, 36, 37, 40, 41, 43, 49, 57}
    for start, end in elf.executable_ranges():
        for pc in range(start, end & ~3, 4):
            word = elf.word(pc)
            if (word >> 26) in memory_ops and (word & 0xFFFF) == wanted:
                matches.append(pc)
    for pc in matches:
        print(f"\n# memory-immediate xref at 0x{pc:X}")
        dump(elf, max(pc - context * 4, 0), pc + (context + 1) * 4)
    print(f"\n# {len(matches)} memory references with immediate {sx16(wanted):+#x}")


def resolve_base_backwards(elf: Elf32, pc: int, reg: int, displacement: int):
    extra = displacement
    current = reg
    for back in range(1, 25):
        word = elf.word(pc - back * 4)
        op = word >> 26
        rs = (word >> 21) & 31
        rt = (word >> 16) & 31
        rd = (word >> 11) & 31
        if op == 15 and rt == current:  # lui
            return ((word & 0xFFFF) << 16) + extra
        if op in (8, 9) and rt == current:  # addi/addiu
            extra += sx16(word & 0xFFFF)
            current = rs
            continue
        if op == 13 and rt == current and rs == current:  # ori reg,reg,imm
            extra += word & 0xFFFF
            continue
        if op == 0 and rd == current and (word & 63) in (0x20, 0x21):
            if rs == 0:
                current = rt
                continue
            if rt == 0:
                current = rs
                continue
            return None
        # Stop only when an instruction definitely overwrites the register.
        if (op not in (0, 2, 3, 4, 5, 6, 7) and rt == current) or (op == 0 and rd == current):
            return None
    return None


def abs_xrefs(elf: Elf32, address: int, context: int) -> None:
    matches = []
    memory_ops = {32, 33, 35, 36, 37, 40, 41, 43, 49, 57}
    for start, end in elf.executable_ranges():
        for pc in range(start + 4, end & ~3, 4):
            word = elf.word(pc)
            if (word >> 26) not in memory_ops:
                continue
            base = (word >> 21) & 31
            found = resolve_base_backwards(elf, pc, base, sx16(word & 0xFFFF))
            if found == address:
                matches.append(pc)
    for pc in matches:
        print(f"\n# absolute xref at 0x{pc:X}")
        dump(elf, max(pc - context * 4, 0), pc + (context + 1) * 4)
    print(f"\n# {len(matches)} statically resolved references to 0x{address:X}")


def cstring(elf: Elf32, address: int, limit: int) -> None:
    off = elf.va_to_off(address)
    raw = elf.data[off:off + limit].split(b"\0", 1)[0]
    print(raw.decode("utf-8", errors="backslashreplace"))


def utf16_string(elf: Elf32, address: int, limit: int) -> None:
    off = elf.va_to_off(address)
    raw = elf.data[off:off + limit]
    end = next(
        (index for index in range(0, len(raw) - 1, 2) if raw[index:index + 2] == b"\0\0"),
        len(raw) & ~1,
    )
    value = raw[:end].decode("utf-16le", errors="backslashreplace")
    encoding = sys.stdout.encoding or "utf-8"
    print(value.encode(encoding, errors="backslashreplace").decode(encoding))


def imm_xrefs(elf: Elf32, immediate: int, context: int) -> None:
    wanted = immediate & 0xFFFF
    matches = []
    for start, end in elf.executable_ranges():
        for pc in range(start, end & ~3, 4):
            word = elf.word(pc)
            if (word >> 26) != 0 and (word & 0xFFFF) == wanted:
                matches.append(pc)
    for pc in matches:
        print(f"\n# immediate xref at 0x{pc:X}")
        dump(elf, max(pc - context * 4, 0), pc + (context + 1) * 4)
    print(f"\n# {len(matches)} I-type instructions with immediate {sx16(wanted):+#x}")


def direct_small_constant(word: int, reg: int):
    op = word >> 26
    rs = (word >> 21) & 31
    rt = (word >> 16) & 31
    if op in (8, 9) and rs == 0 and rt == reg:
        return sx16(word & 0xFFFF)
    if op == 13 and rs == 0 and rt == reg:
        return word & 0xFFFF
    return None


def property_xrefs(elf: Elf32, dispatcher: int, prop: int, context: int) -> None:
    matches = []
    for start, end in elf.executable_ranges():
        for pc in range(start, (end & ~3) - 4, 4):
            word = elf.word(pc)
            if word >> 26 != 3:
                continue
            dest = ((pc + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)
            if dest != dispatcher:
                continue
            value = direct_small_constant(elf.word(pc + 4), 4)
            if value is None:
                for back in range(1, 13):
                    candidate = elf.word(pc - back * 4)
                    value = direct_small_constant(candidate, 4)
                    if value is not None:
                        break
                    if candidate >> 26 == 3:
                        break
            if value == prop:
                matches.append(pc)
    for pc in matches:
        print(f"\n# property {prop} xref at 0x{pc:X}")
        dump(elf, max(pc - context * 4, 0), pc + (context + 2) * 4)
    print(f"\n# {len(matches)} direct property {prop} calls through 0x{dispatcher:X}")


def parse_int(value: str) -> int:
    return int(value, 0)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("elf", type=Path)
    sub = parser.add_subparsers(dest="command", required=True)
    p_dump = sub.add_parser("dump")
    p_dump.add_argument("start", type=parse_int)
    p_dump.add_argument("end", type=parse_int)
    p_jal = sub.add_parser("jal-xrefs")
    p_jal.add_argument("target", type=parse_int)
    p_jal.add_argument("--context", type=int, default=8)
    p_table = sub.add_parser("table")
    p_table.add_argument("base", type=parse_int)
    p_table.add_argument("count", type=parse_int)
    p_word = sub.add_parser("word-xrefs")
    p_word.add_argument("value", type=parse_int)
    p_mem = sub.add_parser("mem-imm-xrefs")
    p_mem.add_argument("immediate", type=parse_int)
    p_mem.add_argument("--context", type=int, default=8)
    p_abs = sub.add_parser("abs-xrefs")
    p_abs.add_argument("address", type=parse_int)
    p_abs.add_argument("--context", type=int, default=8)
    p_cstr = sub.add_parser("cstr")
    p_cstr.add_argument("address", type=parse_int)
    p_cstr.add_argument("--limit", type=int, default=512)
    p_u16 = sub.add_parser("u16str")
    p_u16.add_argument("address", type=parse_int)
    p_u16.add_argument("--limit", type=int, default=512)
    p_imm = sub.add_parser("imm-xrefs")
    p_imm.add_argument("immediate", type=parse_int)
    p_imm.add_argument("--context", type=int, default=8)
    p_prop = sub.add_parser("property-xrefs")
    p_prop.add_argument("dispatcher", type=parse_int)
    p_prop.add_argument("property", type=parse_int)
    p_prop.add_argument("--context", type=int, default=8)
    args = parser.parse_args()
    elf = Elf32(args.elf)
    if args.command == "dump":
        dump(elf, args.start, args.end)
    elif args.command == "jal-xrefs":
        jal_xrefs(elf, args.target, args.context)
    elif args.command == "table":
        table(elf, args.base, args.count)
    elif args.command == "word-xrefs":
        word_xrefs(elf, args.value)
    elif args.command == "mem-imm-xrefs":
        mem_imm_xrefs(elf, args.immediate, args.context)
    elif args.command == "abs-xrefs":
        abs_xrefs(elf, args.address, args.context)
    elif args.command == "cstr":
        cstring(elf, args.address, args.limit)
    elif args.command == "u16str":
        utf16_string(elf, args.address, args.limit)
    elif args.command == "imm-xrefs":
        imm_xrefs(elf, args.immediate, args.context)
    elif args.command == "property-xrefs":
        property_xrefs(elf, args.dispatcher, args.property, args.context)


if __name__ == "__main__":
    main()
