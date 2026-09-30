#!/usr/bin/env python3
"""FILL v1: bounded memory-only producer probes and UI-timer FD9 drain."""
import argparse
import hashlib
import struct
from pathlib import Path
import build_folderfollow_view_depth_diag as b

BASE = 0x400000
CODE = b.CAVE_VADDR
RECORD = 0x250
CAPACITY = 512
HEADER = 0x40
def shift(dst, src, amount): return (src << 16) | (dst << 11) | (amount << 6)
SP, RA, Z = 29, 31, 0
VOLATILE = [1, 2, 3, *range(4, 16), 24, 25, 31]
FRAME = 0x80
SAVE = {r: 0x20 + i * 4 for i, r in enumerate(VOLATILE)}
HOOKS = {
    'begin': (0x6ED624, [0x2652B328, 0x2694C540]),
    'row': (0x6ED6E8, [0x0320F809, 0x27A50020]),
    'terminal': (0x6ED704, [0x0C170C70, 0x02002021]),
    'end': (0x6ED7D4, [0x8FBE0AC8, 0x8FB70AC4]),
}


class Asm:
    def __init__(self): self.w, self.labels, self.fix = [], {}, []
    def e(self, *w): self.w.extend(w)
    def label(self, name): self.labels[name] = CODE + len(self.w) * 4
    def branch(self, op, rs, rt, label):
        self.fix.append((len(self.w), 'branch', label, op, rs, rt)); self.e(0, 0)
    def jump(self, label, link=False, delay=0):
        if isinstance(label, str):
            self.fix.append((len(self.w), 'jump', label, 3 if link else 2, 0, 0)); self.e(0, delay)
        else: self.e(((3 if link else 2) << 26) | (label >> 2), delay)
    def abs(self, r, value): self.e(b.lui(r, value >> 16), b.ori(r, r, value & 65535))
    def finish(self):
        for i, kind, name, op, rs, rt in self.fix:
            target = self.labels[name]
            self.w[i] = ((op << 26) | (target >> 2)) if kind == 'jump' else b.i_type(op, rs, rt, (target - (CODE + i*4 + 4)) // 4)
        return struct.pack('<%dI' % len(self.w), *self.w)


def layout(source):
    phoff = struct.unpack_from('<I', source, 0x1C)[0]
    stride, count = struct.unpack_from('<HH', source, 0x2A)
    loads = []
    for i in range(count):
        off = phoff + i * stride
        p = struct.unpack_from('<8I', source, off)
        if p[0] == 1: loads.append((off, p))
    off, p = max(loads, key=lambda x: x[1][2] + x[1][5])
    if p[6] != 6: raise ValueError('last load is not RW')
    buffer = (p[2] + p[5] + 4095) & ~4095
    end = buffer + HEADER + RECORD * CAPACITY
    return off + 20, end - p[2], buffer


def assemble(buffer):
    a = Asm()
    def save():
        a.e(b.addiu(SP, SP, -FRAME))
        for r, off in SAVE.items(): a.e(b.sw(r, off, SP))
    def restore():
        for r, off in SAVE.items(): a.e(b.lw(r, off, SP))
        a.e(b.addiu(SP, SP, FRAME))
    for kind, event in [('begin', 1), ('row', 2), ('terminal', 3), ('end', 4)]:
        a.label(kind)
        if kind == 'row':
            # The original indirect append is called exactly once, with its two
            # arguments unchanged and a separate outgoing argument area.
            a.e(b.addiu(SP, SP, -0x20), b.sw(RA, 0x1C, SP), b.r_type(25, 0, RA, 9), 0,
                b.lw(RA, 0x1C, SP), b.addiu(SP, SP, 0x20))
        save()
        a.e(b.addiu(8, SP, FRAME), b.addiu(4, Z, event))
        a.jump('record', True)
        restore()
        if kind == 'begin':
            a.e(*HOOKS[kind][1]); a.jump(0x6ED62C)
        elif kind == 'row': a.jump(0x6ED6F0)
        elif kind == 'terminal': a.jump(0x5C31C0)  # original a0 delay is at hook
        else:
            a.e(*HOOKS[kind][1]); a.jump(0x6ED7DC)

    # Recorder uses only spilled volatile registers. No external call, no HI/LO.
    a.label('record')
    a.branch(5, 23, Z, 'return')  # mode zero only
    a.e(b.lw(9, 0xACC, 8)); a.abs(10, 0x6F8BF4)
    a.branch(4, 9, 10, 'scope_ok'); a.abs(10, 0x6F8E0C)
    a.branch(5, 9, 10, 'return')
    a.label('scope_ok')
    a.branch(4, 22, Z, 'return')
    a.abs(10, buffer); a.e(b.addiu(11, Z, 8))
    a.label('reserve')
    a.e(b.i_type(0x30, 10, 12, 0), b.i_type(0x0B, 12, 13, CAPACITY))
    a.branch(4, 13, Z, 'overflow')
    a.e(b.addiu(13, 12, 1), b.i_type(0x38, 10, 13, 0))
    a.branch(5, 13, Z, 'reserved')
    a.e(b.addiu(11, 11, -1)); a.branch(5, 11, Z, 'reserve')
    a.e(b.addiu(13, Z, 1), b.sw(13, 12, 10)); a.jump('return')
    a.label('overflow'); a.e(b.addiu(13, Z, 1), b.sw(13, 8, 10)); a.jump('return')
    a.label('reserved')
    # record = buffer+HEADER+seq*(512+64+16)
    a.e(shift(13, 12, 9), shift(14, 12, 6), b.r_type(13, 14, 13, 0x21),
        shift(14, 12, 4), b.r_type(13, 14, 13, 0x21),
        b.r_type(10, 13, 10, 0x21), b.addiu(10, 10, HEADER),
        b.addiu(13, Z, 1), b.sw(13, 4, 10), b.sw(4, 8, 10), b.sw(12, 12, 10),
        b.sw(8, 16, 10), b.sw(16, 20, 10), b.sw(22, 24, 10), b.sw(23, 28, 10),
        b.lw(13, 0xAD8, 8), b.sw(13, 32, 10), b.sw(17, 36, 10),
        b.sw(2, 40, 10), b.sw(9, 44, 10), b.lw(13, 12, 22), b.sw(13, 56, 10))
    a.e(b.addiu(13, Z, 1)); a.branch(4, 4, 13, 'folder')
    a.e(b.addiu(13, Z, 2)); a.branch(5, 4, 13, 'publish')
    a.e(b.lw(13, 0x444, 8), b.sw(13, 48, 10), b.addiu(14, 8, 0x24)); a.jump('copy')
    a.label('folder')
    a.e(b.sw(17, 40, 10), b.sw(Z, 36, 10), b.lw(14, 0xAE4, 8))
    a.branch(4, 14, Z, 'publish')
    a.label('copy')
    a.e(b.addiu(15, 10, 0x40), b.addiu(24, Z, 259))
    a.label('copy_loop')
    a.e(b.i_type(0x25, 14, 13, 0)); a.branch(4, 13, Z, 'publish')
    a.branch(4, 24, Z, 'truncated')
    a.e(b.i_type(0x29, 15, 13, 0), b.addiu(15, 15, 2), b.addiu(14, 14, 2), b.addiu(24, 24, -1)); a.jump('copy_loop')
    a.label('truncated'); a.e(b.addiu(13, Z, 1), b.sw(13, 52, 10))
    a.label('publish')
    a.e(0x0000000F); a.abs(13, 0x4C4C4946); a.e(b.sw(13, 0, 10))
    a.label('return'); a.e(b.r_type(RA, Z, Z, 8), 0)

    # One immutable record per UI callback. Short/error write disables draining.
    a.label('timer')
    a.e(b.addiu(SP, SP, -0x60), b.sw(RA, 0x5C, SP), b.sw(16, 0x58, SP),
        b.sw(17, 0x54, SP), b.sw(18, 0x50, SP))
    a.jump(b.ORIGINAL_CALLBACK, True); a.e(b.move(18, 2)); a.abs(16, buffer)
    a.e(b.lw(8, 16, 16)); a.branch(5, 8, Z, 'timer_done')
    a.abs(8, 0x53545346); a.e(b.sw(8, 0x20, SP), b.addiu(8, Z, 1), b.sw(8, 0x24, SP))
    for src, dst in [(0,0x28),(4,0x2C),(8,0x30),(12,0x34),(16,0x38)]:
        a.e(b.lw(8, src, 16), b.sw(8, dst, SP))
    a.e(b.addiu(8, Z, CAPACITY), b.sw(8, 0x3C, SP), b.addiu(4, Z, 9),
        b.addiu(5, SP, 0x20), b.addiu(6, Z, 32))
    a.jump(b.WRITE_PLT, True); a.e(b.addiu(8, Z, 32)); a.branch(5, 2, 8, 'io_error')
    a.e(b.lw(17, 4, 16), b.lw(8, 0, 16)); a.branch(4, 17, 8, 'timer_done')
    a.e(shift(8,17,9), shift(9,17,6), b.r_type(8,9,8,0x21),
        shift(9,17,4), b.r_type(8,9,8,0x21), b.r_type(16,8,5,0x21),
        b.addiu(5,5,HEADER), b.lw(8,0,5))
    a.abs(9,0x4C4C4946); a.branch(5,8,9,'timer_done'); a.e(0x0000000F)
    a.e(b.addiu(4,Z,9),b.addiu(6,Z,RECORD)); a.jump(b.WRITE_PLT,True)
    a.e(b.addiu(8,Z,RECORD)); a.branch(5,2,8,'io_error')
    a.e(b.addiu(17,17,1),b.sw(17,4,16)); a.jump('timer_done')
    a.label('io_error'); a.e(b.addiu(8,Z,1),b.sw(8,16,16))
    a.label('timer_done')
    a.e(b.move(2,18),b.lw(18,0x50,SP),b.lw(17,0x54,SP),b.lw(16,0x58,SP),
        b.lw(RA,0x5C,SP),b.r_type(RA,Z,Z,8),b.addiu(SP,SP,0x60))
    code = a.finish()
    if len(code) > b.CAVE_CAPACITY: raise ValueError(f'cave overflow: {len(code):#x}')
    return code, a.labels


def build(source):
    golden, _ = b.normalize_source(source)
    sizeoff, memsize, buffer = layout(golden)
    code, labels = assemble(buffer)
    out = bytearray(golden)
    if any(out[b.CAVE_OFFSET:b.CAVE_OFFSET+b.CAVE_CAPACITY]): raise ValueError('occupied cave')
    struct.pack_into('<I', out, sizeoff, memsize)
    for kind, (pc, expected) in HOOKS.items():
        if list(struct.unpack_from('<2I', out, pc-BASE)) != expected: raise ValueError(f'bad hook {kind}')
        link = kind in ('row','terminal')
        delay = expected[1] if link else 0
        struct.pack_into('<2I', out, pc-BASE, ((3 if link else 2)<<26)|(labels[kind]>>2),delay)
    timer = labels['timer']
    struct.pack_into('<I',out,b.CALLBACK_HI_OFFSET,b.lui(6,(timer+0x8000)>>16))
    struct.pack_into('<I',out,b.CALLBACK_LO_OFFSET,b.addiu(6,6,timer&65535))
    out[b.CAVE_OFFSET:b.CAVE_OFFSET+len(code)] = code
    return bytes(out), {'buffer':buffer,'memory_bytes':HEADER+RECORD*CAPACITY,'code_bytes':len(code),
                        'labels':labels,'memsize_offset':sizeoff}


def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('source',type=Path); p.add_argument('output',type=Path)
    args=p.parse_args(); output,meta=build(args.source.read_bytes())
    args.output.parent.mkdir(parents=True,exist_ok=True); args.output.write_bytes(output)
    print('sha256='+hashlib.sha256(output).hexdigest()); print(meta)
    print('hardware=UNTESTED; stock autoscroll/navigation unchanged; no deployment')


if __name__=='__main__': main()
