#!/usr/bin/env python3
"""Build a passive producer/playback/contact bridge, NOT an autoscroll fix.

No installer, setter, view resolution, extra query or retained object access.
Hot hooks copy borrowed inputs into non-reused private BSS records. Timer10
calls stock once and exports published records to inherited FD9. An appended
RX segment is an offline-verified layout, not a hardware-validated loader.
"""

import argparse
import hashlib
import struct
from pathlib import Path

import build_folderfollow_saved_path_rebuild as b
from build_folderfollow_fill_diag import HOOKS as FILL_HOOKS
from reveal_bridge_elf import plan_layout, install_layout


BASE = 0x400000
MEMCPY = 0xA5B440
WRITE = 0xA5B4A0
RECORD, HEADER, CAPACITY = 0x250, 0x40, 1024
MEMORY_BYTES = HEADER + RECORD * CAPACITY
EVENT_MAGIC = int.from_bytes(b'RBRG', 'little')
STATUS_MAGIC = int.from_bytes(b'RBST', 'little')
FRAME = 0x80
VOLATILE = (1, 2, 3, *range(4, 16), 24, 25, 31)
SAVE = {r: 0x20 + i * 4 for i, r in enumerate(VOLATILE)}
HI, LO = 0x68, 0x6C
HOOKS = {
    **FILL_HOOKS,
    'play_set': (0x42AC0C, [0x0C296D10, 0x24060A88]),
    'play_fast': (0x42CBDC, [0x0C296D10, 0x24060A88]),
    'play_general': (0x42CD5C, [0x0C296D10, 0x24060A88]),
    'touch': (0x8B4CC0, [0x1080007C, 0]),
    'close': (0x493AC0, [0x27BDFB48, 0xAFB10494]),
    'reset': (0x491240, [0x27BDFFB8, 0xAFBF0044]),
    'refresh': (0x499CB4, [0x8E360010, 0x8E02004C]),
}
LINKED = {'row', 'terminal', 'play_set', 'play_fast', 'play_general'}


class Asm:
    """Small base-aware assembler; no mutation of legacy assembler globals."""
    def __init__(self, base):
        self.base, self.w, self.labels, self.fix = base, [], {}, []

    def e(self, *words):
        self.w.extend(words)

    def label(self, name):
        if name in self.labels:
            raise ValueError('duplicate label')
        self.labels[name] = self.base + len(self.w) * 4

    def branch(self, op, rs, rt, name):
        self.fix.append((len(self.w), 'branch', name, op, rs, rt))
        self.e(0, 0)

    def jump(self, target, link=False, delay=0):
        if isinstance(target, str):
            self.fix.append((len(self.w), 'jump', target, 3 if link else 2, 0, 0))
            self.e(0, delay)
        else:
            self.e(b.j_type(3 if link else 2, target), delay)

    def absolute(self, r, value):
        self.e(b.lui(r, value >> 16), b.ori(r, r, value & 0xFFFF))

    def finish(self):
        for i, kind, name, op, rs, rt in self.fix:
            target = self.labels[name]
            if kind == 'branch':
                delta = (target - (self.base + i * 4 + 4)) // 4
                if not -32768 <= delta <= 32767:
                    raise ValueError('branch range')
                self.w[i] = b.i_type(op, rs, rt, delta)
            else:
                self.w[i] = b.j_type(op, target)
        return struct.pack('<%dI' % len(self.w), *self.w)


def assemble(buffer, code_base):
    a = Asm(code_base)

    def save():
        a.e(b.addiu(29, 29, -FRAME))
        for r, off in SAVE.items():
            a.e(b.sw(r, off, 29))
        a.e(b.r_type(0, 0, 8, 0x10), b.sw(8, HI, 29),
            b.r_type(0, 0, 8, 0x12), b.sw(8, LO, 29))

    def restore(pop=True):
        a.e(b.lw(8, HI, 29), b.r_type(8, 0, 0, 0x11),
            b.lw(8, LO, 29), b.r_type(8, 0, 0, 0x13))
        for r, off in SAVE.items():
            a.e(b.lw(r, off, 29))
        if pop:
            a.e(b.addiu(29, 29, FRAME))

    def reserve(event):
        a.e(b.addiu(4, 0, event))
        a.jump('reserve', True)

    def publish():
        a.e(0x0000000F)
        a.absolute(8, EVENT_MAGIC)
        a.e(b.sw(8, 0, 2))

    def field(src, src_off, out_off):
        a.e(b.lw(8, src_off, src), b.sw(8, out_off, 2))

    # Keep legacy producer hook ordering, notably append exactly once and
    # a1 computed in the ORIGINAL call delay slot before our temporary frame.
    for kind, event in (('begin', 1), ('row', 2), ('terminal', 3), ('end', 4)):
        a.label(kind)
        if kind == 'row':
            a.e(b.addiu(29, 29, -0x20), b.sw(31, 0x1C, 29),
                b.r_type(25, 0, 31, 9), 0,
                b.lw(31, 0x1C, 29), b.addiu(29, 29, 0x20))
        save()
        a.e(b.addiu(4, 0, event), b.addiu(5, 29, FRAME), b.lw(6, SAVE[2], 29))
        a.jump('fill_record', True)
        restore()
        if kind == 'terminal':
            a.jump(0x5C31C0)
        else:
            if kind != 'row':
                a.e(*HOOKS[kind][1])
            a.jump(HOOKS[kind][0] + 8)

    # All three memcpy call sites share one wrapper. Record source only BEFORE
    # memcpy; completion references that record without rereading its source.
    a.label('playback')
    save()
    reserve(5)
    a.e(b.sw(3, 0x18, 29))  # Sequence, outside callee O32 home area.
    a.branch(4, 2, 0, 'playback_original')
    a.e(b.addiu(8, 29, FRAME), b.sw(8, 16, 2))
    field(29, SAVE[31], 44)
    field(29, SAVE[6], 40)
    a.e(b.lw(5, SAVE[5], 29))
    a.branch(4, 5, 0, 'playback_unreadable')
    a.e(b.i_type(12, 5, 8, 3))
    a.branch(5, 8, 0, 'playback_unreadable')
    a.e(b.lw(8, SAVE[6], 29), b.addiu(9, 0, 0xA88))
    a.branch(5, 8, 9, 'playback_unreadable')
    field(5, 0x424, 48)
    a.e(b.addiu(5, 5, 4))
    a.jump('copy_publish', True)
    a.jump('playback_original')
    a.label('playback_unreadable')
    a.e(b.addiu(8, 0, 1), b.sw(8, 52, 2))
    publish()
    a.label('playback_original')
    restore(False)
    a.jump(MEMCPY, True)
    # Preserve the actual memcpy RESULT state, not the earlier input state.
    save()
    reserve(6)
    a.branch(4, 2, 0, 'playback_return')
    a.e(b.addiu(8, 29, FRAME * 2), b.sw(8, 16, 2))
    field(29, FRAME + 0x18, 20)
    field(29, FRAME + SAVE[31], 44)
    field(29, SAVE[2], 40)
    publish()
    a.label('playback_return')
    restore()
    a.e(b.lw(31, SAVE[31], 29), b.addiu(29, 29, FRAME),
        b.r_type(31, 0, 0, 8), 0)

    # Recognized raw contact only. Null G must not cause a packet read; raw
    # type1 can be an eight-byte key packet and must not read touch fields.
    a.label('touch')
    save()
    a.branch(4, 4, 0, 'touch_original')
    a.branch(4, 5, 0, 'touch_original')
    a.e(b.lw(8, 0, 5), b.addiu(8, 8, -2), b.i_type(11, 8, 9, 2))
    a.branch(4, 9, 0, 'touch_original')
    reserve(7)
    a.branch(4, 2, 0, 'touch_original')
    a.e(b.addiu(8, 29, FRAME), b.sw(8, 16, 2))
    field(29, SAVE[4], 20)
    field(29, SAVE[7], 24)
    field(29, SAVE[31], 44)
    a.e(b.lw(9, SAVE[5], 29))
    field(9, 0, 28)
    field(9, 8, 36)
    field(9, 12, 40)
    a.e(b.lw(9, SAVE[4], 29))
    field(9, 0, 32)
    publish()
    a.label('touch_original')
    restore()
    # Re-encode the displaced conditional branch at its new address.
    a.branch(4, 4, 0, 'touch_null')
    a.jump(0x8B4CC8)
    a.label('touch_null')
    a.jump(0x8B4EB4)

    for kind, event in (('close', 8), ('reset', 9)):
        a.label(kind)
        save()
        reserve(event)
        a.branch(4, 2, 0, kind + '_original')
        a.e(b.addiu(8, 29, FRAME), b.sw(8, 16, 2))
        field(29, SAVE[31], 44)
        if kind == 'reset':
            field(29, SAVE[4], 20)
            field(29, SAVE[5], 24)
        else:
            field(29, SAVE[4], 24)
        publish()
        a.label(kind + '_original')
        restore()
        a.e(*HOOKS[kind][1])
        a.jump(HOOKS[kind][0] + 8)

    # Borrowed V/C from stock's CURRENT refresh invocation, not a timer lookup.
    # V64 is a numeric token; no list/cache/worker pointer is dereferenced.
    a.label('refresh')
    save()
    a.e(b.lw(8, 0x40, 16), b.addiu(9, 0, 2))
    a.branch(5, 8, 9, 'refresh_original')
    reserve(10)
    a.branch(4, 2, 0, 'refresh_original')
    a.e(b.sw(16, 16, 2), b.sw(17, 20, 2))
    for reg, off, out in ((16, 0x64, 24), (16, 0x40, 28),
                          (17, 0x18, 32), (16, 0x4C, 36),
                          (17, 0x10, 40), (29, FRAME + 0xED4, 44)):
        field(reg, off, out)
    a.e(b.addiu(5, 16, 0x3DD8))
    a.jump('copy_publish', True)
    a.label('refresh_original')
    restore()
    a.e(*HOOKS['refresh'][1])
    a.jump(0x499CBC)

    # Producer helper uses a1=original frame, a2=original result, callee-saved
    # stock state. reserve preserves a1/a2/a3. a0 is event number.
    a.label('fill_record')
    a.branch(5, 23, 0, 'record_return')
    a.branch(4, 22, 0, 'record_return')
    a.e(b.lw(8, 0xACC, 5))
    a.absolute(9, 0x6F8BF4)
    a.branch(4, 8, 9, 'fill_scope_ok')
    a.absolute(9, 0x6F8E0C)
    a.branch(5, 8, 9, 'record_return')
    a.label('fill_scope_ok')
    a.e(b.sw(31, 0x14, 29))
    a.jump('reserve', True)
    a.e(b.lw(31, 0x14, 29))
    a.branch(4, 2, 0, 'record_return')
    a.e(b.sw(5, 16, 2), b.sw(16, 20, 2), b.sw(22, 24, 2),
        b.sw(23, 28, 2), b.sw(17, 36, 2), b.sw(6, 40, 2))
    field(5, 0xAD8, 32)
    field(5, 0xACC, 44)
    field(22, 12, 56)
    a.e(b.addiu(8, 0, 1))
    a.branch(4, 4, 8, 'fill_folder')
    a.e(b.addiu(8, 0, 2))
    a.branch(5, 4, 8, 'publish_return')
    field(5, 0x444, 48)
    a.e(b.addiu(5, 5, 0x24))
    a.jump('copy_publish')
    a.label('fill_folder')
    a.e(b.sw(17, 40, 2), b.sw(0, 36, 2), b.lw(5, 0xAE4, 5))
    a.jump('copy_publish')

    # Never wrap/reuse slots. Reservation order is NOT a global stock-mutation
    # linearization order. Eight LL/SC attempts, then sticky loss reporting.
    a.label('reserve')
    a.absolute(8, buffer)
    a.e(b.addiu(9, 0, 8))
    a.label('reserve_retry')
    a.e(b.i_type(0x30, 8, 10, 0), b.i_type(11, 10, 11, CAPACITY))
    a.branch(4, 11, 0, 'reserve_overflow')
    a.e(b.addiu(11, 10, 1), b.i_type(0x38, 8, 11, 0))
    a.branch(5, 11, 0, 'reserved')
    a.e(b.addiu(9, 9, -1))
    a.branch(5, 9, 0, 'reserve_retry')
    a.e(b.addiu(9, 0, 1), b.sw(9, 12, 8))
    a.jump('reserve_failed')
    a.label('reserve_overflow')
    a.e(b.addiu(9, 0, 1), b.sw(9, 8, 8))
    a.label('reserve_failed')
    a.e(b.move(2, 0), b.addiu(3, 0, -1), b.r_type(31, 0, 0, 8), 0)
    a.label('reserved')
    for dst, amount in ((11, 9), (12, 6), (13, 4)):
        a.e((10 << 16) | (dst << 11) | (amount << 6))
    a.e(b.r_type(11, 12, 11, 0x21), b.r_type(11, 13, 11, 0x21),
        b.r_type(8, 11, 2, 0x21), b.addiu(2, 2, HEADER),
        b.addiu(9, 0, 1), b.sw(9, 4, 2), b.sw(4, 8, 2),
        b.sw(10, 12, 2), b.move(3, 10), b.r_type(31, 0, 0, 8), 0)

    a.label('copy_publish')
    a.branch(4, 5, 0, 'publish_return')
    a.e(b.addiu(10, 2, 0x40), b.addiu(11, 0, 259))
    a.label('copy_loop')
    a.e(b.lhu(8, 0, 5))
    a.branch(4, 8, 0, 'publish_return')
    a.branch(4, 11, 0, 'copy_truncated')
    a.e(b.sh(8, 0, 10), b.addiu(5, 5, 2), b.addiu(10, 10, 2),
        b.addiu(11, 11, -1))
    a.jump('copy_loop')
    a.label('copy_truncated')
    a.e(b.addiu(8, 0, 1), b.sw(8, 52, 2))
    a.label('publish_return')
    publish()
    a.label('record_return')
    a.e(b.r_type(31, 0, 0, 8), 0)

    # UI timer reads only permanent private BSS, never a saved stock pointer.
    a.label('timer')
    a.e(b.addiu(29, 29, -0x60), b.sw(31, 0x5C, 29), b.sw(16, 0x58, 29),
        b.sw(17, 0x54, 29), b.sw(18, 0x50, 29), b.sw(19, 0x4C, 29))
    a.jump(b.ORIGINAL_CALLBACK, True)
    a.e(b.move(19, 2))
    a.absolute(16, buffer)
    a.e(b.lw(8, 16, 16))
    a.branch(5, 8, 0, 'timer_done')
    a.absolute(8, STATUS_MAGIC)
    a.e(b.sw(8, 0x20, 29), b.addiu(8, 0, 1), b.sw(8, 0x24, 29))
    for src, dst in ((0, 0x28), (4, 0x2C), (8, 0x30), (12, 0x34), (16, 0x38)):
        a.e(b.lw(8, src, 16), b.sw(8, dst, 29))
    a.e(b.addiu(8, 0, CAPACITY), b.sw(8, 0x3C, 29), b.addiu(4, 0, 9),
        b.addiu(5, 29, 0x20), b.addiu(6, 0, 32))
    a.jump(WRITE, True)
    a.e(b.addiu(8, 0, 32))
    a.branch(5, 2, 8, 'io_error')
    a.e(b.addiu(18, 0, 8))
    a.label('drain_next')
    a.e(b.lw(17, 4, 16), b.lw(8, 0, 16))
    a.branch(4, 17, 8, 'timer_done')
    for dst, amount in ((8, 9), (9, 6), (10, 4)):
        a.e((17 << 16) | (dst << 11) | (amount << 6))
    a.e(b.r_type(8, 9, 8, 0x21), b.r_type(8, 10, 8, 0x21),
        b.r_type(16, 8, 5, 0x21), b.addiu(5, 5, HEADER), b.lw(8, 0, 5))
    a.absolute(9, EVENT_MAGIC)
    a.branch(5, 8, 9, 'timer_done')
    a.e(0x0000000F, b.addiu(4, 0, 9), b.addiu(6, 0, RECORD))
    a.jump(WRITE, True)
    a.e(b.addiu(8, 0, RECORD))
    a.branch(5, 2, 8, 'io_error')
    a.e(b.addiu(17, 17, 1), b.sw(17, 4, 16), b.addiu(18, 18, -1))
    a.branch(5, 18, 0, 'drain_next')
    a.jump('timer_done')
    a.label('io_error')
    a.e(b.addiu(8, 0, 1), b.sw(8, 16, 16))
    a.label('timer_done')
    a.e(b.move(2, 19), b.lw(19, 0x4C, 29), b.lw(18, 0x50, 29),
        b.lw(17, 0x54, 29), b.lw(16, 0x58, 29), b.lw(31, 0x5C, 29),
        b.r_type(31, 0, 0, 8), b.addiu(29, 29, 0x60))
    return a.finish(), a.labels


def normalize_source(source):
    try:
        return b.normalize_source(source)
    except SystemExit as error:
        raise ValueError(str(error)) from error


def build(source):
    golden, input_hash = normalize_source(source)
    layout = plan_layout(golden, MEMORY_BYTES)
    code, labels = assemble(layout['buffer'], layout['code_base'])
    image, meta = install_layout(golden, code, MEMORY_BYTES)
    out = bytearray(image)
    for kind, (pc, expected) in HOOKS.items():
        if tuple(struct.unpack_from('<2I', golden, pc - BASE)) != tuple(expected):
            raise ValueError('unexpected hook: ' + kind)
        label = 'playback' if kind.startswith('play_') else kind
        op = 3 if kind in LINKED else 2
        delay = expected[1] if kind in LINKED else 0
        struct.pack_into('<2I', out, pc - BASE, b.j_type(op, labels[label]), delay)
    target = labels['timer']
    struct.pack_into('<I', out, b.CALLBACK_HI_OFFSET, b.lui(6, (target + 0x8000) >> 16))
    struct.pack_into('<I', out, b.CALLBACK_LO_OFFSET, b.addiu(6, 6, target & 0xFFFF))
    return bytes(out), dict(meta, labels=labels, input_sha256=input_hash,
                           memory_bytes=MEMORY_BYTES, hardware='UNTESTED',
                           autoscroll=False, capture_only=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('source', type=Path)
    p.add_argument('output', type=Path)
    args = p.parse_args()
    result, meta = build(args.source.read_bytes())
    # Binary generation is an explicit build operation, not source editing.
    with args.output.open('xb') as stream:
        stream.write(result)
    print('sha256=' + hashlib.sha256(result).hexdigest())
    print(meta)
    print('CAPTURE ONLY; no autoscroll; new RX loader layout hardware UNTESTED; no deployment')


if __name__ == '__main__':
    main()
