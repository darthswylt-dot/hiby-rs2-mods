#!/usr/bin/env python3
"""Passive active-explorer/cache/viewport telemetry; never deploy unverified."""
import argparse
import hashlib
import struct
from pathlib import Path
import build_folderfollow_view_depth_diag as b

STRNCMP = 0xA5BA40
SIZE = 0x540
FRAME = 0x600
# Historical wire name: cache_count reads P+0x1E0, the total folder count
# published BEFORE fill, not populated cache rows or a completion flag.
# Keep the v1 field name/layout unchanged so existing SCRL/MOVE logs decode.
FIELDS = {
    'controller': 0x20, 'view': 0x24, 'internal': 0x28, 'viewport': 0x2C,
    'cache_owner': 0x30, 'explorer_valid': 0x34, 'type': 0x38, 'pitch': 0x3C,
    'scroll_y': 0x40, 'height': 0x44, 'content_height': 0x48,
    'cache_capacity': 0x4C, 'cache_start': 0x50, 'cache_count': 0x54,
    'sort': 0x58, 'cue_before': 0x5C, 'working_index': 0x60,
    'database': 0x64, 'return': 0x68, 'cue_after': 0x6C,
}
STRINGS = {'folder': (0x80, 0x208, 'utf-16le'),
           'playback': (0x288, 0x208, 'utf-16le'),
           'lookup_key': (0x490, 0x40, 'ascii'),
           'name': (0x4D0, 0x40, 'ascii')}


def build_wrapper():
    w, labels, fixups = [], {}, []
    def emit(*words): w.extend(words)
    def branch(reg, label):
        fixups.append((len(w), reg, label)); emit(0, 0)
    def absolute(reg, address):
        emit(b.lui(reg, (address + 0x8000) >> 16), b.addiu(reg, reg, address & 65535))
    def field(base, offset, name):
        emit(b.lw(b.V0, offset, base), b.sw(b.V0, FIELDS[name], b.S1))
    def call(target): emit(b.jal(target), 0)
    saved = [(b.RA, 0x5FC), (b.S0, 0x5F8), (b.S1, 0x5F4),
             (b.S2, 0x5F0), (b.S3, 0x5EC), (b.S4, 0x5E8), (b.S6, 0x5E4)]
    emit(b.addiu(b.SP, b.SP, -FRAME))
    for reg, off in saved: emit(b.sw(reg, off, b.SP))
    emit(b.sw(b.A1, 0x5E0, b.SP))
    call(b.ORIGINAL_CALLBACK)
    emit(b.move(b.S6, b.V0), b.addiu(b.S1, b.SP, 0x40),
         b.move(b.A0, b.S1), b.move(b.A1, b.ZERO), b.addiu(b.A2, b.ZERO, SIZE))
    call(b.MEMSET_PLT)
    emit(b.lui(b.V0, 0x4C52), b.ori(b.V0, b.V0, 0x4353), b.sw(b.V0, 0, b.S1),
         b.addiu(b.V0, b.ZERO, 1), b.sw(b.V0, 4, b.S1),
         b.addiu(b.V0, b.ZERO, SIZE), b.sw(b.V0, 8, b.S1),
         b.sw(b.S6, FIELDS['return'], b.S1),
         b.addiu(b.A0, b.ZERO, 1), b.addiu(b.A1, b.S1, 0x10))
    call(b.CLOCK_GETTIME_PLT)
    emit(b.lw(b.S0, 0x5E0, b.SP)); branch(b.S0, 'playback')
    emit(b.lw(b.S0, 0x3C, b.S0), b.sw(b.S0, 0x20, b.S1)); branch(b.S0, 'playback')
    emit(b.sw(b.ZERO, 0x24, b.SP), b.move(b.A0, b.S0), b.addiu(b.A1, b.SP, 0x24))
    call(b.GET_CURRENT_VIEW)
    emit(b.lw(b.S2, 0x24, b.SP), b.sw(b.S2, 0x24, b.S1)); branch(b.S2, 'playback')
    emit(b.addiu(b.A0, b.S1, 0x4D0), b.move(b.A1, b.S2), b.addiu(b.A2, b.ZERO, 63))
    call(b.STRNCPY_PLT)
    emit(b.move(b.A0, b.S2)); absolute(b.A1, b.EXPLORER_VIEW_TYPE)
    emit(b.addiu(b.A2, b.ZERO, 20)); call(STRNCMP)
    # Nonzero comparison skips all explorer-only dereferences.
    fixups.append((len(w), b.V0, 'playback')); emit(0, 0)
    mismatch_index = len(w) - 2
    emit(b.addiu(b.V0, b.ZERO, 1), b.sw(b.V0, 0x34, b.S1))
    for off, name in ((0x40, 'type'), (0x4C, 'pitch')): field(b.S2, off, name)
    for pointer_offset, pointer_name, reads in (
        (0x78, 'internal', ((0x5A0, 'working_index'),)),
        (0xCC, 'viewport', ((0x18, 'scroll_y'), (0x10, 'height'), (0x20, 'content_height'))),
        (0x3B68, 'cache_owner', ((0x1D4, 'cache_capacity'), (0x1DC, 'cache_start'), (0x1E0, 'cache_count'))),
    ):
        emit(b.lw(b.S3, pointer_offset, b.S2), b.sw(b.S3, FIELDS[pointer_name], b.S1))
        branch(b.S3, pointer_name + '_done')
        for off, name in reads: field(b.S3, off, name)
        labels[pointer_name + '_done'] = len(w)
    emit(b.addiu(b.A0, b.S1, 0x490), b.addiu(b.A1, b.S2, 0x3824), b.addiu(b.A2, b.ZERO, 63))
    call(b.STRNCPY_PLT)
    emit(b.addiu(b.A0, b.S1, 0x80), b.addiu(b.A1, b.S2, 0x3DD8), b.addiu(b.A2, b.ZERO, 0x103))
    call(b.WIDE_COPY)
    labels['playback'] = len(w)
    absolute(b.S4, 0xADD468)
    field(b.S4, 0x424, 'cue_before')
    emit(b.addiu(b.A0, b.S1, 0x288), b.addiu(b.A1, b.S4, 4), b.addiu(b.A2, b.ZERO, 0x103))
    call(b.WIDE_COPY)
    field(b.S4, 0x424, 'cue_after')
    absolute(b.S3, 0xBAD7B0)
    emit(b.lw(b.S3, 0, b.S3), b.sw(b.S3, FIELDS['database'], b.S1)); branch(b.S3, 'write')
    field(b.S3, 0x538, 'sort')
    labels['write'] = len(w)
    emit(b.addiu(b.A0, b.ZERO, 9), b.move(b.A1, b.S1), b.addiu(b.A2, b.ZERO, SIZE))
    call(b.WRITE_PLT)
    emit(b.move(b.V1, b.S6))
    for reg, off in reversed(saved): emit(b.lw(reg, off, b.SP))
    emit(b.addiu(b.SP, b.SP, FRAME), b.r_type(b.RA, b.ZERO, b.ZERO, 8), b.move(b.V0, b.V1))
    for index, reg, target in fixups:
        w[index] = b.i_type(5 if index == mismatch_index else 4, reg, 0, labels[target] - index - 1)
    result = struct.pack('<%dI' % len(w), *w)
    if len(result) > b.CAVE_CAPACITY: raise ValueError('cave overflow')
    return result


def build(source):
    if len(source) != b.EXPECTED_SIZE: raise ValueError('unexpected ELF size')
    golden, _ = b.normalize_source(source)
    if any(golden[b.CAVE_OFFSET:b.CAVE_OFFSET + b.CAVE_CAPACITY]): raise ValueError('occupied cave')
    output = bytearray(golden)
    output[b.CALLBACK_HI_OFFSET:b.CALLBACK_HI_OFFSET + 4] = bytes.fromhex('9900063c')
    output[b.CALLBACK_LO_OFFSET:b.CALLBACK_LO_OFFSET + 4] = bytes.fromhex('4080c624')
    wrapper = build_wrapper()
    output[b.CAVE_OFFSET:b.CAVE_OFFSET + len(wrapper)] = wrapper
    return bytes(output)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('source', type=Path); p.add_argument('output', type=Path)
    args = p.parse_args()
    output = build(args.source.read_bytes())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(output)
    print('sha256=' + hashlib.sha256(output).hexdigest())
    print(f'wrapper_size={len(build_wrapper()):#x}; record_size={SIZE:#x}; hardware=untested')


if __name__ == '__main__': main()
