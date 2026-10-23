#!/usr/bin/env python3
"""Offline passive observation of two optional playback callback dispatches.

Observe CALL_INTENT after the original target/context loads and nonnull
branch, without rereading B+BA0/B98 or native payloads. Relocate the original
JALR/delay by restoring its exact target-entry state, including native RA,
then JR t9. The callback returns directly to its original continuation.
No completion, coherent playback identity, paint cause or UI permission.
"""
import argparse
import hashlib
import struct
from pathlib import Path

import build_reveal_renderer_transport_stage as previous
import reveal_playback_dispatch_mips as dispatch
from build_reveal_bridge_diag import Asm, BASE, SAVE, HI, LO, b
from reveal_bridge_elf import plan_layout, install_layout


NEW_HOOKS = {
    'playback_fast_dispatch': (0x42CC0C, (0x0320F809, 0x2685D468)),
    'playback_general_dispatch': (0x42D6A0, (0x0320F809, 0x2685D468)),
}
HOOKS = dict(previous.HOOKS, **NEW_HOOKS)
STRIDES, LINKED = previous.STRIDES, previous.LINKED
# New observers tail-dispatch indirectly, not to pc+8. Existing tails stay exact.
NATIVE_TAILS = previous.NATIVE_TAILS
INDIRECT_TAIL_LABELS = ('playback_fast_dispatch_jump', 'playback_general_dispatch_jump')
normalize_source = previous.normalize_source
FRAME, META = 0x90, 0x70
CAPACITY_NAMES = ('capacity', 'row-capacity', 'operation-capacity', 'scope-capacity',
                  'birth-capacity', 'transport-capacity', 'renderer-capacity',
                  'playback-dispatch-capacity')
MISSING_CONTRACTS = (*previous.MISSING_CONTRACTS,
                     'playback-dispatch-intent-is-not-callback-entry-or-completion',
                     'immutable-playback-notification-to-paint-cause-transport')


def assemble(buffer, journal, revision_buffer, operation_buffer, scope_buffer,
             birth_buffer, transport_buffer, renderer_transport_buffer,
             playback_dispatch_buffer, code_base, *, capacity=1024, row_capacity=1024,
             operation_capacity=1024, scope_capacity=1024, birth_capacity=1024,
             transport_capacity=1024, renderer_capacity=1024, playback_dispatch_capacity=1024):
    sizes = (previous.lineage.memory_bytes(capacity), previous.rows.memory_bytes(row_capacity),
             16, previous.operation.memory_bytes(operation_capacity),
             previous.scope.memory_bytes(scope_capacity), previous.birth.memory_bytes(birth_capacity),
             previous.transport.memory_bytes(transport_capacity),
             previous.renderer.memory_bytes(renderer_capacity),
             dispatch.memory_bytes(playback_dispatch_capacity))
    addresses = (buffer, journal, revision_buffer, operation_buffer, scope_buffer,
                 birth_buffer, transport_buffer, renderer_transport_buffer, playback_dispatch_buffer)
    regions = tuple(zip(addresses, sizes))
    for index, (start, size) in enumerate(regions):
        if type(start) is not int or start < 0 or start % 4 or start + size > 0x100000000:
            raise ValueError('playback dispatch regions must be aligned and nonwrapping')
        for other, length in regions[index + 1:]:
            if type(other) is not int or max(start, other) < min(start + size, other + length):
                raise ValueError('playback dispatch private regions must not overlap')
    original, labels = previous.assemble(
        *addresses[:-1], code_base, capacity=capacity, row_capacity=row_capacity,
        operation_capacity=operation_capacity, scope_capacity=scope_capacity,
        birth_capacity=birth_capacity, transport_capacity=transport_capacity,
        renderer_capacity=renderer_capacity)
    kernel, entries = dispatch.assemble(playback_dispatch_buffer, code_base + len(original),
                                         capacity=playback_dispatch_capacity)
    a = Asm(code_base + len(original) + len(kernel))

    def save():
        a.e(b.addiu(29, 29, -FRAME))
        for register, offset in SAVE.items():
            a.e(b.sw(register, offset, 29))
        a.e(b.r_type(0, 0, 8, 0x10), b.sw(8, HI, 29),
            b.r_type(0, 0, 8, 0x12), b.sw(8, LO, 29))

    def restore():
        a.e(b.lw(8, HI, 29), b.r_type(8, 0, 0, 0x11),
            b.lw(8, LO, 29), b.r_type(8, 0, 0, 0x13))
        for register, offset in SAVE.items():
            a.e(b.lw(register, offset, 29))
        a.e(b.addiu(29, 29, FRAME))

    for name, kind, player_register in (('playback_fast_dispatch', dispatch.FAST, 17),
                                         ('playback_general_dispatch', dispatch.GENERAL, 16)):
        site, pair = NEW_HOOKS[name]
        a.label(name)
        # Only a1/s4 occur in the native delay, not RA/t9. The original JALR
        # computes target=t9 and RA=site+8 before that delay. Establish exactly
        # this target-entry state BEFORE saving it for the private observer.
        a.e(pair[1])
        a.absolute(31, site + 8)
        save()
        a.e(b.addiu(8, 29, FRAME), b.sw(8, META, 29))
        for value, offset in ((site, 4), (site + 8, 8)):
            a.absolute(8, value)
            a.e(b.sw(8, META + offset, 29))
        for register, offset in ((25, 12), (4, 16), (5, 20)):
            a.e(b.lw(8, SAVE[register], 29), b.sw(8, META + offset, 29))
        a.e(b.sw(player_register, META + 24, 29), b.addiu(4, 0, kind),
            b.addiu(5, 29, META))
        a.jump(entries['capture'], True)
        # Ignore the diagnostic return, including fault/full/zero. Dispatch
        # never depends on publication, target classification or UI state.
        restore()
        a.label(name + '_jump')
        a.e(b.r_type(25, 0, 0, 8), 0)

    result = original + kernel + a.finish()
    end = code_base + len(result)
    if end > 0x100000000 or code_base >> 28 != (end - 1) >> 28:
        raise ValueError('playback dispatch code must fit one native MIPS jump region')
    if any(max(start, code_base) < min(start + size, end) for start, size in regions):
        raise ValueError('playback dispatch private regions must be outside emitted code')
    merged = dict(labels, **{'playback_dispatch_' + name: value for name, value in entries.items()})
    merged.update(a.labels)
    return result, merged


def build(source, *, enable_reveal=False, capacity=1024, row_capacity=1024,
          operation_capacity=1024, scope_capacity=1024, birth_capacity=1024,
          transport_capacity=1024, renderer_capacity=1024, playback_dispatch_capacity=1024):
    if enable_reveal is not False:
        raise ValueError('active reveal is not admitted: ' + ', '.join(MISSING_CONTRACTS))
    options = dict(capacity=capacity, row_capacity=row_capacity, operation_capacity=operation_capacity,
                   scope_capacity=scope_capacity, birth_capacity=birth_capacity,
                   transport_capacity=transport_capacity, renderer_capacity=renderer_capacity)
    golden, source_hash = normalize_source(source)
    # Reuse the predecessor's layout/schema metadata, but reassemble ALL its
    # code at the new RX address. Old defaults/builders are never modified.
    _, parent_meta = previous.build(source, **options)
    dispatch_bytes = dispatch.memory_bytes(playback_dispatch_capacity)
    total = parent_meta['memory_bytes'] + dispatch_bytes
    layout = plan_layout(golden, total)
    if layout['buffer'] != parent_meta['buffer']:
        raise ValueError('unexpected change to predecessor private base')
    addresses = [parent_meta[name] for name in ('buffer', 'row_buffer', 'contents_revision_buffer',
                 'operation_buffer', 'scope_buffer', 'birth_buffer', 'transport_buffer',
                 'renderer_transport_buffer')]
    dispatch_buffer = layout['buffer'] + parent_meta['memory_bytes']
    code, labels = assemble(*addresses, dispatch_buffer, layout['code_base'], **options,
                            playback_dispatch_capacity=playback_dispatch_capacity)
    image, layout_meta = install_layout(golden, code, total)
    output = bytearray(image)
    for name, (pc, expected) in HOOKS.items():
        if struct.unpack_from('<2I', golden, pc - BASE) != expected:
            raise ValueError('unexpected original playback dispatch hook: ' + name)
        linked = name in LINKED
        struct.pack_into('<2I', output, pc - BASE, b.j_type(3 if linked else 2, labels[name]),
                         expected[1] if linked else 0)
    for pc, (expected, replacement) in STRIDES.items():
        if struct.unpack_from('<I', golden, pc - BASE)[0] != expected:
            raise ValueError('unexpected original stride or node allocation')
        struct.pack_into('<I', output, pc - BASE, replacement)
    return bytes(output), dict(parent_meta, **layout_meta, labels=labels, memory_bytes=total,
        playback_dispatch_buffer=dispatch_buffer, playback_dispatch_memory_bytes=dispatch_bytes,
        playback_dispatch_capacity=playback_dispatch_capacity,
        playback_dispatch_record_bytes=dispatch.RECORD, input_sha256=source_hash,
        snapshot_format='lineage-rows-renderer-playback-dispatch-v1',
        stage='optional-playback-callback-dispatch-intent-observation-only',
        callback_completion_proven=False, playback_identity_proven=False,
        playback_paint_cause_associated=False, complete_playback_coverage=False,
        missing_contracts=MISSING_CONTRACTS)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('output', type=Path)
    for name in CAPACITY_NAMES:
        parser.add_argument('--' + name, type=int, default=1024)
    args = parser.parse_args()
    result, meta = build(args.source.read_bytes(), **{
        name.replace('-', '_'): getattr(args, name.replace('-', '_')) for name in CAPACITY_NAMES})
    with args.output.open('xb') as stream:
        stream.write(result)
    print('sha256=' + hashlib.sha256(result).hexdigest())
    print({name: meta[name] for name in ('output_size', 'memory_bytes', 'code_bytes',
                                       'stage', 'hardware', 'autoscroll')})
    print('OFFLINE CALL_INTENT ONLY; no callback completion, playback/paint cause or UI authority')


if __name__ == '__main__':
    main()
