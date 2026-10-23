#!/usr/bin/env python3
"""Offline explicit queued-birth -> outer -> existing renderer-root binding.

Two additional linear observers preserve previous builders byte-for-byte by
default. No renderer SP10/SP14 overwrite, pointer-key registry, new native
lookup, owner lease, currentness admission, active scrolling or deployment.
The preceding generic-node allocation extension remains an explicit premise.
"""
import argparse
import hashlib
import struct
from pathlib import Path

import build_reveal_queue_transport_stage as previous
import reveal_renderer_transport_mips as renderer
import folderfollow_reveal_lineage_mips as lineage
import reveal_lineage_rows_mips as rows
import reveal_operation_journal_mips as operation
import reveal_native_scope_mips as scope
import reveal_queue_birth_mips as birth
import reveal_queue_transport_mips as transport
from build_reveal_bridge_diag import Asm, BASE, SAVE, HI, LO, b
from reveal_bridge_elf import plan_layout, install_layout


NEW_HOOKS = {
    'renderer_outer_bind': (0x438248, (0x00C0A021, 0x00E08821)),
    'renderer_root_bind': (0x49076C, (0xAE113B50, 0x8E4201BC)),
}
HOOKS = dict(previous.HOOKS, **NEW_HOOKS)
STRIDES, LINKED = previous.STRIDES, previous.LINKED
NATIVE_TAILS = (*previous.NATIVE_TAILS, 0x438250, 0x490774)
normalize_source = previous.normalize_source
FRAME, META, TOKEN_OFFSET = 0xB0, 0x70, 0x14
MISSING_CONTRACTS = tuple(item for item in previous.MISSING_CONTRACTS
                          if item != 'queue-consumer-to-renderer-identity-transport')


def assemble(buffer, journal, revision_buffer, operation_buffer, scope_buffer,
             birth_buffer, transport_buffer, renderer_transport_buffer, code_base,
             *, capacity=1024, row_capacity=1024, operation_capacity=1024,
             scope_capacity=1024, birth_capacity=1024, transport_capacity=1024,
             renderer_capacity=1024):
    regions = ((buffer, lineage.memory_bytes(capacity)), (journal, rows.memory_bytes(row_capacity)),
               (revision_buffer, 16), (operation_buffer, operation.memory_bytes(operation_capacity)),
               (scope_buffer, scope.memory_bytes(scope_capacity)),
               (birth_buffer, birth.memory_bytes(birth_capacity)),
               (transport_buffer, transport.memory_bytes(transport_capacity)),
               (renderer_transport_buffer, renderer.memory_bytes(renderer_capacity)))
    for index, (start, size) in enumerate(regions):
        if type(start) is not int or start < 0 or start % 4 or start + size > 0x100000000:
            raise ValueError('renderer transport regions must be aligned and nonwrapping')
        for other, length in regions[index + 1:]:
            if type(other) is not int or max(start, other) < min(start + size, other + length):
                raise ValueError('renderer transport private regions must not overlap')
    original, labels = previous.assemble(
        buffer, journal, revision_buffer, operation_buffer, scope_buffer, birth_buffer,
        transport_buffer, code_base, capacity=capacity, row_capacity=row_capacity,
        operation_capacity=operation_capacity, scope_capacity=scope_capacity,
        birth_capacity=birth_capacity, transport_capacity=transport_capacity)
    transport_entries = {name: labels['queue_transport_' + name]
                         for name in ('capture', 'validate', 'reserve', 'invalidate')}
    lineage_entries = {name: labels['lineage_' + name]
                       for name in ('reserve', 'validate', 'invalidate')}
    kernel, entries = renderer.assemble(
        renderer_transport_buffer, transport_buffer, transport_entries, buffer, lineage_entries,
        revision_buffer, scope_buffer, code_base + len(original), capacity=renderer_capacity)
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

    def equals(register, constant, failed):
        a.absolute(9, constant)
        a.branch(5, register, 9, failed)

    def native_binding(offset, register, failed):
        a.e(b.lw(8, FRAME + offset, 29))
        a.branch(5, 8, register, failed)

    def capture(kind, site):
        a.absolute(8, site)
        a.e(b.sw(8, META + 48, 29), b.addiu(4, 0, kind), b.addiu(6, 29, META))
        a.jump(entries['capture'], True)

    a.label('renderer_outer_bind')
    # Native pair first: s4=callback coordinates, s1=paint descriptor. This
    # carrier is low native SP14, not an upper local beside native sprintf.
    a.e(*NEW_HOOKS['renderer_outer_bind'][1])
    save()
    a.e(b.sw(0, FRAME + TOKEN_OFFSET, 29), b.lw(8, FRAME + 0x1FC, 29))
    equals(8, 0x439F98, 'renderer_outer_original')
    a.e(b.lw(8, FRAME + 0x234, 29))
    equals(8, 0x8B40EC, 'renderer_outer_original')
    a.e(b.lw(8, SAVE[6], 29), b.addiu(9, 29, FRAME + 0x218))
    a.branch(5, 8, 9, 'renderer_outer_original')
    for source, offset in ((4, 0x1D8), (5, 0x1DC), (7, 0x1E0)):
        a.e(b.lw(8, SAVE[source], 29), b.lw(9, FRAME + offset, 29))
        a.branch(5, 8, 9, 'renderer_outer_original')
    native_binding(0x1E4, 19, 'renderer_outer_original')
    # Exact parent-frame / C / descriptor checks are repeated by the private
    # core; no current C name, resource lookup or native object reread.
    a.e(b.lw(5, FRAME + 0x214, 29))
    for source, offset in ((4, 0), (5, 4), (6, 24), (7, 28)):
        a.e(b.lw(8, SAVE[source], 29), b.sw(8, META + offset, 29))
    for offset in (8, 12, 36, 40, 44):
        a.e(b.sw(0, META + offset, 29))
    a.e(b.addiu(8, 29, FRAME), b.sw(8, META + 16, 29),
        b.addiu(8, 8, 0x200), b.sw(8, META + 20, 29), b.sw(19, META + 32, 29))
    capture(renderer.OUTER, 0x438248)
    a.e(b.sw(2, FRAME + TOKEN_OFFSET, 29))
    a.label('renderer_outer_original')
    restore()
    a.jump(0x438250)

    a.label('renderer_root_bind')
    # The existing root wrapper at 490758 has COMPLETED; the original native
    # call at 490764/delay490768 also completed. v0 is its real opaque return.
    # Do not run/relabel the old root wrapper or overwrite R10/R14.
    save()
    a.e(b.lw(8, FRAME + 0x2C, 29))
    equals(8, 0x438748, 'renderer_root_original')
    a.e(b.lw(8, FRAME + 0x22C, 29))
    equals(8, 0x439F98, 'renderer_root_original')
    a.e(b.lw(8, FRAME + 0x264, 29))
    equals(8, 0x8B40EC, 'renderer_root_original')
    native_binding(0x18, 19, 'renderer_root_original')
    native_binding(0x1E0, 17, 'renderer_root_original')
    a.e(b.lw(8, FRAME + 0x14, 29))
    a.branch(4, 8, 0, 'renderer_root_original')
    a.e(b.sw(8, META + 40, 29), b.lw(5, FRAME + 0x44, 29),
        b.sw(19, META, 29), b.sw(30, META + 4, 29),
        b.sw(16, META + 8, 29), b.sw(18, META + 12, 29),
        b.addiu(8, 29, FRAME), b.sw(8, META + 16, 29),
        b.addiu(8, 8, 0x30), b.sw(8, META + 20, 29))
    for source, target in ((0x28, 24), (0x1C, 28), (0x24, 32)):
        a.e(b.lw(8, FRAME + source, 29), b.sw(8, META + target, 29))
    a.e(b.addiu(8, 16, 0x38A4), b.sw(8, META + 36, 29), b.sw(17, META + 44, 29))
    capture(renderer.RENDER, 0x49076C)
    a.label('renderer_root_original')
    restore()
    a.e(*NEW_HOOKS['renderer_root_bind'][1])
    a.jump(0x490774)

    result = original + kernel + a.finish()
    end = code_base + len(result)
    if end > 0x100000000 or code_base >> 28 != (end - 1) >> 28:
        raise ValueError('renderer transport code must fit one native MIPS jump region')
    if any(max(start, code_base) < min(start + size, end) for start, size in regions):
        raise ValueError('renderer transport private regions must be outside emitted code')
    merged = dict(labels, **{'renderer_transport_' + name: address for name, address in entries.items()})
    merged.update(a.labels)
    return result, merged


def build(source, *, enable_reveal=False, capacity=1024, row_capacity=1024,
          operation_capacity=1024, scope_capacity=1024, birth_capacity=1024,
          transport_capacity=1024, renderer_capacity=1024):
    if enable_reveal is not False:
        raise ValueError('active reveal is not admitted: ' + ', '.join(MISSING_CONTRACTS))
    golden, source_hash = normalize_source(source)
    sizes = (lineage.memory_bytes(capacity), rows.memory_bytes(row_capacity), 16,
             operation.memory_bytes(operation_capacity), scope.memory_bytes(scope_capacity),
             birth.memory_bytes(birth_capacity), transport.memory_bytes(transport_capacity),
             renderer.memory_bytes(renderer_capacity))
    total = sum(sizes)
    layout = plan_layout(golden, total)
    addresses, address = [], layout['buffer']
    for size in sizes:
        addresses.append(address)
        address += size
    code, labels = assemble(*addresses, layout['code_base'], capacity=capacity, row_capacity=row_capacity,
                            operation_capacity=operation_capacity, scope_capacity=scope_capacity,
                            birth_capacity=birth_capacity, transport_capacity=transport_capacity,
                            renderer_capacity=renderer_capacity)
    image, meta = install_layout(golden, code, total)
    output = bytearray(image)
    for name, (pc, expected) in HOOKS.items():
        if struct.unpack_from('<2I', golden, pc - BASE) != expected:
            raise ValueError('unexpected original renderer transport hook: ' + name)
        linked = name in LINKED
        struct.pack_into('<2I', output, pc - BASE, b.j_type(3 if linked else 2, labels[name]),
                         expected[1] if linked else 0)
    for pc, (expected, replacement) in STRIDES.items():
        if struct.unpack_from('<I', golden, pc - BASE)[0] != expected:
            raise ValueError('unexpected original stride or node allocation')
        struct.pack_into('<I', output, pc - BASE, replacement)
    return bytes(output), dict(
        meta, labels=labels, memory_bytes=total, lineage_bytes=sizes[0], capacity=capacity,
        row_buffer=addresses[1], row_memory_bytes=sizes[1], row_capacity=row_capacity, row_record_bytes=592,
        contents_revision_buffer=addresses[2], contents_revision_bytes=16,
        operation_buffer=addresses[3], operation_memory_bytes=sizes[3],
        operation_capacity=operation_capacity, operation_record_bytes=64,
        scope_buffer=addresses[4], scope_memory_bytes=sizes[4], scope_capacity=scope_capacity,
        scope_record_bytes=32, scope_token_offset=TOKEN_OFFSET,
        birth_buffer=addresses[5], birth_memory_bytes=sizes[5], birth_capacity=birth_capacity,
        birth_record_bytes=64, birth_token_offset=TOKEN_OFFSET,
        transport_buffer=addresses[6], transport_memory_bytes=sizes[6],
        transport_capacity=transport_capacity, transport_record_bytes=64,
        transport_token_offset=TOKEN_OFFSET, node_token_offset=0x10,
        renderer_transport_buffer=addresses[7], renderer_transport_memory_bytes=sizes[7],
        renderer_capacity=renderer_capacity, renderer_transport_record_bytes=96,
        outer_token_offset=TOKEN_OFFSET, input_sha256=source_hash,
        snapshot_format='lineage-rows-renderer-transport-v1',
        stage='explicit-queued-birth-to-existing-renderer-root-observation-only',
        autoscroll=False, contents_current=False, capture_only=True, hardware='UNTESTED',
        producer_revision_offset=56, event_revision_offset=60, known_boundary_count=8,
        known_scope_count=2, known_scope_exit_count=3, completion_boundaries_revoke=True,
        origin_entry_offset=0x10, origin_entry_revision_offset=60, requires_original_frontier=True,
        prefix_bytes=708, element_bytes=712, birth_identity_transported=True,
        birth_transport_target='existing-native-renderer-lineage-root', native_allocations_extended=True,
        generic_node_bytes=20, original_generic_node_bytes=16, rectangle_bytes=16,
        allocation_outcomes_preserved=False, native_live_borrow_lease_proven=False,
        renderer_identity_transport_enabled=True, renderer_identity_associated=False,
        request_freshness_proven=False, missing_contracts=MISSING_CONTRACTS)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    result, meta = build(args.source.read_bytes())
    with args.output.open('xb') as stream:
        stream.write(result)
    print('sha256=' + hashlib.sha256(result).hexdigest())
    print(meta)
    print('OFFLINE RENDERER ASSOCIATION; historical evidence only; no native lease/currentness/UI authority')


if __name__ == '__main__':
    main()
