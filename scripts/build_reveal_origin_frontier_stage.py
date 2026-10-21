#!/usr/bin/env python3
"""Offline original-renderer-entry filter, never a current-owner transaction.

Freeze the exact revision returned at guarded renderer entry, propagate it
immutably with original lineage, and refuse additional row payload reads when
known intervening boundaries make the original start stale. Stock callbacks
continue unchanged, even when their diagnostic capture is suppressed.
"""
import argparse
import hashlib
import struct
from pathlib import Path

import build_reveal_operation_stage as previous
import folderfollow_reveal_lineage_mips as lineage
import reveal_lineage_rows_mips as rows
import reveal_operation_journal_mips as operation
from build_reveal_bridge_diag import Asm, BASE, FRAME, SAVE, HI, LO, b
from reveal_bridge_elf import plan_layout, install_layout


HOOKS, STRIDES, LINKED = previous.HOOKS, previous.STRIDES, previous.LINKED
NATIVE_TAILS = (*previous.NATIVE_TAILS, 0x490700)
normalize_source = previous.normalize_source
ENTRY_OFFSET, ORIGIN_REVISION = 0x10, 60
MISSING_CONTRACTS = (*previous.MISSING_CONTRACTS,
                     'playback-and-request-origin-before-render-entry')


def assemble(buffer, journal, revision_buffer, operation_buffer, code_base,
             *, capacity=1024, row_capacity=1024, operation_capacity=1024):
    original, labels = previous.assemble(
        buffer, journal, revision_buffer, operation_buffer, code_base,
        capacity=capacity, row_capacity=row_capacity, operation_capacity=operation_capacity,
        origin_entry_offset=ENTRY_OFFSET, require_origin_frontier=True)
    a = Asm(code_base + len(original))
    a.label('contents_render_entry')
    # Allocate the native renderer frame FIRST. Storing its future SP10 from
    # the old pre-prologue FRAME80 would alias SAVE[t9]. Here the carrier is
    # above our private frame, outside SAVE/HI/LO and before native saved s0.
    a.e(*HOOKS['contents_render_entry'][1], b.addiu(29, 29, -FRAME))
    for register, offset in SAVE.items():
        a.e(b.sw(register, offset, 29))
    a.e(b.r_type(0, 0, 8, 0x10), b.sw(8, HI, 29),
        b.r_type(0, 0, 8, 0x12), b.sw(8, LO, 29))
    a.jump(labels['contents_bump'], True)
    # bump returns THIS successful reservation's historical ticket, even if
    # another entry already advanced the counter before the helper returned.
    # Failure returns zero, replacing any previous stack bytes with unbound.
    a.e(b.sw(2, FRAME + ENTRY_OFFSET, 29))
    a.e(b.lw(8, HI, 29), b.r_type(8, 0, 0, 0x11),
        b.lw(8, LO, 29), b.r_type(8, 0, 0, 0x13))
    for register, offset in SAVE.items():
        a.e(b.lw(register, offset, 29))
    a.e(b.addiu(29, 29, FRAME))
    a.jump(0x490700)  # Never chain through the old entry/bump/prologue again.
    merged = dict(labels, contents_legacy_render_entry=labels['contents_render_entry'])
    merged.update(a.labels)
    result = original + a.finish()
    end = code_base + len(result)
    if end > 0x100000000 or code_base >> 28 != (end - 1) >> 28:
        raise ValueError('frontier code must fit the native MIPS jump region')
    regions = ((buffer, lineage.memory_bytes(capacity)), (journal, rows.memory_bytes(row_capacity)),
               (revision_buffer, 16), (operation_buffer, operation.memory_bytes(operation_capacity)))
    if any(max(start, code_base) < min(start + size, end) for start, size in regions):
        raise ValueError('private frontier regions must be separate from all composed code')
    return result, merged


def build(source, *, enable_reveal=False, capacity=1024, row_capacity=1024, operation_capacity=1024):
    if enable_reveal is not False:
        raise ValueError('active reveal is not admitted: ' + ', '.join(MISSING_CONTRACTS))
    golden, source_hash = normalize_source(source)
    lineage_bytes, journal_bytes = lineage.memory_bytes(capacity), rows.memory_bytes(row_capacity)
    operation_bytes = operation.memory_bytes(operation_capacity)
    total = lineage_bytes + journal_bytes + 16 + operation_bytes
    layout = plan_layout(golden, total)
    journal = layout['buffer'] + lineage_bytes
    revision_buffer, operation_buffer = journal + journal_bytes, journal + journal_bytes + 16
    code, labels = assemble(layout['buffer'], journal, revision_buffer, operation_buffer,
                            layout['code_base'], capacity=capacity, row_capacity=row_capacity,
                            operation_capacity=operation_capacity)
    image, meta = install_layout(golden, code, total)
    output = bytearray(image)
    for name, (pc, expected) in HOOKS.items():
        if struct.unpack_from('<2I', golden, pc - BASE) != expected:
            raise ValueError('unexpected original hook: ' + name)
        linked = name in LINKED
        struct.pack_into('<2I', output, pc - BASE,
                         b.j_type(3 if linked else 2, labels[name]), expected[1] if linked else 0)
    for pc, (expected, replacement) in STRIDES.items():
        if struct.unpack_from('<I', golden, pc - BASE)[0] != expected:
            raise ValueError('unexpected original stride')
        struct.pack_into('<I', output, pc - BASE, replacement)
    return bytes(output), dict(
        meta, labels=labels, memory_bytes=total, lineage_bytes=lineage_bytes, capacity=capacity,
        row_buffer=journal, row_memory_bytes=journal_bytes, row_capacity=row_capacity,
        row_record_bytes=592, contents_revision_buffer=revision_buffer, contents_revision_bytes=16,
        operation_buffer=operation_buffer, operation_memory_bytes=operation_bytes,
        operation_capacity=operation_capacity, operation_record_bytes=64, input_sha256=source_hash,
        snapshot_format='lineage-rows-origin-frontier-v1', stage='original-render-entry-filter-only',
        autoscroll=False, contents_current=False, capture_only=True, hardware='UNTESTED',
        producer_revision_offset=56, event_revision_offset=60, known_boundary_count=8,
        origin_entry_offset=ENTRY_OFFSET, origin_entry_revision_offset=ORIGIN_REVISION,
        requires_original_frontier=True, prefix_bytes=708, element_bytes=712,
        missing_contracts=MISSING_CONTRACTS)


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
    print('OFFLINE ORIGINAL-ENTRY FILTER; no current owner, deployment or UI action')


if __name__ == '__main__':
    main()
