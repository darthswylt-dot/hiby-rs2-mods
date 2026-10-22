#!/usr/bin/env python3
"""Offline exclusion for two audited in-flight native contents routines.

This is diagnostic capture filtering, NOT a writer lock, lifetime lease,
fresh UI request, settled contents or autoscroll implementation. Native calls
continue unchanged on every private fault. No transport/installer is provided.
"""
import argparse
import hashlib
import struct
from pathlib import Path

import build_reveal_origin_frontier_stage as previous
import reveal_native_scope_mips as scope
from build_reveal_bridge_diag import Asm, BASE, FRAME, SAVE, HI, LO, b
from reveal_bridge_elf import plan_layout, install_layout


EXITS = {
    'scope_reset_return': (0x4913F0, (0x03E00008, 0x27BD0048)),
    'scope_reconcile_return': (0x491D08, (0x03E00008, 0x27BD0258)),
    'scope_reconcile_empty_return': (0x491E68, (0x03E00008, 0x27BD0258)),
}
HOOKS = dict(previous.HOOKS, **EXITS)
STRIDES, LINKED = previous.STRIDES, previous.LINKED
NATIVE_TAILS = (*previous.NATIVE_TAILS, 0x491248, 0x4919E8)
normalize_source = previous.normalize_source
SCOPE_TOKEN_OFFSET = 0x14
MISSING_CONTRACTS = (*previous.MISSING_CONTRACTS,
                     'complete-native-writer-and-abnormal-exit-coverage')


def assemble(buffer, journal, revision_buffer, operation_buffer, scope_buffer, code_base,
             *, capacity=1024, row_capacity=1024, operation_capacity=1024, scope_capacity=1024):
    regions = ((buffer, previous.lineage.memory_bytes(capacity)),
               (journal, previous.rows.memory_bytes(row_capacity)), (revision_buffer, 16),
               (operation_buffer, previous.operation.memory_bytes(operation_capacity)),
               (scope_buffer, scope.memory_bytes(scope_capacity)))
    for index, (start, size) in enumerate(regions):
        if type(start) is not int or start < 0 or start % 4 or start + size > 0x100000000:
            raise ValueError('scope stage regions must be aligned and nonwrapping')
        for other, length in regions[index + 1:]:
            if type(other) is not int or max(start, other) < min(start + size, other + length):
                raise ValueError('scope stage private regions must not overlap')
    original, labels = previous.assemble(
        buffer, journal, revision_buffer, operation_buffer, code_base,
        capacity=capacity, row_capacity=row_capacity, operation_capacity=operation_capacity,
        scope_state_address=scope_buffer)
    kernel, entries = scope.assemble(scope_buffer, code_base + len(original), scope_capacity)
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

    for name, kind in (('contents_reset', scope.RESET),
                        ('contents_reconcile', scope.RECONCILE)):
        pc, displaced = HOOKS[name]
        a.label(name)
        # Native frame FIRST: SP14 is the audited native invocation carrier,
        # not a future-frame alias of a saved volatile register in FRAME80.
        a.e(*displaced)
        save()
        a.e(b.addiu(4, 0, kind), b.addiu(5, 29, FRAME),
            b.lw(6, SAVE[4], 29), b.lw(7, SAVE[5], 29))
        a.jump(entries['begin'], True)
        a.e(b.sw(2, FRAME + SCOPE_TOKEN_OFFSET, 29))
        # Active count precedes the revision bump and all remaining stock
        # effects. Never chain the old entry wrapper/prologue/bump twice.
        a.jump(labels['contents_bump'], True)
        restore()
        a.jump(pc + 8)

    for name, kind, native_frame in (
            ('scope_reset_return', scope.RESET, 0x48),
            ('scope_reconcile_return', scope.RECONCILE, 0x258),
            ('scope_reconcile_empty_return', scope.RECONCILE, 0x258)):
        a.label(name)
        save()
        # Revoke before releasing the active scope. Otherwise a renderer
        # entering during the routine could outlive it and appear fresh.
        a.jump(labels['contents_bump'], True)
        a.e(b.lw(4, FRAME + SCOPE_TOKEN_OFFSET, 29), b.addiu(5, 0, kind),
            b.addiu(6, 29, FRAME), b.lw(7, SAVE[2], 29))
        a.jump(entries['end'], True)
        restore()
        # Actual stock v0/RA (including non-normalized reset results) survive.
        # All three audited pairs are JR RA / SP-pop, with no direct target
        # into the replaced delay word. Pop the native frame exactly once.
        a.e(b.addiu(29, 29, native_frame), b.r_type(31, 0, 0, 8), 0)

    merged = dict(labels, scope_legacy_reset=labels['contents_reset'],
                  scope_legacy_reconcile=labels['contents_reconcile'])
    merged.update({'scope_' + name: value for name, value in entries.items()})
    merged.update(a.labels)
    result = original + kernel + a.finish()
    end = code_base + len(result)
    if end > 0x100000000 or code_base >> 28 != (end - 1) >> 28:
        raise ValueError('scope stage code must fit one native MIPS jump region')
    if any(max(start, code_base) < min(start + size, end) for start, size in regions):
        raise ValueError('scope stage private regions must be outside emitted code')
    return result, merged


def build(source, *, enable_reveal=False, capacity=1024, row_capacity=1024,
          operation_capacity=1024, scope_capacity=1024):
    if enable_reveal is not False:
        raise ValueError('active reveal is not admitted: ' + ', '.join(MISSING_CONTRACTS))
    golden, source_hash = normalize_source(source)
    lineage_bytes = previous.lineage.memory_bytes(capacity)
    journal_bytes = previous.rows.memory_bytes(row_capacity)
    operation_bytes = previous.operation.memory_bytes(operation_capacity)
    scope_bytes = scope.memory_bytes(scope_capacity)
    total = lineage_bytes + journal_bytes + 16 + operation_bytes + scope_bytes
    layout = plan_layout(golden, total)
    journal = layout['buffer'] + lineage_bytes
    revision_buffer, operation_buffer = journal + journal_bytes, journal + journal_bytes + 16
    scope_buffer = operation_buffer + operation_bytes
    code, labels = assemble(layout['buffer'], journal, revision_buffer, operation_buffer,
                            scope_buffer, layout['code_base'], capacity=capacity,
                            row_capacity=row_capacity, operation_capacity=operation_capacity,
                            scope_capacity=scope_capacity)
    image, meta = install_layout(golden, code, total)
    output = bytearray(image)
    for name, (pc, expected) in HOOKS.items():
        if struct.unpack_from('<2I', golden, pc - BASE) != expected:
            raise ValueError('unexpected original scope hook: ' + name)
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
        operation_capacity=operation_capacity, operation_record_bytes=64,
        scope_buffer=scope_buffer, scope_memory_bytes=scope_bytes, scope_capacity=scope_capacity,
        scope_record_bytes=scope.RECORD, scope_token_offset=SCOPE_TOKEN_OFFSET,
        input_sha256=source_hash, snapshot_format='lineage-rows-native-scope-v1',
        stage='known-in-flight-native-scope-exclusion-only',
        autoscroll=False, contents_current=False, capture_only=True, hardware='UNTESTED',
        producer_revision_offset=56, event_revision_offset=60, known_boundary_count=8,
        known_scope_count=2, known_scope_exit_count=3, completion_boundaries_revoke=True,
        origin_entry_offset=previous.ENTRY_OFFSET, origin_entry_revision_offset=60,
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
    print('OFFLINE KNOWN-SCOPE EXCLUSION; no current owner, deployment or UI action')


if __name__ == '__main__':
    main()
