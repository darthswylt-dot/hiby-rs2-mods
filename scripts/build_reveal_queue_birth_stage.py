#!/usr/bin/env python3
"""Offline queued-request birth observation, NOT consumer identity transport.

Three invocation-local scalar receipts precede native allocation/append and
observe its actual return. Native geometry/node sizes, metadata, callback
calls and cleanup remain unchanged. There is no queue-tail read, pointer
registry, consumer admission, UI action, installer or device transport.
"""
import argparse
import hashlib
import struct
from pathlib import Path

import build_reveal_native_scope_stage as previous
import reveal_queue_birth_mips as birth
from build_reveal_bridge_diag import Asm, BASE, SAVE, HI, LO, b
from reveal_bridge_elf import plan_layout, install_layout


NEW_HOOKS = {
    'birth_entry': (0x8B428C, (0x27BDFFC0, 0xAFB00030)),
    'birth_enqueue_begin': (0x8B42E0, (0xAE230008, 0x02202821)),
    'birth_enqueue_return': (0x8B42F0, (0x8E280000, 0x8E240004)),
}
HOOKS = dict(previous.HOOKS, **NEW_HOOKS)
STRIDES, LINKED = previous.STRIDES, previous.LINKED
NATIVE_TAILS = (*previous.NATIVE_TAILS, *(pc + 8 for pc, _ in NEW_HOOKS.values()))
normalize_source = previous.normalize_source
FRAME, META, BIRTH_TOKEN_OFFSET = 0xA0, 0x70, 0x14
MISSING_CONTRACTS = (*previous.MISSING_CONTRACTS,
                     'immutable-queue-birth-to-consumer-identity-transport')


def assemble(buffer, journal, revision_buffer, operation_buffer, scope_buffer, birth_buffer, code_base,
             *, capacity=1024, row_capacity=1024, operation_capacity=1024, scope_capacity=1024,
             birth_capacity=1024):
    regions = ((buffer, previous.previous.lineage.memory_bytes(capacity)),
               (journal, previous.previous.rows.memory_bytes(row_capacity)), (revision_buffer, 16),
               (operation_buffer, previous.previous.operation.memory_bytes(operation_capacity)),
               (scope_buffer, previous.scope.memory_bytes(scope_capacity)),
               (birth_buffer, birth.memory_bytes(birth_capacity)))
    for index, (start, size) in enumerate(regions):
        if type(start) is not int or start < 0 or start % 4 or start + size > 0x100000000:
            raise ValueError('birth stage regions must be aligned and nonwrapping')
        for other, length in regions[index + 1:]:
            if type(other) is not int or max(start, other) < min(start + size, other + length):
                raise ValueError('birth stage private regions must not overlap')
    original, labels = previous.assemble(
        buffer, journal, revision_buffer, operation_buffer, scope_buffer, code_base,
        capacity=capacity, row_capacity=row_capacity, operation_capacity=operation_capacity,
        scope_capacity=scope_capacity)
    kernel, entries = birth.assemble(birth_buffer, revision_buffer, scope_buffer,
                                     code_base + len(original), capacity=birth_capacity)
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

    def capture(kind, site, *, entry=False):
        # Only wrapper-owned metadata is passed to the private core. These
        # borrowed native values are numeric scalars, not retained pointers.
        if entry:
            for source, offset in ((4, 0), (5, 4), (6, 12)):
                a.e(b.lw(8, SAVE[source], 29), b.sw(8, META + offset, 29))
            a.e(b.sw(0, META + 8, 29), b.sw(0, META + 24, 29), b.move(5, 0))
        else:
            for source, offset in ((16, 0), (18, 4), (17, 8)):
                a.e(b.sw(source, META + offset, 29))
            a.e(b.lw(8, FRAME + 0x28, 29), b.sw(8, META + 12, 29))
            a.e(b.lw(8, SAVE[2], 29) if kind == birth.RETURN else b.move(8, 0),
                b.sw(8, META + 24, 29), b.lw(5, FRAME + BIRTH_TOKEN_OFFSET, 29))
        a.e(b.addiu(8, 29, FRAME), b.sw(8, META + 16, 29))
        a.absolute(8, site)
        a.e(b.sw(8, META + 20, 29), b.addiu(4, 0, kind), b.addiu(6, 29, META))
        a.jump(entries['capture'], True)

    a.label('birth_entry')
    # Native frame FIRST. Its original RA store occurs later at 8B4294;
    # preserve entry RA and all volatile registers across the private helper.
    a.e(*NEW_HOOKS['birth_entry'][1])
    save()
    a.e(b.sw(0, FRAME + BIRTH_TOKEN_OFFSET, 29), b.lw(8, SAVE[5], 29))
    a.branch(4, 8, 0, 'birth_entry_original')
    capture(birth.BIRTH, 0x8B428C, entry=True)
    a.e(b.sw(2, FRAME + BIRTH_TOKEN_OFFSET, 29))
    a.label('birth_entry_original')
    restore()
    a.jump(0x8B4294)

    a.label('birth_enqueue_begin')
    # Preserve the original JAL E8, original RA F0, and last rect-word store
    # in its delay EC. This event is intent before append, NOT a completed
    # four-word copy, successful publication or an immutable native object.
    a.e(*NEW_HOOKS['birth_enqueue_begin'][1])
    save()
    capture(birth.ENQUEUE_BEGIN, 0x8B42E0)
    a.e(b.sw(2, FRAME + BIRTH_TOKEN_OFFSET, 29))
    restore()
    a.jump(0x8B42E8)

    a.label('birth_enqueue_return')
    save()
    capture(birth.RETURN, 0x8B42F0)
    restore()
    # v0 is still the actual generic-append node/zero return. Stock loads
    # happen once and do not read any new tail word or descriptor field.
    a.e(*NEW_HOOKS['birth_enqueue_return'][1])
    a.jump(0x8B42F8)

    merged = dict(labels, **{'queue_birth_' + name: address for name, address in entries.items()})
    merged.update(a.labels)
    result = original + kernel + a.finish()
    end = code_base + len(result)
    if end > 0x100000000 or code_base >> 28 != (end - 1) >> 28:
        raise ValueError('birth stage code must fit one native MIPS jump region')
    if any(max(start, code_base) < min(start + size, end) for start, size in regions):
        raise ValueError('birth stage private regions must be outside emitted code')
    return result, merged


def build(source, *, enable_reveal=False, capacity=1024, row_capacity=1024,
          operation_capacity=1024, scope_capacity=1024, birth_capacity=1024):
    if enable_reveal is not False:
        raise ValueError('active reveal is not admitted: ' + ', '.join(MISSING_CONTRACTS))
    golden, source_hash = normalize_source(source)
    lineage_bytes = previous.previous.lineage.memory_bytes(capacity)
    journal_bytes = previous.previous.rows.memory_bytes(row_capacity)
    operation_bytes = previous.previous.operation.memory_bytes(operation_capacity)
    scope_bytes, birth_bytes = previous.scope.memory_bytes(scope_capacity), birth.memory_bytes(birth_capacity)
    total = lineage_bytes + journal_bytes + 16 + operation_bytes + scope_bytes + birth_bytes
    layout = plan_layout(golden, total)
    journal = layout['buffer'] + lineage_bytes
    revision_buffer, operation_buffer = journal + journal_bytes, journal + journal_bytes + 16
    scope_buffer = operation_buffer + operation_bytes
    birth_buffer = scope_buffer + scope_bytes
    code, labels = assemble(layout['buffer'], journal, revision_buffer, operation_buffer,
                            scope_buffer, birth_buffer, layout['code_base'], capacity=capacity,
                            row_capacity=row_capacity, operation_capacity=operation_capacity,
                            scope_capacity=scope_capacity, birth_capacity=birth_capacity)
    image, meta = install_layout(golden, code, total)
    output = bytearray(image)
    for name, (pc, expected) in HOOKS.items():
        if struct.unpack_from('<2I', golden, pc - BASE) != expected:
            raise ValueError('unexpected original birth hook: ' + name)
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
        scope_record_bytes=32, scope_token_offset=0x14,
        birth_buffer=birth_buffer, birth_memory_bytes=birth_bytes, birth_capacity=birth_capacity,
        birth_record_bytes=birth.RECORD, birth_token_offset=BIRTH_TOKEN_OFFSET,
        input_sha256=source_hash, snapshot_format='lineage-rows-queue-birth-v1',
        stage='prepublication-queue-birth-observation-only',
        autoscroll=False, contents_current=False, capture_only=True, hardware='UNTESTED',
        producer_revision_offset=56, event_revision_offset=60, known_boundary_count=8,
        known_scope_count=2, known_scope_exit_count=3, completion_boundaries_revoke=True,
        origin_entry_offset=0x10, origin_entry_revision_offset=60,
        requires_original_frontier=True, prefix_bytes=708, element_bytes=712,
        birth_identity_transported=False, native_allocations_extended=False,
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
    print('OFFLINE BIRTH OBSERVATION; no queue-consumer association, current owner or UI action')


if __name__ == '__main__':
    main()
