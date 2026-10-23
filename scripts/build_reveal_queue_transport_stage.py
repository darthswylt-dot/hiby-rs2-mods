#!/usr/bin/env python3
"""Offline explicit queue-node birth transport to the native paint callback.

The inspected generic node allocation grows 16 -> 20 for ALL six uses of
8B3CC0. Its new word is zero before publication; only the exact queued
producer may install an explicit private receipt. No geometry tail, metadata
reuse, address registry, native lease, renderer join, installer or UI action.
"""
import argparse
import hashlib
import struct
from pathlib import Path

import build_reveal_queue_birth_stage as previous
import reveal_queue_transport_mips as transport
from build_reveal_bridge_diag import Asm, BASE, SAVE, HI, LO, b
from reveal_bridge_elf import plan_layout, install_layout


NEW_HOOKS = {
    'transport_node_allocated': (0x8B3CE8, (0x10400010, 0x8FBF0024)),
    'transport_queue_borrow': (0x8B4754, (0x8FC50000, 0x8FC60004)),
    'transport_helper_entry': (0x8B3FA0, (0x27BDFF48, 0xAFB600B0)),
    'transport_callback_entry': (0x439EC0, (0x27BDFFC8, 0xAFBF0034)),
}
HOOKS = dict(previous.HOOKS, **NEW_HOOKS)
STRIDES = dict(previous.STRIDES)
STRIDES[0x8B3CCC] = (0x24040010, 0x24040014)
LINKED = previous.LINKED
NATIVE_TAILS = (*previous.NATIVE_TAILS, 0x8B3CF0, 0x8B3D2C,
                0x8B475C, 0x8B3FA8, 0x439EC8)
normalize_source = previous.normalize_source
FRAME, META, TOKEN_OFFSET, NODE_TOKEN_OFFSET = 0xA0, 0x70, 0x14, 0x10
MISSING_CONTRACTS = (*previous.previous.MISSING_CONTRACTS,
                     'queue-consumer-to-renderer-identity-transport',
                     'native-queue-node-live-borrow-lease')


def assemble(buffer, journal, revision_buffer, operation_buffer, scope_buffer,
             birth_buffer, transport_buffer, code_base, *, capacity=1024,
             row_capacity=1024, operation_capacity=1024, scope_capacity=1024,
             birth_capacity=1024, transport_capacity=1024):
    regions = ((buffer, previous.previous.previous.lineage.memory_bytes(capacity)),
               (journal, previous.previous.previous.rows.memory_bytes(row_capacity)),
               (revision_buffer, 16),
               (operation_buffer, previous.previous.previous.operation.memory_bytes(operation_capacity)),
               (scope_buffer, previous.previous.scope.memory_bytes(scope_capacity)),
               (birth_buffer, previous.birth.memory_bytes(birth_capacity)),
               (transport_buffer, transport.memory_bytes(transport_capacity)))
    for index, (start, size) in enumerate(regions):
        if type(start) is not int or start < 0 or start % 4 or start + size > 0x100000000:
            raise ValueError('transport stage regions must be aligned and nonwrapping')
        for other, length in regions[index + 1:]:
            if type(other) is not int or max(start, other) < min(start + size, other + length):
                raise ValueError('transport stage private regions must not overlap')
    original, labels = previous.assemble(
        buffer, journal, revision_buffer, operation_buffer, scope_buffer, birth_buffer, code_base,
        capacity=capacity, row_capacity=row_capacity, operation_capacity=operation_capacity,
        scope_capacity=scope_capacity, birth_capacity=birth_capacity)
    birth_entries = {name: labels['queue_birth_' + name]
                     for name in ('capture', 'validate', 'reserve', 'invalidate')}
    kernel, entries = transport.assemble(
        transport_buffer, birth_buffer, birth_entries, revision_buffer, scope_buffer,
        code_base + len(original), capacity=transport_capacity)
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

    def equal_constant(register, value, failed):
        a.absolute(9, value)
        a.branch(5, register, 9, failed)

    def finish_capture(kind, site):
        a.absolute(8, site)
        a.e(b.sw(8, META + 24, 29), b.addiu(4, 0, kind), b.addiu(6, 29, META))
        a.jump(entries['capture'], True)

    a.label('transport_node_allocated')
    # Original BEQ delay runs on BOTH outcomes, before our own frame. Preserve
    # the actual allocator v0. A failed allocation must not dereference it.
    a.e(NEW_HOOKS['transport_node_allocated'][1][1])
    a.branch(4, 2, 0, 'transport_node_failed')
    save()
    a.e(b.lw(8, SAVE[2], 29), b.sw(0, NODE_TOKEN_OFFSET, 8))
    a.e(b.lw(8, FRAME + 0x24, 29))
    equal_constant(8, 0x8B42F0, 'transport_node_original')
    # Only after the exact saved-RA gate may we inspect the caller carrier.
    a.e(b.lw(5, FRAME + 0x28 + TOKEN_OFFSET, 29),
        b.addiu(8, 16, -0x34), b.sw(8, META, 29),
        b.lw(8, SAVE[2], 29), b.sw(8, META + 4, 29),
        b.sw(18, META + 8, 29), b.sw(17, META + 12, 29),
        b.addiu(8, 29, FRAME), b.sw(8, META + 16, 29),
        b.addiu(8, 8, 0x28), b.sw(8, META + 20, 29))
    finish_capture(transport.INSTALL, 0x8B3CE8)
    a.e(b.lw(8, SAVE[2], 29), b.sw(2, NODE_TOKEN_OFFSET, 8))
    a.label('transport_node_original')
    restore()
    a.jump(0x8B3CF0)
    a.label('transport_node_failed')
    a.jump(0x8B3D2C)

    a.label('transport_queue_borrow')
    # Replay the native argument loads ONCE. Original JAL/delay at 475C/60
    # stay in place, preserving its native return address 4764.
    a.e(*NEW_HOOKS['transport_queue_borrow'][1])
    save()
    a.e(b.sw(0, FRAME + TOKEN_OFFSET, 29), b.lw(5, NODE_TOKEN_OFFSET, 30),
        b.sw(21, META, 29), b.sw(30, META + 4, 29),
        b.lw(8, SAVE[5], 29), b.sw(8, META + 8, 29),
        b.lw(8, SAVE[6], 29), b.sw(8, META + 12, 29),
        b.addiu(8, 29, FRAME), b.sw(8, META + 16, 29), b.sw(0, META + 20, 29))
    finish_capture(transport.BORROW, 0x8B4754)
    a.e(b.sw(2, FRAME + TOKEN_OFFSET, 29))
    restore()
    a.jump(0x8B475C)

    a.label('transport_helper_entry')
    a.e(*NEW_HOOKS['transport_helper_entry'][1])
    save()
    a.e(b.sw(0, FRAME + TOKEN_OFFSET, 29), b.lw(8, SAVE[31], 29))
    equal_constant(8, 0x8B4764, 'transport_helper_original')
    a.e(b.lw(8, SAVE[4], 29))
    a.branch(5, 8, 21, 'transport_helper_original')
    a.e(b.lw(5, FRAME + 0xB8 + TOKEN_OFFSET, 29),
        b.sw(8, META, 29), b.sw(30, META + 4, 29),
        b.lw(8, SAVE[5], 29), b.sw(8, META + 8, 29),
        b.lw(8, SAVE[6], 29), b.sw(8, META + 12, 29),
        b.addiu(8, 29, FRAME), b.sw(8, META + 16, 29),
        b.addiu(8, 8, 0xB8), b.sw(8, META + 20, 29))
    finish_capture(transport.HELPER, 0x8B3FA0)
    a.e(b.sw(2, FRAME + TOKEN_OFFSET, 29))
    a.label('transport_helper_original')
    restore()
    a.jump(0x8B3FA8)

    a.label('transport_callback_entry')
    a.e(*NEW_HOOKS['transport_callback_entry'][1])
    save()
    a.e(b.sw(0, FRAME + TOKEN_OFFSET, 29), b.lw(8, SAVE[31], 29))
    equal_constant(8, 0x8B40EC, 'transport_callback_original')
    a.e(b.lw(8, SAVE[5], 29), b.addiu(9, 29, FRAME + 0x90))
    a.branch(5, 8, 9, 'transport_callback_original')
    a.e(b.lw(8, SAVE[4], 29))
    a.branch(5, 8, 22, 'transport_callback_original')
    # The helper's saved RA is part of the source/frame premise. The full
    # callback path (RA4998) never reads this ancestor or its carrier.
    a.e(b.lw(8, FRAME + 0xEC, 29))
    equal_constant(8, 0x8B4764, 'transport_callback_original')
    a.e(b.lw(5, FRAME + 0x4C, 29),
        b.lw(8, SAVE[4], 29), b.sw(8, META, 29), b.sw(30, META + 4, 29),
        b.sw(19, META + 8, 29), b.sw(21, META + 12, 29),
        b.addiu(8, 29, FRAME), b.sw(8, META + 16, 29),
        b.addiu(8, 8, 0x38), b.sw(8, META + 20, 29))
    finish_capture(transport.CALLBACK, 0x439EC0)
    a.e(b.sw(2, FRAME + TOKEN_OFFSET, 29))
    a.label('transport_callback_original')
    restore()
    a.jump(0x439EC8)

    result = original + kernel + a.finish()
    end = code_base + len(result)
    if end > 0x100000000 or code_base >> 28 != (end - 1) >> 28:
        raise ValueError('transport stage code must fit one native MIPS jump region')
    if any(max(start, code_base) < min(start + size, end) for start, size in regions):
        raise ValueError('transport stage private regions must be outside emitted code')
    merged = dict(labels, **{'queue_transport_' + name: address for name, address in entries.items()})
    merged.update(a.labels)
    return result, merged


def build(source, *, enable_reveal=False, capacity=1024, row_capacity=1024,
          operation_capacity=1024, scope_capacity=1024, birth_capacity=1024, transport_capacity=1024):
    if enable_reveal is not False:
        raise ValueError('active reveal is not admitted: ' + ', '.join(MISSING_CONTRACTS))
    golden, source_hash = normalize_source(source)
    lineage_bytes = previous.previous.previous.lineage.memory_bytes(capacity)
    journal_bytes = previous.previous.previous.rows.memory_bytes(row_capacity)
    operation_bytes = previous.previous.previous.operation.memory_bytes(operation_capacity)
    scope_bytes = previous.previous.scope.memory_bytes(scope_capacity)
    birth_bytes = previous.birth.memory_bytes(birth_capacity)
    transport_bytes = transport.memory_bytes(transport_capacity)
    total = lineage_bytes + journal_bytes + 16 + operation_bytes + scope_bytes + birth_bytes + transport_bytes
    layout = plan_layout(golden, total)
    journal = layout['buffer'] + lineage_bytes
    revision_buffer, operation_buffer = journal + journal_bytes, journal + journal_bytes + 16
    scope_buffer, birth_buffer = operation_buffer + operation_bytes, operation_buffer + operation_bytes + scope_bytes
    transport_buffer = birth_buffer + birth_bytes
    code, labels = assemble(
        layout['buffer'], journal, revision_buffer, operation_buffer, scope_buffer,
        birth_buffer, transport_buffer, layout['code_base'], capacity=capacity,
        row_capacity=row_capacity, operation_capacity=operation_capacity,
        scope_capacity=scope_capacity, birth_capacity=birth_capacity, transport_capacity=transport_capacity)
    image, meta = install_layout(golden, code, total)
    output = bytearray(image)
    for name, (pc, expected) in HOOKS.items():
        if struct.unpack_from('<2I', golden, pc - BASE) != expected:
            raise ValueError('unexpected original transport hook: ' + name)
        linked = name in LINKED
        struct.pack_into('<2I', output, pc - BASE, b.j_type(3 if linked else 2, labels[name]),
                         expected[1] if linked else 0)
    for pc, (expected, replacement) in STRIDES.items():
        if struct.unpack_from('<I', golden, pc - BASE)[0] != expected:
            raise ValueError('unexpected original stride or node allocation')
        struct.pack_into('<I', output, pc - BASE, replacement)
    return bytes(output), dict(
        meta, labels=labels, memory_bytes=total, lineage_bytes=lineage_bytes, capacity=capacity,
        row_buffer=journal, row_memory_bytes=journal_bytes, row_capacity=row_capacity, row_record_bytes=592,
        contents_revision_buffer=revision_buffer, contents_revision_bytes=16,
        operation_buffer=operation_buffer, operation_memory_bytes=operation_bytes,
        operation_capacity=operation_capacity, operation_record_bytes=64,
        scope_buffer=scope_buffer, scope_memory_bytes=scope_bytes, scope_capacity=scope_capacity,
        scope_record_bytes=32, scope_token_offset=TOKEN_OFFSET,
        birth_buffer=birth_buffer, birth_memory_bytes=birth_bytes, birth_capacity=birth_capacity,
        birth_record_bytes=64, birth_token_offset=TOKEN_OFFSET,
        transport_buffer=transport_buffer, transport_memory_bytes=transport_bytes,
        transport_capacity=transport_capacity, transport_record_bytes=64,
        transport_token_offset=TOKEN_OFFSET, node_token_offset=NODE_TOKEN_OFFSET,
        input_sha256=source_hash, snapshot_format='lineage-rows-queue-transport-v1',
        stage='explicit-queue-birth-to-native-callback-observation-only',
        autoscroll=False, contents_current=False, capture_only=True, hardware='UNTESTED',
        producer_revision_offset=56, event_revision_offset=60, known_boundary_count=8,
        known_scope_count=2, known_scope_exit_count=3, completion_boundaries_revoke=True,
        origin_entry_offset=0x10, origin_entry_revision_offset=60, requires_original_frontier=True,
        prefix_bytes=708, element_bytes=712, birth_identity_transported=True,
        birth_transport_target='439EC0-entry-only', native_allocations_extended=True,
        generic_node_bytes=20, original_generic_node_bytes=16, rectangle_bytes=16,
        allocation_outcomes_preserved=False, native_live_borrow_lease_proven=False,
        renderer_identity_associated=False, request_freshness_proven=False,
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
    print('OFFLINE CALLBACK TRANSPORT; changed allocation pressure; no renderer join, native lease or UI authority')


if __name__ == '__main__':
    main()
