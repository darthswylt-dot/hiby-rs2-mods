#!/usr/bin/env python3
"""Offline exact-BORROW callback observer, never a contents-ready protocol.

Original fill/postfill JALR sites, return PCs and stacks remain unchanged.
Conditional branch/delay and branch-target epilogues are explicitly replayed.
No origin is relabelled with a current view; the known-boundary revocation
filter remains enabled, including ordinary postfill/bind revocation.
"""
import argparse
import hashlib
import struct
from pathlib import Path

import build_reveal_contents_revision_stage as previous
import reveal_operation_journal_mips as operation
from build_reveal_bridge_diag import Asm, BASE, SAVE, HI, LO, b
from reveal_bridge_elf import plan_layout, install_layout


NEW_HOOKS = {
    'operation_fill_begin': (0x48EC48, (0x8E3902C0, 0x1320000B)),
    'operation_fill_return': (0x48EC5C, (0x2403FFFF, 0x1043005A)),
    'operation_post_target': (0x48EC68, (0x8E3902BC, 0x13200003)),
    'operation_normal_end': (0x48EC7C, (0x24020002, 0xAE220004)),
    'operation_error_end': (0x48EDD4, (0x1000FFAA, 0x24020002)),
    'operation_bind_return': (0x48F8E4, (0x8FB00028, 0x03E00008)),
}
HOOKS = dict(previous.HOOKS, **NEW_HOOKS)
STRIDES, LINKED = previous.STRIDES, previous.LINKED
normalize_source = previous.normalize_source
MISSING_CONTRACTS = previous.MISSING_CONTRACTS
FRAME, META = 0xA0, 0x70
# Include the retained older wrapper's tail even though the bind hook now
# first enters our observer. Duplicate target counts are deliberate.
NATIVE_TAILS = tuple(pc + 8 for name, (pc, _) in previous.HOOKS.items() if name not in LINKED) + (
    0x48EC54, 0x48EC7C, 0x48EDCC, 0x48EC68, 0x48EC74, 0x48EC7C,
    0x48EC84, 0x48EC84)


def assemble(buffer, journal, revision_buffer, operation_buffer, code_base,
             *, capacity=1024, row_capacity=1024, operation_capacity=1024,
             origin_entry_offset=None, require_origin_frontier=False, scope_state_address=None):
    if (type(code_base) is not int or code_base % 4 or code_base < 0
            or code_base >> 28 != BASE >> 28):
        raise ValueError('operation code must share the original native jump region')
    regions = ((buffer, previous.previous.core.memory_bytes(capacity)),
               (journal, previous.previous.rows.memory_bytes(row_capacity)),
               (revision_buffer, 16), (operation_buffer, operation.memory_bytes(operation_capacity)))
    for index, (start, size) in enumerate(regions):
        if type(start) is not int or start < 0 or start % 4 or start + size > 0x100000000:
            raise ValueError('private region must be aligned and nonwrapping')
        for other, length in regions[index + 1:]:
            if type(other) is not int or max(start, other) < min(start + size, other + length):
                raise ValueError('private operation regions must not overlap')
    original, labels = previous.assemble(buffer, journal, revision_buffer, code_base,
                                         capacity=capacity, row_capacity=row_capacity,
                                         origin_entry_offset=origin_entry_offset,
                                         require_origin_frontier=require_origin_frontier,
                                         scope_state_address=scope_state_address)
    kernel, entries = operation.assemble(
        buffer, {'validate': labels['lineage_validate']}, operation_buffer,
        revision_buffer, code_base + len(original), capacity=operation_capacity)
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

    def capture(kind, site, *, post_frame=False, result=False, target=False, bind=False):
        # Seven scalars in our owned frame, outside SAVE, HI/LO and O32 homes.
        a.e(b.sw(17, META, 29))  # worker s1=exact actual work record
        a.absolute(8, site)
        a.e(b.sw(8, META + 4, 29))
        for offset, register, enabled in ((8, 2, result), (12, 25, target),
                                          (16, 4, bind), (20, 5, bind)):
            a.e(b.lw(8, SAVE[register], 29) if enabled else b.move(8, 0),
                b.sw(8, META + offset, 29))
        a.e(b.lw(8, FRAME + 0x20, 29) if bind else b.move(8, 0),
            b.sw(8, META + 24, 29),
            b.addiu(6, 29, FRAME + (0x30 if post_frame else 0)),
            b.lw(5, previous.previous.lineage.WORKER_BORROW, 6),
            b.addiu(4, 0, kind), b.addiu(7, 29, META))
        a.jump(entries['capture'], True)

    # Load each original callback pointer once, then preserve it across the
    # observer. The actual native call at EC54/EC74 is never replaced.
    for name, kind, call, site in (
            ('operation_fill_begin', 1, 0x48EC54, 0x48EC48),
            ('operation_post_target', 3, 0x48EC74, 0x48EC68)):
        a.label(name)
        a.e(NEW_HOOKS[name][1][0])
        save()
        capture(kind, site, target=True)
        restore()
        a.e(b.move(4, 16))  # Original native branch delay, on both paths.
        a.branch(4, 25, 0, name + '_null')
        a.jump(call)
        a.label(name + '_null')
        a.jump(0x48EC7C)

    a.label('operation_fill_return')
    save()
    capture(2, 0x48EC5C, result=True)
    restore()
    a.e(b.addiu(3, 0, -1), b.addiu(4, 19, 0x1450))
    a.branch(4, 2, 3, 'operation_fill_failed')
    a.jump(0x48EC68)
    a.label('operation_fill_failed')
    a.jump(0x48EDCC)

    for name, kind in (('operation_normal_end', 6), ('operation_error_end', 7)):
        a.label(name)
        save()
        capture(kind, NEW_HOOKS[name][0], result=True)
        restore()
        # EC80 is the original error-branch target, but our normal hook also
        # replaces it. Replay its flag store here, then skip that patched NOP.
        a.e(b.addiu(2, 0, 2), b.sw(2, 4, 17))
        a.jump(0x48EC84)

    old_bind = labels['contents_bind']
    a.label('contents_bind')
    save()
    a.e(b.lw(8, SAVE[31], 29))
    a.absolute(9, 0x48F8E0)
    a.branch(5, 8, 9, 'operation_bind_original')
    a.e(b.lw(8, FRAME + 0x2C, 29))
    a.absolute(9, 0x48EC7C)
    a.branch(5, 8, 9, 'operation_bind_original')
    capture(4, 0x4A0EE0, post_frame=True, bind=True)
    a.label('operation_bind_original')
    restore()
    a.jump(old_bind)  # Existing global revocation + exact original prologue.

    a.label('operation_bind_return')
    save()
    a.e(b.lw(8, SAVE[31], 29))
    a.absolute(9, 0x48EC7C)
    a.branch(5, 8, 9, 'operation_post_return_original')
    a.e(b.lw(8, FRAME + 0x2C, 29))
    a.branch(5, 8, 9, 'operation_post_return_original')
    capture(5, 0x48F8E4, post_frame=True, result=True)
    a.label('operation_post_return_original')
    restore()
    # Branches on missing V/P land at E4 directly, so E0/E4 cannot be patched
    # as a normal pair. This branch-target-safe epilogue covers every route.
    a.e(b.lw(16, 0x28, 29), b.addiu(29, 29, 0x30), b.r_type(31, 0, 0, 8), 0)

    merged = dict(labels, **{'operation_' + name: address for name, address in entries.items()})
    merged['contents_native_bind'] = old_bind
    merged.update(a.labels)
    result = original + kernel + a.finish()
    end = code_base + len(result)
    if end > 0x100000000 or code_base >> 28 != (end - 1) >> 28:
        raise ValueError('operation code must fit one native jump region')
    if any(max(start, code_base) < min(start + size, end) for start, size in regions):
        raise ValueError('private operation regions must be outside all emitted code')
    return result, merged


def build(source, *, enable_reveal=False, capacity=1024, row_capacity=1024, operation_capacity=1024):
    if enable_reveal is not False:
        raise ValueError('active reveal is not admitted: ' + ', '.join(MISSING_CONTRACTS))
    golden, source_hash = normalize_source(source)
    lineage_bytes = previous.previous.core.memory_bytes(capacity)
    journal_bytes = previous.previous.rows.memory_bytes(row_capacity)
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
        snapshot_format='lineage-rows-content-revision-operation-journal-v1', stage='exact-borrow-callback-observer-only',
        autoscroll=False, contents_current=False, capture_only=True, hardware='UNTESTED',
        producer_revision_offset=56, event_revision_offset=60, known_boundary_count=8,
        prefix_bytes=708, element_bytes=712, missing_contracts=MISSING_CONTRACTS)


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
    print('OFFLINE CALLBACK OBSERVATION ONLY; no current contents, exporter, installer or UI')


if __name__ == '__main__':
    main()
