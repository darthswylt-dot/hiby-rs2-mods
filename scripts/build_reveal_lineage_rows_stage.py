#!/usr/bin/env python3
"""Offline provenance-bound row journal; no export, installer or UI action.

Builds on the unchanged lineage-only emitter. Captures raw append, SQL-step
terminal, actual statement-reset return and producer END in private BSS.
The decoder, not these raw probes, validates per-producer event order. Neither
component publishes ready rows, retains stock objects or enables autoscroll.
"""
import argparse
import hashlib
import struct
from pathlib import Path

import build_reveal_lineage_stage as lineage
import reveal_lineage_rows_mips as rows
from build_reveal_bridge_diag import Asm, BASE, FRAME, SAVE, HI, LO, b
from reveal_bridge_elf import plan_layout, install_layout


HOOKS = dict(lineage.HOOKS, **{
    'row': (0x6ED6E8, (0x0320F809, 0x27A50020)),
    'terminal': (0x6ED704, (0x0C170C70, 0x02002021)),
    'end': (0x6ED7D4, (0x8FBE0AC8, 0x8FB70AC4)),
})
STRIDES = lineage.STRIDES
LINKED = frozenset(('query', 'row', 'terminal'))
core = lineage.core
normalize_source = lineage.normalize_source
MISSING_CONTRACTS = lineage.MISSING_CONTRACTS


def assemble(buffer, journal, code_base, *, capacity=1024, row_capacity=1024,
             content_revision_address=None, origin_entry_offset=None,
             require_origin_frontier=False, scope_state_address=None):
    original, labels = lineage.assemble(
        buffer, code_base, capacity=capacity,
        producer_revision_address=content_revision_address, origin_entry_offset=origin_entry_offset)
    entries = {name: labels['lineage_' + name] for name in ('reserve', 'validate', 'invalidate')}
    capture, capture_labels = rows.assemble(
        buffer, entries, journal, code_base + len(original), capacity=row_capacity,
        content_revision_address=content_revision_address,
        require_origin_frontier=require_origin_frontier, scope_state_address=scope_state_address)
    a = Asm(code_base + len(original) + len(capture))

    def save():
        a.e(b.addiu(29, 29, -FRAME))
        for reg, off in SAVE.items():
            a.e(b.sw(reg, off, 29))
        a.e(b.r_type(0, 0, 8, 0x10), b.sw(8, HI, 29),
            b.r_type(0, 0, 8, 0x12), b.sw(8, LO, 29))

    def restore(pop=True):
        a.e(b.lw(8, HI, 29), b.r_type(8, 0, 0, 0x11),
            b.lw(8, LO, 29), b.r_type(8, 0, 0, 0x13))
        for reg, off in SAVE.items():
            a.e(b.lw(reg, off, 29))
        if pop:
            a.e(b.addiu(29, 29, FRAME))

    def capture_event(kind, stack_delta=0):
        # Four owned scalar parameters, outside O32 argument-home words.
        # s1 is NOW ordinal/count, not the immutable requested limit.
        for register, offset in ((16, 0x10), (22, 0x14), (17, 0x18), (23, 0x1C)):
            a.e(b.sw(register, offset, 29))
        a.e(b.addiu(4, 0, kind), b.addiu(5, 29, FRAME + stack_delta),
            b.lw(6, SAVE[2], 29), b.addiu(7, 29, 0x10))
        a.jump(capture_labels['capture'], True)

    a.label('row')
    # Original delay slot already formed a1 at ORIGINAL producer SP.
    # The native append has its own outgoing home area, and runs ONCE.
    a.e(b.addiu(29, 29, -0x20), b.sw(31, 0x1C, 29),
        b.r_type(25, 0, 31, 9), 0,
        b.lw(31, 0x1C, 29), b.addiu(29, 29, 0x20))
    save()
    capture_event(rows.ROW)
    restore()
    a.e(b.r_type(31, 0, 0, 8), 0)

    a.label('terminal')
    save()
    capture_event(rows.TERMINAL)  # SQL step v0, before native reset overwrites it.
    restore(False)
    a.jump(0x5C31C0, True)        # Original native statement reset exactly once.
    save()                      # Preserve its ACTUAL result, not the SQL result.
    capture_event(rows.RESET, stack_delta=FRAME)
    restore()
    a.e(b.lw(31, SAVE[31], 29), b.addiu(29, 29, FRAME),
        b.r_type(31, 0, 0, 8), 0)

    a.label('end')
    save()
    capture_event(rows.END)
    restore()
    a.e(*HOOKS['end'][1])        # RA was already restored by the native epilogue.
    a.jump(HOOKS['end'][0] + 8)

    merged = dict(labels, **{'rows_' + name: addr for name, addr in capture_labels.items()})
    merged.update(a.labels)
    return original + capture + a.finish(), merged


def build(source, *, enable_reveal=False, capacity=1024, row_capacity=1024):
    if enable_reveal is not False:
        raise ValueError('active reveal is not admitted: ' + ', '.join(MISSING_CONTRACTS))
    golden, input_hash = normalize_source(source)
    lineage_bytes = core.memory_bytes(capacity)
    journal_bytes = rows.memory_bytes(row_capacity)
    total = lineage_bytes + journal_bytes
    layout = plan_layout(golden, total)
    journal = layout['buffer'] + lineage_bytes
    code, labels = assemble(layout['buffer'], journal, layout['code_base'],
                            capacity=capacity, row_capacity=row_capacity)
    image, meta = install_layout(golden, code, total)
    output = bytearray(image)
    for name, (pc, expected) in HOOKS.items():
        if struct.unpack_from('<2I', golden, pc - BASE) != expected:
            raise ValueError('unexpected original hook: ' + name)
        linked = name in LINKED
        struct.pack_into('<2I', output, pc - BASE,
                         b.j_type(3 if linked else 2, labels[name]),
                         expected[1] if linked else 0)
    for pc, (expected, replacement) in STRIDES.items():
        if struct.unpack_from('<I', golden, pc - BASE)[0] != expected:
            raise ValueError('unexpected original stride')
        struct.pack_into('<I', output, pc - BASE, replacement)
    return bytes(output), dict(meta, labels=labels, memory_bytes=total,
                              lineage_bytes=lineage_bytes, capacity=capacity,
                              row_buffer=journal, row_memory_bytes=journal_bytes,
                              row_capacity=row_capacity, row_record_bytes=rows.RECORD,
                              input_sha256=input_hash, stage='native-lineage-row-journal-only',
                              snapshot_format='lineage-rows-bss-v1', autoscroll=False,
                              capture_only=True, hardware='UNTESTED',
                              prefix_bytes=lineage.PREFIX, element_bytes=lineage.ELEMENT,
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
    print('OFFLINE CAPTURE ONLY; no active reveal/export/deployment; hardware UNTESTED')


if __name__ == '__main__':
    main()
