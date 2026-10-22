#!/usr/bin/env python3
"""Offline known-contents-boundary filter, not a settled content epoch.

Eight inspected entry/attempt boundaries bump private diagnostic revision
before displaced stock instructions. Nested entries each bump, with no END,
READY, reset or rearm. Producers freeze a start sample; later known entries
invalidate their journal evidence. A writer already active at that sample,
a stale job beginning later, missed aliases and native lifetime remain unknown.
No exporter, installer, device transport or UI action is provided.
"""
import argparse
import hashlib
import struct
from pathlib import Path

import build_reveal_lineage_rows_stage as previous
import reveal_contents_revision_mips as revision
from build_reveal_bridge_diag import Asm, BASE, FRAME, SAVE, HI, LO, b
from reveal_bridge_elf import plan_layout, install_layout


BOUNDARIES = {
    'contents_render_entry': (0x4906F8, (0x27BDFFD0, 0xAFBF002C)),
    'contents_worker_entry': (0x48D080, (0x27BDFFC0, 0xAFBF003C)),
    'contents_reset': (0x491240, (0x27BDFFB8, 0xAFBF0044)),
    'contents_reconcile': (0x4919E0, (0x27BDFDA8, 0xAFB3024C)),
    'contents_reset_named': (0x494A00, (0x27BDFFB0, 0xAFBF004C)),
    'contents_close_attempt': (0x493B0C, (0x24020001, 0xAE020044)),
    'contents_postfill': (0x48F880, (0x27BDFFD0, 0xAFBF002C)),
    'contents_bind': (0x4A0EE0, (0x27BDFFC0, 0xAFB1002C)),
}
HOOKS = dict(previous.HOOKS, **BOUNDARIES)
STRIDES, LINKED = previous.STRIDES, previous.LINKED
normalize_source = previous.normalize_source
MISSING_CONTRACTS = (*previous.MISSING_CONTRACTS,
                     'exact-original-invocation-to-contents-phase-binding',
                     'matched-operation-completion-and-already-active-writer-coverage')


def assemble(buffer, journal, revision_buffer, code_base, *, capacity=1024, row_capacity=1024,
             origin_entry_offset=None, require_origin_frontier=False, scope_state_address=None):
    if (type(code_base) is not int or not 0 <= code_base <= 0xFFFFFFFC
            or code_base % 4 or code_base >> 28 != BASE >> 28):
        raise ValueError('contents code must share the original native MIPS jump region')
    regions = ((buffer, previous.core.memory_bytes(capacity)),
               (journal, previous.rows.memory_bytes(row_capacity)),
               (revision_buffer, revision.STATE_BYTES))
    for index, (start, size) in enumerate(regions):
        if (type(start) is not int or start < 0 or start % 4
                or start + size > 0x100000000):
            raise ValueError('private region must be aligned and nonwrapping')
        for other, length in regions[index + 1:]:
            if type(other) is not int:
                raise ValueError('private region must be an integer address')
            if max(start, other) < min(start + size, other + length):
                raise ValueError('private contents regions must not overlap')
    original, labels = previous.assemble(
        buffer, journal, code_base, capacity=capacity, row_capacity=row_capacity,
        content_revision_address=revision_buffer, origin_entry_offset=origin_entry_offset,
        require_origin_frontier=require_origin_frontier, scope_state_address=scope_state_address)
    counter, entries = revision.build_revision(revision_buffer, code_base + len(original))
    a = Asm(code_base + len(original) + len(counter))
    for name, (pc, displaced) in BOUNDARIES.items():
        a.label(name)
        a.e(b.addiu(29, 29, -FRAME))
        for register, offset in SAVE.items():
            a.e(b.sw(register, offset, 29))
        a.e(b.r_type(0, 0, 8, 0x10), b.sw(8, HI, 29),
            b.r_type(0, 0, 8, 0x12), b.sw(8, LO, 29))
        a.jump(entries['bump'], True)
        a.e(b.lw(8, HI, 29), b.r_type(8, 0, 0, 0x11),
            b.lw(8, LO, 29), b.r_type(8, 0, 0, 0x13))
        for register, offset in SAVE.items():
            a.e(b.lw(register, offset, 29))
        a.e(b.addiu(29, 29, FRAME))
        # No branch or PC-relative displaced instruction is copied here.
        # Entry prologues run at original SP; the close attempt uses its
        # already-established native frame. Native behavior always continues.
        a.e(*displaced)
        a.jump(pc + 8)
    merged = dict(labels, **{'contents_' + name: address for name, address in entries.items()})
    merged.update(a.labels)
    result = original + counter + a.finish()
    end = code_base + len(result)
    if end > 0x100000000 or code_base >> 28 != (end - 1) >> 28:
        raise ValueError('contents code must fit one MIPS jump region')
    if any(max(start, code_base) < min(start + size, end) for start, size in regions):
        raise ValueError('full private regions must be separate from emitted code')
    return result, merged


def build(source, *, enable_reveal=False, capacity=1024, row_capacity=1024):
    if enable_reveal is not False:
        raise ValueError('active reveal is not admitted: ' + ', '.join(MISSING_CONTRACTS))
    golden, source_hash = normalize_source(source)
    lineage_bytes = previous.core.memory_bytes(capacity)
    journal_bytes = previous.rows.memory_bytes(row_capacity)
    total = lineage_bytes + journal_bytes + revision.STATE_BYTES
    layout = plan_layout(golden, total)
    journal = layout['buffer'] + lineage_bytes
    revision_buffer = journal + journal_bytes
    code, labels = assemble(layout['buffer'], journal, revision_buffer, layout['code_base'],
                            capacity=capacity, row_capacity=row_capacity)
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
        meta, labels=labels, memory_bytes=total, lineage_bytes=lineage_bytes,
        capacity=capacity, row_buffer=journal, row_memory_bytes=journal_bytes,
        row_capacity=row_capacity, row_record_bytes=previous.rows.RECORD,
        contents_revision_buffer=revision_buffer, contents_revision_bytes=revision.STATE_BYTES,
        producer_revision_offset=56, event_revision_offset=60, input_sha256=source_hash,
        stage='native-known-contents-boundary-filter-only',
        snapshot_format='lineage-rows-content-revision-v1', autoscroll=False,
        contents_current=False, capture_only=True, hardware='UNTESTED',
        prefix_bytes=previous.lineage.PREFIX, element_bytes=previous.lineage.ELEMENT,
        known_boundary_count=len(BOUNDARIES), missing_contracts=MISSING_CONTRACTS)


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
    print('OFFLINE NEGATIVE EVIDENCE ONLY; no settled epoch, export, deployment or UI action')


if __name__ == '__main__':
    main()
