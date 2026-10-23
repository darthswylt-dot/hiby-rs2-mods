#!/usr/bin/env python3
"""Offline explicit GENERAL notification -> queue delivery -> paint BIRTH link.

Native action records grow16->20 and paint records32->36, each with an ID
initialized before publication, including unknown producers. Borrowed IDs are
copied once under their native mutexes. This is historical invocation cause,
not coherent media/geometry, a retained native lease or permission to scroll.
"""
import argparse
import hashlib
from pathlib import Path
import struct

import build_reveal_playback_dispatch_stage as previous
import reveal_action_link_mips as link
from build_reveal_bridge_diag import Asm, BASE, SAVE, HI, LO, b
from reveal_bridge_elf import plan_layout, install_layout


NEW_HOOKS = {
    'action_source': (0x4BACBC, (0x8E04001C, 0x24020001)),
    'action_delivery': (0x4BA96C, (0x8C430004, 0x8C5E0008)),
    'action_explorer': (0x4909A4, (0x27BDFFC0, 0xAFBF003C)),
    'action_paint': (0x43C868, (0x27BDFFC0, 0xAFBF003C)),
    'action_paint_delivery': (0x4399E8, (0x8E190288, 0x02002021)),
}
HOOKS = dict(previous.HOOKS, **NEW_HOOKS)
STRIDES = dict(previous.STRIDES, **{})
STRIDES.update({0x4BAAF4: (0x24050010, 0x24050014),
                0x439844: (0x24050020, 0x24050024)})
LINKED = previous.LINKED
NATIVE_TAILS = (*previous.NATIVE_TAILS, *(pc + 8 for pc, _ in NEW_HOOKS.values()))
INDIRECT_TAIL_LABELS = previous.INDIRECT_TAIL_LABELS
normalize_source = previous.normalize_source
FRAME, META, PARENT, TEMP, RETURN_SAVE = 0xD0, 0x70, 0xB4, 0xB8, 0xC8
CAPACITY_NAMES = (*previous.CAPACITY_NAMES, 'action-link-capacity')
MISSING_CONTRACTS = (*previous.MISSING_CONTRACTS,
                     'action-queue-link-is-not-a-coherent-media-or-native-lease-proof')
META_FIELDS = tuple(range(20, 88, 4))


def assemble(addresses, action_link_buffer, code_base, *, capacity=1024, row_capacity=1024,
             operation_capacity=1024, scope_capacity=1024, birth_capacity=1024,
             transport_capacity=1024, renderer_capacity=1024, playback_dispatch_capacity=1024,
             action_link_capacity=1024):
    options = dict(capacity=capacity, row_capacity=row_capacity, operation_capacity=operation_capacity,
        scope_capacity=scope_capacity, birth_capacity=birth_capacity, transport_capacity=transport_capacity,
        renderer_capacity=renderer_capacity, playback_dispatch_capacity=playback_dispatch_capacity)
    if len(addresses) != 9:
        raise ValueError('expected the exact nine predecessor private regions')
    original, labels = previous.assemble(*addresses, code_base, **options)
    prior_end = addresses[-1] + previous.dispatch.memory_bytes(playback_dispatch_capacity)
    size = link.memory_bytes(action_link_capacity)
    if (type(action_link_buffer) is not int or action_link_buffer % 4
            or action_link_buffer < prior_end or action_link_buffer + size > 0x100000000):
        raise ValueError('action link journal must follow predecessor storage without wrap')
    entries = {'validate': labels['queue_birth_validate']}
    kernel, core = link.assemble(action_link_buffer, addresses[5], entries,
                                 code_base + len(original), capacity=action_link_capacity)
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

    def equals(register, value, failed):
        a.absolute(9, value)
        a.branch(5, register, 9, failed)

    def put(field, register):
        a.e(b.sw(register, META + field - 20, 29))

    def constant(field, value):
        a.absolute(8, value)
        put(field, 8)

    def native_frame(field, displacement=0):
        a.e(b.addiu(8, 29, FRAME + displacement))
        put(field, 8)

    def inherit(parent_register, kind, failed):
        a.e(b.sw(parent_register, PARENT, 29))
        a.branch(4, parent_register, 0, failed)
        a.e(b.move(4, parent_register), b.addiu(5, 0, kind))
        a.jump(core['validate'], True)
        a.branch(4, 2, 0, failed)
        for field in META_FIELDS:
            a.e(b.lw(8, field, 2), b.sw(8, META + field - 20, 29))

    def capture(kind):
        a.e(b.addiu(4, 0, kind), b.lw(5, PARENT, 29), b.addiu(6, 29, META))
        a.jump(core['capture'], True)

    a.label('action_source')
    a.e(*NEW_HOOKS['action_source'][1])
    save()
    a.e(b.sw(0, FRAME + 0x28, 29), b.lw(8, FRAME + 0x3C, 29))
    equals(8, 0x42D61C, 'action_source_done')
    a.e(b.lw(8, FRAME + 0x2C, 29))
    equals(8, 0xADD368, 'action_source_done')
    equals(19, 1, 'action_source_done')
    a.branch(5, 17, 0, 'action_source_done')
    for field in META_FIELDS:
        put(field, 0)
    a.e(b.sw(0, PARENT, 29))
    put(link.WORKER, 16)
    a.e(b.lw(8, SAVE[4], 29))
    put(link.QUEUE, 8)
    native_frame(link.RECORD, 0x18)
    native_frame(link.SOURCE_FRAME)
    native_frame(link.FRAME)
    constant(link.SITE, 0x4BACBC)
    constant(link.CALLER, 0x42D61C)
    for field, register in ((link.ACTION, 19), (link.PARAM1, 18), (link.PARAM2, 17)):
        put(field, register)
    capture(link.SOURCE)
    a.e(b.sw(2, FRAME + 0x28, 29))
    a.label('action_source_done')
    restore()
    a.jump(0x4BACC4)

    a.label('action_delivery')
    a.e(*NEW_HOOKS['action_delivery'][1])
    save()
    a.e(b.sw(0, FRAME + 0x1C, 29), b.lw(8, 0x1C, 19))
    a.branch(4, 8, 0, 'action_delivery_done')
    a.e(b.sw(8, TEMP, 29), b.lw(8, 0x10, 8))
    equals(8, 20, 'action_delivery_done')
    a.e(b.lw(5, 0x10, 23))  # Actual selected record tail, ONCE under T+10.
    inherit(5, link.SOURCE, 'action_delivery_done')
    put(link.WORKER, 19)
    a.e(b.lw(8, TEMP, 29))
    put(link.QUEUE, 8)
    put(link.RECORD, 23)
    native_frame(link.FRAME)
    constant(link.SITE, 0x4BA96C)
    constant(link.CALLER, 0)
    a.e(b.lw(8, SAVE[3], 29))
    put(link.PARAM1, 8)
    put(link.PARAM2, 30)
    a.e(b.lw(8, 0xC, 23))
    put(link.ACTION, 8)
    capture(link.DELIVERY)
    a.e(b.sw(2, FRAME + 0x1C, 29))
    a.label('action_delivery_done')
    restore()
    a.jump(0x4BA974)

    a.label('action_explorer')
    a.e(*NEW_HOOKS['action_explorer'][1])
    save()
    a.e(b.sw(0, FRAME + 0x30, 29), b.lw(8, FRAME + 0x3C, 29))
    equals(8, 0x4BAA68, 'action_explorer_done')
    a.e(b.lw(5, FRAME + 0x5C, 29))
    inherit(5, link.DELIVERY, 'action_explorer_done')
    native_frame(link.FRAME)
    constant(link.SITE, 0x4909A4)
    constant(link.CALLER, 0x4BAA68)
    for field, register in ((link.RESOURCE, 4), (link.NODE, 5),
                            (link.ACTION, 6), (link.PARAM1, 7)):
        a.e(b.lw(8, SAVE[register], 29))
        put(field, 8)
    a.e(b.lw(8, FRAME + 0x50, 29))
    put(link.PARAM2, 8)
    capture(link.EXPLORER)
    a.e(b.sw(2, FRAME + 0x30, 29))
    a.label('action_explorer_done')
    restore()
    a.jump(0x4909AC)

    a.label('action_paint')
    a.e(*NEW_HOOKS['action_paint'][1])
    save()
    a.e(b.sw(0, FRAME + 0x38, 29), b.lw(8, FRAME + 0x3C, 29), b.sw(8, TEMP, 29))
    a.absolute(9, 0x490A10)
    a.branch(4, 8, 9, 'action_paint_admitted')
    equals(8, 0x490A60, 'action_paint_done')
    a.label('action_paint_admitted')
    a.e(b.lw(5, FRAME + 0x70, 29))
    inherit(5, link.EXPLORER, 'action_paint_done')
    native_frame(link.FRAME)
    native_frame(link.RECORD, 0x18)
    constant(link.QUEUE, 0)
    constant(link.SITE, 0x43C868)
    a.e(b.lw(8, TEMP, 29))
    put(link.CALLER, 8)
    for field, register in ((link.CONTROLLER, 4), (link.ENGINE, 5),
                            (link.INPUT, 6), (link.METADATA, 7)):
        a.e(b.lw(8, SAVE[register], 29))
        put(field, 8)
    capture(link.PAINT)
    a.e(b.sw(2, FRAME + 0x38, 29))
    a.label('action_paint_done')
    restore()
    a.jump(0x43C870)

    a.label('action_paint_delivery')
    a.e(*NEW_HOOKS['action_paint_delivery'][1])
    save()
    a.e(b.lw(8, FRAME + 0x24, 29))
    equals(8, 0x43C918, 'action_paint_delivery_done')
    a.e(b.sw(0, FRAME + 0x40, 29), b.lw(8, SAVE[2], 29))
    a.branch(4, 8, 0, 'action_paint_delivery_done')
    a.e(b.sw(8, TEMP, 29), b.lw(8, 0x128, 16))
    a.branch(4, 8, 0, 'action_paint_delivery_done')
    a.e(b.lw(8, 0x10, 8))
    equals(8, 36, 'action_paint_delivery_done')
    a.e(b.lw(8, TEMP, 29), b.lw(5, 0x20, 8))  # Under the native +148 lock.
    inherit(5, link.PAINT, 'action_paint_delivery_done')
    a.e(b.lw(8, TEMP, 29))
    put(link.RECORD, 8)
    a.e(b.addiu(8, 8, 0xC))
    put(link.INPUT, 8)
    native_frame(link.FRAME, 0x28)
    constant(link.SITE, 0x4399E8)
    constant(link.CALLER, 0x43C918)
    put(link.CONTROLLER, 16)
    a.e(b.lw(8, TEMP, 29), b.lw(9, 8, 8))
    put(link.ENGINE, 9)
    a.e(b.lw(9, 0x1C, 8))
    put(link.METADATA, 9)
    capture(link.PAINT_DELIVERY)
    a.e(b.sw(2, FRAME + 0x40, 29))
    a.label('action_paint_delivery_done')
    restore()
    a.jump(0x4399F0)

    a.label('action_birth_capture')
    # This private helper replaces ONLY the old BIRTH wrapper's private JAL.
    # Native frames/JAL/RA and the old BIRTH-return carrier remain unchanged.
    a.e(b.addiu(29, 29, -FRAME), b.sw(31, RETURN_SAVE, 29))
    a.jump(labels['queue_birth_capture'], True)
    # Save the ACTUAL old-core result/state. Native entry arguments are still
    # owned by the predecessor wrapper at our SP+FRAME, not by current a0..a2.
    for register, offset in SAVE.items():
        a.e(b.sw(register, offset, 29))
    a.e(b.r_type(0, 0, 8, 0x10), b.sw(8, HI, 29),
        b.r_type(0, 0, 8, 0x12), b.sw(8, LO, 29),
        b.lw(8, RETURN_SAVE, 29), b.sw(8, SAVE[31], 29))
    a.branch(4, 2, 0, 'action_birth_done')
    a.e(b.lw(8, FRAME + SAVE[31], 29))
    equals(8, 0x45987C, 'action_birth_done')
    # E = predecessor wrapper SP+A0. Validate both exact native return PCs
    # BEFORE looking at the deeper consumer's invocation-local ID word.
    a.e(b.lw(8, FRAME + 0xA0 + 0x64, 29))
    equals(8, 0x43C970, 'action_birth_done')
    a.e(b.lw(5, FRAME + 0xA0 + 0x80, 29))
    inherit(5, link.PAINT_DELIVERY, 'action_birth_done')
    native_frame(link.FRAME, 0xA0)
    constant(link.SITE, 0x8B428C)
    constant(link.CALLER, 0x45987C)
    for field, register in ((link.ENGINE, 4), (link.INPUT, 5), (link.METADATA, 6)):
        a.e(b.lw(8, FRAME + SAVE[register], 29))
        put(field, 8)
    a.e(b.lw(8, SAVE[2], 29))
    put(link.BIRTH, 8)
    capture(link.BIRTH_LINK)
    a.label('action_birth_done')
    restore()
    a.e(b.r_type(31, 0, 0, 8), 0)

    original = bytearray(original)
    start, stop = labels['birth_entry'], labels['birth_enqueue_begin']
    old_call = b.j_type(3, labels['queue_birth_capture'])
    matches = [pc for pc in range(start, stop, 4)
               if struct.unpack_from('<I', original, pc - code_base)[0] == old_call]
    if len(matches) != 1 or struct.unpack_from('<I', original, matches[0] - code_base + 4)[0]:
        raise ValueError('expected one exact predecessor BIRTH private call')
    struct.pack_into('<I', original, matches[0] - code_base, b.j_type(3, a.labels['action_birth_capture']))
    result = bytes(original) + kernel + a.finish()
    end = code_base + len(result)
    if (end > 0x100000000 or code_base >> 28 != (end - 1) >> 28
            or max(action_link_buffer, code_base) < min(action_link_buffer + size, end)):
        raise ValueError('action link private code/journal overlap or leave jump region')
    merged = dict(labels, **{'action_link_' + name: value for name, value in core.items()})
    merged.update(a.labels)
    merged['action_birth_private_call'] = matches[0]
    return result, merged


def build(source, *, enable_reveal=False, capacity=1024, row_capacity=1024,
          operation_capacity=1024, scope_capacity=1024, birth_capacity=1024,
          transport_capacity=1024, renderer_capacity=1024, playback_dispatch_capacity=1024,
          action_link_capacity=1024):
    if enable_reveal is not False:
        raise ValueError('active reveal is not admitted: ' + ', '.join(MISSING_CONTRACTS))
    options = dict(capacity=capacity, row_capacity=row_capacity, operation_capacity=operation_capacity,
        scope_capacity=scope_capacity, birth_capacity=birth_capacity, transport_capacity=transport_capacity,
        renderer_capacity=renderer_capacity, playback_dispatch_capacity=playback_dispatch_capacity)
    golden, source_hash = normalize_source(source)
    _, parent_meta = previous.build(source, **options)
    journal = parent_meta['buffer'] + parent_meta['memory_bytes']
    journal_bytes = link.memory_bytes(action_link_capacity)
    total = parent_meta['memory_bytes'] + journal_bytes
    layout = plan_layout(golden, total)
    addresses = [parent_meta[name] for name in ('buffer', 'row_buffer', 'contents_revision_buffer',
        'operation_buffer', 'scope_buffer', 'birth_buffer', 'transport_buffer',
        'renderer_transport_buffer', 'playback_dispatch_buffer')]
    code, labels = assemble(addresses, journal, layout['code_base'], **options,
                            action_link_capacity=action_link_capacity)
    image, layout_meta = install_layout(golden, code, total)
    output = bytearray(image)
    for name, (pc, expected) in HOOKS.items():
        if struct.unpack_from('<2I', golden, pc - BASE) != expected:
            raise ValueError('unexpected original action link hook: ' + name)
        linked = name in LINKED
        struct.pack_into('<2I', output, pc - BASE, b.j_type(3 if linked else 2, labels[name]),
                         expected[1] if linked else 0)
    for pc, (expected, replacement) in STRIDES.items():
        if struct.unpack_from('<I', golden, pc - BASE)[0] != expected:
            raise ValueError('unexpected original action/paint element width')
        struct.pack_into('<I', output, pc - BASE, replacement)
    return bytes(output), dict(parent_meta, **layout_meta, labels=labels, memory_bytes=total,
        action_link_buffer=journal, action_link_memory_bytes=journal_bytes,
        action_link_capacity=action_link_capacity, action_link_record_bytes=link.RECORD_BYTES,
        input_sha256=source_hash, snapshot_format='lineage-rows-action-birth-link-v1',
        stage='explicit-general-notification-through-two-queues-to-birth-observation-only',
        action_element_bytes=20, original_action_element_bytes=16,
        paint_element_bytes=36, original_paint_element_bytes=32,
        historical_notification_link_enabled=True, notification_currentness_proven=False,
        native_paint_payload_lease_proven=False, missing_contracts=MISSING_CONTRACTS)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('output', type=Path)
    for name in CAPACITY_NAMES:
        parser.add_argument('--' + name, type=int, default=1024)
    args = parser.parse_args()
    image, meta = build(args.source.read_bytes(), **{
        name.replace('-', '_'): getattr(args, name.replace('-', '_')) for name in CAPACITY_NAMES})
    with args.output.open('xb') as stream:
        stream.write(image)
    print('sha256=' + hashlib.sha256(image).hexdigest())
    print({name: meta[name] for name in ('output_size', 'memory_bytes', 'code_bytes', 'stage', 'hardware', 'autoscroll')})
    print('OFFLINE HISTORICAL NOTIFICATION LINK ONLY; no native lease/coherent identity/UI authority')


if __name__ == '__main__':
    main()
