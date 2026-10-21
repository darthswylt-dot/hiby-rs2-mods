#!/usr/bin/env python3
"""Native diagnostic job-lineage transport; OFFLINE, not an active reveal.

The stock 0x2C4-byte template/prefix is unchanged. Only internally allocated
master/work list elements gain a four-byte private tail. Native list copies
carry the original invocation ID; borrow/query/producer receipts have their
own non-reused IDs. No name lookup, pointer-key registry or UI call is added.
Raw V/P consistency is NOT lifetime, content ownership, or row readiness.
No installer, timer, I/O, device operation or stock synchronization repair.
"""
import argparse
import hashlib
import struct
from pathlib import Path

from build_reveal_bridge_diag import Asm, BASE, FRAME, SAVE, HI, LO, b, normalize_source
import folderfollow_reveal_lineage_mips as core
from reveal_bridge_elf import plan_layout, install_layout


PREFIX, TAIL, ELEMENT = 0x2C4, 0x2C4, 0x2C8
LOCAL_TAIL = 0x18 + TAIL
RENDER_TICKET, WORKER_BORROW = 0x14, 0xAA0
QUERY_FRAME_MAGIC = 0x59514E4C  # LNQY, only in our temporary query wrapper.
QUERY_TICKET, QUERY_MAGIC = 0x18, 0x1C
HOOKS = {
    'render': (0x490758, (0x00408021, 0x244438AC)),
    'enqueue_stamp': (0x48F1D0, (0x8E040130, 0x8C990024)),
    'initial_stamp': (0x48F40C, (0x8E040130, 0x8C990018)),
    'borrow': (0x48EB40, (0x8E040010, 0x24160001)),
    'query': (0x48D1B8, (0x0C1BDF28, 0xAFB00010)),
    'producer': (0x6ED624, (0x2652B328, 0x2694C540)),
}
STRIDES = {0x48F3BC: (0x240502C4, 0x240502C8),
           0x48F3CC: (0x240502C4, 0x240502C8)}
MISSING_CONTRACTS = (
    'retained-native-view-and-list-lifetime',
    'complete-template-prefix-writer-and-cancellation-coverage',
    'contents-operation-and-playback-generation-association',
    'coherent-full-row-publication-and-owned-ui-action',
    'hardware-validation-of-new-reads-layout-and-timing',
)


def assemble(state_address, code_base, *, capacity=1024,
             producer_revision_address=None, origin_entry_offset=None):
    # Optional diagnostic extension; the default image remains byte-identical.
    # A sampled producer revision is not an original-render epoch or a lease.
    if (origin_entry_offset is not None
            and (type(origin_entry_offset) is not int or origin_entry_offset != 0x10)):
        raise ValueError('only the audited renderer entry carrier at SP10 is admitted')
    if producer_revision_address is not None:
        if (type(producer_revision_address) is not int
                or not 0 <= producer_revision_address <= 0xFFFFFFFC
                or producer_revision_address % 4):
            raise ValueError('producer revision must be an aligned unsigned-32 address')
        if (state_address < producer_revision_address + 4
                and producer_revision_address < state_address + core.memory_bytes(capacity)):
            raise ValueError('producer revision must be outside lineage storage')
    kernel, entries = core.build_lineage(state_address, code_base, capacity=capacity)
    a = Asm(code_base + len(kernel))
    address_fixups = []

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

    def finish(name):
        restore()
        a.e(*HOOKS[name][1])
        a.jump(HOOKS[name][0] + 8)

    def publish():
        a.e(0xF)
        a.absolute(8, core.MAGIC)
        a.e(b.sw(8, 0, 2))

    def value(reg, constant):
        a.absolute(reg, constant)

    def payload(site, *, job=None, destination=None, stack_delta=0):
        if job is not None:
            a.e(b.sw(job, core.JOB, 2))
        if destination is not None:
            a.e(b.sw(destination, core.DEST, 2))
        value(8, site)
        a.e(b.sw(8, core.SITE, 2), b.addiu(8, 29, FRAME + stack_delta),
            b.sw(8, core.STACK, 2))

    def label_address(reg, label):
        address_fixups.append((len(a.w), reg, label))
        a.e(0, 0)

    # Before the renderer writes its stock job template. Only a numeric
    # original association is copied. The unused native stack word is not
    # an outgoing argument-home word and is not a native object field.
    a.label('render')
    save()
    a.e(b.sw(0, FRAME + RENDER_TICKET, 29), b.addiu(4, 0, core.RENDER),
        b.move(5, 0), b.lw(6, SAVE[2], 29), b.move(7, 18))
    a.jump(entries['reserve'], True)
    a.branch(4, 2, 0, 'render_done')
    a.e(b.lw(8, SAVE[2], 29), b.addiu(8, 8, 0x38A4))
    payload(HOOKS['render'][0], job=8)
    if origin_entry_offset is not None:
        # Exact ticket returned at THIS guarded renderer entry, not a later
        # read of the current global counter or the native job template.
        a.e(b.lw(8, FRAME + origin_entry_offset, 29), b.sw(8, 60, 2))
    publish()
    a.e(b.sw(3, FRAME + RENDER_TICKET, 29))
    a.label('render_done')
    finish('render')

    # Stamp a fresh local record AFTER the unchanged 708-byte prefix copy
    # and callback resolver, but BEFORE append. Untracked ingress stays zero.
    a.label('enqueue_stamp')
    save()
    a.e(b.sw(0, FRAME + LOCAL_TAIL, 29),
        b.lw(8, FRAME + 0x18 + 0x2C0, 29))
    value(9, 0x48D280)
    a.branch(5, 8, 9, 'enqueue_done')
    a.e(b.lw(8, FRAME + 0x2EC, 29))
    for caller in (0x490814, 0x490880):
        value(9, caller)
        a.branch(4, 8, 9, 'enqueue_known')
    a.jump('enqueue_done')
    a.label('enqueue_known')
    a.e(b.lw(4, FRAME + 0x2F0 + RENDER_TICKET, 29), b.sw(4, 0x18, 29),
        b.addiu(5, 0, core.RENDER))
    a.jump(entries['validate'], True)
    a.branch(4, 2, 0, 'enqueue_done')
    a.e(b.lw(8, core.STACK, 2), b.addiu(9, 29, FRAME + 0x2F0))
    a.branch(5, 8, 9, 'enqueue_fault')
    a.e(b.lw(8, core.JOB, 2))
    a.branch(5, 8, 17, 'enqueue_fault')  # s1 is the original template arg.
    for field, off in ((core.VIEW, 0x2B4), (core.PANEL, 0x2B0)):
        a.e(b.lw(8, field, 2), b.lw(9, FRAME + 0x18 + off, 29))
        a.branch(5, 8, 9, 'enqueue_fault')
    a.e(b.lw(8, 0x18, 29), 0xF, b.sw(8, FRAME + LOCAL_TAIL, 29))
    a.jump('enqueue_done')
    a.label('enqueue_fault')
    a.jump(entries['invalidate'], True)
    a.label('enqueue_done')
    finish('enqueue_stamp')

    # Initial PRIVATE worker ingress has no renderer parent. Mint a distinct
    # initial-enqueue invocation from its already copied local P/V scalars.
    # This is later than the first synchronous fill, not its contents epoch.
    a.label('initial_stamp')
    save()
    a.e(b.sw(0, FRAME + LOCAL_TAIL, 29),
        b.lw(8, FRAME + 0x2F4, 29))
    value(9, 0x492A38)
    a.branch(5, 8, 9, 'initial_done')
    a.e(b.lw(8, FRAME + 0x18 + 0x2C0, 29))
    value(9, 0x48D280)
    a.branch(5, 8, 9, 'initial_done')
    a.e(b.lw(6, FRAME + 0x18 + 0x2B4, 29),
        b.lw(7, FRAME + 0x18 + 0x2B0, 29))
    a.branch(4, 6, 0, 'initial_fault')
    a.branch(4, 7, 0, 'initial_fault')
    a.e(b.addiu(8, 6, 0x38A4))
    a.branch(5, 8, 19, 'initial_fault')  # s3 was the template argument.
    a.e(b.addiu(4, 0, core.INITIAL), b.move(5, 0))
    a.jump(entries['reserve'], True)
    a.branch(4, 2, 0, 'initial_done')
    payload(HOOKS['initial_stamp'][0], job=19)
    publish()
    a.e(0xF, b.sw(3, FRAME + LOCAL_TAIL, 29))
    a.jump('initial_done')
    a.label('initial_fault')
    a.jump(entries['invalidate'], True)
    a.label('initial_done')
    finish('initial_stamp')

    # Capture at the nonnull stock work-list borrow, BEFORE its later name
    # lookup. Never recover this association by job address in a callback.
    a.label('borrow')
    save()
    a.e(b.sw(0, FRAME + WORKER_BORROW, 29), b.lw(5, TAIL, 17))
    a.branch(4, 5, 0, 'borrow_done')  # Unsupported jobs carry no lineage.
    a.e(b.addiu(4, 0, core.BORROW), b.move(6, 0), b.move(7, 0))
    a.jump(entries['reserve'], True)
    a.branch(4, 2, 0, 'borrow_done')
    payload(HOOKS['borrow'][0], job=17)
    publish()
    a.e(b.sw(3, FRAME + WORKER_BORROW, 29))
    a.label('borrow_done')
    finish('borrow')

    # Original JAL delay-slot fifth-argument store runs at ORIGINAL SP.
    # Our frame owns the saved receipt and rehomes that argument for the
    # real query call exactly once. No native lock is added or held by us.
    a.label('query')
    save()
    a.e(b.sw(0, QUERY_TICKET, 29), b.sw(0, QUERY_MAGIC, 29),
        b.lw(8, FRAME + 0x3C, 29))
    value(9, 0x48EC5C)
    a.branch(5, 8, 9, 'query_original')
    a.e(b.lw(4, FRAME + 0x40 + WORKER_BORROW, 29),
        b.sw(4, QUERY_TICKET, 29), b.addiu(5, 0, core.BORROW))
    a.jump(entries['validate'], True)
    a.branch(4, 2, 0, 'query_unbound')
    a.e(b.lw(8, core.JOB, 2), b.addiu(9, 16, -0x88))
    a.branch(5, 8, 9, 'query_fault')
    a.e(b.lw(8, core.STACK, 2), b.addiu(9, 29, FRAME + 0x40))
    a.branch(5, 8, 9, 'query_fault')
    a.e(b.lw(8, core.ORIGIN, 2), b.lw(9, TAIL - 0x88, 16))
    a.branch(5, 8, 9, 'query_fault')
    a.e(b.lw(8, core.VIEW, 2), b.lw(9, FRAME + 0x20, 29))
    a.branch(5, 8, 9, 'query_fault')
    a.e(b.lw(8, core.PANEL, 2))
    a.branch(5, 8, 17, 'query_fault')
    a.e(b.lw(8, SAVE[7], 29))
    a.branch(5, 8, 0, 'query_fault')
    a.e(b.addiu(4, 0, core.QUERY), b.lw(5, QUERY_TICKET, 29),
        b.move(6, 0), b.move(7, 0))
    a.jump(entries['reserve'], True)
    a.branch(4, 2, 0, 'query_unbound')
    a.e(b.addiu(8, 16, -0x88), b.lw(9, SAVE[4], 29))
    payload(HOOKS['query'][0], job=8, destination=9)
    for reg, off in ((5, core.OFFSET), (6, core.REQUEST)):
        a.e(b.lw(8, SAVE[reg], 29), b.sw(8, off, 2))
    publish()
    a.e(b.sw(3, QUERY_TICKET, 29))
    value(8, QUERY_FRAME_MAGIC)
    a.e(b.sw(8, QUERY_MAGIC, 29))
    a.jump('query_original')
    a.label('query_fault')
    a.jump(entries['invalidate'], True)
    a.label('query_unbound')
    a.e(b.sw(0, QUERY_TICKET, 29), b.sw(0, QUERY_MAGIC, 29))
    a.label('query_original')
    a.e(b.lw(8, FRAME + 0x10, 29), b.sw(8, 0x10, 29))
    restore(False)
    a.jump(0x6F7CA0, True)
    a.label('query_native_return')
    save()  # Preserve native RESULT state, including HI/LO and home writes.
    restore()
    a.e(b.lw(31, SAVE[31], 29), b.addiu(29, 29, FRAME),
        b.r_type(31, 0, 0, 8), 0)

    # The two physical query return PCs prove which stock query frame to
    # inspect. Its saved RA must be OUR query wrapper before reading any of
    # that wrapper's private receipt/magic. There is no current-view lookup.
    a.label('producer')
    save()
    a.e(b.sw(0, FRAME + 0x18, 29), b.lw(8, FRAME + 0xACC, 29))
    for caller in (0x6F8BF4, 0x6F8E0C):
        value(9, caller)
        a.branch(4, 8, 9, 'producer_physical')
    a.jump('producer_done')
    a.label('producer_physical')
    a.e(b.lw(8, FRAME + 0xAD0 + 0xBDC, 29))
    label_address(9, 'query_native_return')
    a.branch(5, 8, 9, 'producer_done')
    a.e(b.lw(8, FRAME + 0xAD0 + 0xBE0 + QUERY_MAGIC, 29))
    value(9, QUERY_FRAME_MAGIC)
    a.branch(5, 8, 9, 'producer_done')
    a.e(b.lw(4, FRAME + 0xAD0 + 0xBE0 + QUERY_TICKET, 29),
        b.sw(4, 0x18, 29), b.addiu(5, 0, core.QUERY))
    a.jump(entries['validate'], True)
    a.branch(4, 2, 0, 'producer_done')
    a.e(b.lw(8, core.STACK, 2), b.addiu(9, 29, FRAME + 0xAD0 + 0xBE0 + FRAME))
    a.branch(5, 8, 9, 'producer_fault')
    a.e(b.lw(8, core.DEST, 2))
    a.branch(5, 8, 22, 'producer_fault')  # s6 = original producer list.
    a.e(b.lw(8, core.OFFSET, 2), b.lw(9, FRAME + 0xAD8, 29))
    a.branch(5, 8, 9, 'producer_fault')
    a.e(b.lw(8, core.REQUEST, 2))
    a.branch(5, 8, 17, 'producer_fault')  # s1 = limit, before row ordinal.
    a.branch(5, 23, 0, 'producer_fault')  # Mode-zero only.
    a.e(b.lw(8, core.JOB, 2), b.sw(8, 0x1C, 29),
        b.addiu(4, 0, core.PRODUCER), b.lw(5, 0x18, 29),
        b.move(6, 0), b.move(7, 0))
    a.jump(entries['reserve'], True)
    a.branch(4, 2, 0, 'producer_done')
    a.e(b.lw(8, 0x1C, 29))
    payload(HOOKS['producer'][0], job=8, destination=22)
    a.e(b.lw(8, FRAME + 0xAD8, 29), b.sw(8, core.OFFSET, 2),
        b.sw(17, core.REQUEST, 2), b.sw(16, core.STMT, 2))
    if producer_revision_address is not None:
        value(8, producer_revision_address)
        a.e(0xF, b.lw(8, 0, 8), b.sw(8, 56, 2), 0xF)
    publish()
    a.e(b.sw(3, FRAME + 0x18, 29))
    a.jump('producer_done')
    a.label('producer_fault')
    a.jump(entries['invalidate'], True)
    a.label('producer_done')
    finish('producer')

    for index, reg, name in address_fixups:
        target = a.labels[name]
        a.w[index:index + 2] = [b.lui(reg, target >> 16), b.ori(reg, reg, target & 0xFFFF)]
    labels = dict(a.labels, **{'lineage_' + name: addr for name, addr in entries.items()})
    result = kernel + a.finish()
    if (producer_revision_address is not None
            and code_base < producer_revision_address + 4
            and producer_revision_address < code_base + len(result)):
        raise ValueError('producer revision must be outside emitted code')
    return result, labels


def build(source, *, enable_reveal=False, capacity=1024):
    if enable_reveal is not False:
        raise ValueError('active reveal is not admitted: ' + ', '.join(MISSING_CONTRACTS))
    golden, source_hash = normalize_source(source)
    memory_bytes = core.memory_bytes(capacity)
    layout = plan_layout(golden, memory_bytes)
    code, labels = assemble(layout['buffer'], layout['code_base'], capacity=capacity)
    image, meta = install_layout(golden, code, memory_bytes)
    out = bytearray(image)
    for name, (pc, expected) in HOOKS.items():
        if struct.unpack_from('<2I', golden, pc - BASE) != expected:
            raise ValueError('unexpected original hook: ' + name)
        linked = name == 'query'
        struct.pack_into('<2I', out, pc - BASE,
                         b.j_type(3 if linked else 2, labels[name]),
                         expected[1] if linked else 0)
    for pc, (expected, replacement) in STRIDES.items():
        if struct.unpack_from('<I', golden, pc - BASE)[0] != expected:
            raise ValueError('unexpected original stride')
        struct.pack_into('<I', out, pc - BASE, replacement)
    return bytes(out), dict(meta, labels=labels, memory_bytes=memory_bytes,
                           capacity=capacity, input_sha256=source_hash,
                           stage='native-job-lineage-only', autoscroll=False,
                           hardware='UNTESTED', prefix_bytes=PREFIX, element_bytes=ELEMENT,
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
    print('OFFLINE INTERMEDIATE ONLY; no active reveal; hardware UNTESTED; no deployment')


if __name__ == '__main__':
    main()
