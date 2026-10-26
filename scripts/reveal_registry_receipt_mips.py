#!/usr/bin/env python3
"""Offline passive native registry-lock receipts, NOT owner admission/hooks.

Four in-memory fixture redirects preserve the original registration path,
including its unchecked raw failures and allocation-failure unlock defect.
No firmware builder or file-patching CLI imports this module. A receipt records
one raw-zero acquisition before publication, NOT release, initialized/retained
native storage, a generation, a lease, or permission to use/free an engine.

All bridge registers and HI/LO are restored before native continuation. Three
previously unused locals in the native40-byte frame carry per-call readiness,
the pinned mutex, and the exact raw status. The raw-call hook checks the actual
mutex argument BEFORE the service; the return hook captures BEFORE masking.
The publication hook consumes readiness once and never accesses shared journal
state unless this exact call captured raw zero for the pinned object.

Caller premises: genuine pinned native route/ABI, stable controller callback/
mutex fields, stable owned native stack and
an extra192 writable bytes at each bridge, no stack/code/state/controller/mutex
aliases, valid initialized ordinary mutex, retained controller/registry/node,
and common pinned13C synchronization for journal users. These are not proved by
pointer checks, return-PC gates, callback fingerprints, or the native factory.
Nonzero raw acquire may still own a robust/unknown mutex. No recovery, guessed
unlock, cleanup continuation or strengthening of stock behavior is performed.
All four redirects must be coherent; arbitrary partial activation is NOT
fail-closed. Global wrapper bridges need extra stack even on rejected routes.
"""

from build_reveal_bridge_diag import Asm, b


HEADER_BYTES, RECORD_BYTES = 16, 40
COUNT, FAULT, RESERVED0, RESERVED1 = 0, 4, 8, 12
MAGIC, SEQUENCE, CONTROLLER, MUTEX, NODE, ENGINE = 0, 4, 8, 12, 16, 20
NATIVE_SP, CALLER, SITE, STATUS = 24, 28, 32, 36
RECORD_MAGIC = int.from_bytes(b'R13C', 'little')
TAG, PTR, RAW_STATUS = 0x10, 0x14, 0x18
ARMED, ENTERED, CAPTURED = 0x52313341, 0x52313345, 0x52313343
REGISTRY_LOCK, REGISTRY_UNLOCK = 0x437D20, 0x437DA0
RAW_LOCK, RAW_UNLOCK = 0xA5B960, 0xA5B830
CONTROLLER_BYTES, MUTEX_BYTES = 0x28C, 24
NATIVE_RX = (0x400000, 0xA5BFA0)  # Exact02fd executable range, not spare RX.
FRAME, HI, LO, SYNC = 192, 0x88, 0x8C, 0xF
CALLBACK_REQUEST_OFFSET, CALLBACK_REQUEST_BYTES = 0x90, 36
SAVE = {register: 0x10 + index * 4
        for index, register in enumerate(r for r in range(1, 32) if r != 29)}
HOOKS = {
    'begin': (0x438A00, (0x8C990274, 0x00808021)),
    'raw_call': (0x466DA8, (0x0C296E58, 0)),
    'raw_return': (0x466DB0, (0x8FBF001C, 0x00001021)),
    'published': (0x438A58, (0xAC620000, 0x8E190278)),
}


def memory_bytes(capacity=16):
    if type(capacity) is not int or not 1 <= capacity <= 1024:
        raise ValueError('capacity must be in1..1024')
    return HEADER_BYTES + RECORD_BYTES * capacity


def hook_words(labels):
    """Instruction-fetch overrides for a local fixture, not an installer."""
    result = {}
    for name, (pc, _) in HOOKS.items():
        target = labels[name]
        if (type(target) is not int or target <= 0 or target % 4
                or target > 0xFFFFFFFC or (pc + 4) >> 28 != target >> 28):
            raise ValueError('hook target must share its native jump region')
        result[pc] = (b.j_type(2, target), 0)
    return result


def assemble(state_address, controller_address, registry_mutex_address, code_base,
             *, capacity=16, publication_callback=None):
    """Emit standalone bridge bytes/labels; journal is initially all zero.

    The journal is append-only, bounded and never reset/reused while visible.
    This is not an authentication scheme against forged native stack frames.
    """
    state_bytes = memory_bytes(capacity)
    extents = [('state', state_address, state_bytes),
               ('controller', controller_address, CONTROLLER_BYTES),
               ('mutex', registry_mutex_address, MUTEX_BYTES),
               ('code', code_base, 4)]
    for name, address, size in extents:
        if (type(address) is not int or not 0 < address <= 0xFFFFFFFC
                or address % 4 or address + size > 0x100000000):
            raise ValueError(name + ' must have a nonwrapping aligned extent')
    if code_base >> 28:
        raise ValueError('bridges must share the native jump region')
    callback_extent = None
    if publication_callback is not None:
        if (type(publication_callback) is not tuple or len(publication_callback) != 3
                or any(type(value) is not int for value in publication_callback)):
            raise ValueError('callback must be an (entry, code_start, code_bytes) tuple')
        entry, start, size = publication_callback
        if (start <= 0 or start % 4 or size <= 0 or size % 4
                or start + size > 0x10000000 or entry % 4
                or not start <= entry < start + size):
            raise ValueError('callback must lie within its nonwrapping native-region RX extent')
        callback_extent = (start, start + size)
        for _, address, extent_size in extents[:-1]:
            if max(start, address) < min(start + size, address + extent_size):
                raise ValueError('callback overlaps private data/controller/mutex')
        if max(start, NATIVE_RX[0]) < min(start + size, NATIVE_RX[1]):
            raise ValueError('callback overlaps pinned native RX')
    for index, (name, address, size) in enumerate(extents[:-1]):
        if max(address, NATIVE_RX[0]) < min(address + size, NATIVE_RX[1]):
            raise ValueError(name + ' overlaps the pinned native executable image')
        for other_name, other_address, other_size in extents[index + 1:-1]:
            if max(address, other_address) < min(address + size, other_address + other_size):
                raise ValueError(name + ' overlaps ' + other_name)
    a = Asm(code_base)

    def equal(register, value, failed):
        a.absolute(9, value)
        a.branch(5, register, 9, failed)

    def save(name):
        a.label(name)
        a.e(b.addiu(29, 29, -FRAME))
        for register, offset in SAVE.items():
            a.e(b.sw(register, offset, 29))
        a.e(b.r_type(0, 0, 8, 0x10), b.sw(8, HI, 29),
            b.r_type(0, 0, 8, 0x12), b.sw(8, LO, 29),
            b.addiu(23, 29, FRAME))

    def restore():
        a.e(b.lw(8, HI, 29), b.r_type(8, 0, 0, 0x11),
            b.lw(8, LO, 29), b.r_type(8, 0, 0, 0x13))
        for register, offset in SAVE.items():
            a.e(b.lw(register, offset, 29))
        a.e(b.addiu(29, 29, FRAME))

    def controller_fields(register, failed):
        equal(register, controller_address, failed)
        for offset, expected in ((0x274, REGISTRY_LOCK), (0x278, REGISTRY_UNLOCK),
                                 (0x13C, registry_mutex_address)):
            a.e(b.lw(8, offset, register))
            equal(8, expected, failed)

    def raw_scope(failed):
        # W is the original466DA0 frame. Gate its saved callback return
        # before reading the deeper frame, and gate native return before
        # touching the original registration's private locals.
        a.e(b.lw(8, 0x1C, 23))
        equal(8, 0x437D30, failed)
        a.e(b.lw(8, 0x3C, 23))
        equal(8, 0x438A10, failed)
        equal(16, controller_address, failed)

    a.label('begin')
    # Snapshot the actual selected callback before any observer work. It is
    # this restored T9, not a later controller-field reread, that native code
    # will call at438A08.
    a.e(b.lw(25, 0x274, 4), b.move(16, 4))
    save('begin_saved')
    # Fresh per invocation, even for an unclassified/rebound callback route.
    a.e(b.sw(0, TAG, 23), b.sw(0, PTR, 23), b.addiu(8, 0, -1),
        b.sw(8, RAW_STATUS, 23))
    controller_fields(16, 'begin_done')
    equal(25, REGISTRY_LOCK, 'begin_done')
    a.absolute(8, registry_mutex_address)
    a.e(b.sw(8, PTR, 23))
    a.absolute(8, ARMED)
    a.e(b.sw(8, TAG, 23))
    a.label('begin_done')
    restore()
    a.jump(0x438A08)

    save('raw_call')
    raw_scope('raw_call_done')
    a.e(b.lw(8, 0x40 + TAG, 23), b.sw(0, 0x40 + TAG, 23))
    equal(8, ARMED, 'raw_call_done')
    a.e(b.lw(8, 0x40 + PTR, 23))
    equal(8, registry_mutex_address, 'raw_call_done')
    a.e(b.lw(8, 0x40 + RAW_STATUS, 23))
    equal(8, 0xFFFFFFFF, 'raw_call_done')
    equal(4, registry_mutex_address, 'raw_call_done')
    a.absolute(8, ENTERED)
    a.e(b.sw(8, 0x40 + TAG, 23))
    a.label('raw_call_done')
    restore()
    # Preserve the original call's native return PC and raw argument homes.
    # The PLT/import body remains a separate runtime/lifetime premise.
    a.absolute(31, 0x466DB0)
    a.jump(RAW_LOCK)

    save('raw_return')
    raw_scope('raw_return_done')
    a.e(b.lw(8, 0x40 + TAG, 23), b.sw(0, 0x40 + TAG, 23))
    equal(8, ENTERED, 'raw_return_done')
    a.e(b.lw(8, 0x40 + PTR, 23))
    equal(8, registry_mutex_address, 'raw_return_done')
    a.e(b.lw(8, SAVE[2], 29), b.sw(8, 0x40 + RAW_STATUS, 23))
    a.absolute(8, CAPTURED)
    a.e(b.sw(8, 0x40 + TAG, 23))
    a.label('raw_return_done')
    restore()
    a.e(b.lw(31, 0x1C, 29), b.move(2, 0))
    a.jump(0x466DB8)

    a.label('published')
    # Complete the final native link store before any observer activity.
    a.e(b.sw(2, 0, 3))
    save('published_saved')
    a.e(b.lw(8, TAG, 23), b.sw(0, TAG, 23))
    equal(8, CAPTURED, 'published_done')
    a.e(b.lw(8, PTR, 23))
    equal(8, registry_mutex_address, 'published_done')
    a.e(b.lw(8, RAW_STATUS, 23))
    a.branch(5, 8, 0, 'published_done')
    controller_fields(16, 'published_done')
    a.absolute(20, state_address)
    # Only now is a journal access admitted under the pinned raw-zero guard.
    a.e(b.lw(8, FAULT, 20))
    a.branch(5, 8, 0, 'published_done')
    for offset in (RESERVED0, RESERVED1):
        a.e(b.lw(8, offset, 20))
        a.branch(5, 8, 0, 'journal_fault')
    a.e(b.lw(21, COUNT, 20))
    a.absolute(9, capacity)
    a.e(b.r_type(9, 21, 8, 0x2B))
    a.branch(5, 8, 0, 'journal_fault')
    # Validate the issued prefix without dereferencing old native addresses.
    # A corrupted count must not skip holes or overwrite a published receipt.
    a.e(b.addiu(22, 20, HEADER_BYTES), b.move(18, 0))
    a.label('journal_rows')
    a.branch(4, 18, 21, 'journal_rows_done')
    a.e(b.lw(8, MAGIC, 22))
    equal(8, RECORD_MAGIC, 'journal_fault')
    a.e(b.addiu(18, 18, 1), b.lw(8, SEQUENCE, 22))
    a.branch(5, 8, 18, 'journal_fault')
    for offset, expected in ((CONTROLLER, controller_address),
                             (MUTEX, registry_mutex_address), (SITE, 0x438A5C),
                             (STATUS, 0)):
        a.e(b.lw(8, offset, 22))
        equal(8, expected, 'journal_fault')
    a.e(b.addiu(22, 22, RECORD_BYTES))
    a.jump('journal_rows')
    a.label('journal_rows_done')
    a.absolute(9, capacity)
    a.branch(4, 21, 9, 'published_done')
    # Never reuse even an incompletely written target slot.
    for offset in range(0, RECORD_BYTES, 4):
        a.e(b.lw(8, offset, 22))
        a.branch(5, 8, 0, 'journal_fault')
    if publication_callback is not None:
        # This request is owned by this exact native invocation, not a
        # mutable/latest journal row. The caller-supplied generated callback
        # must preserve every register and HI/LO; its snapshot lives outside
        # both o32 homes and this bridge's saved architectural state.
        request = CALLBACK_REQUEST_OFFSET
        a.e(b.sw(16, request, 29))
        a.absolute(8, registry_mutex_address)
        a.e(b.sw(8, request + 4, 29), b.lw(8, SAVE[2], 29),
            b.sw(8, request + 8, 29), b.lw(8, 8, 8),
            b.sw(8, request + 12, 29), b.sw(23, request + 16, 29),
            b.lw(8, 0x24, 23), b.sw(8, request + 20, 29))
        a.absolute(8, 0x438A5C)
        a.e(b.sw(8, request + 24, 29), b.sw(0, request + 28, 29),
            b.addiu(8, 21, 1), b.sw(8, request + 32, 29),
            b.move(4, 16), b.addiu(5, 29, request))
        a.jump(publication_callback[0], link=True)
        # Callback ABI preserves its arguments as supplied, whereas native
        # A0/A1 must still be the original observer-entry values on return.
        a.e(b.lw(4, SAVE[4], 29), b.lw(5, SAVE[5], 29))
    a.e(b.addiu(21, 21, 1),
        b.sw(0, MAGIC, 22), b.sw(21, SEQUENCE, 22), b.sw(16, CONTROLLER, 22))
    a.absolute(8, registry_mutex_address)
    a.e(b.sw(8, MUTEX, 22), b.lw(8, SAVE[2], 29), b.sw(8, NODE, 22),
        b.lw(9, 8, 8), b.sw(9, ENGINE, 22), b.sw(23, NATIVE_SP, 22),
        b.lw(8, 0x24, 23), b.sw(8, CALLER, 22))
    a.absolute(8, 0x438A5C)
    a.e(b.sw(8, SITE, 22), b.sw(0, STATUS, 22), SYNC)
    a.absolute(8, RECORD_MAGIC)
    a.e(b.sw(8, MAGIC, 22), SYNC, b.sw(21, COUNT, 20))
    a.jump('published_done')
    a.label('journal_fault')
    a.e(b.addiu(8, 0, 1), b.sw(8, FAULT, 20), SYNC)
    a.label('published_done')
    restore()
    a.e(b.lw(25, 0x278, 16))
    a.jump(0x438A60)

    result = a.finish()
    code_end = code_base + len(result)
    if code_end > 0x10000000:
        raise ValueError('code leaves its native MIPS jump region')
    if max(code_base, NATIVE_RX[0]) < min(code_end, NATIVE_RX[1]):
        raise ValueError('code overlaps the pinned native executable image')
    if callback_extent is not None:
        if max(code_base, callback_extent[0]) < min(code_end, callback_extent[1]):
            raise ValueError('receipt code overlaps callback RX extent')
    for name, address, size in extents[:-1]:
        if max(code_base, address) < min(code_end, address + size):
            raise ValueError('code overlaps ' + name)
    # Validate the exact generated entrypoints, not a guessed code envelope.
    hook_words(a.labels)
    return result, a.labels
