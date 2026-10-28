#!/usr/bin/env python3
"""Offline append-only historical births, NOT a live-incarnation sidecar.

observe(U, owned32_event) is an all-register-preserving callback for a coherent
native publication observer.  Its caller has freshly confirmed raw R=0 for
this exact invocation and still genuinely holds the pinned ordinary mutex.
The eight event words are U, R, node, engine, native SP, caller, publication
site and raw status.  Pointer-looking event words remain historical scalars:
this callback never dereferences a node, engine, native SP or caller.

This independent bounded history does not depend on receipt/binding/owner
quotas.  Its own full/corrupt storage latches a permanent fault under R; it
never resets, reuses a token, replaces an older address, or claims continuous
coverage.  A masked native raw-lock failure can still mutate the native ring
without a safely writable historical event.  Missing events, raw failures,
all unlink/free paths and whole-instance external isolation therefore remain
integration gates.  There is no LIVE state, tombstone, query, lease, cleanup
authority, raw service, native call, installer, image or device operation.

All GPRs and HI/LO, including V0/V1, survive both admission and refusal.  The
independent retained writable192-byte save frame is a caller premise because
it is saved before validation, as in the existing receipt/issuer callbacks.
Arithmetic/frame/input exclusions precede input/controller/history loads, not
those initial architectural-save stores.  They establish neither mapping nor
nonaliasing with unknown native allocations or transitive native stacks.
"""

from build_reveal_bridge_diag import Asm, b
import reveal_registry_receipt_mips as receipt


HEADER_BYTES, RECORD_BYTES, REQUEST_BYTES = 16, 40, 32
EVENT_BYTES = REQUEST_BYTES
COUNT, FAULT, RESERVED0, RESERVED1 = 0, 4, 8, 12
MAGIC, TOKEN, CONTROLLER, MUTEX, NODE, ENGINE = 0, 4, 8, 12, 16, 20
NATIVE_SP, CALLER, SITE, STATUS = 24, 28, 32, 36
RECORD_MAGIC = int.from_bytes(b'BRTH', 'little')
REQUEST_CONTROLLER, REQUEST_REGISTRY_MUTEX = 0, 4
REQUEST_NODE, REQUEST_ENGINE, REQUEST_NATIVE_SP, REQUEST_CALLER = 8, 12, 16, 20
REQUEST_SITE, REQUEST_RAW_STATUS = 24, 28
PUBLICATION_SITE = 0x438A5C
CONTROLLER_BYTES, MUTEX_BYTES = receipt.CONTROLLER_BYTES, receipt.MUTEX_BYTES
REGISTRY_LOCK, REGISTRY_UNLOCK = receipt.REGISTRY_LOCK, receipt.REGISTRY_UNLOCK
NATIVE_RX, SYNC = receipt.NATIVE_RX, 0xF
FRAME, HI, LO, SNAPSHOT = 192, 0x88, 0x8C, 0x90
SAVE = {register: 0x10 + index * 4
        for index, register in enumerate(r for r in range(1, 32) if r != 29)}


def memory_bytes(capacity=16):
    if type(capacity) is not int or not 1 <= capacity <= 1024:
        raise ValueError('capacity must be in1..1024')
    return HEADER_BYTES + RECORD_BYTES * capacity


def assemble(state_address, controller_address, registry_mutex_address, code_base,
             *, capacity=16, protected_code=None, extra_protected_data=()):
    """Return historical callback bytes/labels without allocating/activating it.

    The zero-initialized history is append-only and all of its users share R.
    Its complete occupied prefix and entire unused tail are validated before
    append.  Full storage is a permanent fault rather than a successful drop.
    Invalid event/route/storage extents refuse before any history access.

    protected_code=(start,bytes) must contain this complete fragment.  None
    protects only this fragment.  Both modes have identical word counts for
    two-pass composition.  extra_protected_data is a strict tuple of aligned
    (start,bytes) exclusions; all fixed ranges must be pairwise disjoint.
    Schema checks are not authentication of an arbitrary caller/event or R
    ownership.  No output record or return value asserts that an allocation
    remains live, that native release succeeded, or that coverage is complete.
    """
    state_bytes = memory_bytes(capacity)
    extents = [('birth history', state_address, state_bytes),
               ('controller', controller_address, CONTROLLER_BYTES),
               ('registry mutex', registry_mutex_address, MUTEX_BYTES)]
    if type(extra_protected_data) is not tuple:
        raise ValueError('extra protected data must be a tuple of aligned extents')
    for index, item in enumerate(extra_protected_data):
        if (type(item) is not tuple or len(item) != 2
                or any(type(value) is not int for value in item)):
            raise ValueError('extra protected data must contain (start,bytes) tuples')
        start, size = item
        if size <= 0 or size % 4:
            raise ValueError('extra protected sizes must be positive aligned words')
        extents.append(('extra data ' + str(index), start, size))
    for name, address, size in (*extents, ('code', code_base, 4)):
        if (type(address) is not int or not 0 < address <= 0xFFFFFFFC
                or address % 4 or address + size > 0x100000000):
            raise ValueError(name + ' must have a nonwrapping aligned extent')
    if code_base >> 28:
        raise ValueError('birth callback must share the native jump region')
    for index, (name, address, size) in enumerate(extents):
        if max(address, NATIVE_RX[0]) < min(address + size, NATIVE_RX[1]):
            raise ValueError(name + ' overlaps pinned native RX')
        for other_name, other, other_size in extents[index + 1:]:
            if max(address, other) < min(address + size, other + other_size):
                raise ValueError(name + ' overlaps ' + other_name)

    protected_start, protected_end = code_base, None
    if protected_code is not None:
        if (type(protected_code) is not tuple or len(protected_code) != 2
                or any(type(value) is not int for value in protected_code)):
            raise ValueError('protected code must be an (RX start,bytes) tuple')
        protected_start, protected_bytes = protected_code
        protected_end = protected_start + protected_bytes
        if (protected_start <= 0 or protected_start % 4 or protected_bytes <= 0
                or protected_bytes % 4 or protected_end > 0x10000000
                or not protected_start <= code_base < protected_end):
            raise ValueError('protected code must contain the birth callback')
        if max(protected_start, NATIVE_RX[0]) < min(protected_end, NATIVE_RX[1]):
            raise ValueError('protected code overlaps pinned native RX')
        for name, address, size in extents:
            if max(protected_start, address) < min(protected_end, address + size):
                raise ValueError('protected code overlaps ' + name)

    a = Asm(code_base)
    end_fixups = []
    protected = [*extents,
                 ('native RX', NATIVE_RX[0], NATIVE_RX[1] - NATIVE_RX[0]),
                 ('generated RX', protected_start,
                  None if protected_end is None else protected_end - protected_start)]

    def equal(register, value, failed):
        a.absolute(9, value)
        a.branch(5, register, 9, failed)

    def nonoverlap(first, last, start, end, failed, label):
        a.absolute(10, start)
        a.e(b.r_type(last, 10, 9, 0x2B))
        a.branch(5, 9, 0, label)
        if end is None:
            end_fixups.append(len(a.w))
            a.absolute(10, 0)
        else:
            a.absolute(10, end - 1)
        a.e(b.r_type(10, first, 9, 0x2B))
        a.branch(5, 9, 0, label)
        a.jump(failed)
        a.label(label)

    def exclusions(first, last, failed, prefix):
        for index, (_, address, size) in enumerate(protected):
            nonoverlap(first, last, address, None if size is None else address + size,
                       failed, prefix + '_extent_' + str(index))

    a.label('observe')
    a.label('save_frame')
    a.e(b.addiu(29, 29, -FRAME))
    for register, offset in SAVE.items():
        a.e(b.sw(register, offset, 29))
    a.e(b.r_type(0, 0, 8, 0x10), b.sw(8, HI, 29),
        b.r_type(0, 0, 8, 0x12), b.sw(8, LO, 29),
        b.addiu(23, 29, FRAME))
    equal(4, controller_address, 'restore')
    a.e(b.i_type(12, 23, 8, 7))
    a.branch(5, 8, 0, 'restore')
    a.e(b.i_type(11, 23, 8, FRAME))
    a.branch(5, 8, 0, 'restore')
    a.e(b.addiu(12, 23, -1))
    exclusions(29, 12, 'restore', 'frame')
    a.branch(4, 5, 0, 'restore')
    a.e(b.i_type(12, 5, 8, 3))
    a.branch(5, 8, 0, 'restore')
    a.e(b.addiu(13, 5, REQUEST_BYTES - 1), b.r_type(13, 5, 8, 0x2B))
    a.branch(5, 8, 0, 'restore')
    exclusions(5, 13, 'restore', 'request')
    a.e(b.r_type(13, 29, 8, 0x2B))
    a.branch(5, 8, 0, 'request_frame_ok')
    a.e(b.r_type(12, 5, 8, 0x2B))
    a.branch(4, 8, 0, 'restore')
    a.label('request_frame_ok')
    for offset in range(0, REQUEST_BYTES, 4):
        a.e(b.lw(8, offset, 5), b.sw(8, SNAPSHOT + offset, 29))
    a.label('snapshot_done')
    for offset, expected in ((REQUEST_CONTROLLER, controller_address),
                             (REQUEST_REGISTRY_MUTEX, registry_mutex_address),
                             (REQUEST_SITE, PUBLICATION_SITE), (REQUEST_RAW_STATUS, 0)):
        a.e(b.lw(8, SNAPSHOT + offset, 29))
        equal(8, expected, 'restore')
    for offset, expected in ((0x13C, registry_mutex_address),
                             (0x274, REGISTRY_LOCK), (0x278, REGISTRY_UNLOCK)):
        a.e(b.lw(8, offset, 4))
        equal(8, expected, 'restore')

    a.label('history_admitted')
    a.absolute(20, state_address)
    a.e(b.lw(8, FAULT, 20))
    a.branch(5, 8, 0, 'restore')
    for offset in (RESERVED0, RESERVED1):
        a.e(b.lw(8, offset, 20))
        a.branch(5, 8, 0, 'schema_fault')
    a.e(b.lw(21, COUNT, 20))
    a.absolute(9, capacity)
    a.e(b.r_type(9, 21, 8, 0x2B))
    a.branch(5, 8, 0, 'schema_fault')
    a.e(b.addiu(22, 20, HEADER_BYTES), b.move(18, 0))
    a.label('rows')
    a.branch(4, 18, 21, 'rows_done')
    a.e(b.lw(8, MAGIC, 22))
    equal(8, RECORD_MAGIC, 'schema_fault')
    a.e(b.addiu(18, 18, 1), b.lw(8, TOKEN, 22))
    a.branch(5, 8, 18, 'schema_fault')
    for offset, expected in ((CONTROLLER, controller_address),
                             (MUTEX, registry_mutex_address),
                             (SITE, PUBLICATION_SITE), (STATUS, 0)):
        a.e(b.lw(8, offset, 22))
        equal(8, expected, 'schema_fault')
    a.e(b.addiu(22, 22, RECORD_BYTES))
    a.jump('rows')
    a.label('rows_done')
    # Validate every unused word, not merely the next row.  A rolled-back count
    # or dirty skipped slot must not make an old token reusable later.
    a.e(b.move(19, 22))
    a.absolute(17, state_address + state_bytes)
    a.label('unused_tail')
    a.branch(4, 19, 17, 'unused_tail_done')
    a.e(b.lw(8, 0, 19))
    a.branch(5, 8, 0, 'schema_fault')
    a.e(b.addiu(19, 19, 4))
    a.jump('unused_tail')
    a.label('unused_tail_done')
    a.absolute(9, capacity)
    a.branch(4, 21, 9, 'schema_fault')
    a.e(b.addiu(21, 21, 1), b.sw(0, MAGIC, 22), b.sw(21, TOKEN, 22))
    for event_offset in range(0, REQUEST_BYTES, 4):
        a.e(b.lw(8, SNAPSHOT + event_offset, 29),
            b.sw(8, CONTROLLER + event_offset, 22))
    a.label('birth_commit')
    a.e(SYNC)
    a.absolute(8, RECORD_MAGIC)
    a.e(b.sw(8, MAGIC, 22), SYNC, b.sw(21, COUNT, 20))
    a.jump('restore')
    a.label('schema_fault')
    a.e(b.addiu(8, 0, 1), b.sw(8, FAULT, 20), SYNC)
    a.label('restore')
    a.e(b.lw(8, HI, 29), b.r_type(8, 0, 0, 0x11),
        b.lw(8, LO, 29), b.r_type(8, 0, 0, 0x13))
    for register, offset in SAVE.items():
        a.e(b.lw(register, offset, 29))
    a.e(b.addiu(29, 29, FRAME), b.r_type(31, 0, 0, 8), 0)

    code_end = code_base + len(a.w) * 4
    if code_end > 0x10000000:
        raise ValueError('birth callback leaves the native MIPS jump region')
    if protected_end is not None and code_end > protected_end:
        raise ValueError('protected code does not contain the complete birth callback')
    if max(code_base, NATIVE_RX[0]) < min(code_end, NATIVE_RX[1]):
        raise ValueError('birth callback overlaps pinned native RX')
    for name, address, size in extents:
        if max(code_base, address) < min(code_end, address + size):
            raise ValueError('birth callback overlaps ' + name)
    for index in end_fixups:
        a.w[index] = b.lui(10, (code_end - 1) >> 16)
        a.w[index + 1] = b.ori(10, 10, (code_end - 1) & 0xFFFF)
    return a.finish(), a.labels
