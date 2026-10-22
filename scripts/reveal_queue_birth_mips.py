#!/usr/bin/env python3
"""Emit a private, append-only journal of native queue birth observations.

capture(a0=kind, a1=parent ticket, a2=wrapper-owned seven-word metadata)
returns a fresh journal ticket, or zero for an ignored unbound descendant or
permanent journal fault. Metadata is [engine, input, copy, metadata, frame,
site, actual_result]. These native-looking addresses are numeric evidence;
none is dereferenced. ENQUEUE_BEGIN precedes the final native rect-word store
and original append call: it is not a completed copy or a confirmed enqueue.

Revision and packed scope values are historical samples, not equality gates,
ownership, UI-request freshness, success, coherent capture or UI authority.
Only private BSS, the owned scalar block and this function's own frame are
accessed. No native allocation, native tail, registry or call is introduced.
The bounded non-reusing allocator faults permanently on loss. Magic publishes
last; a global fault overrides all history, including racing publication.
O32 callee-saved registers, SP, RA and HI/LO are preserved; v0 is the ticket.
"""

from build_reveal_bridge_diag import Asm, b


HEADER, RECORD = 16, 64
STATE, FAULT = 0, 0xFFFFFFFF
MAGIC_OFFSET, MAGIC = 0, int.from_bytes(b'LQBR', 'little')
KIND, PARENT, ORIGIN, SEQ = 4, 8, 12, 16
ENGINE, INPUT, COPY, METADATA, FRAME, SITE, RESULT = 20, 24, 28, 32, 36, 40, 44
REVISION, SCOPE, RESERVED = 48, 52, (56, 60)
BIRTH, ENQUEUE_BEGIN, RETURN = 1, 2, 3
ENQUEUE = ENQUEUE_BEGIN
BIRTH_SITE, ENQUEUE_SITE, RETURN_SITE = 0x8B428C, 0x8B42E0, 0x8B42F0
DEFAULT_CAPACITY, RETRIES = 1024, 8
MAX_CAPACITY = (0x100000000 - HEADER) // RECORD
CALL_FRAME, REVISION_BYTES, SCOPE_BYTES, SYNC = 0x80, 16, 16, 0x0000000F


def memory_bytes(capacity=DEFAULT_CAPACITY):
    if type(capacity) is not int or not 1 <= capacity <= MAX_CAPACITY:
        raise ValueError('capacity must fit a nonempty unsigned-32 journal')
    return HEADER + RECORD * capacity


def assemble(journal_address, revision_address, scope_address, code_base,
             capacity=DEFAULT_CAPACITY):
    """Return (code bytes, absolute labels), without I/O or installation.

    Public entries: capture, reserve, validate, invalidate. validate(a0=ticket,
    a1=expected BIRTH/ENQUEUE_BEGIN kind) returns a published private slot or
    zero after permanent invalidation; it confers no native pointer authority.
    The scope address names only its packed header, not its native objects.
    """
    size = memory_bytes(capacity)
    for name, value in (('journal_address', journal_address),
                        ('revision_address', revision_address),
                        ('scope_address', scope_address), ('code_base', code_base)):
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFC or value % 4:
            raise ValueError(name + ' must be an aligned unsigned-32 address')
    regions = ((journal_address, size), (revision_address, REVISION_BYTES),
               (scope_address, SCOPE_BYTES))
    for index, (start, length) in enumerate(regions):
        if start + length > 0x100000000:
            raise ValueError('private storage must not wrap the address space')
        for other, count in regions[index + 1:]:
            if max(start, other) < min(start + length, other + count):
                raise ValueError('private journal/revision/scope regions overlap')

    a = Asm(code_base)

    def journal_check(target='capture_fault'):
        a.absolute(8, journal_address)
        a.absolute(9, capacity)
        a.e(b.lw(10, STATE, 8), b.r_type(9, 10, 11, 0x2B))
        a.branch(5, 11, 0, target)

    def revision_check(sample=False):
        a.absolute(8, revision_address)
        a.e(SYNC, b.lw(9, 0, 8), (9 << 16) | (10 << 11) | (31 << 6) | 2)
        a.branch(5, 10, 0, 'capture_fault')
        if sample:
            a.e(b.sw(9, 0x3C, 29))
        a.e(SYNC)

    def scope_check(sample=False):
        a.absolute(8, scope_address)
        a.e(SYNC, b.lw(9, 0, 8), (9 << 16) | (10 << 11) | (31 << 6) | 2)
        a.branch(5, 10, 0, 'capture_fault')
        a.e(b.i_type(12, 9, 10, 0xFFFF),
            (9 << 16) | (11 << 11) | (16 << 6) | 2,
            b.r_type(10, 11, 12, 0x2B))
        a.branch(5, 12, 0, 'capture_fault')
        if sample:
            a.e(b.sw(9, 0x40, 29))
        a.e(SYNC)

    def aligned_positive_local(local):
        a.e(b.lw(8, local, 29))
        a.branch(4, 8, 0, 'capture_fault')
        a.e(b.i_type(12, 8, 9, 3))
        a.branch(5, 9, 0, 'capture_fault')

    def local_equal(local, value):
        a.e(b.lw(8, local, 29))
        a.absolute(9, value)
        a.branch(5, 8, 9, 'capture_fault')

    a.label('capture')
    a.e(b.addiu(29, 29, -CALL_FRAME), b.sw(31, 0x7C, 29),
        b.sw(4, 0x10, 29), b.sw(5, 0x14, 29))
    a.branch(4, 4, 0, 'capture_fault')
    a.e(b.i_type(11, 4, 8, RETURN + 1))
    a.branch(4, 8, 0, 'capture_fault')
    a.e(b.addiu(8, 0, BIRTH))
    a.branch(4, 4, 8, 'capture_birth_parent')
    a.branch(4, 5, 0, 'capture_ignored')
    a.jump('capture_params')
    a.label('capture_birth_parent')
    a.branch(5, 5, 0, 'capture_fault')
    a.label('capture_params')
    a.branch(4, 6, 0, 'capture_fault')
    a.e(b.i_type(12, 6, 8, 3))
    a.branch(5, 8, 0, 'capture_fault')
    journal_check()
    for index in range(7):
        a.e(b.lw(8, index * 4, 6), b.sw(8, 0x20 + index * 4, 29))
    for local in (0x20, 0x24, 0x30):
        aligned_positive_local(local)
    a.e(b.lw(8, 0x10, 29), b.addiu(9, 0, BIRTH))
    a.branch(4, 8, 9, 'capture_birth')
    a.e(b.addiu(9, 0, ENQUEUE_BEGIN))
    a.branch(4, 8, 9, 'capture_enqueue')
    local_equal(0x34, RETURN_SITE)
    a.jump('capture_parent')
    a.label('capture_enqueue')
    local_equal(0x34, ENQUEUE_SITE)
    local_equal(0x38, 0)
    aligned_positive_local(0x28)
    a.jump('capture_parent')
    a.label('capture_birth')
    local_equal(0x34, BIRTH_SITE)
    local_equal(0x28, 0)
    local_equal(0x38, 0)
    a.e(b.sw(0, 0x44, 29))  # BIRTH origin is assigned from its own reservation.
    a.jump('capture_associated')
    a.label('capture_parent')
    a.e(b.lw(4, 0x14, 29), b.lw(5, 0x10, 29), b.addiu(5, 5, -1))
    a.jump('validate', True)
    a.branch(4, 2, 0, 'capture_fault')
    for field, local in ((ENGINE, 0x20), (INPUT, 0x24),
                         (METADATA, 0x2C), (FRAME, 0x30)):
        a.e(b.lw(8, field, 2), b.lw(9, local, 29))
        a.branch(5, 8, 9, 'capture_fault')
    a.e(b.lw(8, 0x10, 29), b.addiu(9, 0, RETURN))
    a.branch(5, 8, 9, 'capture_copy_bound')
    a.e(b.lw(8, COPY, 2), b.lw(9, 0x28, 29))
    a.branch(5, 8, 9, 'capture_fault')
    a.label('capture_copy_bound')
    a.e(b.lw(8, ORIGIN, 2), b.sw(8, 0x44, 29))
    a.label('capture_associated')
    revision_check(sample=True)
    scope_check(sample=True)
    a.jump('reserve', True)
    a.branch(4, 2, 0, 'capture_ignored')
    a.e(b.sw(2, 0x48, 29), b.sw(3, 0x4C, 29), b.sw(3, SEQ, 2))
    a.e(b.lw(8, 0x10, 29), b.addiu(9, 0, BIRTH))
    a.branch(5, 8, 9, 'capture_origin_bound')
    a.e(b.sw(3, 0x44, 29))
    a.label('capture_origin_bound')
    for local, field in ((0x10, KIND), (0x14, PARENT), (0x44, ORIGIN),
                         (0x20, ENGINE), (0x24, INPUT), (0x28, COPY),
                         (0x2C, METADATA), (0x30, FRAME), (0x34, SITE),
                         (0x38, RESULT), (0x3C, REVISION), (0x40, SCOPE)):
        a.e(b.lw(8, local, 29), b.sw(8, field, 2))
    for field in RESERVED:
        a.e(b.sw(0, field, 2))
    a.label('capture_publish')
    a.e(SYNC)
    revision_check()
    scope_check()
    journal_check()
    a.e(b.lw(2, 0x48, 29), SYNC)
    a.absolute(8, MAGIC)
    a.label('capture_magic_store')
    a.e(b.sw(8, MAGIC_OFFSET, 2), SYNC, b.lw(2, 0x4C, 29))
    a.jump('capture_done')
    a.label('capture_fault')
    a.jump('invalidate', True)
    a.label('capture_ignored')
    a.e(b.move(2, 0))
    a.label('capture_done')
    a.e(b.lw(31, 0x7C, 29), b.addiu(29, 29, CALL_FRAME),
        b.r_type(31, 0, 0, 8), 0)

    # Leaf private parent validation. t2 is requested slot, t5 the root slot.
    a.label('validate')
    a.branch(4, 4, 0, 'invalidate')
    a.branch(4, 5, 0, 'invalidate')
    a.e(b.i_type(11, 5, 12, ENQUEUE_BEGIN + 1))
    a.branch(4, 12, 0, 'invalidate')
    a.absolute(8, journal_address)
    a.absolute(9, capacity)
    a.e(SYNC, b.lw(10, STATE, 8), b.r_type(9, 10, 12, 0x2B))
    a.branch(5, 12, 0, 'invalidate')
    a.e(b.r_type(10, 4, 12, 0x2B))
    a.branch(5, 12, 0, 'invalidate')
    a.e(b.addiu(10, 4, -1), (10 << 16) | (10 << 11) | (6 << 6),
        b.r_type(8, 10, 10, 0x21), b.addiu(10, 10, HEADER), SYNC)
    a.absolute(11, MAGIC)
    for field, reg in ((MAGIC_OFFSET, 11), (SEQ, 4), (KIND, 5)):
        a.e(b.lw(12, field, 10))
        a.branch(5, 12, reg, 'invalidate')
    a.e(b.addiu(12, 0, BIRTH))
    a.branch(4, 5, 12, 'validate_birth_direct')
    # ENQUEUE_BEGIN must name the exact BIRTH root, not another queue event.
    a.e(b.lw(14, PARENT, 10), b.lw(12, ORIGIN, 10))
    a.branch(5, 12, 14, 'invalidate')
    a.branch(4, 14, 0, 'invalidate')
    a.e(b.r_type(14, 4, 12, 0x2B))
    a.branch(4, 12, 0, 'invalidate')
    a.e(b.addiu(13, 14, -1), (13 << 16) | (13 << 11) | (6 << 6),
        b.r_type(8, 13, 13, 0x21), b.addiu(13, 13, HEADER), SYNC)
    a.absolute(11, MAGIC)
    for field, reg in ((MAGIC_OFFSET, 11), (SEQ, 14), (ORIGIN, 14)):
        a.e(b.lw(12, field, 13))
        a.branch(5, 12, reg, 'invalidate')
    a.e(b.lw(12, KIND, 13), b.addiu(11, 0, BIRTH))
    a.branch(5, 12, 11, 'invalidate')
    for field in (ENGINE, INPUT, METADATA, FRAME):
        a.e(b.lw(11, field, 10), b.lw(12, field, 13))
        a.branch(5, 11, 12, 'invalidate')
    a.e(b.lw(12, COPY, 10))
    a.branch(4, 12, 0, 'invalidate')
    a.e(b.i_type(12, 12, 11, 3))
    a.branch(5, 11, 0, 'invalidate')
    a.e(b.lw(12, RESULT, 10))
    a.branch(5, 12, 0, 'invalidate')
    a.absolute(11, ENQUEUE_SITE)
    a.e(b.lw(12, SITE, 10))
    a.branch(5, 12, 11, 'invalidate')
    for field in RESERVED:
        a.e(b.lw(12, field, 10))
        a.branch(5, 12, 0, 'invalidate')
    a.jump('validate_birth_common')
    a.label('validate_birth_direct')
    a.e(b.move(13, 10), b.lw(12, ORIGIN, 13))
    a.branch(5, 12, 4, 'invalidate')
    a.label('validate_birth_common')
    for field in (PARENT, COPY, RESULT, *RESERVED):
        a.e(b.lw(12, field, 13))
        a.branch(5, 12, 0, 'invalidate')
    a.absolute(11, BIRTH_SITE)
    a.e(b.lw(12, SITE, 13))
    a.branch(5, 12, 11, 'invalidate')
    for field in (ENGINE, INPUT, FRAME):
        a.e(b.lw(12, field, 13))
        a.branch(4, 12, 0, 'invalidate')
        a.e(b.i_type(12, 12, 11, 3))
        a.branch(5, 11, 0, 'invalidate')
    # Validate sampled scalar domains of both requested parent and root.
    for pointer in (10, 13):
        a.e(b.lw(12, REVISION, pointer), (12 << 16) | (11 << 11) | (31 << 6) | 2)
        a.branch(5, 11, 0, 'invalidate')
        a.e(b.lw(12, SCOPE, pointer), (12 << 16) | (11 << 11) | (31 << 6) | 2)
        a.branch(5, 11, 0, 'invalidate')
        a.e(b.i_type(12, 12, 11, 0xFFFF),
            (12 << 16) | (12 << 11) | (16 << 6) | 2,
            b.r_type(11, 12, 12, 0x2B))
        a.branch(5, 12, 0, 'invalidate')
    a.e(SYNC, b.move(2, 10), b.r_type(31, 0, 0, 8), 0)

    a.label('reserve')
    a.absolute(8, journal_address)
    a.absolute(9, capacity)
    a.e(b.addiu(14, 0, RETRIES), SYNC)
    a.label('reserve_ll')
    a.e(b.i_type(0x30, 8, 10, STATE), b.r_type(10, 9, 11, 0x2B))
    a.branch(4, 11, 0, 'reserve_fault')
    a.e(b.addiu(3, 10, 1), b.move(11, 3))
    a.label('reserve_sc')
    a.e(b.i_type(0x38, 8, 11, STATE))
    a.branch(5, 11, 0, 'reserve_success')
    a.e(b.addiu(14, 14, -1))
    a.branch(5, 14, 0, 'reserve_ll')
    a.jump('reserve_fault')
    a.label('reserve_success')
    a.e((10 << 16) | (11 << 11) | (6 << 6),
        b.r_type(8, 11, 2, 0x21), b.addiu(2, 2, HEADER), SYNC,
        b.lw(11, MAGIC_OFFSET, 2))
    a.branch(5, 11, 0, 'reserve_fault')
    a.e(b.lw(10, STATE, 8), b.r_type(9, 10, 11, 0x2B))
    a.branch(5, 11, 0, 'reserve_fault')
    a.e(SYNC, b.r_type(31, 0, 0, 8), 0)
    a.label('invalidate')
    a.absolute(8, journal_address)
    a.label('reserve_fault')
    a.e(b.addiu(11, 0, -1), SYNC)
    a.label('fault_store')
    a.e(b.sw(11, STATE, 8), SYNC, b.move(2, 0), b.move(3, 0),
        b.r_type(31, 0, 0, 8), 0)

    code = a.finish()
    end = code_base + len(code)
    if end > 0x100000000 or code_base >> 28 != (end - 1) >> 28:
        raise ValueError('queue journal code must fit one MIPS jump region')
    for start, length in regions:
        if max(start, code_base) < min(start + length, end):
            raise ValueError('private storage and queue code overlap')
    return code, a.labels
