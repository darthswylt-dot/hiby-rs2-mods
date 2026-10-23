#!/usr/bin/env python3
"""Emit diagnostic birth-identity transport to an existing LNRG RENDER root.

capture(a0=OUTER/RENDER, a1=exact parent ID, a2=owned thirteen-word block)
returns a fresh private ID or zero. Metadata is [engine, widget, view, panel,
frame, upstream, descriptor, input, controller, job, lineage, cache, site].
All native-looking addresses are scalar evidence; they are never dereferenced.
OUTER names an existing private LQTR CALLBACK. RENDER names a prior private
OUTER and the exact existing LNRG RENDER root, never a pointer-keyed lookup.
The core validates immutable ancestry, original frame arithmetic and sampled
domains, not native live-borrow lifetime, request freshness, coherent capture,
complete writer coverage, contents currency, success or UI authority.

The only external calls are supplied PRIVATE LQTR/LNRG validators. Allocation
is bounded, non-reusing LL/SC; magic publishes last and a sticky global fault
overrides racing publication. Coherent snapshot acquisition is separate.
O32 callee-saved registers, SP, RA and HI/LO are preserved; v0 is the result.
"""

from build_reveal_bridge_diag import Asm, b
import folderfollow_reveal_lineage_mips as lineage
import reveal_queue_transport_mips as transport


HEADER, RECORD = 16, 96
STATE, FAULT = 0, 0xFFFFFFFF
MAGIC_OFFSET, MAGIC = 0, int.from_bytes(b'LQRD', 'little')
KIND, PARENT, ORIGIN, SEQ = 4, 8, 12, 16
TRANSPORT, LINEAGE, ENGINE, WIDGET, VIEW, PANEL = 20, 24, 28, 32, 36, 40
FRAME, UPSTREAM, DESCRIPTOR, INPUT, CONTROLLER, JOB = 44, 48, 52, 56, 60, 64
REVISION, SCOPE, CACHE, SITE, RESERVED = 68, 72, 76, 80, (84, 88, 92)
OUTER, RENDER = 1, 2
OUTER_SITE, RENDER_SITE, LINEAGE_SITE = 0x438248, 0x49076C, 0x490758
DEFAULT_CAPACITY, RETRIES = 1024, 8
MAX_CAPACITY = (0x100000000 - HEADER) // RECORD
CALL_FRAME, VALIDATE_FRAME, SYNC = 0xB0, 0x80, 0xF
REVISION_BYTES, SCOPE_BYTES, METADATA_WORDS = 16, 16, 13


def memory_bytes(capacity=DEFAULT_CAPACITY):
    if type(capacity) is not int or not 1 <= capacity <= MAX_CAPACITY:
        raise ValueError('capacity must fit a nonempty unsigned-32 renderer journal')
    return HEADER + RECORD * capacity


def assemble(journal_address, transport_address, transport_entries,
             lineage_address, lineage_entries, revision_address, scope_address,
             code_base, capacity=DEFAULT_CAPACITY):
    """Return (code bytes, labels) without I/O. Public capture/validate/reserve/invalidate.

    validate(a0=ID,a1=OUTER/RENDER) returns a published PRIVATE slot or zero.
    Only external header sizes are known; caller must additionally ensure the
    COMPLETE LQTR/LNRG allocations and code are disjoint from this allocation.
    Supplied validators must be private validated code, never native targets.
    """
    size = memory_bytes(capacity)
    try:
        transport_validate = transport_entries['validate']
        lineage_validate = lineage_entries['validate']
    except (KeyError, TypeError) as error:
        raise ValueError('both private validate entries are required') from error
    for name, value in (('journal_address', journal_address),
                        ('transport_address', transport_address),
                        ('lineage_address', lineage_address),
                        ('revision_address', revision_address),
                        ('scope_address', scope_address), ('code_base', code_base),
                        ('transport validate', transport_validate),
                        ('lineage validate', lineage_validate)):
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFC or value % 4:
            raise ValueError(name + ' must be an aligned unsigned-32 address')
    external = (transport_validate, lineage_validate)
    if len(set(external)) != 2:
        raise ValueError('distinct private transport and lineage validators required')
    if any(not entry or entry >> 28 != code_base >> 28 for entry in external):
        raise ValueError('private validators must share the MIPS jump region')
    regions = ((journal_address, size), (transport_address, transport.HEADER),
               (lineage_address, lineage.HEADER), (revision_address, REVISION_BYTES),
               (scope_address, SCOPE_BYTES))
    for index, (start, length) in enumerate(regions):
        if start + length > 0x100000000:
            raise ValueError('private storage must not wrap the address space')
        for other, count in regions[index + 1:]:
            if max(start, other) < min(start + length, other + count):
                raise ValueError('private journal/header/revision/scope regions overlap')
        if any(start <= entry < start + length for entry in external):
            raise ValueError('private validator and known storage overlap')

    a = Asm(code_base)

    def journal_check(target):
        a.absolute(8, journal_address)
        a.absolute(9, capacity)
        a.e(SYNC, b.lw(10, STATE, 8), b.r_type(9, 10, 11, 0x2B))
        a.branch(5, 11, 0, target)

    def external_headers_check(target):
        for address in (transport_address, lineage_address):
            a.absolute(8, address)
            a.e(SYNC, b.lw(9, 0, 8),
                (9 << 16) | (10 << 11) | (31 << 6) | 2)
            a.branch(5, 10, 0, target)

    def revision_check(sample=False):
        a.absolute(8, revision_address)
        a.e(SYNC, b.lw(9, 0, 8), (9 << 16) | (10 << 11) | (31 << 6) | 2)
        a.branch(5, 10, 0, 'capture_fault')
        if sample:
            a.e(b.sw(9, 0x54, 29))
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
            a.e(b.sw(9, 0x58, 29))
        a.e(SYNC)

    def scalar_domains(pointer, target):
        a.e(b.lw(12, REVISION, pointer),
            (12 << 16) | (11 << 11) | (31 << 6) | 2)
        a.branch(5, 11, 0, target)
        a.e(b.lw(12, SCOPE, pointer),
            (12 << 16) | (11 << 11) | (31 << 6) | 2)
        a.branch(5, 11, 0, target)
        a.e(b.i_type(12, 12, 11, 0xFFFF),
            (12 << 16) | (12 << 11) | (16 << 6) | 2,
            b.r_type(11, 12, 12, 0x2B))
        a.branch(5, 12, 0, target)

    def aligned(reg, target):
        a.branch(4, reg, 0, target)
        a.e(b.i_type(12, reg, 15, 3))
        a.branch(5, 15, 0, target)

    def relation(base, delta, expected, target):
        a.e(b.addiu(12, base, delta), b.r_type(12, base, 13, 0x2B))
        a.branch(5, 13, 0, target)
        a.branch(5, 12, expected, target)

    def capture_equal(local, value):
        a.e(b.lw(8, local, 29))
        a.absolute(9, value)
        a.branch(5, 8, 9, 'capture_fault')

    def slot_for(index, base, target):
        # 96 = 64 + 32, without MUL or any HI/LO writes.
        a.e((index << 16) | (11 << 11) | (6 << 6),
            (index << 16) | (12 << 11) | (5 << 6),
            b.r_type(11, 12, 11, 0x21), b.r_type(base, 11, target, 0x21),
            b.addiu(target, target, HEADER))

    a.label('capture')
    a.e(b.addiu(29, 29, -CALL_FRAME), b.sw(31, 0xAC, 29),
        b.sw(4, 0x10, 29), b.sw(5, 0x14, 29))
    a.branch(4, 4, 0, 'capture_fault')
    a.e(b.i_type(11, 4, 8, RENDER + 1))
    a.branch(4, 8, 0, 'capture_fault')
    a.branch(4, 5, 0, 'capture_ignored')
    a.branch(4, 6, 0, 'capture_fault')
    a.e(b.i_type(12, 6, 8, 3))
    a.branch(5, 8, 0, 'capture_fault')
    journal_check('capture_fault')
    external_headers_check('capture_fault')
    for index in range(METADATA_WORDS):
        a.e(b.lw(8, index * 4, 6), b.sw(8, 0x20 + index * 4, 29))
    for local in (0x20, 0x24, 0x30, 0x40):
        a.e(b.lw(8, local, 29))
        aligned(8, 'capture_fault')
    a.e(b.lw(8, 0x10, 29), b.addiu(9, 0, OUTER))
    a.branch(4, 8, 9, 'capture_outer')
    capture_equal(0x50, RENDER_SITE)
    a.e(b.lw(4, 0x14, 29), b.addiu(5, 0, OUTER))
    a.jump('validate', True)
    a.branch(4, 2, 0, 'capture_fault')
    a.e(b.sw(2, 0x6C, 29))
    for field, local in ((ENGINE, 0x20), (WIDGET, 0x24), (DESCRIPTOR, 0x38),
                         (INPUT, 0x3C), (CONTROLLER, 0x40), (FRAME, 0x34)):
        a.e(b.lw(8, field, 2), b.lw(9, local, 29))
        a.branch(5, 8, 9, 'capture_fault')
    a.e(b.lw(8, ORIGIN, 2), b.sw(8, 0x5C, 29),
        b.lw(8, TRANSPORT, 2), b.sw(8, 0x60, 29),
        b.lw(8, 0x30, 29), b.lw(9, 0x34, 29))
    relation(8, 0x30, 9, 'capture_fault')
    for local in (0x28, 0x2C, 0x4C):
        a.e(b.lw(8, local, 29))
        aligned(8, 'capture_fault')
    a.e(b.lw(8, 0x28, 29), b.lw(9, 0x44, 29))
    relation(8, 0x38A4, 9, 'capture_fault')
    a.e(b.lw(4, 0x48, 29), b.addiu(5, 0, lineage.RENDER))
    a.jump(lineage_validate, True)
    a.branch(4, 2, 0, 'capture_fault')
    for field, local in ((lineage.ORIGIN, 0x48), (lineage.STACK, 0x30),
                         (lineage.VIEW, 0x28), (lineage.PANEL, 0x2C),
                         (lineage.JOB, 0x44)):
        a.e(b.lw(8, field, 2), b.lw(9, local, 29))
        a.branch(5, 8, 9, 'capture_fault')
    a.e(b.lw(8, lineage.PARENT, 2))
    a.branch(5, 8, 0, 'capture_fault')
    a.absolute(9, LINEAGE_SITE)
    a.e(b.lw(8, lineage.SITE, 2))
    a.branch(5, 8, 9, 'capture_fault')
    a.e(b.lw(8, 60, 2), (8 << 16) | (9 << 11) | (31 << 6) | 2)
    a.branch(5, 9, 0, 'capture_fault')
    a.jump('capture_associated')
    a.label('capture_outer')
    capture_equal(0x50, OUTER_SITE)
    for local in (0x28, 0x2C, 0x44, 0x48, 0x4C):
        capture_equal(local, 0)
    a.e(b.lw(8, 0x30, 29), b.lw(9, 0x34, 29))
    relation(8, 0x200, 9, 'capture_fault')
    a.e(b.lw(8, 0x34, 29), b.lw(9, 0x38, 29))
    relation(8, 0x18, 9, 'capture_fault')
    a.e(b.lw(9, 0x3C, 29))
    relation(8, 0x90, 9, 'capture_fault')
    a.e(b.lw(4, 0x14, 29), b.addiu(5, 0, transport.CALLBACK))
    a.jump(transport_validate, True)
    a.branch(4, 2, 0, 'capture_fault')
    for field, local in ((transport.ENGINE, 0x20), (transport.FRAME, 0x34)):
        a.e(b.lw(8, field, 2), b.lw(9, local, 29))
        a.branch(5, 8, 9, 'capture_fault')
    a.e(b.lw(8, transport.ORIGIN, 2), b.sw(8, 0x5C, 29),
        b.lw(8, 0x14, 29), b.sw(8, 0x60, 29))
    a.label('capture_associated')
    revision_check(sample=True)
    scope_check(sample=True)
    a.jump('reserve', True)
    a.branch(4, 2, 0, 'capture_ignored')
    a.e(b.sw(2, 0x64, 29), b.sw(3, 0x68, 29), b.sw(3, SEQ, 2))
    for local, field in ((0x10, KIND), (0x14, PARENT), (0x5C, ORIGIN),
                         (0x60, TRANSPORT), (0x20, ENGINE), (0x24, WIDGET),
                         (0x28, VIEW), (0x2C, PANEL), (0x30, FRAME), (0x34, UPSTREAM),
                         (0x38, DESCRIPTOR), (0x3C, INPUT), (0x40, CONTROLLER),
                         (0x44, JOB), (0x48, LINEAGE), (0x4C, CACHE), (0x50, SITE),
                         (0x54, REVISION), (0x58, SCOPE)):
        a.e(b.lw(8, local, 29), b.sw(8, field, 2))
    for field in RESERVED:
        a.e(b.sw(0, field, 2))
    a.label('capture_publish')
    a.e(SYNC)
    revision_check()
    scope_check()
    external_headers_check('capture_fault')
    journal_check('capture_fault')
    a.e(b.lw(2, 0x64, 29), SYNC)
    a.absolute(8, MAGIC)
    a.label('capture_magic_store')
    a.e(b.sw(8, MAGIC_OFFSET, 2), SYNC, b.lw(2, 0x68, 29))
    a.jump('capture_done')
    a.label('capture_fault')
    a.jump('invalidate', True)
    a.label('capture_ignored')
    a.e(b.move(2, 0))
    a.label('capture_done')
    a.e(b.lw(31, 0xAC, 29), b.addiu(29, 29, CALL_FRAME),
        b.r_type(31, 0, 0, 8), 0)

    # A RENDER may recurse only with constant expected OUTER. OUTER has no
    # internal parent recursion, bounding this own-journal chain to two slots.
    a.label('validate')
    a.e(b.addiu(29, 29, -VALIDATE_FRAME), b.sw(31, 0x7C, 29),
        b.sw(4, 0x10, 29), b.sw(5, 0x14, 29))
    a.branch(4, 4, 0, 'validate_fault')
    a.branch(4, 5, 0, 'validate_fault')
    a.e(b.i_type(11, 5, 8, RENDER + 1))
    a.branch(4, 8, 0, 'validate_fault')
    external_headers_check('validate_fault')
    journal_check('validate_fault')
    a.e(b.lw(4, 0x10, 29), b.r_type(10, 4, 11, 0x2B))
    a.branch(5, 11, 0, 'validate_fault')
    a.e(b.addiu(14, 4, -1))
    slot_for(14, 8, 10)
    a.e(b.sw(10, 0x18, 29))
    a.absolute(11, MAGIC)
    a.e(b.lw(12, MAGIC_OFFSET, 10))
    a.branch(5, 11, 12, 'validate_fault')
    a.e(b.lw(12, SEQ, 10))
    a.branch(5, 4, 12, 'validate_fault')
    a.e(b.lw(5, 0x14, 29), b.lw(12, KIND, 10))
    a.branch(5, 5, 12, 'validate_fault')
    for field in (ENGINE, WIDGET, FRAME, CONTROLLER):
        a.e(b.lw(12, field, 10))
        aligned(12, 'validate_fault')
    for field in RESERVED:
        a.e(b.lw(12, field, 10))
        a.branch(5, 12, 0, 'validate_fault')
    scalar_domains(10, 'validate_fault')
    a.e(b.addiu(12, 0, OUTER))
    a.branch(4, 5, 12, 'validate_outer')
    a.absolute(11, RENDER_SITE)
    a.e(b.lw(12, SITE, 10))
    a.branch(5, 11, 12, 'validate_fault')
    for field in (VIEW, PANEL, CACHE):
        a.e(b.lw(12, field, 10))
        aligned(12, 'validate_fault')
    a.e(b.lw(8, VIEW, 10), b.lw(9, JOB, 10))
    relation(8, 0x38A4, 9, 'validate_fault')
    a.e(b.lw(4, PARENT, 10), b.lw(11, 0x10, 29),
        b.r_type(4, 11, 12, 0x2B))
    a.branch(4, 4, 0, 'validate_fault')
    a.branch(4, 12, 0, 'validate_fault')
    a.e(b.addiu(5, 0, OUTER))
    a.jump('validate', True)
    a.branch(4, 2, 0, 'validate_fault')
    a.e(b.lw(10, 0x18, 29))
    for field in (ORIGIN, TRANSPORT, ENGINE, WIDGET, DESCRIPTOR, INPUT, CONTROLLER):
        a.e(b.lw(11, field, 10), b.lw(12, field, 2))
        a.branch(5, 11, 12, 'validate_fault')
    a.e(b.lw(8, FRAME, 10), b.lw(9, UPSTREAM, 10), b.lw(11, FRAME, 2))
    a.branch(5, 9, 11, 'validate_fault')
    relation(8, 0x30, 9, 'validate_fault')
    a.e(b.lw(4, LINEAGE, 10), b.addiu(5, 0, lineage.RENDER))
    a.jump(lineage_validate, True)
    a.branch(4, 2, 0, 'validate_fault')
    a.e(b.lw(10, 0x18, 29))
    for own, other in ((LINEAGE, lineage.ORIGIN), (FRAME, lineage.STACK),
                       (VIEW, lineage.VIEW), (PANEL, lineage.PANEL), (JOB, lineage.JOB)):
        a.e(b.lw(11, own, 10), b.lw(12, other, 2))
        a.branch(5, 11, 12, 'validate_fault')
    a.e(b.lw(11, lineage.PARENT, 2))
    a.branch(5, 11, 0, 'validate_fault')
    a.absolute(11, LINEAGE_SITE)
    a.e(b.lw(12, lineage.SITE, 2))
    a.branch(5, 11, 12, 'validate_fault')
    a.e(b.lw(12, 60, 2), (12 << 16) | (11 << 11) | (31 << 6) | 2)
    a.branch(5, 11, 0, 'validate_fault')
    a.jump('validate_success')
    a.label('validate_outer')
    a.absolute(11, OUTER_SITE)
    a.e(b.lw(12, SITE, 10))
    a.branch(5, 11, 12, 'validate_fault')
    for field in (VIEW, PANEL, JOB, LINEAGE, CACHE):
        a.e(b.lw(12, field, 10))
        a.branch(5, 12, 0, 'validate_fault')
    a.e(b.lw(8, FRAME, 10), b.lw(9, UPSTREAM, 10))
    relation(8, 0x200, 9, 'validate_fault')
    a.e(b.lw(8, UPSTREAM, 10), b.lw(9, DESCRIPTOR, 10))
    relation(8, 0x18, 9, 'validate_fault')
    a.e(b.lw(9, INPUT, 10))
    relation(8, 0x90, 9, 'validate_fault')
    a.e(b.lw(4, PARENT, 10), b.lw(11, TRANSPORT, 10))
    a.branch(5, 4, 11, 'validate_fault')
    a.e(b.addiu(5, 0, transport.CALLBACK))
    a.jump(transport_validate, True)
    a.branch(4, 2, 0, 'validate_fault')
    a.e(b.lw(10, 0x18, 29))
    for own, other in ((ORIGIN, transport.ORIGIN), (ENGINE, transport.ENGINE),
                       (UPSTREAM, transport.FRAME)):
        a.e(b.lw(11, own, 10), b.lw(12, other, 2))
        a.branch(5, 11, 12, 'validate_fault')
    a.label('validate_success')
    external_headers_check('validate_fault')
    journal_check('validate_fault')
    a.e(b.lw(2, 0x18, 29))
    a.jump('validate_done')
    a.label('validate_fault')
    a.jump('invalidate', True)
    a.label('validate_done')
    a.e(b.lw(31, 0x7C, 29), b.addiu(29, 29, VALIDATE_FRAME),
        b.r_type(31, 0, 0, 8), 0)

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
    slot_for(10, 8, 2)
    a.e(SYNC, b.lw(11, MAGIC_OFFSET, 2))
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
        raise ValueError('renderer journal code must fit one MIPS jump region')
    if any(code_base <= entry < end for entry in external):
        raise ValueError('external private validator overlaps renderer code')
    for start, length in regions:
        if max(start, code_base) < min(start + length, end):
            raise ValueError('private storage and renderer code overlap')
    return code, a.labels
