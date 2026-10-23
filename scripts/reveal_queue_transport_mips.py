#!/usr/bin/env python3
"""Emit a diagnostic journal for explicit native queue-carrier transport.

capture(a0=kind, a1=parent ticket, a2=owned seven-word scalar block) returns a
fresh private ticket, or zero. Metadata is [engine, node, copy, metadata,
frame, upstream_frame, site]. Native-looking values are evidence only and
are NEVER dereferenced here. The wrapper owns the scalar block and carrier;
this core does not establish their native lifetime or UI authority.

INSTALL names an exact private queue-birth ENQUEUE_BEGIN ticket. Subsequent
events name the exact preceding transport kind, not an address-keyed lookup.
validate follows at most four transport records and the external private
birth validator. Neither queue address reuse nor equal scalar values reuses
a ticket. Samples of revision/scope are historical, not equality admission.

Only private journals/headers, owned metadata and own stack are accessed.
Allocation is non-reusing, bounded LL/SC; association/loss faults permanently.
Magic publishes last. A global fault overrides published history, including
a racing publication; coherent acquisition is a separate obligation.
No native calls, retention, setters, reset/reuse, readiness or UI authority.
O32 callee-saved registers, SP, RA and HI/LO are preserved; v0 is the result.
"""

from build_reveal_bridge_diag import Asm, b
import reveal_queue_birth_mips as birth


HEADER, RECORD = 16, 64
STATE, FAULT = 0, 0xFFFFFFFF
MAGIC_OFFSET, MAGIC = 0, int.from_bytes(b'LQTR', 'little')
KIND, PARENT, ORIGIN, SEQ = 4, 8, 12, 16
ENGINE, NODE, COPY, METADATA, FRAME, SITE, UPSTREAM = 20, 24, 28, 32, 36, 40, 44
REVISION, SCOPE, RESERVED = 48, 52, (56, 60)
INSTALL, BORROW, HELPER, CALLBACK = 1, 2, 3, 4
INSTALL_SITE, BORROW_SITE, HELPER_SITE, CALLBACK_SITE = (
    0x8B3CE8, 0x8B4754, 0x8B3FA0, 0x439EC0)
DEFAULT_CAPACITY, RETRIES = 1024, 8
MAX_CAPACITY = (0x100000000 - HEADER) // RECORD
CALL_FRAME, VALIDATE_FRAME, REVISION_BYTES, SCOPE_BYTES, SYNC = 0x80, 0x80, 16, 16, 0xF


def memory_bytes(capacity=DEFAULT_CAPACITY):
    if type(capacity) is not int or not 1 <= capacity <= MAX_CAPACITY:
        raise ValueError('capacity must fit a nonempty unsigned-32 journal')
    return HEADER + RECORD * capacity


def assemble(journal_address, birth_address, birth_entries, revision_address,
             scope_address, code_base, capacity=DEFAULT_CAPACITY):
    """Return (code bytes, absolute labels), without I/O or installation.

    Public entries: capture, validate, reserve, invalidate. validate(a0=ticket,
    a1=expected kind) returns a published private record or zero after fault.
    Supplied birth validate must be private code, never a native function.
    Only the birth header size is known here: caller must separately ensure
    its COMPLETE allocation/code do not overlap this allocation/code.
    """
    size = memory_bytes(capacity)
    try:
        birth_validate = birth_entries['validate']
    except (KeyError, TypeError) as error:
        raise ValueError('private birth validate entry is required') from error
    for name, value in (('journal_address', journal_address),
                        ('birth_address', birth_address),
                        ('revision_address', revision_address),
                        ('scope_address', scope_address), ('code_base', code_base),
                        ('birth validate', birth_validate)):
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFC or value % 4:
            raise ValueError(name + ' must be an aligned unsigned-32 address')
    if not birth_validate or birth_validate >> 28 != code_base >> 28:
        raise ValueError('private birth validate must share the MIPS jump region')
    regions = ((journal_address, size), (birth_address, birth.HEADER),
               (revision_address, REVISION_BYTES), (scope_address, SCOPE_BYTES))
    for index, (start, length) in enumerate(regions):
        if start + length > 0x100000000:
            raise ValueError('private storage must not wrap the address space')
        for other, count in regions[index + 1:]:
            if max(start, other) < min(start + length, other + count):
                raise ValueError('private journal/header/revision/scope regions overlap')
        if start <= birth_validate < start + length:
            raise ValueError('private birth code and known storage overlap')

    a = Asm(code_base)

    def journal_check(target):
        a.absolute(8, journal_address)
        a.absolute(9, capacity)
        a.e(SYNC, b.lw(10, STATE, 8), b.r_type(9, 10, 11, 0x2B))
        a.branch(5, 11, 0, target)

    def birth_check(target):
        a.absolute(8, birth_address)
        a.e(SYNC, b.lw(9, birth.STATE, 8),
            (9 << 16) | (10 << 11) | (31 << 6) | 2)
        a.branch(5, 10, 0, target)

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

    def aligned(reg, target):
        a.branch(4, reg, 0, target)
        a.e(b.i_type(12, reg, 15, 3))
        a.branch(5, 15, 0, target)

    def capture_equal(local, value):
        a.e(b.lw(8, local, 29))
        a.absolute(9, value)
        a.branch(5, 8, 9, 'capture_fault')

    def relation(base, delta, upstream, target):
        a.e(b.addiu(12, base, delta), b.r_type(12, base, 13, 0x2B))
        a.branch(5, 13, 0, target)
        a.branch(5, 12, upstream, target)

    a.label('capture')
    a.e(b.addiu(29, 29, -CALL_FRAME), b.sw(31, 0x7C, 29),
        b.sw(4, 0x10, 29), b.sw(5, 0x14, 29))
    a.branch(4, 4, 0, 'capture_fault')
    a.e(b.i_type(11, 4, 8, CALLBACK + 1))
    a.branch(4, 8, 0, 'capture_fault')
    # Unknown carrier is ignored BEFORE reading the owned metadata block.
    a.branch(4, 5, 0, 'capture_ignored')
    a.branch(4, 6, 0, 'capture_fault')
    a.e(b.i_type(12, 6, 8, 3))
    a.branch(5, 8, 0, 'capture_fault')
    journal_check('capture_fault')
    birth_check('capture_fault')
    for index in range(7):
        a.e(b.lw(8, 4 * index, 6), b.sw(8, 0x20 + 4 * index, 29))
    for local in (0x20, 0x24, 0x28, 0x30):
        a.e(b.lw(8, local, 29))
        aligned(8, 'capture_fault')
    a.e(b.lw(4, 0x14, 29), b.lw(5, 0x10, 29), b.addiu(8, 0, INSTALL))
    a.branch(4, 5, 8, 'capture_install')
    a.e(b.addiu(5, 5, -1))
    a.jump('validate', True)
    a.branch(4, 2, 0, 'capture_fault')
    a.e(b.sw(2, 0x50, 29))
    for field, local in ((ENGINE, 0x20), (NODE, 0x24),
                         (COPY, 0x28), (METADATA, 0x2C)):
        a.e(b.lw(8, field, 2), b.lw(9, local, 29))
        a.branch(5, 8, 9, 'capture_fault')
    a.e(b.lw(8, ORIGIN, 2), b.sw(8, 0x44, 29),
        b.lw(8, 0x10, 29), b.addiu(9, 0, BORROW))
    a.branch(4, 8, 9, 'capture_borrow')
    a.e(b.addiu(9, 0, HELPER))
    a.branch(4, 8, 9, 'capture_helper')
    capture_equal(0x38, CALLBACK_SITE)
    a.e(b.addiu(14, 0, 0x38))
    a.jump('capture_nested')
    a.label('capture_helper')
    capture_equal(0x38, HELPER_SITE)
    a.e(b.addiu(14, 0, 0xB8))
    a.label('capture_nested')
    a.e(b.lw(2, 0x50, 29), b.lw(8, FRAME, 2), b.lw(9, 0x34, 29))
    a.branch(5, 8, 9, 'capture_fault')
    a.e(b.lw(9, 0x30, 29), b.r_type(9, 14, 12, 0x21),
        b.r_type(12, 9, 13, 0x2B))
    a.branch(5, 13, 0, 'capture_fault')
    a.branch(5, 12, 8, 'capture_fault')
    a.jump('capture_associated')
    a.label('capture_borrow')
    capture_equal(0x38, BORROW_SITE)
    capture_equal(0x34, 0)
    a.jump('capture_associated')
    a.label('capture_install')
    capture_equal(0x38, INSTALL_SITE)
    a.e(b.lw(8, 0x30, 29), b.lw(9, 0x34, 29))
    relation(8, 0x28, 9, 'capture_fault')
    a.e(b.lw(4, 0x14, 29), b.addiu(5, 0, birth.ENQUEUE_BEGIN))
    a.jump(birth_validate, True)
    a.branch(4, 2, 0, 'capture_fault')
    for field, local in ((birth.ENGINE, 0x20), (birth.COPY, 0x28),
                         (birth.METADATA, 0x2C), (birth.FRAME, 0x34)):
        a.e(b.lw(8, field, 2), b.lw(9, local, 29))
        a.branch(5, 8, 9, 'capture_fault')
    a.e(b.lw(8, birth.ORIGIN, 2), b.sw(8, 0x44, 29))
    a.label('capture_associated')
    revision_check(sample=True)
    scope_check(sample=True)
    a.jump('reserve', True)
    a.branch(4, 2, 0, 'capture_ignored')
    a.e(b.sw(2, 0x48, 29), b.sw(3, 0x4C, 29), b.sw(3, SEQ, 2))
    for local, field in ((0x10, KIND), (0x14, PARENT), (0x44, ORIGIN),
                         (0x20, ENGINE), (0x24, NODE), (0x28, COPY),
                         (0x2C, METADATA), (0x30, FRAME), (0x34, UPSTREAM),
                         (0x38, SITE), (0x3C, REVISION), (0x40, SCOPE)):
        a.e(b.lw(8, local, 29), b.sw(8, field, 2))
    for field in RESERVED:
        a.e(b.sw(0, field, 2))
    a.label('capture_publish')
    a.e(SYNC)
    revision_check()
    scope_check()
    birth_check('capture_fault')
    journal_check('capture_fault')
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

    # Exact, bounded ancestry validation. The current expected kind decrements
    # at every transport parent: at most CALLBACK -> HELPER -> BORROW -> INSTALL.
    # Locals preserve all necessary state across the sole external private call.
    a.label('validate')
    a.e(b.addiu(29, 29, -VALIDATE_FRAME), b.sw(31, 0x7C, 29),
        b.sw(4, 0x10, 29), b.sw(4, 0x1C, 29), b.sw(5, 0x20, 29),
        b.sw(0, 0x28, 29))
    a.branch(4, 4, 0, 'validate_fault')
    a.branch(4, 5, 0, 'validate_fault')
    a.e(b.i_type(11, 5, 8, CALLBACK + 1))
    a.branch(4, 8, 0, 'validate_fault')
    a.label('validate_loop')
    journal_check('validate_fault')
    a.e(b.lw(4, 0x1C, 29), b.r_type(10, 4, 11, 0x2B))
    a.branch(5, 11, 0, 'validate_fault')
    a.e(b.addiu(12, 4, -1), (12 << 16) | (12 << 11) | (6 << 6),
        b.r_type(8, 12, 10, 0x21), b.addiu(10, 10, HEADER),
        b.sw(10, 0x24, 29))
    a.absolute(11, MAGIC)
    a.e(b.lw(12, MAGIC_OFFSET, 10))
    a.branch(5, 11, 12, 'validate_fault')
    a.e(b.lw(12, SEQ, 10))
    a.branch(5, 4, 12, 'validate_fault')
    a.e(b.lw(5, 0x20, 29), b.lw(12, KIND, 10))
    a.branch(5, 5, 12, 'validate_fault')
    for field in (ENGINE, NODE, COPY, FRAME):
        a.e(b.lw(12, field, 10))
        aligned(12, 'validate_fault')
    for field in RESERVED:
        a.e(b.lw(12, field, 10))
        a.branch(5, 12, 0, 'validate_fault')
    scalar_domains(10, 'validate_fault')
    a.e(b.lw(14, 0x28, 29))
    a.branch(4, 14, 0, 'validate_first')
    for field in (ENGINE, NODE, COPY, METADATA, ORIGIN):
        a.e(b.lw(11, field, 10), b.lw(12, field, 14))
        a.branch(5, 11, 12, 'validate_fault')
    a.e(b.lw(11, KIND, 14), b.addiu(12, 0, BORROW))
    a.branch(4, 11, 12, 'validate_kind_site')
    a.e(b.lw(8, FRAME, 14), b.lw(9, FRAME, 10),
        b.lw(12, UPSTREAM, 14))
    a.branch(5, 9, 12, 'validate_fault')
    a.e(b.addiu(12, 0, HELPER))
    a.branch(4, 11, 12, 'validate_helper_frame')
    relation(8, 0x38, 9, 'validate_fault')
    a.jump('validate_kind_site')
    a.label('validate_helper_frame')
    relation(8, 0xB8, 9, 'validate_fault')
    a.jump('validate_kind_site')
    a.label('validate_first')
    a.e(b.sw(10, 0x18, 29))
    a.label('validate_kind_site')
    a.e(b.lw(11, 0x20, 29), b.addiu(12, 0, INSTALL))
    a.branch(4, 11, 12, 'validate_install')
    a.e(b.addiu(12, 0, BORROW))
    a.branch(4, 11, 12, 'validate_borrow')
    a.e(b.addiu(12, 0, HELPER))
    a.branch(4, 11, 12, 'validate_helper')
    a.absolute(12, CALLBACK_SITE)
    a.jump('validate_site')
    a.label('validate_helper')
    a.absolute(12, HELPER_SITE)
    a.jump('validate_site')
    a.label('validate_borrow')
    a.e(b.lw(12, UPSTREAM, 10))
    a.branch(5, 12, 0, 'validate_fault')
    a.absolute(12, BORROW_SITE)
    a.label('validate_site')
    a.e(b.lw(13, SITE, 10))
    a.branch(5, 12, 13, 'validate_fault')
    a.e(b.lw(12, PARENT, 10), b.lw(13, 0x1C, 29))
    a.branch(4, 12, 0, 'validate_fault')
    a.e(b.r_type(12, 13, 14, 0x2B))
    a.branch(4, 14, 0, 'validate_fault')
    a.e(b.sw(10, 0x28, 29), b.sw(12, 0x1C, 29),
        b.lw(11, 0x20, 29), b.addiu(11, 11, -1), b.sw(11, 0x20, 29))
    a.jump('validate_loop')
    a.label('validate_install')
    a.absolute(12, INSTALL_SITE)
    a.e(b.lw(13, SITE, 10))
    a.branch(5, 12, 13, 'validate_fault')
    a.e(b.lw(8, FRAME, 10), b.lw(9, UPSTREAM, 10))
    relation(8, 0x28, 9, 'validate_fault')
    a.e(b.lw(4, PARENT, 10), b.addiu(5, 0, birth.ENQUEUE_BEGIN))
    a.jump(birth_validate, True)
    a.branch(4, 2, 0, 'validate_fault')
    a.e(b.lw(10, 0x24, 29))
    for own, other in ((ENGINE, birth.ENGINE), (COPY, birth.COPY),
                       (METADATA, birth.METADATA), (UPSTREAM, birth.FRAME),
                       (ORIGIN, birth.ORIGIN)):
        a.e(b.lw(11, own, 10), b.lw(12, other, 2))
        a.branch(5, 11, 12, 'validate_fault')
    birth_check('validate_fault')
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
        raise ValueError('transport code must fit one MIPS jump region')
    if code_base <= birth_validate < end:
        raise ValueError('external private birth validator overlaps transport code')
    for start, length in regions:
        if max(start, code_base) < min(start + length, end):
            raise ValueError('private storage and transport code overlap')
    return code, a.labels
