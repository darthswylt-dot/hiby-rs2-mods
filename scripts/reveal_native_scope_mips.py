#!/usr/bin/env python3
"""Emit a private diagnostic guard for audited reset/reconcile invocations.

begin(a0=kind, a1=native frame, a2=raw argument 0, a3=raw argument 1)
returns its own non-reused ticket in v0, or zero on permanent fault.
end(a0=ticket, a1=kind, a2=native frame, a3=actual native result)
closes that exact published invocation and returns zero. Raw addresses are
numeric evidence only: no native pointer is dereferenced and no native call
is made. O32 callee-saved registers, SP/RA and HI/LO are untouched.

The packed issued/active update precedes publication, so a paused begin still
counts as active. Slot identity is immutable after publication; status/result
are one-shot closure fields, not an append-only event log. A terminal fault
overrides all slots, including any publication racing that fault. There is no
reset, reuse, ready state, owner proof, successful-write proof or UI authority.
SYNC and bounded LL/SC are emitted; instruction tests do not establish target
cache ordering, coherent acquisition, native lifetime or exhaustive writers.
"""

from build_reveal_bridge_diag import Asm, b


HEADER, RECORD = 16, 32
STATE, FAULT = 0, 0xFFFFFFFF
ISSUED_MASK, ACTIVE_MASK, ACTIVE_SHIFT = 0xFFFF, 0x7FFF0000, 16
ACTIVE_MAX, DEFAULT_CAPACITY, MAX_CAPACITY, RETRIES = 0x7FFF, 1024, 0xFFFF, 8
MAGIC_OFFSET, MAGIC = 0, int.from_bytes(b'LSCP', 'little')
KIND, TICKET, FRAME, RAWARG0, RAWARG1, STATUS, RESULT = 4, 8, 12, 16, 20, 24, 28
RESET, RECONCILE = 1, 2
OPEN, CLOSING, CLOSED = 1, 2, 3
SYNC = 0x0000000F


def memory_bytes(capacity=DEFAULT_CAPACITY):
    if type(capacity) is not int or not 1 <= capacity <= MAX_CAPACITY:
        raise ValueError('capacity must be an integer in 1..65535')
    return HEADER + RECORD * capacity


def assemble(scope_address, code_base, capacity=DEFAULT_CAPACITY):
    """Return (code bytes, absolute labels); public begin/end/invalidate."""
    size = memory_bytes(capacity)
    for name, value in (('scope_address', scope_address), ('code_base', code_base)):
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFC or value % 4:
            raise ValueError(name + ' must be an aligned unsigned-32 address')
    if scope_address + size > 0x100000000:
        raise ValueError('private scope storage must not wrap the address space')
    a = Asm(code_base)

    def kind_check(register):
        a.branch(4, register, 0, 'invalidate')
        a.e(b.i_type(11, register, 12, RECONCILE + 1))
        a.branch(4, 12, 0, 'invalidate')

    def frame_check(register):
        a.branch(4, register, 0, 'invalidate')
        a.e(b.i_type(12, register, 12, 3))
        a.branch(5, 12, 0, 'invalidate')

    def state_check():
        # t0=state address; t1=raw, t2=issued, t3=active; t4/t8 scratch.
        a.e((9 << 16) | (12 << 11) | (31 << 6) | 2)
        a.branch(5, 12, 0, 'invalidate')
        a.e(b.i_type(12, 9, 10, ISSUED_MASK),
            (9 << 16) | (11 << 11) | (ACTIVE_SHIFT << 6) | 2)
        a.absolute(24, capacity)
        a.e(b.r_type(24, 10, 12, 0x2B))
        a.branch(5, 12, 0, 'invalidate')
        a.e(b.r_type(10, 11, 12, 0x2B))
        a.branch(5, 12, 0, 'invalidate')

    def issued_at_least(register):
        a.e(b.r_type(10, register, 12, 0x2B))
        a.branch(5, 12, 0, 'invalidate')
        a.branch(4, 11, 0, 'invalidate')

    a.label('begin')
    kind_check(4)
    frame_check(5)
    a.absolute(8, scope_address)
    a.e(b.addiu(14, 0, RETRIES), SYNC)
    a.label('begin_ll')
    a.e(b.i_type(0x30, 8, 9, STATE))
    state_check()
    a.branch(4, 10, 24, 'invalidate')
    a.e(b.addiu(12, 0, ACTIVE_MAX))
    a.branch(4, 11, 12, 'invalidate')
    a.e(b.addiu(25, 10, 1))
    a.absolute(12, 0x10001)
    a.e(b.r_type(9, 12, 15, 0x21))
    a.label('begin_sc')
    a.e(b.i_type(0x38, 8, 15, STATE))
    a.branch(5, 15, 0, 'begin_reserved')
    a.e(b.addiu(14, 14, -1))
    a.branch(5, 14, 0, 'begin_ll')
    a.jump('invalidate')
    a.label('begin_reserved')
    a.e((10 << 16) | (13 << 11) | (5 << 6),
        b.r_type(8, 13, 13, 0x21), b.addiu(13, 13, HEADER), SYNC,
        b.lw(12, MAGIC_OFFSET, 13))
    a.branch(5, 12, 0, 'invalidate')
    for source, offset in ((4, KIND), (25, TICKET), (5, FRAME), (6, RAWARG0), (7, RAWARG1)):
        a.e(b.sw(source, offset, 13))
    a.e(b.addiu(12, 0, OPEN), b.sw(12, STATUS, 13), b.sw(0, RESULT, 13))
    a.label('begin_publish')
    a.e(SYNC, b.lw(9, STATE, 8))
    state_check()
    issued_at_least(25)
    a.e(SYNC)
    a.absolute(12, MAGIC)
    a.label('begin_magic_store')
    a.e(b.sw(12, MAGIC_OFFSET, 13), SYNC, b.move(2, 25))
    a.label('begin_done')
    a.e(b.r_type(31, 0, 0, 8), 0)

    a.label('end')
    kind_check(5)
    frame_check(6)
    a.branch(4, 4, 0, 'invalidate')
    a.absolute(8, scope_address)
    a.e(SYNC, b.lw(9, STATE, 8))
    state_check()
    issued_at_least(4)
    a.e(b.addiu(13, 4, -1), (13 << 16) | (13 << 11) | (5 << 6),
        b.r_type(8, 13, 13, 0x21), b.addiu(13, 13, HEADER), SYNC)
    for offset, register in ((MAGIC_OFFSET, None), (TICKET, 4), (KIND, 5), (FRAME, 6)):
        a.e(b.lw(12, offset, 13))
        if register is None:
            a.absolute(15, MAGIC)
            register = 15
        a.branch(5, 12, register, 'invalidate')
    a.e(b.addiu(8, 13, STATUS), b.addiu(14, 0, RETRIES), SYNC)
    a.label('end_status_ll')
    a.e(b.i_type(0x30, 8, 9, 0), b.addiu(12, 0, OPEN))
    a.branch(5, 9, 12, 'invalidate')
    a.e(b.addiu(15, 0, CLOSING))
    a.label('end_status_sc')
    a.e(b.i_type(0x38, 8, 15, 0))
    a.branch(5, 15, 0, 'end_claimed')
    a.e(b.addiu(14, 14, -1))
    a.branch(5, 14, 0, 'end_status_ll')
    a.jump('invalidate')
    a.label('end_claimed')
    a.e(b.sw(7, RESULT, 13), SYNC, b.addiu(12, 0, CLOSED), b.sw(12, STATUS, 13), SYNC)
    a.absolute(8, scope_address)
    a.e(b.addiu(14, 0, RETRIES))
    a.label('end_state_ll')
    a.e(b.i_type(0x30, 8, 9, STATE))
    state_check()
    issued_at_least(4)
    a.absolute(12, 0xFFFF0000)
    a.e(b.r_type(9, 12, 15, 0x21))
    a.label('end_state_sc')
    a.e(b.i_type(0x38, 8, 15, STATE))
    a.branch(5, 15, 0, 'end_done')
    a.e(b.addiu(14, 14, -1))
    a.branch(5, 14, 0, 'end_state_ll')
    a.jump('invalidate')
    a.label('end_done')
    a.e(SYNC, b.move(2, 0), b.r_type(31, 0, 0, 8), 0)

    a.label('invalidate')
    a.absolute(8, scope_address)
    a.e(b.addiu(15, 0, -1), SYNC)
    a.label('fault_store')
    a.e(b.sw(15, STATE, 8), SYNC, b.move(2, 0), b.r_type(31, 0, 0, 8), 0)

    code = a.finish()
    end = code_base + len(code)
    if end > 0x100000000 or code_base >> 28 != (end - 1) >> 28:
        raise ValueError('scope code must fit one MIPS jump region')
    if max(scope_address, code_base) < min(scope_address + size, end):
        raise ValueError('private scope storage and code overlap')
    return code, a.labels
