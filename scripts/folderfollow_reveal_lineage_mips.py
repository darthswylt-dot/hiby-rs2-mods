#!/usr/bin/env python3
"""Emit a bounded, append-only *diagnostic* lineage ledger for MIPS O32.

reserve(a0=kind, a1=parent token, a2=raw V, a3=raw P) returns a private
unpublished slot in v0 and a never-reused token in v1. Only RENDER/INITIAL
accept raw V/P; descendants inherit these scalars from a published private
parent. The caller fills payload fields, executes SYNC, then writes MAGIC at
MAGIC_OFFSET exactly once. Published records and their headers are immutable.
validate(a0=token, a1=exact kind or zero for any) returns a published private
slot in v0; v1 is unspecified. invalidate() permanently faults and returns
zero in both result registers. Invalid protocol, exhaustion, or bounded SC
failure also permanently fault. No entry resets state or reuses storage.

The ledger reads only its permanent, initially zeroed private BSS. V/P/job
values are diagnostic integers, never dereferenced. A successful validation
is historical, not a lease: concurrent invalidation can occur immediately
after the final check. Publication is NOT native object ownership, coherent
job bytes, a current UI epoch, completed rows, or permission for any setter.
The wrapper/native-copy coverage and immutable-private-memory discipline are
separate obligations; a magic word is not an authentication mechanism.

Only the allocator word is changed atomically. A sticky fault store invalidates
competing LL/SC reservations; no ordinary counter store can erase it. SYNC
marks acquire/publication boundaries, but instruction tests cannot establish
the target hardware's memory model. There are no external calls, native
reads, stack accesses, or runtime allocations. SP, RA, s0..s7, gp, HI/LO and
reserved registers are preserved; O32 volatile registers may be clobbered.
"""

from build_reveal_bridge_diag import Asm, b


HEADER, RECORD = 16, 64
STATE = 0
MAGIC_OFFSET = 0
MAGIC = int.from_bytes(b'LNRG', 'little')
KIND, ORIGIN, PARENT, VIEW, PANEL = 4, 8, 12, 16, 20
JOB, DEST, SITE, STACK, OFFSET, REQUEST, STMT, FLAGS = 24, 28, 32, 36, 40, 44, 48, 52
RENDER, INITIAL, BORROW, QUERY, PRODUCER = 1, 2, 3, 4, 5
FAULT = 0xFFFFFFFF
DEFAULT_CAPACITY, DEFAULT_RETRIES = 1024, 8
MAX_CAPACITY = (0x100000000 - HEADER) // RECORD
SYNC = 0x0000000F


def memory_bytes(capacity=DEFAULT_CAPACITY):
    if type(capacity) is not int or not 1 <= capacity <= MAX_CAPACITY:
        raise ValueError('capacity must fit a nonempty unsigned-32 ledger')
    return HEADER + RECORD * capacity


def build_lineage(state_address, code_base, capacity=DEFAULT_CAPACITY,
                  retries=DEFAULT_RETRIES):
    """Return (little-endian code bytes, absolute labels), without I/O.

    Public labels are reserve, validate and invalidate. The caller supplies
    distinct permanent RW zero-initialized ledger storage and RX code storage.
    Tokens are one-based record indices; zero and every unissued token fail.
    """
    size = memory_bytes(capacity)
    for name, value in (('state_address', state_address), ('code_base', code_base)):
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFC or value % 4:
            raise ValueError(name + ' must be an aligned unsigned-32 address')
    if state_address + size > 0x100000000:
        raise ValueError('private ledger must not wrap the address space')
    if type(retries) is not int or not 1 <= retries <= 0x7FFF:
        raise ValueError('retries must be in 1..32767')
    a = Asm(code_base)

    def setup(label):
        a.label(label)
        a.absolute(8, state_address)  # t0: immutable private base
        a.absolute(9, capacity)       # t1: limit, including malformed states
        a.e(SYNC)

    def global_check(label):
        a.label(label)
        a.e(b.lw(10, STATE, 8), b.r_type(9, 10, 11, 0x2B))
        a.branch(5, 11, 0, 'fault')  # counter > capacity includes sticky fault

    def slot_for(token, target):
        a.e(b.addiu(target, token, -1),
            (target << 16) | (target << 11) | (6 << 6),
            b.r_type(target, 8, target, 0x21), b.addiu(target, target, HEADER))

    def published(slot):
        a.e(b.lw(11, MAGIC_OFFSET, slot))
        a.absolute(12, MAGIC)
        a.branch(5, 11, 12, 'fault')
        a.e(SYNC)  # acquire the immutable header after publication

    def checked_record(token, prefix):
        # Leaves t7=record, t6=kind, t8=origin; uses only private addresses.
        global_check(prefix + '_global_before')
        a.branch(4, token, 0, 'fault')
        a.e(b.r_type(10, token, 11, 0x2B))
        a.branch(5, 11, 0, 'fault')
        slot_for(token, 15)
        published(15)
        a.e(b.lw(14, KIND, 15))
        a.branch(4, 14, 0, 'fault')
        a.e(b.i_type(11, 14, 11, PRODUCER + 1))
        a.branch(4, 11, 0, 'fault')
        a.e(b.lw(24, ORIGIN, 15))
        a.branch(4, 24, 0, 'fault')
        a.e(b.r_type(token, 24, 11, 0x2B))
        a.branch(5, 11, 0, 'fault')
        slot_for(24, 13)
        published(13)
        a.e(b.lw(11, KIND, 13), b.addiu(11, 11, -1), b.i_type(11, 11, 11, 2))
        a.branch(4, 11, 0, 'fault')
        a.e(b.lw(11, ORIGIN, 13))
        a.branch(5, 11, 24, 'fault')
        a.e(b.lw(11, PARENT, 13))
        a.branch(5, 11, 0, 'fault')
        for offset in (VIEW, PANEL):
            a.e(b.lw(11, offset, 13), b.lw(12, offset, 15))
            a.branch(5, 11, 12, 'fault')
        a.e(b.i_type(11, 14, 11, BORROW))
        a.branch(5, 11, 0, prefix + '_root')
        a.e(b.lw(13, PARENT, 15))
        a.branch(4, 13, 0, 'fault')
        a.e(b.r_type(13, token, 11, 0x2B))
        a.branch(4, 11, 0, 'fault')
        slot_for(13, 13)
        published(13)
        a.e(b.lw(11, ORIGIN, 13))
        a.branch(5, 11, 24, 'fault')
        a.e(b.lw(11, KIND, 13), b.addiu(12, 0, BORROW))
        a.branch(4, 14, 12, prefix + '_borrow_parent')
        a.e(b.addiu(12, 14, -1))
        a.branch(5, 11, 12, 'fault')
        a.jump(prefix + '_checked')
        a.label(prefix + '_borrow_parent')
        a.e(b.addiu(11, 11, -1), b.i_type(11, 11, 11, 2))
        a.branch(4, 11, 0, 'fault')
        a.e(b.lw(11, PARENT, 15))
        a.branch(5, 11, 24, 'fault')
        a.jump(prefix + '_checked')
        a.label(prefix + '_root')
        a.branch(5, 24, token, 'fault')
        a.e(b.lw(11, PARENT, 15))
        a.branch(5, 11, 0, 'fault')
        a.label(prefix + '_checked')
        a.e(SYNC)
        global_check(prefix + '_global_after')

    setup('reserve')
    a.branch(4, 4, 0, 'fault')
    a.e(b.i_type(11, 4, 11, PRODUCER + 1))
    a.branch(4, 11, 0, 'fault')
    a.e(b.i_type(11, 4, 11, BORROW))
    a.branch(5, 11, 0, 'reserve_origin')
    checked_record(5, 'parent')
    a.e(b.addiu(11, 0, BORROW))
    a.branch(4, 4, 11, 'reserve_borrow')
    a.e(b.addiu(11, 4, -1))
    a.branch(5, 14, 11, 'fault')
    a.jump('reserve_inherit')
    a.label('reserve_borrow')
    a.e(b.i_type(11, 14, 11, BORROW))
    a.branch(4, 11, 0, 'fault')
    a.label('reserve_inherit')
    a.e(b.lw(6, VIEW, 15), b.lw(7, PANEL, 15))
    a.jump('reserve_allocate')
    a.label('reserve_origin')
    a.branch(5, 5, 0, 'fault')
    a.e(b.move(24, 0))
    a.label('reserve_allocate')
    a.e(b.addiu(14, 0, retries), SYNC)
    a.label('reserve_ll')
    a.e(b.i_type(0x30, 8, 10, STATE), b.r_type(10, 9, 11, 0x2B))
    a.branch(4, 11, 0, 'fault')
    a.e(b.addiu(3, 10, 1), b.move(11, 3))
    a.label('reserve_sc')
    a.e(b.i_type(0x38, 8, 11, STATE))
    a.branch(5, 11, 0, 'reserve_allocated')
    a.e(b.addiu(14, 14, -1))
    a.branch(5, 14, 0, 'reserve_ll')
    a.jump('fault')
    a.label('reserve_allocated')
    a.e(SYNC)
    slot_for(3, 15)
    # Fresh BSS and no reuse are required; a previously published slot faults.
    a.e(b.lw(11, MAGIC_OFFSET, 15))
    a.branch(5, 11, 0, 'fault')
    a.branch(5, 24, 0, 'reserve_write')
    a.e(b.move(24, 3))
    a.label('reserve_write')
    for register, offset in ((4, KIND), (24, ORIGIN), (5, PARENT),
                             (6, VIEW), (7, PANEL)):
        a.e(b.sw(register, offset, 15))
    a.e(SYNC)
    global_check('reserve_global_after')
    a.e(b.move(2, 15), SYNC, b.r_type(31, 0, 0, 8), 0)

    setup('validate')
    a.e(b.i_type(11, 5, 11, PRODUCER + 1))
    a.branch(4, 11, 0, 'fault')
    checked_record(4, 'validate_record')
    a.branch(4, 5, 0, 'validate_success')
    a.branch(5, 5, 14, 'fault')
    a.label('validate_success')
    a.e(b.move(2, 15), SYNC, b.r_type(31, 0, 0, 8), 0)

    setup('invalidate')
    a.label('fault')
    a.e(b.addiu(11, 0, -1), SYNC)
    a.label('fault_store')
    a.e(b.sw(11, STATE, 8), SYNC, b.move(2, 0), b.move(3, 0),
        b.r_type(31, 0, 0, 8), 0)

    code = a.finish()
    end = code_base + len(code)
    if end > 0x100000000 or code_base >> 28 != (end - 1) >> 28:
        raise ValueError('code must fit within one MIPS jump region')
    if state_address < end and code_base < state_address + size:
        raise ValueError('private ledger and code must not overlap')
    return code, a.labels
