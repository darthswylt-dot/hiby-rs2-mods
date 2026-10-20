#!/usr/bin/env python3
"""Emit a diagnostic clock for beginnings of audited contents mutations.

The permanent private 16-byte state consists of one monotonic counter and
three reserved zero words. bump() returns a fresh positive signed-31 revision
in v0, or zero after permanent failure. invalidate() stores FAULT and returns
zero. There is no finish, READY, reset, recovery, native pointer or reader API.
An unchanged clock only says that no additional instrumented beginning was
observed: a previously begun mutation may still be running. A returned revision
is historical, not currentness, a completed phase, a UI epoch or a lifetime
lease. Complete writer coverage and propagation remain external obligations.

Only a successful LL/SC changes the counter to another valid value. An aligned
sticky fault store defeats outstanding reservations; no plain counter store
can erase it. Exhaustion, malformed private state, or bounded retry loss faults
permanently. SYNC brackets transitions, but instruction tests do not prove the
target's cache or scheduler behavior. Storage must be private, initially zero,
never reset, and retained for all outstanding callers.

No native reads, external calls, allocations or stack accesses are emitted.
O32 callee-saved registers, SP, RA, HI/LO and reserved registers are preserved.
Only v0 and t0..t6 may be clobbered.
"""

from build_reveal_bridge_diag import Asm, b


STATE_OFFSET = 0
STATE_BYTES = 16
RESERVED = (4, 8, 12)
EMPTY = 0
REVISION_MASK = 0x7FFFFFFF
FAULT = 0xFFFFFFFF
DEFAULT_RETRIES = 8
SYNC = 0x0000000F


def memory_bytes():
    return STATE_BYTES


def build_revision(state_address, code_base, *, revision_limit=REVISION_MASK,
                   retries=DEFAULT_RETRIES):
    """Return (little-endian code bytes, absolute labels), with no I/O.

    Public entrypoints are bump and invalidate. RW state and RX code must be
    disjoint. The function neither installs nor initializes either region.
    """
    for name, value in (('state_address', state_address), ('code_base', code_base)):
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFC or value % 4:
            raise ValueError(name + ' must be an aligned unsigned-32 address')
    if state_address + STATE_BYTES > 0x100000000:
        raise ValueError('private state must not wrap the address space')
    if type(revision_limit) is not int or not 1 <= revision_limit <= REVISION_MASK:
        raise ValueError('revision_limit must be a positive signed-31 integer')
    if type(retries) is not int or not 1 <= retries <= 0x7FFF:
        raise ValueError('retries must be in 1..32767')

    a = Asm(code_base)
    # t0 state address; t1 retries; t2 observed counter; t3 scratch/SC result;
    # t4 newly issued revision; t6 maximum revision.
    a.label('bump')
    a.absolute(8, state_address)
    a.absolute(14, revision_limit)
    a.e(b.addiu(9, 0, retries), SYNC)
    for offset in RESERVED:
        a.e(b.lw(11, offset, 8))
        a.branch(5, 11, 0, 'fault')
    a.label('bump_ll')
    a.e(b.i_type(0x30, 8, 10, STATE_OFFSET),
        b.r_type(10, 14, 11, 0x2B))
    a.branch(4, 11, 0, 'fault')  # >= limit includes malformed high-bit states.
    a.e(b.addiu(12, 10, 1), b.move(11, 12))
    a.label('bump_sc')
    a.e(b.i_type(0x38, 8, 11, STATE_OFFSET))
    a.branch(5, 11, 0, 'bump_success')
    a.e(b.addiu(9, 9, -1))
    a.branch(5, 9, 0, 'bump_ll')
    a.jump('fault')
    a.label('bump_success')
    a.e(SYNC)
    a.label('bump_check')
    a.e(b.lw(10, STATE_OFFSET, 8), b.r_type(14, 10, 11, 0x2B))
    a.branch(5, 11, 0, 'fault')
    # A later successful bump does not revoke this already issued revision.
    # Invalidation after this check can still precede the return.
    a.e(SYNC, b.move(2, 12), b.r_type(31, 0, 0, 8), 0)

    a.label('invalidate')
    a.absolute(8, state_address)
    a.label('fault')
    a.e(b.addiu(11, 0, -1), SYNC)
    a.label('fault_store')
    a.e(b.sw(11, STATE_OFFSET, 8), SYNC, b.move(2, 0),
        b.r_type(31, 0, 0, 8), 0)

    code = a.finish()
    end = code_base + len(code)
    if end > 0x100000000 or code_base >> 28 != (end - 1) >> 28:
        raise ValueError('code must fit within one MIPS jump region')
    if state_address < end and code_base < state_address + STATE_BYTES:
        raise ValueError('private state and code must not overlap')
    return code, a.labels
