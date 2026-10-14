#!/usr/bin/env python3
"""Emit a private-memory MIPS mutation guard, not a reveal/UI operation.

One aligned word is the entire atomic state. Zero means EMPTY; a positive
signed-31 ticket means READY; WRITER_MASK | ticket means WRITER; FAULT is
terminal. READY means only that the matching instrumented mutation finished.
It is NOT a copied identity, a coherent snapshot, currentness, retained object
ownership, or permission to call any UI setter.

begin() returns a fresh positive ticket, or zero after permanent failure.
finish(a0=ticket) returns one only when it atomically publishes that writer.
invalidate() permanently withdraws readiness and returns zero. Calls preserve
O32 callee-saved registers, SP, RA, HI and LO; only v0 and t0..t6 are clobbered.
There are no stock pointers, external calls, stack accesses, or allocations.

The packed word avoids a separate phase/revision initialization window. Every
successful begin withdraws READY before returning to a stock mutation. Only
that ticket can finish. Observing another WRITER, a bad completion, exhaustion,
or bounded LL/SC retry failure faults. A plain aligned fault store invalidates
competing reservations; no successful CAS may subsequently overwrite FAULT.
SYNC brackets state transitions. These rely on the target's coherent LL/SC and
SYNC implementation; instruction tests do not prove a hardware memory model.

Unlike the host model, the terminal fault encoding discards its old revision;
there is no recovery or wrapping. Successfully issued tickets strictly increase
from 1 through revision_limit. A return value is not a lease: invalidation can
occur after a successful operation's linearization and before its return.
"""

from build_reveal_bridge_diag import Asm, b


STATE_OFFSET = 0
STATE_BYTES = 4
EMPTY = 0
WRITER_MASK = 0x80000000
FAULT = WRITER_MASK
REVISION_MASK = 0x7FFFFFFF
DEFAULT_RETRIES = 8
SYNC = 0x0000000F


def build_guard(state_address, code_base, *, revision_limit=REVISION_MASK,
                retries=DEFAULT_RETRIES):
    """Return (little-endian code bytes, absolute labels), without any I/O.

Entrypoint labels: begin, finish, invalidate. The caller must provide distinct
permanent RW zero-initialized state and RX code storage. This function does not
install or initialize either, instrument all writers, or create a reader API.
    """
    for name, value in (('state_address', state_address), ('code_base', code_base)):
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFC or value % 4:
            raise ValueError(name + ' must be an aligned unsigned-32 address')
    if type(revision_limit) is not int or not 1 <= revision_limit <= REVISION_MASK:
        raise ValueError('revision_limit must be a positive signed-31 integer')
    if type(retries) is not int or not 1 <= retries <= 0x7FFF:
        raise ValueError('retries must be in 1..32767')
    a = Asm(code_base)
    # t0 state address; t1 remaining retries; t2 observed control;
    # t3 scratch/SC result; t4 fresh ticket; t5 mask; t6 revision limit.
    def setup(label):
        a.label(label)
        a.absolute(8, state_address)
        a.absolute(13, WRITER_MASK)
        a.absolute(14, revision_limit)
        a.e(b.addiu(9, 0, retries), SYNC)

    def retry(label):
        a.e(b.addiu(9, 9, -1))
        a.branch(5, 9, 0, label)
        a.jump('fault')

    def ret(value_register):
        a.e(SYNC, b.move(2, value_register), b.r_type(31, 0, 0, 8), 0)

    setup('begin')
    a.label('begin_ll')
    a.e(b.i_type(0x30, 8, 10, STATE_OFFSET))
    # A high bit means WRITER or FAULT. Both permanently fail closed.
    a.e((10 << 16) | (11 << 11) | (31 << 6) | 2)  # srl t3,t2,31
    a.branch(5, 11, 0, 'fault')
    # Guard >= limit, including malformed values under a smaller test limit.
    a.e(b.r_type(10, 14, 11, 0x2B))  # sltu t3,t2,t6
    a.branch(4, 11, 0, 'fault')
    a.e(b.addiu(12, 10, 1), b.r_type(12, 13, 11, 0x21))
    a.label('begin_sc')
    a.e(b.i_type(0x38, 8, 11, STATE_OFFSET))
    a.branch(5, 11, 0, 'begin_success')
    retry('begin_ll')
    a.label('begin_success')
    ret(12)

    setup('finish')
    a.branch(4, 4, 0, 'fault')
    a.e(b.r_type(14, 4, 11, 0x2B))  # sltu t3,t6,a0
    a.branch(5, 11, 0, 'fault')
    a.e(b.r_type(4, 13, 12, 0x21))  # expected WRITER | ticket
    a.label('finish_ll')
    a.e(b.i_type(0x30, 8, 10, STATE_OFFSET))
    a.branch(5, 10, 12, 'fault')
    a.e(b.move(11, 4))
    a.label('finish_sc')
    a.e(b.i_type(0x38, 8, 11, STATE_OFFSET))
    a.branch(5, 11, 0, 'finish_success')
    retry('finish_ll')
    a.label('finish_success')
    a.e(b.addiu(11, 0, 1))
    ret(11)

    a.label('invalidate')
    a.absolute(8, state_address)
    a.absolute(13, FAULT)
    a.label('fault')
    a.e(SYNC)
    a.label('fault_store')
    a.e(b.sw(13, STATE_OFFSET, 8))
    ret(0)

    code = a.finish()
    end = code_base + len(code)
    if end > 0x100000000 or code_base >> 28 != (end - 1) >> 28:
        raise ValueError('code must fit within one MIPS jump region')
    if state_address < end and code_base < state_address + STATE_BYTES:
        raise ValueError('private state and code must not overlap')
    return code, a.labels
