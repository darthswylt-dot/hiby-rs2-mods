#!/usr/bin/env python3
"""Uninstalled MIPS32 geometry core for the host-only reveal specification.

This emits a position-independent O32 leaf function, NOT a patched firmware
image. There is no hook, installer, object lookup, lock, setter or refresh.
The live row/owner/gesture adapter is deliberately absent until audited.
"""

from build_folderfollow_fill_diag import Asm
from build_folderfollow_saved_path_rebuild import addiu, lw, move, r_type, i_type


def build_geometry() -> bytes:
    """Implement minimal_reveal(row, count, pitch, height, scroll_y).

    O32 inputs: a0=row, a1=count, a2=pitch, a3=height, [entry_sp+16]=y.
    Result v0: -1 for invalid/unsupported geometry, otherwise target y >= 0.
    Unchanged y means already visible; caller must not issue a setter for it.

    Inputs are 32-bit scalar values, not pointers. Preserves argument registers,
    s0..s7, fp, gp, sp and ra; clobbers v0, t0..t5 and HI/LO (O32 volatile).
    Reads only the fifth stack argument. No memory writes or external calls.
    Branch and return delay slots are explicit nops. The reused assembler has
    a fixed bookkeeping base, but only PC-relative branches are emitted, so
    these bytes can be relocated without fixups. No code-cave space is claimed.
    """
    a = Asm()
    z, v0, row, count, pitch, height, sp, ra = 0, 2, 4, 5, 6, 7, 29, 31
    y, extent, limit, test, edge, visible_bottom = 8, 9, 10, 11, 12, 13

    def branch(op, rs, rt, target):
        a.branch(op, rs, rt, target)

    def go(target):
        branch(4, z, z, target)

    # Bound the whole-folder count. Unsigned comparisons also reject negative
    # row/count bit patterns; positive pitch and height use signed guards.
    branch(4, count, z, 'invalid')
    a.e(i_type(11, count, test, 513))  # sltiu test,count,513
    branch(4, test, z, 'invalid')
    a.e(r_type(row, count, test, 0x2B))  # row < count, unsigned
    branch(4, test, z, 'invalid')
    branch(6, pitch, z, 'invalid')  # blez pitch
    a.e(r_type(height, pitch, test, 0x2A))
    branch(5, test, z, 'invalid')  # includes negative/zero/tall-row height
    a.e(lw(y, 16, sp))
    branch(1, y, 0, 'invalid')  # bltz y

    # Reject both >32-bit and >signed-32-bit extent before any subtraction.
    a.e(r_type(count, pitch, 0, 0x19), r_type(0, 0, test, 0x10))
    branch(5, test, z, 'invalid')
    a.e(r_type(0, 0, extent, 0x12))
    branch(1, extent, 0, 'invalid')
    a.e(r_type(extent, height, limit, 0x23))
    branch(1, limit, 1, 'limit_ready')  # bgez
    a.e(move(limit, z))
    a.label('limit_ready')
    a.e(r_type(limit, y, test, 0x2B))
    branch(5, test, z, 'invalid')  # do not correct manual overscroll
    a.e(r_type(y, height, visible_bottom, 0x21))
    branch(1, visible_bottom, 0, 'invalid')

    # row<count and checked extent make row*pitch and (row+1)*pitch safe.
    a.e(r_type(row, pitch, 0, 0x19), r_type(0, 0, edge, 0x12))
    a.e(r_type(edge, y, test, 0x2B))
    branch(5, test, z, 'above')
    a.e(r_type(edge, pitch, edge, 0x21))
    a.e(r_type(visible_bottom, edge, test, 0x2B))
    branch(4, test, z, 'visible')
    a.e(r_type(edge, height, v0, 0x23))
    go('return')
    a.label('above')
    a.e(move(v0, edge))
    go('return')
    a.label('visible')
    a.e(move(v0, y))
    go('return')
    a.label('invalid')
    a.e(addiu(v0, z, -1))
    a.label('return')
    a.e(r_type(ra, z, z, 8), 0)
    return a.finish()
