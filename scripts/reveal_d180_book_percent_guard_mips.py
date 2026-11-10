#!/usr/bin/env python3
"""Emit the RS2 1.4 book-percent dialog cleanup on factory refusal."""

from build_reveal_bridge_diag import Asm, b
from reveal_d960_payload_guard_mips import _validate_code_base, _validate_code_extent


SITE = 0x5276B8
ORIGINAL = (0xAC500058, 0x8FBF004C)
RELEASE = 0x466A80


def assemble(code_base):
    """Publish the payload on success or release it before the native return."""
    _validate_code_base(code_base)
    asm = Asm(code_base)
    asm.branch(4, 2, 0, 'refused')  # beq v0,zero
    asm.jump(SITE + 8, delay=ORIGINAL[0])
    asm.label('refused')
    asm.branch(4, 16, 0, 'return_null')  # beq s0,zero
    asm.jump(RELEASE, link=True, delay=b.move(4, 16))
    asm.label('return_null')
    # Reload the saved RA after the cleanup call and restore the original frame.
    asm.jump(SITE + 4, delay=b.move(2, 0))
    code = asm.finish()
    _validate_code_extent(code_base, len(code))
    return code, {SITE: (ORIGINAL, (b.j_type(2, code_base), ORIGINAL[1]))}
