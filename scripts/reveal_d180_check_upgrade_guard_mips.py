#!/usr/bin/env python3
"""Defer the RS2 update-check status until the dialog factory succeeds."""

from build_reveal_bridge_diag import Asm, b
from reveal_d960_payload_guard_mips import _validate_code_base, _validate_code_extent


ARM_SITE = 0x4D4FF0
RESULT_SITE = 0x4D5018
ARM = 0x454BA0


def assemble(code_base):
    """Return the arm move and the result guard for the native update wrapper."""
    _validate_code_base(code_base)
    asm = Asm(code_base)
    asm.branch(4, 16, 0, 'refused')  # S0 holds the factory result.
    asm.e(b.addiu(4, 0, 4))
    asm.jump(ARM, link=True, delay=b.addiu(5, 0, 1))
    asm.jump(RESULT_SITE + 8, delay=0x3C0200B9)
    asm.label('refused')
    asm.jump(0x4D5048)
    code = asm.finish()
    _validate_code_extent(code_base, len(code))
    return code, {
        ARM_SITE: ((0x0C1152E8, 0xAFA00038), (0, 0xAFA00038)),
        RESULT_SITE: ((0x00408021, 0x3C0200B9), (b.j_type(2, code_base), 0x00408021)),
    }
