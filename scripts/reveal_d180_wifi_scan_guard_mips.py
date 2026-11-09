#!/usr/bin/env python3
"""Emit the local RS2 1.4 wifi_scan factory-result guard."""

from build_reveal_bridge_diag import Asm, b
from reveal_d960_payload_guard_mips import _validate_code_base, _validate_code_extent


SITE = 0x4A4F24
ORIGINAL = (0x24030001, 0x3C04004A)  # addiu v1,zero,1; lui a0,0x4a


def assemble(code_base):
    """Keep the stock scan path for a live dialog and use the return-one exit for NULL."""
    _validate_code_base(code_base)
    asm = Asm(code_base)
    asm.branch(4, 2, 0, 'refuse')  # beq v0,zero
    asm.jump(SITE + 8, delay=ORIGINAL[1])
    asm.label('refuse')
    asm.jump(0x4A4A14)
    code = asm.finish()
    _validate_code_extent(code_base, len(code))
    return code, {SITE: (ORIGINAL, (b.j_type(2, code_base), ORIGINAL[0]))}
