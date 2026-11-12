#!/usr/bin/env python3
"""Emit allocation and factory refusal handling for the ordinary RS2 QR dialog."""

from build_reveal_bridge_diag import Asm, b
from reveal_d960_payload_guard_mips import _validate_code_base, _validate_code_extent


MODE_SITE, OWNER_SITE, RESULT_SITE = 0x501A54, 0x501A80, 0x501A9C
RESULT_PAIR = (0x3C040050, 0x24841680)
QR_NAME, RETURN, RELEASE = 0x94DE78, 0x501AB8, 0x466A80
OWNER_FLAG = 0x208
SELECTOR, SAVED_OWNER = 0x3C, 0x40


def assemble(code_base):
    _validate_code_base(code_base)
    asm = Asm(code_base)

    asm.branch(5, 2, 0, 'generic_mode')
    asm.branch(4, 16, 0, 'return_empty')  # Ordinary mode requires the payload.
    asm.jump(MODE_SITE + 8)
    asm.label('generic_mode')
    asm.jump(0x501AD4)

    asm.label('owner')
    # A3 is set to zero in the original factory call delay. The selector
    # remains in our frame across the call, where zero means ordinary QR.
    asm.absolute(7, QR_NAME)
    asm.e(b.r_type(4, 7, 7, 0x26))  # xor a3,a0,a3
    asm.e(b.sw(7, SELECTOR, 29))
    asm.branch(5, 7, 0, 'clear_owner')
    asm.e(b.lw(7, OWNER_FLAG, 18), b.sw(7, SAVED_OWNER, 29))
    asm.label('clear_owner')
    asm.jump(OWNER_SITE + 8, delay=b.sw(0, OWNER_FLAG, 18))

    asm.label('result')
    asm.branch(5, 2, 0, 'resume')
    asm.e(b.lw(4, SELECTOR, 29))
    asm.branch(5, 4, 0, 'resume')
    asm.jump(RELEASE, link=True, delay=b.move(4, 16))
    asm.label('restore_owner')
    asm.e(b.lw(5, SAVED_OWNER, 29))
    asm.branch(4, 5, 0, 'return_empty')
    # Retry an interrupted restore while the word remains zero. A nonzero
    # update belongs to its writer and ends our rollback.
    asm.e(b.i_type(0x30, 18, 4, OWNER_FLAG))  # ll a0,owner+0x208
    asm.branch(5, 4, 0, 'return_empty')
    asm.e(b.i_type(0x38, 18, 5, OWNER_FLAG))  # sc a1,owner+0x208
    asm.branch(4, 5, 0, 'restore_owner')
    asm.label('return_empty')
    asm.jump(RETURN, delay=b.move(2, 0))
    asm.label('resume')
    asm.e(RESULT_PAIR[0])
    asm.jump(RESULT_SITE + 8, delay=RESULT_PAIR[1])

    code = asm.finish()
    _validate_code_extent(code_base, len(code))
    return code, {
        MODE_SITE: ((0x1440001F, 0), (b.j_type(2, code_base), 0)),
        OWNER_SITE: ((0x27A20020, 0xAE400208), (b.j_type(2, asm.labels['owner']), 0x27A20020)),
        RESULT_SITE: (RESULT_PAIR, (b.j_type(2, asm.labels['result']), 0)),
    }
