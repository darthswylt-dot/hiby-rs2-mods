#!/usr/bin/env python3
"""Local coherent snapshots for two callers preserving the scalar userId.

Replace each adjacent copy/get-field sequence with one checked mutex span.
Text and scalar are captured from the same primary response; a capacity check
precedes copying strlen+1 bytes into the native zeroed 128-byte destination.
The original native continuation keeps the scalar in S4 or S3 before calling
41FEC0 outside the mutex. These helpers do not hold native response aliases.

All 41 composed redirects require coherent activation, retained 52-byte sidecar,
valid nonaliasing caller frames plus 192 helper stack bytes, normal libc calls
and the selected primary-class scalar interpretation of +4. Errors use the
native stack-only return-zero tails, skipping opaque APIs/UI inside the caller.
Outer callers do not thereby gain quarantine or request freshness. Raw errors
latch FAILED without guessed unlock; failed unlock can follow a completed copy.
This is partial local integration with no firmware builder or device operation.
"""

from build_reveal_bridge_diag import Asm, b
import reveal_tidal_session_disposal_mips as disposal
import reveal_tidal_response_reader_bridge_mips as session
from reveal_registry_receipt_mips import FRAME, HI, LO, SAVE
from reveal_d960_payload_guard_mips import _validate_code_extent


SNAPSHOTS = (
    # Name, first call/pair, second call/pair, buffer offset, pure failure tail.
    ('large', 0x4AAC48, (0x0C12C588, 0x27A40BAC),
     0x4AAC50, (0x0C12C5A8, 0), 0xBAC, 0x4AADA4),
    ('small', 0x4AB2F8, (0x0C12C588, 0x27A403B4),
     0x4AB300, (0x0C12C5A8, 0), 0x3B4, 0x4AB35C),
)
CAPACITY, STRLEN, COPY = 128, 0xA5B4E0, 0xA5B6E0
TEXT, USER_ID, ERROR = 0x90, 0x94, 0x98


def assemble(mutex_address, code_base):
    prefix, patches = disposal.assemble(mutex_address, code_base)
    asm = Asm(code_base + len(prefix))

    def control():
        asm.absolute(8, mutex_address)

    def save():
        asm.e(b.addiu(29, 29, -FRAME))
        for register, offset in SAVE.items():
            asm.e(b.sw(register, offset, 29))
        asm.e(b.r_type(0, 0, 8, 0x10), b.sw(8, HI, 29),
              b.r_type(0, 0, 8, 0x12), b.sw(8, LO, 29))

    def restore():
        asm.e(b.lw(8, HI, 29), b.r_type(8, 0, 0, 0x11),
              b.lw(8, LO, 29), b.r_type(8, 0, 0, 0x13))
        for register, offset in SAVE.items():
            asm.e(b.lw(register, offset, 29))
        asm.e(b.addiu(29, 29, FRAME))

    for name, site, original, second, second_pair, _, failure in SNAPSHOTS:
        patches[site] = original, (b.j_type(2, asm.base + len(asm.w) * 4), 0)
        asm.e(original[1])
        save()
        control()
        asm.e(b.lw(9, session.PHASE, 8), b.addiu(10, 0, session.READY))
        asm.branch(5, 9, 10, name + '_unavailable')
        asm.e(0xF)
        asm.absolute(4, mutex_address)
        asm.jump(session.LOCK, link=True)
        asm.branch(5, 2, 0, name + '_raw_error')
        control()
        asm.e(b.lw(9, session.PHASE, 8), b.addiu(10, 0, session.READY), b.addiu(2, 0, 11))
        asm.branch(5, 9, 10, name + '_unlock_error')
        asm.e(b.lw(9, session.LIFECYCLE, 8), b.addiu(10, 0, session.LIVE), b.addiu(2, 0, 116))
        asm.branch(5, 9, 10, name + '_unlock_error')
        asm.e(b.lw(11, session.BOUND_SESSION, 8))
        asm.branch(4, 11, 0, name + '_unlock_error')
        asm.absolute(9, session.SESSION_SLOT)
        asm.e(b.lw(10, 0, 9))
        asm.branch(5, 10, 11, name + '_unlock_error')
        asm.e(b.lw(13, 0x18, 11), b.addiu(2, 0, 61))
        asm.branch(4, 13, 0, name + '_unlock_error')
        asm.e(b.lw(14, 8, 13), b.addiu(2, 0, 22))
        asm.branch(4, 14, 0, name + '_unlock_error')
        asm.e(b.lw(15, 4, 13), b.sw(14, TEXT, 29), b.sw(15, USER_ID, 29), b.move(4, 14))
        asm.jump(STRLEN, link=True)
        asm.e(b.i_type(11, 2, 9, CAPACITY), b.addiu(6, 2, 1), b.addiu(2, 0, 75))
        asm.branch(4, 9, 0, name + '_unlock_error')
        asm.e(b.lw(4, SAVE[4], 29), b.lw(5, TEXT, 29))
        asm.jump(COPY, link=True)
        asm.absolute(4, mutex_address)
        asm.jump(session.UNLOCK, link=True)
        asm.branch(5, 2, 0, name + '_raw_error')
        asm.e(b.lw(8, USER_ID, 29), b.sw(8, SAVE[2], 29), b.sw(0, SAVE[3], 29))
        asm.absolute(8, second + 8)
        asm.e(b.sw(8, SAVE[31], 29))
        restore()
        asm.jump(second + 8, delay=second_pair[1])

        asm.label(name + '_unavailable')
        control()
        asm.e(0xF, b.lw(2, session.INIT_ERROR, 8))
        asm.branch(5, 2, 0, name + '_abort')
        asm.jump(name + '_abort', delay=b.addiu(2, 0, 11))
        asm.label(name + '_unlock_error')
        asm.e(b.sw(2, ERROR, 29))
        asm.absolute(4, mutex_address)
        asm.jump(session.UNLOCK, link=True)
        asm.branch(5, 2, 0, name + '_raw_error')
        asm.jump(name + '_abort', delay=b.lw(2, ERROR, 29))
        asm.label(name + '_raw_error')
        control()
        asm.e(b.sw(2, session.INIT_ERROR, 8), b.addiu(9, 0, session.FAILED),
              0xF, b.sw(9, session.PHASE, 8), 0xF)
        asm.label(name + '_abort')
        asm.e(b.sw(2, SAVE[3], 29), b.addiu(8, 0, -1), b.sw(8, SAVE[2], 29))
        restore()
        asm.jump(failure)

    code = prefix + asm.finish()
    _validate_code_extent(code_base, len(code))
    if code_base < mutex_address + session.CONTROL_BYTES and mutex_address < code_base + len(code):
        raise ValueError('preserved snapshot helpers overlap the sidecar')
    return code, patches
