#!/usr/bin/env python3
"""Retain the selected direct-response branch of native 48D820 until return.

The entry only zeros two unused frame locals; unrelated paths do not enter the
session protocol. The getter site claims BORROWS and records pointer/generation.
Both ordinary native epilogues release that claim, including the early NULL
response path. Keeping it to function return also covers native postprocessing.
There is no entry-wide availability gate or mutex around external services.

The pinned frame has 1392 bytes; +544/+548 follow the one-word status output
and precede saved S0. All four redirects require coherent activation. Native
frames/objects and the selected service/class bindings must remain valid;
callees return normally and obey their bounded output/stack ABI. Nonlocal exits
and dynamic callers are outside this fixture. External native callbacks may
continue after a nested fault until a guarded epilogue is reached.

Raw errors latch FAILED without guessed unlock, counter rollback or repeated
object release. Errors use a private copy of the native stack-only epilogue.
Already produced native effects persist, and owned objects/counts can remain
unresolved. This is local partial integration, not an installable image.
"""

from build_reveal_bridge_diag import Asm, b
import reveal_tidal_qr_generation_mips as qr
import reveal_tidal_response_reader_bridge_mips as session
from reveal_registry_receipt_mips import FRAME, HI, LO, SAVE
from reveal_d960_payload_guard_mips import _validate_code_extent


ENTRY, ENTRY_PAIR = 0x48D820, (0x27BDFA90, 0x24060410)
BEGIN, BEGIN_PAIR = 0x48E020, (0x0C11D4C8, 0x8E7402A4)
EXITS = ((0x48D9E4, (0x8FBF056C, 0x02401021)),
         (0x48DAE8, (0x8FBF056C, 0x02401021)))
NATIVE_FRAME, TOKEN, POINTER = 1392, 0x544, 0x548
TEMP_ERROR = 0x90
MAX_BORROWS = 0x7FFFFFFF
HOOKS = ((ENTRY, ENTRY_PAIR), (BEGIN, BEGIN_PAIR), *EXITS)


def assemble(mutex_address, code_base):
    """Append four selected-branch hooks to the local 33-hook QR composer."""
    prefix, patches = qr.assemble(mutex_address, code_base)
    asm = Asm(code_base + len(prefix))

    def redirect(site, original):
        patches[site] = original, (b.j_type(2, asm.base + 4 * len(asm.w)), 0)

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

    def control():
        asm.absolute(8, mutex_address)

    def lock(label):
        control()
        asm.e(b.lw(9, session.PHASE, 8), b.addiu(10, 0, session.READY))
        asm.branch(5, 9, 10, label + '_unavailable')
        asm.e(0xF)
        asm.absolute(4, mutex_address)
        asm.jump(session.LOCK, link=True)
        asm.branch(5, 2, 0, label + '_raw_error')
        control()
        asm.e(b.lw(9, session.PHASE, 8), b.addiu(10, 0, session.READY), b.addiu(2, 0, 11))
        asm.branch(5, 9, 10, label + '_unlock_error')
        asm.e(b.lw(9, session.LIFECYCLE, 8), b.addiu(10, 0, session.LIVE), b.addiu(2, 0, 116))
        asm.branch(5, 9, 10, label + '_unlock_error')
        asm.e(b.lw(11, session.BOUND_SESSION, 8))
        asm.branch(4, 11, 0, label + '_unlock_error')
        asm.absolute(9, session.SESSION_SLOT)
        asm.e(b.lw(10, 0, 9))
        asm.branch(5, 10, 11, label + '_unlock_error')
        asm.e(b.lw(12, session.GENERATION, 8))
        asm.branch(6, 12, 0, label + '_unlock_error')

    def unlock(label):
        asm.absolute(4, mutex_address)
        asm.jump(session.UNLOCK, link=True)
        asm.branch(5, 2, 0, label + '_raw_error')

    def errors(label):
        asm.label(label + '_unavailable')
        control()
        asm.e(0xF, b.lw(2, session.INIT_ERROR, 8))
        asm.branch(5, 2, 0, 'abort')
        asm.jump('abort', delay=b.addiu(2, 0, 11))
        asm.label(label + '_unlock_error')
        asm.e(b.sw(2, TEMP_ERROR, 29))
        unlock(label)
        asm.jump('abort', delay=b.lw(2, TEMP_ERROR, 29))
        asm.label(label + '_raw_error')
        control()
        asm.e(b.sw(2, session.INIT_ERROR, 8), b.addiu(9, 0, session.FAILED),
              0xF, b.sw(9, session.PHASE, 8), 0xF)
        asm.jump('abort')

    redirect(ENTRY, ENTRY_PAIR)
    asm.e(ENTRY_PAIR[0], b.sw(0, TOKEN, 29), b.sw(0, POINTER, 29))
    asm.jump(ENTRY + 8, delay=ENTRY_PAIR[1])

    redirect(BEGIN, BEGIN_PAIR)
    save()
    lock('begin')
    asm.e(b.lw(9, session.WRITER, 8), b.addiu(2, 0, 16))
    asm.branch(1, 9, 0, 'begin_unlock_error')
    asm.e(b.lw(13, FRAME + TOKEN, 29), b.addiu(2, 0, 116))
    asm.branch(4, 13, 0, 'claim')
    # Re-entering this exact activation must not count its existing lease twice.
    asm.branch(5, 13, 12, 'begin_unlock_error')
    asm.e(b.lw(9, FRAME + POINTER, 29))
    asm.branch(5, 9, 11, 'begin_unlock_error')
    asm.e(b.lw(14, session.BORROWS, 8))
    asm.branch(6, 14, 0, 'begin_unlock_error')
    asm.jump('claimed')
    asm.label('claim')
    asm.e(b.lw(14, session.BORROWS, 8))
    asm.absolute(9, MAX_BORROWS)
    asm.e(b.r_type(14, 9, 10, 0x2B), b.addiu(2, 0, 75))
    asm.branch(4, 10, 0, 'begin_unlock_error')
    asm.e(b.addiu(14, 14, 1), b.sw(14, session.BORROWS, 8),
          b.sw(12, FRAME + TOKEN, 29), b.sw(11, FRAME + POINTER, 29))
    asm.label('claimed')
    unlock('begin')
    asm.e(b.lw(8, FRAME + POINTER, 29), b.sw(8, SAVE[2], 29))
    asm.absolute(8, BEGIN + 8)
    asm.e(b.sw(8, SAVE[31], 29))
    restore()
    asm.jump(BEGIN + 8, delay=BEGIN_PAIR[1])
    errors('begin')

    for index, (site, original) in enumerate(EXITS):
        label = f'exit_{index}'
        redirect(site, original)
        save()
        asm.e(b.lw(9, FRAME + TOKEN, 29))
        asm.branch(4, 9, 0, label + '_native')
        lock(label)
        asm.e(b.lw(9, FRAME + TOKEN, 29))
        asm.branch(5, 9, 12, label + '_unlock_error')
        asm.e(b.lw(9, FRAME + POINTER, 29))
        asm.branch(5, 9, 11, label + '_unlock_error')
        asm.e(b.lw(14, session.BORROWS, 8))
        asm.branch(6, 14, 0, label + '_unlock_error')
        asm.e(b.addiu(14, 14, -1), b.sw(14, session.BORROWS, 8),
              b.sw(0, FRAME + TOKEN, 29), b.sw(0, FRAME + POINTER, 29))
        unlock(label)
        asm.e(b.sw(0, SAVE[3], 29))
        asm.label(label + '_native')
        restore()
        asm.e(*original)
        asm.jump(site + 8)
        errors(label)

    asm.label('abort')
    asm.e(b.sw(2, SAVE[3], 29), b.addiu(8, 0, -1), b.sw(8, SAVE[18], 29))
    restore()
    # Deliberately bypass both patched exit gates on an unresolved protocol error.
    asm.e(*EXITS[1][1])
    asm.jump(EXITS[1][0] + 8)

    code = prefix + asm.finish()
    _validate_code_extent(code_base, len(code))
    if code_base < mutex_address + session.CONTROL_BYTES and mutex_address < code_base + len(code):
        raise ValueError('direct reader helpers overlap their sidecar')
    return code, patches
