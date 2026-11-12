#!/usr/bin/env python3
"""Local final response-pair disposal before native session destruction.

The first redirect runs after the native worker-stop call returns and before
the remaining context teardown. It validates the closing native frame, detaches
both response slots under the mutex and releases distinct owned objects outside
it. The second redirect revalidates identity, drained counts and empty slots
before the native session free. CLOSING remains until native free/reset/finish.
No remote close API or cleanup scheduling is added, and session+20 is irrelevant.

All composed redirects require coherent activation, valid owned starting
objects and frames, normal callback returns, retained sidecar and192 helper
stack bytes. The worker stop's masked raw results still leave completion as a
premise. Unconnected aliases and arbitrary destructor bindings remain open.
Raw failure quarantines without guessed unlock or repeated release/free/reset.
Policy rejection retains the encountered binding. Already detached unreleased
objects can leak; no recovery journal or rollback of broad teardown is supplied.
READY checks suppress callbacks after an observed fault, not every concurrent
fault that could race a check. This composer is local, not a firmware candidate.
"""

from build_reveal_bridge_diag import Asm, b
import reveal_tidal_direct_reader_span_mips as direct
import reveal_tidal_response_reader_bridge_mips as session
from reveal_registry_receipt_mips import FRAME, HI, LO, SAVE
from reveal_d960_payload_guard_mips import _validate_code_extent


DETACH, DETACH_PAIR = 0x4757E4, (0x0C110510, 0)
FREE_SITE, FREE_PAIR = 0x475808, (0x0C119AA0, 0x02002021)
AFTER_DETACH, FREE, RELEASE = 0x441440, 0x466A80, 0x8CBD6C
HOOKS = ((DETACH, DETACH_PAIR), (FREE_SITE, FREE_PAIR))
PRIMARY, SECONDARY, ERROR = 0x90, 0x94, 0x98


def assemble(mutex_address, code_base, *, close_queue_gate=None):
    prefix, patches = direct.assemble(
        mutex_address, code_base, close_queue_gate=close_queue_gate)
    asm = Asm(code_base + len(prefix))

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

    def available():
        control()
        asm.e(b.lw(9, session.PHASE, 8), b.addiu(10, 0, session.READY))
        asm.branch(5, 9, 10, 'unavailable')
        asm.e(0xF)

    def gate():
        available()
        asm.absolute(4, mutex_address)
        asm.jump(session.LOCK, link=True)
        asm.branch(5, 2, 0, 'raw_error')
        control()
        asm.e(b.lw(9, session.PHASE, 8), b.addiu(10, 0, session.READY), b.addiu(2, 0, 11))
        asm.branch(5, 9, 10, 'unlock_error')
        asm.e(b.lw(9, session.LIFECYCLE, 8), b.addiu(10, 0, session.CLOSING), b.addiu(2, 0, 116))
        asm.branch(5, 9, 10, 'unlock_error')
        asm.e(b.lw(9, FRAME + session.STAMP, 29))
        asm.absolute(10, session.FRAME_MAGIC)
        asm.branch(5, 9, 10, 'unlock_error')
        asm.e(b.lw(11, session.BOUND_SESSION, 8))
        asm.branch(6, 11, 0, 'unlock_error')
        asm.absolute(9, session.SESSION_SLOT)
        asm.e(b.lw(10, 0, 9))
        asm.branch(5, 10, 11, 'unlock_error')
        for register in (16, 17):
            asm.e(b.lw(9, SAVE[register], 29))
            asm.branch(5, 9, 11, 'unlock_error')
        asm.e(b.lw(12, session.GENERATION, 8), b.lw(9, FRAME + session.TOKEN, 29))
        asm.branch(6, 12, 0, 'unlock_error')
        asm.branch(5, 9, 12, 'unlock_error')
        asm.e(b.lw(9, session.WRITER, 8), b.addiu(2, 0, 16))
        asm.branch(5, 9, 0, 'unlock_error')
        asm.e(b.lw(9, session.BORROWS, 8))
        asm.branch(5, 9, 0, 'unlock_error')

    def unlock():
        asm.absolute(4, mutex_address)
        asm.jump(session.UNLOCK, link=True)
        asm.branch(5, 2, 0, 'raw_error')

    def empty_pair():
        asm.e(b.addiu(2, 0, 71), b.lw(9, 0x18, 11))
        asm.branch(5, 9, 0, 'unlock_error')
        asm.e(b.lw(9, 0x1C, 11))
        asm.branch(5, 9, 0, 'unlock_error')

    patches[DETACH] = DETACH_PAIR, (b.j_type(2, asm.base + 4 * len(asm.w)), 0)
    save()
    gate()
    asm.e(b.lw(13, 0x18, 11), b.lw(14, 0x1C, 11), b.addiu(2, 0, 22))
    asm.branch(4, 13, 0, 'detach_pair')
    asm.branch(4, 13, 14, 'unlock_error')
    asm.label('detach_pair')
    asm.e(b.sw(13, PRIMARY, 29), b.sw(14, SECONDARY, 29),
          b.sw(0, 0x18, 11), b.sw(0, 0x1C, 11))
    unlock()
    for index, offset in enumerate((PRIMARY, SECONDARY)):
        asm.e(b.lw(4, offset, 29))
        asm.branch(4, 4, 0, f'released_{index}')
        available()
        asm.jump(RELEASE, link=True)
        asm.label(f'released_{index}')
    gate()
    empty_pair()
    unlock()
    available()
    restore()
    asm.absolute(31, DETACH + 8)
    asm.jump(AFTER_DETACH)

    patches[FREE_SITE] = FREE_PAIR, (b.j_type(2, asm.base + 4 * len(asm.w)), 0)
    save()
    gate()
    empty_pair()
    unlock()
    available()
    restore()
    asm.absolute(31, FREE_SITE + 8)
    asm.jump(FREE, delay=FREE_PAIR[1])

    asm.label('unavailable')
    control()
    asm.e(0xF, b.lw(2, session.INIT_ERROR, 8))
    asm.branch(5, 2, 0, 'abort')
    asm.jump('abort', delay=b.addiu(2, 0, 11))
    asm.label('unlock_error')
    asm.e(b.sw(2, ERROR, 29))
    unlock()
    asm.jump('abort', delay=b.lw(2, ERROR, 29))
    asm.label('raw_error')
    control()
    asm.e(b.sw(2, session.INIT_ERROR, 8), b.addiu(9, 0, session.FAILED),
          0xF, b.sw(9, session.PHASE, 8), 0xF)
    asm.label('abort')
    asm.e(b.sw(2, SAVE[3], 29), b.addiu(8, 0, -1), b.sw(8, SAVE[2], 29))
    restore()
    # Bypass the patched finish hook: session free/reset did not complete.
    asm.e(*session.FINISH_PAIR)
    asm.jump(session.FINISH_SITE + 8)

    code = prefix + asm.finish()
    _validate_code_extent(code_base, len(code))
    if code_base < mutex_address + session.CONTROL_BYTES and mutex_address < code_base + len(code):
        raise ValueError('session disposal helpers overlap the sidecar')
    session._validate_close_queue_gate(mutex_address, code_base, len(code), close_queue_gate)
    return code, patches
