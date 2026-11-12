#!/usr/bin/env python3
"""Local generation transport and command-zero worker pin for Tidal.

Compose the shared-session fixture's eight hooks with three more redirects.
Command-zero POST replaces its unused argument with the live generation. The
worker validates that queued generation before its busy notification, copying
input or issuing a request, then pins WRITER until the matching result boundary.
The native result store and pin clear form one checked mutex transaction.
The base close gate refuses EBUSY while WRITER is nonzero. Network, input and
native worker bodies execute outside the mutex; no waiting/join is introduced.

All eleven redirects require coherent activation, initialized retained sidecar,
192 extra writable stack bytes, the single native worker route, valid frames
and the pinned ABI. Raw
errors latch FAILED without guessed unlock. Rejected worker entry/result skips
to the native loop without publishing a possibly stale shared status. That can
leave a pending status; UI recovery and progress are not established here.

This transports session identity only. It does not snapshot mutable input
strings, distinguish requests within one generation, establish queue lifetime,
or synchronize response-pair publication, readers and disposal. The later
worker postprocessing, notification and loop suffix remain outside the pin.
No image builder or deployment uses these partial local hooks.
"""

from build_reveal_bridge_diag import Asm, b
import reveal_tidal_response_reader_bridge_mips as session
from reveal_registry_receipt_mips import FRAME, HI, LO, SAVE
from reveal_d960_payload_guard_mips import _validate_code_extent


POST, POST_PAIR = 0x454B40, (0x27BDFFD8, 0x3C0200B9)
WORK_BEGIN, BEGIN_PAIR = 0x45442C, (0x24040014, 0x0C11DC60)
BEGIN_DELAY, BEGIN_RESUME, NOTIFY = 0x24050001, 0x454438, 0x477180
WORK_END, END_PAIR = 0x4547D4, (0x8FA40830, 0xAFC20004)
WORK_SKIP, QUEUED_COMMAND, QUEUED_GENERATION = 0x4544EC, 0x820, 0x824
TEMP_ERROR, TEMP_GENERATION = 0x90, 0x94
HOOKS = ((POST, POST_PAIR), (WORK_BEGIN, BEGIN_PAIR), (WORK_END, END_PAIR))


def assemble(mutex_address, code_base, *, close_queue_gate=None):
    """Append checked transport/pin helpers to the base local session fixture."""
    if session.CONTROL_BYTES != 52 or session.WRITER != 44 or session.BORROWS != 48:
        raise ValueError('request identity requires the 52-byte session sidecar')
    prefix, patches = session.assemble(
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

    for action, site, original in (('post', POST, POST_PAIR),
                                    ('begin', WORK_BEGIN, BEGIN_PAIR),
                                    ('end', WORK_END, END_PAIR)):
        entry = asm.base + 4 * len(asm.w)
        patches[site] = original, (b.j_type(2, entry), 0)
        if action == 'post':
            asm.branch(5, 4, 0, 'post_native')
        save()
        if action == 'begin':
            asm.e(b.lw(8, FRAME + QUEUED_COMMAND, 29))
            asm.branch(5, 8, 0, 'begin_restore')
        control()
        asm.e(b.lw(9, session.PHASE, 8), b.addiu(10, 0, session.READY))
        asm.branch(5, 9, 10, action + '_unavailable')
        asm.e(0xF)
        asm.absolute(4, mutex_address)
        asm.jump(session.LOCK, link=True)
        asm.branch(5, 2, 0, action + '_raw_error')
        control()
        asm.e(b.lw(9, session.PHASE, 8), b.addiu(10, 0, session.READY),
              b.addiu(2, 0, 11))
        asm.branch(5, 9, 10, action + '_unlock_error')
        asm.e(b.lw(9, session.LIFECYCLE, 8), b.addiu(10, 0, session.LIVE),
              b.addiu(2, 0, 116))
        asm.branch(5, 9, 10, action + '_unlock_error')
        asm.e(b.lw(11, session.BOUND_SESSION, 8))
        asm.branch(4, 11, 0, action + '_unlock_error')
        asm.absolute(9, session.SESSION_SLOT)
        asm.e(b.lw(10, 0, 9))
        asm.branch(5, 10, 11, action + '_unlock_error')
        asm.e(b.lw(12, session.GENERATION, 8))
        asm.branch(6, 12, 0, action + '_unlock_error')  # Generation must be signed positive.
        if action == 'post':
            asm.e(b.sw(12, TEMP_GENERATION, 29))
        else:
            asm.e(b.lw(13, FRAME + QUEUED_GENERATION, 29))
            asm.branch(5, 13, 12, action + '_unlock_error')
            asm.e(b.lw(14, session.WRITER, 8))
            if action == 'begin':
                asm.e(b.addiu(2, 0, 16))
                asm.branch(5, 14, 0, action + '_unlock_error')
                asm.e(b.sw(12, session.WRITER, 8))
            else:
                asm.branch(5, 14, 12, action + '_unlock_error')
                # Publish the saved native result while its generation is
                # still pinned. Unlocking before this store admits rebind.
                asm.e(b.lw(9, SAVE[30], 29), b.lw(10, SAVE[2], 29),
                      b.sw(10, 4, 9), b.sw(0, session.WRITER, 8))
        asm.absolute(4, mutex_address)
        asm.jump(session.UNLOCK, link=True)
        asm.branch(5, 2, 0, action + '_raw_error')
        if action == 'post':
            asm.e(b.lw(8, TEMP_GENERATION, 29), b.sw(8, SAVE[5], 29))
        if action == 'begin':
            asm.label('begin_restore')
        restore()
        asm.label(action + '_native')
        if action == 'begin':
            asm.e(BEGIN_PAIR[0])
            asm.absolute(31, BEGIN_RESUME)
            asm.jump(NOTIFY, delay=BEGIN_DELAY)
        elif action == 'end':
            asm.e(original[0])
            asm.jump(site + 8)
        else:
            asm.e(original[0])
            asm.jump(site + 8, delay=original[1])

        asm.label(action + '_unavailable')
        control()
        asm.e(0xF, b.lw(2, session.INIT_ERROR, 8))
        asm.branch(5, 2, 0, action + '_abort')
        asm.jump(action + '_abort', delay=b.addiu(2, 0, 11))
        asm.label(action + '_unlock_error')
        asm.e(b.sw(2, TEMP_ERROR, 29))
        asm.absolute(4, mutex_address)
        asm.jump(session.UNLOCK, link=True)
        asm.branch(5, 2, 0, action + '_raw_error')
        asm.jump(action + '_abort', delay=b.lw(2, TEMP_ERROR, 29))
        asm.label(action + '_raw_error')
        control()
        asm.e(b.sw(2, session.INIT_ERROR, 8), b.addiu(9, 0, session.FAILED),
              0xF, b.sw(9, session.PHASE, 8), 0xF)
        asm.label(action + '_abort')
        if action == 'post':
            asm.e(b.sw(2, SAVE[3], 29), b.addiu(8, 0, -1), b.sw(8, SAVE[2], 29))
        restore()
        if action == 'post':
            asm.e(0x03E00008, 0)
        else:
            asm.jump(WORK_SKIP)

    code = prefix + asm.finish()
    _validate_code_extent(code_base, len(code))
    if code_base < mutex_address + session.CONTROL_BYTES and mutex_address < code_base + len(code):
        raise ValueError('request identity helpers overlap the sidecar')
    session._validate_close_queue_gate(mutex_address, code_base, len(code), close_queue_gate)
    return code, patches
