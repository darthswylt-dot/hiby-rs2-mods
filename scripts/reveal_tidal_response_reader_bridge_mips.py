#!/usr/bin/env python3
"""Bind two native Tidal readers to checked session publication and retirement.

These are local instruction-fetch hooks. The sidecar is supplied zeroed,
retained and exclusive to the shared-session protocol. Startup checks the raw
mutex initializer before publishing availability. Both native session-pointer
publications bind a nonzero pointer and generation to the startup frame. Both
close routes withdraw reader admission before native teardown; finish keeps
the old binding closed until session free and allocator reset have returned.
Copying holds the mutex through the getter and libc string operations.
Presence returns a scalar. Reader admission is rechecked after acquisition.

All eight redirects must be activated coherently. The native startup frame's
unused +1C/+20 words carry its generation and stamp; lifecycle helpers require
192 extra writable stack bytes. Ordinary callee returns, retained sidecar,
valid nonaliasing storage, and the pinned native ABI remain premises. A raw
error latches FAILED without guessed unlock or recovery. V1 reports the error.
Policy errors abort the selected invocation without clearing another binding.
Neither error path guesses cleanup authority; a provisional session can remain
allocated. An unlock failure can follow a completed native effect.

The optional command-zero transport module retains one in-flight operation in
WRITER. Close rejects a nonzero pin with EBUSY before native teardown. That
module owns pin release; this gate adds no wait or rescheduling. The retained
reader composer also counts active BORROWS; close refuses them before CLOSING.
Pair replacement and cleanup share this retention boundary in their composers.
Remaining readers, compound calls and caller quarantine still need integration
before a firmware candidate can establish shared-response lifetime. These hooks
do not protect unconnected aliases.
"""

from build_reveal_bridge_diag import Asm, b
from reveal_d180_data_dealing_snapshot_mips import LOCK, UNLOCK
from reveal_d960_payload_guard_mips import _validate_code_base, _validate_code_extent
from reveal_registry_receipt_mips import FRAME as INIT_FRAME, HI, LO, SAVE


FRAME, ARGUMENT, RESULT, DIAGNOSTIC, SAVED_RA = 0x20, 0x10, 0x14, 0x18, 0x1C
MUTEX_BYTES = 24
PHASE, INIT_ERROR, BOUND_SESSION, GENERATION, LIFECYCLE = 24, 28, 32, 36, 40
WRITER, BORROWS, CONTROL_BYTES = 44, 48, 52
NEW, INITIALIZING, READY, FAILED = 0, 1, 2, 3
EMPTY, LIVE, CLOSING = 0, 1, 2
NATIVE_FRAME, TOKEN, STAMP = 56, 0x1C, 0x20
FRAME_MAGIC, MAX_GENERATION = 0x314C5354, 0x7FFFFFFF
TEMP_ERROR = 0x90
INIT_SITE, INIT_PAIR, RAW_INIT = 0x475448, (0x3C04009D, 0x2484F4D4), 0xA5B8A0
SESSION_SLOT = 0xB8A9EC
PUBLISH_SITES = (
    (0x475458, (0x0C11B298, 0xAE71A9EC), 0x46CA60),
    (0x475660, (0xAE71A9EC, 0xAFA00018), 0),
)
CLOSE_SITES = (
    (0x475788, (0x0C1120A0, 0), 0x448280),
    (0x475834, (0x0C115CC0, 0x24040001), 0x457300),
)
FINISH_SITE, FINISH_PAIR = 0x475818, (0x8FBF0034, 0x8FB30030)
READERS = (
    # Name, entry, original pair, body after that pair, failure return.
    ('copy', 0x4B1620, (0x1080001C, 0), 0x4B1628, -1),
    ('presence', 0x513A40, (0x27BDFFE0, 0xAFBF001C), 0x513A40, 0),
)


def assemble(mutex_address, code_base):
    """Return helper bytes and pinned native entry redirects for a local fixture."""
    _validate_code_base(code_base)
    _validate_code_base(mutex_address)
    _validate_code_extent(mutex_address, CONTROL_BYTES)
    asm, patches = Asm(code_base), {}

    def save_native():
        asm.e(b.addiu(29, 29, -INIT_FRAME))
        for register, offset in SAVE.items():
            asm.e(b.sw(register, offset, 29))
        asm.e(b.r_type(0, 0, 8, 0x10), b.sw(8, HI, 29),
              b.r_type(0, 0, 8, 0x12), b.sw(8, LO, 29))

    def restore_native():
        asm.e(b.lw(8, HI, 29), b.r_type(8, 0, 0, 0x11),
              b.lw(8, LO, 29), b.r_type(8, 0, 0, 0x13))
        for register, offset in SAVE.items():
            asm.e(b.lw(register, offset, 29))
        asm.e(b.addiu(29, 29, INIT_FRAME))

    def control(register=8):
        asm.absolute(register, mutex_address)

    for name, site, original, body, failure in READERS:
        entry = code_base + 4 * len(asm.w)
        patches[site] = original, (b.j_type(2, entry), 0)
        if name == 'copy':
            asm.branch(4, 4, 0, 'copy_null')
        asm.e(b.addiu(29, 29, -FRAME), b.sw(31, SAVED_RA, 29), b.sw(4, ARGUMENT, 29))
        asm.absolute(8, mutex_address + PHASE)
        asm.e(b.lw(9, 0, 8), b.addiu(10, 0, READY))
        asm.branch(5, 9, 10, name + '_unavailable')
        asm.e(0xF)  # SYNC before using the initialized mutex.
        asm.absolute(4, mutex_address)
        asm.jump(LOCK, link=True)
        asm.branch(5, 2, 0, name + '_failed')
        asm.e(b.sw(0, DIAGNOSTIC, 29))
        control()
        asm.e(b.lw(9, PHASE, 8), b.addiu(10, 0, READY))
        asm.branch(5, 9, 10, name + '_closed_error')
        asm.e(b.lw(9, LIFECYCLE, 8), b.addiu(10, 0, LIVE))
        asm.branch(5, 9, 10, name + '_empty')
        asm.e(b.lw(10, BOUND_SESSION, 8))
        asm.branch(4, 10, 0, name + '_stale')
        asm.absolute(8, SESSION_SLOT)
        asm.e(b.lw(9, 0, 8))
        asm.branch(5, 9, 10, name + '_stale')
        asm.branch(5, 9, 0, name + '_read')
        asm.label(name + '_empty')
        asm.jump(name + '_save_result', delay=b.move(2, 0))
        asm.label(name + '_stale')
        asm.e(b.addiu(3, 0, 116))  # ESTALE for an unbound global pointer.
        asm.jump(name + '_error_result')
        asm.label(name + '_closed_error')
        control()
        asm.e(b.lw(3, INIT_ERROR, 8))
        asm.branch(5, 3, 0, name + '_error_result')
        asm.e(b.addiu(3, 0, 11))
        asm.label(name + '_error_result')
        asm.e(b.sw(3, DIAGNOSTIC, 29), b.addiu(2, 0, failure))
        asm.jump(name + '_save_result')
        asm.label(name + '_read')
        asm.e(b.lw(4, ARGUMENT, 29))
        if name == 'presence':
            # Replay its overwritten frame/RA save, then resume the native body.
            asm.jump('presence_body', link=True)
        else:
            asm.jump(body, link=True)
        asm.label(name + '_save_result')
        asm.e(b.sw(2, RESULT, 29))
        asm.absolute(4, mutex_address)
        asm.jump(UNLOCK, link=True)
        asm.branch(5, 2, 0, name + '_failed')
        asm.e(b.lw(2, RESULT, 29), b.lw(3, DIAGNOSTIC, 29))
        asm.jump(name + '_return')
        asm.label(name + '_failed')
        control()
        asm.e(b.sw(2, INIT_ERROR, 8), b.addiu(9, 0, FAILED), 0xF, b.sw(9, PHASE, 8), 0xF)
        asm.e(b.move(3, 2), b.addiu(2, 0, failure))
        asm.jump(name + '_return')
        asm.label(name + '_unavailable')
        asm.e(0xF, b.lw(3, INIT_ERROR - PHASE, 8))
        asm.branch(5, 3, 0, name + '_unavailable_result')
        asm.e(b.addiu(3, 0, 11))  # EAGAIN while startup is incomplete.
        asm.label(name + '_unavailable_result')
        asm.e(b.addiu(2, 0, failure))
        asm.label(name + '_return')
        asm.e(b.lw(31, SAVED_RA, 29), 0x03E00008, b.addiu(29, 29, FRAME))
        if name == 'copy':
            asm.label('copy_null')
            asm.e(b.move(3, 0), 0x03E00008, b.addiu(2, 0, -1))

    asm.label('presence_body')
    asm.e(*READERS[1][2])
    asm.jump(READERS[1][1] + 8)

    asm.label('initialize')
    save_native()
    asm.e(b.sw(0, INIT_FRAME + TOKEN, 29))
    asm.absolute(8, FRAME_MAGIC)
    asm.e(b.sw(8, INIT_FRAME + STAMP, 29))
    asm.absolute(8, mutex_address + PHASE)
    asm.label('initialize_claim')
    asm.e(b.i_type(0x30, 8, 9, 0))
    asm.branch(5, 9, 0, 'initialize_restore')
    asm.e(b.addiu(10, 0, INITIALIZING), b.i_type(0x38, 8, 10, 0))
    asm.branch(4, 10, 0, 'initialize_claim')
    asm.e(0xF)
    asm.absolute(4, mutex_address)
    asm.jump(RAW_INIT, link=True, delay=b.move(5, 0))
    asm.absolute(8, mutex_address + PHASE)
    asm.e(b.sw(2, INIT_ERROR - PHASE, 8), b.addiu(9, 0, FAILED))
    asm.branch(5, 2, 0, 'initialize_publish')
    asm.e(b.addiu(9, 0, READY))
    asm.label('initialize_publish')
    asm.e(0xF, b.sw(9, 0, 8), 0xF)
    asm.label('initialize_restore')
    restore_native()
    asm.e(INIT_PAIR[0])
    asm.jump(INIT_SITE + 8, delay=INIT_PAIR[1])
    patches[INIT_SITE] = INIT_PAIR, (b.j_type(2, asm.labels['initialize']), 0)

    for action, sites in (('publish', PUBLISH_SITES), ('close', CLOSE_SITES),
                          ('finish', ((FINISH_SITE, FINISH_PAIR, 0),))):
        for site, original, callee in sites:
            entry = code_base + 4 * len(asm.w)
            label = f'{action}_{site:x}'
            patches[site] = original, (b.j_type(2, entry), 0)
            save_native()
            control()
            asm.e(b.lw(9, PHASE, 8), b.addiu(10, 0, READY))
            asm.branch(5, 9, 10, 'lifecycle_unavailable')
            asm.absolute(4, mutex_address)
            asm.jump(LOCK, link=True)
            asm.branch(5, 2, 0, 'lifecycle_raw_error')
            control()
            asm.e(b.lw(9, PHASE, 8), b.addiu(10, 0, READY), b.addiu(2, 0, 11))
            asm.branch(5, 9, 10, 'lifecycle_unlock_error')
            asm.e(b.lw(9, INIT_FRAME + STAMP, 29), b.addiu(2, 0, 116))
            asm.absolute(10, FRAME_MAGIC)
            asm.branch(5, 9, 10, 'lifecycle_unlock_error')
            asm.e(b.lw(11, INIT_FRAME + TOKEN, 29), b.lw(12, GENERATION, 8),
                  b.lw(13, BOUND_SESSION, 8), b.lw(14, LIFECYCLE, 8))

            if action == 'publish':
                asm.branch(4, 14, 0, label + '_new')
                asm.e(b.addiu(9, 0, LIVE))
                asm.branch(5, 14, 9, 'lifecycle_unlock_error')
                asm.branch(4, 11, 0, 'lifecycle_unlock_error')
                asm.branch(5, 11, 12, 'lifecycle_unlock_error')
                asm.branch(5, 13, 17, 'lifecycle_unlock_error')
                asm.absolute(9, SESSION_SLOT)
                asm.e(b.lw(10, 0, 9))
                asm.branch(5, 10, 17, 'lifecycle_unlock_error')
                asm.jump(label + '_store')
                asm.label(label + '_new')
                asm.branch(5, 11, 0, 'lifecycle_unlock_error')
                asm.branch(4, 17, 0, 'lifecycle_unlock_error')
                asm.absolute(9, SESSION_SLOT)
                asm.e(b.lw(10, 0, 9))
                asm.branch(5, 10, 0, 'lifecycle_unlock_error')
                asm.absolute(9, MAX_GENERATION)
                asm.e(b.r_type(12, 9, 10, 0x2B), b.addiu(2, 0, 75))
                asm.branch(4, 10, 0, 'lifecycle_unlock_error')
                asm.e(b.addiu(12, 12, 1), b.sw(12, GENERATION, 8), b.sw(17, BOUND_SESSION, 8),
                      b.addiu(9, 0, LIVE), b.sw(9, LIFECYCLE, 8), b.sw(12, INIT_FRAME + TOKEN, 29))
                asm.label(label + '_store')
                asm.absolute(9, SESSION_SLOT)
                asm.e(b.sw(17, 0, 9))
            else:
                asm.e(b.addiu(9, 0, LIVE if action == 'close' else CLOSING))
                asm.branch(5, 14, 9, 'lifecycle_unlock_error')
                asm.branch(4, 11, 0, 'lifecycle_unlock_error')
                asm.branch(5, 11, 12, 'lifecycle_unlock_error')
                asm.branch(5, 13, 17, 'lifecycle_unlock_error')
                asm.absolute(9, SESSION_SLOT)
                asm.e(b.lw(10, 0, 9))
                asm.branch(5, 10, 17, 'lifecycle_unlock_error')
                if action == 'close':
                    asm.e(b.lw(10, WRITER, 8))
                    asm.branch(4, 10, 0, label + '_drained')
                    asm.jump('lifecycle_unlock_error', delay=b.addiu(2, 0, 16))  # EBUSY.
                    asm.label(label + '_drained')
                    asm.e(b.lw(10, BORROWS, 8))
                    asm.branch(4, 10, 0, label + '_readers_drained')
                    asm.jump('lifecycle_unlock_error', delay=b.addiu(2, 0, 16))
                    asm.label(label + '_readers_drained')
                    # Native teardown still reloads this global. Keep it bound
                    # and closed through free and allocator reset.
                    asm.e(b.addiu(10, 0, CLOSING), b.sw(10, LIFECYCLE, 8))
                else:
                    asm.e(b.sw(0, 0, 9), b.sw(0, BOUND_SESSION, 8), b.sw(0, LIFECYCLE, 8),
                          b.sw(0, INIT_FRAME + TOKEN, 29))
            asm.absolute(4, mutex_address)
            asm.jump(UNLOCK, link=True)
            asm.branch(5, 2, 0, 'lifecycle_raw_error')
            restore_native()
            if callee:
                asm.absolute(31, site + 8)
                asm.jump(callee, delay=original[1] if action == 'close' else 0)
            elif action == 'publish':
                asm.jump(site + 8, delay=original[1])
            else:
                asm.jump('native_epilogue')

    asm.label('lifecycle_unavailable')
    control()
    asm.e(0xF, b.lw(2, INIT_ERROR, 8))
    asm.branch(5, 2, 0, 'lifecycle_abort')
    asm.jump('lifecycle_abort', delay=b.addiu(2, 0, 11))
    asm.label('lifecycle_unlock_error')
    asm.e(b.sw(2, TEMP_ERROR, 29))
    asm.absolute(4, mutex_address)
    asm.jump(UNLOCK, link=True)
    asm.branch(5, 2, 0, 'lifecycle_raw_error')
    asm.jump('lifecycle_abort', delay=b.lw(2, TEMP_ERROR, 29))
    asm.label('lifecycle_raw_error')
    control()
    asm.e(b.sw(2, INIT_ERROR, 8), b.addiu(9, 0, FAILED), 0xF, b.sw(9, PHASE, 8), 0xF)
    asm.label('lifecycle_abort')
    asm.e(b.sw(2, SAVE[3], 29), b.addiu(8, 0, -1), b.sw(8, SAVE[2], 29))
    restore_native()
    asm.label('native_epilogue')
    asm.e(*FINISH_PAIR)
    asm.jump(FINISH_SITE + 8)

    code = asm.finish()
    _validate_code_extent(code_base, len(code))
    if code_base < mutex_address + CONTROL_BYTES and mutex_address < code_base + len(code):
        raise ValueError('reader bridges overlap their sidecar')
    return code, patches
