#!/usr/bin/env python3
"""Local retained spans for four selected Tidal reader entries.

Each wrapper claims BORROWS under the shared mutex, runs its complete native
body outside the mutex, then checks identity and releases exactly one count.
Pair commit, cleanup and native close refuse EBUSY while a retained span is
active. There is no wait, deferred retirement or retry scheduling.

The native bodies use at most four incoming arguments; caller argument homes
0..F are reserved in the 192-byte helper frame. All original GPRs and HI/LO
are restored before the native call. Its outcome is captured again before
unpinning, with the caller's original RA restored at the final return.

48CE80 is limited to the two identified synchronous service adapters. Their
returned payload ownership and the scalar interpretation of primary+4 require
the selected class/method bindings. Arbitrary callbacks, borrowed return
aliases and nonlocal exits are not covered. NULL 4B16E0 arguments reject before
its native nonreturning assertions. Other live caller objects remain premises.

Raw errors latch FAILED without guessed unlock or rollback. Failed acquisition
can retain a count; final unlock failure can follow its completed decrement.
A native body may already have produced effects or an owned result before a
failed unpin; those effects are not rolled back and owned results can leak.
All 21 redirects require coherent activation, zeroed retained 52-byte sidecar,
extra helper/native stack, nonaliasing storage, normal returns and the pinned
ABI. This is partial local integration, not a firmware image candidate.
"""

from build_reveal_bridge_diag import Asm, b
import reveal_tidal_response_cleanup_mips as cleanup
import reveal_tidal_response_reader_bridge_mips as session
from reveal_registry_receipt_mips import FRAME, HI, LO, SAVE
from reveal_d960_payload_guard_mips import _validate_code_extent


READERS = (
    ('pages', 0x48CAC0, (0x27BDFFB0, 0xAFB70044), 0),
    ('callback', 0x48CE80, (0x27BDFFC0, 0xAFB20028), 0),
    ('pair_copy', 0x4B16E0, (0x27BDFFC0, 0xAFBF003C), -1),
    ('user_id', 0x4B16A0, (0x27BDFFE0, 0xAFBF001C), 0),
)
CALLBACKS = (0x8C0330, 0x8C0450)
GENERATION, SESSION, ORIGINAL_RA, TEMP_ERROR = 0x90, 0x94, 0x98, 0x9C
MAX_BORROWS = 0x7FFFFFFF


def assemble(mutex_address, code_base):
    """Append four whole-entry retained wrappers to the local cleanup composer."""
    prefix, patches = cleanup.assemble(mutex_address, code_base)
    asm = Asm(code_base + len(prefix))

    def save_registers():
        for register, offset in SAVE.items():
            asm.e(b.sw(register, offset, 29))
        asm.e(b.r_type(0, 0, 8, 0x10), b.sw(8, HI, 29),
              b.r_type(0, 0, 8, 0x12), b.sw(8, LO, 29))

    def restore_registers():
        asm.e(b.lw(8, HI, 29), b.r_type(8, 0, 0, 0x11),
              b.lw(8, LO, 29), b.r_type(8, 0, 0, 0x13))
        for register, offset in SAVE.items():
            asm.e(b.lw(register, offset, 29))

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

    for name, site, original, failure in READERS:
        entry = asm.base + 4 * len(asm.w)
        patches[site] = original, (b.j_type(2, entry), 0)
        begin, finish = name + '_begin', name + '_finish'
        asm.e(b.addiu(29, 29, -FRAME))
        save_registers()
        asm.e(b.lw(8, SAVE[31], 29), b.sw(8, ORIGINAL_RA, 29))
        if name == 'pair_copy':
            asm.branch(4, 4, 0, name + '_invalid')
            asm.branch(4, 5, 0, name + '_invalid')
        elif name == 'callback':
            asm.absolute(8, CALLBACKS[0])
            asm.branch(4, 5, 8, name + '_callback_allowed')
            asm.absolute(8, CALLBACKS[1])
            asm.branch(5, 5, 8, name + '_invalid')
            asm.label(name + '_callback_allowed')
        lock(begin)
        asm.e(b.lw(13, session.WRITER, 8), b.addiu(2, 0, 16))
        asm.branch(1, 13, 0, begin + '_unlock_error')  # BLTZ: cleanup owns the detached pair.
        asm.e(b.lw(14, session.BORROWS, 8))
        asm.absolute(9, MAX_BORROWS)
        asm.e(b.r_type(14, 9, 10, 0x2B), b.addiu(2, 0, 75))
        asm.branch(4, 10, 0, begin + '_unlock_error')
        asm.e(b.addiu(14, 14, 1), b.sw(14, session.BORROWS, 8),
              b.sw(11, SESSION, 29), b.sw(12, GENERATION, 29))
        unlock(begin)
        restore_registers()
        asm.jump(name + '_body', link=True)

        # The native body has returned into this retained outer frame. Save
        # its actual result/ABI state before any release-mutex calls.
        save_registers()
        lock(finish)
        asm.e(b.lw(9, SESSION, 29))
        asm.branch(5, 11, 9, finish + '_unlock_error')
        asm.e(b.lw(9, GENERATION, 29))
        asm.branch(5, 12, 9, finish + '_unlock_error')
        asm.e(b.lw(14, session.BORROWS, 8))
        asm.branch(6, 14, 0, finish + '_unlock_error')
        asm.e(b.addiu(14, 14, -1), b.sw(14, session.BORROWS, 8))
        unlock(finish)
        asm.e(b.sw(0, SAVE[3], 29))
        asm.jump(name + '_return')

        asm.label(name + '_invalid')
        asm.jump(name + '_abort', delay=b.addiu(2, 0, 22))
        for label in (begin, finish):
            asm.label(label + '_unavailable')
            control()
            asm.e(0xF, b.lw(2, session.INIT_ERROR, 8))
            asm.branch(5, 2, 0, name + '_abort')
            asm.jump(name + '_abort', delay=b.addiu(2, 0, 11))
            asm.label(label + '_unlock_error')
            asm.e(b.sw(2, TEMP_ERROR, 29))
            unlock(label)
            asm.jump(name + '_abort', delay=b.lw(2, TEMP_ERROR, 29))
            asm.label(label + '_raw_error')
            control()
            asm.e(b.sw(2, session.INIT_ERROR, 8), b.addiu(9, 0, session.FAILED),
                  0xF, b.sw(9, session.PHASE, 8), 0xF)
            asm.jump(name + '_abort')
        asm.label(name + '_abort')
        asm.e(b.sw(2, SAVE[3], 29), b.addiu(8, 0, failure), b.sw(8, SAVE[2], 29))
        asm.label(name + '_return')
        asm.e(b.lw(8, ORIGINAL_RA, 29), b.sw(8, SAVE[31], 29))
        restore_registers()
        asm.e(0x03E00008, b.addiu(29, 29, FRAME))
        asm.label(name + '_body')
        asm.e(*original)
        asm.jump(site + 8)

    code = prefix + asm.finish()
    _validate_code_extent(code_base, len(code))
    if code_base < mutex_address + session.CONTROL_BYTES and mutex_address < code_base + len(code):
        raise ValueError('retained reader helpers overlap their sidecar')
    return code, patches
