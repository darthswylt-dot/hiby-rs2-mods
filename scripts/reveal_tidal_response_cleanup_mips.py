#!/usr/bin/env python3
"""Local checked detach and outside-mutex disposal for Tidal responses.

Compose pair/transport/session hooks with a full replacement of native5139C0.
Cleanup claims a distinct negative generation pin, detaches both fields under
the checked mutex, then calls close and release outside it. The matching pin
is kept through all callbacks and cleared only after checked final admission.
Close failure does not put released pointers back into session fields.

These are local instruction-fetch hooks, not an image candidate. All composed
redirects must be coherent. The retained sidecar, valid nonaliasing native
storage, a single worker, normal callback returns and 192 extra writable stack
bytes remain premises. Generic response destructors are bounded in tests.
Published starting objects must be valid and owned; all retained borrows need
the shared mutex. Only two selected reader spans are connected in this fixture.
Unconnected readers/releases, command-one queue identity, the caller's later
status store and worker scheduling/recovery remain outside this partial stage.

Raw errors latch FAILED without guessed unlock or callbacks. Failed unlock
after detach leaves empty slots and an unresolved pin, with detached allocations
unreleased. No recoverable ownership journal is added. Final errors cannot undo
callbacks already completed and never repeat them. Policy rejection preserves
the state it encounters and never clears a different owner's pin.
READY checks before each callback suppress disposal after an observed reentrant
fault; they are not atomic admission against arbitrary concurrent faults.
"""

from build_reveal_bridge_diag import Asm, b
import reveal_tidal_response_pair_mips as pair
import reveal_tidal_response_reader_bridge_mips as session
from reveal_registry_receipt_mips import FRAME, HI, LO, SAVE
from reveal_d960_payload_guard_mips import _validate_code_extent


ENTRY, ENTRY_PAIR = 0x5139C0, (0x27BDFFD8, 0xAFB00020)
CLOSE, RELEASE, OWNER_BIT = 0x8BD9D4, 0x8CBD6C, 0x80000000
SESSION, GENERATION, PIN = 0x90, 0x94, 0x98
PRIMARY, SECONDARY, DATA, RESULT, ERROR = 0x9C, 0xA0, 0xA4, 0xA8, 0xAC


def assemble(mutex_address, code_base):
    """Append a complete checked cleanup replacement to the local pair fixture."""
    prefix, patches = pair.assemble(mutex_address, code_base)
    asm = Asm(code_base + len(prefix))
    entry = asm.base
    patches[ENTRY] = ENTRY_PAIR, (b.j_type(2, entry), 0)

    def control():
        asm.absolute(8, mutex_address)

    def checked_lock():
        control()
        asm.e(b.lw(9, session.PHASE, 8), b.addiu(10, 0, session.READY))
        asm.branch(5, 9, 10, 'unavailable')
        asm.e(0xF)
        asm.absolute(4, mutex_address)
        asm.jump(session.LOCK, link=True)
        asm.branch(5, 2, 0, 'raw_error')
        control()
        asm.e(b.lw(9, session.PHASE, 8), b.addiu(10, 0, session.READY), b.addiu(2, 0, 11))
        asm.branch(5, 9, 10, 'unlock_error')
        asm.e(b.lw(9, session.LIFECYCLE, 8), b.addiu(10, 0, session.LIVE), b.addiu(2, 0, 116))
        asm.branch(5, 9, 10, 'unlock_error')
        asm.e(b.lw(11, session.BOUND_SESSION, 8))
        asm.branch(4, 11, 0, 'unlock_error')
        asm.absolute(9, session.SESSION_SLOT)
        asm.e(b.lw(10, 0, 9))
        asm.branch(5, 10, 11, 'unlock_error')
        asm.e(b.lw(12, session.GENERATION, 8))
        asm.branch(6, 12, 0, 'unlock_error')

    def checked_unlock():
        asm.absolute(4, mutex_address)
        asm.jump(session.UNLOCK, link=True)
        asm.branch(5, 2, 0, 'raw_error')

    def callback_admission():
        # A normally returning callback can have observed a protocol fault.
        # Do not continue disposal after that FAILED state is visible.
        control()
        asm.e(b.lw(9, session.PHASE, 8), b.addiu(10, 0, session.READY))
        asm.branch(5, 9, 10, 'unavailable')
        asm.e(0xF)

    asm.e(b.addiu(29, 29, -FRAME))
    for register, offset in SAVE.items():
        asm.e(b.sw(register, offset, 29))
    asm.e(b.r_type(0, 0, 8, 0x10), b.sw(8, HI, 29),
          b.r_type(0, 0, 8, 0x12), b.sw(8, LO, 29), b.sw(0, ERROR, 29))

    checked_lock()
    asm.e(b.lw(13, session.WRITER, 8), b.addiu(2, 0, 16))
    asm.branch(5, 13, 0, 'unlock_error')
    asm.e(b.lw(13, session.BORROWS, 8))
    asm.branch(5, 13, 0, 'unlock_error')
    asm.e(b.lw(9, 0x20, 11), b.addiu(2, 0, -1))
    asm.branch(4, 9, 0, 'no_callbacks')
    asm.e(b.lw(13, 0x18, 11), b.lw(14, 0x1C, 11))
    asm.branch(5, 13, 0, 'primary_present')
    asm.e(b.addiu(2, 0, 71))  # An orphan follow-up has no validated close token.
    asm.branch(5, 14, 0, 'unlock_error')
    asm.jump('no_callbacks', delay=b.move(2, 0))
    asm.label('primary_present')
    asm.e(b.addiu(2, 0, 22))
    asm.branch(4, 13, 14, 'unlock_error')  # Never guess two owned refs to one object.
    asm.e(b.lw(15, 8, 13))
    asm.branch(4, 15, 0, 'unlock_error')
    asm.e(b.sw(11, SESSION, 29), b.sw(12, GENERATION, 29),
          b.sw(13, PRIMARY, 29), b.sw(14, SECONDARY, 29), b.sw(15, DATA, 29))
    asm.absolute(9, OWNER_BIT)
    # Positive GEN has no owner bit; XOR therefore constructs OWNER_BIT | GEN.
    asm.e(b.r_type(12, 9, 10, 0x26), b.sw(10, PIN, 29), b.sw(10, session.WRITER, 8),
          b.sw(0, 0x18, 11), b.sw(0, 0x1C, 11))
    checked_unlock()

    callback_admission()
    asm.e(b.lw(4, DATA, 29))
    asm.jump(CLOSE, link=True, delay=b.move(5, 0))
    asm.e(b.sw(2, RESULT, 29))
    callback_admission()
    asm.e(b.lw(4, PRIMARY, 29))
    asm.jump(RELEASE, link=True)
    asm.e(b.lw(4, SECONDARY, 29))
    asm.branch(4, 4, 0, 'finalize')
    callback_admission()
    asm.jump(RELEASE, link=True)

    asm.label('finalize')
    checked_lock()
    asm.e(b.lw(9, SESSION, 29))
    asm.branch(5, 11, 9, 'unlock_error')
    asm.e(b.lw(9, GENERATION, 29))
    asm.branch(5, 12, 9, 'unlock_error')
    asm.e(b.lw(9, PIN, 29), b.lw(10, session.WRITER, 8))
    asm.branch(5, 9, 10, 'unlock_error')
    asm.e(b.sw(0, session.WRITER, 8))
    checked_unlock()
    asm.jump('restore_return')

    asm.label('no_callbacks')
    asm.e(b.sw(2, RESULT, 29))
    checked_unlock()
    asm.jump('restore_return')

    asm.label('unavailable')
    control()
    asm.e(0xF, b.lw(2, session.INIT_ERROR, 8))
    asm.branch(5, 2, 0, 'return_error')
    asm.jump('return_error', delay=b.addiu(2, 0, 11))
    asm.label('unlock_error')
    asm.e(b.sw(2, ERROR, 29))
    checked_unlock()
    asm.jump('return_error', delay=b.lw(2, ERROR, 29))
    asm.label('raw_error')
    control()
    asm.e(b.sw(2, session.INIT_ERROR, 8), b.addiu(9, 0, session.FAILED),
          0xF, b.sw(9, session.PHASE, 8), 0xF)
    asm.label('return_error')
    asm.e(b.sw(2, ERROR, 29), b.addiu(2, 0, -1), b.sw(2, RESULT, 29))
    asm.label('restore_return')
    asm.e(b.lw(8, RESULT, 29), b.sw(8, SAVE[2], 29),
          b.lw(8, ERROR, 29), b.sw(8, SAVE[3], 29),
          b.lw(8, HI, 29), b.r_type(8, 0, 0, 0x11),
          b.lw(8, LO, 29), b.r_type(8, 0, 0, 0x13))
    for register, offset in SAVE.items():
        asm.e(b.lw(register, offset, 29))
    asm.e(0x03E00008, b.addiu(29, 29, FRAME))

    code = prefix + asm.finish()
    _validate_code_extent(code_base, len(code))
    if code_base < mutex_address + session.CONTROL_BYTES and mutex_address < code_base + len(code):
        raise ValueError('cleanup helpers overlap the sidecar')
    return code, patches
