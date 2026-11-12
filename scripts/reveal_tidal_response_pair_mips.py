#!/usr/bin/env python3
"""Local private response preparation and checked pair publication for Tidal.

Compose the eleven transport/session hooks with five request redirects. The
single worker passes its queued generation in A3. Admission validates that
generation and its existing writer pin before running the native request body.
Both native response stores are deferred; a complete pair replaces both slots
in one mutex transaction. Failed preparation keeps the old pair and retires
only its private partial response. Detached old objects are released outside
the mutex while the worker still owns its pin.

All sixteen redirects require coherent activation, retained nonaliasing state,
valid native frames plus 192 helper stack bytes, normal callee returns and the
selected single-worker ABI. Native locals +14/+1C hold the private follow-up
and generation. The called services use at most four outgoing arguments.
Service results must be fresh caller-owned objects; indirect class/method
binding and complete borrow closure are separate premises. Pointer alias
checks reject ambiguous reclamation rather than guessing reference ownership.
Starting slots must contain valid owned objects, and every admitted borrow
must use this mutex. The fixture closes only the two selected reader spans.

Raw failure latches FAILED, suppressing release callbacks even after commit.
Each callback checks READY again; an observed reentrant fault suppresses later
callbacks without promising atomic admission against any concurrent fault.
Policy rejection preserves published fields and retains private candidates.
When only an active retained borrow prevents commit, verified disjoint private
candidates are released outside the mutex and the old pair remains published.
No recovery journal is supplied; retained private objects can leak on errors.
Other reader spans, QR aliases, cleanup, input snapshots, worker postprocessing
and queue lifetime still need integration before any firmware image is built.
"""

from build_reveal_bridge_diag import Asm, b
import reveal_tidal_request_identity_mips as identity
import reveal_tidal_response_reader_bridge_mips as session
from reveal_registry_receipt_mips import FRAME, HI, LO, SAVE
from reveal_d960_payload_guard_mips import _validate_code_extent


CALL, CALL_PAIR = 0x4547CC, (0x0C144E18, 0xAFC20004)
REQUEST = 0x513860
ADMIT, ADMIT_PAIR = 0x51387C, (0x0C11D4C8, 0xAFA50024)
FIRST, FIRST_PAIR = 0x5138BC, (0xAE300018, 0x8E040008)
SECOND, SECOND_PAIR = 0x5138D8, (0xAE22001C, 0x00001021)
FINISH, FINISH_PAIR = 0x5138E0, (0x8FBF0034, 0x8FB20030)
REQUEST_FRAME, PRIVATE_FOLLOWUP, TOKEN = 56, 0x14, 0x1C
TEMP_ERROR, RETIRED_FIRST, RETIRED_SECOND, CAPTURED = 0x90, 0x94, 0x98, 0x9C
RELEASE = 0x8CBD6C
HOOKS = ((CALL, CALL_PAIR), (ADMIT, ADMIT_PAIR), (FIRST, FIRST_PAIR),
         (SECOND, SECOND_PAIR), (FINISH, FINISH_PAIR))


def assemble(mutex_address, code_base):
    """Return the composed local code and all sixteen pinned redirect pairs."""
    prefix, patches = identity.assemble(mutex_address, code_base)
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

    def checked_entry(action):
        save()
        control()
        asm.e(b.lw(9, session.PHASE, 8), b.addiu(10, 0, session.READY))
        asm.branch(5, 9, 10, action + '_unavailable')
        asm.e(0xF)
        asm.absolute(4, mutex_address)
        asm.jump(session.LOCK, link=True)
        asm.branch(5, 2, 0, action + '_raw_error')
        control()
        asm.e(b.lw(9, session.PHASE, 8), b.addiu(10, 0, session.READY), b.addiu(2, 0, 11))
        asm.branch(5, 9, 10, action + '_unlock_error')
        asm.e(b.lw(9, session.LIFECYCLE, 8), b.addiu(10, 0, session.LIVE), b.addiu(2, 0, 116))
        asm.branch(5, 9, 10, action + '_unlock_error')
        asm.e(b.lw(11, session.BOUND_SESSION, 8))
        asm.branch(4, 11, 0, action + '_unlock_error')
        asm.absolute(9, session.SESSION_SLOT)
        asm.e(b.lw(10, 0, 9))
        asm.branch(5, 10, 11, action + '_unlock_error')
        asm.e(b.lw(12, session.GENERATION, 8))
        asm.branch(6, 12, 0, action + '_unlock_error')
        if action == 'admit':
            asm.e(b.lw(13, SAVE[7], 29))
        else:
            asm.e(b.lw(13, FRAME + TOKEN, 29), b.lw(14, SAVE[17], 29))
            asm.branch(5, 14, 11, action + '_unlock_error')
        asm.branch(5, 13, 12, action + '_unlock_error')
        asm.e(b.lw(14, session.WRITER, 8))
        asm.branch(5, 14, 12, action + '_unlock_error')

    def unlock(action):
        asm.absolute(4, mutex_address)
        asm.jump(session.UNLOCK, link=True)
        asm.branch(5, 2, 0, action + '_raw_error')

    def errors(action):
        asm.label(action + '_unavailable')
        control()
        asm.e(0xF, b.lw(2, session.INIT_ERROR, 8))
        asm.branch(5, 2, 0, action + '_abort')
        asm.jump(action + '_abort', delay=b.addiu(2, 0, 11))
        asm.label(action + '_unlock_error')
        asm.e(b.sw(2, TEMP_ERROR, 29))
        unlock(action)
        asm.jump(action + '_abort', delay=b.lw(2, TEMP_ERROR, 29))
        asm.label(action + '_raw_error')
        control()
        asm.e(b.sw(2, session.INIT_ERROR, 8), b.addiu(9, 0, session.FAILED),
              0xF, b.sw(9, session.PHASE, 8), 0xF)
        asm.label(action + '_abort')
        asm.e(b.sw(2, SAVE[3], 29), b.addiu(8, 0, -2), b.sw(8, SAVE[2], 29))
        restore()
        asm.jump('request_epilogue')

    redirect(CALL, CALL_PAIR)
    asm.e(b.lw(7, identity.QUEUED_GENERATION, 29))
    asm.absolute(31, CALL + 8)
    asm.jump(REQUEST, delay=CALL_PAIR[1])

    redirect(FIRST, FIRST_PAIR)
    asm.e(FIRST_PAIR[1])  # Borrow the private primary, without publishing it.
    asm.jump(FIRST + 8)

    redirect(SECOND, SECOND_PAIR)
    asm.e(b.sw(2, PRIVATE_FOLLOWUP, 29))
    asm.jump(SECOND + 8, delay=SECOND_PAIR[1])

    redirect(ADMIT, ADMIT_PAIR)
    checked_entry('admit')
    asm.e(b.sw(11, CAPTURED, 29), b.sw(12, FRAME + TOKEN, 29),
          b.sw(0, FRAME + PRIVATE_FOLLOWUP, 29))
    unlock('admit')
    asm.e(b.lw(8, CAPTURED, 29), b.sw(8, SAVE[2], 29))
    restore()
    asm.jump(ADMIT + 8, delay=ADMIT_PAIR[1])  # Replay the saved native A1.
    errors('admit')

    redirect(FINISH, FINISH_PAIR)
    checked_entry('finish')
    asm.e(b.sw(0, RETIRED_FIRST, 29), b.sw(0, RETIRED_SECOND, 29), b.sw(0, TEMP_ERROR, 29),
          b.lw(10, SAVE[16], 29), b.lw(11, FRAME + PRIVATE_FOLLOWUP, 29),
          b.lw(12, 0x18, 17), b.lw(13, 0x1C, 17), b.addiu(2, 0, 22))
    asm.branch(5, 10, 0, 'finish_primary')
    asm.branch(5, 11, 0, 'finish_unlock_error')
    asm.jump('finish_unlock')  # Request failure: no new allocation to retire.
    asm.label('finish_primary')
    asm.branch(4, 10, 12, 'finish_unlock_error')
    asm.branch(4, 10, 13, 'finish_unlock_error')
    asm.branch(5, 11, 0, 'finish_complete')
    asm.e(b.sw(10, RETIRED_FIRST, 29))  # Partial preparation: keep the old pair.
    asm.jump('finish_unlock')
    asm.label('finish_complete')
    asm.branch(4, 10, 11, 'finish_unlock_error')
    asm.branch(4, 11, 12, 'finish_unlock_error')
    asm.branch(4, 11, 13, 'finish_unlock_error')
    asm.branch(4, 12, 0, 'finish_swap')
    asm.branch(4, 12, 13, 'finish_unlock_error')
    asm.label('finish_swap')
    asm.e(b.lw(14, session.BORROWS, 8))
    asm.branch(4, 14, 0, 'finish_readers_drained')
    # The checked candidates are private and disjoint from every published
    # object. Refuse the swap, retiring these candidates instead of old data.
    asm.e(b.sw(10, RETIRED_FIRST, 29), b.sw(11, RETIRED_SECOND, 29),
          b.addiu(9, 0, -2), b.sw(9, SAVE[2], 29), b.addiu(9, 0, 16), b.sw(9, TEMP_ERROR, 29))
    asm.jump('finish_unlock')
    asm.label('finish_readers_drained')
    asm.e(b.sw(12, RETIRED_FIRST, 29), b.sw(13, RETIRED_SECOND, 29),
          b.sw(10, 0x18, 17), b.sw(11, 0x1C, 17))
    asm.label('finish_unlock')
    unlock('finish')
    for index, offset in enumerate((RETIRED_FIRST, RETIRED_SECOND)):
        asm.e(b.lw(4, offset, 29))
        asm.branch(4, 4, 0, f'finish_released_{index}')
        control()
        asm.e(b.lw(9, session.PHASE, 8), b.addiu(10, 0, session.READY))
        asm.branch(5, 9, 10, 'finish_unavailable')
        asm.e(0xF)
        asm.jump(RELEASE, link=True)
        asm.label(f'finish_released_{index}')
    asm.e(b.lw(8, TEMP_ERROR, 29), b.sw(8, SAVE[3], 29))
    restore()
    asm.jump('request_epilogue')
    errors('finish')

    asm.label('request_epilogue')
    asm.e(*FINISH_PAIR)
    asm.jump(FINISH + 8)

    code = prefix + asm.finish()
    _validate_code_extent(code_base, len(code))
    if code_base < mutex_address + session.CONTROL_BYTES and mutex_address < code_base + len(code):
        raise ValueError('response pair helpers overlap their sidecar')
    return code, patches
