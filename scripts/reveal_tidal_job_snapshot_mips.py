#!/usr/bin/env python3
"""Local coherent snapshot for the consumer holding a native job mutex.

Compose 44 redirects. Replace the masking job-lock facades at this caller
with checked raw operations. The otherwise unused native frame word +FBC
holds only the actual nonnull mutex whose acquisition returned zero. Normal
unlock and snapshot refusal use that receipt, even if job+0C later changes.

The snapshot captures text and scalar from one primary under the session
mutex, bounds the private 128-byte buffer and resumes native postprocessing
outside that mutex. Policy refusal performs native completion/pending callbacks
only while the session sidecar remains READY, then releases the independently
held job mutex and uses the stack-only epilogue, skipping job status/UI writes.
On that refusal path, session raw errors suppress those callbacks but still
balance the known job lock once. A job raw error latches FAILED without guessed
unlock or retry.
Native completion/pending state stays unresolved on raw failure. The original
successful native continuation has no new internal fault/callback gates.

This requires coherent activation, the retained sidecar, valid nonaliasing
native/helper frames, distinct nonoverlapping session/job mutex objects,
normal selected calls and live job/controller/mutex objects. Native destructor
waiting and masked destroy calls do not establish their lifetime. No general
recovery, outer-caller quarantine, firmware image or hardware activation is
provided here.
"""

from build_reveal_bridge_diag import Asm, b
import reveal_tidal_preserved_snapshots_mips as preserved
import reveal_tidal_response_reader_bridge_mips as session
from reveal_registry_receipt_mips import FRAME, HI, LO, SAVE
from reveal_d960_payload_guard_mips import _validate_code_extent


ENTRY, END = 0x4ECA28, 0x4ED0D8
ACQUIRE, ACQUIRE_PAIR = 0x4ECA70, (0x0C119B68, 0x00009021)
RELEASE, RELEASE_PAIR = 0x4ECB68, (0x0C119B70, 0xAE130008)
SNAPSHOT, SNAPSHOT_PAIR = 0x4ECC8C, (0x0C12C588, 0x02802021)
SECOND, SECOND_PAIR = 0x4ECC94, (0x0C12C5A8, 0)
HOOKS = ((ACQUIRE, ACQUIRE_PAIR), (RELEASE, RELEASE_PAIR),
         (SNAPSHOT, SNAPSHOT_PAIR))
NATIVE_FRAME, RECEIPT, SAVED_INDEX, EPILOGUE = 0xFE0, 0xFBC, 0xFB8, 0x4ECB90
BUFFER, CAPACITY = 0xEB8, 128
STRLEN, COPY, COMPLETE_INDEX, CLEAR_PENDING = 0xA5B4E0, 0xA5B6E0, 0x42DCC0, 0x42B140
TEXT, USER_ID, ERROR = 0x90, 0x94, 0x98


def assemble(mutex_address, code_base):
    prefix, patches = preserved.assemble(mutex_address, code_base)
    asm = Asm(code_base + len(prefix))

    def hook(site, pair):
        patches[site] = pair, (b.j_type(2, asm.base + len(asm.w) * 4), 0)

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

    def resume(target, result=None):
        if result is not None:
            asm.e(b.addiu(8, 0, result), b.sw(8, SAVE[2], 29))
        asm.absolute(8, target)
        asm.e(b.sw(8, SAVE[31], 29))
        restore()
        asm.jump(target)

    def latch():
        control()
        asm.e(b.sw(2, session.INIT_ERROR, 8), b.addiu(9, 0, session.FAILED),
              0xF, b.sw(9, session.PHASE, 8), 0xF)

    def ready_or_skip(label):
        control()
        asm.e(b.lw(9, session.PHASE, 8), 0xF, b.addiu(10, 0, session.READY))
        asm.branch(5, 9, 10, label)

    def observe_raw_error(label):
        control()
        asm.e(b.lw(9, session.PHASE, 8), 0xF, b.addiu(10, 0, session.FAILED))
        asm.branch(5, 9, 10, label)
        asm.e(b.lw(9, session.INIT_ERROR, 8))
        asm.branch(4, 9, 0, label)
        asm.e(b.sw(9, ERROR, 29))
        asm.label(label)

    # The native S0==NULL branch bypasses this hook and never uses a receipt.
    hook(ACQUIRE, ACQUIRE_PAIR)
    asm.e(ACQUIRE_PAIR[1], b.sw(0, RECEIPT, 29))
    save()
    asm.e(b.addiu(2, 0, 22))
    asm.branch(4, 4, 0, 'finish_error')
    asm.absolute(8, mutex_address)
    asm.branch(4, 4, 8, 'finish_error')  # Never recursively acquire the session mutex.
    asm.jump(session.LOCK, link=True)  # A0 is the actual native mutex argument.
    asm.branch(5, 2, 0, 'job_raw_error')
    asm.e(b.lw(8, SAVE[4], 29), b.sw(8, FRAME + RECEIPT, 29))
    resume(ACQUIRE + 8, result=0)

    # Do not replay the native status write until a successful acquire receipt.
    hook(RELEASE, RELEASE_PAIR)
    save()
    asm.e(b.lw(4, FRAME + RECEIPT, 29), b.addiu(2, 0, 1))
    asm.branch(4, 4, 0, 'finish_error')
    asm.e(RELEASE_PAIR[1])
    asm.jump(session.UNLOCK, link=True)
    asm.branch(5, 2, 0, 'job_raw_error')
    asm.e(b.sw(0, FRAME + RECEIPT, 29))
    resume(RELEASE + 8, result=0)

    hook(SNAPSHOT, SNAPSHOT_PAIR)
    asm.e(SNAPSHOT_PAIR[1])
    save()
    asm.e(b.lw(8, FRAME + RECEIPT, 29), b.addiu(2, 0, 1))
    asm.branch(4, 8, 0, 'finish_error')
    ready_or_skip('unavailable')
    asm.absolute(4, mutex_address)
    asm.jump(session.LOCK, link=True)
    asm.branch(5, 2, 0, 'snapshot_raw_error')
    control()
    asm.e(b.lw(9, session.PHASE, 8), b.addiu(10, 0, session.READY), b.addiu(2, 0, 11))
    asm.branch(5, 9, 10, 'snapshot_unlock_error')
    asm.e(b.lw(9, session.LIFECYCLE, 8), b.addiu(10, 0, session.LIVE), b.addiu(2, 0, 116))
    asm.branch(5, 9, 10, 'snapshot_unlock_error')
    asm.e(b.lw(11, session.BOUND_SESSION, 8))
    asm.branch(4, 11, 0, 'snapshot_unlock_error')
    asm.absolute(9, session.SESSION_SLOT)
    asm.e(b.lw(10, 0, 9))
    asm.branch(5, 10, 11, 'snapshot_unlock_error')
    asm.e(b.lw(13, 0x18, 11), b.addiu(2, 0, 61))
    asm.branch(4, 13, 0, 'snapshot_unlock_error')
    asm.e(b.lw(14, 8, 13), b.addiu(2, 0, 22))
    asm.branch(4, 14, 0, 'snapshot_unlock_error')
    asm.e(b.lw(15, 4, 13), b.sw(14, TEXT, 29), b.sw(15, USER_ID, 29), b.move(4, 14))
    asm.jump(STRLEN, link=True)
    asm.e(b.i_type(11, 2, 9, CAPACITY), b.addiu(6, 2, 1), b.addiu(2, 0, 75))
    asm.branch(4, 9, 0, 'snapshot_unlock_error')
    asm.e(b.lw(4, SAVE[4], 29), b.lw(5, TEXT, 29))
    asm.jump(COPY, link=True)
    asm.absolute(4, mutex_address)
    asm.jump(session.UNLOCK, link=True)
    asm.branch(5, 2, 0, 'snapshot_raw_error')
    asm.e(b.lw(8, USER_ID, 29), b.sw(8, SAVE[2], 29), b.sw(0, SAVE[3], 29))
    resume(SECOND + 8)

    asm.label('unavailable')
    control()
    asm.e(b.lw(2, session.INIT_ERROR, 8))
    asm.branch(5, 2, 0, 'snapshot_abort')
    asm.jump('snapshot_abort', delay=b.addiu(2, 0, 11))
    asm.label('snapshot_unlock_error')
    asm.e(b.sw(2, ERROR, 29))
    asm.absolute(4, mutex_address)
    asm.jump(session.UNLOCK, link=True)
    asm.branch(5, 2, 0, 'snapshot_raw_error')
    asm.jump('snapshot_abort', delay=b.lw(2, ERROR, 29))
    asm.label('snapshot_raw_error')
    latch()
    asm.label('snapshot_abort')
    asm.e(b.sw(2, ERROR, 29))
    ready_or_skip('abort_job_unlock')
    asm.e(b.lw(4, FRAME + SAVED_INDEX, 29))
    asm.jump(COMPLETE_INDEX, link=True)
    ready_or_skip('abort_job_unlock')
    asm.e(b.lw(8, SAVE[18], 29))
    asm.branch(4, 8, 0, 'abort_job_unlock')
    asm.e(b.addiu(4, 0, 8), b.move(5, 0))
    asm.jump(CLEAR_PENDING, link=True)
    asm.label('abort_job_unlock')
    observe_raw_error('before_job_unlock')
    asm.e(b.lw(4, FRAME + RECEIPT, 29))
    asm.jump(session.UNLOCK, link=True)
    asm.branch(5, 2, 0, 'job_raw_error')
    observe_raw_error('after_job_unlock')
    asm.e(b.sw(0, FRAME + RECEIPT, 29), b.lw(2, ERROR, 29))
    asm.jump('finish_error')

    asm.label('job_raw_error')
    latch()
    asm.label('finish_error')
    asm.e(b.sw(2, SAVE[3], 29), b.addiu(8, 0, -1), b.sw(8, SAVE[2], 29))
    restore()
    asm.jump(EPILOGUE)

    code = prefix + asm.finish()
    _validate_code_extent(code_base, len(code))
    if code_base < mutex_address + session.CONTROL_BYTES and mutex_address < code_base + len(code):
        raise ValueError('job snapshot helpers overlap the sidecar')
    return code, patches
