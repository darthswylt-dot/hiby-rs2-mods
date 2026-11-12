#!/usr/bin/env python3
"""Local generation-stamped QR payload construction and retained timer entry.

Compose the compound fixture with nine QR redirects. Only mode2 payloads
grow from1A8 to1AC; their tail carries the generation captured together with
the descriptor's session pointer. The timer validates allocation size before
reading that tail, then retains its expected generation through native return.
An incompatible status200 primary-schema path returns EPROTO before dereference.
That refusal is not working Tidal QR authentication or proof of its schema.

The source ABI, live dialog/owner/payloads and descriptor frames, allocator
headers, normal callback returns and coherent activation are premises. Existing
same-name handles keep their old payload and metadata; the unused fresh payload
is released. NULL factory results restore the saved owner only while zero,
with the same undetectable zero-to-zero updates as the ordinary QR guard.
Raw errors quarantine without guessed unlock or private-payload release.
The native timer's callbacks after a concurrent fault remain an open frontier.
No image builder, cleanup scheduling, request sequence or device operation is
introduced by this local composer.
"""

from build_reveal_bridge_diag import Asm, b
import reveal_tidal_compound_snapshot_mips as compound
import reveal_tidal_response_reader_bridge_mips as session
from reveal_registry_receipt_mips import FRAME, HI, LO, SAVE
from reveal_d960_payload_guard_mips import _validate_code_extent


CAPTURE, CAPTURE_PAIR = 0x50826C, (0x0C11D4C8, 0xAFA20020)
POST, POST_PAIR = 0x5082A8, (0x0C1152D0, 0x00002821)
ALLOC, ALLOC_PAIR = 0x501A10, (0x0C119A78, 0xAFA20024)
CLEAR, CLEAR_PAIR = 0x501A28, (0x0C296F18, 0x240601A8)
BIND, BIND_PAIR = 0x501A38, (0x8E220018, 0xAFB0002C)
OWNER, OWNER_PAIR = 0x501A80, (0x27A20020, 0xAE400208)
RESULT, RESULT_PAIR = 0x501A9C, (0x3C040050, 0x24841680)
TIMER, TIMER_PAIR = 0x501680, (0x27BDFDC0, 0xAFBF023C)
SCHEMA, SCHEMA_PAIR = 0x501838, (0x8E420018, 0x1040005D)
HOOKS = ((CAPTURE, CAPTURE_PAIR), (POST, POST_PAIR), (ALLOC, ALLOC_PAIR), (CLEAR, CLEAR_PAIR),
         (BIND, BIND_PAIR), (OWNER, OWNER_PAIR), (RESULT, RESULT_PAIR),
         (TIMER, TIMER_PAIR), (SCHEMA, SCHEMA_PAIR))
ALLOCATOR, MEMSET, FREE = 0x4669E0, 0xA5BC60, 0x466A80
QR_RETURN, CALLER_RETURN = 0x501AB8, 0x5082C0
ORDINARY_BYTES, TIDAL_BYTES, PAYLOAD_TOKEN = 0x1A8, 0x1AC, 0x1A8
DESCRIPTOR_TOKEN, CALLER_TOKEN, SAVED_OWNER = 0x1C, 0x3C, 0x40
TEMP, GENERATION, POINTER, ORIGINAL_RA, ERROR, DIAG = 0x90, 0x94, 0x98, 0x9C, 0xA0, 0xA4
EXPECTED_POINTER, EXPECTED_TOKEN = 0xA8, 0xAC
TIMER_FRAME, MAX_BORROWS = 576, 0x7FFFFFFF


def assemble(mutex_address, code_base):
    prefix, patches = compound.assemble(mutex_address, code_base)
    asm = Asm(code_base + len(prefix))

    def redirect(site, original):
        patches[site] = original, (b.j_type(2, asm.base + 4 * len(asm.w)), 0)

    def save_registers():
        for register, offset in SAVE.items():
            asm.e(b.sw(register, offset, 29))
        asm.e(b.r_type(0, 0, 8, 0x10), b.sw(8, HI, 29),
              b.r_type(0, 0, 8, 0x12), b.sw(8, LO, 29))

    def save():
        asm.e(b.addiu(29, 29, -FRAME))
        save_registers()

    def restore(pop=True):
        asm.e(b.lw(8, HI, 29), b.r_type(8, 0, 0, 0x11),
              b.lw(8, LO, 29), b.r_type(8, 0, 0, 0x13))
        for register, offset in SAVE.items():
            asm.e(b.lw(register, offset, 29))
        if pop:
            asm.e(b.addiu(29, 29, FRAME))

    def control():
        asm.absolute(8, mutex_address)

    def gate(label):
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

    def errors(label, destination, *, timer=False, bind=False):
        asm.label(label + '_unavailable')
        control()
        asm.e(0xF, b.lw(2, session.INIT_ERROR, 8))
        asm.branch(5, 2, 0, label + '_raw_abort')
        asm.jump(label + '_raw_abort', delay=b.addiu(2, 0, 11))
        asm.label(label + '_unlock_error')
        asm.e(b.sw(2, ERROR, 29))
        unlock(label)
        asm.e(b.lw(2, ERROR, 29))
        asm.jump(label + '_policy_abort')
        asm.label(label + '_raw_error')
        control()
        asm.e(b.sw(2, session.INIT_ERROR, 8), b.addiu(9, 0, session.FAILED),
              0xF, b.sw(9, session.PHASE, 8), 0xF)
        asm.label(label + '_raw_abort')
        asm.jump(label + '_abort')
        asm.label(label + '_policy_abort')
        if bind:
            asm.e(b.sw(2, ERROR, 29))
            control()
            asm.e(b.lw(9, session.PHASE, 8), b.addiu(10, 0, session.READY))
            asm.branch(5, 9, 10, label + '_unavailable')
            asm.jump(FREE, link=True, delay=b.move(4, 16))
            asm.e(b.lw(2, ERROR, 29))
        asm.label(label + '_abort')
        asm.e(b.sw(2, SAVE[3], 29), b.addiu(8, 0, -1 if timer else 0), b.sw(8, SAVE[2], 29))
        if timer:
            asm.e(b.lw(8, ORIGINAL_RA, 29), b.sw(8, SAVE[31], 29))
        restore()
        if timer:
            asm.e(0x03E00008, 0)
        else:
            asm.jump(destination)

    redirect(CAPTURE, CAPTURE_PAIR)
    asm.e(CAPTURE_PAIR[1])  # Preserve mode=2 before any raw call changes V0.
    save()
    gate('capture')
    asm.e(b.sw(11, POINTER, 29), b.sw(12, FRAME + CALLER_TOKEN, 29))
    unlock('capture')
    asm.e(b.lw(8, POINTER, 29), b.sw(8, SAVE[2], 29))
    asm.absolute(8, CAPTURE + 8)
    asm.e(b.sw(8, SAVE[31], 29))
    restore()
    asm.jump(CAPTURE + 8)
    errors('capture', CALLER_RETURN)

    redirect(POST, POST_PAIR)
    save()
    gate('post')
    asm.e(b.lw(9, FRAME + 0x38, 29))
    asm.branch(5, 9, 11, 'post_unlock_error')
    asm.e(b.lw(9, FRAME + CALLER_TOKEN, 29))
    asm.branch(5, 9, 12, 'post_unlock_error')
    asm.e(b.sw(12, EXPECTED_TOKEN, 29))
    unlock('post')
    asm.e(b.move(4, 0), b.lw(5, EXPECTED_TOKEN, 29))
    asm.jump('native_post', link=True)
    asm.e(b.sw(2, SAVE[2], 29), b.sw(0, SAVE[3], 29))
    asm.absolute(8, POST + 8)
    asm.e(b.sw(8, SAVE[31], 29))
    restore()
    asm.jump(POST + 8)
    errors('post', CALLER_RETURN)

    for name, site, original, service in (('alloc', ALLOC, ALLOC_PAIR, ALLOCATOR),
                                          ('clear', CLEAR, CLEAR_PAIR, MEMSET)):
        redirect(site, original)
        if name == 'alloc':
            asm.e(original[1])  # The descriptor destructor value predates ALLOC.
        save()
        asm.e(b.lw(8, 0, 17), b.addiu(9, 0, 2),
              b.addiu(4 if name == 'alloc' else 6, 0, ORDINARY_BYTES))
        asm.branch(5, 8, 9, name + '_call')
        asm.e(b.addiu(4 if name == 'alloc' else 6, 0, TIDAL_BYTES))
        asm.label(name + '_call')
        asm.jump(service, link=True)
        asm.e(b.sw(2, SAVE[2], 29))
        if name == 'alloc':
            asm.branch(5, 2, 0, 'alloc_success')
            asm.e(b.addiu(8, 0, 12), b.sw(8, SAVE[3], 29))
            restore()
            asm.jump(QR_RETURN)
            asm.label('alloc_success')
        asm.absolute(8, site + 8)
        asm.e(b.sw(8, SAVE[31], 29))
        restore()
        asm.jump(site + 8)

    redirect(BIND, BIND_PAIR)
    save()
    asm.e(b.lw(8, 0, 17), b.addiu(9, 0, 2))
    asm.branch(5, 8, 9, 'bind_ordinary')
    gate('bind')
    asm.e(b.lw(9, 0x18, 17))
    asm.branch(5, 9, 11, 'bind_unlock_error')
    asm.e(b.lw(9, DESCRIPTOR_TOKEN, 17))
    asm.branch(5, 9, 12, 'bind_unlock_error')
    asm.e(b.sw(11, 0x18C, 16), b.sw(12, PAYLOAD_TOKEN, 16), b.sw(16, FRAME + 0x2C, 29))
    unlock('bind')
    restore()
    asm.jump(0x501A44)
    asm.label('bind_ordinary')
    restore()
    asm.e(*BIND_PAIR)
    asm.jump(BIND + 8)
    errors('bind', QR_RETURN, bind=True)

    redirect(OWNER, OWNER_PAIR)
    save()
    asm.e(b.lw(8, 0x208, 18), b.sw(8, FRAME + SAVED_OWNER, 29))
    restore()
    asm.e(OWNER_PAIR[0])
    asm.jump(OWNER + 8, delay=OWNER_PAIR[1])

    redirect(RESULT, RESULT_PAIR)
    save()
    asm.branch(4, 2, 0, 'result_null')
    asm.e(b.lw(8, 0x4C, 2))
    asm.branch(4, 8, 16, 'result_fresh')
    asm.jump(FREE, link=True, delay=b.move(4, 16))
    asm.e(b.sw(0, SAVE[3], 29))
    restore()
    asm.jump(QR_RETURN)
    asm.label('result_null')
    asm.jump(FREE, link=True, delay=b.move(4, 16))
    asm.label('restore_owner')
    asm.e(b.lw(5, FRAME + SAVED_OWNER, 29))
    asm.branch(4, 5, 0, 'result_empty')
    asm.e(b.i_type(0x30, 18, 4, 0x208))
    asm.branch(5, 4, 0, 'result_empty')
    asm.e(b.i_type(0x38, 18, 5, 0x208))
    asm.branch(4, 5, 0, 'restore_owner')
    asm.label('result_empty')
    asm.e(b.sw(0, SAVE[2], 29), b.addiu(8, 0, 12), b.sw(8, SAVE[3], 29))
    restore()
    asm.jump(QR_RETURN)
    asm.label('result_fresh')
    restore()
    asm.e(RESULT_PAIR[0])
    asm.jump(RESULT + 8, delay=RESULT_PAIR[1])

    redirect(TIMER, TIMER_PAIR)
    save()
    asm.e(b.lw(8, SAVE[31], 29), b.sw(8, ORIGINAL_RA, 29), b.sw(0, DIAG, 29),
          b.lw(8, 0x4C, 4))
    asm.branch(4, 8, 0, 'timer_ordinary')
    asm.e(b.lw(9, 0, 8), b.addiu(10, 0, 2))
    asm.branch(5, 9, 10, 'timer_ordinary')
    asm.e(b.lw(9, -4, 8), b.addiu(10, 0, TIDAL_BYTES), b.addiu(2, 0, 71))
    asm.branch(5, 9, 10, 'timer_begin_abort')
    asm.e(b.lw(9, 0x18C, 8), b.sw(9, EXPECTED_POINTER, 29),
          b.lw(9, PAYLOAD_TOKEN, 8), b.sw(9, EXPECTED_TOKEN, 29))
    gate('timer_begin')
    asm.e(b.lw(9, EXPECTED_POINTER, 29))
    asm.branch(5, 9, 11, 'timer_begin_unlock_error')
    asm.e(b.lw(9, EXPECTED_TOKEN, 29))
    asm.branch(5, 9, 12, 'timer_begin_unlock_error')
    asm.e(b.lw(9, session.WRITER, 8), b.addiu(2, 0, 16))
    asm.branch(1, 9, 0, 'timer_begin_unlock_error')
    asm.e(b.lw(14, session.BORROWS, 8))
    asm.absolute(9, MAX_BORROWS)
    asm.e(b.r_type(14, 9, 10, 0x2B), b.addiu(2, 0, 75))
    asm.branch(4, 10, 0, 'timer_begin_unlock_error')
    asm.e(b.addiu(14, 14, 1), b.sw(14, session.BORROWS, 8),
          b.sw(11, POINTER, 29), b.sw(12, GENERATION, 29))
    unlock('timer_begin')
    restore(pop=False)
    asm.jump('timer_body', link=True)
    save_registers()
    gate('timer_finish')
    asm.e(b.lw(9, POINTER, 29))
    asm.branch(5, 9, 11, 'timer_finish_unlock_error')
    asm.e(b.lw(9, GENERATION, 29))
    asm.branch(5, 9, 12, 'timer_finish_unlock_error')
    asm.e(b.lw(14, session.BORROWS, 8))
    asm.branch(6, 14, 0, 'timer_finish_unlock_error')
    asm.e(b.addiu(14, 14, -1), b.sw(14, session.BORROWS, 8))
    unlock('timer_finish')
    asm.e(b.lw(8, DIAG, 29), b.sw(8, SAVE[3], 29),
          b.lw(8, ORIGINAL_RA, 29), b.sw(8, SAVE[31], 29))
    restore()
    asm.e(0x03E00008, 0)
    asm.label('timer_ordinary')
    restore()
    asm.e(*TIMER_PAIR)
    asm.jump(TIMER + 8)
    for name in ('timer_begin', 'timer_finish'):
        errors(name, 0, timer=True)
    asm.label('timer_body')
    asm.e(*TIMER_PAIR)
    asm.jump(TIMER + 8)

    redirect(SCHEMA, SCHEMA_PAIR)
    asm.e(b.addiu(2, 0, 71), b.sw(2, TIMER_FRAME + DIAG, 29))
    asm.jump(0x5016D0, delay=b.addiu(2, 0, -1))

    asm.label('native_post')
    asm.e(0x27BDFFD8, 0x3C0200B9)
    asm.jump(0x454B48)

    code = prefix + asm.finish()
    _validate_code_extent(code_base, len(code))
    if code_base < mutex_address + session.CONTROL_BYTES and mutex_address < code_base + len(code):
        raise ValueError('QR generation helpers overlap their sidecar')
    return code, patches
