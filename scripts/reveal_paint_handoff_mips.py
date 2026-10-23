#!/usr/bin/env python3
"""Offline native-list handoff, NOT a firmware stage or native owner lease.

The five emitted entries use the pinned controller148 mutex callbacks and
actual segmented-list methods. A separately versioned40-byte element contains
the original36-byte body unchanged and one non-reused publication nonce.
Every writer/remover/destructor MUST participate in this protocol; the stock
13C-only purge and native lifecycle do not. Inputs must already be coherent,
owned values. No engine/name/source-rectangle pointer is dereferenced; the
bound controller/list require a retained mapped native lifetime as a premise.

publish(a0=bound controller,a1=owned36): v0=nonce/0,v1=raw append result/0.
claim(a0=controller): v0=private36 copy/0,v1=nonce/0. That copy is valid ONLY
until the exact complete; the next claim may overwrite it.
complete(a0=controller,a1=nonce,a2=0/1): v0=completed1/failed2/cancelled3/0,
v1=raw remove result/0. cancel and close return active nonce/0 in v0.
Cancellation/close never remove or free. Faults withdraw new publication and
claims but admit an exact existing acknowledgement for cancellation cleanup.

An integer nonce is a cooperative private protocol ID, not an unforgeable
capability or native lifetime proof. Source/stack/controller validity and
mutex lifetime remain caller premises. Normal lock-service failures deny
success; failed unlock additionally sets a monotonic atomic terminal fault,
without claiming that lock ownership or native effects were rolled back.
There are no native frees, render calls, UI setters, timers or install hooks.
"""

from build_reveal_bridge_diag import Asm, b


SERIAL, ACTIVE, CANCELLED, FAULT, CLOSED = range(0, 20, 4)
COPY, ACTIVE_LIST, RESERVED, STATE_BYTES = 20, 56, 60, 64
PAYLOAD_BYTES, NONCE, ELEMENT_BYTES = 36, 36, 40
CONTROLLER_BYTES, LIST_BYTES = 0x28C, 0x38
LOCK, UNLOCK = 0x437CE0, 0x437D60
APPEND, GET, REMOVE = 0x455DA0, 0x4557E0, 0x455860
MAX_TICKET, SYNC = 0x7FFFFFFF, 0xF
FRAME, TEMP, ARG2, RESULT, RAW = 0x80, 0x10, 0x38, 0x3C, 0x40
HI, LO, OLD_COUNT = 0x44, 0x48, 0x64
SAVE = {16: 0x4C, 17: 0x50, 18: 0x54, 19: 0x58, 20: 0x5C, 31: 0x60}


def memory_bytes():
    return STATE_BYTES


def assemble(state_address, controller_address, code_base, *, capacity=64,
             ticket_limit=MAX_TICKET):
    """Return standalone instructions/labels; never construct a firmware image.

    The state must initially be zero and must never be reset/reused while a
    caller can retain a nonce/copy. Configured extents are scalar validation,
    not proof that native memory or mutex objects actually exist. All calls
    require an aligned mapped writable stack, including all nested native
    callee frames, separate from code/native heap. The explicit frame checks
    below cannot prove the stack depth of native mutex/libc/list services.
    """
    for name, value in (('capacity', capacity), ('ticket_limit', ticket_limit)):
        if type(value) is not int or not 1 <= value <= MAX_TICKET:
            raise ValueError(name + ' must be a positive signed word')
    for name, value, size in (('state', state_address, STATE_BYTES),
                              ('controller', controller_address, CONTROLLER_BYTES),
                              ('code', code_base, 4)):
        if (type(value) is not int or not 0 < value <= 0xFFFFFFFC
                or value % 4 or value + size > 0x100000000):
            raise ValueError(name + ' must have a nonwrapping aligned extent')
    if max(state_address, controller_address) < min(
            state_address + STATE_BYTES, controller_address + CONTROLLER_BYTES):
        raise ValueError('private state and controller overlap')
    a = Asm(code_base)

    def constant_equal(register, value, failed):
        a.absolute(9, value)
        a.branch(5, register, 9, failed)

    def nonoverlap(first, last, start, end, failed, label):
        # Inclusive runtime endpoints avoid falsely rejecting an extent whose
        # exclusive endpoint equals2**32. Scratch t1/t2 only.
        a.absolute(10, start)
        a.e(b.r_type(last, 10, 9, 0x2B))
        a.branch(5, 9, 0, label)
        a.absolute(10, end - 1)
        a.e(b.r_type(10, first, 9, 0x2B))
        a.branch(5, 9, 0, label)
        a.jump(failed)
        a.label(label)

    def prologue(name, *, input_block=False, outcome=False):
        a.label(name)
        constant_equal(4, controller_address, 'early_denied')
        a.e(b.i_type(12, 29, 8, 7))
        a.branch(5, 8, 0, 'early_denied')
        a.e(b.i_type(11, 29, 8, FRAME))
        a.branch(5, 8, 0, 'early_denied')
        a.e(b.addiu(11, 29, -FRAME), b.addiu(12, 29, -1))
        nonoverlap(11, 12, state_address, state_address + STATE_BYTES,
                   'early_denied', name + '_stack_state_ok')
        nonoverlap(11, 12, controller_address,
                   controller_address + CONTROLLER_BYTES,
                   'early_denied', name + '_stack_controller_ok')
        if outcome:
            a.e(b.i_type(11, 6, 8, 2))
            a.branch(4, 8, 0, 'early_denied')
        if input_block:
            a.branch(4, 5, 0, 'early_denied')
            a.e(b.i_type(12, 5, 8, 3))
            a.branch(5, 8, 0, 'early_denied')
            a.e(b.addiu(13, 5, PAYLOAD_BYTES - 1), b.r_type(13, 5, 8, 0x2B))
            a.branch(5, 8, 0, 'early_denied')
            nonoverlap(5, 13, state_address, state_address + STATE_BYTES,
                       'early_denied', name + '_input_state_ok')
            nonoverlap(5, 13, controller_address,
                       controller_address + CONTROLLER_BYTES,
                       'early_denied', name + '_input_controller_ok')
            # Reject overlap with the prospective frame BEFORE saving any
            # register there. The caller's outgoing home words at oldSP are
            # outside it and can contain an already-owned source.
            a.e(b.r_type(13, 11, 8, 0x2B))
            a.branch(5, 8, 0, name + '_input_stack_ok')
            a.e(b.r_type(12, 5, 8, 0x2B))
            a.branch(4, 8, 0, 'early_denied')
            a.label(name + '_input_stack_ok')
        # Pin the actual controller callbacks BEFORE their indirect call.
        # This remains a borrowed controller read, not a controller lease.
        a.e(b.lw(8, 0x284, 4))
        constant_equal(8, LOCK, 'early_denied')
        a.e(b.lw(8, 0x288, 4))
        constant_equal(8, UNLOCK, 'early_denied')
        a.e(b.addiu(29, 29, -FRAME))
        for register, offset in SAVE.items():
            a.e(b.sw(register, offset, 29))
        a.e(b.r_type(0, 0, 8, 0x10), b.sw(8, HI, 29),
            b.r_type(0, 0, 8, 0x12), b.sw(8, LO, 29),
            b.sw(6, ARG2, 29), b.sw(0, RESULT, 29), b.sw(0, RAW, 29),
            b.move(17, 4), b.move(18, 5))
        a.absolute(16, state_address)
        a.e(b.lw(25, 0x284, 17), b.move(4, 17), b.r_type(25, 0, 31, 9), 0)
        # Failed acquire owns no guard: do not inspect/change state/list or
        # attempt an unlock. Saved stack words are the only restore source.
        a.branch(5, 2, 0, 'restore')
        # Validate bounded state while148 is actually held. FAULT is monotonic;
        # it may already be set by another failed unlock outside the guard.
        a.e(SYNC, b.lw(8, SERIAL, 16))
        a.absolute(9, ticket_limit)
        a.e(b.r_type(9, 8, 10, 0x2B))
        a.branch(5, 10, 0, 'fault')
        a.e(b.lw(9, ACTIVE, 16), b.r_type(8, 9, 10, 0x2B))
        a.branch(5, 10, 0, 'fault')
        for offset in (CANCELLED, FAULT, CLOSED):
            a.e(b.lw(10, offset, 16), b.i_type(11, 10, 11, 2))
            a.branch(4, 11, 0, 'fault')
        a.e(b.lw(10, RESERVED, 16))
        a.branch(5, 10, 0, 'fault')
        a.branch(5, 9, 0, name + '_active_state')
        for offset in (CANCELLED, ACTIVE_LIST):
            a.e(b.lw(10, offset, 16))
            a.branch(5, 10, 0, 'fault')
        a.jump(name + '_state_ok')
        a.label(name + '_active_state')
        a.e(b.lw(10, ACTIVE_LIST, 16))
        a.branch(4, 10, 0, 'fault')
        a.e(b.i_type(12, 10, 11, 3))
        a.branch(5, 11, 0, 'fault')
        a.label(name + '_state_ok')

    def live():
        for offset in (FAULT, CLOSED):
            a.e(b.lw(8, offset, 16))
            a.branch(5, 8, 0, 'unlock')

    def native_list(name):
        a.e(b.lw(19, 0x128, 17))
        a.branch(4, 19, 0, 'fault')
        a.e(b.i_type(12, 19, 8, 3))
        a.branch(5, 8, 0, 'fault')
        a.e(b.addiu(8, 19, LIST_BYTES - 1), b.r_type(8, 19, 9, 0x2B))
        a.branch(5, 9, 0, 'fault')
        nonoverlap(19, 8, state_address, state_address + STATE_BYTES,
                   'fault', name + '_list_state_ok')
        nonoverlap(19, 8, controller_address,
                   controller_address + CONTROLLER_BYTES,
                   'fault', name + '_list_controller_ok')
        # A list structure aliasing this frame could overwrite saved state in
        # native methods. Its actual allocation validity remains a premise.
        a.e(b.r_type(8, 29, 9, 0x2B))
        a.branch(5, 9, 0, name + '_list_stack_ok')
        a.e(b.addiu(10, 29, FRAME - 1), b.r_type(10, 19, 9, 0x2B))
        a.branch(4, 9, 0, 'fault')
        a.label(name + '_list_stack_ok')
        a.e(b.lw(8, 0x10, 19))
        constant_equal(8, ELEMENT_BYTES, 'fault')
        for offset, target in ((0x18, APPEND), (0x2C, GET), (0x20, REMOVE)):
            a.e(b.lw(8, offset, 19))
            constant_equal(8, target, 'fault')
        # Pin the original ten-element segment geometry and reject the
        # concrete failed-grow state in which455A08 stores a null block table.
        # These scalar checks are not a general native heap-validity proof.
        a.e(b.lw(8, 0x14, 19))
        constant_equal(8, 10, 'fault')
        a.e(b.lw(8, 0, 19))
        a.branch(4, 8, 0, 'fault')
        a.e(b.i_type(12, 8, 9, 3))
        a.branch(5, 9, 0, 'fault')
        a.e(b.lw(11, 8, 19))
        a.branch(4, 11, 0, 'fault')
        a.absolute(9, MAX_TICKET)
        a.e(b.r_type(9, 11, 10, 0x2B))
        a.branch(5, 10, 0, 'fault')
        a.e(b.lw(8, 0xC, 19))
        a.e(b.r_type(11, 8, 10, 0x2B))
        a.branch(5, 10, 0, 'fault')
        a.absolute(9, capacity)
        a.e(b.r_type(9, 8, 10, 0x2B))
        a.branch(5, 10, 0, 'fault')

    def selected(name):
        a.branch(4, 2, 0, 'fault')
        a.e(b.i_type(12, 2, 8, 3))
        a.branch(5, 8, 0, 'fault')
        a.e(b.addiu(8, 2, ELEMENT_BYTES - 1), b.r_type(8, 2, 9, 0x2B))
        a.branch(5, 9, 0, 'fault')
        nonoverlap(2, 8, state_address, state_address + STATE_BYTES,
                   'fault', name + '_selected_state_ok')
        nonoverlap(2, 8, controller_address,
                   controller_address + CONTROLLER_BYTES,
                   'fault', name + '_selected_controller_ok')
        a.e(b.r_type(8, 29, 9, 0x2B))
        a.branch(5, 9, 0, name + '_selected_stack_ok')
        a.e(b.addiu(10, 29, FRAME - 1), b.r_type(10, 2, 9, 0x2B))
        a.branch(4, 9, 0, 'fault')
        a.label(name + '_selected_stack_ok')

    def call_list(offset, *, zero_index=False):
        a.e(b.lw(25, offset, 19), b.move(4, 19))
        if zero_index:
            a.e(b.move(5, 0))
        a.e(b.r_type(25, 0, 31, 9), 0)

    prologue('publish', input_block=True)
    live()
    native_list('publish')
    a.e(b.sw(8, OLD_COUNT, 29))
    a.branch(4, 8, 9, 'unlock')  # explicit logical cap, NOT chunk geometry
    a.e(b.lw(20, SERIAL, 16))
    a.absolute(9, ticket_limit)
    a.branch(4, 20, 9, 'fault')
    a.e(b.addiu(20, 20, 1), b.sw(20, SERIAL, 16))
    for offset in range(0, PAYLOAD_BYTES, 4):
        a.e(b.lw(8, offset, 18), b.sw(8, TEMP + offset, 29))
    a.e(b.sw(20, TEMP + NONCE, 29), b.addiu(5, 29, TEMP))
    call_list(0x18)
    a.e(b.sw(2, RAW, 29), b.addiu(8, 0, -1))
    # Native grow failure is NOT transactional:455A08 can clear its block
    # table even when the logical count did not change. Burn the nonce and
    # withdraw terminally instead of promising a retry/rollback.
    a.branch(4, 2, 8, 'fault')
    a.e(b.lw(8, OLD_COUNT, 29))
    a.branch(5, 2, 8, 'fault')
    a.e(b.addiu(8, 8, 1), b.lw(9, 0xC, 19))
    a.branch(5, 8, 9, 'fault')
    a.e(b.sw(20, RESULT, 29))
    a.jump('unlock')

    prologue('claim')
    live()
    a.e(b.lw(8, ACTIVE, 16))
    a.branch(5, 8, 0, 'unlock')
    native_list('claim')
    a.branch(4, 8, 0, 'unlock')
    call_list(0x2C, zero_index=True)
    selected('claim')
    a.e(b.lw(20, NONCE, 2))
    a.branch(4, 20, 0, 'fault')
    a.e(b.lw(8, SERIAL, 16), b.r_type(8, 20, 9, 0x2B))
    a.branch(5, 9, 0, 'fault')
    for offset in range(0, PAYLOAD_BYTES, 4):
        a.e(b.lw(8, offset, 2), b.sw(8, COPY + offset, 16))
    a.e(b.sw(19, ACTIVE_LIST, 16), b.sw(0, CANCELLED, 16), SYNC,
        b.sw(20, ACTIVE, 16), b.addiu(8, 16, COPY),
        b.sw(8, RESULT, 29), b.sw(20, RAW, 29))
    a.jump('unlock')

    prologue('complete', outcome=True)
    a.e(b.lw(20, ACTIVE, 16))
    a.branch(4, 20, 0, 'unlock')
    a.branch(5, 20, 18, 'unlock')
    # Check the current list identity BEFORE reading that list's header. A
    # replaced pointer is not admitted just because the old list was valid.
    a.e(b.lw(8, 0x128, 17), b.lw(9, ACTIVE_LIST, 16))
    a.branch(5, 8, 9, 'fault')
    native_list('complete')
    a.branch(4, 8, 0, 'fault')
    call_list(0x2C, zero_index=True)
    selected('complete')
    a.e(b.lw(8, NONCE, 2))
    a.branch(5, 8, 20, 'fault')
    call_list(0x20, zero_index=True)
    a.e(b.sw(2, RAW, 29))
    a.branch(5, 2, 0, 'fault')
    # Cancellation/terminal withdrawal wins over the caller's success report.
    for offset in (CANCELLED, CLOSED, FAULT):
        a.e(b.lw(8, offset, 16))
        a.branch(5, 8, 0, 'complete_cancelled')
    a.e(b.lw(8, ARG2, 29), b.addiu(9, 0, 2))
    a.branch(4, 8, 0, 'complete_outcome')
    a.e(b.addiu(9, 0, 1))
    a.jump('complete_outcome')
    a.label('complete_cancelled')
    a.e(b.addiu(9, 0, 3))
    a.label('complete_outcome')
    a.e(b.sw(9, RESULT, 29), b.sw(0, ACTIVE, 16),
        b.sw(0, ACTIVE_LIST, 16), b.sw(0, CANCELLED, 16))
    a.jump('unlock')

    for name in ('cancel', 'close'):
        prologue(name)
        if name == 'close':
            a.e(b.addiu(8, 0, 1), b.sw(8, CLOSED, 16))
        a.e(b.lw(8, ACTIVE, 16), b.sw(8, RESULT, 29))
        a.branch(4, 8, 0, 'unlock')
        a.e(b.addiu(8, 0, 1), b.sw(8, CANCELLED, 16))
        a.jump('unlock')

    a.label('fault')
    a.e(b.addiu(8, 0, 1), b.sw(8, FAULT, 16), b.sw(0, RESULT, 29), SYNC,
        b.lw(9, ACTIVE, 16))
    a.branch(4, 9, 0, 'unlock')
    a.e(b.sw(8, CANCELLED, 16))
    a.label('unlock')
    a.e(SYNC, b.lw(25, 0x288, 17), b.move(4, 17), b.r_type(25, 0, 31, 9), 0)
    a.branch(4, 2, 0, 'restore')
    # Ownership is unknown after a failed unlock. Only this aligned monotonic
    # terminal bit is published outside148; never clear it or mutate ACTIVE.
    a.e(b.addiu(8, 0, 1), b.sw(8, FAULT, 16), SYNC,
        b.sw(0, RESULT, 29), b.sw(0, RAW, 29))
    a.label('restore')
    a.e(b.lw(8, HI, 29), b.r_type(8, 0, 0, 0x11),
        b.lw(8, LO, 29), b.r_type(8, 0, 0, 0x13),
        b.lw(2, RESULT, 29), b.lw(3, RAW, 29))
    for register, offset in SAVE.items():
        a.e(b.lw(register, offset, 29))
    a.e(b.addiu(29, 29, FRAME), b.r_type(31, 0, 0, 8), 0)
    a.label('early_denied')
    a.e(b.move(2, 0), b.move(3, 0), b.r_type(31, 0, 0, 8), 0)

    result = a.finish()
    end = code_base + len(result)
    if end > 0x100000000 or code_base >> 28 != (end - 1) >> 28:
        raise ValueError('code wraps or leaves its MIPS jump region')
    for start, size in ((state_address, STATE_BYTES),
                        (controller_address, CONTROLLER_BYTES)):
        if max(start, code_base) < min(start + size, end):
            raise ValueError('code overlaps private state/controller')
    return result, a.labels
