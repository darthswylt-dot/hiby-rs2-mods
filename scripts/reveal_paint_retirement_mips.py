#!/usr/bin/env python3
"""Offline generation-aware44-byte native paint queue, NOT firmware integration.

All registered owners are append-only tombstones; owner and publication tickets
share a non-reused serial. Producers supply the generation captured at admission,
never register a replacement implicitly. Engine values are compared as scalars,
not dereferenced. Inputs must already be coherent/owned; controller, mutex, list,
stack and source lifetime remain caller premises. Every native writer and cleanup
path must cooperate before this could be installed. No engine/free/UI calls occur.

open_owner(controller,engine): v0=owner ticket/0. publish(controller,owned36,
owner): v0=nonce/0,v1=raw append result. claim returns private36 copy/nonce.
complete(controller,nonce,0/1): v0=completed1/failed2/cancelled3/0,v1=raw remove.
retire(controller,owner): v0=1 only after its full guarded scan,v1=removed count;
drained(controller,owner): v0=1 only for a retired generation with no locally
queued/active references and no fault. Neither result authorizes a native free.
close only withdraws/cancels; it does not retire owners or drain queued tails.
In default facade-fixture mode, substituted callback-unlock failure denies
success and sets a fault withdrawing new work/positive drained; a valid old
claim may still acknowledge cancellation. Native facades erase actual raw
statuses, so this is NOT raw-failure coverage. Effects are never rolled back.

Optional checked_mutex=True bypasses status-erasing native mutex facades and
calls the raw pthread services with one captured mutex pointer. Raw errors
return (0,status); the caller MUST quarantine the instance externally. An
uncertain unlock does not permit further shared-state writes or an internal
fault-latch promise. The unchanged default is only the prior facade fixture,
not evidence that native raw mutex failures are handled.
"""

from build_reveal_bridge_diag import Asm, b


SERIAL, ACTIVE, CANCELLED, FAULT, CLOSED = range(0, 20, 4)
COPY, ACTIVE_LIST, ACTIVE_OWNER, OWNER_COUNT, RESERVED, HEADER_BYTES = 20, 56, 60, 64, 68, 72
HEADER = HEADER_BYTES
OWNER_TICKET, OWNER_ENGINE, OWNER_RETIRED, OWNER_RESERVED, OWNER_BYTES = 0, 4, 8, 12, 16
PAYLOAD_BYTES, NONCE, OWNER, ELEMENT_BYTES = 36, 36, 40, 44
CONTROLLER_BYTES, LIST_BYTES = 0x28C, 0x38
LOCK, UNLOCK = 0x437CE0, 0x437D60
APPEND, GET, REMOVE = 0x455DA0, 0x4557E0, 0x455860
MAX_TICKET, SYNC = 0x7FFFFFFF, 0xF
FRAME, TEMP, ARG2, RESULT, RAW = 0xA0, 0x10, 0x3C, 0x40, 0x44
HI, LO, OLD_COUNT, INDEX, REMOVED, BUDGET, ROWPTR = 0x48, 0x4C, 0x50, 0x54, 0x58, 0x5C, 0x60
MUTEX, MUTEX_BYTES, RAW_LOCK, RAW_UNLOCK = 0x64, 24, 0xA5B960, 0xA5B830
SAVE = {16: 0x6C, 17: 0x70, 18: 0x74, 19: 0x78, 20: 0x7C,
        21: 0x80, 22: 0x84, 23: 0x88, 31: 0x8C}


def memory_bytes(owner_capacity=16):
    if type(owner_capacity) is not int or not 1 <= owner_capacity <= 1024:
        raise ValueError('owner capacity must be in1..1024')
    return HEADER_BYTES + OWNER_BYTES * owner_capacity


def assemble(state_address, controller_address, code_base, *, capacity=64,
             owner_capacity=16, ticket_limit=MAX_TICKET, checked_mutex=False):
    """Emit a standalone prototype; zero state initially and never reset/reuse it."""
    state_bytes = memory_bytes(owner_capacity)
    if type(checked_mutex) is not bool:
        raise ValueError('checked_mutex must be a bool')
    if checked_mutex and (type(code_base) is not int or code_base >> 28):
        raise ValueError('checked raw mutex calls must share the native jump region')
    for name, value in (('capacity', capacity), ('ticket_limit', ticket_limit)):
        if type(value) is not int or not 1 <= value <= MAX_TICKET:
            raise ValueError(name + ' must be a positive signed word')
    for name, value, size in (('state', state_address, state_bytes),
                              ('controller', controller_address, CONTROLLER_BYTES),
                              ('code', code_base, 4)):
        if (type(value) is not int or not 0 < value <= 0xFFFFFFFC
                or value % 4 or value + size > 0x100000000):
            raise ValueError(name + ' must have a nonwrapping aligned extent')
    if max(state_address, controller_address) < min(
            state_address + state_bytes, controller_address + CONTROLLER_BYTES):
        raise ValueError('private state and controller overlap')
    a = Asm(code_base)

    def equal(register, value, failed):
        a.absolute(9, value)
        a.branch(5, register, 9, failed)

    def nonoverlap(first, last, start, end, failed, label):
        a.absolute(10, start)
        a.e(b.r_type(last, 10, 9, 0x2B))
        a.branch(5, 9, 0, label)
        a.absolute(10, end - 1)
        a.e(b.r_type(10, first, 9, 0x2B))
        a.branch(5, 9, 0, label)
        a.jump(failed)
        a.label(label)

    def lookup(ticket, destination, missing, label):
        # Scratch t3..t7 only; ticket/destination must not use those registers.
        a.e(b.addiu(11, 16, HEADER_BYTES), b.lw(12, OWNER_COUNT, 16))
        a.label(label + '_loop')
        a.branch(4, 12, 0, missing)
        a.e(b.lw(13, OWNER_TICKET, 11))
        a.branch(4, 13, ticket, label + '_found')
        a.e(b.addiu(11, 11, OWNER_BYTES), b.addiu(12, 12, -1))
        a.jump(label + '_loop')
        a.label(label + '_found')
        a.e(b.move(destination, 11))

    def prologue(name, *, input_block=False, outcome=False):
        a.label(name)
        equal(4, controller_address, 'early_denied')
        a.e(b.i_type(12, 29, 8, 7))
        a.branch(5, 8, 0, 'early_denied')
        a.e(b.i_type(11, 29, 8, FRAME))
        a.branch(5, 8, 0, 'early_denied')
        a.e(b.addiu(11, 29, -FRAME), b.addiu(12, 29, -1))
        nonoverlap(11, 12, state_address, state_address + state_bytes,
                   'early_denied', name + '_stack_state_ok')
        nonoverlap(11, 12, controller_address, controller_address + CONTROLLER_BYTES,
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
            nonoverlap(5, 13, state_address, state_address + state_bytes,
                       'early_denied', name + '_input_state_ok')
            nonoverlap(5, 13, controller_address, controller_address + CONTROLLER_BYTES,
                       'early_denied', name + '_input_controller_ok')
            a.e(b.r_type(13, 11, 8, 0x2B))
            a.branch(5, 8, 0, name + '_input_stack_ok')
            a.e(b.r_type(12, 5, 8, 0x2B))
            a.branch(4, 8, 0, 'early_denied')
            a.label(name + '_input_stack_ok')
        a.e(b.lw(8, 0x284, 4))
        equal(8, LOCK, 'early_denied')
        a.e(b.lw(8, 0x288, 4))
        equal(8, UNLOCK, 'early_denied')
        if checked_mutex:
            # Capture once before acquisition. This scalar/extent check is
            # not a proof of allocation lifetime, mutex initialization or a
            # complete native/service stack bound.
            a.e(b.lw(15, 0x148, 4))
            a.branch(4, 15, 0, 'early_denied')
            a.e(b.i_type(12, 15, 8, 3))
            a.branch(5, 8, 0, 'early_denied')
            a.e(b.addiu(14, 15, MUTEX_BYTES - 1), b.r_type(14, 15, 8, 0x2B))
            a.branch(5, 8, 0, 'early_denied')
            nonoverlap(15, 14, state_address, state_address + state_bytes,
                       'early_denied', name + '_mutex_state_ok')
            nonoverlap(15, 14, controller_address, controller_address + CONTROLLER_BYTES,
                       'early_denied', name + '_mutex_controller_ok')
            a.e(b.r_type(14, 11, 8, 0x2B))
            a.branch(5, 8, 0, name + '_mutex_stack_ok')
            a.e(b.r_type(12, 15, 8, 0x2B))
            a.branch(4, 8, 0, 'early_denied')
            a.label(name + '_mutex_stack_ok')
        a.e(b.addiu(29, 29, -FRAME))
        for register, offset in SAVE.items():
            a.e(b.sw(register, offset, 29))
        a.e(b.r_type(0, 0, 8, 0x10), b.sw(8, HI, 29),
            b.r_type(0, 0, 8, 0x12), b.sw(8, LO, 29), b.sw(6, ARG2, 29),
            b.sw(0, RESULT, 29), b.sw(0, RAW, 29), b.move(17, 4), b.move(18, 5))
        a.absolute(16, state_address)
        if checked_mutex:
            a.e(b.sw(15, MUTEX, 29), b.move(4, 15))
            a.jump(RAW_LOCK, link=True)
            a.e(b.sw(2, RAW, 29))
        else:
            a.e(b.lw(25, 0x284, 17), b.move(4, 17), b.r_type(25, 0, 31, 9), 0)
        a.branch(5, 2, 0, 'restore')
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
        # Validate the whole bounded append-only owner schema before lookup.
        a.e(b.lw(12, OWNER_COUNT, 16))
        a.absolute(10, owner_capacity)
        a.e(b.r_type(10, 12, 11, 0x2B))
        a.branch(5, 11, 0, 'fault')
        a.e(b.addiu(11, 16, HEADER_BYTES), b.move(13, 0))
        a.label(name + '_owners_loop')
        a.branch(4, 12, 0, name + '_owners_done')
        a.e(b.lw(14, OWNER_TICKET, 11), b.r_type(13, 14, 15, 0x2B))
        a.branch(4, 15, 0, 'fault')
        a.e(b.r_type(8, 14, 15, 0x2B))
        a.branch(5, 15, 0, 'fault')
        a.e(b.lw(15, OWNER_RETIRED, 11), b.i_type(11, 15, 15, 2))
        a.branch(4, 15, 0, 'fault')
        a.e(b.lw(15, OWNER_RESERVED, 11))
        a.branch(5, 15, 0, 'fault')
        a.e(b.move(13, 14), b.addiu(11, 11, OWNER_BYTES), b.addiu(12, 12, -1))
        a.jump(name + '_owners_loop')
        a.label(name + '_owners_done')
        a.e(b.lw(9, ACTIVE, 16))
        a.branch(5, 9, 0, name + '_active_state')
        for offset in (CANCELLED, ACTIVE_LIST, ACTIVE_OWNER):
            a.e(b.lw(10, offset, 16))
            a.branch(5, 10, 0, 'fault')
        a.jump(name + '_state_ok')
        a.label(name + '_active_state')
        a.e(b.lw(10, ACTIVE_LIST, 16))
        a.branch(4, 10, 0, 'fault')
        a.e(b.i_type(12, 10, 11, 3))
        a.branch(5, 11, 0, 'fault')
        a.e(b.lw(24, ACTIVE_OWNER, 16))
        lookup(24, 21, 'fault', name + '_active_owner')
        a.e(b.lw(8, OWNER_RETIRED, 21))
        a.branch(4, 8, 0, name + '_state_ok')
        a.e(b.lw(8, CANCELLED, 16))
        a.branch(4, 8, 0, 'fault')
        a.label(name + '_state_ok')

    def live(*, closed=True):
        for offset in ((FAULT, CLOSED) if closed else (FAULT,)):
            a.e(b.lw(8, offset, 16))
            a.branch(5, 8, 0, 'unlock')

    def native_list(name):
        a.e(b.lw(19, 0x128, 17))
        a.e(b.lw(8, ACTIVE, 16))
        a.branch(4, 8, 0, name + '_list_binding_ok')
        a.e(b.lw(8, ACTIVE_LIST, 16))
        a.branch(5, 19, 8, 'fault')
        a.label(name + '_list_binding_ok')
        a.branch(4, 19, 0, 'fault')
        a.e(b.i_type(12, 19, 8, 3))
        a.branch(5, 8, 0, 'fault')
        a.e(b.addiu(8, 19, LIST_BYTES - 1), b.r_type(8, 19, 9, 0x2B))
        a.branch(5, 9, 0, 'fault')
        nonoverlap(19, 8, state_address, state_address + state_bytes,
                   'fault', name + '_list_state_ok')
        nonoverlap(19, 8, controller_address, controller_address + CONTROLLER_BYTES,
                   'fault', name + '_list_controller_ok')
        a.e(b.r_type(8, 29, 9, 0x2B))
        a.branch(5, 9, 0, name + '_list_stack_ok')
        a.e(b.addiu(10, 29, FRAME - 1), b.r_type(10, 19, 9, 0x2B))
        a.branch(4, 9, 0, 'fault')
        a.label(name + '_list_stack_ok')
        a.e(b.lw(8, 0x10, 19))
        equal(8, ELEMENT_BYTES, 'fault')
        for offset, target in ((0x18, APPEND), (0x2C, GET), (0x20, REMOVE)):
            a.e(b.lw(8, offset, 19))
            equal(8, target, 'fault')
        a.e(b.lw(8, 0x14, 19))
        equal(8, 10, 'fault')
        a.e(b.lw(8, 0, 19))
        a.branch(4, 8, 0, 'fault')
        a.e(b.i_type(12, 8, 9, 3))
        a.branch(5, 9, 0, 'fault')
        a.e(b.lw(11, 8, 19))
        a.branch(4, 11, 0, 'fault')
        a.absolute(9, MAX_TICKET)
        a.e(b.r_type(9, 11, 10, 0x2B))
        a.branch(5, 10, 0, 'fault')
        a.e(b.lw(8, 0xC, 19), b.r_type(11, 8, 10, 0x2B))
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
        nonoverlap(2, 8, state_address, state_address + state_bytes,
                   'fault', name + '_selected_state_ok')
        nonoverlap(2, 8, controller_address, controller_address + CONTROLLER_BYTES,
                   'fault', name + '_selected_controller_ok')
        a.e(b.r_type(8, 29, 9, 0x2B))
        a.branch(5, 9, 0, name + '_selected_stack_ok')
        a.e(b.addiu(10, 29, FRAME - 1), b.r_type(10, 2, 9, 0x2B))
        a.branch(4, 9, 0, 'fault')
        a.label(name + '_selected_stack_ok')
        a.e(b.lw(20, NONCE, 2))
        a.branch(4, 20, 0, 'fault')
        a.e(b.lw(8, SERIAL, 16), b.r_type(8, 20, 9, 0x2B))
        a.branch(5, 9, 0, 'fault')
        a.e(b.lw(24, OWNER, 2))
        lookup(24, 21, 'fault', name + '_row_owner')
        a.e(b.r_type(24, 20, 8, 0x2B))
        a.branch(4, 8, 0, 'fault')
        a.e(b.lw(8, 8, 2), b.lw(9, OWNER_ENGINE, 21))
        a.branch(5, 8, 9, 'fault')

    def call_list(offset, *, index=0):
        a.e(b.lw(25, offset, 19), b.move(4, 19), b.move(5, index),
            b.r_type(25, 0, 31, 9), 0)

    def mint(destination):
        a.e(b.lw(destination, SERIAL, 16))
        a.absolute(9, ticket_limit)
        a.branch(4, destination, 9, 'fault')
        a.e(b.addiu(destination, destination, 1), b.sw(destination, SERIAL, 16))

    def active_binding(name):
        # Call after native_list. Verify before ANY purge removal, not only
        # after finding a matching generation deeper in the list.
        a.e(b.lw(8, ACTIVE, 16))
        a.branch(4, 8, 0, name + '_active_binding_done')
        a.e(b.lw(9, ACTIVE_LIST, 16))
        a.branch(5, 19, 9, 'fault')
        a.e(b.lw(8, 0xC, 19))
        a.branch(4, 8, 0, 'fault')
        call_list(0x2C)
        selected(name + '_active_binding')
        a.e(b.lw(8, ACTIVE, 16))
        a.branch(5, 20, 8, 'fault')
        a.e(b.lw(8, ACTIVE_OWNER, 16), b.lw(9, OWNER, 2))
        a.branch(5, 8, 9, 'fault')
        a.label(name + '_active_binding_done')

    prologue('open_owner')
    live()
    a.e(b.lw(8, OWNER_COUNT, 16))
    a.absolute(9, owner_capacity)
    a.branch(4, 8, 9, 'unlock')
    a.e((8 << 16) | (8 << 11) | (4 << 6), b.addiu(21, 16, HEADER_BYTES),
        b.r_type(21, 8, 21, 0x21))
    mint(20)
    a.e(b.sw(20, OWNER_TICKET, 21), b.sw(18, OWNER_ENGINE, 21),
        b.sw(0, OWNER_RETIRED, 21), b.sw(0, OWNER_RESERVED, 21),
        b.lw(8, OWNER_COUNT, 16), b.addiu(8, 8, 1), SYNC,
        b.sw(8, OWNER_COUNT, 16), b.sw(20, RESULT, 29))
    a.jump('unlock')

    prologue('publish', input_block=True)
    live()
    a.e(b.lw(23, ARG2, 29))
    lookup(23, 21, 'unlock', 'publish_owner')
    a.e(b.lw(8, OWNER_RETIRED, 21))
    a.branch(5, 8, 0, 'unlock')
    a.e(b.lw(8, 8, 18), b.lw(9, OWNER_ENGINE, 21))
    a.branch(5, 8, 9, 'unlock')
    native_list('publish')
    a.e(b.sw(8, OLD_COUNT, 29))
    a.branch(4, 8, 9, 'unlock')
    mint(20)
    for offset in range(0, PAYLOAD_BYTES, 4):
        a.e(b.lw(8, offset, 18), b.sw(8, TEMP + offset, 29))
    a.e(b.sw(20, TEMP + NONCE, 29), b.sw(23, TEMP + OWNER, 29),
        b.addiu(5, 29, TEMP), b.lw(25, 0x18, 19), b.move(4, 19),
        b.r_type(25, 0, 31, 9), 0, b.sw(2, RAW, 29), b.addiu(8, 0, -1))
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
    call_list(0x2C)
    selected('claim')
    a.e(b.lw(8, OWNER_RETIRED, 21))
    a.branch(5, 8, 0, 'fault')
    for offset in range(0, PAYLOAD_BYTES, 4):
        a.e(b.lw(8, offset, 2), b.sw(8, COPY + offset, 16))
    a.e(b.lw(8, OWNER, 2), b.sw(8, ACTIVE_OWNER, 16),
        b.sw(19, ACTIVE_LIST, 16), b.sw(0, CANCELLED, 16), SYNC,
        b.sw(20, ACTIVE, 16), b.addiu(8, 16, COPY),
        b.sw(8, RESULT, 29), b.sw(20, RAW, 29))
    a.jump('unlock')

    prologue('complete', outcome=True)
    a.e(b.lw(20, ACTIVE, 16))
    a.branch(4, 20, 0, 'unlock')
    a.branch(5, 20, 18, 'unlock')
    a.e(b.lw(8, 0x128, 17), b.lw(9, ACTIVE_LIST, 16))
    a.branch(5, 8, 9, 'fault')
    native_list('complete')
    a.branch(4, 8, 0, 'fault')
    a.e(b.sw(8, OLD_COUNT, 29))
    call_list(0x2C)
    selected('complete')
    a.e(b.lw(8, ACTIVE, 16))
    a.branch(5, 20, 8, 'fault')
    a.e(b.lw(8, OWNER, 2), b.lw(9, ACTIVE_OWNER, 16))
    a.branch(5, 8, 9, 'fault')
    call_list(0x20)
    a.e(b.sw(2, RAW, 29))
    a.branch(5, 2, 0, 'fault')
    a.e(b.lw(8, OLD_COUNT, 29), b.addiu(8, 8, -1), b.lw(9, 0xC, 19))
    a.branch(5, 8, 9, 'fault')
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
    a.e(b.sw(9, RESULT, 29), b.sw(0, ACTIVE, 16), b.sw(0, ACTIVE_LIST, 16),
        b.sw(0, ACTIVE_OWNER, 16), b.sw(0, CANCELLED, 16))
    a.jump('unlock')

    for name in ('retire', 'drained'):
        prologue(name)
        if name == 'drained':
            live(closed=False)
        a.e(b.move(23, 18))
        lookup(23, 21, 'unlock', name + '_owner')
        if name == 'retire':
            a.e(b.addiu(8, 0, 1), b.sw(8, OWNER_RETIRED, 21), SYNC,
                b.lw(9, ACTIVE_OWNER, 16))
            a.branch(5, 9, 23, name + '_revoked')
            a.e(b.sw(8, CANCELLED, 16))
            a.label(name + '_revoked')
            live(closed=False)
        else:
            a.e(b.lw(8, OWNER_RETIRED, 21))
            a.branch(4, 8, 0, 'unlock')
        native_list(name)
        a.e(b.sw(8, BUDGET, 29), b.sw(0, REMOVED, 29), b.move(22, 0))
        active_binding(name)
        a.label(name + '_scan')
        a.e(b.lw(8, BUDGET, 29))
        a.branch(4, 8, 0, name + '_finished')
        a.e(b.addiu(8, 8, -1), b.sw(8, BUDGET, 29), b.lw(8, 0xC, 19),
            b.r_type(22, 8, 9, 0x2B))
        a.branch(4, 9, 0, 'fault')
        call_list(0x2C, index=22)
        selected(name + '_scan_row')
        a.e(b.lw(8, OWNER, 2))
        a.branch(5, 8, 23, name + '_keep')
        if name == 'drained':
            a.jump('unlock')
        else:
            a.branch(5, 22, 0, name + '_remove')
            a.e(b.lw(8, ACTIVE, 16))
            a.branch(5, 8, 0, name + '_keep')
            a.label(name + '_remove')
            a.e(b.lw(8, 0xC, 19), b.sw(8, OLD_COUNT, 29))
            call_list(0x20, index=22)
            a.branch(5, 2, 0, 'fault')
            a.e(b.lw(8, OLD_COUNT, 29), b.addiu(8, 8, -1), b.lw(9, 0xC, 19))
            a.branch(5, 8, 9, 'fault')
            a.e(b.lw(8, REMOVED, 29), b.addiu(8, 8, 1), b.sw(8, REMOVED, 29))
            a.jump(name + '_scan')
        a.label(name + '_keep')
        a.e(b.addiu(22, 22, 1))
        a.jump(name + '_scan')
        a.label(name + '_finished')
        a.e(b.lw(8, 0xC, 19))
        a.branch(5, 22, 8, 'fault')
        if name == 'drained':
            a.e(b.lw(8, ACTIVE_OWNER, 16))
            a.branch(4, 8, 23, 'unlock')
        a.e(b.addiu(8, 0, 1), b.sw(8, RESULT, 29))
        if name == 'retire':
            a.e(b.lw(8, REMOVED, 29), b.sw(8, RAW, 29))
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
    if checked_mutex:
        a.e(SYNC, b.lw(4, MUTEX, 29))
        a.jump(RAW_UNLOCK, link=True)
    else:
        a.e(SYNC, b.lw(25, 0x288, 17), b.move(4, 17), b.r_type(25, 0, 31, 9), 0)
    a.branch(4, 2, 0, 'restore')
    if checked_mutex:
        # Unlock may have released the mutex despite reporting an error.
        # Only our retained stack frame is writable now. No rollback/latch.
        a.e(b.sw(0, RESULT, 29), b.sw(2, RAW, 29))
    else:
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
    for start, size in ((state_address, state_bytes),
                        (controller_address, CONTROLLER_BYTES)):
        if max(start, code_base) < min(start + size, end):
            raise ValueError('code overlaps private state/controller')
    return result, a.labels
