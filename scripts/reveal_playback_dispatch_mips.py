#!/usr/bin/env python3
"""Emit a private journal of two exact playback dispatch-intent observations.

capture(a0=FAST/GENERAL, a1=wrapper-owned seven-word scalar block) returns
a fresh private ID or zero. Metadata is [frame, site, return, target, context,
descriptor, player]. Addresses in the block are evidence only: the core does
not read the callback target, context, player, descriptor or native frame.
An observation precedes the original indirect transfer. It does not prove
callback entry, return, success, a playback change, or any UI/queue cause.

Only this journal, the owned input block and this function's own frame are
accessed. There are no native calls, clocks, parent links or native carriers.
Allocation uses bounded, non-reusing LL/SC; magic publishes last. A permanent
global fault overrides even a racing publication. Snapshot acquisition and
the wrapper's unconditional native dispatch are separate responsibilities.
O32 callee-saved registers, SP, RA and HI/LO are preserved; v0 is the ID.
"""

from build_reveal_bridge_diag import Asm, b


HEADER, RECORD = 16, 64
STATE, FAULT = 0, 0xFFFFFFFF
MAGIC_OFFSET, MAGIC = 0, int.from_bytes(b'LPDI', 'little')
KIND, PARENT, ORIGIN, SEQ = 4, 8, 12, 16
FRAME, SITE, RETURN, TARGET, CONTEXT, DESCRIPTOR, PLAYER = 20, 24, 28, 32, 36, 40, 44
RESERVED = (48, 52, 56, 60)
FAST, GENERAL = 1, 2
FAST_SITE, GENERAL_SITE = 0x42CC0C, 0x42D6A0
DESCRIPTOR_ADDRESS, PLAYER_ADDRESS = 0xADD468, 0xADD368
DEFAULT_CAPACITY, RETRIES = 1024, 8
MAX_CAPACITY = (0x100000000 - HEADER) // RECORD
CALL_FRAME, METADATA_WORDS, SYNC = 0x60, 7, 0x0000000F


def memory_bytes(capacity=DEFAULT_CAPACITY):
    if type(capacity) is not int or not 1 <= capacity <= MAX_CAPACITY:
        raise ValueError('capacity must fit a nonempty unsigned-32 dispatch journal')
    return HEADER + RECORD * capacity


def assemble(journal_address, code_base, capacity=DEFAULT_CAPACITY):
    """Return (code bytes, absolute labels), without I/O or installation.

    Public entries are capture, reserve and invalidate. reserve returns a
    PRIVATE slot in v0 and its fresh ID in v1, or both zero on permanent loss.
    The caller owns and maps the complete seven-word metadata input block;
    checking its scalar address does not establish ownership of native data.
    """
    size = memory_bytes(capacity)
    for name, value in (('journal_address', journal_address), ('code_base', code_base)):
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFC or value % 4:
            raise ValueError(name + ' must be an aligned unsigned-32 address')
    if journal_address + size > 0x100000000:
        raise ValueError('private journal must not wrap the address space')

    a = Asm(code_base)

    def journal_check():
        a.absolute(8, journal_address)
        a.absolute(9, capacity)
        a.e(SYNC, b.lw(10, STATE, 8), b.r_type(9, 10, 11, 0x2B))
        a.branch(5, 11, 0, 'capture_fault')

    def local_equal(local, value):
        a.e(b.lw(8, local, 29))
        a.absolute(9, value)
        a.branch(5, 8, 9, 'capture_fault')

    a.label('capture')
    a.e(b.addiu(29, 29, -CALL_FRAME), b.sw(31, 0x5C, 29), b.sw(4, 0x10, 29))
    a.branch(4, 4, 0, 'capture_fault')
    a.e(b.i_type(11, 4, 8, GENERAL + 1))
    a.branch(4, 8, 0, 'capture_fault')
    a.branch(4, 5, 0, 'capture_fault')
    a.e(b.i_type(12, 5, 8, 3))
    a.branch(5, 8, 0, 'capture_fault')
    # The last word must not wrap before copying the caller-owned block.
    a.e(b.addiu(8, 5, (METADATA_WORDS - 1) * 4), b.r_type(8, 5, 9, 0x2B))
    a.branch(5, 9, 0, 'capture_fault')
    journal_check()
    for index in range(METADATA_WORDS):
        a.e(b.lw(8, index * 4, 5), b.sw(8, 0x20 + index * 4, 29))
    # Native frame is an aligned positive scalar, never an accessed pointer.
    a.e(b.lw(8, 0x20, 29))
    a.branch(4, 8, 0, 'capture_fault')
    a.e(b.i_type(12, 8, 9, 3))
    a.branch(5, 9, 0, 'capture_fault')
    # A target is an uninterpreted nonzero scalar (including odd/MIPS16-like).
    a.e(b.lw(8, 0x2C, 29))
    a.branch(4, 8, 0, 'capture_fault')
    local_equal(0x34, DESCRIPTOR_ADDRESS)
    local_equal(0x38, PLAYER_ADDRESS)
    a.e(b.lw(8, 0x10, 29), b.addiu(9, 0, FAST))
    a.branch(4, 8, 9, 'capture_fast')
    local_equal(0x24, GENERAL_SITE)
    local_equal(0x28, GENERAL_SITE + 8)
    a.jump('capture_bound')
    a.label('capture_fast')
    local_equal(0x24, FAST_SITE)
    local_equal(0x28, FAST_SITE + 8)
    a.label('capture_bound')
    a.jump('reserve', True)
    a.branch(4, 2, 0, 'capture_ignored')
    a.e(b.sw(2, 0x3C, 29), b.sw(3, 0x40, 29),
        b.sw(3, SEQ, 2), b.sw(3, ORIGIN, 2), b.sw(0, PARENT, 2))
    for local, field in ((0x10, KIND), (0x20, FRAME), (0x24, SITE),
                         (0x28, RETURN), (0x2C, TARGET), (0x30, CONTEXT),
                         (0x34, DESCRIPTOR), (0x38, PLAYER)):
        a.e(b.lw(8, local, 29), b.sw(8, field, 2))
    for field in RESERVED:
        a.e(b.sw(0, field, 2))
    a.label('capture_publish')
    journal_check()
    a.e(b.lw(2, 0x3C, 29), SYNC)
    a.absolute(8, MAGIC)
    a.label('capture_magic_store')
    a.e(b.sw(8, MAGIC_OFFSET, 2), SYNC, b.lw(2, 0x40, 29))
    a.jump('capture_done')
    a.label('capture_fault')
    a.jump('invalidate', True)
    a.label('capture_ignored')
    a.e(b.move(2, 0))
    a.label('capture_done')
    a.e(b.lw(31, 0x5C, 29), b.addiu(29, 29, CALL_FRAME),
        b.r_type(31, 0, 0, 8), 0)

    a.label('reserve')
    a.absolute(8, journal_address)
    a.absolute(9, capacity)
    a.e(b.addiu(14, 0, RETRIES), SYNC)
    a.label('reserve_ll')
    a.e(b.i_type(0x30, 8, 10, STATE), b.r_type(10, 9, 11, 0x2B))
    a.branch(4, 11, 0, 'reserve_fault')
    a.e(b.addiu(3, 10, 1), b.move(11, 3))
    a.label('reserve_sc')
    a.e(b.i_type(0x38, 8, 11, STATE))
    a.branch(5, 11, 0, 'reserve_success')
    a.e(b.addiu(14, 14, -1))
    a.branch(5, 14, 0, 'reserve_ll')
    a.jump('reserve_fault')
    a.label('reserve_success')
    a.e((10 << 16) | (11 << 11) | (6 << 6),
        b.r_type(8, 11, 2, 0x21), b.addiu(2, 2, HEADER), SYNC,
        b.lw(11, MAGIC_OFFSET, 2))
    a.branch(5, 11, 0, 'reserve_fault')
    a.e(b.lw(10, STATE, 8), b.r_type(9, 10, 11, 0x2B))
    a.branch(5, 11, 0, 'reserve_fault')
    a.e(SYNC, b.r_type(31, 0, 0, 8), 0)
    a.label('invalidate')
    a.absolute(8, journal_address)
    a.label('reserve_fault')
    a.e(b.addiu(11, 0, -1), SYNC)
    a.label('fault_store')
    a.e(b.sw(11, STATE, 8), SYNC, b.move(2, 0), b.move(3, 0),
        b.r_type(31, 0, 0, 8), 0)

    code = a.finish()
    end = code_base + len(code)
    if end > 0x100000000 or code_base >> 28 != (end - 1) >> 28:
        raise ValueError('dispatch journal code must fit one MIPS jump region')
    if max(journal_address, code_base) < min(journal_address + size, end):
        raise ValueError('private journal and dispatch code overlap')
    return code, a.labels
