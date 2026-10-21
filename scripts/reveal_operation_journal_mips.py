#!/usr/bin/env python3
"""Emit an append-only diagnostic journal of exact borrowed dispatch events.

capture(a0=kind, a1=original BORROW ID, a2=original worker SP,
        a3=wrapper-owned [job, site, result, callee, panel, dest, view])
returns no status or authority. A zero borrow is ignored before metadata
access. Nonzero IDs require a published private BORROW with the exact job and
worker frame. BIND_BEGIN additionally checks original numeric panel/view.
No job, worker, panel, destination, view or callback pointer is dereferenced.
Only the owned scalar block, private BSS and this function's own frame are read.

The revision is a historical sample, not a mutation phase or currentness.
Duplicate, missing, reordered, skipped and failed callback events remain raw
evidence for a strict decoder; neither this core nor a native return publishes
ready rows, certifies success, retains objects, or authorizes a UI operation.
Allocation loss, invalid association or a faulted private counter permanently
faults this journal. There is no reset, reuse, pointer registry or native call.

Records are published with SYNC then magic last. Global journal/lineage/revision
faults override previously published history. Concurrent invalidation after
the final check is still possible; a coherent owned acquisition is a separate
obligation. Instruction tests do not prove CPU caches or native lifetimes.
O32 s-registers, SP, RA and HI/LO are preserved; volatile registers may change.
"""

from build_reveal_bridge_diag import Asm, b
import folderfollow_reveal_lineage_mips as lineage


HEADER, RECORD = 16, 64
STATE, FAULT = 0, 0xFFFFFFFF
MAGIC_OFFSET, MAGIC = 0, int.from_bytes(b'LOPR', 'little')
KIND, BORROW, SEQ, ORIGIN, JOB, STACK = 4, 8, 12, 16, 20, 24
SITE, RESULT, CALLEE, PANEL, DEST, VIEW, REVISION = 28, 32, 36, 40, 44, 48, 52
RESERVED = (56, 60)
FILL_BEGIN, FILL_RETURN, POST_TARGET, BIND_BEGIN, BIND_RETURN, NORMAL_END, ERROR_END = range(1, 8)
DEFAULT_CAPACITY, RETRIES = 1024, 8
MAX_CAPACITY = (0x100000000 - HEADER) // RECORD
CALL_FRAME, REVISION_BYTES, SYNC = 0x60, 16, 0x0000000F


def memory_bytes(capacity=DEFAULT_CAPACITY):
    if type(capacity) is not int or not 1 <= capacity <= MAX_CAPACITY:
        raise ValueError('capacity must fit a nonempty unsigned-32 journal')
    return HEADER + RECORD * capacity


def assemble(lineage_address, lineage_entries, journal_address, revision_address,
             code_base, capacity=DEFAULT_CAPACITY):
    """Return (code bytes, absolute labels), without I/O or installation.

    Public labels: capture, reserve, invalidate. The caller additionally owns
    the complete disjoint lineage allocation; only its header size is known
    here. Supplied validate must be the private lineage validator, not native.
    """
    size = memory_bytes(capacity)
    try:
        validate = lineage_entries['validate']
    except (KeyError, TypeError) as error:
        raise ValueError('private lineage validate entry is required') from error
    for name, value in (('lineage_address', lineage_address), ('journal_address', journal_address),
                        ('revision_address', revision_address), ('code_base', code_base),
                        ('validate', validate)):
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFC or value % 4:
            raise ValueError(name + ' must be an aligned unsigned-32 address')
    regions = ((lineage_address, lineage.HEADER), (journal_address, size),
               (revision_address, REVISION_BYTES))
    for index, (start, length) in enumerate(regions):
        if start + length > 0x100000000:
            raise ValueError('private region must not wrap the address space')
        for other, count in regions[index + 1:]:
            if max(start, other) < min(start + length, other + count):
                raise ValueError('private journal/header/revision regions overlap')

    a = Asm(code_base)

    def journal_check():
        a.absolute(8, journal_address)
        a.absolute(9, capacity)
        a.e(b.lw(10, STATE, 8), b.r_type(9, 10, 11, 0x2B))
        a.branch(5, 11, 0, 'capture_fault')

    def lineage_check():
        a.absolute(8, lineage_address)
        a.e(b.lw(8, lineage.STATE, 8),
            (8 << 16) | (8 << 11) | (31 << 6) | 2)
        a.branch(5, 8, 0, 'capture_fault')

    def revision_check(sample=False):
        a.absolute(8, revision_address)
        a.e(SYNC, b.lw(9, 0, 8),
            (9 << 16) | (10 << 11) | (31 << 6) | 2)
        a.branch(5, 10, 0, 'capture_fault')
        if sample:
            a.e(b.sw(9, 0x3C, 29))
        a.e(SYNC)

    a.label('capture')
    a.e(b.addiu(29, 29, -CALL_FRAME), b.sw(31, 0x5C, 29))
    a.branch(4, 5, 0, 'capture_done')
    a.e(b.sw(4, 0x10, 29), b.sw(5, 0x14, 29), b.sw(6, 0x18, 29))
    a.branch(4, 4, 0, 'capture_fault')
    a.e(b.i_type(11, 4, 8, ERROR_END + 1))
    a.branch(4, 8, 0, 'capture_fault')
    a.branch(4, 7, 0, 'capture_fault')
    a.e(b.i_type(12, 7, 8, 3))
    a.branch(5, 8, 0, 'capture_fault')
    journal_check()
    lineage_check()
    # Copy the wrapper-owned scalar block once. Its raw addresses are values.
    for index in range(7):
        a.e(b.lw(8, index * 4, 7), b.sw(8, 0x20 + index * 4, 29))
    a.e(b.lw(4, 0x14, 29), b.addiu(5, 0, lineage.BORROW))
    a.jump(validate, True)
    a.branch(4, 2, 0, 'capture_fault')
    for field, local in ((lineage.STACK, 0x18), (lineage.JOB, 0x20)):
        a.e(b.lw(8, field, 2), b.lw(9, local, 29))
        a.branch(5, 8, 9, 'capture_fault')
    a.e(b.lw(8, 0x10, 29), b.addiu(9, 0, BIND_BEGIN))
    a.branch(5, 8, 9, 'capture_associated')
    for field, local in ((lineage.PANEL, 0x30), (lineage.VIEW, 0x38)):
        a.e(b.lw(8, field, 2), b.lw(9, local, 29))
        a.branch(5, 8, 9, 'capture_fault')
    a.label('capture_associated')
    a.e(b.lw(8, lineage.ORIGIN, 2), b.sw(8, 0x40, 29))
    revision_check(sample=True)
    lineage_check()
    a.jump('reserve', True)
    a.branch(4, 2, 0, 'capture_done')
    a.e(b.sw(2, 0x44, 29), b.sw(3, SEQ, 2))
    for local, field in (
            (0x10, KIND), (0x14, BORROW), (0x18, STACK), (0x20, JOB),
            (0x24, SITE), (0x28, RESULT), (0x2C, CALLEE), (0x30, PANEL),
            (0x34, DEST), (0x38, VIEW), (0x3C, REVISION), (0x40, ORIGIN)):
        a.e(b.lw(8, local, 29), b.sw(8, field, 2))
    a.label('capture_publish')
    a.e(SYNC)
    lineage_check()
    journal_check()
    revision_check()
    a.e(b.lw(2, 0x44, 29), SYNC)
    a.absolute(8, MAGIC)
    a.label('capture_magic_store')
    a.e(b.sw(8, MAGIC_OFFSET, 2), SYNC)
    a.jump('capture_done')
    a.label('capture_fault')
    a.jump('invalidate', True)
    a.label('capture_done')
    a.e(b.lw(31, 0x5C, 29), b.addiu(29, 29, CALL_FRAME), b.move(2, 0),
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
    if (end > 0x100000000 or code_base >> 28 != (end - 1) >> 28
            or code_base >> 28 != validate >> 28):
        raise ValueError('journal and private validator must share one MIPS jump region')
    for start, length in regions:
        if max(start, code_base) < min(start + length, end):
            raise ValueError('private storage and journal code overlap')
        if start <= validate < start + length:
            raise ValueError('private validate must not be data')
    if code_base <= validate < end:
        raise ValueError('private validate must be separate code')
    return code, a.labels
