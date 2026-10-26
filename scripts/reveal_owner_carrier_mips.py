#!/usr/bin/env python3
"""Offline explicit historical-generation carrier to checked paint publication.

publish(controller, owned36, captured_binding_sequence, captured_owner) returns
the checked44-byte publication nonce/zero in v0 and its raw index/status in v1.
The captured pair must come from the actual creation event, not a later search
by engine, name, node or the newest binding. This interface checks a presented
pair; it does not authenticate its capture or route any native producer.

Only the existing append-only binding table is shared. A pinned raw13C bracket
protects all its accesses; the actual composed checked/pinned publish entry
obtains the distinct148 bracket. No owner state is accessed directly, no owner
is opened implicitly and no failed operation is retried or rolled back.

Caller premises include retained/coherent owned input, private binding/owner
storage, controller/native list and initialized ordinary distinct mutexes;
stable routes, genuine creation-time carrier, common synchronization and safe
13C->148 ordering; resolved imports and sufficient separate writable stack
through every nested service. Checks do not establish these lifetimes, complete
native call coverage, scheduling, loader/cache behavior or safe native freeing.
Raw errors require full-instance external quarantine. This local table's flag
does not gate direct clients of the old44-byte API. No firmware/file/device CLI.
"""

from build_reveal_bridge_diag import Asm, b
import reveal_paint_retirement_mips as owner_core
import reveal_registry_owner_mips as bindings


MAX_TICKET = owner_core.MAX_TICKET
CONTROLLER_BYTES, MUTEX_BYTES, PAYLOAD_BYTES = 0x28C, 24, 36
RAW_LOCK, RAW_UNLOCK, SYNC = 0xA5B960, 0xA5B830, 0xF
FRAME, COPY, RESULT, RAW, HI, LO = 160, 0x10, 0x3C, 0x40, 0x44, 0x48
PREV_RECEIPT, SELECTED = 0x70, 0x74
SAVE = {16: 0x4C, 17: 0x50, 18: 0x54, 19: 0x58, 20: 0x5C,
        21: 0x60, 22: 0x64, 23: 0x68, 31: 0x6C}


def assemble(binding_address, owner_address, controller_address,
             registry_mutex_address, paint_mutex_address, code_base,
             publish_entry, *, capacity=16, owner_capacity=16,
             ticket_limit=MAX_TICKET, protected_prefix=None,
             receipt_extent=None):
    """Emit a standalone adapter; no new state is allocated or initialized.

    The composer must verify the actual checked/pinned publish entry, not merely
    its scalar address. Optional protected_prefix=(start, bytes) pins the whole
    preceding composed kernel/callback RX extent for input/frame exclusion.
    Omitting it retains the full preceding-code nonaliasing caller premise.
    Optional receipt_extent=(start, bytes) excludes the full existing receipt
    journal from the independently owned source/frame. Without it that journal
    separation remains a caller premise, as does general native heap lifetime.
    Neither existing append-only table may be reset while any carrier survives.
    """
    binding_bytes = bindings.memory_bytes(capacity)
    owner_bytes = owner_core.memory_bytes(owner_capacity)
    if type(ticket_limit) is not int or not 1 <= ticket_limit <= MAX_TICKET:
        raise ValueError('ticket limit must be a positive signed word')
    extents = [('bindings', binding_address, binding_bytes),
               ('owner state', owner_address, owner_bytes),
               ('controller', controller_address, CONTROLLER_BYTES),
               ('registry mutex', registry_mutex_address, MUTEX_BYTES),
               ('paint mutex', paint_mutex_address, MUTEX_BYTES)]
    if receipt_extent is not None:
        if (type(receipt_extent) is not tuple or len(receipt_extent) != 2
                or any(type(value) is not int for value in receipt_extent)):
            raise ValueError('receipt extent must be an (address, bytes) tuple')
        receipt_start, receipt_bytes = receipt_extent
        if (receipt_start <= 0 or receipt_start % 4 or receipt_bytes <= 0
                or receipt_bytes % 4
                or receipt_start + receipt_bytes > 0x100000000):
            raise ValueError('receipt extent must be aligned, positive and nonwrapping')
        extents.append(('receipt', receipt_start, receipt_bytes))
    for name, address, size in (*extents, ('code', code_base, 4),
                                ('publish entry', publish_entry, 4)):
        if (type(address) is not int or not 0 < address <= 0xFFFFFFFC
                or address % 4 or address + size > 0x100000000):
            raise ValueError(name + ' must have a nonwrapping aligned extent')
    if code_base >> 28 or publish_entry >> 28:
        raise ValueError('adapter and publish entry must share the native jump region')
    for index, (name, address, size) in enumerate(extents):
        if max(address, bindings.NATIVE_RX[0]) < min(address + size, bindings.NATIVE_RX[1]):
            raise ValueError(name + ' overlaps pinned native RX')
        for other_name, other, other_size in extents[index + 1:]:
            if max(address, other) < min(address + size, other + other_size):
                raise ValueError(name + ' overlaps ' + other_name)
        if max(address, publish_entry) < min(address + size, publish_entry + 4):
            raise ValueError('publish entry overlaps ' + name)
    if bindings.NATIVE_RX[0] <= publish_entry < bindings.NATIVE_RX[1]:
        raise ValueError('publish entry overlaps pinned native RX')
    prefix_extent = None
    if protected_prefix is not None:
        if (type(protected_prefix) is not tuple or len(protected_prefix) != 2
                or any(type(value) is not int for value in protected_prefix)):
            raise ValueError('protected prefix must be an (RX start, bytes) tuple')
        prefix_start, prefix_bytes = protected_prefix
        prefix_end = prefix_start + prefix_bytes
        if (prefix_start <= 0 or prefix_start % 4 or prefix_bytes <= 0
                or prefix_bytes % 4 or prefix_end > 0x10000000
                or prefix_end > code_base
                or not prefix_start <= publish_entry
                or publish_entry + 4 > prefix_end):
            raise ValueError('protected prefix must contain publish and precede adapter RX')
        if max(prefix_start, bindings.NATIVE_RX[0]) < min(prefix_end, bindings.NATIVE_RX[1]):
            raise ValueError('protected prefix overlaps pinned native RX')
        for name, address, size in extents:
            if max(prefix_start, address) < min(prefix_end, address + size):
                raise ValueError('protected prefix overlaps ' + name)
        prefix_extent = ('protected prefix', prefix_start, prefix_bytes)
    a = Asm(code_base)
    code_end_fixups = []

    def equal(register, value, failed):
        a.absolute(9, value)
        a.branch(5, register, 9, failed)

    def bounded(register, limit, failed):
        a.branch(4, register, 0, failed)
        a.absolute(9, limit)
        a.e(b.r_type(9, register, 8, 0x2B))
        a.branch(5, 8, 0, failed)

    def nonoverlap(first, last, start, end, failed, label):
        a.absolute(10, start)
        a.e(b.r_type(last, 10, 9, 0x2B))
        a.branch(5, 9, 0, label)
        if end is None:
            code_end_fixups.append(len(a.w))
            a.absolute(10, 0)
        else:
            a.absolute(10, end - 1)
        a.e(b.r_type(10, first, 9, 0x2B))
        a.branch(5, 9, 0, label)
        a.jump(failed)
        a.label(label)

    a.label('publish')
    equal(4, controller_address, 'early_denied')
    a.e(b.i_type(12, 29, 8, 7))
    a.branch(5, 8, 0, 'early_denied')
    a.e(b.i_type(11, 29, 8, FRAME))
    a.branch(5, 8, 0, 'early_denied')
    bounded(6, capacity, 'early_denied')
    bounded(7, ticket_limit, 'early_denied')
    a.branch(4, 5, 0, 'early_denied')
    a.e(b.i_type(12, 5, 8, 3))
    a.branch(5, 8, 0, 'early_denied')
    a.e(b.addiu(11, 29, -FRAME), b.addiu(12, 29, -1),
        b.addiu(13, 5, PAYLOAD_BYTES - 1), b.r_type(13, 5, 8, 0x2B))
    a.branch(5, 8, 0, 'early_denied')
    protected = [*extents, ('native RX', bindings.NATIVE_RX[0],
                            bindings.NATIVE_RX[1] - bindings.NATIVE_RX[0]),
                 ('publish entry', publish_entry, 4)]
    if prefix_extent is not None:
        protected.append(prefix_extent)
    protected.append(('adapter', code_base, None))
    for index, (_, address, size) in enumerate(protected):
        end = None if size is None else address + size
        nonoverlap(11, 12, address, end, 'early_denied', 'frame_extent_' + str(index))
        nonoverlap(5, 13, address, end, 'early_denied', 'input_extent_' + str(index))
    a.e(b.r_type(13, 11, 8, 0x2B))
    a.branch(5, 8, 0, 'input_frame_ok')
    a.e(b.r_type(12, 5, 8, 0x2B))
    a.branch(4, 8, 0, 'early_denied')
    a.label('input_frame_ok')
    for offset, expected in ((0x13C, registry_mutex_address),
                             (0x274, bindings.REGISTRY_LOCK),
                             (0x278, bindings.REGISTRY_UNLOCK),
                             (0x148, paint_mutex_address),
                             (0x284, bindings.PAINT_LOCK),
                             (0x288, bindings.PAINT_UNLOCK)):
        a.e(b.lw(8, offset, 4))
        equal(8, expected, 'early_denied')
    a.e(b.addiu(29, 29, -FRAME))
    for register, offset in SAVE.items():
        a.e(b.sw(register, offset, 29))
    a.e(b.r_type(0, 0, 8, 0x10), b.sw(8, HI, 29),
        b.r_type(0, 0, 8, 0x12), b.sw(8, LO, 29),
        b.move(17, 4), b.move(22, 6), b.move(23, 7),
        b.sw(0, RESULT, 29), b.sw(0, RAW, 29),
        b.sw(0, PREV_RECEIPT, 29), b.sw(0, SELECTED, 29))
    # The source is an independently retained/coherent owned block. Copy it
    # before a raw service can clobber registers or mutate any caller input.
    for offset in range(0, PAYLOAD_BYTES, 4):
        a.e(b.lw(8, offset, 5), b.sw(8, COPY + offset, 29))
    a.absolute(16, binding_address)
    a.absolute(4, registry_mutex_address)
    a.jump(RAW_LOCK, link=True)
    a.e(b.sw(2, RAW, 29))
    a.branch(5, 2, 0, 'restore')
    a.e(SYNC, b.lw(8, bindings.QUARANTINE, 16))
    a.branch(5, 8, 0, 'quarantined')
    for offset in (bindings.STATUS, bindings.RESERVED):
        a.e(b.lw(8, offset, 16))
        a.branch(5, 8, 0, 'schema_fault')
    a.e(b.lw(20, bindings.COUNT, 16))
    a.absolute(9, capacity)
    a.e(b.r_type(9, 20, 8, 0x2B))
    a.branch(5, 8, 0, 'schema_fault')
    a.e(b.addiu(19, 16, bindings.HEADER_BYTES), b.move(18, 0), b.move(21, 0))
    a.label('rows')
    a.branch(4, 18, 20, 'rows_done')
    a.e(b.lw(8, bindings.MAGIC, 19))
    equal(8, bindings.RECORD_MAGIC, 'schema_fault')
    a.e(b.addiu(18, 18, 1), b.lw(8, bindings.SEQUENCE, 19))
    a.branch(5, 8, 18, 'schema_fault')
    a.e(b.lw(14, bindings.OWNER, 19))
    bounded(14, ticket_limit, 'schema_fault')
    a.e(b.r_type(21, 14, 8, 0x2B))
    a.branch(4, 8, 0, 'schema_fault')
    a.e(b.move(21, 14))
    for offset, expected in ((bindings.CONTROLLER, controller_address),
                             (bindings.REGISTRY_MUTEX, registry_mutex_address),
                             (bindings.SITE, bindings.PUBLICATION_SITE),
                             (bindings.RAW_STATUS, 0)):
        a.e(b.lw(8, offset, 19))
        equal(8, expected, 'schema_fault')
    a.e(b.lw(14, bindings.RECEIPT_SEQUENCE, 19))
    bounded(14, 1024, 'schema_fault')
    a.e(b.lw(15, PREV_RECEIPT, 29), b.r_type(15, 14, 8, 0x2B))
    a.branch(4, 8, 0, 'schema_fault')
    a.e(b.sw(14, PREV_RECEIPT, 29))
    a.branch(5, 18, 22, 'row_not_selected')
    a.e(b.sw(19, SELECTED, 29))
    a.label('row_not_selected')
    a.e(b.addiu(19, 19, bindings.RECORD_BYTES))
    a.jump('rows')
    a.label('rows_done')
    # An occupied next slot exposes a rolled-back count or interrupted tail.
    # A genuinely full immutable table needs no free slot to publish an
    # existing captured owner, and must never read beyond its final row.
    a.absolute(9, capacity)
    a.branch(4, 20, 9, 'next_slot_done')
    for offset in range(0, bindings.RECORD_BYTES, 4):
        a.e(b.lw(8, offset, 19))
        a.branch(5, 8, 0, 'schema_fault')
    a.label('next_slot_done')
    a.e(b.lw(19, SELECTED, 29))
    a.branch(4, 19, 0, 'unlock')
    a.e(b.lw(8, bindings.OWNER, 19))
    a.branch(5, 8, 23, 'unlock')
    a.e(b.lw(8, bindings.ENGINE, 19), b.lw(9, COPY + 8, 29))
    a.branch(5, 8, 9, 'unlock')
    a.e(b.move(4, 17), b.addiu(5, 29, COPY), b.move(6, 23))
    a.absolute(25, publish_entry)
    a.e(b.r_type(25, 0, 31, 9), 0, b.sw(2, RESULT, 29), b.sw(3, RAW, 29))
    a.branch(5, 2, 0, 'unlock')
    a.branch(4, 3, 0, 'unlock')
    # A failed checked publication with nonzero status is ambiguous: raw lock,
    # raw unlock or append failure can overlap numerically. Quarantine while
    # the distinct outer13C guard remains held; never touch owner storage.
    a.e(b.sw(3, bindings.STATUS, 16), SYNC, b.addiu(8, 0, 1),
        b.sw(8, bindings.QUARANTINE, 16), SYNC)
    a.jump('unlock')
    a.label('schema_fault')
    a.e(b.sw(0, bindings.STATUS, 16), SYNC, b.addiu(8, 0, 1),
        b.sw(8, bindings.QUARANTINE, 16), SYNC)
    a.jump('unlock')
    a.label('quarantined')
    a.e(b.lw(8, bindings.STATUS, 16), b.sw(8, RAW, 29))
    a.label('unlock')
    a.e(SYNC)
    a.absolute(4, registry_mutex_address)
    a.jump(RAW_UNLOCK, link=True)
    a.branch(4, 2, 0, 'restore')
    # The service may already have released13C. From here all data accesses
    # are to our retained frame, not a post-unlock shared quarantine latch.
    a.e(b.sw(0, RESULT, 29), b.sw(2, RAW, 29))
    a.label('restore')
    a.e(b.lw(8, HI, 29), b.r_type(8, 0, 0, 0x11),
        b.lw(8, LO, 29), b.r_type(8, 0, 0, 0x13),
        b.lw(2, RESULT, 29), b.lw(3, RAW, 29))
    for register, offset in SAVE.items():
        a.e(b.lw(register, offset, 29))
    a.e(b.addiu(29, 29, FRAME), b.r_type(31, 0, 0, 8), 0)
    a.label('early_denied')
    a.e(b.move(2, 0), b.move(3, 0), b.r_type(31, 0, 0, 8), 0)

    code_end = code_base + len(a.w) * 4
    if code_end > 0x10000000:
        raise ValueError('adapter leaves its native MIPS jump region')
    if max(code_base, bindings.NATIVE_RX[0]) < min(code_end, bindings.NATIVE_RX[1]):
        raise ValueError('adapter overlaps pinned native RX')
    for name, address, size in extents:
        if max(code_base, address) < min(code_end, address + size):
            raise ValueError('adapter overlaps ' + name)
    if code_base <= publish_entry < code_end:
        raise ValueError('adapter overlaps publish entry')
    for index in code_end_fixups:
        a.w[index] = b.lui(10, (code_end - 1) >> 16)
        a.w[index + 1] = b.ori(10, 10, (code_end - 1) & 0xFFFF)
    return a.finish(), a.labels
