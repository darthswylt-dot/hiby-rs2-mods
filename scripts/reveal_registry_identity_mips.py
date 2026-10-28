#!/usr/bin/env python3
"""Offline checked-R historical/current registry observations, NOT withdrawal.

audit_identity(U, exclusive CINT48, owned zero64) consumes that owned intent
before acquiring R.  It validates the exact historical binding and walks the
entire bounded native registry ring before exporting RIAU64 after checked R
release.  MATCHING_FIELDS reports equal scalar fields, NOT a continuously
retained allocation, native incarnation, lease, or permission to unlink/free.
Native deletion and allocator reuse can make an old capture match a new node.

No native/shared data is written.  The only input write changes the exclusively
owned CINT magic to CCNS; cloned records are not globally deduplicated.  There
is no M/P acquisition, name/object lookup, queue method, callback, native free,
retry, fault latch, installation or device I/O.  Raw R errors return immediately
without another service or native/shared/input/output access.  Current ring,
controller and mutex storage, imports, coherent R synchronization, owned buffers
and independent transitive stacks remain caller premises. Historical pointer
fields are scalars, not a requirement or proof that those old allocations live.
"""

from build_reveal_bridge_diag import Asm, b
import reveal_deferred_envelope_mips as envelope
import reveal_registry_owner_mips as bindings
import reveal_registry_receipt_mips as receipt
import reveal_paint_retirement_mips as owners
import reveal_retained_operations_mips as retained


MAX_TICKET = owners.MAX_TICKET
INTENT_BYTES, OUTPUT_BYTES, NODE_BYTES = 48, 64, 28
QUEUE_BYTES, MUTEX_BYTES, ANCHOR = 56, 24, 0x34
OUTPUT_MAGIC = int.from_bytes(b'RIAU', 'little')
CONSUMED_MAGIC = int.from_bytes(b'CCNS', 'little')
MATCHING_FIELDS, NODE_ABSENT, ENGINE_MISMATCH = 1, 2, 3
RAW_LOCK, RAW_UNLOCK, SYNC = 0xA5B960, 0xA5B830, 0xF
FRAME, COPY = 256, 0x10
HISTORICAL_NODE, OBSERVED_ENGINE, SCANNED_COUNT, KIND = 0x40, 0x44, 0x48, 0x4C
RESULT, RAW, OUTPUT, SOURCE = 0x50, 0x54, 0x58, 0x5C
PREV_RECEIPT, SELECTED, FOUND, NEXT = 0x60, 0x64, 0x68, 0x6C
HI, LO = 0x70, 0x74
SAVE = {register: 0x78 + index * 4
        for index, register in enumerate((*range(16, 24), 28, 30, 31))}


def assemble(receipt_address, binding_address, owner_address, controller_address,
             registry_mutex_address, paint_mutex_address, code_base,
             queue_address, transport_mutex_address, fault_address,
             ledger_address, retained_queue_address, retained_mutex_address,
             cleanup_intent_address, *, capacity=16, owner_capacity=16,
             ticket_limit=MAX_TICKET, operation_capacity=16, max_nodes=64,
             protected_code=None):
    """Emit an explicit read-only audit, with no allocation or activation.

    RIAU64 contains magic0, observation kind4, exact GCAP32 at8, opaque resource,
    callback and callback-context at40/44/48, historical node52, observed engine56
    (zero if absent), and full walk count60.  A returned output pointer/zero
    means only that this diagnostic was exported.  An ordinary refusal is0/0;
    a raw R error is0/exact_status.  No record is exported on a malformed ring,
    incomplete walk, mismatched historical binding, dirty output, or raw error.

    protected_code=(start,bytes) must contain this entire fragment.  None knows
    only this fragment.  Both modes emit equal word counts for composition.
    Bounds/exclusions precede source/output reads and frame saves, but establish
    neither mapping nor native allocation lifetime.  Historical node/engine
    identities are not authenticated, revived or retagged by current lookup.
    """
    extents = [('receipt', receipt_address, receipt.memory_bytes(capacity)),
               ('bindings', binding_address, bindings.memory_bytes(capacity)),
               ('owners', owner_address, owners.memory_bytes(owner_capacity)),
               ('controller', controller_address, receipt.CONTROLLER_BYTES),
               ('registry mutex', registry_mutex_address, MUTEX_BYTES),
               ('paint mutex', paint_mutex_address, MUTEX_BYTES),
               ('old queue', queue_address, QUEUE_BYTES),
               ('old transport mutex', transport_mutex_address, MUTEX_BYTES),
               ('old fault', fault_address, 4),
               ('ledger', ledger_address, retained.memory_bytes(operation_capacity)),
               ('retained queue', retained_queue_address, QUEUE_BYTES),
               ('retained mutex', retained_mutex_address, MUTEX_BYTES),
               ('cleanup intent', cleanup_intent_address, 4)]
    if type(ticket_limit) is not int or not 1 <= ticket_limit <= MAX_TICKET:
        raise ValueError('ticket limit must be a positive signed word')
    if type(max_nodes) is not int or not 1 <= max_nodes <= 1024:
        raise ValueError('max nodes must be an integer in1..1024')
    for name, address, size in (*extents, ('code', code_base, 4)):
        if (type(address) is not int or not 0 < address <= 0xFFFFFFFC
                or address % 4 or address + size > 0x100000000):
            raise ValueError(name + ' must have a nonwrapping aligned extent')
    if code_base >> 28:
        raise ValueError('identity fragment must share the native jump region')
    for index, (name, address, size) in enumerate(extents):
        if max(address, receipt.NATIVE_RX[0]) < min(address + size, receipt.NATIVE_RX[1]):
            raise ValueError(name + ' overlaps pinned native RX')
        for other_name, other, other_size in extents[index + 1:]:
            if max(address, other) < min(address + size, other + other_size):
                raise ValueError(name + ' overlaps ' + other_name)

    protected_start, protected_end = code_base, None
    if protected_code is not None:
        if (type(protected_code) is not tuple or len(protected_code) != 2
                or any(type(value) is not int for value in protected_code)):
            raise ValueError('protected code must be an (RX start, bytes) tuple')
        protected_start, protected_bytes = protected_code
        protected_end = protected_start + protected_bytes
        if (protected_start <= 0 or protected_start % 4 or protected_bytes <= 0
                or protected_bytes % 4 or protected_end > 0x10000000
                or not protected_start <= code_base < protected_end):
            raise ValueError('protected code must contain this fragment')
        if max(protected_start, receipt.NATIVE_RX[0]) < min(protected_end, receipt.NATIVE_RX[1]):
            raise ValueError('protected code overlaps pinned native RX')
        for name, address, size in extents:
            if max(protected_start, address) < min(protected_end, address + size):
                raise ValueError('protected code overlaps ' + name)

    a = Asm(code_base)
    end_fixups = []
    protected = [*extents,
                 ('native RX', receipt.NATIVE_RX[0], receipt.NATIVE_RX[1] - receipt.NATIVE_RX[0]),
                 ('generated RX', protected_start,
                  None if protected_end is None else protected_end - protected_start)]

    def equal(register, value, failed):
        a.absolute(9, value)
        a.branch(5, register, 9, failed)

    def bounded(register, limit, failed):
        a.branch(4, register, 0, failed)
        a.absolute(9, limit)
        a.e(b.r_type(9, register, 8, 0x2B))
        a.branch(5, 8, 0, failed)

    def extent(pointer, last, size, failed):
        a.branch(4, pointer, 0, failed)
        a.e(b.i_type(12, pointer, 8, 3))
        a.branch(5, 8, 0, failed)
        a.e(b.addiu(last, pointer, size - 1), b.r_type(last, pointer, 8, 0x2B))
        a.branch(5, 8, 0, failed)

    def nonoverlap(first, last, start, end, failed, label):
        a.absolute(10, start)
        a.e(b.r_type(last, 10, 9, 0x2B))
        a.branch(5, 9, 0, label)
        if end is None:
            end_fixups.append(len(a.w))
            a.absolute(10, 0)
        else:
            a.absolute(10, end - 1)
        a.e(b.r_type(10, first, 9, 0x2B))
        a.branch(5, 9, 0, label)
        a.jump(failed)
        a.label(label)

    def exclusions(first, last, failed, prefix):
        for index, (_, address, size) in enumerate(protected):
            nonoverlap(first, last, address, None if size is None else address + size,
                       failed, prefix + '_extent_' + str(index))

    def disjoint(first, last, other_first, other_last, failed, label):
        a.e(b.r_type(last, other_first, 8, 0x2B))
        a.branch(5, 8, 0, label)
        a.e(b.r_type(other_last, first, 8, 0x2B))
        a.branch(4, 8, 0, failed)
        a.label(label)

    def node_guards(pointer, prefix):
        extent(pointer, 13, NODE_BYTES, 'ring_denied')
        exclusions(pointer, 13, 'ring_denied', prefix)
        a.e(b.lw(11, SOURCE, 29), b.addiu(12, 11, INTENT_BYTES - 1))
        disjoint(pointer, 13, 11, 12, 'ring_denied', prefix + '_source_ok')
        a.e(b.lw(11, OUTPUT, 29), b.addiu(12, 11, OUTPUT_BYTES - 1))
        disjoint(pointer, 13, 11, 12, 'ring_denied', prefix + '_output_ok')
        a.e(b.addiu(12, 29, FRAME - 1))
        disjoint(pointer, 13, 29, 12, 'ring_denied', prefix + '_frame_ok')

    a.label('audit_identity')
    equal(4, controller_address, 'early_denied')
    a.e(b.i_type(12, 29, 8, 7))
    a.branch(5, 8, 0, 'early_denied')
    a.e(b.i_type(11, 29, 8, FRAME))
    a.branch(5, 8, 0, 'early_denied')
    extent(5, 13, INTENT_BYTES, 'early_denied')
    extent(6, 14, OUTPUT_BYTES, 'early_denied')
    a.e(b.addiu(11, 29, -FRAME), b.addiu(12, 29, -1))
    exclusions(11, 12, 'early_denied', 'frame')
    exclusions(5, 13, 'early_denied', 'source')
    exclusions(6, 14, 'early_denied', 'output')
    disjoint(5, 13, 6, 14, 'early_denied', 'source_output_ok')
    disjoint(5, 13, 11, 12, 'early_denied', 'source_frame_ok')
    disjoint(6, 14, 11, 12, 'early_denied', 'output_frame_ok')
    a.label('output_initial_check')
    for offset in range(0, OUTPUT_BYTES, 4):
        a.e(b.lw(8, offset, 6))
        a.branch(5, 8, 0, 'early_denied')
    a.label('save_frame')
    a.e(b.addiu(29, 29, -FRAME))
    for register, offset in SAVE.items():
        a.e(b.sw(register, offset, 29))
    a.e(b.r_type(0, 0, 8, 0x10), b.sw(8, HI, 29),
        b.r_type(0, 0, 8, 0x12), b.sw(8, LO, 29),
        b.sw(5, SOURCE, 29), b.sw(6, OUTPUT, 29),
        b.sw(0, RESULT, 29), b.sw(0, RAW, 29),
        b.sw(0, KIND, 29), b.sw(0, SELECTED, 29),
        b.sw(0, PREV_RECEIPT, 29), b.sw(0, HISTORICAL_NODE, 29),
        b.sw(0, OBSERVED_ENGINE, 29), b.sw(0, SCANNED_COUNT, 29))
    for offset in range(0, INTENT_BYTES, 4):
        a.e(b.lw(8, offset, 5), b.sw(8, COPY + offset, 29))
    a.label('snapshot_done')
    for offset, expected in ((0, retained.CLEANUP_INTENT_MAGIC),
                             (4 + envelope.MAGIC, envelope.READY_MAGIC),
                             (4 + envelope.FLAGS, envelope.REGISTRY_RELEASE_OBSERVED),
                             (4 + envelope.CONTROLLER, controller_address),
                             (4 + envelope.NATIVE_RESULT, 0)):
        a.e(b.lw(8, COPY + offset, 29))
        equal(8, expected, 'restore')
    for offset, limit in ((envelope.BINDING_SEQUENCE, capacity),
                          (envelope.OWNER, ticket_limit),
                          (envelope.RECEIPT_SEQUENCE, capacity)):
        a.e(b.lw(8, COPY + 4 + offset, 29))
        bounded(8, limit, 'restore')
    a.e(b.lw(8, COPY + 4 + envelope.ENGINE, 29))
    a.branch(4, 8, 0, 'restore')
    a.label('consume_intent')
    a.e(b.lw(10, SOURCE, 29))
    a.absolute(8, CONSUMED_MAGIC)
    a.e(b.sw(8, 0, 10), SYNC)
    a.absolute(16, binding_address)
    a.absolute(17, controller_address)
    a.e(b.lw(22, COPY + 4 + envelope.BINDING_SEQUENCE, 29),
        b.lw(23, COPY + 4 + envelope.OWNER, 29))
    a.label('raw_acquire')
    a.absolute(4, registry_mutex_address)
    a.jump(RAW_LOCK, link=True)
    a.label('raw_acquire_return')
    a.e(b.sw(2, RAW, 29))
    a.branch(5, 2, 0, 'restore')
    a.e(SYNC)
    a.label('binding_begin')
    for offset, expected in ((0x13C, registry_mutex_address),
                             (0x274, bindings.REGISTRY_LOCK),
                             (0x278, bindings.REGISTRY_UNLOCK)):
        a.e(b.lw(8, offset, 17))
        equal(8, expected, 'ring_denied')
    for offset in (bindings.QUARANTINE, bindings.STATUS, bindings.RESERVED):
        a.e(b.lw(8, offset, 16))
        a.branch(5, 8, 0, 'ring_denied')
    a.e(b.lw(20, bindings.COUNT, 16))
    a.absolute(9, capacity)
    a.e(b.r_type(9, 20, 8, 0x2B))
    a.branch(5, 8, 0, 'ring_denied')
    a.e(b.addiu(19, 16, bindings.HEADER_BYTES), b.move(18, 0), b.move(21, 0))
    a.label('rows')
    a.branch(4, 18, 20, 'rows_done')
    a.e(b.lw(8, bindings.MAGIC, 19))
    equal(8, bindings.RECORD_MAGIC, 'ring_denied')
    a.e(b.addiu(18, 18, 1), b.lw(8, bindings.SEQUENCE, 19))
    a.branch(5, 8, 18, 'ring_denied')
    a.e(b.lw(14, bindings.OWNER, 19))
    bounded(14, ticket_limit, 'ring_denied')
    a.e(b.r_type(21, 14, 8, 0x2B))
    a.branch(4, 8, 0, 'ring_denied')
    a.e(b.move(21, 14))
    for offset, expected in ((bindings.CONTROLLER, controller_address),
                             (bindings.REGISTRY_MUTEX, registry_mutex_address),
                             (bindings.SITE, bindings.PUBLICATION_SITE),
                             (bindings.RAW_STATUS, 0)):
        a.e(b.lw(8, offset, 19))
        equal(8, expected, 'ring_denied')
    a.e(b.lw(14, bindings.RECEIPT_SEQUENCE, 19))
    bounded(14, capacity, 'ring_denied')
    a.e(b.lw(15, PREV_RECEIPT, 29), b.r_type(15, 14, 8, 0x2B))
    a.branch(4, 8, 0, 'ring_denied')
    a.e(b.sw(14, PREV_RECEIPT, 29))
    a.branch(5, 18, 22, 'row_not_selected')
    a.e(b.sw(19, SELECTED, 29))
    a.label('row_not_selected')
    a.e(b.addiu(19, 19, bindings.RECORD_BYTES))
    a.jump('rows')
    a.label('rows_done')
    a.absolute(9, capacity)
    a.branch(4, 20, 9, 'next_slot_done')
    for offset in range(0, bindings.RECORD_BYTES, 4):
        a.e(b.lw(8, offset, 19))
        a.branch(5, 8, 0, 'ring_denied')
    a.label('next_slot_done')
    a.e(b.lw(19, SELECTED, 29))
    a.branch(4, 19, 0, 'ring_denied')
    a.label('selected_binding')
    a.e(b.lw(8, bindings.OWNER, 19))
    a.branch(5, 8, 23, 'ring_denied')
    for offset, capture_offset in ((bindings.ENGINE, envelope.ENGINE),
                                   (bindings.RECEIPT_SEQUENCE, envelope.RECEIPT_SEQUENCE)):
        a.e(b.lw(8, offset, 19), b.lw(9, COPY + 4 + capture_offset, 29))
        a.branch(5, 8, 9, 'ring_denied')
    a.e(b.lw(19, bindings.NODE, 19), b.sw(19, HISTORICAL_NODE, 29))
    a.label('historical_node_guard')
    node_guards(19, 'historical_node')
    # Historical NODE is never dereferenced.  Only a guarded node reached from
    # the actual live ring may supply the observed engine scalar.
    a.label('ring_begin')
    a.absolute(16, controller_address + ANCHOR)
    a.e(b.lw(17, 0, 16), b.lw(23, 4, 16), b.move(18, 16),
        b.move(20, 0), b.move(21, 0), b.move(22, 0))
    a.label('node_next')
    a.branch(4, 17, 16, 'ring_done')
    a.absolute(9, max_nodes)
    a.branch(4, 20, 9, 'ring_denied')
    a.label('node_guard')
    node_guards(17, 'live_node')
    a.label('node_read')
    a.e(b.lw(8, 4, 17))
    a.branch(5, 8, 18, 'ring_denied')
    a.e(b.lw(8, 0, 17), b.sw(8, NEXT, 29))
    a.branch(5, 17, 19, 'node_not_selected')
    a.e(b.lw(21, 8, 17), b.addiu(22, 0, 1))
    a.label('node_not_selected')
    a.e(b.addiu(20, 20, 1), b.move(18, 17), b.lw(17, NEXT, 29))
    a.jump('node_next')
    a.label('ring_done')
    a.branch(5, 23, 18, 'ring_denied')
    a.e(b.lw(8, 4, 16))
    a.branch(5, 8, 18, 'ring_denied')
    a.e(b.sw(20, SCANNED_COUNT, 29), b.sw(21, OBSERVED_ENGINE, 29),
        b.addiu(8, 0, NODE_ABSENT), b.sw(8, KIND, 29))
    a.branch(4, 22, 0, 'raw_release')
    a.e(b.lw(9, COPY + 4 + envelope.ENGINE, 29), b.addiu(8, 0, ENGINE_MISMATCH))
    a.branch(5, 21, 9, 'kind_ready')
    a.e(b.addiu(8, 0, MATCHING_FIELDS))
    a.label('kind_ready')
    a.e(b.sw(8, KIND, 29))
    a.jump('raw_release')
    a.label('ring_denied')
    a.e(b.sw(0, KIND, 29))
    a.label('raw_release')
    a.e(SYNC)
    a.absolute(4, registry_mutex_address)
    a.jump(RAW_UNLOCK, link=True)
    a.label('raw_release_return')
    a.e(b.sw(2, RAW, 29))
    a.branch(5, 2, 0, 'restore')
    # No shared/native/source read occurs after confirmed or uncertain release.
    a.e(b.lw(8, KIND, 29))
    a.branch(4, 8, 0, 'restore')
    a.e(b.lw(10, OUTPUT, 29))
    a.label('output_recheck')
    for offset in range(0, OUTPUT_BYTES, 4):
        a.e(b.lw(8, offset, 10))
        a.branch(5, 8, 0, 'restore')
    a.label('export_body')
    a.e(b.lw(8, KIND, 29), b.sw(8, 4, 10))
    for offset in range(0, 32, 4):
        a.e(b.lw(8, COPY + 4 + offset, 29), b.sw(8, 8 + offset, 10))
    for offset in range(0, 12, 4):
        a.e(b.lw(8, COPY + 36 + offset, 29), b.sw(8, 40 + offset, 10))
    for source_offset, output_offset in ((HISTORICAL_NODE, 52),
                                         (OBSERVED_ENGINE, 56), (SCANNED_COUNT, 60)):
        a.e(b.lw(8, source_offset, 29), b.sw(8, output_offset, 10))
    a.label('export_commit')
    a.e(SYNC)
    a.absolute(8, OUTPUT_MAGIC)
    a.e(b.sw(8, 0, 10), SYNC, b.sw(10, RESULT, 29))
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
        raise ValueError('identity fragment leaves its native MIPS jump region')
    if protected_end is not None and code_end > protected_end:
        raise ValueError('protected code does not contain the complete identity fragment')
    if max(code_base, receipt.NATIVE_RX[0]) < min(code_end, receipt.NATIVE_RX[1]):
        raise ValueError('identity fragment overlaps pinned native RX')
    for name, address, size in extents:
        if max(code_base, address) < min(code_end, address + size):
            raise ValueError('identity fragment overlaps ' + name)
    for index in end_fixups:
        a.w[index] = b.lui(10, (code_end - 1) >> 16)
        a.w[index + 1] = b.ori(10, 10, (code_end - 1) & 0xFFFF)
    return a.finish(), a.labels
