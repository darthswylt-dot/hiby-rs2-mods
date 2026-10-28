#!/usr/bin/env python3
"""Offline retained-operation accounting, NOT a native object retain/free API.

One ledger binds once to an actual checked GCAP32 and three opaque retained
resource/callback/context scalars. Its separate FIFO contains token32+READY68.
An append-only token remains outstanding after FIFO extraction, across actual
publication, and until an exact claimed paint completion returns terminally.
Closing admission does not interrupt callbacks or retire the paint owner.

Only CLOSED, healthy, empty transport with every operation DONE may attempt
the actual checked owner retire/drained barrier. A positive answer is local
accounting evidence, never permission to free native controller/engine/resource
graphs. All cleanup/bypass routes and all paint completion callers must still
cooperate; the externally retained bundle and native service/list/stack storage
must remain alive. No existing native retain/release has been established.

M protects this ledger and FIFO72 only. It is released before R/P helpers. Raw
mutex errors return immediately without guessed unlock, retry, rollback, late
shared writes or further locks; the caller must isolate the WHOLE instance.
Ordinary paint complete(0,0) is ambiguous and conservatively leaves ACKING.
No stock hook, native object read, callback invocation, free, image or device I/O.
"""

from build_reveal_bridge_diag import Asm, b
import reveal_deferred_envelope_mips as envelope
import reveal_registry_owner_mips as bindings
import reveal_registry_receipt_mips as receipt
import reveal_paint_retirement_mips as owners


MAX_TICKET = owners.MAX_TICKET
HEADER_BYTES, OPERATION_BYTES = 64, 16
CAPTURE_BYTES, BUNDLE_BYTES, ENVELOPE_BYTES, PACKET_BYTES = 32, 44, 68, 72
CLEANUP_INTENT_BYTES = 48
CLEANUP_INTENT_MAGIC = int.from_bytes(b'CINT', 'little')
QUEUE_BYTES, MUTEX_BYTES = 56, 24
BIND_STATE, FAULT, OP_COUNT, CAPTURE = 0, 4, 8, 16
RESOURCE, CALLBACK, CALLBACK_CONTEXT = 48, 52, 56
UNBOUND, OPEN, CLOSED = 0, 1, 2
TOKEN, STATE, NONCE = 0, 4, 8
RESERVED, QUEUED, EXTRACTED, PUBLISHED, ACKING, DONE = range(1, 7)
HEADER_FAULT, LEDGER_FAULT, HEAD_FAULT = 1, 2, 3
APPEND_FAULT, REMOVE_FAULT, REBIND_FAULT = 4, 5, 6
RAW_LOCK, RAW_UNLOCK = 0xA5B960, 0xA5B830
APPEND, GET, REMOVE = 0x455DA0, 0x4557E0, 0x455860
FRAME, PRIVATE, PRIVATE_ENVELOPE = 256, 0x10, 0x14
RESULT, RAW, OLD_COUNT, PRIVATE_TOKEN = 0x60, 0x64, 0x68, 0x6C
PRIVATE_ROW, PRIVATE_NONCE, OUTCOME, MODE, PRIVATE_OWNER = 0x70, 0x74, 0x78, 0x7C, 0x80
PUBLISH_INDEX = 0xB8
CLEANUP_OUTPUT = 0xBC
HI, LO, SYNC = 0x84, 0x88, 0xF
SAVE = {register: 0x8C + index * 4
        for index, register in enumerate((*range(16, 24), 28, 30, 31))}


def memory_bytes(operation_capacity=16):
    """Zero-initialized retained ledger extent; there is no reset/reuse API."""
    if type(operation_capacity) is not int or not 1 <= operation_capacity <= 1024:
        raise ValueError('operation capacity must be an integer in1..1024')
    return HEADER_BYTES + OPERATION_BYTES * operation_capacity


def assemble(receipt_address, binding_address, owner_address, controller_address,
             registry_mutex_address, paint_mutex_address, code_base,
             queue_address, transport_mutex_address, fault_address,
             ledger_address, retained_queue_address, retained_mutex_address,
             pack_entry, dispatch_entry, complete_entry, retire_entry,
             drained_entry, *, capacity=16, owner_capacity=16,
             ticket_limit=MAX_TICKET, operation_capacity=16, retained_capacity=40,
             protected_code=None, cleanup_intent_address=None):
    """Return instructions/labels without allocating or activating anything.

    bind(U, owned44) returns1/0 once; owned44 is GCAP32 plus three opaque words,
    NOT the constructor's diagnostic output48. enqueue(U, READY68) returns a
    nonreused positive operation token/0. pop_dispatch(U) returns the actual
    publisher nonce/index after binding the nonce under M, or0/0 for ordinary
    refusal/cancel. complete(U, nonce, outcome0..1) accepts only an already
    PUBLISHED nonce and forwards the actual terminal complete result1..3/0
    after marking its operation DONE. A valid actual claim is a caller premise;
    a zero actual completion leaves ACKING and can permanently deny quiescence.

    close(U) irreversibly closes admission (repeated healthy close is1/0).
    quiescent(U) is positive only after CLOSED/allDONE/Qempty and actual checked
    retire then drained. Successful retire v1 is a removed count, not raw status;
    successful publication v1 is an index. All zero-v0/nonzero-v1 raw errors are
    forwarded without any later shared access or service call.

    Optional prepare_cleanup(U, owned_zero48) reserves a separate irreversible
    intent word only after healthy CLOSED/all-DONE/empty local accounting.
    It releases M before calling this fragment's actual quiescent barrier.
    Exact barrier(1,0) exports CINT48: magic, bound GCAP32, and three opaque
    resource/callback/context words, body first and magic last. Success is the
    output pointer/0; all ordinary refusals are0/0. Reservation remains consumed
    after a raw error, ambiguous barrier or dirty late output, with no retry.
    This snapshot is NOT native cleanup/free authority or a lifetime lease.
    No native object is read, called or destroyed; all storage and native bundle
    lifetime, cleanup/user coverage and future intent consumption remain external.

    All fixed extents, complete generated RX and this outer256-byte frame are
    excluded before source reads/saves. Mapping, coherent exclusive snapshots,
    nonaliasing native queue allocations, initialized ordinary nonrobust M,
    nested service stack, genuine capture and externally retained native bundle
    remain caller premises. protected_code must contain all five supplied
    entries and the complete fragment; None knows only their four-byte words.
    """
    ledger_bytes = memory_bytes(operation_capacity)
    extents = [('receipt', receipt_address, receipt.memory_bytes(capacity)),
               ('bindings', binding_address, bindings.memory_bytes(capacity)),
               ('owners', owner_address, owners.memory_bytes(owner_capacity)),
               ('controller', controller_address, receipt.CONTROLLER_BYTES),
               ('registry mutex', registry_mutex_address, MUTEX_BYTES),
               ('paint mutex', paint_mutex_address, MUTEX_BYTES),
               ('old queue', queue_address, QUEUE_BYTES),
               ('old transport mutex', transport_mutex_address, MUTEX_BYTES),
               ('old fault', fault_address, 4),
               ('ledger', ledger_address, ledger_bytes),
               ('retained queue', retained_queue_address, QUEUE_BYTES),
               ('retained mutex', retained_mutex_address, MUTEX_BYTES)]
    if cleanup_intent_address is not None:
        extents.append(('cleanup intent', cleanup_intent_address, 4))
    entries = [('pack entry', pack_entry, 4), ('dispatch entry', dispatch_entry, 4),
               ('complete entry', complete_entry, 4), ('retire entry', retire_entry, 4),
               ('drained entry', drained_entry, 4)]
    if type(ticket_limit) is not int or not 1 <= ticket_limit <= MAX_TICKET:
        raise ValueError('ticket limit must be a positive signed word')
    if (type(retained_capacity) is not int or not 10 <= retained_capacity <= 10240
            or retained_capacity % 10):
        raise ValueError('retained capacity must be a multiple of10 in10..10240')
    for name, address, size in (*extents, ('code', code_base, 4), *entries):
        if (type(address) is not int or not 0 < address <= 0xFFFFFFFC
                or address % 4 or address + size > 0x100000000):
            raise ValueError(name + ' must have a nonwrapping aligned extent')
    if code_base >> 28 or any(entry >> 28 for _, entry, _ in entries):
        raise ValueError('retained fragment and entries must share native jump region')
    if len({entry for _, entry, _ in entries}) != len(entries):
        raise ValueError('supplied entries overlap')
    for index, (name, address, size) in enumerate(extents):
        if max(address, receipt.NATIVE_RX[0]) < min(address + size, receipt.NATIVE_RX[1]):
            raise ValueError(name + ' overlaps pinned native RX')
        for other_name, other, other_size in extents[index + 1:]:
            if max(address, other) < min(address + size, other + other_size):
                raise ValueError(name + ' overlaps ' + other_name)
        for entry_name, entry, entry_size in entries:
            if max(address, entry) < min(address + size, entry + entry_size):
                raise ValueError(entry_name + ' overlaps ' + name)
    for name, entry, _ in entries:
        if receipt.NATIVE_RX[0] <= entry < receipt.NATIVE_RX[1]:
            raise ValueError(name + ' overlaps pinned native RX')

    protected_start, protected_end = code_base, None
    if protected_code is not None:
        if (type(protected_code) is not tuple or len(protected_code) != 2
                or any(type(value) is not int for value in protected_code)):
            raise ValueError('protected code must be an (RX start, bytes) tuple')
        protected_start, protected_bytes = protected_code
        protected_end = protected_start + protected_bytes
        if (protected_start <= 0 or protected_start % 4 or protected_bytes <= 0
                or protected_bytes % 4 or protected_end > 0x10000000
                or not protected_start <= code_base < protected_end
                or any(not protected_start <= entry or entry + 4 > protected_end
                       for _, entry, _ in entries)):
            raise ValueError('protected code must contain fragment and all supplied entries')
        if max(protected_start, receipt.NATIVE_RX[0]) < min(protected_end, receipt.NATIVE_RX[1]):
            raise ValueError('protected code overlaps pinned native RX')
        for name, address, size in extents:
            if max(protected_start, address) < min(protected_end, address + size):
                raise ValueError('protected code overlaps ' + name)

    a = Asm(code_base)
    end_fixups, fault_handlers = [], []
    protected = [*extents,
                 ('native RX', receipt.NATIVE_RX[0],
                  receipt.NATIVE_RX[1] - receipt.NATIVE_RX[0]),
                 *entries, ('generated RX', protected_start,
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

    def disjoint(first, last, other_first, other_last, failed, label):
        a.e(b.r_type(last, other_first, 8, 0x2B))
        a.branch(5, 8, 0, label)
        a.e(b.r_type(other_last, first, 8, 0x2B))
        a.branch(4, 8, 0, failed)
        a.label(label)

    def fixed_exclusions(first, last, failed, prefix):
        for index, (_, address, size) in enumerate(protected):
            nonoverlap(first, last, address, None if size is None else address + size,
                       failed, prefix + '_extent_' + str(index))

    def preflight(name, source_bytes=0, completion=False, initial_zero_bytes=0):
        a.label(name)
        equal(4, controller_address, 'early_denied')
        a.e(b.i_type(12, 29, 8, 7))
        a.branch(5, 8, 0, 'early_denied')
        a.e(b.i_type(11, 29, 8, FRAME))
        a.branch(5, 8, 0, 'early_denied')
        if completion:
            bounded(5, ticket_limit, 'early_denied')
            a.e(b.i_type(11, 6, 8, 2))
            a.branch(4, 8, 0, 'early_denied')
        a.e(b.addiu(11, 29, -FRAME), b.addiu(12, 29, -1))
        fixed_exclusions(11, 12, 'early_denied', name + '_frame')
        if source_bytes:
            extent(5, 13, source_bytes, 'early_denied')
            fixed_exclusions(5, 13, 'early_denied', name + '_source')
            disjoint(5, 13, 11, 12, 'early_denied', name + '_source_frame_ok')
        for offset in range(0, initial_zero_bytes, 4):
            a.e(b.lw(8, offset, 5))
            a.branch(5, 8, 0, 'early_denied')
        a.e(b.addiu(29, 29, -FRAME))
        for register, offset in SAVE.items():
            a.e(b.sw(register, offset, 29))
        a.e(b.r_type(0, 0, 8, 0x10), b.sw(8, HI, 29),
            b.r_type(0, 0, 8, 0x12), b.sw(8, LO, 29))
        for offset in range(PRIVATE, HI, 4):
            a.e(b.sw(0, offset, 29))
        if completion:
            a.e(b.sw(5, PRIVATE_NONCE, 29), b.sw(6, OUTCOME, 29))

    def capture_schema(base, offset, failed):
        for field, expected in ((envelope.MAGIC, envelope.READY_MAGIC),
                                (envelope.FLAGS, envelope.REGISTRY_RELEASE_OBSERVED),
                                (envelope.CONTROLLER, controller_address),
                                (envelope.NATIVE_RESULT, 0)):
            a.e(b.lw(8, offset + field, base))
            equal(8, expected, failed)
        for field, limit in ((envelope.BINDING_SEQUENCE, capacity),
                             (envelope.OWNER, ticket_limit),
                             (envelope.RECEIPT_SEQUENCE, capacity)):
            a.e(b.lw(14, offset + field, base))
            bounded(14, limit, failed)
        a.e(b.lw(8, offset + envelope.ENGINE, base))
        a.branch(4, 8, 0, failed)

    def capture_matches(failed):
        a.absolute(10, ledger_address)
        for offset in range(0, CAPTURE_BYTES, 4):
            a.e(b.lw(8, PRIVATE_ENVELOPE + offset, 29),
                b.lw(9, CAPTURE + offset, 10))
            a.branch(5, 8, 9, failed)

    def pack_private(source):
        a.absolute(4, controller_address)
        a.e(b.move(5, source), b.addiu(6, source, envelope.PAYLOAD),
            b.addiu(7, 29, PRIVATE_ENVELOPE))
        a.absolute(25, pack_entry)
        a.e(b.r_type(25, 0, 31, 9), 0)

    def call_entry(entry):
        a.absolute(25, entry)
        a.e(b.r_type(25, 0, 31, 9), 0)

    def acquire(name):
        a.label(name + '_before_lock')
        a.absolute(4, retained_mutex_address)
        a.jump(RAW_LOCK, link=True)
        a.label(name + '_after_lock')
        a.e(b.sw(2, RAW, 29))
        a.branch(4, 2, 0, name + '_lock_succeeded')
        a.e(b.sw(0, RESULT, 29))
        a.jump('restore')
        a.label(name + '_lock_succeeded')
        a.e(SYNC)
        a.jump('validate_locked', link=True)
        a.branch(4, 2, 0, name + '_before_release')

    def release(name, success=None):
        a.label(name + '_before_release')
        a.e(SYNC)
        a.absolute(4, retained_mutex_address)
        a.jump(RAW_UNLOCK, link=True)
        a.label(name + '_after_release')
        a.branch(4, 2, 0, name + '_release_succeeded')
        a.e(b.sw(0, RESULT, 29), b.sw(2, RAW, 29))
        a.jump('restore')
        a.label(name + '_release_succeeded')
        a.jump('restore' if success is None else success)

    def fault(name, value, release_name):
        label = name + '_fault'
        fault_handlers.append((label, value, release_name + '_before_release'))
        return label

    def row_from_token():
        a.e(b.lw(8, PRIVATE_TOKEN, 29), b.addiu(8, 8, -1))
        for _ in range(4):
            a.e(b.r_type(8, 8, 8, 0x21))
        a.absolute(10, ledger_address + HEADER_BYTES)
        a.e(b.r_type(10, 8, 10, 0x21), b.sw(10, PRIVATE_ROW, 29))

    # Binding captures all44 owned bytes before acquiring M. No caller source
    # access occurs after this snapshot, including after an uncertain release.
    preflight('bind', BUNDLE_BYTES)
    for offset in range(0, BUNDLE_BYTES, 4):
        a.e(b.lw(8, offset, 5), b.sw(8, PRIVATE_ENVELOPE + offset, 29))
    capture_schema(29, PRIVATE_ENVELOPE, 'restore')
    acquire('bind')
    a.absolute(10, ledger_address)
    a.e(b.lw(8, BIND_STATE, 10))
    a.branch(5, 8, 0, 'bind_before_release')
    for offset in range(0, BUNDLE_BYTES, 4):
        a.e(b.lw(8, PRIVATE_ENVELOPE + offset, 29), b.sw(8, CAPTURE + offset, 10))
    a.e(SYNC, b.addiu(8, 0, OPEN), b.sw(8, BIND_STATE, 10),
        b.addiu(8, 0, 1), b.sw(8, RESULT, 29))
    release('bind')

    preflight('enqueue', ENVELOPE_BYTES)
    pack_private(5)
    a.e(b.addiu(8, 29, PRIVATE_ENVELOPE))
    a.branch(5, 2, 8, 'restore')
    acquire('enqueue')
    a.absolute(10, ledger_address)
    a.e(b.lw(8, BIND_STATE, 10))
    equal(8, OPEN, 'enqueue_before_release')
    capture_matches('enqueue_before_release')
    a.e(b.lw(8, OLD_COUNT, 29))
    a.absolute(9, retained_capacity)
    a.branch(4, 8, 9, 'enqueue_before_release')
    a.absolute(10, ledger_address)
    a.e(b.lw(8, OP_COUNT, 10))
    a.absolute(9, operation_capacity)
    a.branch(4, 8, 9, 'enqueue_before_release')
    # Reserve BEFORE native APPEND. An uncertain/failed append is never rolled
    # back or silently reused; the permanent fault keeps its reservation live.
    a.e(b.addiu(8, 8, 1), b.sw(8, PRIVATE_TOKEN, 29), b.sw(8, PRIVATE, 29),
        b.sw(8, OP_COUNT, 10))
    row_from_token()
    a.e(b.lw(8, PRIVATE_TOKEN, 29), b.sw(8, TOKEN, 10),
        b.addiu(8, 0, RESERVED), b.sw(8, STATE, 10), SYNC)
    a.label('before_append')
    a.absolute(4, retained_queue_address)
    a.e(b.addiu(5, 29, PRIVATE))
    a.jump(APPEND, link=True)
    a.label('after_append')
    a.e(b.lw(8, OLD_COUNT, 29))
    a.branch(5, 2, 8, fault('enqueue_append', APPEND_FAULT, 'enqueue'))
    a.e(b.addiu(8, 8, 1))
    a.absolute(10, retained_queue_address)
    a.e(b.lw(9, 0x0C, 10))
    a.branch(5, 8, 9, 'enqueue_append_fault')
    a.e(b.lw(10, PRIVATE_ROW, 29), b.addiu(8, 0, QUEUED), b.sw(8, STATE, 10),
        b.lw(8, PRIVATE_TOKEN, 29), b.sw(8, RESULT, 29))
    release('enqueue')

    preflight('pop_dispatch')
    acquire('pop')
    a.e(b.lw(8, OLD_COUNT, 29))
    a.branch(4, 8, 0, 'pop_before_release')
    a.absolute(10, ledger_address)
    a.e(b.lw(8, BIND_STATE, 10))
    a.branch(4, 8, 0, 'pop_before_release')
    a.label('before_get')
    a.absolute(4, retained_queue_address)
    a.e(b.move(5, 0))
    a.jump(GET, link=True)
    a.label('after_get')
    a.e(b.move(5, 2))
    pop_head_fault = fault('pop_head', HEAD_FAULT, 'pop')
    extent(5, 13, PACKET_BYTES, pop_head_fault)
    fixed_exclusions(5, 13, pop_head_fault, 'head')
    a.e(b.addiu(11, 29, 0), b.addiu(12, 29, FRAME - 1))
    disjoint(5, 13, 11, 12, pop_head_fault, 'head_frame_ok')
    a.e(b.lw(8, 0, 5), b.sw(8, PRIVATE_TOKEN, 29))
    bounded(8, operation_capacity, pop_head_fault)
    # bounded() may use r8 as scratch, so reload the exact saved token.
    a.e(b.lw(8, PRIVATE_TOKEN, 29))
    a.absolute(10, ledger_address)
    a.e(b.lw(9, OP_COUNT, 10), b.r_type(9, 8, 9, 0x2B))
    a.branch(5, 9, 0, pop_head_fault)
    row_from_token()
    a.e(b.lw(8, STATE, 10))
    equal(8, QUEUED, pop_head_fault)
    # Borrowed token and68 bytes are copied BEFORE REMOVE shifts head storage.
    a.e(b.addiu(5, 5, 4))
    pack_private(5)
    a.e(b.addiu(8, 29, PRIVATE_ENVELOPE))
    a.branch(5, 2, 8, pop_head_fault)
    capture_matches(pop_head_fault)
    a.label('before_remove')
    a.absolute(4, retained_queue_address)
    a.e(b.move(5, 0))
    a.jump(REMOVE, link=True)
    a.label('after_remove')
    pop_remove_fault = fault('pop_remove', REMOVE_FAULT, 'pop')
    a.branch(5, 2, 0, pop_remove_fault)
    a.e(b.lw(8, OLD_COUNT, 29), b.addiu(8, 8, -1))
    a.absolute(10, retained_queue_address)
    a.e(b.lw(9, 0x0C, 10))
    a.branch(5, 8, 9, pop_remove_fault)
    a.absolute(10, ledger_address)
    a.e(b.lw(8, BIND_STATE, 10))
    equal(8, OPEN, 'pop_cancel')
    a.e(b.lw(10, PRIVATE_ROW, 29), b.addiu(8, 0, EXTRACTED),
        b.sw(8, STATE, 10), b.addiu(8, 0, 1), b.sw(8, MODE, 29))
    a.jump('pop_before_release')
    a.label('pop_cancel')
    a.e(b.lw(10, PRIVATE_ROW, 29), b.addiu(8, 0, DONE), b.sw(8, STATE, 10))
    release('pop', 'pop_released')
    a.label('pop_released')
    a.e(b.lw(8, MODE, 29))
    a.branch(4, 8, 0, 'restore')
    a.label('before_dispatch')
    a.absolute(4, controller_address)
    a.e(b.addiu(5, 29, PRIVATE_ENVELOPE))
    call_entry(dispatch_entry)
    a.label('after_dispatch')
    a.e(b.sw(2, RESULT, 29), b.sw(3, RAW, 29), b.sw(3, PUBLISH_INDEX, 29),
        b.sw(2, PRIVATE_NONCE, 29))
    # Successful publication carries an index in v1, NOT a raw error. Only a
    # zero nonce with nonzero v1 is an uncertain R/P error; no M call follows it.
    a.branch(5, 2, 0, 'pop_rebind')
    a.branch(5, 3, 0, 'restore')
    a.label('pop_rebind')
    acquire('pop_rebind')
    row_from_token()
    a.e(b.lw(8, STATE, 10))
    pop_rebind_fault = fault('pop_rebind_state', REBIND_FAULT, 'pop_rebind')
    equal(8, EXTRACTED, pop_rebind_fault)
    a.e(b.lw(8, PRIVATE_NONCE, 29))
    a.branch(4, 8, 0, 'pop_rebind_denied')
    bounded(8, ticket_limit, pop_rebind_fault)
    a.e(b.lw(8, PRIVATE_NONCE, 29), b.sw(8, NONCE, 10),
        b.addiu(8, 0, PUBLISHED), b.sw(8, STATE, 10))
    # Check historical nonce uniqueness before exposing success. A corrupted
    # publisher cannot manufacture positive quiescence via a duplicate nonce.
    a.jump('validate_locked', link=True)
    a.branch(4, 2, 0, 'pop_rebind_before_release')
    a.e(b.lw(8, PUBLISH_INDEX, 29), b.sw(8, RAW, 29))
    a.jump('pop_rebind_before_release')
    a.label('pop_rebind_denied')
    a.e(b.addiu(8, 0, DONE), b.sw(8, STATE, 10))
    release('pop_rebind')

    preflight('complete', completion=True)
    acquire('complete')
    a.absolute(10, ledger_address)
    a.e(b.lw(8, BIND_STATE, 10))
    a.branch(4, 8, 0, 'complete_before_release')
    a.e(b.lw(12, OP_COUNT, 10), b.addiu(10, 10, HEADER_BYTES),
        b.addiu(13, 0, 1), b.lw(15, PRIVATE_NONCE, 29))
    a.label('complete_find')
    a.e(b.r_type(12, 13, 8, 0x2B))
    a.branch(5, 8, 0, 'complete_before_release')
    a.e(b.lw(8, STATE, 10))
    a.absolute(9, PUBLISHED)
    a.branch(5, 8, 9, 'complete_find_next')
    a.e(b.lw(8, NONCE, 10))
    a.branch(4, 8, 15, 'complete_found')
    a.label('complete_find_next')
    a.e(b.addiu(10, 10, OPERATION_BYTES), b.addiu(13, 13, 1))
    a.jump('complete_find')
    a.label('complete_found')
    a.e(b.sw(13, PRIVATE_TOKEN, 29), b.sw(10, PRIVATE_ROW, 29),
        b.addiu(8, 0, ACKING), b.sw(8, STATE, 10),
        b.addiu(8, 0, 1), b.sw(8, MODE, 29))
    release('complete', 'complete_released')
    a.label('complete_released')
    a.e(b.lw(8, MODE, 29))
    a.branch(4, 8, 0, 'restore')
    a.label('before_complete')
    a.absolute(4, controller_address)
    a.e(b.lw(5, PRIVATE_NONCE, 29), b.lw(6, OUTCOME, 29))
    call_entry(complete_entry)
    a.label('after_complete')
    a.e(b.sw(2, RESULT, 29), b.sw(3, RAW, 29))
    # A zero result conflates harmless denial and post-remove/schema failure.
    # Keep ACKING outstanding. Neither raw errors nor zero ordinary outcomes
    # are followed by an M reacquire, cleanup, state restoration or retry.
    a.branch(4, 2, 0, 'restore')
    a.branch(5, 3, 0, 'complete_invalid_result')
    a.e(b.i_type(11, 2, 8, 4))
    a.branch(4, 8, 0, 'complete_invalid_result')
    acquire('complete_rebind')
    row_from_token()
    complete_rebind_fault = fault('complete_rebind_state', REBIND_FAULT, 'complete_rebind')
    a.e(b.lw(8, STATE, 10))
    equal(8, ACKING, complete_rebind_fault)
    a.e(b.lw(8, NONCE, 10), b.lw(9, PRIVATE_NONCE, 29))
    a.branch(5, 8, 9, complete_rebind_fault)
    a.e(b.addiu(8, 0, DONE), b.sw(8, STATE, 10))
    release('complete_rebind')
    a.label('complete_invalid_result')
    a.e(b.sw(0, RESULT, 29), b.sw(0, RAW, 29))
    a.jump('restore')

    preflight('close')
    acquire('close')
    a.absolute(10, ledger_address)
    a.e(b.lw(8, BIND_STATE, 10))
    a.branch(4, 8, 0, 'close_before_release')
    a.e(b.addiu(8, 0, CLOSED), b.sw(8, BIND_STATE, 10),
        b.addiu(8, 0, 1), b.sw(8, RESULT, 29))
    release('close')

    preflight('quiescent')
    acquire('quiescent')
    a.absolute(10, ledger_address)
    a.e(b.lw(8, BIND_STATE, 10))
    equal(8, CLOSED, 'quiescent_before_release')
    a.e(b.lw(8, OLD_COUNT, 29))
    a.branch(5, 8, 0, 'quiescent_before_release')
    a.e(b.lw(12, OP_COUNT, 10), b.lw(8, CAPTURE + envelope.OWNER, 10),
        b.sw(8, PRIVATE_OWNER, 29), b.addiu(10, 10, HEADER_BYTES),
        b.addiu(13, 0, 0))
    a.label('quiescent_rows')
    a.branch(4, 12, 13, 'quiescent_rows_done')
    a.e(b.lw(8, STATE, 10))
    equal(8, DONE, 'quiescent_before_release')
    a.e(b.addiu(10, 10, OPERATION_BYTES), b.addiu(13, 13, 1))
    a.jump('quiescent_rows')
    a.label('quiescent_rows_done')
    a.e(b.addiu(8, 0, 1), b.sw(8, MODE, 29))
    release('quiescent', 'quiescent_released')
    a.label('quiescent_released')
    a.e(b.lw(8, MODE, 29))
    a.branch(4, 8, 0, 'restore')
    # CLOSED is irreversible and no operation remains live. Retire cannot
    # purge away a tracked outstanding acknowledgement at this boundary.
    a.label('before_retire')
    a.absolute(4, controller_address)
    a.e(b.lw(5, PRIVATE_OWNER, 29))
    call_entry(retire_entry)
    a.label('after_retire')
    a.e(b.sw(2, RESULT, 29), b.sw(3, RAW, 29))
    a.absolute(8, 1)
    a.branch(5, 2, 8, 'restore')
    a.label('before_drained')
    a.absolute(4, controller_address)
    a.e(b.lw(5, PRIVATE_OWNER, 29))
    call_entry(drained_entry)
    a.label('after_drained')
    a.e(b.sw(2, RESULT, 29), b.sw(3, RAW, 29))
    a.jump('restore')

    if cleanup_intent_address is not None:
        # No gate reservation occurs while live work is merely unfinished.
        # Once reserved, however, failure is terminal for this one attempt:
        # neither uncertain release nor a later barrier/output refusal resets it.
        preflight('prepare_cleanup', CLEANUP_INTENT_BYTES,
                  initial_zero_bytes=CLEANUP_INTENT_BYTES)
        a.e(b.sw(5, CLEANUP_OUTPUT, 29))
        acquire('prepare_cleanup')
        a.absolute(10, ledger_address)
        a.e(b.lw(8, BIND_STATE, 10))
        equal(8, CLOSED, 'prepare_cleanup_before_release')
        a.e(b.lw(8, OLD_COUNT, 29))
        a.branch(5, 8, 0, 'prepare_cleanup_before_release')
        a.e(b.lw(12, OP_COUNT, 10), b.addiu(11, 10, HEADER_BYTES),
            b.addiu(13, 0, 0))
        a.label('prepare_cleanup_rows')
        a.branch(4, 12, 13, 'prepare_cleanup_rows_done')
        a.e(b.lw(8, STATE, 11))
        equal(8, DONE, 'prepare_cleanup_before_release')
        a.e(b.addiu(11, 11, OPERATION_BYTES), b.addiu(13, 13, 1))
        a.jump('prepare_cleanup_rows')
        a.label('prepare_cleanup_rows_done')
        a.absolute(11, cleanup_intent_address)
        a.e(b.lw(8, 0, 11))
        a.branch(5, 8, 0, 'prepare_cleanup_before_release')
        # The binding is immutable. Copy it while M is held, before consuming
        # the sole attempt; later output never re-reads native or ledger state.
        for offset in range(0, BUNDLE_BYTES, 4):
            a.e(b.lw(8, CAPTURE + offset, 10),
                b.sw(8, PRIVATE_ENVELOPE + offset, 29))
        a.label('before_cleanup_intent_reserve')
        a.e(b.addiu(8, 0, 1), b.sw(8, 0, 11), SYNC,
            b.sw(8, MODE, 29))
        a.label('after_cleanup_intent_reserve')
        release('prepare_cleanup', 'prepare_cleanup_released')
        a.label('prepare_cleanup_released')
        a.e(b.lw(8, MODE, 29))
        a.branch(4, 8, 0, 'restore')
        # Reservation precedes every checked P barrier. A competing prepare
        # therefore refuses before it can race a later intent consumer.
        a.label('before_cleanup_intent_barrier')
        a.absolute(4, controller_address)
        a.jump('quiescent', link=True)
        a.label('after_cleanup_intent_barrier')
        a.e(b.sw(0, RESULT, 29), b.sw(3, RAW, 29))
        a.branch(5, 3, 0, 'restore')
        equal(2, 1, 'restore')
        a.e(b.lw(5, CLEANUP_OUTPUT, 29))
        for offset in range(0, CLEANUP_INTENT_BYTES, 4):
            a.e(b.lw(8, offset, 5))
            a.branch(5, 8, 0, 'restore')
        a.label('before_cleanup_intent_output')
        for offset in range(0, BUNDLE_BYTES, 4):
            a.e(b.lw(8, PRIVATE_ENVELOPE + offset, 29),
                b.sw(8, 4 + offset, 5))
        a.e(SYNC)
        a.absolute(8, CLEANUP_INTENT_MAGIC)
        a.e(b.sw(8, 0, 5), SYNC, b.sw(5, RESULT, 29))
        a.label('after_cleanup_intent_output')
        a.jump('restore')

    for label, value, release_label in fault_handlers:
        a.label(label)
        a.absolute(10, ledger_address)
        a.e(b.addiu(8, 0, value), b.sw(8, FAULT, 10), SYNC,
            b.sw(0, RESULT, 29), b.sw(0, RAW, 29), b.sw(0, MODE, 29))
        a.jump(release_label)

    # Internal leaf checker: called ONLY while M is confirmed held. It never
    # invokes native services and never uses caller-volatiles across a call.
    # A permanent prior fault suppresses all positive results without reset.
    a.label('validate_locked')
    a.absolute(10, ledger_address)
    a.e(b.lw(8, FAULT, 10))
    a.branch(5, 8, 0, 'schema_denied')
    a.absolute(11, retained_queue_address)
    for offset, expected in ((0x10, PACKET_BYTES), (0x14, 10),
                             (0x08, retained_capacity)):
        a.e(b.lw(8, offset, 11))
        equal(8, expected, 'schema_header_fault')
    a.e(b.lw(12, 0x0C, 11))
    a.absolute(9, retained_capacity)
    a.e(b.r_type(9, 12, 8, 0x2B))
    a.branch(5, 8, 0, 'schema_header_fault')
    a.e(b.sw(12, OLD_COUNT, 29), b.lw(8, 0, 11))
    a.branch(4, 8, 0, 'schema_header_fault')
    a.e(b.i_type(12, 8, 9, 3))
    a.branch(5, 9, 0, 'schema_header_fault')
    # Native header+4 is uninitialized factory padding, intentionally ignored.
    a.e(b.lw(8, 12, 10))
    a.branch(5, 8, 0, 'schema_ledger_fault')
    a.e(b.lw(8, 60, 10))
    a.branch(5, 8, 0, 'schema_ledger_fault')
    a.e(b.lw(8, BIND_STATE, 10), b.i_type(11, 8, 9, CLOSED + 1))
    a.branch(4, 9, 0, 'schema_ledger_fault')
    a.branch(4, 8, 0, 'schema_unbound')
    capture_schema(10, CAPTURE, 'schema_ledger_fault')
    a.jump('schema_count')
    a.label('schema_unbound')
    a.e(b.lw(8, OLD_COUNT, 29))
    a.branch(5, 8, 0, 'schema_ledger_fault')
    for offset in (OP_COUNT, *range(CAPTURE, 60, 4)):
        a.e(b.lw(8, offset, 10))
        a.branch(5, 8, 0, 'schema_ledger_fault')
    a.label('schema_count')
    a.e(b.lw(12, OP_COUNT, 10))
    a.absolute(9, operation_capacity)
    a.e(b.r_type(9, 12, 8, 0x2B))
    a.branch(5, 8, 0, 'schema_ledger_fault')
    a.e(b.addiu(11, 10, HEADER_BYTES), b.addiu(13, 0, 1))
    a.label('schema_rows')
    a.absolute(9, operation_capacity)
    a.e(b.r_type(9, 13, 8, 0x2B))
    a.branch(5, 8, 0, 'schema_valid')
    a.e(b.r_type(12, 13, 8, 0x2B))
    a.branch(5, 8, 0, 'schema_unused')
    a.e(b.lw(8, TOKEN, 11))
    a.branch(5, 8, 13, 'schema_ledger_fault')
    a.e(b.lw(8, 12, 11))
    a.branch(5, 8, 0, 'schema_ledger_fault')
    a.e(b.lw(14, STATE, 11))
    bounded(14, DONE, 'schema_ledger_fault')
    a.e(b.lw(15, NONCE, 11))
    a.absolute(9, PUBLISHED)
    a.branch(4, 14, 9, 'schema_positive_nonce')
    a.absolute(9, ACKING)
    a.branch(4, 14, 9, 'schema_positive_nonce')
    a.absolute(9, DONE)
    a.branch(4, 14, 9, 'schema_done_nonce')
    a.branch(5, 15, 0, 'schema_ledger_fault')
    a.jump('schema_next_row')
    a.label('schema_done_nonce')
    a.branch(4, 15, 0, 'schema_next_row')
    a.label('schema_positive_nonce')
    bounded(15, ticket_limit, 'schema_ledger_fault')
    a.absolute(24, ledger_address + HEADER_BYTES)
    a.label('schema_nonce_unique')
    a.branch(4, 24, 11, 'schema_next_row')
    a.e(b.lw(8, NONCE, 24))
    a.branch(4, 8, 15, 'schema_ledger_fault')
    a.e(b.addiu(24, 24, OPERATION_BYTES))
    a.jump('schema_nonce_unique')
    a.label('schema_unused')
    for offset in range(0, OPERATION_BYTES, 4):
        a.e(b.lw(8, offset, 11))
        a.branch(5, 8, 0, 'schema_ledger_fault')
    a.label('schema_next_row')
    a.e(b.addiu(11, 11, OPERATION_BYTES), b.addiu(13, 13, 1))
    a.jump('schema_rows')
    a.label('schema_valid')
    a.e(b.addiu(2, 0, 1), b.r_type(31, 0, 0, 8), 0)
    for label, value in (('schema_header_fault', HEADER_FAULT),
                         ('schema_ledger_fault', LEDGER_FAULT)):
        a.label(label)
        a.absolute(10, ledger_address)
        a.e(b.addiu(8, 0, value), b.sw(8, FAULT, 10), SYNC,
            b.sw(0, RESULT, 29), b.sw(0, RAW, 29), b.sw(0, MODE, 29))
        a.jump('schema_denied')
    a.label('schema_denied')
    # A preexisting fault also clears any saved successful result of a rebind.
    a.e(b.sw(0, RESULT, 29), b.sw(0, RAW, 29), b.sw(0, MODE, 29),
        b.move(2, 0), b.r_type(31, 0, 0, 8), 0)

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
        raise ValueError('retained fragment leaves the native jump region')
    if protected_end is not None and code_end > protected_end:
        raise ValueError('protected code does not contain the complete retained fragment')
    if max(code_base, receipt.NATIVE_RX[0]) < min(code_end, receipt.NATIVE_RX[1]):
        raise ValueError('retained fragment overlaps pinned native RX')
    for name, entry, _ in entries:
        if code_base <= entry < code_end:
            raise ValueError('retained fragment overlaps ' + name)
    for name, address, size in extents:
        if max(code_base, address) < min(code_end, address + size):
            raise ValueError('retained fragment overlaps ' + name)
    for index in end_fixups:
        value = code_end - 1
        a.w[index:index + 2] = (b.lui(10, value >> 16), b.ori(10, 10, value & 0xFFFF))
    return a.finish(), a.labels
