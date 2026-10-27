#!/usr/bin/env python3
"""Offline checked-mutex transport for owned68 records, NOT stock integration.

enqueue(U, owned_READY68) first copies through the actual emitted envelope
packer into a private frame, then acquires one pinned ordinary raw mutex T.
While held it validates a separate pinned preallocated native FIFO and appends
without growth, requiring the actual returned index and incremented count to
match the saved prior count. Success is (native_index+1,0); refusal is (0,0).

pop_dispatch(U) holds T across native GET, validation/copy of the borrowed head,
and successful native REMOVE with the exact expected decremented count. It
releases T before calling the actual emitted
envelope dispatcher with its independent private copy. No T->R/P nesting occurs.
Extraction is FIFO, but concurrent consumers can publish in a different order
after releasing T. Removing transport work is not paint completion or admission.

One initially-zero retained fault word is read/written ONLY while T is held;
it is never cleared. Header, head, append, and remove failures latch1..4.
Any nonzero raw acquire/release status returns (0,status), without guessed
unlock, retry, rollback, late shared-state access or post-release fault writes.
The caller must isolate the WHOLE instance after such an uncertain raw error.

All queue users, including clear/destroy/rebind/bypass routes, must cooperate.
Initialized retained ordinary nonrobust T, coherent exclusive source68, mapped
retained queue header/table/all allocated chunks, nonaliasing heap storage,
native method semantics and sufficient nested native/service stack are caller
premises. Pointer checks do not establish any of these. The source is not
consumed by enqueue; copies are not deduplicated. No free/UI/image/device I/O.
"""

from build_reveal_bridge_diag import Asm, b
import reveal_deferred_envelope_mips as envelope
import reveal_registry_owner_mips as bindings
import reveal_registry_receipt_mips as receipt
import reveal_paint_retirement_mips as owners


MAX_TICKET = owners.MAX_TICKET
ENVELOPE_BYTES, QUEUE_BYTES, MUTEX_BYTES = 68, 56, 24
RAW_LOCK, RAW_UNLOCK = 0xA5B960, 0xA5B830
APPEND, GET, REMOVE = 0x455DA0, 0x4557E0, 0x455860
HEADER_FAULT, HEAD_FAULT, APPEND_FAULT, REMOVE_FAULT = 1, 2, 3, 4
FRAME, PRIVATE, RESULT, RAW, OLD_COUNT, REMOVED = 256, 0x10, 0x54, 0x58, 0x5C, 0x60
HI, LO, SYNC = 0x64, 0x68, 0xF
SAVE = {register: 0x6C + index * 4
        for index, register in enumerate((*range(16, 24), 28, 30, 31))}


def assemble(receipt_address, binding_address, owner_address, controller_address,
             registry_mutex_address, paint_mutex_address, code_base,
             queue_address, transport_mutex_address, fault_address,
             pack_entry, dispatch_entry, *, capacity=16, owner_capacity=16,
             ticket_limit=MAX_TICKET, transport_capacity=40,
             protected_code=None):
    """Return instructions/labels, with no state allocation or native activation.

    Q is an independently allocated native56-byte list header, not U+128 or the
    stock worker queue. Its allocated slot count is pinned, positive, a multiple
    of10 and at most10240; an append at full capacity is refused before native
    growth can run. The retained fault word starts zero and is never reset.

    protected_code=(start,bytes) must contain this complete fragment and both
    supplied envelope entries. With None only this fragment and the two entry
    words are excluded; exclusion of their remaining generated RX is a caller
    premise. Both modes emit identical word counts for two-pass composition.

    Full extent arithmetic guards precede any source read or frame save. They
    cover this outer256-byte frame, not the entire nested native/service stack.
    """
    extents = [('receipt', receipt_address, receipt.memory_bytes(capacity)),
               ('bindings', binding_address, bindings.memory_bytes(capacity)),
               ('owners', owner_address, owners.memory_bytes(owner_capacity)),
               ('controller', controller_address, receipt.CONTROLLER_BYTES),
               ('registry mutex', registry_mutex_address, MUTEX_BYTES),
               ('paint mutex', paint_mutex_address, MUTEX_BYTES),
               ('queue', queue_address, QUEUE_BYTES),
               ('transport mutex', transport_mutex_address, MUTEX_BYTES),
               ('fault', fault_address, 4)]
    entries = [('pack entry', pack_entry, 4), ('dispatch entry', dispatch_entry, 4)]
    if type(ticket_limit) is not int or not 1 <= ticket_limit <= MAX_TICKET:
        raise ValueError('ticket limit must be a positive signed word')
    if (type(transport_capacity) is not int
            or not 10 <= transport_capacity <= 10240 or transport_capacity % 10):
        raise ValueError('transport capacity must be a multiple of10 in10..10240')
    for name, address, size in (*extents, ('code', code_base, 4), *entries):
        if (type(address) is not int or not 0 < address <= 0xFFFFFFFC
                or address % 4 or address + size > 0x100000000):
            raise ValueError(name + ' must have a nonwrapping aligned extent')
    if code_base >> 28 or pack_entry >> 28 or dispatch_entry >> 28:
        raise ValueError('queue and envelope entries must share the native jump region')
    if pack_entry == dispatch_entry:
        raise ValueError('pack and dispatch entries overlap')
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
            raise ValueError('protected code must contain queue fragment and envelope entries')
        if max(protected_start, receipt.NATIVE_RX[0]) < min(protected_end, receipt.NATIVE_RX[1]):
            raise ValueError('protected code overlaps pinned native RX')
        for name, address, size in extents:
            if max(protected_start, address) < min(protected_end, address + size):
                raise ValueError('protected code overlaps ' + name)

    a = Asm(code_base)
    end_fixups = []
    protected = [*extents,
                 ('native RX', receipt.NATIVE_RX[0],
                  receipt.NATIVE_RX[1] - receipt.NATIVE_RX[0]),
                 *entries,
                 ('generated RX', protected_start,
                  None if protected_end is None else protected_end - protected_start)]

    def equal(register, value, failed):
        a.absolute(9, value)
        a.branch(5, register, 9, failed)

    def extent(pointer, last, size, failed):
        a.branch(4, pointer, 0, failed)
        a.e(b.i_type(12, pointer, 8, 3))
        a.branch(5, 8, 0, failed)
        a.e(b.addiu(last, pointer, size - 1), b.r_type(last, pointer, 8, 0x2B))
        a.branch(5, 8, 0, failed)

    def nonoverlap(first, last, start, end, failed, label):
        # Inclusive endpoints admit an extent ending exactly at2**32.
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
            nonoverlap(first, last, address,
                       None if size is None else address + size,
                       failed, prefix + '_extent_' + str(index))

    def preflight(name, *, source):
        a.label(name)
        equal(4, controller_address, 'early_denied')
        a.e(b.i_type(12, 29, 8, 7))
        a.branch(5, 8, 0, 'early_denied')
        a.e(b.i_type(11, 29, 8, FRAME))
        a.branch(5, 8, 0, 'early_denied')
        a.e(b.addiu(11, 29, -FRAME), b.addiu(12, 29, -1))
        fixed_exclusions(11, 12, 'early_denied', name + '_frame')
        if source:
            extent(5, 13, ENVELOPE_BYTES, 'early_denied')
            fixed_exclusions(5, 13, 'early_denied', name + '_source')
            disjoint(5, 13, 11, 12, 'early_denied', name + '_source_frame_ok')
        a.e(b.addiu(29, 29, -FRAME))
        for register, offset in SAVE.items():
            a.e(b.sw(register, offset, 29))
        a.e(b.r_type(0, 0, 8, 0x10), b.sw(8, HI, 29),
            b.r_type(0, 0, 8, 0x12), b.sw(8, LO, 29),
            b.sw(0, RESULT, 29), b.sw(0, RAW, 29), b.sw(0, REMOVED, 29))
        for offset in range(0, ENVELOPE_BYTES, 4):
            a.e(b.sw(0, PRIVATE + offset, 29))

    def pack_private(source):
        a.absolute(4, controller_address)
        a.e(b.move(5, source), b.addiu(6, source, envelope.PAYLOAD),
            b.addiu(7, 29, PRIVATE))
        a.absolute(25, pack_entry)
        a.e(b.r_type(25, 0, 31, 9), 0)

    def acquire(name):
        a.label(name + '_before_lock')
        a.absolute(4, transport_mutex_address)
        a.jump(RAW_LOCK, link=True)
        a.label(name + '_after_lock')
        a.e(b.sw(2, RAW, 29))
        a.branch(5, 2, 0, 'restore')
        a.e(SYNC)
        a.absolute(10, fault_address)
        a.e(b.lw(8, 0, 10))
        a.branch(5, 8, 0, 'before_release')
        # Header bytes+4 are uninitialized in the native factory, not schema.
        a.absolute(11, queue_address)
        for offset, expected in ((0x10, ENVELOPE_BYTES), (0x14, 10),
                                 (0x08, transport_capacity)):
            a.e(b.lw(8, offset, 11))
            equal(8, expected, 'header_fault')
        a.e(b.lw(12, 0x0C, 11))
        a.absolute(9, transport_capacity)
        a.e(b.r_type(9, 12, 8, 0x2B))
        a.branch(5, 8, 0, 'header_fault')
        a.e(b.sw(12, OLD_COUNT, 29), b.lw(8, 0, 11))
        a.branch(4, 8, 0, 'header_fault')
        a.e(b.i_type(12, 8, 9, 3))
        a.branch(5, 9, 0, 'header_fault')

    preflight('enqueue', source=True)
    # No source read or source retention follows this actual emitted copy.
    pack_private(5)
    a.e(b.addiu(8, 29, PRIVATE))
    a.branch(5, 2, 8, 'restore')
    acquire('enqueue')
    a.e(b.lw(8, OLD_COUNT, 29))
    a.absolute(9, transport_capacity)
    a.branch(4, 8, 9, 'before_release')
    a.label('before_append')
    a.absolute(4, queue_address)
    a.e(b.addiu(5, 29, PRIVATE))
    a.jump(APPEND, link=True)
    a.label('after_append')
    a.e(b.lw(8, OLD_COUNT, 29))
    a.branch(5, 2, 8, 'append_fault')
    a.e(b.addiu(8, 8, 1))
    a.absolute(10, queue_address)
    a.e(b.lw(9, 0x0C, 10))
    a.branch(5, 8, 9, 'append_fault')
    a.e(b.sw(8, RESULT, 29))
    a.jump('before_release')

    preflight('pop_dispatch', source=False)
    acquire('pop')
    a.e(b.lw(8, OLD_COUNT, 29))
    a.branch(4, 8, 0, 'before_release')
    a.label('before_get')
    a.absolute(4, queue_address)
    a.e(b.move(5, 0))
    a.jump(GET, link=True)
    a.label('after_get')
    a.e(b.move(5, 2))
    extent(5, 13, ENVELOPE_BYTES, 'head_fault')
    fixed_exclusions(5, 13, 'head_fault', 'head')
    a.e(b.addiu(11, 29, 0), b.addiu(12, 29, FRAME - 1))
    disjoint(5, 13, 11, 12, 'head_fault', 'head_frame_ok')
    # Copy borrowed head BEFORE REMOVE can shift/reuse its storage.
    pack_private(5)
    a.e(b.addiu(8, 29, PRIVATE))
    a.branch(5, 2, 8, 'head_fault')
    a.label('before_remove')
    a.absolute(4, queue_address)
    a.e(b.move(5, 0))
    a.jump(REMOVE, link=True)
    a.label('after_remove')
    a.branch(5, 2, 0, 'remove_fault')
    a.e(b.lw(8, OLD_COUNT, 29), b.addiu(8, 8, -1))
    a.absolute(10, queue_address)
    a.e(b.lw(9, 0x0C, 10))
    a.branch(5, 8, 9, 'remove_fault')
    a.e(b.addiu(8, 0, 1), b.sw(8, REMOVED, 29))
    a.jump('before_release')

    for name, value in (('header_fault', HEADER_FAULT), ('head_fault', HEAD_FAULT),
                        ('append_fault', APPEND_FAULT), ('remove_fault', REMOVE_FAULT)):
        a.label(name)
        a.absolute(10, fault_address)
        a.e(b.addiu(8, 0, value), b.sw(8, 0, 10), SYNC,
            b.sw(0, RESULT, 29), b.sw(0, REMOVED, 29))
        a.jump('before_release')

    a.label('before_release')
    a.e(SYNC)
    a.absolute(4, transport_mutex_address)
    a.jump(RAW_UNLOCK, link=True)
    a.label('after_release')
    a.branch(4, 2, 0, 'release_succeeded')
    # Actual raw error may have released T. Touch ONLY retained private stack.
    a.e(b.sw(0, RESULT, 29), b.sw(2, RAW, 29))
    a.jump('restore')
    a.label('release_succeeded')
    a.e(b.lw(8, REMOVED, 29))
    a.branch(4, 8, 0, 'restore')
    # No Q/fault/source access is permitted from actual release onwards.
    a.label('before_dispatch')
    a.absolute(4, controller_address)
    a.e(b.addiu(5, 29, PRIVATE))
    a.absolute(25, dispatch_entry)
    a.e(b.r_type(25, 0, 31, 9), 0,
        b.sw(2, RESULT, 29), b.sw(3, RAW, 29))

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
        raise ValueError('queue fragment leaves the native jump region')
    if protected_end is not None and code_end > protected_end:
        raise ValueError('protected code does not contain the complete queue fragment')
    if max(code_base, receipt.NATIVE_RX[0]) < min(code_end, receipt.NATIVE_RX[1]):
        raise ValueError('queue fragment overlaps pinned native RX')
    for name, entry, _ in entries:
        if code_base <= entry < code_end:
            raise ValueError('queue fragment overlaps ' + name)
    for name, address, size in extents:
        if max(code_base, address) < min(code_end, address + size):
            raise ValueError('queue fragment overlaps ' + name)
    for index in end_fixups:
        value = code_end - 1
        a.w[index:index + 2] = (b.lui(10, value >> 16), b.ori(10, 10, value & 0xFFFF))
    return a.finish(), a.labels
