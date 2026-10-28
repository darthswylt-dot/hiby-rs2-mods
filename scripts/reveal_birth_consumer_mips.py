#!/usr/bin/env python3
"""Offline exact-token history comparison, never native lifetime or dispatch.

take(U, zero_out100) first pops BQ84 into an owned private snapshot. Only after
the queue has successfully released T does it acquire fresh raw R, validate the
complete BRLC history and compare the exact captured birth token and fields.
Both NO_RETIREMENT_OBSERVED and RETIREMENT_SELECTED are historical observations,
not LIVE/DEAD states, retained native references or permission to use pointers.

A new BOBS100 output owns the BQ84 body and four retirement-observation words.
It is exported only after checked raw R release and a second full output-zero
check. The consumer never mutates history, writes a shared fault, requeues an
extracted item, follows native node/engine/payload words or calls paint/UI code.
Unobserved native mutations can still make a healthy historical row describe a
different physical incarnation at reused addresses. Exact matching does not
authenticate provenance or repair that incomplete lifecycle coverage.

After either queue or registry raw error, only the retained private frame is
accessed. No guessed unlock, retry, late output/shared access or recovery is
attempted; synchronous coordinated WHOLE combined-instance isolation remains
the caller's responsibility. Mapped, retained, exclusive, nonaliasing storage,
ordinary mutex semantics and complete transitive stack space remain premises.
"""

from build_reveal_bridge_diag import Asm, b
import reveal_birth_queue_mips as queue
import reveal_registry_lifecycle_mips as lifecycle
import reveal_registry_owner_mips as bindings
import reveal_registry_receipt_mips as receipt
import reveal_paint_retirement_mips as owners


OUTPUT_BYTES, OUTPUT_MAGIC = 100, int.from_bytes(b'BOBS', 'little')
ENVELOPE_BYTES = queue.ENVELOPE_BYTES
OBSERVATION_STATE, RETIREMENT_SITE = 84, 88
RETIREMENT_SP, RETIREMENT_CALLER = 92, 96
RAW_LOCK, RAW_UNLOCK, SYNC = receipt.RAW_LOCK, receipt.RAW_UNLOCK, 0xF
FRAME, COMBINED_FRAME, PRIVATE = 192, 192 + queue.FRAME, 0x10
RESULT, RAW, OUTPUT_PTR, MATCH, HI, LO = 0x74, 0x78, 0x7C, 0x80, 0x84, 0x88
SAVE = {register: 0x8C + index * 4
        for index, register in enumerate((*range(16, 24), 28, 30, 31))}


def assemble(receipt_address, binding_address, owner_address, controller_address,
             registry_mutex_address, paint_mutex_address, lifecycle_address,
             code_base, queue_address, transport_mutex_address, fault_address,
             queue_pop, native_return, *, capacity=16, lifecycle_capacity=16,
             owner_capacity=16, protected_code=None):
    """Return an uninstalled observational consumer and explicit entry labels.

    queue_pop is the coherent BQ84 pop entry; native_return is the coherent
    checked capture's actual native return. Both are distinct external entries,
    never callbacks supplied by the consumed record. protected_code=(start,
    bytes) must contain this complete fragment and both entries. None guards
    this fragment plus those two external words, not unknown enclosing RX.

    Before any output read or frame save, bounds exclude all known fixed/RX
    extents and the complete contiguous consumer192 + nested pop224 frames.
    Additional native/service/transitive frames and unknown heap aliases are
    not certified. Neither ordinary mutex T nor R may already be held on entry.
    Successful extraction is consumed even if later R admission, matching or
    output export fails; delivery is not transactional completion.
    """
    extents = [('receipt', receipt_address, receipt.memory_bytes(capacity)),
               ('bindings', binding_address, bindings.memory_bytes(capacity)),
               ('owners', owner_address, owners.memory_bytes(owner_capacity)),
               ('controller', controller_address, receipt.CONTROLLER_BYTES),
               ('registry mutex', registry_mutex_address, receipt.MUTEX_BYTES),
               ('paint mutex', paint_mutex_address, receipt.MUTEX_BYTES),
               ('lifecycle history', lifecycle_address,
                lifecycle.memory_bytes(lifecycle_capacity)),
               ('birth queue', queue_address, queue.QUEUE_BYTES),
               ('birth transport mutex', transport_mutex_address, queue.MUTEX_BYTES),
               ('birth queue fault', fault_address, 4)]
    entries = (('queue pop', queue_pop), ('native return', native_return))
    for name, address, size in (*extents, ('code', code_base, 4),
                                *((name, address, 4) for name, address in entries)):
        if (type(address) is not int or not 0 < address <= 0xFFFFFFFC
                or address % 4 or address + size > 0x100000000):
            raise ValueError(name + ' must have a nonwrapping aligned extent')
    if code_base >> 28 or queue_pop >> 28 or native_return >> 28:
        raise ValueError('consumer and external entries need native jump region')
    if queue_pop == native_return:
        raise ValueError('queue pop and native return must be distinct entries')
    for index, (name, address, size) in enumerate(extents):
        if max(address, receipt.NATIVE_RX[0]) < min(address + size, receipt.NATIVE_RX[1]):
            raise ValueError(name + ' overlaps pinned native RX')
        for other_name, other, other_size in extents[index + 1:]:
            if max(address, other) < min(address + size, other + other_size):
                raise ValueError(name + ' overlaps ' + other_name)
        for entry_name, entry in entries:
            if address <= entry < address + size:
                raise ValueError(entry_name + ' overlaps ' + name)
    for name, entry in entries:
        if receipt.NATIVE_RX[0] <= entry < receipt.NATIVE_RX[1]:
            raise ValueError(name + ' overlaps pinned native RX')

    protected_start, protected_end = code_base, None
    if protected_code is not None:
        if (type(protected_code) is not tuple or len(protected_code) != 2
                or any(type(value) is not int for value in protected_code)):
            raise ValueError('protected code must be an (RX start,bytes) tuple')
        protected_start, protected_bytes = protected_code
        protected_end = protected_start + protected_bytes
        if (protected_start <= 0 or protected_start % 4 or protected_bytes <= 0
                or protected_bytes % 4 or protected_end > 0x10000000
                or not protected_start <= code_base < protected_end
                or any(not protected_start <= entry < protected_end
                       for _, entry in entries)):
            raise ValueError('protected code must contain consumer and external entries')
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
                 *((name, entry, 4) for name, entry in entries),
                 ('generated RX', protected_start,
                  None if protected_end is None else protected_end - protected_start)]

    def equal(register, value, failed):
        a.absolute(9, value)
        a.branch(5, register, 9, failed)

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
            nonoverlap(first, last, address,
                       None if size is None else address + size,
                       failed, prefix + '_extent_' + str(index))

    a.label('take')
    equal(4, controller_address, 'early_denied')
    a.e(b.i_type(12, 29, 8, 7))
    a.branch(5, 8, 0, 'early_denied')
    a.e(b.i_type(11, 29, 8, COMBINED_FRAME))
    a.branch(5, 8, 0, 'early_denied')
    a.e(b.addiu(11, 29, -COMBINED_FRAME), b.addiu(12, 29, -1))
    a.branch(4, 11, 0, 'early_denied')
    exclusions(11, 12, 'early_denied', 'combined_frame')
    a.branch(4, 5, 0, 'early_denied')
    a.e(b.i_type(12, 5, 8, 3))
    a.branch(5, 8, 0, 'early_denied')
    a.e(b.addiu(13, 5, OUTPUT_BYTES - 1), b.r_type(13, 5, 8, 0x2B))
    a.branch(5, 8, 0, 'early_denied')
    exclusions(5, 13, 'early_denied', 'output')
    a.e(b.r_type(13, 11, 8, 0x2B))
    a.branch(5, 8, 0, 'output_frame_ok')
    a.e(b.r_type(12, 5, 8, 0x2B))
    a.branch(4, 8, 0, 'early_denied')
    a.label('output_frame_ok')
    for offset in range(0, OUTPUT_BYTES, 4):
        a.e(b.lw(8, offset, 5))
        a.branch(5, 8, 0, 'early_denied')
    a.label('save_frame')
    a.e(b.addiu(29, 29, -FRAME))
    for register, offset in SAVE.items():
        a.e(b.sw(register, offset, 29))
    a.e(b.r_type(0, 0, 8, 0x10), b.sw(8, HI, 29),
        b.r_type(0, 0, 8, 0x12), b.sw(8, LO, 29),
        b.sw(0, RESULT, 29), b.sw(0, RAW, 29), b.sw(5, OUTPUT_PTR, 29),
        b.sw(0, MATCH, 29))
    for offset in range(0, OUTPUT_BYTES, 4):
        a.e(b.sw(0, PRIVATE + offset, 29))
    a.label('before_pop')
    a.absolute(4, controller_address)
    a.e(b.addiu(5, 29, PRIVATE))
    a.jump(queue_pop, link=True)
    a.label('after_pop')
    # A queue raw error admits no BQ/output/shared read and no R service.
    a.e(b.sw(3, RAW, 29))
    a.branch(5, 3, 0, 'restore')
    a.branch(4, 2, 0, 'restore')
    a.e(b.addiu(8, 29, PRIVATE))
    a.branch(5, 2, 8, 'restore')
    for offset, expected in ((0, queue.READY_MAGIC),
                             (queue.CONTROLLER, controller_address),
                             (queue.REGISTRY_MUTEX, registry_mutex_address),
                             (queue.CALLER, native_return),
                             (queue.SITE, lifecycle.PUBLICATION_SITE),
                             (queue.STATUS, 0), (queue.NATIVE_RESULT, 0),
                             (queue.RELEASE_STATUS, 0)):
        a.e(b.lw(8, PRIVATE + offset, 29))
        equal(8, expected, 'restore')
    a.e(b.lw(14, PRIVATE + queue.TOKEN, 29))
    a.branch(4, 14, 0, 'restore')
    a.absolute(9, lifecycle_capacity)
    a.e(b.r_type(9, 14, 8, 0x2B))
    a.branch(5, 8, 0, 'restore')
    a.e(b.lw(8, PRIVATE + queue.ENGINE, 29),
        b.lw(9, PRIVATE + queue.PAYLOAD + queue.PAYLOAD_ENGINE, 29))
    a.branch(5, 8, 9, 'restore')
    a.label('snapshot_done')

    a.label('before_lock')
    a.absolute(4, registry_mutex_address)
    a.jump(RAW_LOCK, link=True)
    a.label('after_lock')
    a.e(b.sw(2, RAW, 29))
    a.branch(5, 2, 0, 'restore')
    a.e(SYNC)
    a.absolute(4, controller_address)
    for offset, expected in ((0x13C, registry_mutex_address),
                             (0x274, receipt.REGISTRY_LOCK),
                             (0x278, receipt.REGISTRY_UNLOCK)):
        a.e(b.lw(8, offset, 4))
        equal(8, expected, 'before_release')
    a.label('history_admitted')
    a.absolute(20, lifecycle_address)
    for offset in (lifecycle.FAULT, lifecycle.RESERVED0, lifecycle.RESERVED1):
        a.e(b.lw(8, offset, 20))
        a.branch(5, 8, 0, 'before_release')
    a.e(b.lw(21, lifecycle.COUNT, 20))
    a.absolute(9, lifecycle_capacity)
    a.e(b.r_type(9, 21, 8, 0x2B))
    a.branch(5, 8, 0, 'before_release')
    a.e(b.addiu(22, 20, lifecycle.HEADER_BYTES), b.move(18, 0))
    a.label('rows')
    a.branch(4, 18, 21, 'rows_done')
    a.e(b.lw(8, lifecycle.MAGIC, 22))
    equal(8, lifecycle.RECORD_MAGIC, 'before_release')
    a.e(b.addiu(18, 18, 1), b.lw(8, lifecycle.TOKEN, 22))
    a.branch(5, 8, 18, 'before_release')
    for offset, expected in ((lifecycle.CONTROLLER, controller_address),
                             (lifecycle.MUTEX, registry_mutex_address),
                             (lifecycle.SITE, lifecycle.PUBLICATION_SITE),
                             (lifecycle.STATUS, 0), (lifecycle.RESERVED2, 0),
                             (lifecycle.RESERVED3, 0)):
        a.e(b.lw(8, offset, 22))
        equal(8, expected, 'before_release')
    a.e(b.lw(8, lifecycle.STATE, 22),
        b.addiu(9, 0, lifecycle.NO_RETIREMENT_OBSERVED))
    a.branch(4, 8, 9, 'row_outstanding')
    equal(8, lifecycle.RETIREMENT_SELECTED, 'before_release')
    a.e(b.lw(8, lifecycle.RETIREMENT_SITE, 22))
    for site in lifecycle.RETIREMENT_SITES:
        a.absolute(9, site)
        a.branch(4, 8, 9, 'row_done')
    a.jump('before_release')

    a.label('row_outstanding')
    for offset in (lifecycle.RETIREMENT_SITE, lifecycle.RETIREMENT_SP,
                   lifecycle.RETIREMENT_CALLER):
        a.e(b.lw(8, offset, 22))
        a.branch(5, 8, 0, 'before_release')
    a.e(b.addiu(24, 20, lifecycle.HEADER_BYTES), b.lw(6, lifecycle.NODE, 22))
    a.label('earlier_rows')
    a.branch(4, 24, 22, 'earlier_rows_done')
    a.e(b.lw(8, lifecycle.STATE, 24),
        b.addiu(9, 0, lifecycle.NO_RETIREMENT_OBSERVED))
    a.branch(5, 8, 9, 'earlier_row_done')
    a.e(b.lw(8, lifecycle.NODE, 24))
    a.branch(4, 8, 6, 'before_release')
    a.label('earlier_row_done')
    a.e(b.addiu(24, 24, lifecycle.RECORD_BYTES))
    a.jump('earlier_rows')
    a.label('earlier_rows_done')
    a.label('row_done')
    a.e(b.lw(8, PRIVATE + queue.TOKEN, 29))
    a.branch(5, 18, 8, 'row_next')
    a.e(b.sw(22, MATCH, 29))
    a.label('row_next')
    a.e(b.addiu(22, 22, lifecycle.RECORD_BYTES))
    a.jump('rows')
    a.label('rows_done')
    # Count down actual remaining words, without encoding or dereferencing a
    # one-past history end that may equal the unrepresentable 2**32 address.
    a.absolute(19, lifecycle_capacity)
    a.e(b.r_type(19, 21, 19, 0x23),
        (19 << 16) | (19 << 11) | (4 << 6))
    a.label('unused_tail')
    a.branch(4, 19, 0, 'unused_tail_done')
    a.e(b.lw(8, 0, 22))
    a.branch(5, 8, 0, 'before_release')
    a.e(b.addiu(19, 19, -1))
    a.branch(4, 19, 0, 'unused_tail_done')
    a.e(b.addiu(22, 22, 4))
    a.jump('unused_tail')
    a.label('unused_tail_done')
    a.e(b.lw(16, MATCH, 29))
    a.branch(4, 16, 0, 'before_release')
    for offset in range(lifecycle.TOKEN, lifecycle.STATE, 4):
        a.e(b.lw(8, offset, 16), b.lw(9, PRIVATE + offset, 29))
        a.branch(5, 8, 9, 'before_release')
    a.label('selected_match')
    for source, target in ((lifecycle.STATE, OBSERVATION_STATE),
                            (lifecycle.RETIREMENT_SITE, RETIREMENT_SITE),
                            (lifecycle.RETIREMENT_SP, RETIREMENT_SP),
                            (lifecycle.RETIREMENT_CALLER, RETIREMENT_CALLER)):
        a.e(b.lw(8, source, 16), b.sw(8, PRIVATE + target, 29))
    a.e(b.addiu(8, 0, 1), b.sw(8, RESULT, 29))
    a.label('history_snapshot_done')
    a.label('before_release')
    a.e(SYNC)
    a.absolute(4, registry_mutex_address)
    a.jump(RAW_UNLOCK, link=True)
    a.label('after_release')
    a.branch(4, 2, 0, 'release_succeeded')
    # Raw release may already have unlocked R. Private storage only below.
    a.e(b.sw(2, RAW, 29), b.sw(0, RESULT, 29))
    a.jump('restore')
    a.label('release_succeeded')
    a.e(b.lw(8, RESULT, 29), b.sw(0, RESULT, 29))
    a.branch(4, 8, 0, 'restore')
    a.e(b.lw(16, OUTPUT_PTR, 29))
    a.label('before_export')
    # No history, queue, native source or service is accessed after release.
    for offset in range(0, OUTPUT_BYTES, 4):
        a.e(b.lw(8, offset, 16))
        a.branch(5, 8, 0, 'restore')
    for offset in range(4, OUTPUT_BYTES, 4):
        a.e(b.lw(8, PRIVATE + offset, 29), b.sw(8, offset, 16))
    a.e(SYNC)
    a.absolute(8, OUTPUT_MAGIC)
    a.e(b.sw(8, 0, 16), SYNC, b.sw(16, RESULT, 29))

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
        raise ValueError('consumer leaves the native MIPS jump region')
    if protected_end is not None and code_end > protected_end:
        raise ValueError('protected code does not contain complete consumer')
    if max(code_base, receipt.NATIVE_RX[0]) < min(code_end, receipt.NATIVE_RX[1]):
        raise ValueError('consumer overlaps pinned native RX')
    for name, entry in entries:
        if code_base <= entry < code_end:
            raise ValueError('consumer overlaps ' + name)
    for name, address, size in extents:
        if max(code_base, address) < min(code_end, address + size):
            raise ValueError('consumer overlaps ' + name)
    for index in end_fixups:
        a.w[index] = b.lui(10, (code_end - 1) >> 16)
        a.w[index + 1] = b.ori(10, 10, (code_end - 1) & 0xFFFF)
    return a.finish(), a.labels
