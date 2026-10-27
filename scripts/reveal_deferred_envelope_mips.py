#!/usr/bin/env python3
"""Offline owned generation envelope, NOT native explorer queue integration.

pack(U, capture32, payload36, out68) snapshots a checked creation output and an
already coherent owned payload into an independently owned write-once envelope.
It returns (out68,0), or (0,0) on refusal. The envelope is the exact32-byte GCAP
record followed by all36 payload bytes; no pointer to the source is retained.

dispatch(U, exclusively_owned68) snapshots and validates that envelope, changes
its magic from GCAP to CONSUMED before attempting the actual explicit carrier
publication, and returns that producer's v0/v1 unchanged. One envelope is never
automatically retried, including normal denial/backpressure and uncertain raw
failure. Consuming a private copy is not a global replay/authentication boundary.

Callers must retain coherent, exclusively owned private inputs/output and all
native controller, mutex, list, stack and service storage through nested calls.
The checked capture flag is bounded release evidence, not an engine lease or
permission to free. Native FIFO extraction/copy/removal must be separately
serialized, with the borrowed head copied BEFORE removal and removal successful
BEFORE dispatch. Transport extraction is not paint completion acknowledgement.
This fragment performs no queue, mutex, free, render, UI, lookup or retry action;
its only call is the explicitly supplied publication entry. No image/device I/O.
"""

from build_reveal_bridge_diag import Asm, b
import reveal_creation_capture_mips as capture
import reveal_registry_owner_mips as bindings
import reveal_registry_receipt_mips as receipt
import reveal_paint_retirement_mips as owners


MAX_TICKET = owners.MAX_TICKET
CAPTURE_BYTES, PAYLOAD_BYTES, PAYLOAD, ENVELOPE_BYTES = 32, 36, 32, 68
MAGIC, FLAGS, CONTROLLER, ENGINE = 0, 4, 8, 12
BINDING_SEQUENCE, OWNER, RECEIPT_SEQUENCE, NATIVE_RESULT = 16, 20, 24, 28
READY_MAGIC = capture.OUTPUT_MAGIC
CONSUMED_MAGIC = int.from_bytes(b'DCNS', 'little')
REGISTRY_RELEASE_OBSERVED = capture.REGISTRY_RELEASE_OBSERVED
FRAME, COPY, RESULT, RAW, HI, LO, SYNC = 160, 0x10, 0x54, 0x58, 0x5C, 0x60, 0xF
SAVE = {register: 0x64 + index * 4
        for index, register in enumerate((*range(16, 24), 31))}


def assemble(receipt_address, binding_address, owner_address, controller_address,
             registry_mutex_address, paint_mutex_address, code_base,
             publish_entry, *, capacity=16, owner_capacity=16,
             ticket_limit=MAX_TICKET, protected_code=None):
    """Return standalone instructions/labels without allocating state or I/O.

    protected_code=(start, bytes) excludes the complete composed generated RX
    and must contain the whole fragment and supplied publication entry. With
    None, only this fragment and the four-byte publication entry are known;
    exclusion of the rest of the publisher's RX remains a caller premise. Both
    modes emit the same word count for a two-pass full-composition descriptor.

    Full extent arithmetic guards precede all source/output accesses or frame
    saves. They cannot establish mapping, exclusive ownership, input coherence,
    nested native/service stack availability, service semantics or lifetimes.
    Neither schema checks nor GCAP/CONSUMED tags authenticate genuine capture,
    prevent arbitrary copied records, or replace the carrier's guarded checks.
    """
    extents = [('receipt', receipt_address, receipt.memory_bytes(capacity)),
               ('bindings', binding_address, bindings.memory_bytes(capacity)),
               ('owners', owner_address, owners.memory_bytes(owner_capacity)),
               ('controller', controller_address, receipt.CONTROLLER_BYTES),
               ('registry mutex', registry_mutex_address, receipt.MUTEX_BYTES),
               ('paint mutex', paint_mutex_address, receipt.MUTEX_BYTES)]
    if type(ticket_limit) is not int or not 1 <= ticket_limit <= MAX_TICKET:
        raise ValueError('ticket limit must be a positive signed word')
    for name, address, size in (*extents, ('code', code_base, 4),
                                ('publish entry', publish_entry, 4)):
        if (type(address) is not int or not 0 < address <= 0xFFFFFFFC
                or address % 4 or address + size > 0x100000000):
            raise ValueError(name + ' must have a nonwrapping aligned extent')
    if code_base >> 28 or publish_entry >> 28:
        raise ValueError('envelope and publisher must share the native jump region')
    for index, (name, address, size) in enumerate(extents):
        if max(address, receipt.NATIVE_RX[0]) < min(address + size, receipt.NATIVE_RX[1]):
            raise ValueError(name + ' overlaps pinned native RX')
        for other_name, other, other_size in extents[index + 1:]:
            if max(address, other) < min(address + size, other + other_size):
                raise ValueError(name + ' overlaps ' + other_name)
        if max(address, publish_entry) < min(address + size, publish_entry + 4):
            raise ValueError('publish entry overlaps ' + name)
    if receipt.NATIVE_RX[0] <= publish_entry < receipt.NATIVE_RX[1]:
        raise ValueError('publish entry overlaps pinned native RX')

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
                or not protected_start <= publish_entry
                or publish_entry + 4 > protected_end):
            raise ValueError('protected code must contain the envelope fragment and publisher')
        if max(protected_start, receipt.NATIVE_RX[0]) < min(protected_end, receipt.NATIVE_RX[1]):
            raise ValueError('protected code overlaps pinned native RX')
        for name, address, size in extents:
            if max(protected_start, address) < min(protected_end, address + size):
                raise ValueError('protected code overlaps ' + name)

    a = Asm(code_base)
    end_fixups = []
    protected = [*extents, ('native RX', receipt.NATIVE_RX[0],
                           receipt.NATIVE_RX[1] - receipt.NATIVE_RX[0]),
                 ('publish entry', publish_entry, 4),
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

    def extent(pointer, last, size):
        a.branch(4, pointer, 0, 'early_denied')
        a.e(b.i_type(12, pointer, 8, 3))
        a.branch(5, 8, 0, 'early_denied')
        a.e(b.addiu(last, pointer, size - 1), b.r_type(last, pointer, 8, 0x2B))
        a.branch(5, 8, 0, 'early_denied')

    def nonoverlap(first, last, start, end, label):
        # Inclusive endpoints admit a valid extent ending exactly at2**32.
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
        a.jump('early_denied')
        a.label(label)

    def disjoint(first, last, other_first, other_last, label):
        a.e(b.r_type(last, other_first, 8, 0x2B))
        a.branch(5, 8, 0, label)
        a.e(b.r_type(other_last, first, 8, 0x2B))
        a.branch(4, 8, 0, 'early_denied')
        a.label(label)

    def preflight(name, *, packing):
        a.label(name)
        equal(4, controller_address, 'early_denied')
        a.e(b.i_type(12, 29, 8, 7))
        a.branch(5, 8, 0, 'early_denied')
        a.e(b.i_type(11, 29, 8, FRAME))
        a.branch(5, 8, 0, 'early_denied')
        if packing:
            extent(5, 13, CAPTURE_BYTES)
            extent(6, 14, PAYLOAD_BYTES)
            extent(7, 15, ENVELOPE_BYTES)
            spans = [('capture', 5, 13), ('payload', 6, 14), ('output', 7, 15)]
        else:
            extent(5, 13, ENVELOPE_BYTES)
            spans = [('input', 5, 13)]
        a.e(b.addiu(11, 29, -FRAME), b.addiu(12, 29, -1))
        spans.append(('frame', 11, 12))
        for index, (_, address, size) in enumerate(protected):
            end = None if size is None else address + size
            for prefix, first, last in spans:
                nonoverlap(first, last, address, end,
                           name + '_' + prefix + '_extent_' + str(index))
        for index, (prefix, first, last) in enumerate(spans):
            for other_prefix, other_first, other_last in spans[index + 1:]:
                disjoint(first, last, other_first, other_last,
                         name + '_' + prefix + '_' + other_prefix + '_ok')

    def save(output_or_input):
        a.e(b.addiu(29, 29, -FRAME))
        for register, offset in SAVE.items():
            a.e(b.sw(register, offset, 29))
        a.e(b.r_type(0, 0, 8, 0x10), b.sw(8, HI, 29),
            b.r_type(0, 0, 8, 0x12), b.sw(8, LO, 29),
            b.move(17, output_or_input),
            b.sw(0, RESULT, 29), b.sw(0, RAW, 29))

    def schema():
        for offset, expected in ((MAGIC, READY_MAGIC),
                                 (FLAGS, REGISTRY_RELEASE_OBSERVED),
                                 (CONTROLLER, controller_address), (NATIVE_RESULT, 0)):
            a.e(b.lw(8, COPY + offset, 29))
            equal(8, expected, 'restore')
        for offset, limit in ((BINDING_SEQUENCE, capacity), (OWNER, ticket_limit),
                              (RECEIPT_SEQUENCE, capacity)):
            a.e(b.lw(14, COPY + offset, 29))
            bounded(14, limit, 'restore')
        a.e(b.lw(8, COPY + ENGINE, 29), b.lw(9, COPY + PAYLOAD + 8, 29))
        a.branch(5, 8, 9, 'restore')

    preflight('pack', packing=True)
    # Exclusively owned output is write-once, and no source is read before
    # this first complete zero check. Recheck after the private snapshot.
    for offset in range(0, ENVELOPE_BYTES, 4):
        a.e(b.lw(8, offset, 7))
        a.branch(5, 8, 0, 'early_denied')
    save(7)
    for offset in range(0, CAPTURE_BYTES, 4):
        a.e(b.lw(8, offset, 5), b.sw(8, COPY + offset, 29))
    for offset in range(0, PAYLOAD_BYTES, 4):
        a.e(b.lw(8, offset, 6), b.sw(8, COPY + PAYLOAD + offset, 29))
    schema()
    for offset in range(0, ENVELOPE_BYTES, 4):
        a.e(b.lw(8, offset, 17))
        a.branch(5, 8, 0, 'restore')
    for offset in range(4, ENVELOPE_BYTES, 4):
        a.e(b.lw(8, COPY + offset, 29), b.sw(8, offset, 17))
    a.e(SYNC)
    a.absolute(8, READY_MAGIC)
    a.e(b.sw(8, MAGIC, 17), SYNC, b.sw(17, RESULT, 29))
    a.jump('restore')

    preflight('dispatch', packing=False)
    save(5)
    for offset in range(0, ENVELOPE_BYTES, 4):
        a.e(b.lw(8, offset, 5), b.sw(8, COPY + offset, 29))
    schema()
    # This is an exclusive private-envelope transition, not a shared latch
    # under an invented guard. It happens BEFORE any publication/raw service;
    # even ordinary backpressure consumes this one attempt without retry.
    a.absolute(8, CONSUMED_MAGIC)
    a.e(b.sw(8, MAGIC, 17), SYNC)
    a.absolute(4, controller_address)
    a.e(b.addiu(5, 29, COPY + PAYLOAD),
        b.lw(6, COPY + BINDING_SEQUENCE, 29), b.lw(7, COPY + OWNER, 29))
    a.absolute(25, publish_entry)
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
        raise ValueError('envelope fragment leaves the native jump region')
    if protected_end is not None and code_end > protected_end:
        raise ValueError('protected code does not contain the complete envelope fragment')
    if max(code_base, receipt.NATIVE_RX[0]) < min(code_end, receipt.NATIVE_RX[1]):
        raise ValueError('envelope fragment overlaps pinned native RX')
    if code_base <= publish_entry < code_end:
        raise ValueError('envelope fragment overlaps publish entry')
    for name, address, size in extents:
        if max(code_base, address) < min(code_end, address + size):
            raise ValueError('envelope fragment overlaps ' + name)
    for index in end_fixups:
        value = code_end - 1
        a.w[index:index + 2] = (b.lui(10, value >> 16), b.ori(10, 10, value & 0xFFFF))
    return a.finish(), a.labels
