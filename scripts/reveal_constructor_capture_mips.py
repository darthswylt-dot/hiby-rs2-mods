#!/usr/bin/env python3
"""Local diagnostic capture around the first native explorer constructor.

construct(U, request12, out48) snapshots three owned request words: a mutable
native descriptor104 pointer, callback and callback context. It invokes actual
43AD00 once. A coherent redirect of its one registration call binds a checked
historical GCAP to this exact outer invocation, without lookup by name, engine
address or latest table row. The native constructor and every continuation,
including its NULL/error/UI behavior, are unchanged. This is NOT safe native
admission, error isolation, an engine lease, retry/free authority or installation.

The descriptor is independently coherent, exclusive, mapped and retained for
the whole native call. Its first64 bytes contain NUL; its full104 bytes remain
mutable because native code writes descriptor+5C. All nested native/import
stacks and object lifetimes remain caller premises. Arithmetic gates only cover
the named extents; scalar stack tags do not authenticate fabricated invocations.

No output is written before the actual constructor returns. Exported diagnostics
preserve its actual V0, and the observed registration's actual V0/V1. A positive
record has exact checked GCAP32 followed by native engine, register V0/V1 and
witness flags3. Otherwise the first32 bytes are zero except CNFL, with witness
REG_SEEN only if the bridge actually returned. The captured register V1 is merely a
diagnostic scalar, not a retained pointer. A second dirty-output check suppresses
the entire export. No call or shared/native-object read occurs after return.
"""

from build_reveal_bridge_diag import Asm, b
import reveal_creation_capture_mips as capture
import reveal_registry_owner_mips as bindings
import reveal_registry_receipt_mips as receipt
import reveal_paint_retirement_mips as owners


MAX_TICKET = owners.MAX_TICKET
NATIVE_CONSTRUCT, NATIVE_REGISTER = 0x43AD00, 0x4389E0
NATIVE_FRAME, NATIVE_DESCRIPTOR, NATIVE_SAVED_RA = 136, 0x50, 0x84
REGISTER_SITE, REGISTER_CONTINUATION = 0x43AE8C, 0x43AE94
REQUEST_BYTES, DESCRIPTOR_BYTES, OUTPUT_BYTES = 12, 104, 48
OUTPUT_NATIVE_ENGINE, OUTPUT_REGISTER_V0 = 32, 36
OUTPUT_REGISTER_V1, OUTPUT_WITNESS_FLAGS = 40, 44
REG_SEEN, MATCHED_CAPTURE = 1, 2
DIAGNOSTIC_MAGIC = int.from_bytes(b'CNFL', 'little')
FRAME, CAPTURE, REQUEST, OUTPUT_PTR = 256, 0x10, 0x30, 0x3C
NATIVE_ENGINE, REGISTER_V0, REGISTER_V1 = 0x40, 0x44, 0x48
TAG, PINNED_U, WITNESS_FLAGS, EXPORTED_PTR = 0x4C, 0x50, 0x54, 0x58
HI, LO, SYNC = 0x5C, 0x60, 0xF
ARMED = int.from_bytes(b'CCAR', 'little')
ENTERED = int.from_bytes(b'CCEN', 'little')
RETURNED = int.from_bytes(b'CCRT', 'little')
INVALID = int.from_bytes(b'CCIV', 'little')
SAVE = {register: 0x64 + index * 4
        for index, register in enumerate((*range(16, 24), 28, 30, 31))}
BRIDGE_FRAME, BRIDGE_HI, BRIDGE_LO = 160, 0x10, 0x14
BRIDGE_SAVE = {register: 0x18 + index * 4
               for index, register in enumerate((*range(16, 24), 28, 30, 31))}
HOOKS = {'register_bridge': (REGISTER_SITE, (0x0C10E278, 0x27A50050))}


def hook_words(labels):
    """Return this single coherent local fetch override, never install it."""
    target = labels.get('register_bridge')
    if (type(target) is not int or not 0 < target <= 0xFFFFFFFC or target % 4
            or (REGISTER_SITE + 4) >> 28 != target >> 28):
        raise ValueError('constructor bridge must share the native jump region')
    return {REGISTER_SITE: (b.j_type(3, target), 0x27A50050)}


def assemble(receipt_address, binding_address, owner_address, controller_address,
             registry_mutex_address, paint_mutex_address, code_base,
             register_entry, *, capacity=16, owner_capacity=16,
             ticket_limit=MAX_TICKET, protected_code=None, protected_data=()):
    """Return diagnostic wrapper/bridge bytes and labels without I/O.

    register_entry must be the actual checked creation-capture entry in the
    coherent seven-hook receipt/release composition. This fragment adds only
    the constructor's registration-call redirect. A composer verifies the
    checked-mode route; this assembler cannot certify an arbitrary code word.

    protected_code=(start,bytes) contains this entire fragment and register
    entry. None knows only this fragment plus that entry word; exclusion of the
    rest of its RX is a caller premise. protected_data is a strict tuple of
    additional (start,bytes) exclusions, e.g. separate queue56/mutex24/fault4.
    Both RX modes emit identical word counts for two-pass composition.
    """
    extents = [('receipt', receipt_address, receipt.memory_bytes(capacity)),
               ('bindings', binding_address, bindings.memory_bytes(capacity)),
               ('owners', owner_address, owners.memory_bytes(owner_capacity)),
               ('controller', controller_address, receipt.CONTROLLER_BYTES),
               ('registry mutex', registry_mutex_address, receipt.MUTEX_BYTES),
               ('paint mutex', paint_mutex_address, receipt.MUTEX_BYTES)]
    if type(ticket_limit) is not int or not 1 <= ticket_limit <= MAX_TICKET:
        raise ValueError('ticket limit must be a positive signed word')
    if type(protected_data) is not tuple:
        raise ValueError('protected data must be a tuple of aligned extents')
    for index, item in enumerate(protected_data):
        if (type(item) is not tuple or len(item) != 2
                or any(type(value) is not int for value in item)):
            raise ValueError('protected data must contain (start,bytes) tuples')
        start, size = item
        if size <= 0 or size % 4:
            raise ValueError('protected data sizes must be positive aligned words')
        extents.append(('extra data ' + str(index), start, size))
    for name, address, size in (*extents, ('code', code_base, 4),
                                 ('register entry', register_entry, 4)):
        if (type(address) is not int or not 0 < address <= 0xFFFFFFFC
                or address % 4 or address + size > 0x100000000):
            raise ValueError(name + ' must have a nonwrapping aligned extent')
    if code_base >> 28 or register_entry >> 28:
        raise ValueError('constructor capture and register entry need native jump region')
    for index, (name, address, size) in enumerate(extents):
        if max(address, receipt.NATIVE_RX[0]) < min(address + size, receipt.NATIVE_RX[1]):
            raise ValueError(name + ' overlaps pinned native RX')
        for other_name, other, other_size in extents[index + 1:]:
            if max(address, other) < min(address + size, other + other_size):
                raise ValueError(name + ' overlaps ' + other_name)
        if address <= register_entry < address + size:
            raise ValueError('register entry overlaps ' + name)
    if receipt.NATIVE_RX[0] <= register_entry < receipt.NATIVE_RX[1]:
        raise ValueError('register entry overlaps pinned native RX')
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
                or not protected_start <= register_entry
                or register_entry + 4 > protected_end):
            raise ValueError('protected code must contain fragment and register entry')
        if max(protected_start, receipt.NATIVE_RX[0]) < min(protected_end, receipt.NATIVE_RX[1]):
            raise ValueError('protected code overlaps pinned native RX')
        for name, address, size in extents:
            if max(protected_start, address) < min(protected_end, address + size):
                raise ValueError('protected code overlaps ' + name)

    a = Asm(code_base)
    end_fixups, return_fixups = [], []
    protected = [*extents,
                 ('native RX', receipt.NATIVE_RX[0],
                  receipt.NATIVE_RX[1] - receipt.NATIVE_RX[0]),
                 ('register entry', register_entry, 4),
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

    def disjoint(first, last, other_first, other_last, failed, label):
        a.e(b.r_type(last, other_first, 8, 0x2B))
        a.branch(5, 8, 0, label)
        a.e(b.r_type(other_last, first, 8, 0x2B))
        a.branch(4, 8, 0, failed)
        a.label(label)

    def exclusions(first, last, failed, prefix):
        for index, (_, address, size) in enumerate(protected):
            nonoverlap(first, last, address,
                       None if size is None else address + size,
                       failed, prefix + '_extent_' + str(index))

    a.label('construct')
    equal(4, controller_address, 'early_denied')
    a.e(b.i_type(12, 29, 8, 7))
    a.branch(5, 8, 0, 'early_denied')
    a.e(b.i_type(11, 29, 8, FRAME))
    a.branch(5, 8, 0, 'early_denied')
    extent(5, 13, REQUEST_BYTES, 'early_denied')
    extent(6, 14, OUTPUT_BYTES, 'early_denied')
    a.e(b.addiu(11, 29, -FRAME), b.addiu(12, 29, -1))
    exclusions(11, 12, 'early_denied', 'frame')
    exclusions(5, 13, 'early_denied', 'request')
    exclusions(6, 14, 'early_denied', 'output')
    disjoint(5, 13, 6, 14, 'early_denied', 'request_output_ok')
    disjoint(5, 13, 11, 12, 'early_denied', 'request_frame_ok')
    disjoint(6, 14, 11, 12, 'early_denied', 'output_frame_ok')
    for offset in range(0, OUTPUT_BYTES, 4):
        a.e(b.lw(8, offset, 6))
        a.branch(5, 8, 0, 'early_denied')
    # The guarded request must be read to locate its independent descriptor.
    # No stack save, descriptor read or output store precedes these gates.
    a.e(b.lw(15, 0, 5))
    extent(15, 24, DESCRIPTOR_BYTES, 'early_denied')
    exclusions(15, 24, 'early_denied', 'descriptor')
    disjoint(15, 24, 5, 13, 'early_denied', 'descriptor_request_ok')
    disjoint(15, 24, 6, 14, 'early_denied', 'descriptor_output_ok')
    disjoint(15, 24, 11, 12, 'early_denied', 'descriptor_frame_ok')
    a.e(b.move(25, 15), b.addiu(13, 15, 64))
    a.label('name_scan')
    a.e(b.i_type(36, 25, 8, 0))
    a.branch(4, 8, 0, 'name_terminated')
    a.e(b.addiu(25, 25, 1))
    a.branch(5, 25, 13, 'name_scan')
    a.jump('early_denied')
    a.label('name_terminated')
    a.e(b.addiu(29, 29, -FRAME))
    for register, offset in SAVE.items():
        a.e(b.sw(register, offset, 29))
    a.e(b.r_type(0, 0, 8, 0x10), b.sw(8, HI, 29),
        b.r_type(0, 0, 8, 0x12), b.sw(8, LO, 29),
        b.sw(4, PINNED_U, 29), b.sw(6, OUTPUT_PTR, 29))
    for offset in (*range(CAPTURE, CAPTURE + capture.OUTPUT_BYTES, 4),
                   REGISTER_V0, REGISTER_V1, WITNESS_FLAGS, EXPORTED_PTR):
        a.e(b.sw(0, offset, 29))
    a.absolute(8, ARMED)
    a.e(b.sw(8, TAG, 29))
    # Retain the exact descriptor pointer whose full extent/name was guarded;
    # do not reread request+0 into an unchecked native argument.
    a.e(b.sw(15, REQUEST, 29))
    for offset in range(4, REQUEST_BYTES, 4):
        a.e(b.lw(8, offset, 5), b.sw(8, REQUEST + offset, 29))
    a.absolute(4, controller_address)
    a.e(b.lw(5, REQUEST, 29), b.lw(6, REQUEST + 4, 29),
        b.lw(7, REQUEST + 8, 29))
    a.label('native_call')
    a.jump(NATIVE_CONSTRUCT, link=True)
    a.label('native_return')
    # Only private frame/output accesses are emitted below this continuation.
    a.e(b.sw(2, NATIVE_ENGINE, 29), b.lw(16, OUTPUT_PTR, 29))
    for offset in range(0, OUTPUT_BYTES, 4):
        a.e(b.lw(8, offset, 16))
        a.branch(5, 8, 0, 'restore')
    a.e(b.lw(8, TAG, 29))
    equal(8, RETURNED, 'diagnostic_output')
    a.e(b.lw(8, WITNESS_FLAGS, 29))
    equal(8, REG_SEEN, 'diagnostic_output')
    a.e(b.lw(8, REGISTER_V0, 29))
    a.branch(5, 8, 0, 'diagnostic_output')
    a.e(b.lw(8, REGISTER_V1, 29), b.addiu(9, 29, CAPTURE))
    a.branch(5, 8, 9, 'diagnostic_output')
    for offset, expected in ((capture.MAGIC, capture.OUTPUT_MAGIC),
                             (capture.FLAGS, capture.REGISTRY_RELEASE_OBSERVED),
                             (capture.CONTROLLER, controller_address),
                             (capture.RESULT, 0)):
        a.e(b.lw(8, CAPTURE + offset, 29))
        equal(8, expected, 'diagnostic_output')
    a.e(b.lw(8, CAPTURE + capture.ENGINE, 29), b.lw(9, NATIVE_ENGINE, 29))
    a.branch(5, 8, 9, 'diagnostic_output')
    for offset, limit in ((capture.BINDING_SEQUENCE, capacity),
                          (capture.OWNER, ticket_limit),
                          (capture.RECEIPT_SEQUENCE, capacity)):
        a.e(b.lw(14, CAPTURE + offset, 29))
        bounded(14, limit, 'diagnostic_output')
    a.label('matched_output')
    for offset in range(4, capture.OUTPUT_BYTES, 4):
        a.e(b.lw(8, CAPTURE + offset, 29), b.sw(8, offset, 16))
    a.absolute(17, capture.OUTPUT_MAGIC)
    a.e(b.addiu(18, 0, REG_SEEN | MATCHED_CAPTURE))
    a.jump('output_tail')
    a.label('diagnostic_output')
    for offset in range(4, capture.OUTPUT_BYTES, 4):
        a.e(b.sw(0, offset, 16))
    a.absolute(17, DIAGNOSTIC_MAGIC)
    a.e(b.lw(18, WITNESS_FLAGS, 29), b.i_type(12, 18, 18, REG_SEEN))
    a.label('output_tail')
    for own, out in ((NATIVE_ENGINE, OUTPUT_NATIVE_ENGINE),
                     (REGISTER_V0, OUTPUT_REGISTER_V0),
                     (REGISTER_V1, OUTPUT_REGISTER_V1)):
        a.e(b.lw(8, own, 29), b.sw(8, out, 16))
    a.e(b.sw(18, OUTPUT_WITNESS_FLAGS, 16), SYNC,
        b.sw(17, capture.MAGIC, 16), SYNC, b.sw(16, EXPORTED_PTR, 29))
    a.label('restore')
    a.e(b.lw(8, HI, 29), b.r_type(8, 0, 0, 0x11),
        b.lw(8, LO, 29), b.r_type(8, 0, 0, 0x13),
        b.lw(2, NATIVE_ENGINE, 29), b.lw(3, EXPORTED_PTR, 29))
    for register, offset in SAVE.items():
        a.e(b.lw(register, offset, 29))
    a.e(b.addiu(29, 29, FRAME), b.r_type(31, 0, 0, 8), 0)
    a.label('early_denied')
    a.e(b.addiu(2, 0, -1), b.move(3, 0), b.r_type(31, 0, 0, 8), 0)

    a.label('register_bridge')
    # Legacy calls are forwarded with untouched SP/RA/A0..A3 and no new frame.
    equal(31, REGISTER_CONTINUATION, 'native_forward')
    equal(4, controller_address, 'native_forward')
    a.e(b.i_type(12, 29, 8, 7))
    a.branch(5, 8, 0, 'native_forward')
    a.e(b.move(11, 29))
    extent(11, 12, NATIVE_FRAME, 'native_forward')
    exclusions(11, 12, 'native_forward', 'bridge_native')
    a.e(b.addiu(13, 11, NATIVE_DESCRIPTOR))
    a.branch(5, 5, 13, 'native_forward')
    # Validate N completely, then its saved continuation, BEFORE outer W.
    a.e(b.lw(8, NATIVE_SAVED_RA, 11))
    return_fixups.append(len(a.w))
    a.absolute(9, 0)
    a.branch(5, 8, 9, 'native_forward')
    a.e(b.addiu(24, 11, NATIVE_FRAME), b.r_type(24, 11, 8, 0x2B))
    a.branch(5, 8, 0, 'native_forward')
    extent(24, 14, FRAME, 'native_forward')
    exclusions(24, 14, 'native_forward', 'bridge_outer')
    disjoint(11, 12, 24, 14, 'native_forward', 'native_outer_ok')
    a.e(b.i_type(11, 29, 8, BRIDGE_FRAME))
    a.branch(5, 8, 0, 'native_forward')
    a.e(b.addiu(13, 29, -BRIDGE_FRAME), b.addiu(15, 29, -1))
    exclusions(13, 15, 'native_forward', 'bridge_frame')
    # Outer mapping/retention is independent of these arithmetic scope gates.
    a.e(b.lw(8, PINNED_U, 24))
    equal(8, controller_address, 'native_forward')
    a.e(b.lw(8, TAG, 24))
    equal(8, ARMED, 'bridge_invalid')
    a.e(b.addiu(29, 29, -BRIDGE_FRAME))
    for register, offset in BRIDGE_SAVE.items():
        a.e(b.sw(register, offset, 29))
    a.e(b.r_type(0, 0, 8, 0x10), b.sw(8, BRIDGE_HI, 29),
        b.r_type(0, 0, 8, 0x12), b.sw(8, BRIDGE_LO, 29), b.move(16, 24))
    a.absolute(8, ENTERED)
    a.e(b.sw(8, TAG, 16), b.addiu(6, 16, CAPTURE))
    a.label('bridge_call')
    a.jump(register_entry, link=True)
    a.label('bridge_return')
    a.e(b.sw(2, REGISTER_V0, 16), b.sw(3, REGISTER_V1, 16),
        b.addiu(8, 0, REG_SEEN), b.sw(8, WITNESS_FLAGS, 16),
        b.lw(8, TAG, 16))
    equal(8, ENTERED, 'bridge_return_invalid')
    a.absolute(8, RETURNED)
    a.e(b.sw(8, TAG, 16))
    a.jump('bridge_restore')
    a.label('bridge_return_invalid')
    a.absolute(8, INVALID)
    a.e(b.sw(8, TAG, 16))
    a.label('bridge_restore')
    a.e(b.lw(8, BRIDGE_HI, 29), b.r_type(8, 0, 0, 0x11),
        b.lw(8, BRIDGE_LO, 29), b.r_type(8, 0, 0, 0x13))
    for register, offset in BRIDGE_SAVE.items():
        a.e(b.lw(register, offset, 29))
    a.e(b.addiu(29, 29, BRIDGE_FRAME), b.r_type(31, 0, 0, 8), 0)
    a.label('bridge_invalid')
    a.absolute(8, INVALID)
    a.e(b.sw(8, TAG, 24))
    a.label('native_forward')
    a.jump(NATIVE_REGISTER)

    code_end = code_base + len(a.w) * 4
    if code_end > 0x10000000:
        raise ValueError('constructor capture leaves the native jump region')
    if protected_end is not None and code_end > protected_end:
        raise ValueError('protected code does not contain the complete fragment')
    if code_base <= register_entry < code_end:
        raise ValueError('constructor capture overlaps register entry')
    if max(code_base, receipt.NATIVE_RX[0]) < min(code_end, receipt.NATIVE_RX[1]):
        raise ValueError('constructor capture overlaps pinned native RX')
    for name, address, size in extents:
        if max(code_base, address) < min(code_end, address + size):
            raise ValueError('constructor capture overlaps ' + name)
    for word_index in end_fixups:
        value = code_end - 1
        a.w[word_index:word_index + 2] = (b.lui(10, value >> 16),
                                       b.ori(10, 10, value & 0xFFFF))
    for word_index in return_fixups:
        value = a.labels['native_return']
        a.w[word_index:word_index + 2] = (b.lui(9, value >> 16),
                                       b.ori(9, 9, value & 0xFFFF))
    hook_words(a.labels)
    return a.finish(), a.labels
