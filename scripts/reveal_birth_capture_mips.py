#!/usr/bin/env python3
"""Owned per-invocation birth diagnostics, never native lifetime authority.

register_birth(U, descriptor20, zero_out48) calls the existing checked creation
capture exactly once.  An optional lifecycle post-commit callback hands the
just-minted token directly to this invocation's private frame.  There is no
lookup by node, engine, name, current address or latest history row.

BCAP48 contains magic, token, the exact owned32 birth event, native result zero
and observed raw registry-release status zero.  It is separate from GCAP: no
owner/paint success, complete lifecycle coverage, incarnation liveness, lease,
retry/free permission or native cleanup is implied.  Receipt/binding/owner
refusal can therefore coexist with a valid historical BCAP after raw R release
zero.  A missing/faulted lifecycle observation exports nothing.

After checked capture returns, only the private wrapper frame and the exclusive
output are accessed.  A nonzero checked result preserves V0/V1 and performs no
output access at all.  The callback saves all GPRs and HI/LO before validation;
that initial writable192-byte frame, every transitive native stack, stable code,
coherent hooks and retained nonaliasing storage remain independent premises.
Arithmetic bounds and scalar stack tags do not authenticate fabricated calls.
No installer, image, device operation or native-lifetime repair is provided.
"""

from build_reveal_bridge_diag import Asm, b
import reveal_creation_capture_mips as capture
import reveal_registry_lifecycle_mips as lifecycle
import reveal_registry_owner_mips as bindings
import reveal_registry_receipt_mips as receipt
import reveal_paint_retirement_mips as owners


MAX_TICKET = owners.MAX_TICKET
OUTPUT_BYTES, DESCRIPTOR_BYTES = 48, capture.DESCRIPTOR_BYTES
OUTPUT_MAGIC = int.from_bytes(b'BCAP', 'little')
OUTPUT_TOKEN, OUTPUT_EVENT = 4, 8
OUTPUT_NATIVE_RESULT, OUTPUT_RELEASE_STATUS = 40, 44
FRAME, GCAP, DESCRIPTOR, OUTPUT_PTR = 192, 0x10, 0x30, 0x44
CONTROLLER, TAG, TOKEN, EVENT = 0x48, 0x4C, 0x50, 0x54
NATIVE_RESULT, RETURN_V1, EXPORTED_PTR = 0x74, 0x78, 0x7C
HI, LO, SYNC = 0x80, 0x84, 0xF
ARMED = int.from_bytes(b'BCAR', 'little')
CONSUMED = int.from_bytes(b'BCCN', 'little')
CAPTURED = int.from_bytes(b'BCCP', 'little')
INVALID = int.from_bytes(b'BCIV', 'little')
SAVE = {register: 0x88 + index * 4
        for index, register in enumerate((*range(16, 24), 28, 30, 31))}
SINK_FRAME, SINK_HI, SINK_LO = 192, 0x88, 0x8C
SINK_SAVE = {register: 0x10 + index * 4
             for index, register in enumerate(r for r in range(1, 32) if r != 29)}


def assemble(receipt_address, binding_address, owner_address, controller_address,
             registry_mutex_address, paint_mutex_address, lifecycle_address,
             code_base, register_entry, native_return, *, capacity=16,
             lifecycle_capacity=16, owner_capacity=16,
             ticket_limit=MAX_TICKET, protected_code=None,
             extra_protected_data=()):
    """Return the standalone wrapper and all-register-preserving sink.

    register_entry/native_return must be the actual register/return labels of
    the coherent checked creation capture.  The composer, not arbitrary address
    values, establishes that mode and wires the lifecycle's post-commit sink.
    protected_code=(start,bytes) contains this fragment and both capture labels;
    None excludes only this fragment plus the two named external entry words.
    Both modes have identical instruction counts for two-pass composition.
    Optional extra_protected_data excludes additional fixed data from this
    fragment's guards. Empty preserves preceding bytes/labels; mapping and
    all unknown native/heap/transitive-stack nonaliasing remain premises.
    """
    extents = [('receipt', receipt_address, receipt.memory_bytes(capacity)),
               ('bindings', binding_address, bindings.memory_bytes(capacity)),
               ('owners', owner_address, owners.memory_bytes(owner_capacity)),
               ('controller', controller_address, receipt.CONTROLLER_BYTES),
               ('registry mutex', registry_mutex_address, receipt.MUTEX_BYTES),
               ('paint mutex', paint_mutex_address, receipt.MUTEX_BYTES),
               ('lifecycle history', lifecycle_address,
                lifecycle.memory_bytes(lifecycle_capacity))]
    if (type(extra_protected_data) is not tuple
            or any(type(extent) is not tuple or len(extent) != 2
                   or any(type(value) is not int for value in extent)
                   or extent[1] <= 0 or extent[1] % 4
                   for extent in extra_protected_data)):
        raise ValueError('extra protected data must be a tuple of aligned extents')
    extents.extend(('extra data ' + str(index), start, size)
                   for index, (start, size) in enumerate(extra_protected_data))
    if type(ticket_limit) is not int or not 1 <= ticket_limit <= MAX_TICKET:
        raise ValueError('ticket limit must be a positive signed word')
    for name, address, size in (*extents, ('code', code_base, 4),
                                 ('register entry', register_entry, 4),
                                 ('native return', native_return, 4)):
        if (type(address) is not int or not 0 < address <= 0xFFFFFFFC
                or address % 4 or address + size > 0x100000000):
            raise ValueError(name + ' must have a nonwrapping aligned extent')
    if code_base >> 28 or register_entry >> 28 or native_return >> 28:
        raise ValueError('birth capture and capture labels need native jump region')
    if register_entry == native_return:
        raise ValueError('register entry and native return must be distinct')
    for index, (name, address, size) in enumerate(extents):
        if max(address, receipt.NATIVE_RX[0]) < min(address + size, receipt.NATIVE_RX[1]):
            raise ValueError(name + ' overlaps pinned native RX')
        for other_name, other, other_size in extents[index + 1:]:
            if max(address, other) < min(address + size, other + other_size):
                raise ValueError(name + ' overlaps ' + other_name)
        for label, entry in (('register entry', register_entry),
                             ('native return', native_return)):
            if address <= entry < address + size:
                raise ValueError(label + ' overlaps ' + name)
    for label, entry in (('register entry', register_entry),
                         ('native return', native_return)):
        if receipt.NATIVE_RX[0] <= entry < receipt.NATIVE_RX[1]:
            raise ValueError(label + ' overlaps pinned native RX')

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
                or not protected_start <= register_entry < protected_end
                or not protected_start <= native_return < protected_end):
            raise ValueError('protected code must contain fragment and capture labels')
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
                 ('native return', native_return, 4),
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
            nonoverlap(first, last, address, None if size is None else address + size,
                       failed, prefix + '_extent_' + str(index))

    a.label('register_birth')
    equal(4, controller_address, 'early_denied')
    a.e(b.i_type(12, 29, 8, 7))
    a.branch(5, 8, 0, 'early_denied')
    a.e(b.i_type(11, 29, 8, FRAME))
    a.branch(5, 8, 0, 'early_denied')
    extent(5, 13, DESCRIPTOR_BYTES, 'early_denied')
    extent(6, 14, OUTPUT_BYTES, 'early_denied')
    a.e(b.addiu(11, 29, -FRAME), b.addiu(12, 29, -1))
    exclusions(11, 12, 'early_denied', 'frame')
    exclusions(5, 13, 'early_denied', 'descriptor')
    exclusions(6, 14, 'early_denied', 'output')
    disjoint(5, 13, 6, 14, 'early_denied', 'descriptor_output_ok')
    disjoint(5, 13, 11, 12, 'early_denied', 'descriptor_frame_ok')
    disjoint(6, 14, 11, 12, 'early_denied', 'output_frame_ok')
    for offset in range(0, OUTPUT_BYTES, 4):
        a.e(b.lw(8, offset, 6))
        a.branch(5, 8, 0, 'early_denied')
    a.e(b.addiu(29, 29, -FRAME))
    for register, offset in SAVE.items():
        a.e(b.sw(register, offset, 29))
    a.e(b.r_type(0, 0, 8, 0x10), b.sw(8, HI, 29),
        b.r_type(0, 0, 8, 0x12), b.sw(8, LO, 29),
        b.sw(4, CONTROLLER, 29), b.sw(6, OUTPUT_PTR, 29))
    for offset in (*range(GCAP, GCAP + capture.OUTPUT_BYTES, 4), TOKEN,
                   *range(EVENT, EVENT + lifecycle.REQUEST_BYTES, 4), EXPORTED_PTR):
        a.e(b.sw(0, offset, 29))
    a.absolute(8, ARMED)
    a.e(b.sw(8, TAG, 29))
    for offset in range(0, DESCRIPTOR_BYTES, 4):
        a.e(b.lw(8, offset, 5), b.sw(8, DESCRIPTOR + offset, 29))
    a.absolute(4, controller_address)
    a.e(b.addiu(5, 29, DESCRIPTOR), b.addiu(6, 29, GCAP))
    a.label('capture_call')
    a.jump(register_entry, link=True)
    a.label('capture_return')
    # No native/shared data or calls occur below this continuation. In
    # particular a checked error touches no output word, including reads.
    a.e(b.sw(2, NATIVE_RESULT, 29), b.sw(3, RETURN_V1, 29))
    a.branch(5, 2, 0, 'restore')
    a.e(b.sw(0, RETURN_V1, 29))
    a.branch(4, 3, 0, 'capture_pointer_ok')
    a.e(b.addiu(9, 29, GCAP))
    a.branch(5, 3, 9, 'restore')
    a.label('capture_pointer_ok')
    a.e(b.lw(8, TAG, 29))
    equal(8, CAPTURED, 'restore')
    a.e(b.lw(8, CONTROLLER, 29))
    equal(8, controller_address, 'restore')
    a.e(b.lw(14, TOKEN, 29))
    bounded(14, lifecycle_capacity, 'restore')
    for offset, expected in ((lifecycle.REQUEST_CONTROLLER, controller_address),
                             (lifecycle.REQUEST_REGISTRY_MUTEX, registry_mutex_address),
                             (lifecycle.REQUEST_CALLER, native_return),
                             (lifecycle.REQUEST_SITE, lifecycle.PUBLICATION_SITE),
                             (lifecycle.REQUEST_RAW_STATUS, 0)):
        a.e(b.lw(8, EVENT + offset, 29))
        equal(8, expected, 'restore')
    a.e(b.lw(8, EVENT + lifecycle.REQUEST_ENGINE, 29),
        b.lw(9, DESCRIPTOR, 29))
    a.branch(5, 8, 9, 'restore')
    a.e(b.lw(16, OUTPUT_PTR, 29))
    for offset in range(0, OUTPUT_BYTES, 4):
        a.e(b.lw(8, offset, 16))
        a.branch(5, 8, 0, 'restore')
    a.e(b.sw(14, OUTPUT_TOKEN, 16))
    for offset in range(0, lifecycle.REQUEST_BYTES, 4):
        a.e(b.lw(8, EVENT + offset, 29), b.sw(8, OUTPUT_EVENT + offset, 16))
    a.e(b.sw(0, OUTPUT_NATIVE_RESULT, 16), b.sw(0, OUTPUT_RELEASE_STATUS, 16), SYNC)
    a.absolute(8, OUTPUT_MAGIC)
    a.e(b.sw(8, 0, 16), SYNC, b.sw(16, EXPORTED_PTR, 29),
        b.sw(16, RETURN_V1, 29))
    a.label('restore')
    a.e(b.lw(8, HI, 29), b.r_type(8, 0, 0, 0x11),
        b.lw(8, LO, 29), b.r_type(8, 0, 0, 0x13))
    for register, offset in SAVE.items():
        a.e(b.lw(register, offset, 29))
    a.e(b.lw(2, NATIVE_RESULT, 29), b.lw(3, RETURN_V1, 29),
        b.addiu(29, 29, FRAME), b.r_type(31, 0, 0, 8), 0)
    a.label('early_denied')
    a.e(b.addiu(2, 0, -1), b.move(3, 0), b.r_type(31, 0, 0, 8), 0)

    a.label('birth_sink')
    a.e(b.addiu(29, 29, -SINK_FRAME))
    for register, offset in SINK_SAVE.items():
        a.e(b.sw(register, offset, 29))
    a.e(b.r_type(0, 0, 8, 0x10), b.sw(8, SINK_HI, 29),
        b.r_type(0, 0, 8, 0x12), b.sw(8, SINK_LO, 29),
        b.addiu(23, 29, SINK_FRAME), b.move(18, 6))
    equal(4, controller_address, 'birth_sink_restore')
    bounded(18, lifecycle_capacity, 'birth_sink_restore')
    a.e(b.i_type(12, 23, 8, 7))
    a.branch(5, 8, 0, 'birth_sink_restore')
    a.e(b.i_type(11, 23, 8, SINK_FRAME))
    a.branch(5, 8, 0, 'birth_sink_restore')
    a.e(b.addiu(12, 23, -1))
    exclusions(29, 12, 'birth_sink_restore', 'sink_frame')
    # L is the actual lifecycle callback frame, not an arbitrary event source.
    extent(23, 15, lifecycle.FRAME, 'birth_sink_restore')
    exclusions(23, 15, 'birth_sink_restore', 'lifecycle_frame')
    a.e(b.addiu(21, 23, lifecycle.SNAPSHOT), b.r_type(21, 23, 8, 0x2B))
    a.branch(5, 8, 0, 'birth_sink_restore')
    a.branch(5, 5, 21, 'birth_sink_restore')
    extent(5, 14, lifecycle.REQUEST_BYTES, 'birth_sink_restore')
    exclusions(5, 14, 'birth_sink_restore', 'sink_event')
    disjoint(5, 14, 29, 12, 'birth_sink_restore', 'event_sink_frame_ok')
    for offset, expected in ((lifecycle.REQUEST_CONTROLLER, controller_address),
                             (lifecycle.REQUEST_REGISTRY_MUTEX, registry_mutex_address),
                             (lifecycle.REQUEST_CALLER, native_return),
                             (lifecycle.REQUEST_SITE, lifecycle.PUBLICATION_SITE),
                             (lifecycle.REQUEST_RAW_STATUS, 0)):
        a.e(b.lw(8, offset, 5))
        equal(8, expected, 'birth_sink_restore')
    # The coherent route is sink -> L192 -> receipt192 -> native N40 ->
    # checked capture C160 -> this outer W192. Gate each complete extent and
    # saved continuation before following the next outer private frame.
    a.e(b.addiu(22, 23, lifecycle.FRAME + receipt.FRAME),
        b.r_type(22, 23, 8, 0x2B))
    a.branch(5, 8, 0, 'birth_sink_restore')
    extent(22, 15, capture.NATIVE_FRAME, 'birth_sink_restore')
    exclusions(22, 15, 'birth_sink_restore', 'native_frame')
    a.e(b.lw(8, lifecycle.REQUEST_NATIVE_SP, 5))
    a.branch(5, 8, 22, 'birth_sink_restore')
    a.e(b.lw(8, 0x24, 22))
    equal(8, native_return, 'birth_sink_restore')
    a.e(b.addiu(17, 22, capture.NATIVE_FRAME), b.r_type(17, 22, 8, 0x2B))
    a.branch(5, 8, 0, 'birth_sink_restore')
    extent(17, 15, capture.FRAME, 'birth_sink_restore')
    exclusions(17, 15, 'birth_sink_restore', 'capture_frame')
    a.e(b.lw(8, capture.SAVE[31], 17))
    return_fixups.append(len(a.w))
    a.absolute(9, 0)
    a.branch(5, 8, 9, 'birth_sink_restore')
    for offset, expected in ((capture.PINNED_U, controller_address),
                             (capture.ARMED_TAG, capture.ARMED),
                             (capture.RELEASE_TAG, capture.RELEASE_ARMED)):
        a.e(b.lw(8, offset, 17))
        equal(8, expected, 'birth_sink_restore')
    a.e(b.addiu(16, 17, capture.FRAME), b.r_type(16, 17, 8, 0x2B))
    a.branch(5, 8, 0, 'birth_sink_restore')
    extent(16, 15, FRAME, 'birth_sink_restore')
    exclusions(16, 15, 'birth_sink_restore', 'outer_frame')
    disjoint(16, 15, 29, 12, 'birth_sink_restore', 'outer_sink_frame_ok')
    disjoint(16, 15, 5, 14, 'birth_sink_restore', 'outer_event_ok')
    a.e(b.lw(8, capture.OUTPUT_PTR, 17), b.addiu(9, 16, GCAP))
    a.branch(5, 8, 9, 'birth_sink_restore')
    a.e(b.lw(8, capture.DESCRIPTOR, 17), b.lw(9, lifecycle.REQUEST_ENGINE, 5))
    a.branch(5, 8, 9, 'birth_sink_restore')
    a.e(b.lw(8, CONTROLLER, 16))
    equal(8, controller_address, 'birth_sink_restore')
    a.e(b.lw(8, DESCRIPTOR, 16), b.lw(9, lifecycle.REQUEST_ENGINE, 5))
    a.branch(5, 8, 9, 'birth_sink_restore')
    a.e(b.lw(8, TAG, 16))
    equal(8, ARMED, 'birth_sink_invalid')
    for offset in (TOKEN, *range(EVENT, EVENT + lifecycle.REQUEST_BYTES, 4)):
        a.e(b.lw(8, offset, 16))
        a.branch(5, 8, 0, 'birth_sink_invalid')
    a.absolute(8, CONSUMED)
    a.e(b.sw(8, TAG, 16), b.sw(18, TOKEN, 16))
    for offset in range(0, lifecycle.REQUEST_BYTES, 4):
        a.e(b.lw(8, offset, 5), b.sw(8, EVENT + offset, 16))
    a.e(SYNC)
    a.absolute(8, CAPTURED)
    a.e(b.sw(8, TAG, 16), SYNC)
    a.jump('birth_sink_restore')
    a.label('birth_sink_invalid')
    # Only a fully scope-verified W reaches this poison. Never overwrite or
    # remint its first token/event on duplicate or dirty private delivery.
    a.absolute(8, INVALID)
    a.e(b.sw(8, TAG, 16))
    a.label('birth_sink_restore')
    a.e(b.lw(8, SINK_HI, 29), b.r_type(8, 0, 0, 0x11),
        b.lw(8, SINK_LO, 29), b.r_type(8, 0, 0, 0x13))
    for register, offset in SINK_SAVE.items():
        a.e(b.lw(register, offset, 29))
    a.e(b.addiu(29, 29, SINK_FRAME), b.r_type(31, 0, 0, 8), 0)

    code_end = code_base + len(a.w) * 4
    if code_end > 0x10000000:
        raise ValueError('birth capture leaves the native jump region')
    if protected_end is not None and code_end > protected_end:
        raise ValueError('protected code does not contain complete birth capture')
    for label, entry in (('register entry', register_entry),
                         ('native return', native_return)):
        if code_base <= entry < code_end:
            raise ValueError('birth capture overlaps ' + label)
    if max(code_base, receipt.NATIVE_RX[0]) < min(code_end, receipt.NATIVE_RX[1]):
        raise ValueError('birth capture overlaps pinned native RX')
    for name, address, size in extents:
        if max(code_base, address) < min(code_end, address + size):
            raise ValueError('birth capture overlaps ' + name)
    for word_index in end_fixups:
        value = code_end - 1
        a.w[word_index:word_index + 2] = (b.lui(10, value >> 16),
                                       b.ori(10, 10, value & 0xFFFF))
    for word_index in return_fixups:
        value = a.labels['capture_return']
        a.w[word_index:word_index + 2] = (b.lui(9, value >> 16),
                                       b.ori(9, 9, value & 0xFFFF))
    return a.finish(), a.labels
