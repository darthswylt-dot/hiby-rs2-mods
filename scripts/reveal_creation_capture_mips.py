#!/usr/bin/env python3
"""Offline per-invocation capture of a historical native issuance pair.

register(U, descriptor20, out32) calls actual4389E0 once using a private
descriptor snapshot. By default it returns the native result in v0 and out32
or zero in v1. Preflight denial is FFFFFFFF/zero without native execution. Its matching
all-register-preserving sink(U, owned36, sequence, owner) receives the actual
issuer event and writes only this wrapper invocation's private stack slots.
No native pointer/name/latest-row search or shared-table access occurs here.

By default a record explicitly means HISTORICAL_RELEASE_UNOBSERVED. Native
unlock masks its real status; even an ambiguous unlock can produce this
historical record. The optional checked mode instead needs three coherent
release observers and exports REGISTRY_RELEASE_OBSERVED only after the actual
same-invocation pinned raw release returned zero. It reports nonzero raw
release as FFFFFFFF/exact status, or a missing witness as FFFFFFFF/zero,
without writing the output. Neither flag is proof of initialized/retained
native objects, a lease, safe retry or cleanup.
Allocation failure still has the original missing-unlock defect. No recovery,
guessed unlock, remint, lifetime repair, image or device operation is provided.

Caller premises: genuine coherent receipt/issuer/callback route, independently
owned coherent descriptor/output, output exclusively write-once, retained
nonaliasing mapped stacks through all nested native/import calls, stable U and
mutex fields, real service semantics and all previous issuance prerequisites.
The sink and optional observers save all registers before validation: their
initial192-byte frame
validity/nonaliasing is a premise, not a denial-before-store guarantee. Scalar
scope checks do not authenticate arbitrary fabricated stack/request data.
"""

from build_reveal_bridge_diag import Asm, b
import reveal_registry_receipt_mips as receipt
import reveal_registry_owner_mips as issue
import reveal_paint_retirement_mips as owners


MAX_TICKET = owners.MAX_TICKET
NATIVE_REGISTER, NATIVE_FRAME, SYNC = 0x4389E0, 40, 0xF
OUTPUT_BYTES, DESCRIPTOR_BYTES = 32, 20
MAGIC, FLAGS, CONTROLLER, ENGINE = 0, 4, 8, 12
BINDING_SEQUENCE, OWNER, RECEIPT_SEQUENCE, RESULT = 16, 20, 24, 28
OUTPUT_MAGIC = int.from_bytes(b'GCAP', 'little')
HISTORICAL_RELEASE_UNOBSERVED = 1
REGISTRY_RELEASE_OBSERVED = 2
FRAME, DESCRIPTOR, OUTPUT_PTR, NATIVE_RESULT = 160, 0x10, 0x24, 0x28
ARMED_TAG, PINNED_U, CAPTURE_MAGIC = 0x2C, 0x30, 0x34
CAPTURE_BINDING_SEQUENCE, CAPTURE_OWNER = 0x38, 0x3C
CAPTURE_RECEIPT_SEQUENCE, CAPTURE_NODE = 0x40, 0x44
HI, LO, EXPORTED_PTR = 0x48, 0x4C, 0x74
ARMED, CONSUMED = int.from_bytes(b'GCAR', 'little'), int.from_bytes(b'GCCN', 'little')
CAPTURED = int.from_bytes(b'GCCP', 'little')
RELEASE_TAG, RELEASE_STATUS = 0x78, 0x7C
RELEASE_NATIVE_SP, RELEASE_RAW_SP, RELEASE_MUTEX = 0x80, 0x84, 0x88
RELEASE_ARMED = int.from_bytes(b'GRAR', 'little')
RELEASE_SELECTED = int.from_bytes(b'GRSL', 'little')
RELEASE_ENTERED = int.from_bytes(b'GREN', 'little')
RELEASE_CAPTURED = int.from_bytes(b'GRCP', 'little')
HOOKS = {
    'release_call': (0x438A60, (0x0320F809, 0x02002021)),
    'raw_release_call': (0x466DC8, (0x0C296E0C, 0)),
    'raw_release_return': (0x466DD0, (0x8FBF001C, 0x00001021)),
}
CAPTURE_FIELDS = (CAPTURE_MAGIC, CAPTURE_BINDING_SEQUENCE, CAPTURE_OWNER,
                  CAPTURE_RECEIPT_SEQUENCE, CAPTURE_NODE)
SAVE = {register: 0x50 + index * 4
        for index, register in enumerate((*range(16, 24), 31))}
SINK_FRAME, SINK_HI, SINK_LO = 192, 0x88, 0x8C
SINK_SAVE = {register: 0x10 + index * 4
             for index, register in enumerate(r for r in range(1, 32) if r != 29)}


def hook_words(labels):
    """Return checked-only local instruction-fetch overrides, not an installer.

    An unchecked fragment has no release labels and therefore no redirects.
    All three optional redirects must be coherent; partial activation is not
    a guarantee against arbitrary native-frame fabrication or stale state.
    """
    if not any(name in labels for name in HOOKS):
        return {}
    result = {}
    for name, (pc, _) in HOOKS.items():
        target = labels.get(name)
        if (type(target) is not int or target <= 0 or target % 4
                or target > 0xFFFFFFFC or (pc + 4) >> 28 != target >> 28):
            raise ValueError('release hook target must share its native jump region')
        result[pc] = (b.j_type(2, target), 0)
    return result


def assemble(receipt_address, binding_address, owner_address, controller_address,
             registry_mutex_address, paint_mutex_address, code_base, *,
             capacity=16, owner_capacity=16, ticket_limit=MAX_TICKET,
             protected_code=None, checked_registry_release=False,
             extra_protected_data=()):
    """Return standalone wrapper/sink bytes and labels without I/O.

    protected_code=(start, bytes) excludes the whole composed generated RX.
    If omitted, only this complete fragment is known. Both choices emit the
    same instruction count, permitting a composer to resolve the full extent
    in two passes. Complete nested-stack availability remains a premise.
    Optional extra_protected_data is a tuple of (start, bytes) fixed extents
    excluded by this fragment's frame/descriptor/output guards. Empty preserves
    preceding bytes/labels; it does not extend guards in other internal entries.

    The optional checked mode additionally requires the three coherent local
    release redirects. It returns FFFFFFFF/exact raw release status on an
    observed nonzero release, or FFFFFFFF/zero when no valid fresh release
    witness arrives. Only native-zero plus witnessed raw-zero may return an
    output pointer (flag REGISTRY_RELEASE_OBSERVED); denied owner issuance
    with witnessed raw-zero still returns zero/zero. No failed output is
    written. The default instruction bytes and labels remain unchanged.
    """
    if type(checked_registry_release) is not bool:
        raise ValueError('checked registry release must be a boolean')
    extents = [('receipt', receipt_address, receipt.memory_bytes(capacity)),
               ('bindings', binding_address, issue.memory_bytes(capacity)),
               ('owners', owner_address, owners.memory_bytes(owner_capacity)),
               ('controller', controller_address, receipt.CONTROLLER_BYTES),
               ('registry mutex', registry_mutex_address, receipt.MUTEX_BYTES),
               ('paint mutex', paint_mutex_address, receipt.MUTEX_BYTES)]
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
    for name, address, size in (*extents, ('code', code_base, 4)):
        if (type(address) is not int or not 0 < address <= 0xFFFFFFFC
                or address % 4 or address + size > 0x100000000):
            raise ValueError(name + ' must have a nonwrapping aligned extent')
    if code_base >> 28:
        raise ValueError('capture code must share the native jump region')
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
            raise ValueError('protected code must contain the native-region capture fragment')
        if max(protected_start, receipt.NATIVE_RX[0]) < min(protected_end, receipt.NATIVE_RX[1]):
            raise ValueError('protected code overlaps pinned native RX')
        for name, address, size in extents:
            if max(protected_start, address) < min(protected_end, address + size):
                raise ValueError('protected code overlaps ' + name)

    a = Asm(code_base)
    end_fixups, return_fixups = [], []
    protected = [*extents, ('native RX', receipt.NATIVE_RX[0],
                           receipt.NATIVE_RX[1] - receipt.NATIVE_RX[0]),
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

    def extent(pointer, last, size, failed):
        a.branch(4, pointer, 0, failed)
        a.e(b.i_type(12, pointer, 8, 3))
        a.branch(5, 8, 0, failed)
        a.e(b.addiu(last, pointer, size - 1), b.r_type(last, pointer, 8, 0x2B))
        a.branch(5, 8, 0, failed)

    a.label('register')
    equal(4, controller_address, 'early_denied')
    a.e(b.i_type(12, 29, 8, 7))
    a.branch(5, 8, 0, 'early_denied')
    a.e(b.i_type(11, 29, 8, FRAME))
    a.branch(5, 8, 0, 'early_denied')
    extent(5, 13, DESCRIPTOR_BYTES, 'early_denied')
    extent(6, 14, OUTPUT_BYTES, 'early_denied')
    a.e(b.addiu(11, 29, -FRAME), b.addiu(12, 29, -1))
    for index, (_, address, size) in enumerate(protected):
        end = None if size is None else address + size
        for prefix, first, last in (('frame', 11, 12), ('source', 5, 13),
                                    ('output', 6, 14)):
            nonoverlap(first, last, address, end, 'early_denied',
                       prefix + '_extent_' + str(index))
    disjoint(5, 13, 6, 14, 'early_denied', 'source_output_ok')
    disjoint(5, 13, 11, 12, 'early_denied', 'source_frame_ok')
    disjoint(6, 14, 11, 12, 'early_denied', 'output_frame_ok')
    for offset, expected in ((0x13C, registry_mutex_address),
                             (0x274, issue.REGISTRY_LOCK), (0x278, issue.REGISTRY_UNLOCK),
                             (0x148, paint_mutex_address),
                             (0x284, issue.PAINT_LOCK), (0x288, issue.PAINT_UNLOCK)):
        a.e(b.lw(8, offset, 4))
        equal(8, expected, 'early_denied')
    for offset in range(0, OUTPUT_BYTES, 4):
        a.e(b.lw(8, offset, 6))
        a.branch(5, 8, 0, 'early_denied')
    a.e(b.addiu(29, 29, -FRAME))
    for register, offset in SAVE.items():
        a.e(b.sw(register, offset, 29))
    a.e(b.r_type(0, 0, 8, 0x10), b.sw(8, HI, 29),
        b.r_type(0, 0, 8, 0x12), b.sw(8, LO, 29),
        b.sw(4, PINNED_U, 29), b.sw(6, OUTPUT_PTR, 29),
        b.sw(0, EXPORTED_PTR, 29))
    a.absolute(8, ARMED)
    a.e(b.sw(8, ARMED_TAG, 29))
    for offset in CAPTURE_FIELDS:
        a.e(b.sw(0, offset, 29))
    if checked_registry_release:
        a.absolute(8, RELEASE_ARMED)
        a.e(b.sw(8, RELEASE_TAG, 29), b.addiu(8, 0, -1),
            b.sw(8, RELEASE_STATUS, 29))
        for offset in (RELEASE_NATIVE_SP, RELEASE_RAW_SP, RELEASE_MUTEX):
            a.e(b.sw(0, offset, 29))
    for offset in range(0, DESCRIPTOR_BYTES, 4):
        a.e(b.lw(8, offset, 5), b.sw(8, DESCRIPTOR + offset, 29))
    a.absolute(4, controller_address)
    a.e(b.addiu(5, 29, DESCRIPTOR))
    a.jump(NATIVE_REGISTER, link=True)
    a.label('native_return')
    a.e(b.sw(2, NATIVE_RESULT, 29))
    if checked_registry_release:
        # Only private wrapper state is touched after native release. Consume
        # the witness even on error; a prior invocation cannot supply it.
        a.e(b.lw(8, RELEASE_TAG, 29), b.sw(0, RELEASE_TAG, 29))
        equal(8, RELEASE_CAPTURED, 'release_missing')
        a.e(b.lw(8, RELEASE_STATUS, 29))
        a.branch(5, 8, 0, 'release_failed')
    a.branch(5, 2, 0, 'register_restore')
    for offset, expected in ((ARMED_TAG, CONSUMED), (CAPTURE_MAGIC, CAPTURED),
                             (PINNED_U, controller_address)):
        a.e(b.lw(8, offset, 29))
        equal(8, expected, 'register_restore')
    for offset, limit in ((CAPTURE_BINDING_SEQUENCE, capacity),
                          (CAPTURE_OWNER, ticket_limit), (CAPTURE_RECEIPT_SEQUENCE, 1024)):
        a.e(b.lw(14, offset, 29))
        bounded(14, limit, 'register_restore')
    a.e(b.lw(16, OUTPUT_PTR, 29))
    for offset in range(0, OUTPUT_BYTES, 4):
        a.e(b.lw(8, offset, 16))
        a.branch(5, 8, 0, 'register_restore')
    output_flag = (REGISTRY_RELEASE_OBSERVED if checked_registry_release
                   else HISTORICAL_RELEASE_UNOBSERVED)
    a.e(b.addiu(8, 0, output_flag), b.sw(8, FLAGS, 16))
    for own, out in ((PINNED_U, CONTROLLER), (DESCRIPTOR, ENGINE),
                     (CAPTURE_BINDING_SEQUENCE, BINDING_SEQUENCE),
                     (CAPTURE_OWNER, OWNER), (CAPTURE_RECEIPT_SEQUENCE, RECEIPT_SEQUENCE),
                     (NATIVE_RESULT, RESULT)):
        a.e(b.lw(8, own, 29), b.sw(8, out, 16))
    a.e(SYNC)
    a.absolute(8, OUTPUT_MAGIC)
    a.e(b.sw(8, MAGIC, 16), SYNC, b.sw(16, EXPORTED_PTR, 29))
    a.label('register_restore')
    a.e(b.lw(8, HI, 29), b.r_type(8, 0, 0, 0x11),
        b.lw(8, LO, 29), b.r_type(8, 0, 0, 0x13))
    for register, offset in SAVE.items():
        a.e(b.lw(register, offset, 29))
    a.e(b.lw(2, NATIVE_RESULT, 29), b.lw(3, EXPORTED_PTR, 29),
        b.addiu(29, 29, FRAME), b.r_type(31, 0, 0, 8), 0)
    if checked_registry_release:
        a.label('release_failed')
        a.e(b.sw(8, EXPORTED_PTR, 29), b.addiu(8, 0, -1),
            b.sw(8, NATIVE_RESULT, 29))
        a.jump('register_restore')
        a.label('release_missing')
        a.e(b.addiu(8, 0, -1), b.sw(8, NATIVE_RESULT, 29))
        a.jump('register_restore')
    a.label('early_denied')
    a.e(b.addiu(2, 0, -1), b.move(3, 0), b.r_type(31, 0, 0, 8), 0)

    a.label('sink')
    a.e(b.addiu(29, 29, -SINK_FRAME))
    for register, offset in SINK_SAVE.items():
        a.e(b.sw(register, offset, 29))
    a.e(b.r_type(0, 0, 8, 0x10), b.sw(8, SINK_HI, 29),
        b.r_type(0, 0, 8, 0x12), b.sw(8, SINK_LO, 29),
        b.addiu(23, 29, SINK_FRAME), b.move(18, 6), b.move(19, 7))
    equal(4, controller_address, 'sink_restore')
    a.e(b.i_type(12, 23, 8, 7))
    a.branch(5, 8, 0, 'sink_restore')
    a.e(b.i_type(11, 23, 8, SINK_FRAME))
    a.branch(5, 8, 0, 'sink_restore')
    bounded(18, capacity, 'sink_restore')
    bounded(19, ticket_limit, 'sink_restore')
    # The closed issuer route passes its own snapshot at a fixed offset in
    # the actual caller frame. A schema-equivalent copied request elsewhere
    # is not this invocation's source. Pin it before any request load.
    a.e(b.addiu(21, 23, issue.SNAPSHOT), b.r_type(21, 23, 8, 0x2B))
    a.branch(5, 8, 0, 'sink_restore')
    a.branch(5, 5, 21, 'sink_restore')
    extent(5, 14, issue.REQUEST_BYTES, 'sink_restore')
    a.e(b.addiu(12, 23, -1))
    for index, (_, address, size) in enumerate(protected):
        end = None if size is None else address + size
        nonoverlap(29, 12, address, end, 'sink_restore', 'sink_frame_extent_' + str(index))
        nonoverlap(5, 14, address, end, 'sink_restore', 'sink_request_extent_' + str(index))
    disjoint(5, 14, 29, 12, 'sink_restore', 'request_sink_frame_ok')
    for offset, expected in ((issue.REQUEST_CONTROLLER, controller_address),
                             (issue.REQUEST_REGISTRY_MUTEX, registry_mutex_address),
                             (issue.REQUEST_SITE, issue.PUBLICATION_SITE),
                             (issue.REQUEST_RAW_STATUS, 0)):
        a.e(b.lw(8, offset, 5))
        equal(8, expected, 'sink_restore')
    a.e(b.lw(8, issue.REQUEST_CALLER, 5))
    return_fixups.append(len(a.w))
    a.absolute(9, 0)
    a.branch(5, 8, 9, 'sink_restore')
    a.e(b.lw(11, issue.REQUEST_NATIVE_SP, 5), b.i_type(12, 11, 8, 7))
    a.branch(5, 8, 0, 'sink_restore')
    # This exact sink is called from the issuer's192-byte frame inside the
    # receipt's192-byte frame. Pin the actual nested stack, not merely a
    # plausible armed wrapper named by the request: otherwise two live equal-
    # engine invocations could exchange their native-SP scalar. This bounded
    # coherent route remains a caller premise, not arbitrary-frame identity.
    a.e(b.addiu(21, 23, receipt.FRAME + issue.FRAME),
        b.r_type(21, 23, 8, 0x2B))
    a.branch(5, 8, 0, 'sink_restore')
    a.branch(5, 11, 21, 'sink_restore')
    a.e(b.addiu(16, 11, NATIVE_FRAME), b.r_type(16, 11, 8, 0x2B))
    a.branch(5, 8, 0, 'sink_restore')
    extent(16, 15, FRAME, 'sink_restore')
    for index, (_, address, size) in enumerate(protected):
        end = None if size is None else address + size
        nonoverlap(16, 15, address, end, 'sink_restore', 'wrapper_extent_' + str(index))
    disjoint(16, 15, 29, 12, 'sink_restore', 'wrapper_sink_frame_ok')
    disjoint(16, 15, 5, 14, 'sink_restore', 'wrapper_request_ok')
    for offset, expected in ((ARMED_TAG, ARMED), (PINNED_U, controller_address)):
        a.e(b.lw(8, offset, 16))
        equal(8, expected, 'sink_restore')
    for offset in CAPTURE_FIELDS:
        a.e(b.lw(8, offset, 16))
        a.branch(5, 8, 0, 'sink_restore')
    a.e(b.lw(8, issue.REQUEST_ENGINE, 5), b.lw(9, DESCRIPTOR, 16))
    a.branch(5, 8, 9, 'sink_restore')
    a.e(b.lw(20, issue.REQUEST_RECEIPT_SEQUENCE, 5))
    bounded(20, 1024, 'sink_restore')
    a.absolute(8, CONSUMED)
    a.e(b.sw(8, ARMED_TAG, 16), b.sw(18, CAPTURE_BINDING_SEQUENCE, 16),
        b.sw(19, CAPTURE_OWNER, 16), b.sw(20, CAPTURE_RECEIPT_SEQUENCE, 16),
        b.lw(8, issue.REQUEST_NODE, 5), b.sw(8, CAPTURE_NODE, 16), SYNC)
    a.absolute(8, CAPTURED)
    a.e(b.sw(8, CAPTURE_MAGIC, 16), SYNC)
    a.label('sink_restore')
    a.e(b.lw(8, SINK_HI, 29), b.r_type(8, 0, 0, 0x11),
        b.lw(8, SINK_LO, 29), b.r_type(8, 0, 0, 0x13))
    for register, offset in SINK_SAVE.items():
        a.e(b.lw(register, offset, 29))
    a.e(b.addiu(29, 29, SINK_FRAME), b.r_type(31, 0, 0, 8), 0)

    if checked_registry_release:
        def release_save(name):
            a.label(name)
            a.e(b.addiu(29, 29, -SINK_FRAME))
            for register, offset in SINK_SAVE.items():
                a.e(b.sw(register, offset, 29))
            a.e(b.r_type(0, 0, 8, 0x10), b.sw(8, SINK_HI, 29),
                b.r_type(0, 0, 8, 0x12), b.sw(8, SINK_LO, 29),
                b.addiu(23, 29, SINK_FRAME))

        def release_restore():
            a.e(b.lw(8, SINK_HI, 29), b.r_type(8, 0, 0, 0x11),
                b.lw(8, SINK_LO, 29), b.r_type(8, 0, 0, 0x13))
            for register, offset in SINK_SAVE.items():
                a.e(b.lw(register, offset, 29))
            a.e(b.addiu(29, 29, SINK_FRAME))

        def release_wrapper(native, failed, prefix):
            # Pointer/stack validity remains a premise. The bounded frame
            # checks distinguish this explicit wrapper continuation from an
            # ordinary registration, without consulting shared U or tables.
            a.e(b.i_type(12, native, 8, 7))
            a.branch(5, 8, 0, failed)
            a.e(b.lw(8, 0x24, native))
            return_fixups.append(len(a.w))
            a.absolute(9, 0)
            a.branch(5, 8, 9, failed)
            a.e(b.addiu(16, native, NATIVE_FRAME),
                b.r_type(16, native, 8, 0x2B))
            a.branch(5, 8, 0, failed)
            extent(16, 15, FRAME, failed)
            for index, (_, address, size) in enumerate(protected):
                end = None if size is None else address + size
                nonoverlap(16, 15, address, end, failed,
                           prefix + '_wrapper_extent_' + str(index))
            a.e(b.lw(8, PINNED_U, 16))
            equal(8, controller_address, failed)
            a.e(b.lw(8, ARMED_TAG, 16))
            a.absolute(9, ARMED)
            a.branch(4, 8, 9, prefix + '_wrapper_armed')
            equal(8, CONSUMED, failed)
            a.label(prefix + '_wrapper_armed')

        def raw_release_scope(failed, prefix):
            # W is466DC0's32-byte frame, then the32-byte facade, then N.
            # Gate both saved PCs before following N's wrapper continuation.
            a.e(b.lw(8, 0x1C, 23))
            equal(8, 0x437DB0, failed)
            a.e(b.lw(8, 0x3C, 23))
            equal(8, 0x438A68, failed)
            equal(16, controller_address, failed)
            a.e(b.addiu(22, 23, 0x40), b.r_type(22, 23, 8, 0x2B))
            a.branch(5, 8, 0, failed)
            release_wrapper(22, failed, prefix)

        release_save('release_call')
        equal(16, controller_address, 'release_call_done')
        release_wrapper(23, 'release_call_done', 'selected')
        a.e(b.lw(8, RELEASE_TAG, 16), b.sw(0, RELEASE_TAG, 16))
        equal(8, RELEASE_ARMED, 'release_call_done')
        # The actual T9 used by the displaced jalr is checked, not a later
        # reread of U+278 and not a callback observed only after it ran.
        equal(25, receipt.REGISTRY_UNLOCK, 'release_call_done')
        a.absolute(8, registry_mutex_address)
        a.e(b.sw(8, RELEASE_MUTEX, 16), b.sw(23, RELEASE_NATIVE_SP, 16))
        a.absolute(8, RELEASE_SELECTED)
        a.e(b.sw(8, RELEASE_TAG, 16))
        a.label('release_call_done')
        release_restore()
        a.absolute(31, 0x438A68)
        a.e(b.move(4, 16), b.r_type(25, 0, 0, 8), 0)

        release_save('raw_release_call')
        raw_release_scope('raw_release_call_done', 'raw_selected')
        a.e(b.lw(8, RELEASE_TAG, 16), b.sw(0, RELEASE_TAG, 16))
        equal(8, RELEASE_SELECTED, 'raw_release_call_done')
        a.e(b.lw(8, RELEASE_NATIVE_SP, 16))
        a.branch(5, 8, 22, 'raw_release_call_done')
        a.e(b.lw(8, RELEASE_MUTEX, 16))
        equal(8, registry_mutex_address, 'raw_release_call_done')
        equal(4, registry_mutex_address, 'raw_release_call_done')
        equal(25, receipt.REGISTRY_UNLOCK, 'raw_release_call_done')
        a.e(b.lw(8, RELEASE_STATUS, 16))
        equal(8, 0xFFFFFFFF, 'raw_release_call_done')
        a.e(b.sw(23, RELEASE_RAW_SP, 16))
        a.absolute(8, RELEASE_ENTERED)
        a.e(b.sw(8, RELEASE_TAG, 16))
        a.label('raw_release_call_done')
        release_restore()
        a.absolute(31, 0x466DD0)
        a.jump(receipt.RAW_UNLOCK)

        release_save('raw_release_return')
        raw_release_scope('raw_release_return_done', 'raw_returned')
        a.e(b.lw(8, RELEASE_TAG, 16), b.sw(0, RELEASE_TAG, 16))
        equal(8, RELEASE_ENTERED, 'raw_release_return_done')
        a.e(b.lw(8, RELEASE_NATIVE_SP, 16))
        a.branch(5, 8, 22, 'raw_release_return_done')
        a.e(b.lw(8, RELEASE_RAW_SP, 16))
        a.branch(5, 8, 23, 'raw_release_return_done')
        a.e(b.lw(8, RELEASE_MUTEX, 16))
        equal(8, registry_mutex_address, 'raw_release_return_done')
        a.e(b.lw(8, SINK_SAVE[31], 29))
        equal(8, 0x466DD0, 'raw_release_return_done')
        a.e(b.lw(8, SINK_SAVE[2], 29), b.sw(8, RELEASE_STATUS, 16))
        a.absolute(8, RELEASE_CAPTURED)
        a.e(b.sw(8, RELEASE_TAG, 16))
        a.label('raw_release_return_done')
        release_restore()
        a.e(b.lw(31, 0x1C, 29), b.move(2, 0))
        a.jump(0x466DD8)

    code_end = code_base + len(a.w) * 4
    if code_end > 0x10000000:
        raise ValueError('capture fragment leaves the native jump region')
    if protected_end is not None and code_end > protected_end:
        raise ValueError('protected code does not contain the complete capture fragment')
    if max(code_base, receipt.NATIVE_RX[0]) < min(code_end, receipt.NATIVE_RX[1]):
        raise ValueError('capture fragment overlaps pinned native RX')
    for name, address, size in extents:
        if max(code_base, address) < min(code_end, address + size):
            raise ValueError('capture fragment overlaps ' + name)
    for word_index in end_fixups:
        value = code_end - 1
        a.w[word_index:word_index + 2] = (b.lui(10, value >> 16), b.ori(10, 10, value & 0xFFFF))
    for word_index in return_fixups:
        value = a.labels['native_return']
        a.w[word_index:word_index + 2] = (b.lui(9, value >> 16), b.ori(9, 9, value & 0xFFFF))
    hook_words(a.labels)
    return a.finish(), a.labels
