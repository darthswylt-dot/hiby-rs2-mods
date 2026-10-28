#!/usr/bin/env python3
"""Offline typed historical-birth FIFO, never liveness or native UI authority.

enqueue(U, exclusive_BCAP48, owned_payload36) snapshots both inputs, validates
the historical capture and matching payload engine scalar, and consumes the
source magic BEFORE the first raw T call. One source means one attempt, even
on full, refusal or an uncertain raw error; independently copied records are
not globally deduplicated. The separate native FIFO stores BQ84, not BCAP,
GCAP, READY68, retained-operation72 or a stock worker's payload format.

pop(U, zero_out84) copies a validated borrowed head BEFORE native REMOVE and
exports the private BQ84 only after successful raw T release and a second full
output-zero check. Extraction is not rendering, completion, native retention,
incarnation identity or cleanup permission. No R/P service, pointer lookup,
engine/resource dereference, callback, installer, image or device I/O occurs.

The dedicated ordinary mutex and retained native header/table/allocated chunks
must be correctly initialized, mapped, coherent and nonaliasing. All users,
including future clear/destroy/rebind routes, must cooperate with T. Bounds do
not establish these premises or sufficient transitive native/service stack.
After a nonzero raw acquire/release result, only the retained private frame is
accessed; no guessed unlock, late shared fault write, output access or retry is
performed. External coordinated WHOLE-instance isolation is then required.
"""

from build_reveal_bridge_diag import Asm, b
import reveal_birth_capture_mips as capture
import reveal_registry_lifecycle_mips as lifecycle
import reveal_registry_owner_mips as bindings
import reveal_registry_receipt_mips as receipt
import reveal_paint_retirement_mips as owners


CAPTURE_BYTES, PAYLOAD_BYTES, PAYLOAD, ENVELOPE_BYTES = 48, 36, 48, 84
QUEUE_BYTES, MUTEX_BYTES = 56, 24
READY_MAGIC = int.from_bytes(b'BQ84', 'little')
CONSUMED_MAGIC = int.from_bytes(b'BCNS', 'little')
TOKEN, CONTROLLER, REGISTRY_MUTEX = 4, 8, 12
NODE, ENGINE, NATIVE_SP, CALLER, SITE, STATUS = 16, 20, 24, 28, 32, 36
NATIVE_RESULT, RELEASE_STATUS, PAYLOAD_ENGINE = 40, 44, 8
RAW_LOCK, RAW_UNLOCK = 0xA5B960, 0xA5B830
APPEND, GET, REMOVE = 0x455DA0, 0x4557E0, 0x455860
HEADER_FAULT, HEAD_FAULT, APPEND_FAULT, REMOVE_FAULT = 1, 2, 3, 4
FRAME, PRIVATE, RESULT, RAW = 224, 0x10, 0x64, 0x68
OLD_COUNT, REMOVED, OUTPUT_PTR, HI, LO, SYNC = 0x6C, 0x70, 0x74, 0x78, 0x7C, 0xF
SAVE = {register: 0x80 + index * 4
        for index, register in enumerate((*range(16, 24), 28, 30, 31))}


def assemble(receipt_address, binding_address, owner_address, controller_address,
             registry_mutex_address, paint_mutex_address, lifecycle_address,
             code_base, queue_address, transport_mutex_address, fault_address,
             native_return, *, capacity=16, lifecycle_capacity=16,
             owner_capacity=16, transport_capacity=40, protected_code=None):
    """Return uninstalled standalone enqueue/pop code and explicit labels.

    Q is a distinct native 56-byte header, preallocated at width 84/chunk 10 and
    the pinned positive capacity (a multiple of 10 in 10..10240). No growth is allowed.
    Its initially-zero retained fault word is permanently latched under T for
    an admitted header/head/append/remove failure, but never after raw errors.

    native_return must be the coherent checked capture's actual native-return
    label; that scalar and the schema do not authenticate fabricated captures.
    protected_code=(start,bytes) contains this fragment and native_return. With
    None, only this fragment and that external word are excluded; the caller
    must exclude the rest of composed RX. Both modes have identical sizes.

    Actual input/output/frame extents are checked before reads or frame saves.
    Historical node/engine/SP words are opaque scalars, never followed or given
    pointer-validity semantics. The exclusive inputs/output and native storage
    remain independently retained and nonaliasing caller premises. The borrowed head
    is additionally checked against this invocation's output before any copy
    or REMOVE, not just before the eventual post-release export.
    """
    extents = [('receipt', receipt_address, receipt.memory_bytes(capacity)),
               ('bindings', binding_address, bindings.memory_bytes(capacity)),
               ('owners', owner_address, owners.memory_bytes(owner_capacity)),
               ('controller', controller_address, receipt.CONTROLLER_BYTES),
               ('registry mutex', registry_mutex_address, MUTEX_BYTES),
               ('paint mutex', paint_mutex_address, MUTEX_BYTES),
               ('lifecycle history', lifecycle_address,
                lifecycle.memory_bytes(lifecycle_capacity)),
               ('birth queue', queue_address, QUEUE_BYTES),
               ('birth transport mutex', transport_mutex_address, MUTEX_BYTES),
               ('birth queue fault', fault_address, 4)]
    if (type(transport_capacity) is not int
            or not 10 <= transport_capacity <= 10240 or transport_capacity % 10):
        raise ValueError('transport capacity must be a multiple of10 in10..10240')
    for name, address, size in (*extents, ('code', code_base, 4),
                                ('native return', native_return, 4)):
        if (type(address) is not int or not 0 < address <= 0xFFFFFFFC
                or address % 4 or address + size > 0x100000000):
            raise ValueError(name + ' must have a nonwrapping aligned extent')
    if code_base >> 28 or native_return >> 28:
        raise ValueError('birth queue and native return need native jump region')
    for index, (name, address, size) in enumerate(extents):
        if max(address, receipt.NATIVE_RX[0]) < min(address + size, receipt.NATIVE_RX[1]):
            raise ValueError(name + ' overlaps pinned native RX')
        for other_name, other, other_size in extents[index + 1:]:
            if max(address, other) < min(address + size, other + other_size):
                raise ValueError(name + ' overlaps ' + other_name)
        if address <= native_return < address + size:
            raise ValueError('native return overlaps ' + name)
    if receipt.NATIVE_RX[0] <= native_return < receipt.NATIVE_RX[1]:
        raise ValueError('native return overlaps pinned native RX')

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
                or not protected_start <= native_return < protected_end):
            raise ValueError('protected code must contain queue and native return')
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
                 ('native return', native_return, 4),
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

    def preflight(name, *, enqueue):
        a.label(name)
        equal(4, controller_address, 'early_denied')
        a.e(b.i_type(12, 29, 8, 7))
        a.branch(5, 8, 0, 'early_denied')
        a.e(b.i_type(11, 29, 8, FRAME))
        a.branch(5, 8, 0, 'early_denied')
        a.e(b.addiu(11, 29, -FRAME), b.addiu(12, 29, -1))
        exclusions(11, 12, 'early_denied', name + '_frame')
        extent(5, 13, CAPTURE_BYTES if enqueue else ENVELOPE_BYTES, 'early_denied')
        exclusions(5, 13, 'early_denied', name + '_first')
        disjoint(5, 13, 11, 12, 'early_denied', name + '_first_frame_ok')
        if enqueue:
            extent(6, 14, PAYLOAD_BYTES, 'early_denied')
            exclusions(6, 14, 'early_denied', name + '_payload')
            disjoint(6, 14, 11, 12, 'early_denied', name + '_payload_frame_ok')
            disjoint(5, 13, 6, 14, 'early_denied', name + '_inputs_ok')
        else:
            # No output read precedes the complete extent/alias guards, and
            # no private frame save precedes this first complete zero check.
            for offset in range(0, ENVELOPE_BYTES, 4):
                a.e(b.lw(8, offset, 5))
                a.branch(5, 8, 0, 'early_denied')
        a.e(b.addiu(29, 29, -FRAME))
        for register, offset in SAVE.items():
            a.e(b.sw(register, offset, 29))
        a.e(b.r_type(0, 0, 8, 0x10), b.sw(8, HI, 29),
            b.r_type(0, 0, 8, 0x12), b.sw(8, LO, 29),
            b.sw(0, RESULT, 29), b.sw(0, RAW, 29),
            b.sw(0, REMOVED, 29), b.sw(0, OUTPUT_PTR, 29))
        if not enqueue:
            a.e(b.sw(5, OUTPUT_PTR, 29))

    def schema(magic, failed, prefix):
        for offset, expected in ((0, magic), (CONTROLLER, controller_address),
                                 (REGISTRY_MUTEX, registry_mutex_address),
                                 (CALLER, native_return),
                                 (SITE, lifecycle.PUBLICATION_SITE),
                                 (STATUS, 0), (NATIVE_RESULT, 0), (RELEASE_STATUS, 0)):
            a.e(b.lw(8, PRIVATE + offset, 29))
            equal(8, expected, failed)
        a.e(b.lw(14, PRIVATE + TOKEN, 29))
        a.branch(4, 14, 0, failed)
        a.absolute(9, lifecycle_capacity)
        a.e(b.r_type(9, 14, 8, 0x2B))
        a.branch(5, 8, 0, failed)
        a.e(b.lw(8, PRIVATE + ENGINE, 29),
            b.lw(9, PRIVATE + PAYLOAD + PAYLOAD_ENGINE, 29))
        a.branch(5, 8, 9, failed)
        a.label(prefix + '_schema_valid')

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
        # Native factory leaves Q+4 uninitialized; it is not a schema word.
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

    preflight('enqueue', enqueue=True)
    a.e(b.move(16, 5))
    for offset in range(0, CAPTURE_BYTES, 4):
        a.e(b.lw(8, offset, 5), b.sw(8, PRIVATE + offset, 29))
    for offset in range(0, PAYLOAD_BYTES, 4):
        a.e(b.lw(8, offset, 6), b.sw(8, PRIVATE + PAYLOAD + offset, 29))
    a.label('enqueue_snapshot_done')
    schema(capture.OUTPUT_MAGIC, 'restore', 'enqueue')
    # Exclusive ownership makes this transition private, not a shared latch.
    # Snapshot and complete schema precede consumption; every T outcome follows.
    a.absolute(8, CONSUMED_MAGIC)
    a.e(b.sw(8, 0, 16), SYNC)
    a.label('enqueue_source_consumed')
    a.absolute(8, READY_MAGIC)
    a.e(b.sw(8, PRIVATE, 29))
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

    preflight('pop', enqueue=False)
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
    exclusions(5, 13, 'head_fault', 'head')
    a.e(b.addiu(11, 29, 0), b.addiu(12, 29, FRAME - 1))
    disjoint(5, 13, 11, 12, 'head_fault', 'head_frame_ok')
    a.e(b.lw(14, OUTPUT_PTR, 29), b.addiu(15, 14, ENVELOPE_BYTES - 1))
    disjoint(5, 13, 14, 15, 'head_fault', 'head_output_ok')
    for offset in range(0, ENVELOPE_BYTES, 4):
        a.e(b.lw(8, offset, 5), b.sw(8, PRIVATE + offset, 29))
    a.label('pop_snapshot_done')
    schema(READY_MAGIC, 'head_fault', 'pop')
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
    # No source/head/Q/fault/native/shared access or call below. Only the
    # private snapshot and the exclusive owned output may be accessed.
    a.e(b.lw(16, OUTPUT_PTR, 29))
    a.label('before_export')
    for offset in range(0, ENVELOPE_BYTES, 4):
        a.e(b.lw(8, offset, 16))
        a.branch(5, 8, 0, 'restore')
    for offset in range(4, ENVELOPE_BYTES, 4):
        a.e(b.lw(8, PRIVATE + offset, 29), b.sw(8, offset, 16))
    a.e(SYNC)
    a.absolute(8, READY_MAGIC)
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
        raise ValueError('birth queue leaves the native jump region')
    if protected_end is not None and code_end > protected_end:
        raise ValueError('protected code does not contain complete birth queue')
    if max(code_base, receipt.NATIVE_RX[0]) < min(code_end, receipt.NATIVE_RX[1]):
        raise ValueError('birth queue overlaps pinned native RX')
    if code_base <= native_return < code_end:
        raise ValueError('birth queue overlaps native return')
    for name, address, size in extents:
        if max(code_base, address) < min(code_end, address + size):
            raise ValueError('birth queue overlaps ' + name)
    for index in end_fixups:
        value = code_end - 1
        a.w[index:index + 2] = (b.lui(10, value >> 16), b.ori(10, 10, value & 0xFFFF))
    return a.finish(), a.labels
