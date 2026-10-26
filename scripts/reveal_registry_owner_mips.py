#!/usr/bin/env python3
"""Offline owner issuance after a captured native registry publication.

This callback is only for the coherent four-redirect raw13C receipt fixture.
It is NOT a firmware hook, authenticated request parser, native owner lease,
producer lookup API, recovery path or cleanup/free authorization. A trusted
caller supplies an owned36-byte snapshot from this actual invocation while
the pinned, initialized ordinary13C mutex remains genuinely held. Historical
node/engine/stack/caller words are scalars and are never dereferenced here.

issue(controller, owned_request) preserves every non-SP GPR and HI/LO. It
checks its separate bounded append-only binding table before calling the
checked44-byte open_owner entry. That entry MUST pin the distinct paint148
mutex supplied here; the composer verifies the actual generated code/entry.
No owner state is read directly. A raw148 error quarantines further issuance
in13C-protected binding storage, without owner-state access, rollback, retry,
guessed unlock or a positive binding. Owner effects may already have occurred.
This flag does not gate direct users of the44-byte API: full-instance external
quarantine and complete cooperative producer/lifecycle coverage remain gates.

An opt-in commit_callback receives this actual event's owned36 request and
exact just-committed sequence/owner pair. Its ALL-GPR/HI/LO preservation is a
callee premise. None preserves preceding default bytes/labels; either mode
leaves subsequent native13C release unobserved, not certified successful.

Caller premises include genuine pinned native route/ABI, a fresh independently
captured raw-zero13C receipt, stable controller/callback/mutex fields, retained
controller/registry/node and initialized nonrobust mutex allocations, common
13C synchronization for every binding-table user, safe13C->148 lock order and
an independent writable/retained stack through all nested calls. The192-byte
callback frame is saved before validation to preserve ALL registers, so its
validity and nonaliasing are prerequisites, not established by pointer tests.
Complete native/library stack depth, scheduling, initialization, imports,
loader/cache behavior and native lifetime are not proved. Native13C release
still masks its result, so a binding is historical issuance, not successful
release. There is no installation or image-writing CLI.
"""

from build_reveal_bridge_diag import Asm, b
import reveal_paint_retirement_mips as owner_core


HEADER_BYTES, RECORD_BYTES, REQUEST_BYTES = 16, 48, 36
COUNT, QUARANTINE, STATUS, RESERVED = 0, 4, 8, 12
MAGIC, SEQUENCE, OWNER, CONTROLLER, REGISTRY_MUTEX = 0, 4, 8, 12, 16
NODE, ENGINE, NATIVE_SP, CALLER, SITE, RAW_STATUS, RECEIPT_SEQUENCE = 20, 24, 28, 32, 36, 40, 44
RECORD_MAGIC = int.from_bytes(b'OWNR', 'little')
REQUEST_CONTROLLER, REQUEST_REGISTRY_MUTEX = 0, 4
REQUEST_NODE, REQUEST_ENGINE, REQUEST_NATIVE_SP, REQUEST_CALLER = 8, 12, 16, 20
REQUEST_SITE, REQUEST_RAW_STATUS, REQUEST_RECEIPT_SEQUENCE = 24, 28, 32
REGISTRY_LOCK, REGISTRY_UNLOCK = 0x437D20, 0x437DA0
PAINT_LOCK, PAINT_UNLOCK, PUBLICATION_SITE = 0x437CE0, 0x437D60, 0x438A5C
CONTROLLER_BYTES, MUTEX_BYTES, MAX_TICKET, SYNC = 0x28C, 24, 0x7FFFFFFF, 0xF
NATIVE_RX = (0x400000, 0xA5BFA0)
FRAME, HI, LO, SNAPSHOT = 192, 0x88, 0x8C, 0x90
SAVE = {register: 0x10 + index * 4
        for index, register in enumerate(r for r in range(1, 32) if r != 29)}


def memory_bytes(capacity=16):
    if type(capacity) is not int or not 1 <= capacity <= 1024:
        raise ValueError('capacity must be in1..1024')
    return HEADER_BYTES + RECORD_BYTES * capacity


def assemble(binding_address, owner_address, controller_address,
             registry_mutex_address, paint_mutex_address, code_base,
             open_owner_entry, *, capacity=16, owner_capacity=16,
             ticket_limit=MAX_TICKET, commit_callback=None):
    """Emit an all-register-preserving callback; private binding state is zero.

    The owner-core entry must be the composed checked/pinned open_owner entry.
    The complete generated code extents are a composition-level check; a bare
    entry address cannot establish the callee's behavior or full RX extent.
    Neither table may be reset/recycled while any captured identity is visible.
    Optional commit_callback=(entry, RX start, bytes) receives U, this owned36
    snapshot, the just-committed binding sequence and owner. It must preserve
    ALL GPRs and HI/LO and does not certify subsequent native13C release. None
    emits exactly the preceding default bytes and labels.
    """
    binding_bytes = memory_bytes(capacity)
    owner_bytes = owner_core.memory_bytes(owner_capacity)
    if type(ticket_limit) is not int or not 1 <= ticket_limit <= MAX_TICKET:
        raise ValueError('ticket limit must be a positive signed word')
    extents = [('bindings', binding_address, binding_bytes),
               ('owner state', owner_address, owner_bytes),
               ('controller', controller_address, CONTROLLER_BYTES),
               ('registry mutex', registry_mutex_address, MUTEX_BYTES),
               ('paint mutex', paint_mutex_address, MUTEX_BYTES)]
    for name, address, size in (*extents, ('code', code_base, 4),
                                ('open_owner entry', open_owner_entry, 4)):
        if (type(address) is not int or not 0 < address <= 0xFFFFFFFC
                or address % 4 or address + size > 0x100000000):
            raise ValueError(name + ' must have a nonwrapping aligned extent')
    if code_base >> 28 or open_owner_entry >> 28:
        raise ValueError('callback and owner entry must share the native jump region')
    for index, (name, address, size) in enumerate(extents):
        if max(address, NATIVE_RX[0]) < min(address + size, NATIVE_RX[1]):
            raise ValueError(name + ' overlaps the pinned native executable image')
        for other_name, other_address, other_size in extents[index + 1:]:
            if max(address, other_address) < min(address + size, other_address + other_size):
                raise ValueError(name + ' overlaps ' + other_name)
        if max(address, open_owner_entry) < min(address + size, open_owner_entry + 4):
            raise ValueError('open_owner entry overlaps ' + name)
    if NATIVE_RX[0] <= open_owner_entry < NATIVE_RX[1]:
        raise ValueError('open_owner entry overlaps the pinned native executable image')
    callback_extent = None
    if commit_callback is not None:
        if (type(commit_callback) is not tuple or len(commit_callback) != 3
                or any(type(value) is not int for value in commit_callback)):
            raise ValueError('commit callback must be an (entry, RX start, bytes) tuple')
        entry, start, size = commit_callback
        if (start <= 0 or start % 4 or size <= 0 or size % 4
                or start + size > 0x10000000 or entry % 4
                or not start <= entry or entry + 4 > start + size):
            raise ValueError('commit callback must lie in its nonwrapping native-region RX extent')
        if max(start, NATIVE_RX[0]) < min(start + size, NATIVE_RX[1]):
            raise ValueError('commit callback overlaps pinned native RX')
        for name, address, extent_size in extents:
            if max(start, address) < min(start + size, address + extent_size):
                raise ValueError('commit callback overlaps ' + name)
        if max(start, open_owner_entry) < min(start + size, open_owner_entry + 4):
            raise ValueError('commit callback overlaps open_owner entry')
        callback_extent = (start, start + size)
    a = Asm(code_base)

    def equal(register, value, failed):
        a.absolute(9, value)
        a.branch(5, register, 9, failed)

    def nonoverlap(first, last, start, end, failed, label):
        a.absolute(10, start)
        a.e(b.r_type(last, 10, 9, 0x2B))
        a.branch(5, 9, 0, label)
        a.absolute(10, end - 1)
        a.e(b.r_type(10, first, 9, 0x2B))
        a.branch(5, 9, 0, label)
        a.jump(failed)
        a.label(label)

    def positive_bounded(register, limit, failed):
        a.branch(4, register, 0, failed)
        a.absolute(9, limit)
        a.e(b.r_type(9, register, 8, 0x2B))
        a.branch(5, 8, 0, failed)

    a.label('issue')
    # As in the receipt bridges, a valid retained nonaliasing writable frame
    # is a caller premise. No scratch register may be lost on an early denial.
    a.e(b.addiu(29, 29, -FRAME))
    for register, offset in SAVE.items():
        a.e(b.sw(register, offset, 29))
    a.e(b.r_type(0, 0, 8, 0x10), b.sw(8, HI, 29),
        b.r_type(0, 0, 8, 0x12), b.sw(8, LO, 29),
        b.addiu(23, 29, FRAME))
    equal(4, controller_address, 'restore')
    a.e(b.i_type(12, 23, 8, 7))
    a.branch(5, 8, 0, 'restore')
    a.e(b.i_type(11, 23, 8, FRAME))
    a.branch(5, 8, 0, 'restore')
    a.branch(4, 5, 0, 'restore')
    a.e(b.i_type(12, 5, 8, 3))
    a.branch(5, 8, 0, 'restore')
    a.e(b.addiu(13, 5, REQUEST_BYTES - 1), b.r_type(13, 5, 8, 0x2B))
    a.branch(5, 8, 0, 'restore')
    for index, (_, address, size) in enumerate(extents):
        nonoverlap(5, 13, address, address + size, 'restore',
                   'request_extent_' + str(index))
    # Inclusive request and this callback's saved-frame intervals.
    a.e(b.r_type(13, 29, 8, 0x2B))
    a.branch(5, 8, 0, 'request_stack_ok')
    a.e(b.addiu(12, 23, -1), b.r_type(12, 5, 8, 0x2B))
    a.branch(4, 8, 0, 'restore')
    a.label('request_stack_ok')
    for offset in range(0, REQUEST_BYTES, 4):
        a.e(b.lw(8, offset, 5), b.sw(8, SNAPSHOT + offset, 29))
    for offset, expected in ((REQUEST_CONTROLLER, controller_address),
                             (REQUEST_REGISTRY_MUTEX, registry_mutex_address),
                             (REQUEST_SITE, PUBLICATION_SITE), (REQUEST_RAW_STATUS, 0)):
        a.e(b.lw(8, SNAPSHOT + offset, 29))
        equal(8, expected, 'restore')
    a.e(b.lw(22, SNAPSHOT + REQUEST_RECEIPT_SEQUENCE, 29))
    positive_bounded(22, 1024, 'restore')
    # Reconfirm the expected route/object scalars before entering a distinct
    # nested mutex. Stable fields throughout this bracket remain a premise.
    for offset, expected in ((0x13C, registry_mutex_address),
                             (0x274, REGISTRY_LOCK), (0x278, REGISTRY_UNLOCK),
                             (0x148, paint_mutex_address),
                             (0x284, PAINT_LOCK), (0x288, PAINT_UNLOCK)):
        a.e(b.lw(8, offset, 4))
        equal(8, expected, 'restore')

    a.absolute(16, binding_address)
    # No binding-table access occurs until the current request and route pass.
    a.e(b.lw(8, QUARANTINE, 16))
    a.branch(5, 8, 0, 'restore')
    for offset in (STATUS, RESERVED):
        a.e(b.lw(8, offset, 16))
        a.branch(5, 8, 0, 'schema_fault')
    a.e(b.lw(20, COUNT, 16))
    a.absolute(9, capacity)
    a.e(b.r_type(9, 20, 8, 0x2B))
    a.branch(5, 8, 0, 'schema_fault')
    a.e(b.addiu(19, 16, HEADER_BYTES), b.move(17, 0),
        b.move(21, 0), b.move(18, 0))
    a.label('rows')
    a.branch(4, 17, 20, 'rows_done')
    a.e(b.lw(8, MAGIC, 19))
    equal(8, RECORD_MAGIC, 'schema_fault')
    a.e(b.addiu(17, 17, 1), b.lw(8, SEQUENCE, 19))
    a.branch(5, 8, 17, 'schema_fault')
    a.e(b.lw(14, OWNER, 19))
    positive_bounded(14, ticket_limit, 'schema_fault')
    a.e(b.r_type(21, 14, 8, 0x2B))
    a.branch(4, 8, 0, 'schema_fault')
    a.e(b.move(21, 14))
    for offset, expected in ((CONTROLLER, controller_address),
                             (REGISTRY_MUTEX, registry_mutex_address),
                             (SITE, PUBLICATION_SITE), (RAW_STATUS, 0)):
        a.e(b.lw(8, offset, 19))
        equal(8, expected, 'schema_fault')
    a.e(b.lw(14, RECEIPT_SEQUENCE, 19))
    positive_bounded(14, 1024, 'schema_fault')
    a.e(b.r_type(18, 14, 8, 0x2B))
    a.branch(4, 8, 0, 'schema_fault')
    a.e(b.move(18, 14), b.addiu(19, 19, RECORD_BYTES))
    a.jump('rows')
    a.label('rows_done')
    # A consumed/reordered receipt cannot issue another owner, even if its
    # engine/node words happen to name a newly allocated equal-value object.
    a.e(b.r_type(18, 22, 8, 0x2B))
    a.branch(4, 8, 0, 'restore')
    a.absolute(9, capacity)
    a.branch(4, 20, 9, 'restore')
    for offset in range(0, RECORD_BYTES, 4):
        a.e(b.lw(8, offset, 19))
        a.branch(5, 8, 0, 'schema_fault')
    a.absolute(4, controller_address)
    a.e(b.lw(5, SNAPSHOT + REQUEST_ENGINE, 29))
    a.absolute(25, open_owner_entry)
    a.e(b.r_type(25, 0, 31, 9), 0)
    # S-registers and our owned snapshot survive the checked core and hostile
    # raw-service ABI. No direct owner-state read or write occurs here.
    a.branch(5, 3, 0, 'raw_error')
    a.branch(4, 2, 0, 'restore')
    positive_bounded(2, ticket_limit, 'schema_fault')
    a.e(b.r_type(21, 2, 8, 0x2B))
    a.branch(4, 8, 0, 'schema_fault')
    a.e(b.addiu(20, 20, 1), b.sw(0, MAGIC, 19),
        b.sw(20, SEQUENCE, 19), b.sw(2, OWNER, 19))
    for request_offset, record_offset in (
            (REQUEST_CONTROLLER, CONTROLLER),
            (REQUEST_REGISTRY_MUTEX, REGISTRY_MUTEX), (REQUEST_NODE, NODE),
            (REQUEST_ENGINE, ENGINE), (REQUEST_NATIVE_SP, NATIVE_SP),
            (REQUEST_CALLER, CALLER), (REQUEST_SITE, SITE),
            (REQUEST_RAW_STATUS, RAW_STATUS),
            (REQUEST_RECEIPT_SEQUENCE, RECEIPT_SEQUENCE)):
        a.e(b.lw(8, SNAPSHOT + request_offset, 29), b.sw(8, record_offset, 19))
    a.e(SYNC)
    a.absolute(8, RECORD_MAGIC)
    a.e(b.sw(8, MAGIC, 19), SYNC, b.sw(20, COUNT, 16))
    # Zero-byte observation boundary for capturing this exact issuance pair.
    # This is not a native producer route or a latest-row lookup API.
    a.label('binding_committed')
    if commit_callback is not None:
        # An optional generated observer receives this invocation's private
        # snapshot and exact just-published pair, never a later table lookup.
        # It MUST preserve every GPR and HI/LO, including these arguments.
        a.absolute(4, controller_address)
        a.e(b.addiu(5, 29, SNAPSHOT), b.move(6, 20), b.move(7, 2))
        a.jump(commit_callback[0], link=True)
    a.jump('restore')
    a.label('raw_error')
    # The pinned outer13C guard still protects binding storage.148 ownership
    # is now uncertain; do not inspect or modify any owner-core storage.
    a.e(b.sw(3, STATUS, 16), SYNC, b.addiu(8, 0, 1),
        b.sw(8, QUARANTINE, 16), SYNC)
    a.jump('restore')
    a.label('schema_fault')
    a.e(b.sw(0, STATUS, 16), SYNC, b.addiu(8, 0, 1),
        b.sw(8, QUARANTINE, 16), SYNC)
    a.label('restore')
    a.e(b.lw(8, HI, 29), b.r_type(8, 0, 0, 0x11),
        b.lw(8, LO, 29), b.r_type(8, 0, 0, 0x13))
    for register, offset in SAVE.items():
        a.e(b.lw(register, offset, 29))
    a.e(b.addiu(29, 29, FRAME), b.r_type(31, 0, 0, 8), 0)

    result = a.finish()
    code_end = code_base + len(result)
    if code_end > 0x10000000:
        raise ValueError('callback leaves its native MIPS jump region')
    if max(code_base, NATIVE_RX[0]) < min(code_end, NATIVE_RX[1]):
        raise ValueError('callback overlaps the pinned native executable image')
    for name, address, size in extents:
        if max(code_base, address) < min(code_end, address + size):
            raise ValueError('callback overlaps ' + name)
    if code_base <= open_owner_entry < code_end:
        raise ValueError('callback overlaps open_owner entry')
    if callback_extent is not None:
        if max(code_base, callback_extent[0]) < min(code_end, callback_extent[1]):
            raise ValueError('issuer code overlaps commit callback RX extent')
    return result, a.labels
