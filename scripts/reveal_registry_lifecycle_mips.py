#!/usr/bin/env python3
"""Offline field-correlated birth/retirement history, never native liveness.

The two all-register-preserving callbacks receive the same private owned32
event: U, R, node, engine, native SP, caller, site and raw acquisition status.
The coherent caller has freshly observed raw R=0 for this exact native scope
and genuinely still holds the pinned ordinary mutex. Neither an event schema
nor this module authenticates that premise. Node/engine/SP/caller words are
historical scalars and are never dereferenced here.

Births append nonreused tokens; retirement observations terminally mark the
unique outstanding row with the selected node/engine fields. A terminal row
means RETIREMENT_SELECTED, not that deletion/free completed. In particular the
outer shutdown observations precede R release and an opaque callback that may
not remove the selected node. NO_RETIREMENT_OBSERVED is not a LIVE state.

Coverage is incomplete: native masked raw failures can mutate without a safe
history write, and escaped aliases, callbacks and other writers remain external
gates. A missed deletion and unobserved same-address rebirth can correlate a
later retirement with the wrong historical birth. A healthy header, token or
terminal state therefore proves neither incarnation identity nor retention.
There is no public query/export, native service, cleanup permission, installer,
image or device operation. An optional private post-birth callback can carry
the exact just-committed token without a historical lookup; it grants no new
lifetime authority. Initial architectural-save storage is a caller premise.
"""

from build_reveal_bridge_diag import Asm, b
import reveal_registry_receipt_mips as receipt


HEADER_BYTES, RECORD_BYTES, REQUEST_BYTES = 16, 64, 32
EVENT_BYTES = REQUEST_BYTES
COUNT, FAULT, RESERVED0, RESERVED1 = 0, 4, 8, 12
MAGIC, TOKEN, CONTROLLER, MUTEX, NODE, ENGINE = 0, 4, 8, 12, 16, 20
NATIVE_SP, CALLER, SITE, STATUS, STATE = 24, 28, 32, 36, 40
RETIREMENT_SITE, RETIREMENT_SP, RETIREMENT_CALLER = 44, 48, 52
RESERVED2, RESERVED3 = 56, 60
RECORD_MAGIC = int.from_bytes(b'BRLC', 'little')
NO_RETIREMENT_OBSERVED, RETIREMENT_SELECTED = 1, 2
REQUEST_CONTROLLER, REQUEST_REGISTRY_MUTEX = 0, 4
REQUEST_NODE, REQUEST_ENGINE, REQUEST_NATIVE_SP, REQUEST_CALLER = 8, 12, 16, 20
REQUEST_SITE, REQUEST_RAW_STATUS = 24, 28
PUBLICATION_SITE = 0x438A5C
RETIREMENT_SITES = (0x439618, 0x43CBB0, 0x4E3F18, 0x51A3B8)
CONTROLLER_BYTES, MUTEX_BYTES = receipt.CONTROLLER_BYTES, receipt.MUTEX_BYTES
REGISTRY_LOCK, REGISTRY_UNLOCK = receipt.REGISTRY_LOCK, receipt.REGISTRY_UNLOCK
NATIVE_RX, SYNC = receipt.NATIVE_RX, 0xF
FRAME, HI, LO, SNAPSHOT = 192, 0x88, 0x8C, 0x90
SAVE = {register: 0x10 + index * 4
        for index, register in enumerate(r for r in range(1, 32) if r != 29)}


def memory_bytes(capacity=16):
    if type(capacity) is not int or not 1 <= capacity <= 1024:
        raise ValueError('capacity must be in1..1024')
    return HEADER_BYTES + RECORD_BYTES * capacity


def assemble(state_address, controller_address, registry_mutex_address, code_base,
             *, capacity=16, protected_code=None, extra_protected_data=(),
             birth_commit_callback=None):
    """Return passive callback bytes/labels; initially all history words zero.

    All users synchronize with the same genuine R. Both entry points validate
    the complete occupied prefix, outstanding-node uniqueness and every unused
    word. Birth collision/full, retirement missing/mismatch/duplicate and any
    admitted schema failure permanently fault the bounded history. A full but
    otherwise healthy history can still mark one existing retirement.

    protected_code=(start,bytes) contains this complete fragment; None guards
    only this fragment. The two choices have identical instruction counts.
    extra_protected_data is a strict tuple of aligned (start,bytes) exclusions.
    Guards precede input/controller/history loads, not the initial192-byte
    all-GPR/HI/LO save. Independently valid, retained, writable and nonaliasing
    save/input/native storage remains a caller premise, not proved by bounds.
    Optional birth_commit_callback=(entry,RX start,bytes) receives U, this
    callback's owned32 snapshot and the exact just-committed token in A2.
    It runs once after row/count commit while R is genuinely held and must
    preserve ALL GPRs and HI/LO. None preserves preceding bytes/labels. No
    retirement, refused birth or lookup of a historical/latest row calls it.
    """
    state_bytes = memory_bytes(capacity)
    extents = [('lifecycle history', state_address, state_bytes),
               ('controller', controller_address, CONTROLLER_BYTES),
               ('registry mutex', registry_mutex_address, MUTEX_BYTES)]
    if type(extra_protected_data) is not tuple:
        raise ValueError('extra protected data must be a tuple of aligned extents')
    for index, item in enumerate(extra_protected_data):
        if (type(item) is not tuple or len(item) != 2
                or any(type(value) is not int for value in item)):
            raise ValueError('extra protected data must contain (start,bytes) tuples')
        start, size = item
        if size <= 0 or size % 4:
            raise ValueError('extra protected sizes must be positive aligned words')
        extents.append(('extra data ' + str(index), start, size))
    for name, address, size in (*extents, ('code', code_base, 4)):
        if (type(address) is not int or not 0 < address <= 0xFFFFFFFC
                or address % 4 or address + size > 0x100000000):
            raise ValueError(name + ' must have a nonwrapping aligned extent')
    if code_base >> 28:
        raise ValueError('lifecycle callbacks must share the native jump region')
    for index, (name, address, size) in enumerate(extents):
        if max(address, NATIVE_RX[0]) < min(address + size, NATIVE_RX[1]):
            raise ValueError(name + ' overlaps pinned native RX')
        for other_name, other, other_size in extents[index + 1:]:
            if max(address, other) < min(address + size, other + other_size):
                raise ValueError(name + ' overlaps ' + other_name)

    commit_extent = None
    if birth_commit_callback is not None:
        if (type(birth_commit_callback) is not tuple or len(birth_commit_callback) != 3
                or any(type(value) is not int for value in birth_commit_callback)):
            raise ValueError('birth commit callback must be a strict RX tuple')
        entry, start, size = birth_commit_callback
        if (start <= 0 or start % 4 or size <= 0 or size % 4
                or start + size > 0x10000000 or entry % 4
                or not start <= entry < start + size):
            raise ValueError('birth commit callback must lie in its native-region RX')
        if max(start, NATIVE_RX[0]) < min(start + size, NATIVE_RX[1]):
            raise ValueError('birth commit callback overlaps pinned native RX')
        for name, address, extent_size in extents:
            if max(start, address) < min(start + size, address + extent_size):
                raise ValueError('birth commit callback overlaps ' + name)
        commit_extent = (start, size)

    protected_start, protected_end = code_base, None
    if protected_code is not None:
        if (type(protected_code) is not tuple or len(protected_code) != 2
                or any(type(value) is not int for value in protected_code)):
            raise ValueError('protected code must be an (RX start,bytes) tuple')
        protected_start, protected_bytes = protected_code
        protected_end = protected_start + protected_bytes
        if (protected_start <= 0 or protected_start % 4 or protected_bytes <= 0
                or protected_bytes % 4 or protected_end > 0x10000000
                or not protected_start <= code_base < protected_end):
            raise ValueError('protected code must contain the lifecycle callbacks')
        if max(protected_start, NATIVE_RX[0]) < min(protected_end, NATIVE_RX[1]):
            raise ValueError('protected code overlaps pinned native RX')
        for name, address, size in extents:
            if max(protected_start, address) < min(protected_end, address + size):
                raise ValueError('protected code overlaps ' + name)

    a = Asm(code_base)
    end_fixups = []
    protected = [*extents,
                 ('native RX', NATIVE_RX[0], NATIVE_RX[1] - NATIVE_RX[0]),
                 ('generated RX', protected_start,
                  None if protected_end is None else protected_end - protected_start)]
    if commit_extent is not None:
        protected.append(('birth commit callback RX', *commit_extent))

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
            nonoverlap(first, last, address, None if size is None else address + size,
                       failed, prefix + '_extent_' + str(index))

    def entry(name, mode):
        a.label(name)
        a.label(name + '_save_frame')
        a.e(b.addiu(29, 29, -FRAME))
        for register, offset in SAVE.items():
            a.e(b.sw(register, offset, 29))
        a.e(b.r_type(0, 0, 8, 0x10), b.sw(8, HI, 29),
            b.r_type(0, 0, 8, 0x12), b.sw(8, LO, 29),
            b.addiu(23, 29, FRAME), b.addiu(30, 0, mode))
        a.jump('validate_input')

    entry('observe_birth', 1)
    entry('observe_retirement', 2)
    a.label('validate_input')
    equal(4, controller_address, 'restore')
    a.e(b.i_type(12, 23, 8, 7))
    a.branch(5, 8, 0, 'restore')
    a.e(b.i_type(11, 23, 8, FRAME))
    a.branch(5, 8, 0, 'restore')
    a.e(b.addiu(12, 23, -1))
    exclusions(29, 12, 'restore', 'frame')
    a.branch(4, 5, 0, 'restore')
    a.e(b.i_type(12, 5, 8, 3))
    a.branch(5, 8, 0, 'restore')
    a.e(b.addiu(13, 5, REQUEST_BYTES - 1), b.r_type(13, 5, 8, 0x2B))
    a.branch(5, 8, 0, 'restore')
    exclusions(5, 13, 'restore', 'request')
    a.e(b.r_type(13, 29, 8, 0x2B))
    a.branch(5, 8, 0, 'request_frame_ok')
    a.e(b.r_type(12, 5, 8, 0x2B))
    a.branch(4, 8, 0, 'restore')
    a.label('request_frame_ok')
    for offset in range(0, REQUEST_BYTES, 4):
        a.e(b.lw(8, offset, 5), b.sw(8, SNAPSHOT + offset, 29))
    a.label('snapshot_done')
    for offset, expected in ((REQUEST_CONTROLLER, controller_address),
                             (REQUEST_REGISTRY_MUTEX, registry_mutex_address),
                             (REQUEST_RAW_STATUS, 0)):
        a.e(b.lw(8, SNAPSHOT + offset, 29))
        equal(8, expected, 'restore')
    a.e(b.lw(8, SNAPSHOT + REQUEST_SITE, 29), b.addiu(9, 0, 1))
    a.branch(5, 30, 9, 'validate_retirement_site')
    equal(8, PUBLICATION_SITE, 'restore')
    a.jump('site_valid')
    a.label('validate_retirement_site')
    for site in RETIREMENT_SITES:
        a.absolute(9, site)
        a.branch(4, 8, 9, 'site_valid')
    a.jump('restore')
    a.label('site_valid')
    for offset, expected in ((0x13C, registry_mutex_address),
                             (0x274, REGISTRY_LOCK), (0x278, REGISTRY_UNLOCK)):
        a.e(b.lw(8, offset, 4))
        equal(8, expected, 'restore')

    a.label('history_admitted')
    a.absolute(20, state_address)
    a.e(b.lw(8, FAULT, 20))
    a.branch(5, 8, 0, 'restore')
    for offset in (RESERVED0, RESERVED1):
        a.e(b.lw(8, offset, 20))
        a.branch(5, 8, 0, 'schema_fault')
    a.e(b.lw(21, COUNT, 20))
    a.absolute(9, capacity)
    a.e(b.r_type(9, 21, 8, 0x2B))
    a.branch(5, 8, 0, 'schema_fault')
    a.e(b.addiu(22, 20, HEADER_BYTES), b.move(18, 0), b.move(16, 0),
        b.lw(15, SNAPSHOT + REQUEST_NODE, 29),
        b.lw(14, SNAPSHOT + REQUEST_ENGINE, 29))
    a.label('rows')
    a.branch(4, 18, 21, 'rows_done')
    a.e(b.lw(8, MAGIC, 22))
    equal(8, RECORD_MAGIC, 'schema_fault')
    a.e(b.addiu(18, 18, 1), b.lw(8, TOKEN, 22))
    a.branch(5, 8, 18, 'schema_fault')
    for offset, expected in ((CONTROLLER, controller_address),
                             (MUTEX, registry_mutex_address),
                             (SITE, PUBLICATION_SITE), (STATUS, 0),
                             (RESERVED2, 0), (RESERVED3, 0)):
        a.e(b.lw(8, offset, 22))
        equal(8, expected, 'schema_fault')
    a.e(b.lw(8, STATE, 22), b.addiu(9, 0, NO_RETIREMENT_OBSERVED))
    a.branch(4, 8, 9, 'row_outstanding')
    equal(8, RETIREMENT_SELECTED, 'schema_fault')
    a.e(b.lw(8, RETIREMENT_SITE, 22))
    for site in RETIREMENT_SITES:
        a.absolute(9, site)
        a.branch(4, 8, 9, 'row_done')
    a.jump('schema_fault')

    a.label('row_outstanding')
    for offset in (RETIREMENT_SITE, RETIREMENT_SP, RETIREMENT_CALLER):
        a.e(b.lw(8, offset, 22))
        a.branch(5, 8, 0, 'schema_fault')
    # Validate all outstanding-node uniqueness, including rows unrelated to
    # this event. This bounded quadratic scan never follows a native pointer.
    a.e(b.addiu(24, 20, HEADER_BYTES), b.lw(6, NODE, 22))
    a.label('earlier_rows')
    a.branch(4, 24, 22, 'earlier_rows_done')
    a.e(b.lw(8, STATE, 24), b.addiu(9, 0, NO_RETIREMENT_OBSERVED))
    a.branch(5, 8, 9, 'earlier_row_done')
    a.e(b.lw(8, NODE, 24))
    a.branch(4, 8, 6, 'schema_fault')
    a.label('earlier_row_done')
    a.e(b.addiu(24, 24, RECORD_BYTES))
    a.jump('earlier_rows')
    a.label('earlier_rows_done')
    a.branch(5, 6, 15, 'row_done')
    a.e(b.addiu(9, 0, 1))
    a.branch(4, 30, 9, 'schema_fault')  # An outstanding-node birth collision.
    a.e(b.lw(8, ENGINE, 22))
    a.branch(5, 8, 14, 'schema_fault')
    a.branch(5, 16, 0, 'schema_fault')
    a.e(b.move(16, 22))
    a.label('row_done')
    a.e(b.addiu(22, 22, RECORD_BYTES))
    a.jump('rows')
    a.label('rows_done')
    a.e(b.move(19, 22))
    a.absolute(17, state_address + state_bytes)
    a.label('unused_tail')
    a.branch(4, 19, 17, 'unused_tail_done')
    a.e(b.lw(8, 0, 19))
    a.branch(5, 8, 0, 'schema_fault')
    a.e(b.addiu(19, 19, 4))
    a.jump('unused_tail')
    a.label('unused_tail_done')
    a.e(b.addiu(9, 0, 1))
    a.branch(5, 30, 9, 'retirement_commit')
    a.absolute(9, capacity)
    a.branch(4, 21, 9, 'schema_fault')
    a.e(b.addiu(21, 21, 1), b.sw(0, MAGIC, 22), b.sw(21, TOKEN, 22))
    for event_offset in range(0, REQUEST_BYTES, 4):
        a.e(b.lw(8, SNAPSHOT + event_offset, 29),
            b.sw(8, CONTROLLER + event_offset, 22))
    a.e(b.addiu(8, 0, NO_RETIREMENT_OBSERVED), b.sw(8, STATE, 22))
    a.label('birth_commit')
    a.e(SYNC)
    a.absolute(8, RECORD_MAGIC)
    a.e(b.sw(8, MAGIC, 22), SYNC, b.sw(21, COUNT, 20))
    if birth_commit_callback is not None:
        a.label('birth_commit_callback')
        a.absolute(4, controller_address)
        a.e(b.addiu(5, 29, SNAPSHOT), b.move(6, 21))
        a.jump(birth_commit_callback[0], link=True)
    a.jump('restore')
    a.label('retirement_commit')
    a.branch(4, 16, 0, 'schema_fault')
    for request_offset, row_offset in ((REQUEST_SITE, RETIREMENT_SITE),
                                        (REQUEST_NATIVE_SP, RETIREMENT_SP),
                                        (REQUEST_CALLER, RETIREMENT_CALLER)):
        a.e(b.lw(8, SNAPSHOT + request_offset, 29), b.sw(8, row_offset, 16))
    a.e(SYNC, b.addiu(8, 0, RETIREMENT_SELECTED), b.sw(8, STATE, 16), SYNC)
    a.jump('restore')
    a.label('schema_fault')
    a.e(b.addiu(8, 0, 1), b.sw(8, FAULT, 20), SYNC)
    a.label('restore')
    a.e(b.lw(8, HI, 29), b.r_type(8, 0, 0, 0x11),
        b.lw(8, LO, 29), b.r_type(8, 0, 0, 0x13))
    for register, offset in SAVE.items():
        a.e(b.lw(register, offset, 29))
    a.e(b.addiu(29, 29, FRAME), b.r_type(31, 0, 0, 8), 0)

    code_end = code_base + len(a.w) * 4
    if code_end > 0x10000000:
        raise ValueError('lifecycle callbacks leave the native MIPS jump region')
    if protected_end is not None and code_end > protected_end:
        raise ValueError('protected code does not contain complete lifecycle callbacks')
    if max(code_base, NATIVE_RX[0]) < min(code_end, NATIVE_RX[1]):
        raise ValueError('lifecycle callbacks overlap pinned native RX')
    for name, address, size in extents:
        if max(code_base, address) < min(code_end, address + size):
            raise ValueError('lifecycle callbacks overlap ' + name)
    if commit_extent is not None:
        start, size = commit_extent
        if max(code_base, start) < min(code_end, start + size):
            raise ValueError('lifecycle code overlaps birth commit callback RX')
    for index in end_fixups:
        a.w[index] = b.lui(10, (code_end - 1) >> 16)
        a.w[index + 1] = b.ori(10, 10, (code_end - 1) & 0xFFFF)
    return a.finish(), a.labels
