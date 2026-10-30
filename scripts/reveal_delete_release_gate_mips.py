#!/usr/bin/env python3
"""Offline destructor-scoped propagation of actual name-delete raw release.

Five coherent phases use unused words14/18/1C in the genuine1208-byte
destructor frame D. Native deletion's56-byte frame N is popped BEFORE its
tail unlock, so N's acquisition locals are not a release carrier. The new
ARMED -> SELECTED -> ENTERED -> CAPTURED witness stays in D throughout the
unchanged callback/raw service chain. No extra frame is held across that call.

Begin and pre-pop selection require pinned U and native saved caller493F4C.
The raw bridges require restored S1=U and the exact437DB0/493F4C saved return
chain before following D. Completion consumes the tag for that same native
destructor return. An incoming nonzero V0 preserves its complete older ABI,
including the acquisition gate's V1; it does not need a release witness. For
incoming zero, captured raw zero preserves native success, captured nonzero
returns FFFFFFFF/exact_status, and missing/incoherent evidence FFFFFFFF/zero.
The actual raw FFFFFFFF is separate from missing evidence through its tag.

The begin/raw phases always restore all architecture and delegate their exact
preceding observers. Completion delegates the preceding destructor gate after
restoring architecture or setting only the scoped V0/V1 result. Pre-pop select
replays the original saved-RA and S4 loads before the remaining native unwind.
Actual callback SP remains D, its RA remains493F4C and the raw call retains
native466DD0. No native callback, raw service or unlock is duplicated.

HARD premises: genuine native routes/ABI; mapped, retained, writable,
independently nonaliasing simultaneously live destructor1208, delete56,
facade32, raw32 and private192 frames. Popped N is deliberately reused by
later facade/raw frames; no continued retention of N is assumed. Sufficient
aggregate/transitive stack, coherent fresh-phase redirects, ordinary mutex
semantics and all inherited native/import/storage premises remain required.
Saving precedes classification. Scope constants/tags are not authentication,
static extents do not validate arbitrary SP or lifetime, and arbitrary partial
hook activation is not a fail-closed installation protocol. Earlier unlink,
engine frees and other cleanup may already be effective. No graph read, new
service call, extra unlock, retry, rollback, retention, free authority, caller
isolation, firmware image, installer or device operation is supplied here.
"""

from build_reveal_bridge_diag import Asm, b
import reveal_registry_receipt_mips as receipt


FRAME, HI, LO, RAW = 192, 0x88, 0x8C, 0x90
DELETE_FRAME, DESTRUCTOR_FRAME = 56, 1208
FACADE_FRAME, RAW_FRAME = 32, 32
TAG, STATUS, RAW_SP = 0x14, 0x18, 0x1C
ARMED = int.from_bytes(b'DRAR', 'little')
SELECTED = int.from_bytes(b'DRSL', 'little')
ENTERED = int.from_bytes(b'DREN', 'little')
CAPTURED = int.from_bytes(b'DRCP', 'little')
DELETE_RETURN, RAW_RELEASE_RETURN = 0x493F4C, 0x466DD0
SELECT_CONTINUATION = 0x439660
REGISTRY_UNLOCK = receipt.REGISTRY_UNLOCK
CONTROLLER_BYTES, MUTEX_BYTES = receipt.CONTROLLER_BYTES, receipt.MUTEX_BYTES
NATIVE_RX = receipt.NATIVE_RX
SAVE = {register: 0x10 + index * 4
        for index, register in enumerate(r for r in range(1, 32) if r != 29)}
HOOKS = {
    'begin': (0x4395C0, (0x8C990274, 0x0080A821)),
    'release_select': (0x439658, (0x8FBF0034, 0x8FB4002C)),
    'raw_release_call': (0x466DC8, (0x0C296E0C, 0)),
    'raw_release_return': (0x466DD0, (0x8FBF001C, 0x00001021)),
    'complete': (0x493F4C, (0x8E240024, 0x0C1214C8)),
}


def hook_words(labels):
    """Return five local fetch overrides, never an image edit or installer."""
    result = {}
    for name, (pc, _) in HOOKS.items():
        target = labels[name]
        if (type(target) is not int or target <= 0 or target % 4
                or target > 0xFFFFFFFC or (pc + 4) >> 28 != target >> 28):
            raise ValueError('delete release gate target must share native jump region')
        result[pc] = (b.j_type(2, target), 0)
    return result


def assemble(controller_address, registry_mutex_address, code_base,
             delete_begin_entry, raw_release_call_entry, raw_release_return_entry,
             destructor_gate_entry, *, protected_code=None, extra_protected_data=()):
    """Emit private witnesses and delegate all four exact preceding entries.

    The four legacy entries must be distinct aligned generated RX before this
    fragment. Advertised protected_code=(start,bytes) contains those entries
    and the complete fragment. U/R and extra fixed extents are strict static
    layout declarations, not dynamic frame guards or allocation leases.

    D's14/18/1C words are private unused native locals, outside its first four
    o32 argument homes; D+10 is a native fifth-argument slot and is not reused.
    D=N+56 before tail unwind and D=W+64 inside the raw wrapper. No stale N
    local is read after that unwind. Native entry, callback SP/RA and complete
    retained frames are premises; an arbitrary helper entry is not an API.
    """
    extents = [('controller', controller_address, CONTROLLER_BYTES),
               ('registry mutex', registry_mutex_address, MUTEX_BYTES)]
    if type(extra_protected_data) is not tuple:
        raise ValueError('extra protected data must be a tuple of extents')
    for index, item in enumerate(extra_protected_data):
        if (type(item) is not tuple or len(item) != 2
                or any(type(value) is not int for value in item)):
            raise ValueError('extra protected data must contain (start,bytes) tuples')
        start, size = item
        if size <= 0 or size % 4:
            raise ValueError('extra protected sizes must be positive aligned words')
        extents.append(('extra data ' + str(index), start, size))
    for name, start, size in (*extents, ('code', code_base, 4)):
        if (type(start) is not int or not 0 < start <= 0xFFFFFFFC
                or start % 4 or start + size > 0x100000000):
            raise ValueError(name + ' must have a nonwrapping aligned extent')
    if code_base >> 28:
        raise ValueError('delete release gates must share native jump region')
    legacy_entries = (delete_begin_entry, raw_release_call_entry,
                      raw_release_return_entry, destructor_gate_entry)
    for entry in legacy_entries:
        if (type(entry) is not int or entry <= 0 or entry % 4
                or entry < NATIVE_RX[1] or entry + 4 > code_base
                or entry + 4 > 0x10000000):
            raise ValueError('legacy entries must be preceding aligned generated RX')
    if len(set(legacy_entries)) != len(legacy_entries):
        raise ValueError('legacy delete release entries must be distinct')
    for index, (name, start, size) in enumerate(extents):
        if max(start, NATIVE_RX[0]) < min(start + size, NATIVE_RX[1]):
            raise ValueError(name + ' overlaps pinned native RX')
        for entry in legacy_entries:
            if max(start, entry) < min(start + size, entry + 4):
                raise ValueError(name + ' overlaps legacy RX entry')
        for other_name, other_start, other_size in extents[index + 1:]:
            if max(start, other_start) < min(start + size, other_start + other_size):
                raise ValueError(name + ' overlaps ' + other_name)

    protected_end = None
    if protected_code is not None:
        if (type(protected_code) is not tuple or len(protected_code) != 2
                or any(type(value) is not int for value in protected_code)):
            raise ValueError('protected code must be an (RX start,bytes) tuple')
        protected_start, protected_bytes = protected_code
        protected_end = protected_start + protected_bytes
        if (protected_start <= 0 or protected_start % 4 or protected_bytes <= 0
                or protected_bytes % 4 or protected_end > 0x10000000
                or not protected_start <= code_base < protected_end
                or any(not protected_start <= entry
                       or entry + 4 > protected_end for entry in legacy_entries)):
            raise ValueError('protected code must contain legacy entries and release gates')
        if max(protected_start, NATIVE_RX[0]) < min(protected_end, NATIVE_RX[1]):
            raise ValueError('protected code overlaps pinned native RX')
        for name, start, size in extents:
            if max(protected_start, start) < min(protected_end, start + size):
                raise ValueError('protected code overlaps ' + name)

    a = Asm(code_base)

    def equal(register, value, failed):
        a.absolute(9, value)
        a.branch(5, register, 9, failed)

    def save(name):
        a.label(name)
        a.e(b.addiu(29, 29, -FRAME))
        for register, offset in SAVE.items():
            a.e(b.sw(register, offset, 29))
        a.e(b.r_type(0, 0, 8, 0x10), b.sw(8, HI, 29),
            b.r_type(0, 0, 8, 0x12), b.sw(8, LO, 29),
            b.sw(0, RAW, 29), b.addiu(23, 29, FRAME))

    def restore(denied=False):
        a.e(b.lw(8, HI, 29), b.r_type(8, 0, 0, 0x11),
            b.lw(8, LO, 29), b.r_type(8, 0, 0, 0x13))
        for register, offset in SAVE.items():
            if not denied or register not in (2, 3):
                a.e(b.lw(register, offset, 29))
        if denied:
            a.e(b.addiu(2, 0, -1), b.lw(3, RAW, 29))
        a.e(b.addiu(29, 29, FRAME))

    def delete_scope(name, failed, u_register):
        # N's saved native caller is read only after pinned-U classification.
        a.e(b.lw(8, SAVE[u_register], 29))
        equal(8, controller_address, failed)
        a.e(b.lw(8, 0x34, 23))
        equal(8, DELETE_RETURN, failed)
        a.e(b.addiu(22, 23, DELETE_FRAME))
        a.label(name + '_classified')

    def raw_scope(name, failed):
        # W's two saved PCs identify the original tail callback, not a newly
        # invented return into this fragment. Only then may D be followed.
        a.e(b.lw(8, SAVE[17], 29))
        equal(8, controller_address, failed)
        a.e(b.lw(8, 0x1C, 23))
        equal(8, 0x437DB0, failed)
        a.e(b.lw(8, 0x3C, 23))
        equal(8, DELETE_RETURN, failed)
        a.e(b.addiu(22, 23, FACADE_FRAME + RAW_FRAME))
        a.label(name + '_classified')

    save('begin')
    delete_scope('begin', 'begin_done', 4)
    # A separate fresh phase before acquisition means an omitted later select
    # cannot adopt stale SELECTED/CAPTURED words from an earlier stack use.
    a.e(b.sw(0, TAG, 22), b.addiu(8, 0, -1),
        b.sw(8, STATUS, 22), b.sw(0, RAW_SP, 22))
    a.absolute(8, ARMED)
    a.e(b.sw(8, TAG, 22))
    a.label('begin_done')
    restore()
    a.label('begin_replay')
    a.jump(delete_begin_entry)

    save('release_select')
    delete_scope('release_select', 'release_select_done', 21)
    a.e(b.lw(8, TAG, 22), b.sw(0, TAG, 22))
    equal(8, ARMED, 'release_select_done')
    a.e(b.lw(8, STATUS, 22))
    equal(8, 0xFFFFFFFF, 'release_select_done')
    a.e(b.lw(8, RAW_SP, 22))
    equal(8, 0, 'release_select_done')
    a.e(b.lw(8, SAVE[25], 29))
    equal(8, REGISTRY_UNLOCK, 'release_select_done')
    a.absolute(8, SELECTED)
    a.e(b.sw(8, TAG, 22))
    a.label('release_select_done')
    restore()
    a.label('release_select_replay')
    #439658 is also the empty-ring branch target. Both displaced loads run
    #once before439660; native439678/67C still tail-jumps and pops N to D.
    a.e(*HOOKS['release_select'][1])
    a.jump(SELECT_CONTINUATION)

    save('raw_release_call')
    raw_scope('raw_release_call', 'raw_release_call_done')
    a.e(b.lw(8, TAG, 22), b.sw(0, TAG, 22))
    equal(8, SELECTED, 'raw_release_call_done')
    a.e(b.lw(8, STATUS, 22))
    equal(8, 0xFFFFFFFF, 'raw_release_call_done')
    a.e(b.lw(8, RAW_SP, 22))
    equal(8, 0, 'raw_release_call_done')
    a.e(b.lw(8, SAVE[4], 29))
    equal(8, registry_mutex_address, 'raw_release_call_done')
    a.e(b.lw(8, SAVE[25], 29))
    equal(8, REGISTRY_UNLOCK, 'raw_release_call_done')
    a.e(b.sw(23, RAW_SP, 22))
    a.absolute(8, ENTERED)
    a.e(b.sw(8, TAG, 22))
    a.label('raw_release_call_done')
    restore()
    a.label('raw_release_call_replay')
    a.jump(raw_release_call_entry)

    save('raw_release_return')
    raw_scope('raw_release_return', 'raw_release_return_done')
    a.e(b.lw(8, SAVE[31], 29))
    equal(8, RAW_RELEASE_RETURN, 'raw_release_return_done')
    a.e(b.lw(8, TAG, 22), b.sw(0, TAG, 22))
    equal(8, ENTERED, 'raw_release_return_done')
    a.e(b.lw(8, RAW_SP, 22))
    a.branch(5, 8, 23, 'raw_release_return_done')
    # A0/T9 may be clobbered by the raw service. Capture only saved actual V0.
    a.e(b.lw(8, SAVE[2], 29), b.sw(8, STATUS, 22))
    a.absolute(8, CAPTURED)
    a.e(b.sw(8, TAG, 22))
    a.label('raw_release_return_done')
    restore()
    a.label('raw_release_return_replay')
    a.jump(raw_release_return_entry)

    save('complete')
    a.e(b.lw(8, SAVE[17], 29))
    equal(8, controller_address, 'complete_done')
    a.e(b.lw(8, SAVE[31], 29))
    equal(8, DELETE_RETURN, 'complete_done')
    a.e(b.move(22, 23))
    a.label('complete_classified')
    a.e(b.lw(8, TAG, 22), b.sw(0, TAG, 22),
        b.lw(10, SAVE[2], 29))
    # Acquisition denial bypassed unlock. Preserve its exact V0/V1 before
    #requiring any release evidence; the old destructor gate still stops it.
    a.branch(5, 10, 0, 'complete_admitted')
    equal(8, CAPTURED, 'complete_denied')
    a.e(b.lw(8, RAW_SP, 22),
        b.addiu(9, 23, -(FACADE_FRAME + RAW_FRAME)))
    a.branch(5, 8, 9, 'complete_denied')
    a.e(b.lw(8, STATUS, 22))
    a.branch(4, 8, 0, 'complete_admitted')
    a.e(b.sw(8, RAW, 29))
    a.jump('complete_denied')
    a.label('complete_admitted')
    a.jump('complete_done')
    a.label('complete_denied')
    restore(denied=True)
    a.jump(destructor_gate_entry)
    a.label('complete_done')
    restore()
    a.label('complete_replay')
    a.jump(destructor_gate_entry)

    code_end = code_base + len(a.w) * 4
    if code_end > 0x10000000:
        raise ValueError('delete release gates leave native MIPS jump region')
    if protected_end is not None and code_end > protected_end:
        raise ValueError('protected code does not contain complete delete release gates')
    if max(code_base, NATIVE_RX[0]) < min(code_end, NATIVE_RX[1]):
        raise ValueError('delete release gates overlap pinned native RX')
    for name, start, size in extents:
        if max(code_base, start) < min(code_end, start + size):
            raise ValueError('delete release gates overlap ' + name)
    hook_words(a.labels)
    return a.finish(), a.labels
