#!/usr/bin/env python3
"""Offline constructor-scoped propagation of actual registry release results.

Four coherent phases reuse registration locals10/14/18 only after publication
has consumed the acquisition receipt. Selection is limited to pinned S0=U and
native registration callers43AE94/43B038. A fresh SELECTED -> ENTERED ->
CAPTURED witness binds the actual raw result to this native invocation. The
completion gate consumes it: raw zero preserves native success, actual nonzero
returns FFFFFFFF/exact_status, and missing/incoherent evidence FFFFFFFF/zero.
This scoped V1 result does not normalize other native allocation-failure ABIs.
The completion hook retains source+6C's saved-RA load as its jump delay:
native allocation/acquisition refusals can independently enter that word.
The bridge therefore saves architecture after this original RA-load effect.

The first three bridges always restore all entry architecture and tail-chain
the existing release observers. They neither duplicate a raw call nor relocate
its original438A68/466DD0 return PCs. Explicit checked-capture wrappers and
foreign native routes retain their preceding observer behavior. Unknown
callbacks still execute through that inherited route; absent fresh evidence
then refuses constructor continuation, not the callback's earlier effects.

HARD premises: genuine native routes/ABI and complete mapped, retained,
writable, nonaliasing registration40, facade32, raw32 and separate192-byte
architectural-save frames, sufficient aggregate/transitive service stack,
coherent redirects and all inherited native/import/storage prerequisites.
Saving precedes classification. Scalar scope and static layout exclusions do
not authenticate fabricated frames, validate arbitrary SP or establish lifetime.
No controller/engine/name/shared graph is read, no new raw service is called,
and no unlock retry, free, rollback, quarantine, installer or device operation
is supplied. Earlier publication and ambiguous mutex ownership remain.
"""

from build_reveal_bridge_diag import Asm, b
import reveal_registry_receipt_mips as receipt


FRAME, HI, LO, RAW = 192, 0x88, 0x8C, 0x90
REGISTER_FRAME, FACADE_FRAME, RAW_FRAME = 40, 32, 32
TAG, STATUS, RAW_SP = 0x10, 0x14, 0x18
SELECTED = int.from_bytes(b'NRSL', 'little')
ENTERED = int.from_bytes(b'NREN', 'little')
CAPTURED = int.from_bytes(b'NRCP', 'little')
CONSTRUCTOR_RETURNS = (0x43AE94, 0x43B038)
REGISTRY_UNLOCK = receipt.REGISTRY_UNLOCK
REGISTRATION_RELEASE_RETURN, RAW_RELEASE_RETURN = 0x438A68, 0x466DD0
REGISTRATION_EPILOGUE, COMPLETE_CONTINUATION = 0x438A6C, 0x438A70
CONTROLLER_BYTES, MUTEX_BYTES = receipt.CONTROLLER_BYTES, receipt.MUTEX_BYTES
NATIVE_RX = receipt.NATIVE_RX
SAVE = {register: 0x10 + index * 4
        for index, register in enumerate(r for r in range(1, 32) if r != 29)}
HOOKS = {
    'release_select': (0x438A60, (0x0320F809, 0x02002021)),
    'raw_release_call': (0x466DC8, (0x0C296E0C, 0)),
    'raw_release_return': (0x466DD0, (0x8FBF001C, 0x00001021)),
    'complete': (0x438A68, (0x00001021, 0x8FBF0024)),
}


def hook_words(labels):
    """Return four local native instruction-fetch overrides, not an installer."""
    result = {}
    for name, (pc, _) in HOOKS.items():
        target = labels[name]
        if (type(target) is not int or target <= 0 or target % 4
                or target > 0xFFFFFFFC or (pc + 4) >> 28 != target >> 28):
            raise ValueError('release gate target must share native jump region')
        #438A6C is also independently reached by allocation/acquisition denial.
        # Keep its original word executable in place, and execute it exactly
        # once as the completion J delay before this bridge saves architecture.
        delay = HOOKS[name][1][1] if name == 'complete' else 0
        result[pc] = (b.j_type(2, target), delay)
    return result


def assemble(controller_address, registry_mutex_address, code_base,
             release_call_entry, raw_release_call_entry, raw_release_return_entry,
             *, protected_code=None, extra_protected_data=()):
    """Emit private release witnesses plus a scoped native completion result.

    The three legacy observer entries must be distinct aligned generated RX
    before this appended fragment. A complete advertised protected RX extent
    must contain each entry and this complete fragment. U/R and extra fixed
    allocations participate in layout validation only; there are no dynamic
    frame guards or shared-object accesses in this helper.

    Entrypoints are release_select, raw_release_call, raw_release_return and
    complete. Each observer phase exposes *_done and *_replay labels. Complete
    additionally exposes *_admitted and *_denied. All three observer phases
    tail-chain their supplied legacy entry even after matching new evidence.
    Complete saves/restores the post-delay architecture: its source jump has
    already loaded RA from native+24. Both completion outcomes resume at70,
    never repeating or bypassing that independently addressable source load.
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
        raise ValueError('release gates must share native jump region')
    legacy_entries = (release_call_entry, raw_release_call_entry,
                      raw_release_return_entry)
    for entry in legacy_entries:
        if (type(entry) is not int or entry <= 0 or entry % 4
                or entry < NATIVE_RX[1] or entry + 4 > code_base
                or entry + 4 > 0x10000000):
            raise ValueError('legacy release entries must be preceding aligned generated RX')
    if len(set(legacy_entries)) != len(legacy_entries):
        raise ValueError('legacy release observer entries must be distinct')
    for index, (name, start, size) in enumerate(extents):
        if max(start, NATIVE_RX[0]) < min(start + size, NATIVE_RX[1]):
            raise ValueError(name + ' overlaps pinned native RX')
        for entry in legacy_entries:
            if max(start, entry) < min(start + size, entry + 4):
                raise ValueError(name + ' overlaps legacy release RX entry')
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

    def constructor_scope(name, failed, raw=False):
        # Saved S0, not a controller-field reload, classifies pinned U.
        a.e(b.lw(8, SAVE[16], 29))
        equal(8, controller_address, failed)
        if raw:
            # W is the raw wrapper frame; its saved return and the facade's
            # saved return are checked before following the deeper N frame.
            a.e(b.lw(8, 0x1C, 23))
            equal(8, 0x437DB0, failed)
            a.e(b.lw(8, 0x3C, 23))
            equal(8, REGISTRATION_RELEASE_RETURN, failed)
            a.e(b.addiu(22, 23, FACADE_FRAME + RAW_FRAME))
        else:
            a.e(b.move(22, 23))
        a.e(b.lw(8, 0x24, 22))
        a.absolute(9, CONSTRUCTOR_RETURNS[0])
        a.branch(4, 8, 9, name + '_classified')
        equal(8, CONSTRUCTOR_RETURNS[1], failed)
        a.label(name + '_classified')

    save('release_select')
    constructor_scope('release_select', 'release_select_done')
    # Fresh even when the selected indirect callback is not the pinned one.
    # The inherited observer still executes that callback once; the later
    # completion gate then refuses the absent release witness.
    a.e(b.sw(0, TAG, 22), b.addiu(8, 0, -1),
        b.sw(8, STATUS, 22), b.sw(0, RAW_SP, 22),
        b.lw(8, SAVE[25], 29))
    equal(8, REGISTRY_UNLOCK, 'release_select_done')
    a.absolute(8, SELECTED)
    a.e(b.sw(8, TAG, 22))
    a.label('release_select_done')
    restore()
    a.label('release_select_replay')
    a.jump(release_call_entry)

    save('raw_release_call')
    constructor_scope('raw_release_call', 'raw_release_call_done', raw=True)
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
    constructor_scope('raw_release_return', 'raw_release_return_done', raw=True)
    a.e(b.lw(8, SAVE[31], 29))
    equal(8, RAW_RELEASE_RETURN, 'raw_release_return_done')
    a.e(b.lw(8, TAG, 22), b.sw(0, TAG, 22))
    equal(8, ENTERED, 'raw_release_return_done')
    a.e(b.lw(8, RAW_SP, 22))
    a.branch(5, 8, 23, 'raw_release_return_done')
    a.e(b.lw(8, SAVE[2], 29), b.sw(8, STATUS, 22))
    a.absolute(8, CAPTURED)
    a.e(b.sw(8, TAG, 22))
    a.label('raw_release_return_done')
    restore()
    a.label('raw_release_return_replay')
    a.jump(raw_release_return_entry)

    save('complete')
    constructor_scope('complete', 'complete_done')
    a.e(b.lw(8, TAG, 22), b.sw(0, TAG, 22))
    equal(8, CAPTURED, 'complete_denied')
    a.e(b.lw(8, RAW_SP, 22),
        b.addiu(9, 23, -(FACADE_FRAME + RAW_FRAME)))
    a.branch(5, 8, 9, 'complete_denied')
    # Only a coherent consumed capture permits reading its actual raw status.
    a.e(b.lw(8, STATUS, 22))
    a.branch(4, 8, 0, 'complete_admitted')
    a.e(b.sw(8, RAW, 29))
    a.jump('complete_denied')
    a.label('complete_admitted')
    a.jump('complete_done')
    a.label('complete_denied')
    restore(denied=True)
    a.jump(COMPLETE_CONTINUATION)
    a.label('complete_done')
    restore()
    a.label('complete_replay')
    # The native+24 RA load already ran once in the source J delay. Reproduce
    # only the original V0-zero effect on ordinary/foreign completion paths.
    a.e(HOOKS['complete'][1][0])
    a.jump(COMPLETE_CONTINUATION)

    code_end = code_base + len(a.w) * 4
    if code_end > 0x10000000:
        raise ValueError('release gates leave native MIPS jump region')
    if protected_end is not None and code_end > protected_end:
        raise ValueError('protected code does not contain complete release gates')
    if max(code_base, NATIVE_RX[0]) < min(code_end, NATIVE_RX[1]):
        raise ValueError('release gates overlap pinned native RX')
    for name, start, size in extents:
        if max(code_base, start) < min(code_end, start + size):
            raise ValueError('release gates overlap ' + name)
    hook_words(a.labels)
    return a.finish(), a.labels
