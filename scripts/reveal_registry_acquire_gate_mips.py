#!/usr/bin/env python3
"""Offline opt-in native registration/delete raw-acquisition gates.

Two coherent inline redirects require the existing same-invocation receipt or
retirement CAPTURED witness with actual raw R status zero.  They precede the
registration allocator and the name-delete routine's first registry-ring read.
They do not read controller fields, shared history or a native graph to decide
admission.  A refusal returns FFFFFFFF/exact captured raw error, or FFFFFFFF/0
for an absent or incoherent witness, without guessing an unlock.

HARD premises: genuine native route/ABI, complete retained mapped writable
nonaliasing native40/56-byte frames and a separate192-byte bridge-save frame,
coherent fresh-witness redirects, ordinary mutex semantics, and every inherited
native/import/storage prerequisite.  Stock prologues already wrote their frames
before these gates.  This module does not validate arbitrary stack pointers or
promise a safe unwind for malformed/unmapped/aliased native frames.  Static
layout exclusions are not runtime frame protection or lifetime proof.

Successful admission preserves the complete gate-entry architecture before
replaying the displaced native effects.  Witness locals remain unchanged for
the later passive observers.  Raw uncertainty or a missing witness requires
external isolation; neither the native callers nor these gates implement it.
Native constructors and delete callers ignore failure and may continue unsafe
outer work.  Other unlink routes, missing later events and the registration
allocation-failure missing-unlock defect remain.  No LIVE/lease/free authority,
installer, firmware image, device operation or rendering is supplied.
"""

from build_reveal_bridge_diag import Asm, b
import reveal_registry_receipt_mips as receipt
import reveal_registry_retirement_mips as retirement


FRAME, HI, LO, RAW = 192, 0x88, 0x8C, 0x90
REGISTER_FRAME, DELETE_FRAME = 40, 56
CONTROLLER_BYTES, MUTEX_BYTES = receipt.CONTROLLER_BYTES, receipt.MUTEX_BYTES
NATIVE_RX = receipt.NATIVE_RX
ALLOCATOR, ALLOCATOR_RETURN = 0x4669E0, 0x438A18
REGISTER_EPILOGUE = 0x438A6C
DELETE_DELAY = 0x8E110000
DELETE_TAKEN, DELETE_FALLTHROUGH = 0x4395F4, 0x4395E0
SAVE = {register: 0x10 + index * 4
        for index, register in enumerate(r for r in range(1, 32) if r != 29)}
HOOKS = {
    'register_gate': (0x438A10, (0x0C119A78, 0x2404001C)),
    'delete_gate': (0x4395D4, (0x8EB00034, 0x16130006)),
}


def hook_words(labels):
    """Return only local fixture instruction-fetch overrides, not an installer."""
    result = {}
    for name, (pc, _) in HOOKS.items():
        target = labels[name]
        if (type(target) is not int or target <= 0 or target % 4
                or target > 0xFFFFFFFC or (pc + 4) >> 28 != target >> 28):
            raise ValueError('gate target must share its native jump region')
        result[pc] = (b.j_type(2, target), 0)
    return result


def assemble(controller_address, registry_mutex_address, code_base, *,
             protected_code=None, extra_protected_data=()):
    """Emit gates without I/O or alteration of any existing composition.

    protected_code=(start,bytes) must contain this complete fragment.  Extra
    fixed extents participate only in strict nonwrapping/disjoint static layout
    validation, including exclusion from native and generated RX.  They add no
    runtime guards and establish no mapping, independent stack or lifetime.

    Registration uses receipt TAG/PTR/RAW locals10/14/18.  Delete uses retirement
    TAG/RAW locals10/14.  The actual current native frame is bridgeSP+192.
    Denial accesses only the retained private/native frames under the HARD
    premises above, and never calls a service or native cleanup/unlock path.
    A V1 diagnostic from this direct native entry is not automatically preserved
    by the older checked creation/BCAP wrappers, which have their own return ABI.
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
        raise ValueError('gates must share the native jump region')
    for index, (name, start, size) in enumerate(extents):
        if max(start, NATIVE_RX[0]) < min(start + size, NATIVE_RX[1]):
            raise ValueError(name + ' overlaps pinned native RX')
        for other_name, other_start, other_size in extents[index + 1:]:
            if max(start, other_start) < min(start + size, other_start + other_size):
                raise ValueError(name + ' overlaps ' + other_name)

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
            raise ValueError('protected code must contain the gates')
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

    for name, u_register, tag, captured, raw_status in (
            ('register_gate', 16, receipt.TAG, receipt.CAPTURED,
             receipt.RAW_STATUS),
            ('delete_gate', 21, retirement.TAG, retirement.CAPTURED,
             retirement.RAW_STATUS)):
        save(name)
        denied, admitted = name + '_denied', name + '_admitted'
        # Only scalar registers and owned current-frame locals are examined.
        # In particular, no controller binding reload follows an uncertain raw
        # acquisition.  These are genuine-route witnesses, not authentication.
        a.e(b.lw(8, SAVE[u_register], 29))
        equal(8, controller_address, denied)
        a.e(b.lw(8, tag, 23))
        equal(8, captured, denied)
        if name == 'register_gate':
            a.e(b.lw(8, receipt.PTR, 23))
            equal(8, registry_mutex_address, denied)
        a.e(b.lw(8, raw_status, 23), b.sw(8, RAW, 29))
        a.branch(4, 8, 0, admitted)
        a.label(denied)
        restore(denied=True)
        if name == 'register_gate':
            a.jump(REGISTER_EPILOGUE)
        else:
            # The stock epilogue tail-calls registry unlock.  Denial must
            # instead unwind the genuine native frame directly to its caller.
            a.e(b.lw(31, 0x34, 29), b.lw(21, 0x30, 29),
                b.lw(20, 0x2C, 29), b.lw(19, 0x28, 29),
                b.lw(18, 0x24, 29), b.lw(17, 0x20, 29),
                b.lw(16, 0x1C, 29),
                b.r_type(31, 0, 0, 8), b.addiu(29, 29, DELETE_FRAME))
        a.label(admitted)
        restore()
        a.label(name + '_replay')
        if name == 'register_gate':
            # Reproduce original JAL's architectural RA, and its A0 delay
            # effect before allocator entry, without a relocated return PC.
            a.absolute(31, ALLOCATOR_RETURN)
            a.jump(ALLOCATOR, delay=b.addiu(4, 0, 28))
        else:
            a.e(HOOKS[name][1][0])
            a.label('delete_gate_replay_branch')
            a.branch(5, 16, 19, 'delete_gate_replay_taken')
            # Both native branch outcomes execute this exact original delay
            # instruction once.  Native4395DC is not executed a second time.
            a.w[-1] = DELETE_DELAY
            a.label('delete_gate_replay_fallthrough')
            a.jump(DELETE_FALLTHROUGH)
            a.label('delete_gate_replay_taken')
            a.jump(DELETE_TAKEN)

    code_end = code_base + len(a.w) * 4
    if code_end > 0x10000000:
        raise ValueError('gates leave the native MIPS jump region')
    if protected_end is not None and code_end > protected_end:
        raise ValueError('protected code does not contain the complete gates')
    if max(code_base, NATIVE_RX[0]) < min(code_end, NATIVE_RX[1]):
        raise ValueError('gates overlap pinned native RX')
    for name, start, size in extents:
        if max(code_base, start) < min(code_end, start + size):
            raise ValueError('gates overlap ' + name)
    hook_words(a.labels)
    return a.finish(), a.labels
