#!/usr/bin/env python3
"""Offline scoped stop after one ordinary Files-refresh destructor return.

Only saved S2 equal to pinned U and saved RA equal to native4ACD94 classify
this refresh caller's destructor result. A classified nonzero V0 enters the
existing pure epilogue4ACCE4 before the original branch delay overwrites V0
with1 and before later view recreation/offset-setting work. V1 is preserved
without interpretation. Foreign or zero results replay the original branch
and its V0=1 delay effect exactly once, retaining their preceding native ABI.

HARD premises: genuine native routes/ABI, the complete retained mapped writable
1160-byte native refresh frame and separate192-byte architectural save frame,
independent nonaliasing of simultaneously live frames with native/heap/shared/
RX storage, sufficient transitive stack, coherent redirects, and every inherited
native/import/storage premise. Saving precedes classification. Static layout
checks do not validate arbitrary SP, mapping/lifetime or malformed unwind;
scalar U/RA tests do not authenticate fabricated invocations or native frames.

The destructor call and its earlier cleanup already happened. A zero result
does not prove successful cleanup or the absence of masked errors. The other
destructor call at4ACD1C, other callers and higher callback continuation remain
outside this local stop. No graph read, new service, unlock, free, rollback,
retention, quarantine, caller coordination, retry/free permission, firmware
image, installer or device operation is supplied by this offline fragment.
"""

from build_reveal_bridge_diag import Asm, b
import reveal_registry_receipt_mips as receipt


FRAME, HI, LO = 192, 0x88, 0x8C
REFRESH_FRAME = 1160
EPILOGUE, TAKEN, FALLTHROUGH = 0x4ACCE4, 0x4ACCE4, 0x4ACD9C
REFRESH_DELAY = 0x24020001
CONTROLLER_BYTES, MUTEX_BYTES = receipt.CONTROLLER_BYTES, receipt.MUTEX_BYTES
NATIVE_RX = receipt.NATIVE_RX
SAVE = {register: 0x10 + index * 4
        for index, register in enumerate(r for r in range(1, 32) if r != 29)}
HOOKS = {
    'gate': (0x4ACD94, (0x1680FFD3, 0x24020001)),
}


def hook_words(labels):
    """Return the local fetch override, never install or alter a native image."""
    result = {}
    for name, (pc, _) in HOOKS.items():
        target = labels[name]
        if (type(target) is not int or target <= 0 or target % 4
                or target > 0xFFFFFFFC or (pc + 4) >> 28 != target >> 28):
            raise ValueError('refresh gate target must share native jump region')
        result[pc] = (b.j_type(2, target), 0)
    return result


def assemble(controller_address, registry_mutex_address, code_base, *,
             protected_code=None, extra_protected_data=()):
    """Emit one private continuation decision and exact native branch replay.

    protected_code=(start,bytes) must contain the complete fragment. U/R and
    extra fixed extents participate only in strict nonwrapping/disjoint static
    layout checks, including native/generated RX exclusion. They supply no
    runtime frame guard, native object lease or whole-instance isolation.

    Classification reads only saved S2, RA and V0 from the private snapshot.
    Stop restores all GPRs and HI/LO before native4ACCE4, bypassing4ACCE0's
    forced-success overwrite. Forward restores the same architecture before
    replaying the displaced S4/nonzero branch and V0=1 delay once; native
    4ACD98 is bypassed rather than executing its delay effect a second time.
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
        raise ValueError('refresh gate must share native jump region')
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
            raise ValueError('protected code must contain the refresh gate')
        if max(protected_start, NATIVE_RX[0]) < min(protected_end, NATIVE_RX[1]):
            raise ValueError('protected code overlaps pinned native RX')
        for name, start, size in extents:
            if max(protected_start, start) < min(protected_end, start + size):
                raise ValueError('protected code overlaps ' + name)

    a = Asm(code_base)

    def equal(register, value, failed):
        a.absolute(9, value)
        a.branch(5, register, 9, failed)

    def restore():
        a.e(b.lw(8, HI, 29), b.r_type(8, 0, 0, 0x11),
            b.lw(8, LO, 29), b.r_type(8, 0, 0, 0x13))
        for register, offset in SAVE.items():
            a.e(b.lw(register, offset, 29))
        a.e(b.addiu(29, 29, FRAME))

    a.label('gate')
    a.e(b.addiu(29, 29, -FRAME))
    for register, offset in SAVE.items():
        a.e(b.sw(register, offset, 29))
    a.e(b.r_type(0, 0, 8, 0x10), b.sw(8, HI, 29),
        b.r_type(0, 0, 8, 0x12), b.sw(8, LO, 29))
    # No controller, view, resource or native frame word is consulted here.
    # V1 remains an uninterpreted part of the saved architectural snapshot.
    a.e(b.lw(8, SAVE[18], 29))
    equal(8, controller_address, 'gate_forward')
    a.e(b.lw(8, SAVE[31], 29))
    equal(8, HOOKS['gate'][0], 'gate_forward')
    a.e(b.lw(8, SAVE[2], 29))
    a.branch(4, 8, 0, 'gate_forward')

    a.label('gate_stopped')
    restore()
    a.jump(EPILOGUE)

    a.label('gate_forward')
    restore()
    a.label('gate_replay')
    a.label('gate_replay_branch')
    a.branch(5, 20, 0, 'gate_replay_taken')
    # Both original branch outcomes execute this exact V0=1 effect once.
    a.w[-1] = REFRESH_DELAY
    a.label('gate_replay_fallthrough')
    a.jump(FALLTHROUGH)
    a.label('gate_replay_taken')
    a.jump(TAKEN)

    code_end = code_base + len(a.w) * 4
    if code_end > 0x10000000:
        raise ValueError('refresh gate leaves native MIPS jump region')
    if protected_end is not None and code_end > protected_end:
        raise ValueError('protected code does not contain the complete refresh gate')
    if max(code_base, NATIVE_RX[0]) < min(code_end, NATIVE_RX[1]):
        raise ValueError('refresh gate overlaps pinned native RX')
    for name, start, size in extents:
        if max(code_base, start) < min(code_end, start + size):
            raise ValueError('refresh gate overlaps ' + name)
    hook_words(a.labels)
    return a.finish(), a.labels
