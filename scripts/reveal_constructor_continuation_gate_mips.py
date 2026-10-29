#!/usr/bin/env python3
"""Offline opt-in stops for two ignored constructor registration results.

Only saved S1 equal to pinned U and saved RA equal to the exact registration
return classify a genuine constructor registration return. A classified nonzero
V0 bypasses the local519FA0/name continuation by entering the existing native
epilogue. V1 is never interpreted. All other cases replay the original call.
The stopped constructor still returns its saved engine scalar, not registration
status, NULL, a new ownership handle or a normalized failure diagnostic.

HARD premises: genuine native routes and ABI, complete retained mapped writable
nonaliasing native136/128-byte frames and a separate192-byte architectural save
frame, coherent redirects, and all inherited native/import/storage premises.
The save precedes classification. Static layout checks do not validate dynamic
stack pointers, establish mapping/lifetime or make malformed native unwind safe.
Scalar U/RA scope tests do not authenticate fabricated invocations or frames.

No service, cleanup, unlock, graph/name lookup or UI call is made on the stopped
route. The ordinary and skipped-registration legacy routes remain unchanged,
including existing NULL faults. Higher callers still receive and may use the
engine. This is not caller/whole-instance isolation, repair, rollback, safe
retry/free authority, retention, a firmware image, installation or rendering.
"""

from build_reveal_bridge_diag import Asm, b
import reveal_registry_receipt_mips as receipt


FRAME, HI, LO = 192, 0x88, 0x8C
FIRST_FRAME, SECOND_FRAME = 136, 128
CONTROLLER_BYTES, MUTEX_BYTES = receipt.CONTROLLER_BYTES, receipt.MUTEX_BYTES
NATIVE_RX = receipt.NATIVE_RX
POSTWORK = 0x519FA0
FIRST_CONTINUATION, SECOND_CONTINUATION = 0x43AE9C, 0x43B040
FIRST_EPILOGUE, SECOND_EPILOGUE = 0x43AEA8, 0x43B04C
SAVE = {register: 0x10 + index * 4
        for index, register in enumerate(r for r in range(1, 32) if r != 29)}
HOOKS = {
    'first_gate': (0x43AE94, (0x0C1467E8, 0x02202021)),
    'second_gate': (0x43B038, (0x0C1467E8, 0x02202021)),
}


def hook_words(labels):
    """Return only local instruction-fetch overrides, never install hooks."""
    result = {}
    for name, (pc, _) in HOOKS.items():
        target = labels[name]
        if (type(target) is not int or target <= 0 or target % 4
                or target > 0xFFFFFFFC or (pc + 4) >> 28 != target >> 28):
            raise ValueError('continuation gate target must share native jump region')
        result[pc] = (b.j_type(2, target), 0)
    return result


def assemble(controller_address, registry_mutex_address, code_base, *,
             protected_code=None, extra_protected_data=()):
    """Emit bounded continuation gates without I/O or older-layout changes.

    protected_code=(start,bytes) must contain the complete fragment. Additional
    fixed extents are strict nonwrapping/disjoint static declarations, excluded
    from native and generated RX. They add no runtime stack/lifetime checks.
    R participates in these static layout checks only; no mutex is inspected.

    Decision reads only this gate's saved S1, RA and V0. It neither reads the
    saved native engine at SP+50 nor dereferences a native object. Both routes
    restore all saved GPRs and HI/LO before the exact native continuation. Stop
    uses the stock epilogue, which privately loads the saved engine and unwinds
    the genuine native frame. Forward recreates the displaced JAL's original
    RA and its delay A0=S1 effect before entering519FA0.
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
        raise ValueError('continuation gates must share native jump region')
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
            raise ValueError('protected code must contain continuation gates')
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
            b.r_type(0, 0, 8, 0x12), b.sw(8, LO, 29))

    def restore():
        a.e(b.lw(8, HI, 29), b.r_type(8, 0, 0, 0x11),
            b.lw(8, LO, 29), b.r_type(8, 0, 0, 0x13))
        for register, offset in SAVE.items():
            a.e(b.lw(register, offset, 29))
        a.e(b.addiu(29, 29, FRAME))

    for name, continuation, epilogue in (
            ('first_gate', FIRST_CONTINUATION, FIRST_EPILOGUE),
            ('second_gate', SECOND_CONTINUATION, SECOND_EPILOGUE)):
        save(name)
        stopped, forward = name + '_stopped', name + '_forward'
        # All classification uses this saved architectural snapshot. In
        # particular V1 and the native frame/object graph are not consulted.
        a.e(b.lw(8, SAVE[17], 29))
        equal(8, controller_address, forward)
        a.e(b.lw(8, SAVE[31], 29))
        equal(8, HOOKS[name][0], forward)
        a.e(b.lw(8, SAVE[2], 29))
        a.branch(4, 8, 0, forward)
        a.label(stopped)
        restore()
        # No invented engine NULL/status or uncertain cleanup/unlock: keep
        # the existing engine-return ABI and genuine native unwind exactly.
        a.jump(epilogue)
        a.label(forward)
        restore()
        a.label(name + '_replay')
        a.absolute(31, continuation)
        a.jump(POSTWORK, delay=b.move(4, 17))

    code_end = code_base + len(a.w) * 4
    if code_end > 0x10000000:
        raise ValueError('continuation gates leave native MIPS jump region')
    if protected_end is not None and code_end > protected_end:
        raise ValueError('protected code does not contain complete continuation gates')
    if max(code_base, NATIVE_RX[0]) < min(code_end, NATIVE_RX[1]):
        raise ValueError('continuation gates overlap pinned native RX')
    for name, start, size in extents:
        if max(code_base, start) < min(code_end, start + size):
            raise ValueError('continuation gates overlap ' + name)
    hook_words(a.labels)
    return a.finish(), a.labels
