#!/usr/bin/env python3
"""Offline opt-in stop after one ignored explorer-destructor delete result.

Only saved S1 equal to pinned U and saved RA equal to the exact493F4C native
return classify this destructor's name-delete completion. A classified nonzero
V0 enters its existing pure native epilogue before the resource-controller
load and remaining cleanup. V1 is preserved without interpretation. Other
routes replay the native resource call with its original argument effects and
return PC. A zero result remains only the older native ABI, not cleanup proof.

HARD premises: genuine native routes and ABI, the complete1208-byte destructor
frame and separate192-byte architectural save frame already mapped, retained,
writable and independently nonaliasing with native/heap/shared/RX storage,
coherent redirects, ordinary mutex semantics, sufficient transitive stack, and
all inherited native/import/storage premises. Saving precedes classification.
Static layout checks do not validate arbitrary SP or mapping/lifetime, and the
scalar U/RA checks do not authenticate fabricated invocations or native frames.

The stop makes no service, unlock, graph access or free. Earlier worker/list,
controller/cache and purge/detach effects remain. A masked delete-release error
still returns native zero and forwards. The49 encoded outer destructor callers
and computed/callback routes remain unisolated. No partial-graph cleanup,
rollback, retention, quarantine, retry/free permission, image or installer is
supplied. These bytes and hook metadata are only an offline opt-in fragment.
"""

from build_reveal_bridge_diag import Asm, b
import reveal_registry_receipt_mips as receipt


FRAME, HI, LO = 192, 0x88, 0x8C
DESTRUCTOR_FRAME = 1208
EPILOGUE, CONTINUATION = 0x493C98, 0x493F58
RESOURCE_DELETE, RESOURCE_DELAY = 0x485320, 0x02602821
CONTROLLER_BYTES, MUTEX_BYTES = receipt.CONTROLLER_BYTES, receipt.MUTEX_BYTES
NATIVE_RX = receipt.NATIVE_RX
SAVE = {register: 0x10 + index * 4
        for index, register in enumerate(r for r in range(1, 32) if r != 29)}
HOOKS = {
    'gate': (0x493F4C, (0x8E240024, 0x0C1214C8)),
}


def hook_words(labels):
    """Return the local two-word instruction-fetch override, never install it."""
    result = {}
    for name, (pc, _) in HOOKS.items():
        target = labels[name]
        if (type(target) is not int or target <= 0 or target % 4
                or target > 0xFFFFFFFC or (pc + 4) >> 28 != target >> 28):
            raise ValueError('destructor gate target must share native jump region')
        result[pc] = (b.j_type(2, target), 0)
    return result


def assemble(controller_address, registry_mutex_address, code_base, *,
             protected_code=None, extra_protected_data=()):
    """Emit the bounded continuation gate without I/O or native image edits.

    protected_code=(start,bytes) must contain the complete fragment. Extra
    fixed extents participate only in strict nonwrapping/disjoint static
    validation, including native/generated RX exclusion. They add no runtime
    frame checks, mapping guarantees or native allocation leases. R is used
    only for static layout validation; neither it nor U is read to classify.

    A stopped route restores all saved GPRs and HI/LO, then jumps to493C98.
    The genuine native epilogue preserves V0/V1, restores callee registers and
    unwinds1208 bytes without graph work or unlock. Forwarding restores the
    same architecture before replaying the displaced controller load once,
    setting the resource call's original RA493F58 and executing its original
    A1=S3 delay effect once. Native493F54 is bypassed, not executed again.
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
        raise ValueError('destructor gate must share native jump region')
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
            raise ValueError('protected code must contain the destructor gate')
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
    # The decision reads only this invocation's private architectural snapshot.
    # V1 and native/controller/resource fields are not failure classifiers.
    a.e(b.lw(8, SAVE[17], 29))
    equal(8, controller_address, 'gate_forward')
    a.e(b.lw(8, SAVE[31], 29))
    equal(8, HOOKS['gate'][0], 'gate_forward')
    a.e(b.lw(8, SAVE[2], 29))
    a.branch(4, 8, 0, 'gate_forward')

    a.label('gate_stopped')
    restore()
    #493C98 begins with private saved-register loads. Do not enter493C7C's
    #callback/name continuation or493C94's native success-result overwrite.
    a.jump(EPILOGUE)

    a.label('gate_forward')
    restore()
    a.label('gate_replay')
    a.e(HOOKS['gate'][1][0])
    # The displaced JAL's original architectural RA is retained, rather than
    # a relocated helper return. The separately audited493F54 delay runs once.
    a.absolute(31, CONTINUATION)
    a.jump(RESOURCE_DELETE, delay=RESOURCE_DELAY)

    code_end = code_base + len(a.w) * 4
    if code_end > 0x10000000:
        raise ValueError('destructor gate leaves native MIPS jump region')
    if protected_end is not None and code_end > protected_end:
        raise ValueError('protected code does not contain the complete destructor gate')
    if max(code_base, NATIVE_RX[0]) < min(code_end, NATIVE_RX[1]):
        raise ValueError('destructor gate overlaps pinned native RX')
    for name, start, size in extents:
        if max(code_base, start) < min(code_end, start + size):
            raise ValueError('destructor gate overlaps ' + name)
    hook_words(a.labels)
    return a.finish(), a.labels
