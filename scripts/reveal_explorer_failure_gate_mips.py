#!/usr/bin/env python3
"""Offline invocation-local explorer exit after a classified constructor error.

HARD entry: the inherited first constructor gate has already saved all GPRs
and HI/LO in its retained192-byte private frame and classified pinned S1=U,
registration RA43AE94 and nonzero V0. This helper is entered by replacing the
first restore pair at that gate's first_gate_stopped label. It does not create
another frame or repeat that classification.

Only the genuine native constructor's saved outer RA is read. For492920 it is
rewritten to a private-code trampoline; all other outer callers are unchanged.
Both routes replay the displaced HI restore and resume the inherited restore.
The stock constructor epilogue still returns its engine scalar. The selected
trampoline then enters the explorer's stock NULL-return exit492F84, avoiding
that invocation's remaining explorer continuation without a shared latch.

The genuine constructor136/private192 and selected explorer6096-byte frames
must be mapped, writable, retained and nonaliasing. Static layout checks do
not validate stacks, authenticate fabricated frames or establish lifetime.
There is no new U/R/engine/name/shared read, service, cleanup, free, unlock,
rollback, owner handle, installer or device operation. Earlier side effects,
masked failures, other callers and whole-instance isolation remain outside
this local stop; all inherited and new redirects must be coherent.
"""

from build_reveal_bridge_diag import Asm, b
import reveal_registry_receipt_mips as receipt


PARENT_STOP_PAIR = (0x8FA80088, 0x01000011)
FRAME, FIRST_FRAME, EXPLORER_FRAME = 192, 136, 6096
OUTER_RA_OFFSET = FRAME + 0x84
EXPLORER_RETURN, EXPLORER_FAILURE = 0x492920, 0x492F84
CONTROLLER_BYTES, MUTEX_BYTES = receipt.CONTROLLER_BYTES, receipt.MUTEX_BYTES
NATIVE_RX = receipt.NATIVE_RX


def _parent_site(parent_stopped_address):
    if (type(parent_stopped_address) is not int
            or parent_stopped_address <= 0 or parent_stopped_address % 4
            or parent_stopped_address + 12 > 0x10000000
            or parent_stopped_address < NATIVE_RX[1]):
        raise ValueError('parent stopped pair must be generated RX in native jump region')


def hook_words(labels, parent_stopped_address):
    """Return one local generated instruction-fetch override, not an installer."""
    _parent_site(parent_stopped_address)
    target = labels['scope']
    if (type(target) is not int or target <= 0 or target % 4
            or target > 0xFFFFFFFC
            or (parent_stopped_address + 4) >> 28 != target >> 28):
        raise ValueError('explorer helper target must share parent jump region')
    return {parent_stopped_address: (b.j_type(2, target), 0)}


def assemble(controller_address, registry_mutex_address, code_base,
             parent_stopped_address, *, protected_code=None,
             extra_protected_data=()):
    """Emit a bounded private saved-return rewrite and exact parent replay.

    U, R and additional fixed extents participate only in static validation;
    this helper never reads them. The parent pair must precede this appended
    fragment, with a separate resume instruction at parent+8. A supplied
    complete protected RX extent must contain the parent pair and its resume
    instruction plus this complete fragment. This validates declared addresses,
    not runtime frame ownership, mapping or coherent hook activation.
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
        raise ValueError('explorer helper must share native jump region')
    _parent_site(parent_stopped_address)
    if parent_stopped_address + 12 > code_base:
        raise ValueError('parent stopped pair and resume must precede explorer helper')
    for index, (name, start, size) in enumerate(extents):
        if max(start, NATIVE_RX[0]) < min(start + size, NATIVE_RX[1]):
            raise ValueError(name + ' overlaps pinned native RX')
        if max(start, parent_stopped_address) < min(start + size, parent_stopped_address + 12):
            raise ValueError(name + ' overlaps parent stopped RX pair or resume')
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
                or not protected_start <= parent_stopped_address
                or parent_stopped_address + 12 > protected_end
                or not protected_start <= code_base < protected_end):
            raise ValueError('protected code must contain parent pair and explorer helper')
        if max(protected_start, NATIVE_RX[0]) < min(protected_end, NATIVE_RX[1]):
            raise ValueError('protected code overlaps pinned native RX')
        for name, start, size in extents:
            if max(protected_start, start) < min(protected_end, start + size):
                raise ValueError('protected code overlaps ' + name)

    a = Asm(code_base)
    a.label('scope')
    # The parent has already classified this genuine failed registration.
    # No controller, engine, shared latch or additional native local is read.
    a.e(b.lw(8, OUTER_RA_OFFSET, 29))
    a.absolute(9, EXPLORER_RETURN)
    a.branch(5, 8, 9, 'replay')
    a.label('selected')
    abort_fixup = len(a.w)
    a.absolute(8, 0)
    a.e(b.sw(8, OUTER_RA_OFFSET, 29))
    a.label('replay')
    a.e(*PARENT_STOP_PAIR)
    a.jump(parent_stopped_address + 8)
    a.label('abort_return')
    # Stock43AEA8 has already restored/unwound the constructor. Native SP is
    # now the genuine explorer frame; its own failure epilogue returns NULL.
    a.jump(EXPLORER_FAILURE)
    abort_return = a.labels['abort_return']
    a.w[abort_fixup:abort_fixup + 2] = (
        b.lui(8, abort_return >> 16), b.ori(8, 8, abort_return & 0xFFFF))

    code_end = code_base + len(a.w) * 4
    if code_end > 0x10000000:
        raise ValueError('explorer helper leaves native MIPS jump region')
    if protected_end is not None and code_end > protected_end:
        raise ValueError('protected code does not contain complete explorer helper')
    if max(code_base, NATIVE_RX[0]) < min(code_end, NATIVE_RX[1]):
        raise ValueError('explorer helper overlaps pinned native RX')
    for name, start, size in extents:
        if max(code_base, start) < min(code_end, start + size):
            raise ValueError('explorer helper overlaps ' + name)
    hook_words(a.labels, parent_stopped_address)
    return a.finish(), a.labels
