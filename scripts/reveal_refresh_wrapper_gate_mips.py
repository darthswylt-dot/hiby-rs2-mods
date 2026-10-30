#!/usr/bin/env python3
"""Offline invocation-local wrapper exit after a classified refresh error.

HARD entry: the inherited refresh gate has already saved all30 non-SP GPRs
and HI/LO in its retained192-byte private frame and classified saved S2=U,
native destructor return RA4ACD94 and nonzero V0. This helper replaces only
the first HI-restore pair at that gate's gate_stopped label. It creates no
additional frame, does not repeat classification and is not an arbitrary API.

Only the genuine native1160-byte refresh frame's saved outer RA is examined.
For4AD8E0 it is retargeted to this helper's abort_return; other outer callers
retain their preceding error return. Both routes replay the displaced HI pair
and resume the complete inherited architectural restore. The native refresh
epilogue then restores its callee state, unwinds and returns exact V0/V1.

The selected abort uses the genuine48-byte wrapper frame: it loads that
frame's saved outer RA in its jump delay and enters native4AD904. The actual
remaining S3/S2/S1/S0 restoration and return run, while4AD8E0's continuation
and4AD900's V0=S1 overwrite are bypassed. No witness mailbox, shared latch,
new callback/service or post-error view/controller lookup is introduced.

HARD premises include genuine native routes/ABI, mapped writable retained
private192/refresh1160 and selected wrapper48 frames, independent nonaliasing
of simultaneously live frames with native/heap/shared/RX storage, sufficient
transitive stack and coherent inherited/new redirects. Static layout checks
do not validate SP, mapping/lifetime or malformed unwind, and scope constants
do not authenticate fabricated frames. Earlier cleanup, other refresh/tail
routes and higher callers remain outside this stop. It supplies no rollback,
retention, retry/free permission, whole-instance coordination, installer,
firmware image or device operation.
"""

from build_reveal_bridge_diag import Asm, b
import reveal_registry_receipt_mips as receipt


PARENT_STOP_PAIR = (0x8FA80088, 0x01000011)
FRAME, REFRESH_FRAME, WRAPPER_FRAME = 192, 1160, 48
OUTER_RA_OFFSET = FRAME + 0x484
WRAPPER_RETURN, WRAPPER_EPILOGUE = 0x4AD8E0, 0x4AD904
WRAPPER_RA_DELAY = 0x8FBF002C
CONTROLLER_BYTES, MUTEX_BYTES = receipt.CONTROLLER_BYTES, receipt.MUTEX_BYTES
NATIVE_RX = receipt.NATIVE_RX


def _parent_site(parent_stopped_address):
    if (type(parent_stopped_address) is not int
            or parent_stopped_address <= 0 or parent_stopped_address % 4
            or parent_stopped_address + 12 > 0x10000000
            or parent_stopped_address < NATIVE_RX[1]):
        raise ValueError('parent stopped pair must be generated RX in native jump region')


def hook_words(labels, parent_stopped_address):
    """Return one generated fetch override, never install or edit an image."""
    _parent_site(parent_stopped_address)
    target = labels['scope']
    if (type(target) is not int or target <= 0 or target % 4
            or target > 0xFFFFFFFC
            or (parent_stopped_address + 4) >> 28 != target >> 28):
        raise ValueError('wrapper helper target must share parent jump region')
    return {parent_stopped_address: (b.j_type(2, target), 0)}


def assemble(controller_address, registry_mutex_address, code_base,
             parent_stopped_address, *, protected_code=None,
             extra_protected_data=()):
    """Emit a private saved-return rewrite and the exact inherited HI replay.

    U/R and extra fixed extents participate only in strict static layout
    validation; the helper never reads those allocations. The generated parent
    pair and its separate resume instruction at parent+8 must precede this
    appended fragment. Supplied protected_code=(start,bytes) contains those
    twelve parent bytes and this complete helper. Declarations do not prove
    mapped retained native frames, ownership or coherent hook activation.
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
        raise ValueError('wrapper helper must share native jump region')
    _parent_site(parent_stopped_address)
    if parent_stopped_address + 12 > code_base:
        raise ValueError('parent stopped pair and resume must precede wrapper helper')
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
            raise ValueError('protected code must contain parent pair and wrapper helper')
        if max(protected_start, NATIVE_RX[0]) < min(protected_end, NATIVE_RX[1]):
            raise ValueError('protected code overlaps pinned native RX')
        for name, start, size in extents:
            if max(protected_start, start) < min(protected_end, start + size):
                raise ValueError('protected code overlaps ' + name)

    a = Asm(code_base)
    a.label('scope')
    # The inherited gate has already classified the pinned-U refresh error.
    # Follow the actual current C frame, not a view/resource or shared latch.
    a.e(b.lw(8, OUTER_RA_OFFSET, 29))
    a.absolute(9, WRAPPER_RETURN)
    a.branch(5, 8, 9, 'replay')
    a.label('selected')
    abort_fixup = len(a.w)
    a.absolute(8, 0)
    a.e(b.sw(8, OUTER_RA_OFFSET, 29))
    a.label('replay')
    a.e(*PARENT_STOP_PAIR)
    a.jump(parent_stopped_address + 8)
    a.label('abort_return')
    # Native C has restored/unwound its1160 bytes; SP is now genuine W.
    # Load W's outer RA once, skip4AD900's result overwrite, and let the
    # Actual remaining native callee restoration and48-byte return execute.
    a.jump(WRAPPER_EPILOGUE, delay=WRAPPER_RA_DELAY)
    abort_return = a.labels['abort_return']
    a.w[abort_fixup:abort_fixup + 2] = (
        b.lui(8, abort_return >> 16), b.ori(8, 8, abort_return & 0xFFFF))

    code_end = code_base + len(a.w) * 4
    if code_end > 0x10000000:
        raise ValueError('wrapper helper leaves native MIPS jump region')
    if protected_end is not None and code_end > protected_end:
        raise ValueError('protected code does not contain complete wrapper helper')
    if max(code_base, NATIVE_RX[0]) < min(code_end, NATIVE_RX[1]):
        raise ValueError('wrapper helper overlaps pinned native RX')
    for name, start, size in extents:
        if max(code_base, start) < min(code_end, start + size):
            raise ValueError('wrapper helper overlaps ' + name)
    hook_words(a.labels, parent_stopped_address)
    return a.finish(), a.labels
