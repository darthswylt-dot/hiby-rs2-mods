#!/usr/bin/env python3
"""Offline dialog exit after an inherited, classified callback failure.

The two entries replace generated callback-abort J/NOP pairs, not native
callback entries or a generic V0 classifier. Each genuine callback B frame
is saved privately before its actual saved caller is read. Only47C7D0 selects
a rewrite of B.savedRA to error_return. Full architectural restoration and the
original native B epilogue then establish the genuine D104 dialog frame.

At error_return, classification is carried by that actual return PC. A fresh
ADMITTED/raw-zero acquisition observation is consumed before one direct raw
unlock of the saved M. Immediate raw status is recorded separately from the
original callback V0/V1, which survives every result. Missing proof performs
no release. All outcomes skip dialog graph cleanup, destroy/free and retries.

HARD premises additionally require initialized retained ordinary M, continuous
same-thread ownership from acquisition through this callback handoff, and no
intervening unlock/relock/destroy/transfer by any transitive callee. ADMITTED
alone proves none of those properties. Genuine routes, mapped writable retained
independently nonaliasing simultaneously live B5312/40, D104 and private192
frames, sufficient
transitive stack, import ABI cooperation and coherent redirects remain premises.
Saved PCs/tags and static exclusions do not authenticate frames or establish
lifetime, arbitrary-SP recovery, worker quiescence or outer-caller isolation.
Earlier +0C processing, escaped aliases and the outer dialog frees remain.
No installer, firmware image or device operation is supplied.
"""

from build_reveal_bridge_diag import Asm, b
import reveal_registry_receipt_mips as receipt
import reveal_dialog_acquire_gate_mips as acquire


FRAME, HI, LO = 192, 0x88, 0x8C
FIRST_CALLBACK_FRAME, SECOND_CALLBACK_FRAME = 5312, 40
FIRST_RA, SECOND_RA = 0x14BC, 0x24
FIRST_EPILOGUE, SECOND_EPILOGUE = 0x4AECD8, 0x450DAC
DIALOG_FRAME, DIALOG_RETURN, EPILOGUE = 104, 0x47C7D0, 0x47C814
TAG, MUTEX, STATUS = 0x10, 0x14, 0x58
ATTEMPTING = int.from_bytes(b'DGAT', 'little')
NO_RELEASE = int.from_bytes(b'DGNR', 'little')
RELEASE_ZERO = int.from_bytes(b'DGR0', 'little')
RELEASE_ERROR = int.from_bytes(b'DGRE', 'little')
RAW_UNLOCK = receipt.RAW_UNLOCK
CONTROLLER_BYTES, MUTEX_BYTES = receipt.CONTROLLER_BYTES, receipt.MUTEX_BYTES
NATIVE_RX = receipt.NATIVE_RX
SAVE = {register: 0x10 + index * 4
        for index, register in enumerate(r for r in range(1, 32) if r != 29)}
PARENT_FIRST_PAIR = (b.j_type(2, FIRST_EPILOGUE), 0)
PARENT_SECOND_PAIR = (b.j_type(2, SECOND_EPILOGUE), 0)


def _parent_sites(first, second):
    for address in (first, second):
        if (type(address) is not int or address <= 0 or address % 4
                or address < NATIVE_RX[1] or address + 8 > 0x10000000):
            raise ValueError('parent abort pairs must be generated native-region RX')
    if max(first, second) < min(first + 8, second + 8):
        raise ValueError('parent abort pairs must be disjoint')


def hook_words(labels, parent_first_abort, parent_second_abort):
    """Return two generated fetch overrides, never install or edit an image."""
    _parent_sites(parent_first_abort, parent_second_abort)
    result = {}
    for name, pc in (('first_scope', parent_first_abort),
                     ('second_scope', parent_second_abort)):
        target = labels[name]
        if (type(target) is not int or target <= 0 or target % 4
                or target > 0xFFFFFFFC or (pc + 4) >> 28 != target >> 28):
            raise ValueError('dialog failure helper must share parent jump region')
        result[pc] = (b.j_type(2, target), 0)
    return result


def assemble(controller_address, registry_mutex_address, code_base,
             parent_first_abort, parent_second_abort, *, protected_code=None,
             extra_protected_data=()):
    """Emit private return rewrites and one qualified raw release attempt.

    Both parent8 regions precede the fragment and belong to complete protected
    RX when supplied. U/R and extra extents are static declarations only; no
    H/U/M object is dereferenced after failure. The actual saved M scalar is
    passed to the raw import under the separate continuous-ownership premise.
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
        raise ValueError('dialog failure helper must share native jump region')
    _parent_sites(parent_first_abort, parent_second_abort)
    parents = ((parent_first_abort, 8), (parent_second_abort, 8))
    if any(start + size > code_base for start, size in parents):
        raise ValueError('both parent abort pairs must precede the helper')
    for index, (name, start, size) in enumerate(extents):
        if max(start, NATIVE_RX[0]) < min(start + size, NATIVE_RX[1]):
            raise ValueError(name + ' overlaps pinned native RX')
        for parent, parent_bytes in parents:
            if max(start, parent) < min(start + size, parent + parent_bytes):
                raise ValueError(name + ' overlaps parent abort RX')
        for other_name, other, other_bytes in extents[index + 1:]:
            if max(start, other) < min(start + size, other + other_bytes):
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
                or any(not protected_start <= start or start + size > protected_end
                       for start, size in parents)):
            raise ValueError('protected code must contain both abort pairs and helper')
        if max(protected_start, NATIVE_RX[0]) < min(protected_end, NATIVE_RX[1]):
            raise ValueError('protected code overlaps pinned native RX')
        for name, start, size in extents:
            if max(protected_start, start) < min(protected_end, start + size):
                raise ValueError('protected code overlaps ' + name)

    a = Asm(code_base)

    def save(name):
        a.label(name)
        a.e(b.addiu(29, 29, -FRAME))
        for register, offset in SAVE.items():
            a.e(b.sw(register, offset, 29))
        a.e(b.r_type(0, 0, 8, 0x10), b.sw(8, HI, 29),
            b.r_type(0, 0, 8, 0x12), b.sw(8, LO, 29),
            b.addiu(23, 29, FRAME))

    def restore():
        a.e(b.lw(8, HI, 29), b.r_type(8, 0, 0, 0x11),
            b.lw(8, LO, 29), b.r_type(8, 0, 0, 0x13))
        for register, offset in SAVE.items():
            a.e(b.lw(register, offset, 29))
        a.e(b.addiu(29, 29, FRAME))

    fixups = []
    for name, offset, epilogue in (('first', FIRST_RA, FIRST_EPILOGUE),
                                   ('second', SECOND_RA, SECOND_EPILOGUE)):
        save(name + '_scope')
        a.e(b.lw(8, offset, 23))
        a.absolute(9, DIALOG_RETURN)
        a.branch(5, 8, 9, name + '_done')
        a.label(name + '_selected')
        fixups.append(len(a.w))
        a.absolute(8, 0)
        a.e(b.sw(8, offset, 23))
        a.label(name + '_done')
        restore()
        a.label(name + '_replay')
        a.jump(epilogue)

    save('error_return')
    # D is retained in callee-saved S7 across the one raw service.
    a.e(b.lw(8, TAG, 23), b.sw(0, TAG, 23))
    a.absolute(9, acquire.ADMITTED)
    a.branch(5, 8, 9, 'no_release')
    a.e(b.lw(8, STATUS, 23))
    a.branch(5, 8, 0, 'no_release')
    a.label('release_attempt')
    a.absolute(8, ATTEMPTING)
    a.e(b.sw(8, TAG, 23), b.lw(4, MUTEX, 23))
    # Only homes00..0F may be clobbered by the ordinary raw import. Saved
    # callback V0/V1 and HI/LO occupy10..8C and are restored after capture.
    a.jump(RAW_UNLOCK, link=True)
    a.label('release_return')
    a.e(b.sw(2, STATUS, 23))
    a.branch(4, 2, 0, 'release_zero')
    a.label('release_error')
    a.absolute(8, RELEASE_ERROR)
    a.e(b.sw(8, TAG, 23))
    a.jump('release_done')
    a.label('release_zero')
    a.absolute(8, RELEASE_ZERO)
    a.e(b.sw(8, TAG, 23))
    a.jump('release_done')
    a.label('no_release')
    a.e(b.sw(0, STATUS, 23))
    a.absolute(8, NO_RELEASE)
    a.e(b.sw(8, TAG, 23))
    a.label('release_done')
    restore()
    a.label('exit_replay')
    a.jump(EPILOGUE)
    for fixup in fixups:
        target = a.labels['error_return']
        a.w[fixup:fixup + 2] = (b.lui(8, target >> 16), b.ori(8, 8, target & 0xFFFF))

    code_end = code_base + len(a.w) * 4
    if code_end > 0x10000000:
        raise ValueError('dialog failure helper leaves native jump region')
    if protected_end is not None and code_end > protected_end:
        raise ValueError('protected code does not contain complete dialog failure helper')
    if max(code_base, NATIVE_RX[0]) < min(code_end, NATIVE_RX[1]):
        raise ValueError('dialog failure helper overlaps pinned native RX')
    for name, start, size in extents:
        if max(code_base, start) < min(code_end, start + size):
            raise ValueError('dialog failure helper overlaps ' + name)
    hook_words(a.labels, parent_first_abort, parent_second_abort)
    return a.finish(), a.labels
