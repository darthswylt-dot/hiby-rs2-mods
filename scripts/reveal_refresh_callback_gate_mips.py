#!/usr/bin/env python3
"""Offline saved-return exits for two classified refresh callback callers.

HARD entry: the inherited wrapper helper has reached selected after its
parent saved all30 non-SP GPRs and HI/LO in192 private bytes, classified
saved S2=U, RA4ACD94 and nonzero V0, and checked actual C.savedRA=4AD8E0.
This helper replaces that selected path's first LUI/ORI pair. No new frame,
repeated failure classification, service or result mailbox is introduced.

With current private SP=P, C=P+C0 and W=P+548 hex. Only the genuine W.savedRA
at P+574 is read. Exact4AEEE8 or450DA4 selects a rewrite to its own callback
thunk; other W callers keep their saved return. Every route replays the
parent's exact T0 abort-return materialization and resumes its existing C
saved-return write. The inherited full restore and native C/W unwinds then
preserve exact V0/V1. The new thunks enter the corresponding pure native
callback epilogues with the actual callback SP, without operation-context
free/clear work. Skipping a free does not establish native allocation lifetime.

HARD premises: genuine native routes/ABI, mapped retained writable private192,
refresh1160, wrapper48 and selected callback5312/40 frames, independent
nonaliasing of simultaneously live frames with native/heap/shared/RX storage,
sufficient transitive stack and coherent inherited/new redirects. Saves and
scope decisions already happened. Static layout cannot validate arbitrary SP,
mapping/lifetime or malformed unwind, and saved PCs do not authenticate forged
frames. Earlier effects, other callbacks and the enclosing47C740 dialog's
ignored result, cleanup and lock obligations remain outside this stop. No
rollback, ownership lease, retry/free authority, caller coordination, installer,
firmware image or device operation is supplied.
"""

from build_reveal_bridge_diag import Asm, b
import reveal_registry_receipt_mips as receipt


FRAME, REFRESH_FRAME, WRAPPER_FRAME = 192, 1160, 48
OUTER_RA_OFFSET = FRAME + REFRESH_FRAME + 0x2C
CALLBACK_SP_OFFSET = FRAME + REFRESH_FRAME + WRAPPER_FRAME
FIRST_CALLBACK_FRAME, SECOND_CALLBACK_FRAME = 5312, 40
FIRST_CALLBACK_RETURN, SECOND_CALLBACK_RETURN = 0x4AEEE8, 0x450DA4
FIRST_CALLBACK_EPILOGUE, SECOND_CALLBACK_EPILOGUE = 0x4AECD8, 0x450DAC
PARENT_RESUME_WORD = 0xAFA80544
CONTROLLER_BYTES, MUTEX_BYTES = receipt.CONTROLLER_BYTES, receipt.MUTEX_BYTES
NATIVE_RX = receipt.NATIVE_RX


def _parent_site(parent_selected_address):
    if (type(parent_selected_address) is not int
            or parent_selected_address <= 0 or parent_selected_address % 4
            or parent_selected_address + 12 > 0x10000000
            or parent_selected_address < NATIVE_RX[1]):
        raise ValueError('parent selected pair must be generated RX in native jump region')


def _abort_site(parent_abort_return_address):
    if (type(parent_abort_return_address) is not int
            or parent_abort_return_address <= 0 or parent_abort_return_address % 4
            or parent_abort_return_address + 8 > 0x10000000
            or parent_abort_return_address < NATIVE_RX[1]):
        raise ValueError('parent abort entry must be generated RX in native jump region')


def parent_stop_pair(parent_abort_return_address):
    """Reconstruct the preceding helper's exact label-derived T0 LUI/ORI."""
    _abort_site(parent_abort_return_address)
    return (b.lui(8, parent_abort_return_address >> 16),
            b.ori(8, 8, parent_abort_return_address & 0xFFFF))


def hook_words(labels, parent_selected_address):
    """Return one generated fetch override, never install or edit an image."""
    _parent_site(parent_selected_address)
    target = labels['scope']
    if (type(target) is not int or target <= 0 or target % 4
            or target > 0xFFFFFFFC
            or (parent_selected_address + 4) >> 28 != target >> 28):
        raise ValueError('callback helper target must share parent jump region')
    return {parent_selected_address: (b.j_type(2, target), 0)}


def assemble(controller_address, registry_mutex_address, code_base,
             parent_selected_address, parent_abort_return_address, *,
             protected_code=None, extra_protected_data=()):
    """Emit two private saved-return routes and exact parent materialization.

    U/R and extra fixed extents are strict static declarations only; the helper
    never reads them. The parent selected pair plus its separate resume word
    reserve12 bytes, and its abort thunk reserves8 bytes. Both precede this
    fragment and must be contained with the complete helper by any advertised
    protected_code=(start,bytes). These checks do not prove mapped retained
    frames, allocation ownership or coherent activation.
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
        raise ValueError('callback helper must share native jump region')
    _parent_site(parent_selected_address)
    _abort_site(parent_abort_return_address)
    if (parent_selected_address + 12 > code_base
            or parent_abort_return_address + 8 > code_base):
        raise ValueError('both parent regions must precede callback helper')
    if max(parent_selected_address, parent_abort_return_address) < min(
            parent_selected_address + 12, parent_abort_return_address + 8):
        raise ValueError('parent selected region overlaps parent abort RX')
    parent_extents = ((parent_selected_address, 12), (parent_abort_return_address, 8))
    for index, (name, start, size) in enumerate(extents):
        if max(start, NATIVE_RX[0]) < min(start + size, NATIVE_RX[1]):
            raise ValueError(name + ' overlaps pinned native RX')
        for parent_start, parent_bytes in parent_extents:
            if max(start, parent_start) < min(start + size, parent_start + parent_bytes):
                raise ValueError(name + ' overlaps parent generated RX')
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
                or any(not protected_start <= start or start + size > protected_end
                       for start, size in parent_extents)):
            raise ValueError('protected code must contain both parent regions and callback helper')
        if max(protected_start, NATIVE_RX[0]) < min(protected_end, NATIVE_RX[1]):
            raise ValueError('protected code overlaps pinned native RX')
        for name, start, size in extents:
            if max(protected_start, start) < min(protected_end, start + size):
                raise ValueError('protected code overlaps ' + name)

    a = Asm(code_base)
    a.label('scope')
    # Pinned-U failure and the genuine C->W return were already selected.
    # Read only the still-live W saved return; no graph or mailbox is followed.
    a.e(b.lw(8, OUTER_RA_OFFSET, 29))
    a.absolute(9, FIRST_CALLBACK_RETURN)
    a.branch(4, 8, 9, 'selected_first')
    a.absolute(9, SECOND_CALLBACK_RETURN)
    a.branch(5, 8, 9, 'replay')
    a.label('selected_second')
    second_fixup = len(a.w)
    a.absolute(8, 0)
    a.e(b.sw(8, OUTER_RA_OFFSET, 29))
    a.jump('replay')
    a.label('selected_first')
    first_fixup = len(a.w)
    a.absolute(8, 0)
    a.e(b.sw(8, OUTER_RA_OFFSET, 29))
    a.label('replay')
    # Restore exactly the parent's displaced abort-return materialization.
    # Its following original SW still performs the sole C return-slot write.
    a.e(*parent_stop_pair(parent_abort_return_address))
    a.jump(parent_selected_address + 8)
    a.label('first_abort_return')
    a.jump(FIRST_CALLBACK_EPILOGUE)
    a.label('second_abort_return')
    a.jump(SECOND_CALLBACK_EPILOGUE)
    for fixup, name in ((first_fixup, 'first_abort_return'),
                        (second_fixup, 'second_abort_return')):
        target = a.labels[name]
        a.w[fixup:fixup + 2] = (b.lui(8, target >> 16), b.ori(8, 8, target & 0xFFFF))

    code_end = code_base + len(a.w) * 4
    if code_end > 0x10000000:
        raise ValueError('callback helper leaves native MIPS jump region')
    if protected_end is not None and code_end > protected_end:
        raise ValueError('protected code does not contain complete callback helper')
    if max(code_base, NATIVE_RX[0]) < min(code_end, NATIVE_RX[1]):
        raise ValueError('callback helper overlaps pinned native RX')
    for name, start, size in extents:
        if max(code_base, start) < min(code_end, start + size):
            raise ValueError('callback helper overlaps ' + name)
    hook_words(a.labels, parent_selected_address)
    return a.finish(), a.labels
