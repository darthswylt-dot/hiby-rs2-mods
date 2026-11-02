#!/usr/bin/env python3
"""Offline no-release retention and serialized known dialog consumers.

Continuous M ownership is UNPROVED. Both inherited error routes bypass all
unlock/cleanup work, permanently quarantine a distinct control word and divert
the two known outer saved returns through their pure epilogues. No H/M object
lookup, unlock, destroy or free is performed on those error routes.

The two known outer functions and close facade claim READY->BUSY before object/list
access. BUSY/reentry or any nonzero unknown state refuses entry. Their final
stack-only tails consume a current-frame owner stamp and clear only BUSY->READY.
QUARANTINED is never cleared. Bounded SC failure at exit quarantines instead.
Close(NULL) preserves its native result without claiming the control word.
The facade's synchronous inner close borrows its verified live-frame claim;
it cannot release that claim or mask a quarantined child's error result.

HARD premises: quiescent coherent activation before native calls; a distinct
zero-initialized process-lifetime aligned cacheable control word; coherent LL/SC
and SYNC semantics; mapped writable retained independently nonaliasing
simultaneously live frames/allocations and sufficient stack, including192 bytes
even on rejected/NULL entries. Static exclusions are not mapping, initialization,
frame authentication or ownership proof. Unknown/computed entries and H aliases
outside these two consumers remain outside the retention guarantee. Earlier+C
processing, native worker lifetime and continuous M ownership remain unresolved.
These are offline bytes/metadata, not an installer, image or device operation.
"""

from build_reveal_bridge_diag import Asm, b
import reveal_registry_receipt_mips as receipt


FRAME, HI, LO, RAW = 192, 0x88, 0x8C, 0x90
OUTER_FRAME, OWNER, FUTURE_OWNER = 48, 0x10, 0xA0
FACADE_FRAME, FUTURE_FACADE_OWNER, FACADE_RETURN = 32, 0xB0, 0x47D084
DIALOG_FRAME, DIALOG_RA, TAG, STATUS = 104, 0x64, 0x10, 0x58
READY, BUSY, QUARANTINED = 0, 1, 2
OWNERSTAMP = int.from_bytes(b'QOWN', 'little')
FACADESTAMP = int.from_bytes(b'QFAC', 'little')
BORROWED = int.from_bytes(b'QBOR', 'little')
RETAINED_CALLBACK = int.from_bytes(b'QDCB', 'little')
RETAINED_ACQUIRE = int.from_bytes(b'QDAD', 'little')
FIRST_RETURN, SECOND_RETURN = 0x47CC94, 0x47D00C
FIRST_EPILOGUE, SECOND_EPILOGUE, DIALOG_EPILOGUE = 0x47CCD0, 0x47D034, 0x47C814
PARENT_CALLBACK_PAIR = (0x27BDFF40, 0xAFA10010)
PARENT_DENIED_PAIR, PARENT_DENIED_RESUME = (0x8FA80088, 0x01000011), 0x8FA8008C
CONTROLLER_BYTES, MUTEX_BYTES = receipt.CONTROLLER_BYTES, receipt.MUTEX_BYTES
NATIVE_RX, SYNC = receipt.NATIVE_RX, 0xF
SAVE = {register: 0x10 + index * 4
        for index, register in enumerate(r for r in range(1, 32) if r != 29)}
HOOKS = {
    'poll_enter': (0x47CC20, (0x27BDFFD0, 0xAFB20024)),
    'close_enter': (0x47CF80, (0x10800033, 0)),
    'poll_leave': (0x47CCD8, (0x8FB20024, 0x8FB10020)),
    'close_leave': (0x47D03C, (0x8FB30024, 0x8FB20020)),
    'facade_enter': (0x47D060, (0x27BDFFE0, 0xAFBF001C)),
    'facade_leave': (0x47D084, (0x8FBF001C, 0x8FB00018)),
}


def _parents(callback, denied):
    regions = ((callback, 8), (denied, 12))
    for address, size in regions:
        if (type(address) is not int or address <= 0 or address % 4
                or address < NATIVE_RX[1] or address + size > 0x10000000):
            raise ValueError('retention parent regions must be generated native-region RX')
    if max(callback, denied) < min(callback + 8, denied + 12):
        raise ValueError('retention parent regions must be disjoint')
    return regions


def hook_words(labels, parent_error_return, parent_gate_denied):
    """Return six native and two generated local fetch overrides."""
    _parents(parent_error_return, parent_gate_denied)
    sites = {name: pc for name, (pc, _) in HOOKS.items()}
    sites.update(callback_entry=parent_error_return, deny_entry=parent_gate_denied)
    result = {}
    for name, pc in sites.items():
        target = labels[name]
        if (type(target) is not int or target <= 0 or target % 4
                or target > 0xFFFFFFFC or (pc + 4) >> 28 != target >> 28):
            raise ValueError('retention target must share source jump region')
        result[pc] = (b.j_type(2, target), 0)
    return result


def assemble(controller_address, registry_mutex_address, code_base,
             parent_error_return, parent_gate_denied, guard_address, *,
             retry_limit=8, protected_code=None, extra_protected_data=()):
    """Emit known-consumer exclusion plus no-service classified retention.

    The guard word is independent of native M and the existing transport fault
    word. Callers initialize it to zero before activation and never reset it
    while any native invocation exists. This function allocates/initializes no
    runtime storage. The parent denied region includes its separate LO resume.
    """
    if type(retry_limit) is not int or not 1 <= retry_limit <= 64:
        raise ValueError('retry limit must be an integer in1..64')
    extents = [('controller', controller_address, CONTROLLER_BYTES),
               ('registry mutex', registry_mutex_address, MUTEX_BYTES),
               ('retention guard', guard_address, 4)]
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
        raise ValueError('retention code must share native jump region')
    parents = _parents(parent_error_return, parent_gate_denied)
    if any(start + size > code_base for start, size in parents):
        raise ValueError('retention parent regions must precede the helper')
    for index, (name, start, size) in enumerate(extents):
        if max(start, NATIVE_RX[0]) < min(start + size, NATIVE_RX[1]):
            raise ValueError(name + ' overlaps pinned native RX')
        for parent, count in parents:
            if max(start, parent) < min(start + size, parent + count):
                raise ValueError(name + ' overlaps parent RX')
        for other_name, other, count in extents[index + 1:]:
            if max(start, other) < min(start + size, other + count):
                raise ValueError(name + ' overlaps ' + other_name)
    protected_end = None
    if protected_code is not None:
        if (type(protected_code) is not tuple or len(protected_code) != 2
                or any(type(value) is not int for value in protected_code)):
            raise ValueError('protected code must be an (RX start,bytes) tuple')
        start, count = protected_code
        protected_end = start + count
        if (start <= 0 or start % 4 or count <= 0 or count % 4
                or protected_end > 0x10000000
                or not start <= code_base < protected_end
                or any(not start <= pc or pc + size > protected_end for pc, size in parents)):
            raise ValueError('protected code must contain both parent regions and helper')
        if max(start, NATIVE_RX[0]) < min(protected_end, NATIVE_RX[1]):
            raise ValueError('protected code overlaps pinned native RX')
        for name, address, size in extents:
            if max(start, address) < min(protected_end, address + size):
                raise ValueError('protected code overlaps ' + name)

    a = Asm(code_base)

    def save(name):
        a.label(name)
        a.e(b.addiu(29, 29, -FRAME))
        for register, offset in SAVE.items():
            a.e(b.sw(register, offset, 29))
        a.e(b.r_type(0, 0, 8, 0x10), b.sw(8, HI, 29),
            b.r_type(0, 0, 8, 0x12), b.sw(8, LO, 29), b.addiu(23, 29, FRAME))

    def restore(denied=False):
        a.e(b.lw(8, HI, 29), b.r_type(8, 0, 0, 0x11),
            b.lw(8, LO, 29), b.r_type(8, 0, 0, 0x13))
        for register, offset in SAVE.items():
            if not denied or register not in (2, 3):
                a.e(b.lw(register, offset, 29))
        if denied:
            a.e(b.addiu(2, 0, -1), b.move(3, 0))
        a.e(b.addiu(29, 29, FRAME))

    def quarantine():
        a.absolute(20, guard_address)
        a.e(b.addiu(8, 0, QUARANTINED), SYNC, b.sw(8, 0, 20), SYNC)

    fixups = []

    def retarget(name):
        a.e(b.lw(8, DIALOG_RA, 23))
        a.absolute(9, FIRST_RETURN)
        a.branch(4, 8, 9, name + '_first')
        a.absolute(9, SECOND_RETURN)
        a.branch(5, 8, 9, name + '_done')
        a.label(name + '_second')
        fixups.append((len(a.w), 'second_outer_return'))
        a.absolute(8, 0)
        a.e(b.sw(8, DIALOG_RA, 23))
        a.jump(name + '_done')
        a.label(name + '_first')
        fixups.append((len(a.w), 'first_outer_return'))
        a.absolute(8, 0)
        a.e(b.sw(8, DIALOG_RA, 23))
        a.label(name + '_done')

    save('callback_entry')
    quarantine()
    a.e(b.sw(0, STATUS, 23))
    a.absolute(8, RETAINED_CALLBACK)
    a.e(b.sw(8, TAG, 23))
    retarget('callback_retain')
    restore()
    a.jump(DIALOG_EPILOGUE)

    # The preceding denial already owns a complete192-byte save and RAW90.
    a.label('deny_entry')
    a.e(b.addiu(23, 29, FRAME))
    quarantine()
    a.e(b.lw(8, RAW, 29), b.sw(8, STATUS, 23))
    a.absolute(8, RETAINED_ACQUIRE)
    a.e(b.sw(8, TAG, 23))
    retarget('denied_retain')
    a.label('deny_replay')
    a.e(*PARENT_DENIED_PAIR)
    a.jump(parent_gate_denied + 8)

    for name, is_close, is_facade in (('poll_enter', False, False),
                                      ('close_enter', True, False),
                                      ('facade_enter', False, True)):
        save(name)
        if is_close:
            a.e(b.lw(8, SAVE[4], 29))
            a.branch(4, 8, 0, name + '_null')
            # Only the actual native facade return plus its current-frame
            # stamp may borrow BUSY. This is synchronous nesting, not reentry.
            a.e(b.lw(8, SAVE[31], 29))
            a.absolute(9, FACADE_RETURN)
            a.branch(5, 8, 9, name + '_own')
            a.e(b.lw(8, OWNER, 23))
            a.absolute(9, FACADESTAMP)
            a.branch(5, 8, 9, name + '_denied')
            a.absolute(20, guard_address)
            a.e(SYNC, b.lw(8, 0, 20), b.addiu(9, 0, BUSY))
            a.branch(5, 8, 9, name + '_denied')
            a.e(SYNC)
            a.absolute(8, BORROWED)
            a.e(b.sw(8, FUTURE_OWNER, 29))
            a.jump(name + '_done')
            a.label(name + '_own')
        a.absolute(20, guard_address)
        a.e(b.addiu(12, 0, retry_limit), SYNC)
        a.label(name + '_retry')
        a.e(b.i_type(0x30, 20, 8, 0))
        a.branch(5, 8, 0, name + '_denied')
        a.e(b.addiu(9, 0, BUSY), b.i_type(0x38, 20, 9, 0))
        a.branch(5, 9, 0, name + '_claimed')
        a.e(b.addiu(12, 12, -1))
        a.branch(5, 12, 0, name + '_retry')
        a.jump(name + '_denied')
        a.label(name + '_claimed')
        # Future O+10 is unused private padding at P+A0, not a live overlap.
        a.e(SYNC)
        a.absolute(8, FACADESTAMP if is_facade else OWNERSTAMP)
        a.e(b.sw(8, FUTURE_FACADE_OWNER if is_facade else FUTURE_OWNER, 29))
        a.label(name + '_done')
        restore()
        a.label(name + '_replay')
        if is_facade:
            a.e(*HOOKS[name][1])
            a.jump(0x47D068)
        elif is_close:
            # The exact saved A0 NULL test already ran; nonnull reaches prologue.
            a.jump(0x47CF88)
        else:
            a.e(*HOOKS[name][1])
            a.jump(0x47CC28)
        a.label(name + '_denied')
        restore(denied=True)
        a.e(b.r_type(31, 0, 0, 8), 0)
        if is_close:
            a.label(name + '_null')
            restore()
            a.e(b.r_type(31, 0, 0, 8), 0)

    for name, continuation in (('poll_leave', 0x47CCE0), ('close_leave', 0x47D044)):
        save(name)
        a.e(b.lw(8, OWNER, 23))
        if name == 'close_leave':
            a.absolute(9, BORROWED)
            a.branch(4, 8, 9, name + '_borrowed')
        a.absolute(9, OWNERSTAMP)
        a.branch(5, 8, 9, name + '_done')
        a.e(b.sw(0, OWNER, 23))
        a.absolute(20, guard_address)
        a.e(b.addiu(12, 0, retry_limit), SYNC)
        a.label(name + '_retry')
        a.e(b.i_type(0x30, 20, 8, 0), b.addiu(9, 0, BUSY))
        a.branch(5, 8, 9, name + '_done')
        a.e(b.move(9, 0), b.i_type(0x38, 20, 9, 0))
        a.branch(5, 9, 0, name + '_done')
        a.e(b.addiu(12, 12, -1))
        a.branch(5, 12, 0, name + '_retry')
        quarantine()
        a.jump(name + '_done')
        if name == 'close_leave':
            a.label(name + '_borrowed')
            a.e(b.sw(0, OWNER, 23))
        a.label(name + '_done')
        a.e(SYNC)
        restore()
        a.label(name + '_replay')
        a.e(*HOOKS[name][1])
        a.jump(continuation)

    save('facade_leave')
    a.e(b.lw(8, OWNER, 23))
    a.absolute(9, FACADESTAMP)
    a.branch(5, 8, 9, 'facade_leave_normal')
    a.e(b.sw(0, OWNER, 23))
    a.absolute(20, guard_address)
    a.e(b.addiu(12, 0, retry_limit), SYNC)
    a.label('facade_leave_retry')
    a.e(b.i_type(0x30, 20, 8, 0), b.addiu(9, 0, BUSY))
    a.branch(5, 8, 9, 'facade_leave_fault')
    a.e(b.move(9, 0), b.i_type(0x38, 20, 9, 0))
    a.branch(5, 9, 0, 'facade_leave_normal')
    a.e(b.addiu(12, 12, -1))
    a.branch(5, 12, 0, 'facade_leave_retry')
    a.label('facade_leave_fault')
    quarantine()
    a.e(SYNC)
    restore()
    a.e(*HOOKS['facade_leave'][1])
    # Skip the native V0=0 only on this quarantined/fault route.
    a.jump(0x47D090)
    a.label('facade_leave_normal')
    a.e(SYNC)
    restore()
    a.e(*HOOKS['facade_leave'][1])
    a.jump(0x47D08C)

    a.label('first_outer_return')
    a.jump(FIRST_EPILOGUE)
    a.label('second_outer_return')
    a.jump(SECOND_EPILOGUE)
    for offset, name in fixups:
        target = a.labels[name]
        a.w[offset:offset + 2] = (b.lui(8, target >> 16), b.ori(8, 8, target & 0xFFFF))

    code_end = code_base + len(a.w) * 4
    if code_end > 0x10000000:
        raise ValueError('retention helper leaves native jump region')
    if protected_end is not None and code_end > protected_end:
        raise ValueError('protected code does not contain complete retention helper')
    if max(code_base, NATIVE_RX[0]) < min(code_end, NATIVE_RX[1]):
        raise ValueError('retention helper overlaps native RX')
    for name, start, size in extents:
        if max(code_base, start) < min(code_end, start + size):
            raise ValueError('retention helper overlaps ' + name)
    hook_words(a.labels, parent_error_return, parent_gate_denied)
    return a.finish(), a.labels
