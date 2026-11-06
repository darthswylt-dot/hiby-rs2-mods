#!/usr/bin/env python3
"""Serialize admission of native47D720 with the existing retention guard.

Only this factory's two encoded direct callers were checked to discard its
pointer result. BUSY/nonzero or exhausted entry attempts return NULL0/0 before
the native frame, name lookup, allocation or startup. Other factories remain
unguarded; arbitrary computed callers are not certified NULL-compatible.

A successful claim stamps the native F568 unused+21C word, initially at private
P+A4 padding. Both stack-only exits consume the stamp and clear only BUSY->READY.
Quarantine is terminal. Exit SC exhaustion latches quarantine while preserving
the actual native result; it cannot undo publication or a worker launch.

HARD premises: mapped process-lifetime initialized-zero cacheable coherent Q,
cooperative LL/SC/SYNC and ABI, genuine native entries/frames, mapped retained
independently nonaliasing allocations and sufficient stack (extra192 even on
rejection), bounded cooperating buffer callees, quiescent coherent activation.
Callbacks must tolerate refused reentry and must not wait for a protected
consumer to enter successfully while Q is BUSY. The native startup wait has no
new timeout: a stuck factory can retain BUSY indefinitely. This is not a join,
universal factory fence, initialized mutex proof, allocator or installer.
"""

from build_reveal_bridge_diag import Asm, b
import reveal_registry_receipt_mips as receipt


FRAME, HI, LO = 192, 0x88, 0x8C
FACTORY_FRAME, OWNER, FUTURE_OWNER = 568, 0x21C, 0xA4
READY, BUSY, QUARANTINED, SYNC = 0, 1, 2, 0xF
OWNERSTAMP = int.from_bytes(b'QF72', 'little')
CONTROLLER_BYTES, MUTEX_BYTES, NATIVE_RX = (
    receipt.CONTROLLER_BYTES, receipt.MUTEX_BYTES, receipt.NATIVE_RX)
SAVE = {register: 0x10 + index * 4
        for index, register in enumerate(r for r in range(1, 32) if r != 29)}
HOOKS = {
    'enter': (0x47D720, (0x27BDFDC8, 0xAFBF0234)),
    'early_leave': (0x47D77C, (0x8FB10224, 0x8FB00220)),
    'created_leave': (0x47D93C, (0x8FB10224, 0x8FB00220)),
}
CHECKED_CALLERS = (0x4A4EAC, 0x4EC450)


def hook_words(labels):
    """Return three native redirects, without mutating an image."""
    return _hook_words(labels, HOOKS)


def _hook_words(labels, hooks):
    """Shared emitter support for the two pinned F568 factory layouts."""
    result = {}
    for name, (pc, _) in hooks.items():
        target = labels[name]
        if (type(target) is not int or target % 4 or target < NATIVE_RX[1]
                or target >= 0x10000000 or (pc + 4) >> 28 != target >> 28):
            raise ValueError('factory gate target must be generated native-region RX')
        result[pc] = (b.j_type(2, target), 0)
    return result


def assemble(controller_address, registry_mutex_address, code_base, guard_address,
             *, retry_limit=8, protected_code=None, extra_protected_data=()):
    """Emit a bounded atomic admission check; native body time is unbounded."""
    return _assemble(controller_address, registry_mutex_address, code_base,
                     guard_address, retry_limit=retry_limit,
                     protected_code=protected_code, extra_protected_data=extra_protected_data,
                     hooks=HOOKS, owner_stamp=OWNERSTAMP)


def _assemble(controller_address, registry_mutex_address, code_base, guard_address,
              *, hooks, owner_stamp, retry_limit=8, protected_code=None,
              extra_protected_data=()):
    """Internal shared implementation; public emitters pin their own layout.

    Both audited factories have the same F568 locals and late restore pair.
    This function is not a runtime layout selector or caller-policy verifier.
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
        raise ValueError('factory gate must share native jump region')
    for index, (name, start, size) in enumerate(extents):
        if max(start, NATIVE_RX[0]) < min(start + size, NATIVE_RX[1]):
            raise ValueError(name + ' overlaps pinned native RX')
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
                or protected_end > 0x10000000 or not start <= code_base < protected_end):
            raise ValueError('protected code must contain factory gate')
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
            a.e(b.move(2, 0), b.move(3, 0))
        a.e(b.addiu(29, 29, FRAME))

    save('enter')
    a.absolute(20, guard_address)
    a.e(b.addiu(12, 0, retry_limit), SYNC)
    a.label('enter_retry')
    a.e(b.i_type(0x30, 20, 8, 0))
    a.branch(5, 8, 0, 'enter_denied')
    a.e(b.addiu(9, 0, BUSY), b.i_type(0x38, 20, 9, 0))
    a.branch(5, 9, 0, 'enter_claimed')
    a.e(b.addiu(12, 12, -1))
    a.branch(5, 12, 0, 'enter_retry')
    a.jump('enter_denied')
    a.label('enter_claimed')
    a.e(SYNC)
    a.absolute(8, owner_stamp)
    a.e(b.sw(8, FUTURE_OWNER, 29))
    restore()
    a.label('enter_replay')
    a.e(*hooks['enter'][1])
    a.jump(hooks['enter'][0] + 8)
    a.label('enter_denied')
    restore(denied=True)
    a.e(b.r_type(31, 0, 0, 8), 0)

    for name in ('early_leave', 'created_leave'):
        save(name)
        a.e(b.lw(8, OWNER, 23))
        a.absolute(9, owner_stamp)
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
        a.e(b.addiu(8, 0, QUARANTINED), SYNC, b.sw(8, 0, 20), SYNC)
        a.label(name + '_done')
        a.e(SYNC)
        restore()
        a.label(name + '_replay')
        a.e(*hooks[name][1])
        a.jump(hooks[name][0] + 8)

    code_end = code_base + len(a.w) * 4
    if code_end > 0x10000000:
        raise ValueError('factory gate leaves native jump region')
    if protected_end is not None and code_end > protected_end:
        raise ValueError('protected code does not contain complete factory gate')
    if max(code_base, NATIVE_RX[0]) < min(code_end, NATIVE_RX[1]):
        raise ValueError('factory gate overlaps pinned native RX')
    for name, start, size in extents:
        if max(code_base, start) < min(code_end, start + size):
            raise ValueError('factory gate overlaps ' + name)
    _hook_words(a.labels, hooks)
    return a.finish(), a.labels
