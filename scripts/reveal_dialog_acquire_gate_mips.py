#!/usr/bin/env python3
"""Offline admission after one dialog+10 mutex acquisition, not dialog cleanup.

Four coherent phases require an actual raw-zero result for the native47C740
acquisition at47C794 before its following graph reads/callback. The original
LW A0,+10(S0) remains the begin redirect's delay instruction and executes once
before architectural saving. Native D104 locals10/14/58 carry a fresh tag, the
actual mutex scalar M and raw evidence. The64-byte native buffer18..57 and
saved registers5C/60/64 are not reused.

The raw chain is direct: W=D-32 is466DA0's frame, with saved caller47C79C at
W+1C. No extra callback facade or registry-U scope is invented. Raw-call entry
consumes ARMED, compares actual saved A0 with captured M, records W and writes
ENTERED. Raw return requires actual RA466DB0 and the same W, then captures
actual saved V0 separately from CAPTURED. All raw routes restore architecture
and delegate the exact preceding observers, which retain native call/return PCs.

The gate consumes CAPTURED once. Raw zero changes it to ADMITTED, retains the
private M/status words and replays the two original graph reads. Nonzero raw
returns FFFFFFFF/exact_status; missing evidence returns FFFFFFFF/zero through
the existing pure D104 epilogue, without unlock, destruction, free or retry.
ADMITTED is only this local one-use acquisition observation; no callback-error
exit or release consumer is installed, and unchanged later cleanup still reloads
dialog+10. This protocol gates all genuine invocations of this native call site;
U/R are static layout exclusions only, not runtime controller/mutex pins.

HARD premises: genuine native routes/ABI; mapped writable retained independently
nonaliasing simultaneously live D104/W32/private192 frames and initialized live
ordinary M storage; sufficient transitive stack; coherent fresh-phase redirects
and all inherited native/import/storage cooperation. Saves precede scope checks.
Static checks do not validate arbitrary SP, mapping, ownership or lifetime;
saved PCs/tags do not authenticate forged frames or make partial activation
fail closed. Earlier masked +0C services, worker post-unlock use and outer dialog
frees remain unresolved. Raw error may still leave M held. This local return
isolates no other user/caller and grants no release/destroy/free authority,
worker termination, rollback, ownership lease, installer or device operation.
"""

from build_reveal_bridge_diag import Asm, b
import reveal_registry_receipt_mips as receipt


FRAME, HI, LO, RAW = 192, 0x88, 0x8C, 0x90
DIALOG_FRAME, RAW_FRAME = 104, 32
TAG, MUTEX, RAW_STATUS = 0x10, 0x14, 0x58
ARMED = int.from_bytes(b'DGAA', 'little')
ENTERED = int.from_bytes(b'DGAE', 'little')
CAPTURED = int.from_bytes(b'DGAC', 'little')
ADMITTED = int.from_bytes(b'DGAD', 'little')
ACQUIRE, DIALOG_ACQUIRE_RETURN, RAW_ACQUIRE_RETURN = 0x466DA0, 0x47C79C, 0x466DB0
EPILOGUE, CONTINUATION = 0x47C814, 0x47C7A4
CONTROLLER_BYTES, MUTEX_BYTES = receipt.CONTROLLER_BYTES, receipt.MUTEX_BYTES
NATIVE_RX = receipt.NATIVE_RX
SAVE = {register: 0x10 + index * 4
        for index, register in enumerate(r for r in range(1, 32) if r != 29)}
HOOKS = {
    'begin': (0x47C794, (0x0C119B68, 0x8E040010)),
    'raw_call': (0x466DA8, (0x0C296E58, 0)),
    'raw_return': (0x466DB0, (0x8FBF001C, 0x00001021)),
    'gate': (0x47C79C, (0x8E02003C, 0x8C450000)),
}


def hook_words(labels):
    """Return four local fetch overrides, never install or alter an image."""
    result = {}
    for name, (pc, _) in HOOKS.items():
        target = labels[name]
        if (type(target) is not int or target <= 0 or target % 4
                or target > 0xFFFFFFFC or (pc + 4) >> 28 != target >> 28):
            raise ValueError('dialog acquisition target must share native jump region')
        # Capture the original load's actual value; do not reread dialog+10.
        delay = HOOKS[name][1][1] if name == 'begin' else 0
        result[pc] = (b.j_type(2, target), delay)
    return result


def assemble(controller_address, registry_mutex_address, code_base,
             raw_call_entry, raw_return_entry, *, protected_code=None,
             extra_protected_data=()):
    """Emit native-stack evidence plus a pre-graph admission decision.

    The two exact preceding raw observers must be distinct aligned generated
    RX before this fragment. Advertised protected_code=(start,bytes) contains
    both entries and this complete fragment. U/R and extra fixed extents are
    strict static layout declarations only; the runtime M is the source load's
    actual saved argument. No dynamic allocation/frame guard is supplied.
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
        raise ValueError('dialog acquisition gates must share native jump region')
    legacy_entries = (raw_call_entry, raw_return_entry)
    for entry in legacy_entries:
        if (type(entry) is not int or entry <= 0 or entry % 4
                or entry < NATIVE_RX[1] or entry + 4 > code_base
                or entry + 4 > 0x10000000):
            raise ValueError('legacy raw entries must be preceding aligned generated RX')
    if raw_call_entry == raw_return_entry:
        raise ValueError('legacy raw entries must be distinct')
    for index, (name, start, size) in enumerate(extents):
        if max(start, NATIVE_RX[0]) < min(start + size, NATIVE_RX[1]):
            raise ValueError(name + ' overlaps pinned native RX')
        for entry in legacy_entries:
            if max(start, entry) < min(start + size, entry + 4):
                raise ValueError(name + ' overlaps legacy raw RX entry')
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
                or any(not protected_start <= entry
                       or entry + 4 > protected_end for entry in legacy_entries)):
            raise ValueError('protected code must contain legacy entries and dialog gates')
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

    def raw_scope(name, failed):
        # This acquisition calls466DA0 directly: W.savedRA identifies D.
        # Do not apply registry-controller or callback-facade assumptions.
        a.e(b.lw(8, 0x1C, 23))
        equal(8, DIALOG_ACQUIRE_RETURN, failed)
        a.e(b.addiu(22, 23, RAW_FRAME))
        a.label(name + '_classified')

    save('begin')
    # The source hook delay already executed LW A0,+10(S0) exactly once.
    a.e(b.sw(0, TAG, 23), b.addiu(8, 0, -1),
        b.sw(8, RAW_STATUS, 23), b.lw(8, SAVE[4], 29),
        b.sw(8, MUTEX, 23))
    a.absolute(8, ARMED)
    a.e(b.sw(8, TAG, 23))
    a.label('begin_done')
    restore()
    a.label('begin_replay')
    a.absolute(31, DIALOG_ACQUIRE_RETURN)
    a.jump(ACQUIRE)

    save('raw_call')
    raw_scope('raw_call', 'raw_call_done')
    a.e(b.lw(8, TAG, 22), b.sw(0, TAG, 22))
    equal(8, ARMED, 'raw_call_done')
    a.e(b.lw(8, RAW_STATUS, 22))
    equal(8, 0xFFFFFFFF, 'raw_call_done')
    a.e(b.lw(8, SAVE[4], 29), b.lw(9, MUTEX, 22))
    a.branch(5, 8, 9, 'raw_call_done')
    # RAW_STATUS holds exact W only during ENTERED; M remains retained.
    a.e(b.sw(23, RAW_STATUS, 22))
    a.absolute(8, ENTERED)
    a.e(b.sw(8, TAG, 22))
    a.label('raw_call_done')
    restore()
    a.label('raw_call_replay')
    a.jump(raw_call_entry)

    save('raw_return')
    raw_scope('raw_return', 'raw_return_done')
    a.e(b.lw(8, SAVE[31], 29))
    equal(8, RAW_ACQUIRE_RETURN, 'raw_return_done')
    a.e(b.lw(8, TAG, 22), b.sw(0, TAG, 22))
    equal(8, ENTERED, 'raw_return_done')
    a.e(b.lw(8, RAW_STATUS, 22))
    a.branch(5, 8, 23, 'raw_return_done')
    # The actual saved service result is captured before the native mask.
    # Post-service A0/T9 are volatile and deliberately not consulted.
    a.e(b.lw(8, SAVE[2], 29), b.sw(8, RAW_STATUS, 22))
    a.absolute(8, CAPTURED)
    a.e(b.sw(8, TAG, 22))
    a.label('raw_return_done')
    restore()
    a.label('raw_return_replay')
    a.jump(raw_return_entry)

    save('gate')
    a.e(b.lw(8, TAG, 23), b.sw(0, TAG, 23))
    equal(8, CAPTURED, 'gate_denied')
    a.e(b.lw(8, RAW_STATUS, 23), b.sw(8, RAW, 29))
    a.branch(4, 8, 0, 'gate_admitted')
    a.label('gate_denied')
    restore(denied=True)
    # This pure native epilogue preserves V0/V1 and performs no service.
    a.jump(EPILOGUE)
    a.label('gate_admitted')
    a.absolute(8, ADMITTED)
    a.e(b.sw(8, TAG, 23))
    a.label('gate_done')
    restore()
    a.label('gate_replay')
    a.e(*HOOKS['gate'][1])
    a.jump(CONTINUATION)

    code_end = code_base + len(a.w) * 4
    if code_end > 0x10000000:
        raise ValueError('dialog acquisition gates leave native MIPS jump region')
    if protected_end is not None and code_end > protected_end:
        raise ValueError('protected code does not contain complete dialog gates')
    if max(code_base, NATIVE_RX[0]) < min(code_end, NATIVE_RX[1]):
        raise ValueError('dialog acquisition gates overlap pinned native RX')
    for name, start, size in extents:
        if max(code_base, start) < min(code_end, start + size):
            raise ValueError('dialog acquisition gates overlap ' + name)
    hook_words(a.labels)
    return a.finish(), a.labels
