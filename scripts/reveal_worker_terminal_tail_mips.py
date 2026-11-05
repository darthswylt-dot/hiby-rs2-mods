#!/usr/bin/env python3
"""Detach the worker's buffer field before its final C release.

Entry is the genuine W56 terminal path at47C6E8. The displaced delay load
still captures A0=H+0C before this helper. S1 is available scratch in this
native frame: its incoming value is already saved at W+20 and the pure
epilogue restores it. Both called native facades must preserve S1 by ABI.

Capture H+14 once and, when nonnull, clear it before the existing C release.
A SYNC orders that field clear before the release call under native semantics.
After that release the helper uses only the captured pointer and the native
stack epilogue. This removes direct post-release H accesses; it is not a
worker join, C ownership proof, raw-status gate or free-authority check.

H must remain valid through capture/clear; a nonnull buffer must independently
be retained, freeable and nonaliasing with H, mutexes, live frames and shared/RX
storage. Foreign writers/observers must permit the earlier field clear. The
import/free ABI must cooperate; this does not fence arbitrary allocator hooks.
Cooperative SYNC semantics, quiescent coherent activation, genuine entry/stack
and the preceding retention
stage's premises remain required. No Q claim, additional frame, installer,
firmware image or device operation is supplied.
"""

from build_reveal_bridge_diag import Asm, b
import reveal_registry_receipt_mips as receipt


WORKER_FRAME, SAVED_S1 = 56, 0x20
RELEASE, FREE, EPILOGUE = 0x466DC0, 0x466A80, 0x47C708
SYNC = 0xF
NATIVE_RX = receipt.NATIVE_RX
CONTROLLER_BYTES, MUTEX_BYTES = receipt.CONTROLLER_BYTES, receipt.MUTEX_BYTES
HOOKS = {'terminal': (0x47C6E8, (0x0C119B70, 0x8E04000C))}


def hook_words(labels):
    """Return one native redirect with its original H+0C delay load."""
    site, source = HOOKS['terminal']
    target = labels['entry']
    if (type(target) is not int or target % 4 or target < NATIVE_RX[1]
            or target >= 0x10000000 or (site + 4) >> 28 != target >> 28):
        raise ValueError('worker tail entry must be generated RX in native jump region')
    return {site: (b.j_type(2, target), source[1])}


def assemble(controller_address, registry_mutex_address, code_base, guard_address,
             *, protected_code=None, extra_protected_data=()):
    """Emit a terminal tail; fixed data declarations are exclusion checks only.

    U/R/Q and extras are never accessed. protected_code optionally declares
    the complete preceding/following generated RX extent. These checks do not
    establish dynamic allocation ownership, mappings or a valid worker frame.
    """
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
        raise ValueError('worker tail must share native jump region')
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
                or protected_end > 0x10000000
                or not start <= code_base < protected_end):
            raise ValueError('protected code must contain worker tail')
        if max(start, NATIVE_RX[0]) < min(protected_end, NATIVE_RX[1]):
            raise ValueError('protected code overlaps pinned native RX')
        for name, address, size in extents:
            if max(start, address) < min(protected_end, address + size):
                raise ValueError('protected code overlaps ' + name)

    a = Asm(code_base)
    a.label('entry')
    a.e(b.lw(17, 0x14, 16))
    a.branch(4, 17, 0, 'captured')
    a.e(b.sw(0, 0x14, 16))
    a.label('captured')
    a.e(SYNC)
    a.jump(RELEASE, link=True)
    a.label('release_return')
    a.e(b.move(4, 17))
    a.branch(4, 17, 0, 'finish')
    a.jump(FREE, link=True)
    a.label('finish')
    a.jump(EPILOGUE)

    code_end = code_base + len(a.w) * 4
    if code_end > 0x10000000:
        raise ValueError('worker tail leaves native jump region')
    if protected_end is not None and code_end > protected_end:
        raise ValueError('protected code does not contain complete worker tail')
    if max(code_base, NATIVE_RX[0]) < min(code_end, NATIVE_RX[1]):
        raise ValueError('worker tail overlaps pinned native RX')
    for name, start, size in extents:
        if max(code_base, start) < min(code_end, start + size):
            raise ValueError('worker tail overlaps ' + name)
    hook_words(a.labels)
    return a.finish(), a.labels
