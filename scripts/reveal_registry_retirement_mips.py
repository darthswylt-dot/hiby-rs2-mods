#!/usr/bin/env python3
"""Offline passive native retirement frontiers, NOT confirmed deletion.

Four coherent native routes select a node while freshly holding the pinned
ordinary registry mutex.  Two observers precede the first native unlink;
two precede an unlock after which native code may call an opaque callback or
unlink/free without R.  Events therefore mean only retirement selected, not
DEAD, successful cleanup, continuous lifetime coverage, or free authority.

The raw dispatcher chains unclassified/registration routes to the preceding
birth-receipt bridges after restoring every register.  It never duplicates
their displaced raw call or forced-zero return.  Eleven local instruction
overrides, including all beginnings and the teardown release, are a coherent
fixture premise, not an installation plan.  Partial activation is not safe.
Native masked lock failures still execute their original unsafe continuation.

Each bridge preserves all GPRs and HI/LO.  Its independent retained writable
192-byte architectural-save frame is a premise because saving precedes
validation.  Arithmetic exclusions precede private native-local, controller,
and current-node observer reads; they do not establish mapping, lifetime,
native/transitive-stack nonaliasing, ordinary-mutex semantics or authenticity.
No native call, callback result, event or history entry grants object use.
"""

from build_reveal_bridge_diag import Asm, b
import reveal_registry_receipt_mips as receipt


TAG, RAW_STATUS = 0x10, 0x14
ARMED, ENTERED, CAPTURED = 0x52544141, 0x52544145, 0x52544143
FRAME, HI, LO, REQUEST = 192, 0x88, 0x8C, 0x90
REQUEST_BYTES = 32
CONTROLLER_BYTES, MUTEX_BYTES = receipt.CONTROLLER_BYTES, receipt.MUTEX_BYTES
REGISTRY_LOCK, REGISTRY_UNLOCK = receipt.REGISTRY_LOCK, receipt.REGISTRY_UNLOCK
RAW_LOCK, NATIVE_RX = receipt.RAW_LOCK, receipt.NATIVE_RX
SAVE = {register: 0x10 + index * 4
        for index, register in enumerate(r for r in range(1, 32) if r != 29)}
HOOKS = {
    'delete_begin': (0x4395C0, (0x8C990274, 0x0080A821)),
    'teardown_begin': (0x43CB8C, (0x8E390274, 0x02202021)),
    'shutdown_a_begin': (0x4E3F00, (0x0320F809, 0x02002021)),
    'shutdown_b_begin': (0x51A3A0, (0x0320F809, 0x02002021)),
    'delete_frontier': (0x439618, (0xAC620004, 0xAC430000)),
    'teardown_frontier': (0x43CBB0, (0xAE030004, 0xAC700000)),
    'shutdown_a_frontier': (0x4E3F18, (0x0320F809, 0)),
    'shutdown_b_frontier': (0x51A3B8, (0x0320F809, 0)),
    'teardown_release': (0x43CBD4, (0x0320F809, 0x02202021)),
    'raw_call': receipt.HOOKS['raw_call'],
    'raw_return': receipt.HOOKS['raw_return'],
}
# native raw-callback return, U register, native frame bytes, saved caller.
SCOPES = (
    (0x4395D4, 21, 56, 0x34),
    (0x43CB9C, 17, 40, 0x24),
    (0x4E3F08, 16, 56, 0x34),
    (0x51A3A8, 16, 56, 0x34),
)
FRONTIER_SITES = (0x439618, 0x43CBB0, 0x4E3F18, 0x51A3B8)


def hook_words(labels):
    """Return fixture instruction-fetch overrides, without changing a file."""
    result = {}
    for name, (pc, _) in HOOKS.items():
        target = labels[name]
        if (type(target) is not int or target <= 0 or target % 4
                or target > 0xFFFFFFFC or (pc + 4) >> 28 != target >> 28):
            raise ValueError('hook target must share its native jump region')
        result[pc] = (b.j_type(2, target), 0)
    return result


def assemble(controller_address, registry_mutex_address, code_base, *, callback,
             fallback, protected_code=None, extra_protected_data=()):
    """Emit bridges/labels; no observer storage, image or device is modified.

    callback=(entry,RX start,bytes) is all-register/HI/LO preserving and receives
    (U, owned32 [U,R,node,engine,nativeSP,caller,frontierPC,raw0]).  It executes
    under genuine R and must not unlock it.  fallback=(raw_call,raw_return,
    RX start,bytes) names the preceding receipt observer's exact two entries.
    protected_code=(start,bytes), when supplied, contains this complete
    fragment; its length is stable for a two-pass enclosing composition.
    extra_protected_data is a strict tuple of disjoint aligned extents.
    Caller-owned stacks, native allocations and callback cooperation remain
    external premises, including all unknown allocation/stack aliases.
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
        raise ValueError('bridges must share the native jump region')
    for index, (name, start, size) in enumerate(extents):
        if max(start, NATIVE_RX[0]) < min(start + size, NATIVE_RX[1]):
            raise ValueError(name + ' overlaps pinned native RX')
        for other_name, other_start, other_size in extents[index + 1:]:
            if max(start, other_start) < min(start + size, other_start + other_size):
                raise ValueError(name + ' overlaps ' + other_name)

    def rx_tuple(value, count, name):
        if (type(value) is not tuple or len(value) != count
                or any(type(part) is not int for part in value)):
            raise ValueError(name + ' must be a strict RX tuple')
        *entries, start, size = value
        if (start <= 0 or start % 4 or size <= 0 or size % 4
                or start + size > 0x10000000
                or any(entry % 4 or not start <= entry < start + size
                       for entry in entries)):
            raise ValueError(name + ' entries must lie in its native-region RX extent')
        if max(start, NATIVE_RX[0]) < min(start + size, NATIVE_RX[1]):
            raise ValueError(name + ' overlaps pinned native RX')
        for other_name, other_start, other_size in extents:
            if max(start, other_start) < min(start + size, other_start + other_size):
                raise ValueError(name + ' overlaps ' + other_name)
        return start, size

    callback_start, callback_bytes = rx_tuple(callback, 3, 'callback')
    fallback_start, fallback_bytes = rx_tuple(fallback, 4, 'fallback')
    if fallback[0] == fallback[1]:
        raise ValueError('fallback call and return entries must be distinct')
    if (max(callback_start, fallback_start)
            < min(callback_start + callback_bytes, fallback_start + fallback_bytes)):
        raise ValueError('callback and fallback RX extents overlap')
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
            raise ValueError('protected code must contain the bridges')
        if max(protected_start, NATIVE_RX[0]) < min(protected_end, NATIVE_RX[1]):
            raise ValueError('protected code overlaps pinned native RX')
        for name, start, size in extents:
            if max(protected_start, start) < min(protected_end, start + size):
                raise ValueError('protected code overlaps ' + name)

    a, end_fixups = Asm(code_base), []
    protected = [*extents,
                 ('native RX', NATIVE_RX[0], NATIVE_RX[1] - NATIVE_RX[0]),
                 ('callback RX', callback_start, callback_bytes),
                 ('fallback RX', fallback_start, fallback_bytes),
                 ('generated RX', protected_start,
                  None if protected_end is None else protected_end - protected_start)]

    def equal(register, value, failed):
        a.absolute(9, value)
        a.branch(5, register, 9, failed)

    def nonoverlap(first, last, start, end, failed, label):
        a.absolute(10, start)
        a.e(b.r_type(last, 10, 9, 0x2B))
        a.branch(5, 9, 0, label)
        if end is None:
            end_fixups.append(len(a.w))
            a.absolute(10, 0)
        else:
            a.absolute(10, end - 1)
        a.e(b.r_type(10, first, 9, 0x2B))
        a.branch(5, 9, 0, label)
        a.jump(failed)
        a.label(label)

    def exclusions(first, last, failed, prefix):
        for index, (_, start, size) in enumerate(protected):
            nonoverlap(first, last, start, None if size is None else start + size,
                       failed, prefix + '_extent_' + str(index))

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

    def frame_guard(native, native_bytes, failed, prefix):
        # SAVE stores are already covered by the independent private-frame
        # premise.  These checks precede all observer native-local accesses.
        a.branch(4, native, 0, failed)
        a.e(b.i_type(12, native, 8, 7))
        a.branch(5, 8, 0, failed)
        a.e(b.i_type(12, 23, 8, 7))
        a.branch(5, 8, 0, failed)
        a.e(b.i_type(11, 23, 8, FRAME))
        a.branch(5, 8, 0, failed)
        a.e(b.addiu(12, 23, -1))
        exclusions(29, 12, failed, prefix + '_save')
        a.e(b.addiu(13, native, native_bytes - 1),
            b.r_type(13, native, 8, 0x2B))
        a.branch(5, 8, 0, failed)
        exclusions(native, 13, failed, prefix + '_native')

    def controller_fields(register, failed):
        equal(register, controller_address, failed)
        for offset, expected in ((0x13C, registry_mutex_address),
                                 (0x274, REGISTRY_LOCK), (0x278, REGISTRY_UNLOCK)):
            a.e(b.lw(8, offset, register))
            equal(8, expected, failed)

    def indirect_return(return_pc):
        # The original JALR and delay slot were displaced.  Set its original
        # native RA explicitly; a relocated JALR would invent another scope.
        a.absolute(31, return_pc)
        a.e(b.r_type(25, 0, 0, 8), 0)

    begins = (
        ('delete_begin', 21, 56, (0x8C990274, 0x0080A821), 0x4395C8, False),
        ('teardown_begin', 17, 40, (0x8E390274, 0x02202021), 0x43CB94, False),
        ('shutdown_a_begin', 16, 56, (0x02002021,), 0x4E3F08, True),
        ('shutdown_b_begin', 16, 56, (0x02002021,), 0x51A3A8, True),
    )
    for name, u_register, native_bytes, displaced, continuation, indirect in begins:
        a.label(name)
        a.e(*displaced)
        save(name + '_saved')
        done = name + '_done'
        frame_guard(23, native_bytes, done, name)
        a.e(b.sw(0, TAG, 23), b.addiu(8, 0, -1), b.sw(8, RAW_STATUS, 23))
        a.e(b.lw(16, SAVE[u_register], 29))
        controller_fields(16, done)
        a.e(b.lw(8, SAVE[25], 29))
        equal(8, REGISTRY_LOCK, done)
        a.absolute(8, ARMED)
        a.e(b.sw(8, TAG, 23))
        a.label(done)
        restore()
        if indirect:
            indirect_return(continuation)
        else:
            a.jump(continuation)

    for name, fallback_entry in (('raw_call', fallback[0]),
                                  ('raw_return', fallback[1])):
        save(name)
        refused = name + '_fallback'
        # Only read deeper frames after classifying the genuine callback
        # chain.  Unknown routes leave no private tags or native side effects.
        frame_guard(23, 0x40, refused, name + '_wrapper')
        a.e(b.lw(8, 0x1C, 23))
        equal(8, 0x437D30, refused)
        a.e(b.lw(11, 0x3C, 23))
        for index, (native_ra, _, _, _) in enumerate(SCOPES):
            a.absolute(9, native_ra)
            a.branch(4, 11, 9, name + '_scope_' + str(index))
        a.jump(refused)
        for index, (_, u_register, native_bytes, _) in enumerate(SCOPES):
            a.label(name + '_scope_' + str(index))
            a.e(b.lw(16, SAVE[u_register], 29), b.addiu(18, 23, 0x40),
                b.r_type(18, 23, 8, 0x2B))
            a.branch(5, 8, 0, refused)
            equal(16, controller_address, refused)
            frame_guard(18, native_bytes, refused, name + '_scope_' + str(index))
            controller_fields(16, refused)
            a.jump(name + '_classified')
        a.label(name + '_classified')
        a.e(b.lw(8, TAG, 18), b.sw(0, TAG, 18))
        equal(8, ARMED if name == 'raw_call' else ENTERED, refused)
        a.e(b.lw(8, RAW_STATUS, 18))
        equal(8, 0xFFFFFFFF, refused)
        if name == 'raw_call':
            a.e(b.lw(8, SAVE[4], 29))
            equal(8, registry_mutex_address, refused)
            a.absolute(8, ENTERED)
        else:
            a.e(b.lw(8, SAVE[2], 29), b.sw(8, RAW_STATUS, 18))
            a.absolute(8, CAPTURED)
        a.e(b.sw(8, TAG, 18))
        restore()
        if name == 'raw_call':
            a.absolute(31, 0x466DB0)
            a.jump(RAW_LOCK)
        else:
            a.e(b.lw(31, 0x1C, 29), b.move(2, 0))
            a.jump(0x466DB8)
        a.label(refused)
        restore()
        a.jump(fallback_entry)

    frontiers = (
        ('delete_frontier', 21, 16, 56, 0x34, 0x439618, True, False),
        ('teardown_frontier', 17, 2, 40, 0x24, 0x43CBB0, False, False),
        ('shutdown_a_frontier', 16, 17, 56, 0x34, 0x4E3F18, True, True),
        ('shutdown_b_frontier', 16, 17, 56, 0x34, 0x51A3B8, True, True),
    )
    for name, u_register, node_register, native_bytes, caller, site, consume, indirect in frontiers:
        save(name)
        done = name + '_done'
        frame_guard(23, native_bytes, done, name)
        a.e(b.lw(8, TAG, 23))
        if consume:
            a.e(b.sw(0, TAG, 23))
        equal(8, CAPTURED, done)
        a.e(b.lw(8, RAW_STATUS, 23))
        a.branch(5, 8, 0, done)
        a.e(b.lw(16, SAVE[u_register], 29))
        controller_fields(16, done)
        # This is the current native selected node, not a historical pointer.
        # Validate its complete28-byte arithmetic extent before reading +8.
        a.e(b.lw(18, SAVE[node_register], 29))
        a.branch(4, 18, 0, done)
        a.e(b.i_type(12, 18, 8, 3))
        a.branch(5, 8, 0, done)
        a.e(b.addiu(19, 18, 27), b.r_type(19, 18, 8, 0x2B))
        a.branch(5, 8, 0, done)
        exclusions(18, 19, done, name + '_node')
        # Exclude the complete currently borrowed native/save-frame range.
        a.e(b.r_type(19, 29, 8, 0x2B))
        a.branch(5, 8, 0, name + '_node_frame_ok')
        a.e(b.addiu(12, 23, native_bytes - 1), b.r_type(12, 18, 8, 0x2B))
        a.branch(4, 8, 0, done)
        a.label(name + '_node_frame_ok')
        if indirect:
            a.e(b.lw(8, SAVE[25], 29))
            equal(8, REGISTRY_UNLOCK, done)
        a.e(b.sw(16, REQUEST, 29))
        a.absolute(8, registry_mutex_address)
        a.e(b.sw(8, REQUEST + 4, 29), b.sw(18, REQUEST + 8, 29),
            b.lw(8, 8, 18), b.sw(8, REQUEST + 12, 29),
            b.sw(23, REQUEST + 16, 29), b.lw(8, caller, 23),
            b.sw(8, REQUEST + 20, 29))
        a.absolute(8, site)
        a.e(b.sw(8, REQUEST + 24, 29), b.sw(0, REQUEST + 28, 29),
            b.move(4, 16), b.addiu(5, 29, REQUEST))
        a.jump(callback[0], link=True)
        a.label(done)
        restore()
        if indirect:
            indirect_return(site + 8)
        else:
            a.label(name + '_replay')
            a.e(*HOOKS[name][1])
            a.jump(site + 8)

    # The teardown scope covers every iteration.  Revoke its private witness
    # before the real release, even though the facade later masks raw errors.
    a.label('teardown_release')
    a.e(b.move(4, 17))
    save('teardown_release_saved')
    frame_guard(23, 40, 'teardown_release_done', 'teardown_release')
    a.e(b.sw(0, TAG, 23))
    a.label('teardown_release_done')
    restore()
    indirect_return(0x43CBDC)

    code_end = code_base + len(a.w) * 4
    if code_end > 0x10000000:
        raise ValueError('bridges leave the native MIPS jump region')
    if protected_end is not None and code_end > protected_end:
        raise ValueError('protected code does not contain the complete bridges')
    if max(code_base, NATIVE_RX[0]) < min(code_end, NATIVE_RX[1]):
        raise ValueError('bridges overlap pinned native RX')
    for name, start, size in (*extents, ('callback RX', callback_start, callback_bytes),
                               ('fallback RX', fallback_start, fallback_bytes)):
        if max(code_base, start) < min(code_end, start + size):
            raise ValueError('bridges overlap ' + name)
    for index in end_fixups:
        a.w[index] = b.lui(10, (code_end - 1) >> 16)
        a.w[index + 1] = b.ori(10, 10, (code_end - 1) & 0xFFFF)
    hook_words(a.labels)
    return a.finish(), a.labels
