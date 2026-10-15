#!/usr/bin/env python3
"""Connect a private mutation guard to known stock writers; no active reveal.

This is an offline intermediate ELF, NOT a deployable autoscroll fix. It has
no UI setter, object lookup, retained stock pointer, diagnostic I/O or installer.
The hook inventory is bounded, not all-writer proof. READY is only a completed
instrumented mutation; no identity or live UI authority is published.
"""
import argparse
import hashlib
import struct
from pathlib import Path

from build_reveal_bridge_diag import Asm, BASE, FRAME, SAVE, HI, LO, b, normalize_source
from folderfollow_reveal_guard_mips import STATE_BYTES, build_guard
from reveal_bridge_elf import plan_layout, install_layout

MEMCPY, MEMSET = 0xA5B440, 0xA5BC60
# Five copies, two memset calls, and two inline identity stores. Non-identity
# delay-slot effects stay at their ORIGINAL callsite/stack, before our frame.
HOOKS = {
    'set': (0x42AC0C, (0x0C296D10, 0x24060A88), 'copy'),
    'fast': (0x42CBDC, (0x0C296D10, 0x24060A88), 'copy'),
    'general': (0x42CD5C, (0x0C296D10, 0x24060A88), 'copy'),
    'general_recopy': (0x42CF84, (0x0C296D10, 0x24060A88), 'copy'),
    'general_mode3': (0x42D398, (0x0C296D10, 0xAE020BA8), 'copy'),
    'clear': (0x42DECC, (0x0C296F18, 0xA440E9BC), 'zero'),
    'initialize': (0x42B9DC, (0x0C296F18, 0xAFB0001C), 'zero'),
    'prepare': (0x429EF8, (0xA6000104, 0xA600144C), 'prepare'),
    'cue': (0x42AC68, (0x1000FFCB, 0xAE120524), 'cue'),
}
MISSING_CONTRACTS = (
    'escaped-descriptor-pointer-writers',
    'general-transition-intermediate-clear-and-recopy-grouping',
    'coherent-copied-identity-and-full-row-publication',
    'owned-ui-transaction-and-complete-cancellation',
)
GROUPED_MISSING_CONTRACTS = (
    MISSING_CONTRACTS[0],
    'logical-update-boundaries-for-other-playback-routes',
    *MISSING_CONTRACTS[2:],
)
GROUP_HOOKS = {
    'scope_entry': (0x42CC60, (0x27BDE230, 0xAFB01DA8), 'scope_entry'),
    'scope_exit': (0x42D6E4, (0x8FBF1DCC, 0x8FBE1DC8), 'scope_exit'),
}
FAST_HOOKS = {
    'fast_scope_entry': (0x42CBD4, (0x2684D468, 0x02002821), 'fast_scope_entry'),
    'fast_scope_exit': (0x42CC20, (0x1000FFD1, 0x2664DFB4), 'fast_scope_exit'),
}
SCOPE, OWNER_SP, OWNER_TICKET, OUTCOME = 4, 8, 12, 16
GROUP_MEMORY_BYTES, GENERAL_FRAME = 20, 0x1DD0
OWNER_KIND, FAST_GROUP_MEMORY_BYTES = 20, 24
GENERAL_KIND, FAST_KIND = 1, 2


def hook_inventory(grouped=False, fast_grouped=False):
    hooks = dict(HOOKS, **GROUP_HOOKS) if grouped else dict(HOOKS)
    return dict(hooks, **FAST_HOOKS) if fast_grouped else hooks


def assemble(state_address, code_base, *, grouped=False, fast_grouped=False):
    guard, entries = build_guard(state_address, code_base)
    scope = {}
    if grouped:
        scope_code, scope = build_guard(state_address + SCOPE, code_base + len(guard))
        guard += scope_code
    a = Asm(code_base + len(guard))

    def save():
        a.e(b.addiu(29, 29, -FRAME))
        for reg, off in SAVE.items():
            a.e(b.sw(reg, off, 29))
        a.e(b.r_type(0, 0, 8, 0x10), b.sw(8, HI, 29),
            b.r_type(0, 0, 8, 0x12), b.sw(8, LO, 29))

    def restore(pop=True):
        a.e(b.lw(8, HI, 29), b.r_type(8, 0, 0, 0x11),
            b.lw(8, LO, 29), b.r_type(8, 0, 0, 0x13))
        for reg, off in SAVE.items():
            a.e(b.lw(reg, off, 29))
        if pop:
            a.e(b.addiu(29, 29, FRAME))

    for label, target in (('copy', MEMCPY), ('zero', MEMSET)):
        a.label(label)
        save()
        a.jump(entries['begin'], True)
        a.e(b.sw(2, 0x18, 29))  # Outside outgoing O32 home words.
        if grouped:
            a.e(b.addiu(4, 29, FRAME), b.lw(5, SAVE[31], 29), b.move(6, 2),
                b.addiu(7, 0, 0 if label == 'copy' else 2))
            a.jump('scope_write', True)
        restore(False)
        a.jump(target, True)  # Original call exactly once, even after fault.
        save()  # Preserve RESULT registers/HI/LO, not pre-call state.
        a.e(b.lw(4, FRAME + 0x18, 29))
        a.jump(entries['finish'], True)
        restore()
        a.e(b.lw(31, SAVE[31], 29), b.addiu(29, 29, FRAME),
            b.r_type(31, 0, 0, 8), 0)

    for label, displaced, continuation in (
            ('prepare', HOOKS['prepare'][1], 0x429F00),
            ('cue', (HOOKS['cue'][1][1],), 0x42AB98)):
        a.label(label)
        save()
        a.jump(entries['begin'], True)
        a.e(b.sw(2, 0x18, 29))
        if grouped:
            a.e(b.move(6, 2))
            if label == 'prepare':
                # The helper's CURRENT 0x20-byte frame owns this saved RA.
                a.e(b.addiu(4, 29, FRAME + 0x20), b.lw(5, FRAME + 0x1C, 29),
                    b.addiu(7, 0, 1))
            else:
                a.e(b.addiu(4, 29, FRAME), b.move(5, 0), b.addiu(7, 0, 2))
            a.jump('scope_write', True)
        restore(False)
        a.e(*displaced)  # Identity mutation occurs AFTER begin, once only.
        # Both displaced sequences only store through preserved s0/s2 and
        # alter no registers; the first frame is the correct state to restore.
        a.e(b.lw(4, 0x18, 29))
        a.jump(entries['finish'], True)
        restore()
        a.jump(continuation)

    scopes = [('scope_entry', 'scope_exit', GENERAL_KIND, GENERAL_FRAME,
               GROUP_HOOKS['scope_entry'][1], 0x42CC68,
               GROUP_HOOKS['scope_exit'][1], 0x42D6EC)] if grouped else []
    if fast_grouped:
        scopes.append(('fast_scope_entry', 'fast_scope_exit', FAST_KIND, 0,
                       FAST_HOOKS['fast_scope_entry'][1], 0x42CBDC,
                       (FAST_HOOKS['fast_scope_exit'][1][1],), 0x42CB68))
    for entry, leave, kind, frame, entry_pair, entry_resume, exit_pair, exit_resume in scopes:
        a.label(entry)
        save()
        a.jump(scope['begin'], True)
        a.branch(4, 2, 0, entry + '_original')
        a.absolute(8, state_address)
        # Scope BEGIN first, then inspect raw writer state: no stock mutation
        # can be admitted by checking EMPTY before both guards are acquired.
        a.e(b.lw(9, 0, 8), (9 << 16) | (10 << 11) | (31 << 6) | 2)
        a.branch(5, 10, 0, entry + '_fault')
        a.e(b.addiu(9, 29, FRAME - frame), b.sw(9, OWNER_SP, 8),
            b.sw(2, OWNER_TICKET, 8), b.addiu(9, 0, -2),
            b.sw(9, OUTCOME, 8), 0xF)
        if fast_grouped:
            a.e(b.addiu(9, 0, kind), b.sw(9, OWNER_KIND, 8), 0xF)
        a.jump(entry + '_original')
        a.label(entry + '_fault')
        a.jump(scope['invalidate'], True)
        a.label(entry + '_original')
        restore()
        a.e(*entry_pair)
        a.jump(entry_resume)

        a.label(leave)
        save()
        a.absolute(8, state_address)
        if fast_grouped:
            a.e(b.lw(9, OWNER_KIND, 8), b.addiu(10, 0, kind))
            a.branch(5, 9, 10, leave + '_fault')
        a.e(b.lw(9, OWNER_SP, 8), b.addiu(10, 29, FRAME))
        a.branch(5, 9, 10, leave + '_fault')
        a.e(b.lw(9, 0, 8), (9 << 16) | (10 << 11) | (31 << 6) | 2)
        a.branch(5, 10, 0, leave + '_fault')
        a.e(b.lw(4, OWNER_TICKET, 8))
        a.branch(4, 4, 0, leave + '_fault')
        a.absolute(9, 0x80000000)
        a.e(b.r_type(9, 4, 9, 0x21), b.lw(10, SCOPE, 8))
        a.branch(5, 9, 10, leave + '_fault')
        if kind == GENERAL_KIND:
            a.e(b.lw(9, SAVE[2], 29))
            a.branch(4, 9, 0, leave + '_outcome')
            a.e(b.addiu(10, 0, -1))
            a.branch(5, 9, 10, leave + '_fault')
        else:
            # Dedicated fast block completed; stock v0 here is a queue-call
            # result, NOT the function's eventual forced-zero return value.
            a.e(b.move(9, 0))
        a.label(leave + '_outcome')
        a.e(b.sw(9, OUTCOME, 8), 0xF)
        a.jump(scope['finish'], True)
        a.jump(leave + '_original')
        a.label(leave + '_fault')
        a.jump(scope['invalidate'], True)
        a.label(leave + '_original')
        restore()
        a.e(*exit_pair)
        a.jump(exit_resume)

    if grouped:
        # Leaf helper called AFTER raw BEGIN but BEFORE every known mutation.
        # a0 = original active scope-frame token (or preparation helper SP+0x20),
        # a1 = original call return, a2 = raw mutation ticket,
        # a3 = writer kind (0 copy, 1 preparation, 2 always foreign).
        # Never dereference a retained owner token; compare scalar values only.
        a.label('scope_write')
        a.absolute(8, state_address)
        a.branch(4, 6, 0, 'scope_write_fault')
        a.absolute(9, 0x80000000)
        a.e(b.r_type(6, 9, 10, 0x21), b.lw(11, 0, 8))
        a.branch(5, 10, 11, 'scope_write_fault')
        a.e(b.lw(11, SCOPE, 8))
        a.branch(4, 11, 9, 'scope_write_return')
        a.branch(4, 7, 0, 'scope_write_copy')
        a.e(b.addiu(10, 0, 1))
        a.branch(5, 7, 10, 'scope_write_foreign')
        a.absolute(10, 0x42CD40)
        general_owned = 'scope_write_general_owned' if fast_grouped else 'scope_write_owned'
        a.branch(4, 5, 10, general_owned)
        a.jump('scope_write_foreign')
        a.label('scope_write_copy')
        for return_pc in (0x42CD64, 0x42CF8C, 0x42D3A0):
            a.absolute(10, return_pc)
            a.branch(4, 5, 10, general_owned)
        if fast_grouped:
            a.absolute(10, 0x42CBE4)
            a.branch(4, 5, 10, 'scope_write_fast_owned')
        # Foreign mutation: READY/EMPTY scopes describe earlier/no update;
        # an active scope must be revoked before this writer touches stock.
        a.label('scope_write_foreign')
        a.e((11 << 16) | (10 << 11) | (31 << 6) | 2)
        a.branch(5, 10, 0, 'scope_write_fault')
        a.jump('scope_write_return')
        if fast_grouped:
            a.label('scope_write_general_owned')
            a.e(b.addiu(12, 0, GENERAL_KIND))
            a.jump('scope_write_kind')
            a.label('scope_write_fast_owned')
            a.e(b.addiu(12, 0, FAST_KIND))
            a.label('scope_write_kind')
            a.e(b.lw(10, OWNER_KIND, 8))
            a.branch(5, 10, 12, 'scope_write_fault')
        a.label('scope_write_owned')
        a.e(b.lw(10, OWNER_SP, 8))
        a.branch(5, 4, 10, 'scope_write_fault')
        a.e(b.lw(10, OWNER_TICKET, 8))
        a.branch(4, 10, 0, 'scope_write_fault')
        a.e(b.r_type(9, 10, 10, 0x21))
        a.branch(5, 10, 11, 'scope_write_fault')
        a.label('scope_write_return')
        a.e(b.r_type(31, 0, 0, 8), 0)
        a.label('scope_write_fault')
        a.jump(scope['invalidate'])

    labels = dict(a.labels, **{'guard_' + k: v for k, v in entries.items()})
    labels.update({'scope_guard_' + k: v for k, v in scope.items()})
    return guard + a.finish(), labels


def build(source, *, enable_reveal=False, grouped=False, fast_grouped=False):
    if type(grouped) is not bool or type(fast_grouped) is not bool:
        raise ValueError('grouping flags must be explicit booleans')
    if fast_grouped and not grouped:
        raise ValueError('fast grouping requires the general grouped guard')
    missing = GROUPED_MISSING_CONTRACTS if grouped else MISSING_CONTRACTS
    if enable_reveal is not False:
        raise ValueError('active reveal is not admitted: ' + ', '.join(missing))
    golden, input_hash = normalize_source(source)
    memory_bytes = (FAST_GROUP_MEMORY_BYTES if fast_grouped else
                    GROUP_MEMORY_BYTES if grouped else STATE_BYTES)
    layout = plan_layout(golden, memory_bytes)
    code, labels = assemble(layout['buffer'], layout['code_base'],
                            grouped=grouped, fast_grouped=fast_grouped)
    image, meta = install_layout(golden, code, memory_bytes)
    out = bytearray(image)
    for name, (pc, expected, label) in hook_inventory(grouped, fast_grouped).items():
        if struct.unpack_from('<2I', golden, pc - BASE) != expected:
            raise ValueError('unexpected original hook: ' + name)
        linked = label in ('copy', 'zero')
        struct.pack_into('<2I', out, pc - BASE,
                         b.j_type(3 if linked else 2, labels[label]),
                         expected[1] if linked else 0)
    return bytes(out), dict(meta, labels=labels, input_sha256=input_hash,
                           memory_bytes=memory_bytes, hardware='UNTESTED',
                           stage=('fast-grouped-guard-only' if fast_grouped else
                                  'grouped-guard-only' if grouped else 'mutation-guard-only'),
                           grouped=grouped, fast_grouped=fast_grouped, autoscroll=False,
                           missing_contracts=missing)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--grouped', action='store_true', help='include general entry/exit scope guard')
    parser.add_argument('--fast-grouped', action='store_true', help='also group the synchronous fast block')
    args = parser.parse_args()
    result, meta = build(args.source.read_bytes(), grouped=args.grouped or args.fast_grouped,
                        fast_grouped=args.fast_grouped)
    # Explicit binary build, never a source edit or overwrite.
    with args.output.open('xb') as stream:
        stream.write(result)
    print('sha256=' + hashlib.sha256(result).hexdigest())
    print(meta)
    print('INTERMEDIATE GUARD ONLY; no active reveal; hardware UNTESTED; no deployment')


if __name__ == '__main__':
    main()
