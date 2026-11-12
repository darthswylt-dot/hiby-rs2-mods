#!/usr/bin/env python3
"""Local allocation refusal and selected Tidal queue-operation serialization.

Compose 47 redirects: the previous 44, a common ring WRITE allocation check,
and two Tidal-only WRITE/READ callsite wrappers. A separate retained, zeroed,
exclusive four-byte gate admits one operation with bounded LL/SC attempts.
Contention returns -1/EBUSY without touching the ring. An admitted call checks
native +C is zero before entering its body, avoiding its native sleep loop.
The gate remains held through the complete native return, including READ's
index commit after its own early +C decrement. It is not the session mutex.

The common allocation check preserves the non-NULL path. On NULL it balances
the writer's already incremented native +C once, skips memcpy/publication and
takes its stack-only return with -1/ENOMEM. Other rings acquire no new gate.

Coherent activation, valid nonaliasing frames plus 192 helper stack bytes,
normal bounded allocator/copy/free returns, and live ring/packet storage for
the entire admitted operation are premises. Every selected Tidal operation
must cooperate through these callsites. Native CLEAR/DESTROY and unconnected
aliases are not serialized here. Default assembly provides no queue lifetime
seal. The separate close-seal composer enables a one-lifetime admission seal;
caller recovery, startup repair, safe reopening and firmware activation remain
outside both. Native opaque allocator/free callbacks still run under this
nonblocking gate; reentry via guarded callsites is refused, not waited on.
"""

from build_reveal_bridge_diag import Asm, b
import reveal_tidal_job_snapshot_mips as previous
import reveal_tidal_response_reader_bridge_mips as session
from reveal_registry_receipt_mips import FRAME, HI, LO, SAVE
from reveal_d960_payload_guard_mips import _validate_code_base, _validate_code_extent


WRITE, READ = 0x4504E0, 0x450600
WRITE_SITE, WRITE_PAIR = 0x454B5C, (0x0C114138, 0x27A50018)
READ_SITE, READ_PAIR = 0x454410, (0x0C114180, 0xAFA00824)
ALLOC_SITE, ALLOC_PAIR = 0x45056C, (0x00402021, 0x02802821)
WRITE_EPILOGUE = 0x4505A8
HOOKS = ((WRITE_SITE, WRITE_PAIR), (READ_SITE, READ_PAIR), (ALLOC_SITE, ALLOC_PAIR))
GATE_BYTES, MAX_ATTEMPTS = 4, 4
FREE, OWNED = 0, 1


def assemble(mutex_address, code_base, *, queue_gate_address, _seal_on_close=False):
    """Return a local composer requiring a separate retained operation gate."""
    if type(_seal_on_close) is not bool:
        raise ValueError('queue seal composition requires a boolean selection')
    _validate_code_base(queue_gate_address)
    _validate_code_extent(queue_gate_address, GATE_BYTES)
    if (queue_gate_address < mutex_address + session.CONTROL_BYTES
            and mutex_address < queue_gate_address + GATE_BYTES):
        raise ValueError('queue operation gate overlaps the session sidecar')
    prefix, patches = previous.assemble(
        mutex_address, code_base,
        close_queue_gate=queue_gate_address if _seal_on_close else None)
    asm = Asm(code_base + len(prefix))

    def hook(site, original):
        patches[site] = original, (b.j_type(2, asm.base + len(asm.w) * 4), 0)

    def save():
        asm.e(b.addiu(29, 29, -FRAME))
        for register, offset in SAVE.items():
            asm.e(b.sw(register, offset, 29))
        asm.e(b.r_type(0, 0, 8, 0x10), b.sw(8, HI, 29),
              b.r_type(0, 0, 8, 0x12), b.sw(8, LO, 29))

    def restore():
        asm.e(b.lw(8, HI, 29), b.r_type(8, 0, 0, 0x11),
              b.lw(8, LO, 29), b.r_type(8, 0, 0, 0x13))
        for register, offset in SAVE.items():
            asm.e(b.lw(register, offset, 29))
        asm.e(b.addiu(29, 29, FRAME))

    for name, site, pair, target in (('write', WRITE_SITE, WRITE_PAIR, WRITE),
                                     ('read', READ_SITE, READ_PAIR, READ)):
        hook(site, pair)
        asm.e(pair[1])  # Native-SP argument/store before allocating the helper frame.
        save()
        asm.absolute(8, queue_gate_address)
        asm.e(b.addiu(11, 0, MAX_ATTEMPTS))
        asm.label(name + '_claim')
        asm.e(b.i_type(0x30, 8, 9, 0))
        asm.branch(5, 9, 0, name + '_busy')
        asm.e(b.addiu(10, 0, OWNED), b.i_type(0x38, 8, 10, 0))
        asm.branch(5, 10, 0, name + '_claimed')
        asm.e(b.addiu(11, 11, -1))
        asm.branch(5, 11, 0, name + '_claim')
        asm.jump(name + '_busy')

        asm.label(name + '_claimed')
        asm.e(0xF, b.lw(4, SAVE[4], 29), b.addiu(3, 0, 22))
        asm.branch(4, 4, 0, name + '_release_error')
        asm.e(b.lw(9, 0xC, 4), b.addiu(3, 0, 71))
        asm.branch(1, 9, 0, name + '_release_error')  # Negative legacy counter is invalid.
        asm.e(b.addiu(3, 0, 16))
        asm.branch(5, 9, 0, name + '_release_error')
        asm.e(b.lw(5, SAVE[5], 29), b.lw(6, SAVE[6], 29))
        asm.jump(target, link=True)
        asm.e(b.sw(2, SAVE[2], 29), b.sw(3, SAVE[3], 29))
        asm.jump(name + '_release')

        asm.label(name + '_release_error')
        asm.e(b.sw(3, SAVE[3], 29), b.addiu(9, 0, -1), b.sw(9, SAVE[2], 29))
        asm.label(name + '_release')
        asm.absolute(8, queue_gate_address)
        asm.e(0xF, b.sw(0, 0, 8))
        asm.jump(name + '_return')
        asm.label(name + '_busy')
        asm.e(b.addiu(9, 0, -1), b.sw(9, SAVE[2], 29),
              b.addiu(9, 0, 16), b.sw(9, SAVE[3], 29))
        asm.label(name + '_return')
        asm.absolute(8, site + 8)
        asm.e(b.sw(8, SAVE[31], 29))
        restore()
        asm.jump(site + 8)

    hook(ALLOC_SITE, ALLOC_PAIR)
    asm.branch(4, 2, 0, 'allocation_refused')
    asm.e(*ALLOC_PAIR)
    asm.jump(ALLOC_SITE + 8)
    asm.label('allocation_refused')
    # Mirror native full-queue cleanup without calling another service. Its
    # existing failure tail overwrites V1 with +C, so set ENOMEM afterward.
    asm.e(b.lw(3, 0xC, 16), b.addiu(3, 3, -1), b.sw(3, 0xC, 16),
          b.addiu(2, 0, -1), b.addiu(3, 0, 12))
    asm.jump(WRITE_EPILOGUE)

    code = prefix + asm.finish()
    _validate_code_extent(code_base, len(code))
    if (code_base < queue_gate_address + GATE_BYTES
            and queue_gate_address < code_base + len(code)):
        raise ValueError('queue operation gate overlaps the helper code')
    return code, patches
