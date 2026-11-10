#!/usr/bin/env python3
"""Transfer the RS2 producer's request and dispose of marked queue records."""

from build_reveal_bridge_diag import Asm, MEMCPY, b
from reveal_d960_payload_guard_mips import _validate_code_base, _validate_code_extent


POST_SETUP = 0x4AEF08
WORKER_CALL = 0x4AEF24
QUEUE_COPY = 0x45056C
QUEUE_WRITE = 0x4504E0
ALTERNATE_RECORD = 0x45431C
DESTROY_RECORD = 0x450830
APP_DESTROY_RETURN = 0x474888
MUSIC_RESULT = 0x453374
MUSIC_RETURN = 0x453388
COMPLETION = 0x450D60
LOCK = 0xA5B960
UNLOCK = 0xA5B830
CLOCK = 0x466960
RELEASE = 0x466A80
SNAPSHOT_OFFSET = 0x20
COPY_SIZE = 0xA88
RECORD_FRAME = 0x30
MUSIC_FRAME = 0x30
EVENT = 0x138
OWNED_TAG = int.from_bytes(b'OD38', 'little')


def _emit_owned_payload(asm, record_register, ordinary):
    """Read the payload into T0 only for a marked, nonempty event 0x138."""
    asm.e(b.lw(8, 0, record_register))
    asm.absolute(9, OWNED_TAG)
    asm.branch(5, 8, 9, ordinary)
    asm.e(b.lw(8, 4, record_register), b.addiu(9, 0, EVENT))
    asm.branch(5, 8, 9, ordinary)
    asm.e(b.lw(8, 8, record_register))
    asm.branch(4, 8, 0, ordinary)


def _emit_music(asm, code_base):
    # H+74 identifies a request accepted by the guarded dispatcher.
    owned_completion = code_base + 4 * len(asm.w)
    asm.e(b.lw(8, 0x50, 4))
    asm.branch(5, 8, 5, 'completion_return')
    asm.e(b.sw(0, 0x50, 4))
    asm.absolute(8, COMPLETION)
    asm.jump(COMPLETION, delay=b.sw(8, 0x74, 4))
    asm.label('completion_return')
    asm.e(0x03E00008, b.move(2, 0))

    entry = code_base + 4 * len(asm.w)
    asm.e(b.move(10, 2), b.move(11, 0))  # T2 = H, T3 = validated incoming ownership.
    _emit_owned_payload(asm, 16, 'music_check')
    asm.e(b.move(11, 8))
    asm.label('music_check')
    asm.branch(4, 10, 0, 'music_refused')
    asm.branch(5, 11, 0, 'music_lock')
    asm.e(b.lw(8, 0x74, 10))
    asm.absolute(9, owned_completion)
    asm.branch(5, 8, 9, 'music_native')

    asm.label('music_lock')
    # Save H, owned input, mutex and the pointer to release after unlocking.
    asm.e(b.addiu(29, 29, -MUSIC_FRAME), b.sw(10, 0x18, 29), b.sw(11, 0x1C, 29),
          b.lw(4, 0x10, 10), b.sw(4, 0x20, 29), b.sw(0, 0x24, 29))
    asm.branch(4, 4, 0, 'music_pop')
    asm.jump(LOCK, link=True)
    asm.branch(5, 2, 0, 'music_pop')
    asm.e(b.lw(10, 0x18, 29), b.lw(11, 0x1C, 29), b.lw(12, 8, 16),
          b.lw(8, 0x74, 10), b.lw(9, 0x50, 10))
    asm.absolute(13, owned_completion)
    asm.absolute(14, COMPLETION)

    asm.branch(5, 8, 13, 'music_unmarked_dialog')
    asm.branch(4, 9, 12, 'music_mode')  # The same pointer keeps its existing ownership.
    asm.e(b.sw(9, 0x24, 29))
    asm.branch(5, 11, 0, 'music_mark_dialog')
    asm.e(b.sw(14, 0x74, 10))
    asm.jump('music_store')

    asm.label('music_unmarked_dialog')
    asm.branch(4, 11, 0, 'music_store')
    asm.branch(4, 8, 14, 'music_mark_dialog')
    # An unfamiliar completion must keep its old request and callback.
    asm.branch(4, 9, 12, 'music_mode')
    asm.jump('music_mode', delay=b.sw(11, 0x24, 29))
    asm.label('music_mark_dialog')
    asm.e(b.sw(13, 0x74, 10))
    asm.label('music_store')
    asm.e(b.sw(12, 0x50, 10))
    asm.label('music_mode')
    asm.e(b.addiu(8, 0, 1), b.sw(8, 0x5C, 10))
    asm.jump(UNLOCK, link=True, delay=b.lw(4, 0x20, 29))
    asm.branch(5, 2, 0, 'music_pop')
    asm.e(b.lw(4, 0x24, 29))
    asm.branch(4, 4, 0, 'music_pop')
    asm.jump(RELEASE, link=True)
    asm.label('music_pop')
    asm.jump(MUSIC_RETURN, delay=b.addiu(29, 29, MUSIC_FRAME))

    asm.label('music_refused')
    asm.branch(4, 11, 0, 'music_return')
    asm.jump(RELEASE, link=True, delay=b.move(4, 11))
    asm.label('music_return')
    asm.jump(MUSIC_RETURN)
    asm.label('music_native')
    asm.jump(MUSIC_RESULT + 8, delay=b.move(4, 2))
    return entry


def assemble(code_base):
    """Return the producer handoff and the local queue redirects."""
    _validate_code_base(code_base)
    asm = Asm(code_base)
    # F+20 is a native descriptor-sized local ending at F+AA8.
    asm.e(b.addiu(4, 29, SNAPSHOT_OFFSET), b.addiu(5, 17, 0x50))
    asm.jump(MEMCPY, link=True, delay=b.addiu(6, 0, COPY_SIZE))

    # Keep the stock post if the old dialog has an optional teardown callback
    # or its request slot no longer contains this producer's pointer.
    asm.e(b.lw(8, 0x7C, 16))
    asm.branch(5, 8, 0, 'native_post')
    asm.e(b.lw(8, 0x58, 16))
    asm.branch(5, 8, 17, 'native_post')
    asm.e(b.sw(0, 0x58, 16))
    asm.e(b.lui(8, 0xB9), b.lw(4, -0x6398, 8))
    asm.branch(4, 4, 0, 'release')

    # Keep the 20-byte queue record out of the producer's snapshot area.
    asm.e(b.addiu(29, 29, -RECORD_FRAME), b.sw(4, 0x2C, 29))
    asm.jump(CLOCK, link=True)
    asm.absolute(9, OWNED_TAG)
    asm.e(b.addiu(8, 0, EVENT), b.sw(9, 0x18, 29), b.sw(8, 0x1C, 29),
          b.sw(17, 0x20, 29), b.sw(0, 0x24, 29), b.sw(2, 0x28, 29),
          b.lw(4, 0x2C, 29), b.addiu(5, 29, 0x18))
    asm.jump(QUEUE_WRITE, link=True, delay=b.addiu(6, 0, 20))
    asm.e(b.addiu(29, 29, RECORD_FRAME))
    asm.branch(4, 2, 0, 'worker')
    asm.label('release')
    asm.jump(RELEASE, link=True, delay=b.move(4, 17))
    asm.label('worker')
    asm.jump(POST_SETUP + 0x10)

    asm.label('native_post')
    asm.e(b.addiu(4, 0, EVENT))
    asm.jump(POST_SETUP + 8, delay=b.move(5, 17))

    queue_guard = code_base + 4 * len(asm.w)
    asm.branch(4, 2, 0, 'queue_refused')
    asm.jump(QUEUE_COPY + 8, delay=b.move(4, 2))
    asm.label('queue_refused')
    asm.jump(0x4505C8)  # Decrement the writer count and return -1.

    alternate = code_base + 4 * len(asm.w)
    asm.e(b.addiu(10, 29, 0x18))
    _emit_owned_payload(asm, 10, 'alternate_scan')
    asm.jump(RELEASE, link=True, delay=b.move(4, 8))
    asm.e(b.lui(4, 0x92), b.lw(6, 0x1C, 29))
    asm.label('alternate_scan')
    asm.jump(ALTERNATE_RECORD + 8, delay=0x24846F94)

    destroy = code_base + 4 * len(asm.w)
    # Only the application's drain owns 20-byte records at this call site.
    asm.e(b.lw(8, 0x1C, 29))
    asm.absolute(9, APP_DESTROY_RETURN)
    asm.branch(5, 8, 9, 'free_record')
    asm.branch(4, 4, 0, 'free_record')
    _emit_owned_payload(asm, 4, 'free_record')
    asm.e(b.addiu(29, 29, -0x20), b.sw(4, 0x18, 29))
    asm.jump(RELEASE, link=True, delay=b.move(4, 8))
    asm.e(b.lw(4, 0x18, 29), b.addiu(29, 29, 0x20))
    asm.label('free_record')
    asm.jump(RELEASE, link=True)
    asm.jump(DESTROY_RECORD + 8)

    music = _emit_music(asm, code_base)
    code = asm.finish()
    _validate_code_extent(code_base, len(code))
    return code, {
        POST_SETUP: ((0x24040138, 0x02202821), (b.j_type(2, code_base), 0x02202821)),
        WORKER_CALL: ((0x0C123C88, 0x26270050), (0x0C123C88, b.addiu(7, 29, SNAPSHOT_OFFSET))),
        QUEUE_COPY: ((0x00402021, 0x02802821), (b.j_type(2, queue_guard), 0x02802821)),
        ALTERNATE_RECORD: ((0x24846F94, 0x8FA6001C), (b.j_type(2, alternate), 0x8FA6001C)),
        DESTROY_RECORD: ((0x0C119AA0, 0x8C440000), (b.j_type(2, destroy), 0x8C440000)),
        MUSIC_RESULT: ((0x8E030008, 0x00402021), (b.j_type(2, music), 0x8E030008)),
    }
