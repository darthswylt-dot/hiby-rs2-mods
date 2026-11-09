#!/usr/bin/env python3
"""Emit the two local payload guards for the pinned RS2 1.4 executable.

Each redirect keeps the native delay that saves the factory result. A live
result tail-calls the allocator with its original link. A NULL result replays
the allocation-failure delay and takes the existing wrapper return suffix.
The caller must check both original pairs and provide a free executable span.
"""

from build_reveal_bridge_diag import Asm, b
from reveal_bridge_elf import J_REGION_END, RW_HEADER
from reveal_registry_receipt_mips import NATIVE_RX


ALLOCATOR = 0x4669E0
NATIVE_RW = (RW_HEADER[2], RW_HEADER[2] + RW_HEADER[5])
# Allocator JAL, saved handle delay, failure suffix, NULL exit delay.
SITES = (
    (0x5091B4, 0x00408821, 0x5091E4, 0x00408021),  # s1 = v0; s0 = v0
    (0x50BAC0, 0x00408021, 0x50BAEC, 0x3C040051),  # s0 = v0; lui a0,0x51
)


def assemble(code_base):
    """Return little-endian helper code and {site: (old_pair, new_pair)}."""
    return _assemble(code_base, SITES)


def _validate_code_base(code_base):
    if type(code_base) is not int or not 0x10000 <= code_base < J_REGION_END or code_base % 4:
        raise ValueError('payload guard requires an aligned address in the native jump region')


def _validate_code_extent(code_base, size):
    code_end = code_base + size
    if code_end > J_REGION_END:
        raise ValueError('payload guard extends past the native jump region')
    if any(code_base < end and start < code_end for start, end in (NATIVE_RX, NATIVE_RW)):
        raise ValueError('payload guard overlaps a native load')


def _assemble(code_base, sites):
    _validate_code_base(code_base)
    asm = Asm(code_base)
    patches = {}
    for site, save_handle, failure, failure_delay in sites:
        entry = code_base + len(asm.w) * 4
        refuse = f'refuse_{site:x}'
        resume = site + 8
        asm.branch(4, 2, 0, refuse)  # beq v0,zero
        asm.e(b.lui(31, resume >> 16))
        asm.jump(ALLOCATOR, delay=b.ori(31, 31, resume & 0xFFFF))
        asm.label(refuse)
        asm.jump(failure, delay=failure_delay)
        patches[site] = ((b.j_type(3, ALLOCATOR), save_handle),
                         (b.j_type(2, entry), save_handle))

    code = asm.finish()
    _validate_code_extent(code_base, len(code))
    return code, patches
