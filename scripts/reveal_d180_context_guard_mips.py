#!/usr/bin/env python3
"""Emit three local context-read guards for the pinned RS2 1.4 ELF."""

from build_reveal_bridge_diag import Asm, b
from reveal_d960_payload_guard_mips import _validate_code_base, _validate_code_extent


# Post-factory pair and existing NULL exit.
SITES = {
    0x4AF960: ((0x00409021, 0x8C420058), 0x4AFB54),
    0x4CF1FC: ((0x00408021, 0x8C420058), 0x4CF20C),
    0x4AFC7C: ((0x00408821, 0x8C420058), 0x4AFCAC),
}


def assemble(code_base):
    """Keep the saved handle in the native delay and load its context only when live."""
    return _assemble(code_base, SITES)


def _assemble(code_base, sites):
    _validate_code_base(code_base)
    asm = Asm(code_base)
    patches = {}
    for site, (original, failure) in sites.items():
        entry = code_base + len(asm.w) * 4
        refuse = f'refuse_{site:x}'
        asm.branch(4, 2, 0, refuse)  # beq v0,zero
        asm.jump(site + 8, delay=original[1])
        asm.label(refuse)
        asm.jump(failure)
        patches[site] = (original, (b.j_type(2, entry), original[0]))
    code = asm.finish()
    _validate_code_extent(code_base, len(code))
    return code, patches
