#!/usr/bin/env python3
"""Emit the local RS2 1.4 volume-dialog factory-result guard."""

from reveal_d180_context_guard_mips import _assemble


SITES = {0x505074: ((0x00408821, 0x8C420058), 0x5050A8)}


def assemble(code_base):
    """Return to the existing zero exit before reading H+58 if H is zero."""
    return _assemble(code_base, SITES)
