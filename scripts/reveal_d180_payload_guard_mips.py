#!/usr/bin/env python3
"""Emit local payload guards for seven pinned RS2 1.4 wrappers."""

from reveal_d960_payload_guard_mips import _assemble


# Allocator JAL, saved handle delay, failure suffix, NULL exit delay.
SITES = (
    (0x5270AC, 0x00408821, 0x5270F0, 0),  # The native delay writes through S1.
    (0x4CFF44, 0x00408821, 0x4CFFC8, 0x00408021),
    (0x4D1AE8, 0x00409021, 0x4D1BD4, 0x00002821),
    (0x4D2B50, 0x00409021, 0x4D2C24, 0x00408821),
    (0x4D3730, 0x00408821, 0x4D3760, 0x00408021),
    (0x515224, 0x00408021, 0x515250, 0x00408821),
    (0x509A38, 0x00408821, 0x509A5C, 0x00408021),
)


def assemble(code_base):
    """Return helper bytes and the original and replacement allocator pairs."""
    return _assemble(code_base, SITES)
