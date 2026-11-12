#!/usr/bin/env python3
"""Build or verify the book and bookmark removal guards on the tested RS2 ELF."""

import hashlib

import build_reveal_d960_payload_guard_test as shared
from reveal_d180_book_percent_guard_mips import assemble_payload_cleanup


BASELINE_SHA256 = 'c553e85d0da312b839e40928b9cb7c1776736db6fcf0aab2c161062b4deaf16a'
SITES = {
    0x527FA4: (0xAC500058, 0x8FBF0054),
    0x5295E0: (0xAC500058, 0x8FBF0054),
}


def _assemble(code_base):
    return assemble_payload_cleanup(code_base, SITES)


def build(baseline):
    if hashlib.sha256(baseline).hexdigest() != BASELINE_SHA256:
        raise ValueError('expected the exact hardware-tested update-check ELF')
    return shared._append_payload_guards(baseline, _assemble, rx_page_limit=2)


if __name__ == '__main__':
    shared.main(build, __doc__)
