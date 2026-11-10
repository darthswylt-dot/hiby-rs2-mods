#!/usr/bin/env python3
"""Build or verify the book-percent guard on the tested RS2 volume image."""

import hashlib

import build_reveal_d960_payload_guard_test as shared
import reveal_d180_book_percent_guard_mips as book_percent


BASELINE_SHA256 = 'ffd64aaf914cc49da1aeb20c5536469e26ed9cad1d7d658de3aae8f2d93ca786'


def build(baseline):
    if hashlib.sha256(baseline).hexdigest() != BASELINE_SHA256:
        raise ValueError('expected the exact hardware-tested volume ELF')
    return shared._append_payload_guards(baseline, book_percent.assemble)


if __name__ == '__main__':
    shared.main(build, __doc__)
