#!/usr/bin/env python3
"""Build or verify the combined RS2 payload test from the tested D960 ELF."""

import hashlib

import build_reveal_d960_payload_guard_test as previous
import reveal_d180_payload_guard_mips as guard


BASELINE_SHA256 = '6d52c40a658bf21cb2d9da03c7266702902ff81e48c70f3775b9b549615c00d0'


def build(baseline):
    if hashlib.sha256(baseline).hexdigest() != BASELINE_SHA256:
        raise ValueError('expected the exact hardware-tested D960 ELF')
    return previous._append_payload_guards(baseline, guard.assemble)


if __name__ == '__main__':
    previous.main(build, __doc__)
