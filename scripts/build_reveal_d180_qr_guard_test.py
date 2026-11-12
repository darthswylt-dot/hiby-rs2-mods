#!/usr/bin/env python3
"""Build or verify the ordinary QR guard on the hardware-tested RS2 ELF."""

import hashlib

import build_reveal_d960_payload_guard_test as shared
import reveal_d180_qr_guard_mips as guard


BASELINE_SHA256 = 'd6f40e26013cd89de7dd2b1fb0be0192f60df0e71ce2c9eadb4d02b92da2e5b2'


def build(baseline):
    if hashlib.sha256(baseline).hexdigest() != BASELINE_SHA256:
        raise ValueError('expected the exact hardware-tested removal-dialog ELF')
    return shared._append_payload_guards(
        baseline, guard.assemble, delay_source_index=0,
        delay_overrides={guard.MODE_SITE: 0, guard.RESULT_SITE: 0}, rx_page_limit=2,
    )


if __name__ == '__main__':
    shared.main(build, __doc__)
