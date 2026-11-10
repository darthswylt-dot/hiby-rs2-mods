#!/usr/bin/env python3
"""Build or verify the local RS2 data_dealing ownership test image."""

import hashlib

import build_reveal_d960_payload_guard_test as shared
import reveal_d180_data_dealing_snapshot_mips as data_dealing


BASELINE_SHA256 = 'e28a7cb7e798548aad0b20f867cf32308385a8a9a83bfda83e832238f3c02c08'
DELAY_OVERRIDES = {
    data_dealing.WORKER_CALL: 0x27A70020,  # addiu a3,sp,0x20
    data_dealing.MUSIC_RESULT: 0x8E030008,  # lw v1,0x8(s0)
}


def build(baseline):
    if hashlib.sha256(baseline).hexdigest() != BASELINE_SHA256:
        raise ValueError('expected the exact book-percent test ELF')
    return shared._append_payload_guards(baseline, data_dealing.assemble,
                                         delay_overrides=DELAY_OVERRIDES, rx_page_limit=2)


if __name__ == '__main__':
    shared.main(build, __doc__)
