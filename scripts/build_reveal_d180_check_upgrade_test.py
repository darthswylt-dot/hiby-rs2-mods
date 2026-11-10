#!/usr/bin/env python3
"""Build or verify the update-check guard on the tested RS2 data_dealing ELF."""

import hashlib

import build_reveal_d960_payload_guard_test as shared
import reveal_d180_check_upgrade_guard_mips as check_upgrade


BASELINE_SHA256 = '2a0c358fbe663eea7093412a6a9d73034e31d0a55843692c1a5ab408a9a40845'


def build(baseline):
    if hashlib.sha256(baseline).hexdigest() != BASELINE_SHA256:
        raise ValueError('expected the exact hardware-tested data_dealing ELF')
    return shared._append_payload_guards(
        baseline, check_upgrade.assemble,
        delay_overrides={check_upgrade.RESULT_SITE: 0x00408021},
        rx_page_limit=2,
    )


if __name__ == '__main__':
    shared.main(build, __doc__)
