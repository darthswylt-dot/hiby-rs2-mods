#!/usr/bin/env python3
"""Build or verify the volume guard on the tested RS2 UI image."""

import hashlib

import build_reveal_d960_payload_guard_test as shared
import reveal_d180_volume_guard_mips as volume


BASELINE_SHA256 = '38819c764a9c5bb34eda8c10a46f50ebf34089d26aea3aac0de9fcf5f666e250'


def build(baseline):
    if hashlib.sha256(baseline).hexdigest() != BASELINE_SHA256:
        raise ValueError('expected the exact hardware-tested UI ELF')
    return shared._append_payload_guards(baseline, volume.assemble, delay_source_index=0)


if __name__ == '__main__':
    shared.main(build, __doc__)
