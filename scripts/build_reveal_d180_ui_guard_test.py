#!/usr/bin/env python3
"""Build or verify the RS2 UI guards on the tested combined payload image."""

import hashlib

import build_reveal_d960_payload_guard_test as shared
import reveal_d180_context_guard_mips as context
import reveal_d180_wifi_scan_guard_mips as wifi


BASELINE_SHA256 = '6f9cfb9c9a25fd65b4522c6b2e2eaea3073162d15a7194d8b21c36e426bc90cf'


def _assemble(code_base):
    wifi_code, wifi_pairs = wifi.assemble(code_base)
    context_code, context_pairs = context.assemble(code_base + len(wifi_code))
    return wifi_code + context_code, {**wifi_pairs, **context_pairs}


def build(baseline):
    if hashlib.sha256(baseline).hexdigest() != BASELINE_SHA256:
        raise ValueError('expected the exact hardware-tested combined ELF')
    return shared._append_payload_guards(baseline, _assemble, delay_source_index=0)


if __name__ == '__main__':
    shared.main(build, __doc__)
