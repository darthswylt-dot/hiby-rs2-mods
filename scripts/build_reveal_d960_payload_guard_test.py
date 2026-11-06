#!/usr/bin/env python3
"""Build or verify the isolated RS2 payload test from the tested capture ELF."""

import argparse
import hashlib
import struct
from pathlib import Path

from build_reveal_bridge_diag import BASE
from reveal_bridge_elf import CODE_INDEX, PAGE_ALIGNMENT, PHENTSIZE, PHOFF
import reveal_d960_payload_guard_mips as guard


BASELINE_SHA256 = '7cc98a67a32dabce3b4d22b50b8dc847f5462d99d70d0ee04254a0ec272439a9'
RX_HEADER = PHOFF + CODE_INDEX * PHENTSIZE


def build(baseline):
    if hashlib.sha256(baseline).hexdigest() != BASELINE_SHA256:
        raise ValueError('expected the exact hardware-tested capture ELF')

    offset, address, _, old_size = struct.unpack_from('<4I', baseline, RX_HEADER + 4)
    code, patches = guard.assemble(address + old_size)
    new_size = old_size + len(code)
    if offset + old_size != len(baseline) or new_size > PAGE_ALIGNMENT:
        raise ValueError('payload guards must fit in the existing final RX page')

    candidate = bytearray(baseline)
    for pc, (original, replacement) in patches.items():
        if struct.unpack_from('<2I', baseline, pc - BASE) != original:
            raise ValueError(f'unexpected original pair at {pc:#x}')
        if replacement[1] != original[1]:
            raise ValueError(f'payload redirect changes the native delay at {pc:#x}')
        struct.pack_into('<I', candidate, pc - BASE, replacement[0])
    struct.pack_into('<2I', candidate, RX_HEADER + 16, new_size, new_size)
    candidate.extend(code)
    return bytes(candidate)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('baseline', type=Path)
    parser.add_argument('candidate', type=Path)
    parser.add_argument('--verify', action='store_true')
    args = parser.parse_args()
    try:
        candidate = build(args.baseline.read_bytes())
        if args.verify:
            if args.candidate.read_bytes() != candidate:
                raise ValueError('candidate differs from the deterministic build')
        else:
            with args.candidate.open('xb') as stream:
                stream.write(candidate)
    except (OSError, ValueError) as error:
        parser.exit(1, f'{error}\n')
    print(f'{len(candidate)} bytes, SHA-256 {hashlib.sha256(candidate).hexdigest()}')


if __name__ == '__main__':
    main()
