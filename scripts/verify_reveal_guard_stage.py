#!/usr/bin/env python3
"""Verify the non-active guard ELF, patch scope and instruction inventory."""
import argparse
import hashlib
import struct
from pathlib import Path

import build_reveal_guard_stage as stage


def verify(source, candidate, *, grouped=False):
    golden, _ = stage.normalize_source(source)
    expected, meta = stage.build(source, grouped=grouped)
    if candidate != expected:
        raise ValueError('candidate differs from deterministic guard-only build')
    spans = [(meta['memsize_offset'], 4), (meta['phdr_offset'], 32)]
    spans.extend((pc - stage.BASE, 8) for pc, _, _ in stage.hook_inventory(grouped).values())
    changes = [i for i, (x, y) in enumerate(zip(golden, candidate)) if x != y]
    if any(not any(start <= i < start + size for start, size in spans) for i in changes):
        raise ValueError('undeclared original-image change')
    if any(candidate[len(golden):meta['code_offset']]):
        raise ValueError('nonzero appended padding')
    headers = [struct.unpack_from('<8I', candidate, 52 + i * 32) for i in range(10)]
    original = [struct.unpack_from('<8I', golden, 52 + i * 32) for i in range(10)]
    for i in range(9):
        allowed = original[i][:5] + (meta['memsize'],) + original[i][6:] if i == 3 else original[i]
        if headers[i] != allowed:
            raise ValueError('original program header changed')
    if headers[9] != (1, meta['code_offset'], meta['code_base'], meta['code_base'],
                      meta['code_bytes'], meta['code_bytes'], 5, 0x10000):
        raise ValueError('unexpected added RX segment')
    if (headers[3][2] + headers[3][5] != meta['buffer'] + meta['memory_bytes']
            or meta['buffer'] < original[3][2] + original[3][5]
            or len(candidate) != meta['code_offset'] + meta['code_bytes']):
        raise ValueError('private memory/file extent')
    loads = [h for h in headers if h[0] == 1]
    for i, load in enumerate(loads):
        if load[6] & 3 == 3 or load[1] % load[7] != load[2] % load[7]:
            raise ValueError('LOAD permissions/alignment')
        for other in loads[i + 1:]:
            if max(load[2], other[2]) < min(load[2] + load[5], other[2] + other[5]):
                raise ValueError('overlapping LOADs')

    for pc, original_words, label in stage.hook_inventory(grouped).values():
        linked = label in ('copy', 'zero')
        expected_pair = (stage.b.j_type(3 if linked else 2, meta['labels'][label]),
                         original_words[1] if linked else 0)
        if struct.unpack_from('<2I', candidate, pc - stage.BASE) != expected_pair:
            raise ValueError('hook/delay mismatch')

    start, end = meta['code_base'], meta['code_base'] + meta['code_bytes']
    words = struct.unpack_from('<%dI' % (meta['code_bytes'] // 4), candidate, meta['code_offset'])
    calls, tails = [], []
    for i, word in enumerate(words):
        pc, op = start + i * 4, word >> 26
        rs, imm = (word >> 21) & 31, word & 0xFFFF
        if op not in (0, 2, 3, 4, 5, 9, 13, 15, 35, 41, 43, 48, 56):
            raise ValueError('unknown opcode')
        if op == 0 and word & 63 not in (0, 2, 8, 15, 16, 17, 18, 19, 33, 43):
            raise ValueError('unknown SPECIAL instruction')
        if op == 35 and rs != 29 and not (grouped and rs == 8 and imm in (0, 4, 8, 12)):
            raise ValueError('non-stack additional read')
        if op in (48, 56) and (rs, imm) != (8, 0):
            raise ValueError('non-private atomic access')
        if op == 41 and word not in (0xA6000104, 0xA600144C):
            raise ValueError('unexpected halfword write')
        if (op == 43 and rs != 29 and word not in (0xAD0D0000, 0xAE120524)
                and not (grouped and rs == 8 and imm in (8, 12, 16))):
            raise ValueError('non-stack/non-private extra write')
        if op in (4, 5):
            delta = imm - (0x10000 if imm & 0x8000 else 0)
            if not start <= pc + 4 + delta * 4 < end or words[i + 1] != 0:
                raise ValueError('invalid branch/delay')
        if op in (2, 3):
            target = ((pc + 4) & 0xF0000000) | ((word & 0x3FFFFFF) << 2)
            if words[i + 1] != 0:
                raise ValueError('unexpected jump delay')
            if not start <= target < end:
                (calls if op == 3 else tails).append(target)
        if op == 0 and word & 63 == 8:
            if word != 0x03E00008 or words[i + 1] != 0:
                raise ValueError('unexpected indirect return/delay')
    expected_tails = [0x429F00, 0x42AB98] + ([0x42CC68, 0x42D6EC] if grouped else [])
    if sorted(calls) != [stage.MEMCPY, stage.MEMSET] or sorted(tails) != expected_tails:
        raise ValueError('external control-flow inventory changed')
    return dict(meta, sha256=hashlib.sha256(candidate).hexdigest(),
                changed_original_bytes=len(changes), external_calls=calls,
                verification='offline guard only; no UI authorization; hardware UNTESTED')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('candidate', type=Path)
    parser.add_argument('--grouped', action='store_true')
    args = parser.parse_args()
    print(verify(args.source.read_bytes(), args.candidate.read_bytes(), grouped=args.grouped))


if __name__ == '__main__':
    main()
