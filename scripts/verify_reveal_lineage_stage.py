#!/usr/bin/env python3
"""Verify exact offline native-lineage ELF, declared patches and transfers.

This is not an installer or a proof of stock object lifetime or hardware
behavior. It deliberately rejects every active reveal and unknown source.
"""
import argparse
import hashlib
import struct
from pathlib import Path

import build_reveal_lineage_stage as stage


def verify(source, candidate, *, capacity=1024):
    golden, _ = stage.normalize_source(source)
    expected, meta = stage.build(source, capacity=capacity)
    if candidate != expected:
        raise ValueError('candidate differs from deterministic lineage-only build')
    spans = [(meta['memsize_offset'], 4), (meta['phdr_offset'], 32)]
    spans += [(pc - stage.BASE, 8) for pc, _ in stage.HOOKS.values()]
    spans += [(pc - stage.BASE, 4) for pc in stage.STRIDES]
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
    for name, (pc, words) in stage.HOOKS.items():
        linked = name == 'query'
        pair = (stage.b.j_type(3 if linked else 2, meta['labels'][name]),
                words[1] if linked else 0)
        if struct.unpack_from('<2I', candidate, pc - stage.BASE) != pair:
            raise ValueError('hook/delay mismatch')
    for pc, (_, replacement) in stage.STRIDES.items():
        if struct.unpack_from('<I', candidate, pc - stage.BASE)[0] != replacement:
            raise ValueError('job stride mismatch')
    for pc in (0x48F1B4, 0x48F3EC):
        if struct.unpack_from('<I', candidate, pc - stage.BASE)[0] != 0x240602C4:
            raise ValueError('stock template prefix was widened')

    start, end = meta['code_base'], meta['code_base'] + meta['code_bytes']
    words = struct.unpack_from('<%dI' % (meta['code_bytes'] // 4), candidate, meta['code_offset'])
    calls, tails = [], []
    for index, word in enumerate(words):
        pc, op = start + index * 4, word >> 26
        rs, imm = (word >> 21) & 31, word & 0xFFFF
        if op not in (0, 2, 3, 4, 5, 9, 11, 13, 15, 35, 43, 48, 56):
            raise ValueError('unknown opcode')
        if op == 0 and word & 63 not in (0, 8, 15, 16, 17, 18, 19, 33, 43):
            raise ValueError('unknown SPECIAL instruction')
        if op in (48, 56) and (rs, imm) != (8, 0):
            raise ValueError('non-private atomic access')
        if op in (4, 5):
            delta = imm - (0x10000 if imm & 0x8000 else 0)
            if not start <= pc + 4 + delta * 4 < end or words[index + 1] != 0:
                raise ValueError('invalid branch/delay')
        if op in (2, 3):
            target = ((pc + 4) & 0xF0000000) | ((word & 0x3FFFFFF) << 2)
            if words[index + 1] != 0:
                raise ValueError('unexpected jump delay')
            if not start <= target < end:
                (calls if op == 3 else tails).append(target)
        if op == 0 and word & 63 == 8:
            if word != 0x03E00008 or words[index + 1] != 0:
                raise ValueError('unexpected indirect return/delay')
    expected_tails = [pc + 8 for name, (pc, _) in stage.HOOKS.items() if name != 'query']
    if calls != [0x6F7CA0] or sorted(tails) != sorted(expected_tails):
        raise ValueError('external control-flow inventory changed')
    return dict(meta, sha256=hashlib.sha256(candidate).hexdigest(),
                changed_original_bytes=len(changes), external_calls=calls,
                verification='offline lineage only; no native ownership; hardware UNTESTED')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('candidate', type=Path)
    args = parser.parse_args()
    print(verify(args.source.read_bytes(), args.candidate.read_bytes()))


if __name__ == '__main__':
    main()
