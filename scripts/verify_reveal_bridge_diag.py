#!/usr/bin/env python3
"""Verify exact passive bridge build/layout/control-flow, never deploy it."""

import argparse
import hashlib
import struct
from pathlib import Path

import build_reveal_bridge_diag as d


def verify(source, candidate):
    golden, _ = d.normalize_source(source)
    expected, meta = d.build(source)
    if candidate != expected:
        raise ValueError('candidate differs from deterministic capture-only build')
    spans = [(meta['memsize_offset'], 4), (meta['phdr_offset'], 32),
             (d.b.CALLBACK_HI_OFFSET, 4), (d.b.CALLBACK_LO_OFFSET, 4)]
    spans.extend((pc - d.BASE, 8) for pc, _ in d.HOOKS.values())
    changes = [i for i, (old, new) in enumerate(zip(golden, candidate)) if old != new]
    if any(not any(start <= i < start + size for start, size in spans)
           for i in changes):
        raise ValueError('undeclared change to original image')
    if any(candidate[len(golden):meta['code_offset']]):
        raise ValueError('nonzero new file padding')
    # Independent PHDR checks, not just matching the layout builder's result.
    headers = [struct.unpack_from('<8I', candidate, 52 + i * 32) for i in range(10)]
    old_headers = [struct.unpack_from('<8I', golden, 52 + i * 32) for i in range(10)]
    for i in range(9):
        allowed = tuple(old_headers[i][:5]) + (meta['memsize'],) + old_headers[i][6:] if i == 3 else old_headers[i]
        if headers[i] != allowed:
            raise ValueError('original program header changed unexpectedly')
    new = headers[9]
    if new != (1, meta['code_offset'], meta['code_base'], meta['code_base'],
               meta['code_bytes'], meta['code_bytes'], 5, 0x10000):
        raise ValueError('new segment is not exact separate RX')
    if new[1] % new[7] != new[2] % new[7] or len(candidate) != new[1] + new[4]:
        raise ValueError('new segment alignment or file extent')
    rw = headers[3]
    if (rw[2] + rw[5] != meta['buffer'] + d.MEMORY_BYTES
            or meta['buffer'] < old_headers[3][2] + old_headers[3][5]):
        raise ValueError('private BSS geometry')
    loads = [p for p in headers if p[0] == 1]
    for i, p in enumerate(loads):
        if p[6] & 3 == 3:
            raise ValueError('writable executable LOAD')
        for q in loads[i + 1:]:
            if max(p[2], q[2]) < min(p[2] + p[5], q[2] + q[5]):
                raise ValueError('overlapping LOAD memory')

    for kind, (pc, original) in d.HOOKS.items():
        link = kind in d.LINKED
        target = meta['labels']['playback' if kind.startswith('play_') else kind]
        patched = struct.unpack_from('<2I', candidate, pc - d.BASE)
        if patched != (d.b.j_type(3 if link else 2, target), original[1] if link else 0):
            raise ValueError('hook redirect/delay mismatch')
    hi = struct.unpack_from('<I', candidate, d.b.CALLBACK_HI_OFFSET)[0]
    lo = struct.unpack_from('<I', candidate, d.b.CALLBACK_LO_OFFSET)[0]
    signed_lo = (lo & 0xFFFF) - (0x10000 if lo & 0x8000 else 0)
    if hi >> 16 != 0x3C06 or lo >> 16 != 0x24C6 or ((hi & 0xFFFF) << 16) + signed_lo != meta['labels']['timer']:
        raise ValueError('timer pointer construction mismatch')

    start, end = meta['code_base'], meta['code_base'] + meta['code_bytes']
    words = struct.unpack_from('<%dI' % (meta['code_bytes'] // 4), candidate, meta['code_offset'])
    allowed_ops = {0, 2, 3, 4, 5, 9, 11, 12, 13, 15, 35, 37, 41, 43, 48, 56}
    allowed_special = {0, 8, 9, 15, 16, 17, 18, 19, 33}
    # Explicit external target sets: no resolver, database query, setter,
    # refresh entry, property getter or stock synchronization call added.
    allowed_calls = {0xA5B440, 0xA5B4A0, 0x4E90C0}
    allowed_tails = {0x6ED62C, 0x6ED6F0, 0x5C31C0, 0x6ED7DC,
                     0x8B4CC8, 0x8B4EB4, 0x493AC8, 0x491248, 0x499CBC}
    external_calls, external_tails, indirect_calls = [], [], []
    for i, word in enumerate(words):
        pc, op = start + i * 4, word >> 26
        if op not in allowed_ops or (op == 0 and word & 63 not in allowed_special):
            raise ValueError(f'unexpected instruction at {pc:#x}')
        if op in (4, 5):
            imm = word & 0xFFFF
            delta = imm - (0x10000 if imm & 0x8000 else 0)
            if not start <= pc + 4 + delta * 4 < end or words[i + 1] != 0:
                raise ValueError('branch target or delay slot')
        if op in (2, 3):
            target = ((pc + 4) & 0xF0000000) | ((word & 0x3FFFFFF) << 2)
            if words[i + 1] != 0:
                raise ValueError('unexpected jump delay slot')
            if not start <= target < end:
                if target not in (allowed_calls if op == 3 else allowed_tails):
                    raise ValueError(f'unexpected external target {target:#x}')
                (external_calls if op == 3 else external_tails).append(target)
        if op == 0 and word & 63 == 9:
            if word != 0x0320F809 or words[i + 1] != 0:
                raise ValueError('unexpected indirect call')
            indirect_calls.append(pc)
        if op == 0 and word & 63 == 8 and word != 0x03E00008:
            raise ValueError('unexpected indirect jump')
    if sorted(external_calls) != sorted((0xA5B440, 0x4E90C0, 0xA5B4A0, 0xA5B4A0)):
        raise ValueError('external call inventory changed')
    if set(external_tails) != allowed_tails or len(indirect_calls) != 1:
        raise ValueError('stock continuation inventory changed')
    return dict(meta, sha256=hashlib.sha256(candidate).hexdigest(),
                changed_original_bytes=len(changes), external_calls=external_calls,
                verification='offline structure only; hardware UNTESTED')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('source', type=Path)
    p.add_argument('candidate', type=Path)
    args = p.parse_args()
    print(verify(args.source.read_bytes(), args.candidate.read_bytes()))


if __name__ == '__main__':
    main()
