#!/usr/bin/env python3
"""Exact offline nine-hook row-journal image verifier; no deployment."""
import argparse
import hashlib
import struct
from pathlib import Path

import build_reveal_lineage_rows_stage as stage


def verify(source, candidate, *, capacity=1024, row_capacity=1024):
    return verify_stage(source, candidate, stage, capacity=capacity, row_capacity=row_capacity)


def verify_stage(source, candidate, stage, *, capacity=1024, row_capacity=1024,
                 operation_capacity=None, scope_capacity=None, birth_capacity=None,
                 transport_capacity=None, renderer_capacity=None, playback_dispatch_capacity=None,
                 action_link_capacity=None):
    """Shared structural inventory, still bound to an exact deterministic build."""
    golden, _ = stage.normalize_source(source)
    build_options = dict(capacity=capacity, row_capacity=row_capacity)
    if operation_capacity is not None:
        build_options['operation_capacity'] = operation_capacity
    if scope_capacity is not None:
        build_options['scope_capacity'] = scope_capacity
    if birth_capacity is not None:
        build_options['birth_capacity'] = birth_capacity
    if transport_capacity is not None:
        build_options['transport_capacity'] = transport_capacity
    if renderer_capacity is not None:
        build_options['renderer_capacity'] = renderer_capacity
    if playback_dispatch_capacity is not None:
        build_options['playback_dispatch_capacity'] = playback_dispatch_capacity
    if action_link_capacity is not None:
        build_options['action_link_capacity'] = action_link_capacity
    expected, meta = stage.build(source, **build_options)
    if candidate != expected:
        raise ValueError('candidate differs from deterministic lineage/rows build')
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
    journal_end = meta['row_buffer'] + meta['row_memory_bytes']
    memory_end = meta['buffer'] + meta['memory_bytes']
    prefix_end = meta.get('operation_buffer', memory_end)
    if 'operation_buffer' in meta:
        if (meta['operation_memory_bytes'] != 16 + 64 * meta['operation_capacity']
                or meta['operation_buffer'] + meta['operation_memory_bytes']
                != meta.get('scope_buffer', memory_end)):
            raise ValueError('operation memory extent')
    if 'scope_buffer' in meta:
        if (meta['scope_memory_bytes'] != 16 + 32 * meta['scope_capacity']
                or meta['scope_buffer'] + meta['scope_memory_bytes']
                != meta.get('birth_buffer', memory_end)):
            raise ValueError('native scope memory extent')
    if 'birth_buffer' in meta:
        if (meta['birth_memory_bytes'] != 16 + 64 * meta['birth_capacity']
                or meta['birth_buffer'] + meta['birth_memory_bytes']
                != meta.get('transport_buffer', memory_end)):
            raise ValueError('queue birth memory extent')
    if 'transport_buffer' in meta:
        if (meta['transport_memory_bytes'] != 16 + 64 * meta['transport_capacity']
                or meta['transport_buffer'] + meta['transport_memory_bytes']
                != meta.get('renderer_transport_buffer', memory_end)):
            raise ValueError('queue transport memory extent')
    if 'renderer_transport_buffer' in meta:
        if (meta['renderer_transport_memory_bytes'] != 16 + 96 * meta['renderer_capacity']
                or meta['renderer_transport_buffer'] + meta['renderer_transport_memory_bytes']
                != meta.get('playback_dispatch_buffer', memory_end)):
            raise ValueError('renderer transport memory extent')
    if 'playback_dispatch_buffer' in meta:
        if (meta['playback_dispatch_memory_bytes'] != 16 + 64 * meta['playback_dispatch_capacity']
                or meta['playback_dispatch_buffer'] + meta['playback_dispatch_memory_bytes']
                != meta.get('action_link_buffer', memory_end)):
            raise ValueError('playback dispatch memory extent')
    if 'action_link_buffer' in meta:
        if (meta['action_link_memory_bytes'] != 16 + 96 * meta['action_link_capacity']
                or meta['action_link_buffer'] + meta['action_link_memory_bytes'] != memory_end):
            raise ValueError('action link memory extent')
    if 'contents_revision_buffer' in meta:
        if (meta['contents_revision_buffer'] != journal_end
                or meta['contents_revision_bytes'] != 16
                or journal_end + 16 != prefix_end):
            raise ValueError('contents revision memory extent')
    elif journal_end != memory_end:
        raise ValueError('journal memory extent')
    if (headers[3][2] + headers[3][5] != memory_end
            or meta['row_buffer'] != meta['buffer'] + meta['lineage_bytes']
            or meta['buffer'] < original[3][2] + original[3][5]
            or len(candidate) != meta['code_offset'] + meta['code_bytes']):
        raise ValueError('private memory/file extent')
    loads = [h for h in headers if h[0] == 1]
    for index, load in enumerate(loads):
        if load[6] & 3 == 3 or load[1] % load[7] != load[2] % load[7]:
            raise ValueError('LOAD permissions/alignment')
        for other in loads[index + 1:]:
            if max(load[2], other[2]) < min(load[2] + load[5], other[2] + other[5]):
                raise ValueError('overlapping LOADs')
    for name, (pc, words) in stage.HOOKS.items():
        linked = name in stage.LINKED
        pair = (stage.b.j_type(3 if linked else 2, meta['labels'][name]), words[1] if linked else 0)
        if struct.unpack_from('<2I', candidate, pc - stage.BASE) != pair:
            raise ValueError('hook/delay mismatch')
    for pc, (_, replacement) in stage.STRIDES.items():
        if struct.unpack_from('<I', candidate, pc - stage.BASE)[0] != replacement:
            raise ValueError('job stride mismatch')
    for pc in (0x48F1B4, 0x48F3EC):
        if struct.unpack_from('<I', candidate, pc - stage.BASE)[0] != 0x240602C4:
            raise ValueError('source template prefix was widened')

    start, end = meta['code_base'], meta['code_base'] + meta['code_bytes']
    words = struct.unpack_from('<%dI' % (meta['code_bytes'] // 4), candidate, meta['code_offset'])
    calls, tails, indirect, dispatch_tails = [], [], [], []
    expected_dispatch_tails = {meta['labels'][name]
                              for name in getattr(stage, 'INDIRECT_TAIL_LABELS', ())}
    for index, word in enumerate(words):
        pc, op = start + index * 4, word >> 26
        rs, imm = (word >> 21) & 31, word & 0xFFFF
        if op not in (0, 2, 3, 4, 5, 9, 11, 12, 13, 15, 35, 37, 41, 43, 48, 56):
            raise ValueError('unknown opcode')
        if op == 0 and word & 63 not in (0, 2, 8, 9, 15, 16, 17, 18, 19, 33, 43):
            raise ValueError('unknown SPECIAL instruction')
        if op in (48, 56) and (rs, imm) != (8, 0):
            raise ValueError('unexpected atomic access')
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
        if op == 0 and word & 63 in (8, 9):
            if words[index + 1] != 0:
                raise ValueError('unexpected indirect delay')
            if word & 63 == 8:
                if word != 0x03E00008:
                    if word != 0x03200008 or pc not in expected_dispatch_tails:
                        raise ValueError('unexpected indirect return')
                    dispatch_tails.append(pc)
            else:
                if word != 0x0320F809 or pc != meta['labels']['row'] + 8:
                    raise ValueError('unexpected indirect append call')
                indirect.append(pc)
    expected_tails = getattr(stage, 'NATIVE_TAILS',
                             [pc + 8 for name, (pc, _) in stage.HOOKS.items() if name not in stage.LINKED])
    if (sorted(calls) != [0x5C31C0, 0x6F7CA0] or sorted(tails) != sorted(expected_tails)
            or len(indirect) != 1 or set(dispatch_tails) != expected_dispatch_tails
            or len(dispatch_tails) != len(expected_dispatch_tails)):
        raise ValueError('external control-flow inventory changed')
    result = dict(meta, sha256=hashlib.sha256(candidate).hexdigest(),
                changed_original_bytes=len(changes), external_calls=calls,
                indirect_append_calls=indirect,
                verification='offline raw row journal; no ready rows/native ownership; hardware UNTESTED')
    if expected_dispatch_tails:
        result['indirect_dispatch_tails'] = dispatch_tails
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('candidate', type=Path)
    args = parser.parse_args()
    print(verify(args.source.read_bytes(), args.candidate.read_bytes()))


if __name__ == '__main__':
    main()
