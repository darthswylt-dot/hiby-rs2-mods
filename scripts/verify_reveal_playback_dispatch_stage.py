#!/usr/bin/env python3
"""Exact offline callback-dispatch-intent image verification, not deployment."""
import argparse
from pathlib import Path
import struct

import build_reveal_playback_dispatch_stage as stage
from verify_reveal_lineage_rows_stage import verify_stage


def verify(source, candidate, *, capacity=1024, row_capacity=1024, operation_capacity=1024,
           scope_capacity=1024, birth_capacity=1024, transport_capacity=1024,
           renderer_capacity=1024, playback_dispatch_capacity=1024):
    result = verify_stage(source, candidate, stage, capacity=capacity, row_capacity=row_capacity,
        operation_capacity=operation_capacity, scope_capacity=scope_capacity,
        birth_capacity=birth_capacity, transport_capacity=transport_capacity,
        renderer_capacity=renderer_capacity, playback_dispatch_capacity=playback_dispatch_capacity)
    if any(result[name] is not False for name in ('autoscroll', 'request_freshness_proven',
            'callback_completion_proven', 'playback_identity_proven',
            'playback_paint_cause_associated', 'complete_playback_coverage')):
        raise ValueError('dispatch intent must not grant completion, playback identity or UI authority')
    if result['playback_dispatch_record_bytes'] != 64:
        raise ValueError('unknown playback dispatch layout')
    golden, _ = stage.normalize_source(source)
    # Keep original target load, nonnull branch, context load, and all native
    # continuations/order. In particular GENERAL action1 is EARLIER than BA0.
    for pc in (0x42CBFC, 0x42CC00, 0x42CC04, 0x42CC08,
               0x42CC14, 0x42CC18, 0x42CC1C, 0x42D614, 0x42D618,
               0x42D690, 0x42D694, 0x42D698, 0x42D69C, 0x42D6A8, 0x42D6AC):
        if struct.unpack_from('<I', candidate, pc - stage.BASE) != struct.unpack_from('<I', golden, pc - stage.BASE):
            raise ValueError('native playback dispatch gate/continuation changed')
    for name, (pc, pair) in stage.NEW_HOOKS.items():
        offset = result['code_offset'] + result['labels'][name] - result['code_base']
        first = struct.unpack_from('<3I', candidate, offset)
        expected = (pair[1], stage.b.lui(31, (pc + 8) >> 16),
                    stage.b.ori(31, 31, (pc + 8) & 0xFFFF))
        if first != expected:
            raise ValueError('relocated native delay/original RA contract changed')
        jump = result['labels'][name + '_jump']
        if struct.unpack_from('<2I', candidate, result['code_offset'] + jump - result['code_base']) != (0x03200008, 0):
            raise ValueError('callback must tail-dispatch to its original target')
    return dict(result, verification='offline CALL_INTENT only; original target-entry ABI/RA, no callback completion/playback paint cause/UI authority')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('candidate', type=Path)
    args = parser.parse_args()
    result = verify(args.source.read_bytes(), args.candidate.read_bytes())
    print({key: result[key] for key in ('sha256', 'output_size', 'memory_bytes', 'code_bytes',
                                       'changed_original_bytes', 'indirect_dispatch_tails', 'verification')})


if __name__ == '__main__':
    main()
