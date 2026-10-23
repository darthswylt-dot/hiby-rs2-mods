#!/usr/bin/env python3
"""Exact offline notification-to-BIRTH image, not currentness/UI approval."""
import argparse
from pathlib import Path
import struct

import build_reveal_action_link_stage as stage
from verify_reveal_lineage_rows_stage import verify_stage


def verify(source, candidate, *, capacity=1024, row_capacity=1024, operation_capacity=1024,
           scope_capacity=1024, birth_capacity=1024, transport_capacity=1024,
           renderer_capacity=1024, playback_dispatch_capacity=1024, action_link_capacity=1024):
    result = verify_stage(source, candidate, stage, capacity=capacity, row_capacity=row_capacity,
        operation_capacity=operation_capacity, scope_capacity=scope_capacity,
        birth_capacity=birth_capacity, transport_capacity=transport_capacity,
        renderer_capacity=renderer_capacity, playback_dispatch_capacity=playback_dispatch_capacity,
        action_link_capacity=action_link_capacity)
    if (result['action_element_bytes'], result['original_action_element_bytes'],
            result['paint_element_bytes'], result['original_paint_element_bytes'],
            result['action_link_record_bytes']) != (20, 16, 36, 32, 96):
        raise ValueError('unknown native action/paint identity carrier layout')
    if (result['autoscroll'] or result['request_freshness_proven']
            or result['notification_currentness_proven'] or result['native_paint_payload_lease_proven']
            or not result['historical_notification_link_enabled']):
        raise ValueError('historical notification link must not grant currentness/lifetime/UI authority')
    golden, _ = stage.normalize_source(source)
    # Original calls, native return PCs, last payload-word delay stores and
    # locking order stay unchanged. Width changes do not change capacities.
    for pc in (0x4BAAEC, 0x4BACD8, 0x4BACDC, 0x4BACE0, 0x4BACE4,
               0x4BA95C, 0x4BA960, 0x4BA964, 0x4BA968, 0x4BAA60, 0x4BAA64,
               0x490994, 0x490A08, 0x490A0C, 0x490A58, 0x490A5C,
               0x43C8A4, 0x43C8A8, 0x43C8D0, 0x43C8D4,
               0x439854, 0x439858, 0x439924, 0x439928, 0x4399E0, 0x4399E4,
               0x4399F0, 0x4399F4, 0x43C910, 0x43C914, 0x43C968, 0x43C96C,
               0x459874, 0x459878, 0x8B4294, 0x8B42E8, 0x8B42EC):
        if struct.unpack_from('<I', candidate, pc - stage.BASE) != struct.unpack_from('<I', golden, pc - stage.BASE):
            raise ValueError('native notification/paint call, delay, capacity or lock order changed')
    # Only the exact old BIRTH wrapper's private call is redirected. The
    # replacement invokes the old core once and restores its actual result.
    call = result['labels']['action_birth_private_call']
    offset = result['code_offset'] + call - result['code_base']
    if struct.unpack_from('<2I', candidate, offset) != (
            stage.b.j_type(3, result['labels']['action_birth_capture']), 0):
        raise ValueError('unknown private BIRTH link point')
    begin = result['labels']['birth_entry']
    end = result['labels']['birth_enqueue_begin']
    for pc in range(begin, end, 4):
        word = struct.unpack_from('<I', candidate, result['code_offset'] + pc - result['code_base'])[0]
        if word == stage.b.j_type(3, result['labels']['queue_birth_capture']):
            raise ValueError('old BIRTH wrapper still bypasses the single exact link helper')
    return dict(result, verification='offline explicit notification/control-flow ancestry to actual BIRTH; no native payload lease/coherent media/currentness/UI authority')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('candidate', type=Path)
    args = parser.parse_args()
    result = verify(args.source.read_bytes(), args.candidate.read_bytes())
    print({name: result[name] for name in ('sha256', 'output_size', 'memory_bytes', 'code_bytes',
        'changed_original_bytes', 'action_element_bytes', 'paint_element_bytes', 'verification')})


if __name__ == '__main__':
    main()
