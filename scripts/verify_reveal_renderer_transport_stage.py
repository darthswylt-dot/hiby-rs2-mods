#!/usr/bin/env python3
"""Exact offline renderer association verification, not deployment approval."""
import argparse
import struct
from pathlib import Path

import build_reveal_renderer_transport_stage as stage
from verify_reveal_lineage_rows_stage import verify_stage


def verify(source, candidate, *, capacity=1024, row_capacity=1024, operation_capacity=1024,
           scope_capacity=1024, birth_capacity=1024, transport_capacity=1024, renderer_capacity=1024):
    result = verify_stage(source, candidate, stage, capacity=capacity, row_capacity=row_capacity,
                          operation_capacity=operation_capacity, scope_capacity=scope_capacity,
                          birth_capacity=birth_capacity, transport_capacity=transport_capacity,
                          renderer_capacity=renderer_capacity)
    if (result['outer_token_offset'], result['renderer_transport_record_bytes'],
            result['birth_transport_target'], result['origin_entry_offset']) != (
            0x14, 96, 'existing-native-renderer-lineage-root', 0x10):
        raise ValueError('unknown renderer identity transport contract')
    if (not result['renderer_identity_transport_enabled'] or result['renderer_identity_associated']
            or result['request_freshness_proven'] or result['native_live_borrow_lease_proven']):
        raise ValueError('renderer association must not confer native ownership/currentness/UI authority')
    golden, _ = stage.normalize_source(source)
    anchors = (0x8B42E8, 0x8B42EC, 0x8B475C, 0x8B4760, 0x8B40E4, 0x8B40E8,
               0x439F84, 0x439F88, 0x439F8C, 0x439F90, 0x439F94,
               0x438200, 0x438204, 0x438738, 0x43873C, 0x438740, 0x438744,
               0x490750, 0x490754, 0x490760, 0x490764, 0x490768, 0x490774,
               0x48EC54, 0x48EC74)
    for pc in anchors:
        if struct.unpack_from('<I', candidate, pc - stage.BASE) != struct.unpack_from('<I', golden, pc - stage.BASE):
            raise ValueError('original callback/outer/renderer native call/delay/order changed')
    return dict(result, verification='offline explicit renderer-root association; no original UI cause/native lease/currentness/UI authority')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('candidate', type=Path)
    args = parser.parse_args()
    print(verify(args.source.read_bytes(), args.candidate.read_bytes()))


if __name__ == '__main__':
    main()
