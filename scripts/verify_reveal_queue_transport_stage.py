#!/usr/bin/env python3
"""Exact offline queue-transport verification, never deployment approval."""
import argparse
import struct
from pathlib import Path

import build_reveal_queue_transport_stage as stage
from verify_reveal_lineage_rows_stage import verify_stage


def verify(source, candidate, *, capacity=1024, row_capacity=1024, operation_capacity=1024,
           scope_capacity=1024, birth_capacity=1024, transport_capacity=1024):
    result = verify_stage(source, candidate, stage, capacity=capacity, row_capacity=row_capacity,
                          operation_capacity=operation_capacity, scope_capacity=scope_capacity,
                          birth_capacity=birth_capacity, transport_capacity=transport_capacity)
    if (result['transport_token_offset'], result['node_token_offset'], result['generic_node_bytes'],
            result['rectangle_bytes'], result['birth_transport_target']) != (0x14, 0x10, 20, 16, '439EC0-entry-only'):
        raise ValueError('unknown explicit queue transport contract')
    if (not result['birth_identity_transported'] or not result['native_allocations_extended']
            or result['request_freshness_proven'] or result['renderer_identity_associated']
            or result['native_live_borrow_lease_proven'] or result['allocation_outcomes_preserved']):
        raise ValueError('queue transport must not confer ownership, freshness or UI authority')
    golden, _ = stage.normalize_source(source)
    anchors = (0x8B4280, 0x8B4284, 0x8B4288, 0x8B4294, 0x8B42A8,
               0x8B42B0, 0x8B42B4, 0x8B42BC, 0x8B42D8, 0x8B42DC,
               0x8B42E8, 0x8B42EC, 0x8B42F8, 0x8B3CE0, 0x8B3CE4,
               0x8B3D24, 0x8B3D4C, 0x8B40E4, 0x8B40E8, 0x8B475C,
               0x8B4760, 0x8B4774, 0x8B4788, 0x43963C, 0x8B4BB0,
               0x439F90, 0x438740, 0x48EC54, 0x48EC74)
    for pc in anchors:
        if struct.unpack_from('<I', candidate, pc - stage.BASE) != struct.unpack_from('<I', golden, pc - stage.BASE):
            raise ValueError('native queue prefix/call/delay/publication/free anchor changed')
    return dict(result, verification='offline explicit transport to callback entry; no renderer association/native lease/UI authority')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('candidate', type=Path)
    args = parser.parse_args()
    print(verify(args.source.read_bytes(), args.candidate.read_bytes()))


if __name__ == '__main__':
    main()
