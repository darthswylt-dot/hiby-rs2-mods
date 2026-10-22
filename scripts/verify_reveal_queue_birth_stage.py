#!/usr/bin/env python3
"""Exact offline queue-birth observer verification; never deployment approval."""
import argparse
import struct
from pathlib import Path

import build_reveal_queue_birth_stage as stage
from verify_reveal_lineage_rows_stage import verify_stage


def verify(source, candidate, *, capacity=1024, row_capacity=1024, operation_capacity=1024,
           scope_capacity=1024, birth_capacity=1024):
    result = verify_stage(source, candidate, stage, capacity=capacity, row_capacity=row_capacity,
                          operation_capacity=operation_capacity, scope_capacity=scope_capacity,
                          birth_capacity=birth_capacity)
    if (result['birth_token_offset'], result['birth_record_bytes'],
            result['birth_identity_transported'], result['native_allocations_extended'],
            result['request_freshness_proven']) != (0x14, 64, False, False, False):
        raise ValueError('unknown queue birth observer contract')
    golden, _ = stage.normalize_source(source)
    # Keep allocator size, original native call+delay and later free paths.
    anchors = (0x8B4280, 0x8B4284, 0x8B4288, 0x8B4294, 0x8B42A8,
               0x8B42B0, 0x8B42B4, 0x8B42BC, 0x8B42D8, 0x8B42DC,
               0x8B42E8, 0x8B42EC, 0x8B42F8, 0x8B3CCC, 0x8B3CE0,
               0x8B40E4, 0x8B40E8, 0x8B475C, 0x8B4774, 0x8B4788,
               0x439F90, 0x438740, 0x48EC54, 0x48EC74)
    for pc in anchors:
        if struct.unpack_from('<I', candidate, pc - stage.BASE) != struct.unpack_from('<I', golden, pc - stage.BASE):
            raise ValueError('native queue size/call/free or consumer anchor changed')
    return dict(result, verification='offline queue-birth evidence; no native consumer identity or UI authority')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('candidate', type=Path)
    args = parser.parse_args()
    print(verify(args.source.read_bytes(), args.candidate.read_bytes()))


if __name__ == '__main__':
    main()
