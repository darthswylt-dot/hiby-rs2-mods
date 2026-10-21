#!/usr/bin/env python3
"""Exact offline original-entry filter verifier; no device transport."""
import argparse
import struct
from pathlib import Path

import build_reveal_origin_frontier_stage as stage
from verify_reveal_lineage_rows_stage import verify_stage


def verify(source, candidate, *, capacity=1024, row_capacity=1024, operation_capacity=1024):
    result = verify_stage(source, candidate, stage, capacity=capacity, row_capacity=row_capacity,
                          operation_capacity=operation_capacity)
    if (result['origin_entry_offset'], result['origin_entry_revision_offset'],
            result['requires_original_frontier'], result['contents_current']) != (0x10, 60, True, False):
        raise ValueError('unknown original-entry frontier contract')
    golden, _ = stage.normalize_source(source)
    # No guarded entry branches, remaining native saves or callback call/RA
    # anchors may be silently moved by the entry-carrier extension.
    for pc in (*range(0x4906E0, 0x4906F8, 4), *range(0x490700, 0x490714, 4),
               0x48EC50, 0x48EC54, 0x48EC58, 0x48EC64, 0x48EC70,
               0x48EC74, 0x48EC78, 0x48F8E0, 0x48F8EC):
        if struct.unpack_from('<I', candidate, pc - stage.BASE) != struct.unpack_from('<I', golden, pc - stage.BASE):
            raise ValueError('native guard/save/call anchor changed')
    return dict(result, verification='offline original-entry stale-start filter; no currentness or UI authority')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('candidate', type=Path)
    args = parser.parse_args()
    print(verify(args.source.read_bytes(), args.candidate.read_bytes()))


if __name__ == '__main__':
    main()
