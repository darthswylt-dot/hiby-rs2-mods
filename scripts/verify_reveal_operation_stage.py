#!/usr/bin/env python3
"""Exact offline operation-observer image verifier, never a device launcher."""
import argparse
import struct
from pathlib import Path

import build_reveal_operation_stage as stage
from verify_reveal_lineage_rows_stage import verify_stage


def verify(source, candidate, *, capacity=1024, row_capacity=1024, operation_capacity=1024):
    result = verify_stage(source, candidate, stage, capacity=capacity, row_capacity=row_capacity,
                          operation_capacity=operation_capacity)
    golden, _ = stage.normalize_source(source)
    for pc in (0x48EC50, 0x48EC54, 0x48EC58, 0x48EC64,
               0x48EC70, 0x48EC74, 0x48EC78, 0x48F8E0, 0x48F8EC):
        if struct.unpack_from('<I', candidate, pc - stage.BASE) != struct.unpack_from('<I', golden, pc - stage.BASE):
            raise ValueError('native call/delay/epilogue anchor changed')
    return dict(result, verification='offline exact-BORROW callback evidence, not contents completion or UI authority')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('candidate', type=Path)
    args = parser.parse_args()
    print(verify(args.source.read_bytes(), args.candidate.read_bytes()))


if __name__ == '__main__':
    main()
