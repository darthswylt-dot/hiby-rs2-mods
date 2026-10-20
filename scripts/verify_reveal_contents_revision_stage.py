#!/usr/bin/env python3
"""Exact offline seventeen-hook contents-boundary image verifier; no device."""
import argparse
from pathlib import Path

import build_reveal_contents_revision_stage as stage
from verify_reveal_lineage_rows_stage import verify_stage


def verify(source, candidate, *, capacity=1024, row_capacity=1024):
    result = verify_stage(source, candidate, stage, capacity=capacity, row_capacity=row_capacity)
    if (result['producer_revision_offset'], result['event_revision_offset'],
            result['known_boundary_count'], result['contents_current']) != (56, 60, 8, False):
        raise ValueError('unknown contents diagnostic format')
    return dict(result, verification='offline known-boundary filter; no settled epoch or UI authority')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('candidate', type=Path)
    args = parser.parse_args()
    print(verify(args.source.read_bytes(), args.candidate.read_bytes()))


if __name__ == '__main__':
    main()
