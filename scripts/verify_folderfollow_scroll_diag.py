#!/usr/bin/env python3
"""Verify exact passive diagnostic bytes and allowed differences from golden."""
import argparse
import hashlib
from pathlib import Path
import build_folderfollow_scroll_diag as d


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('candidate', type=Path)
    args = parser.parse_args()
    source, candidate = args.source.read_bytes(), args.candidate.read_bytes()
    golden, _ = d.b.normalize_source(source)
    if candidate != d.build(source): raise SystemExit('candidate differs from reproducible build')
    spans = [(d.b.CALLBACK_HI_OFFSET, 4), (d.b.CALLBACK_LO_OFFSET, 4),
             (d.b.CAVE_OFFSET, len(d.build_wrapper()))]
    changes = [i for i, (a, b) in enumerate(zip(golden, candidate)) if a != b]
    if any(not any(start <= i < start + size for start, size in spans) for i in changes):
        raise SystemExit('change outside callback pointer and cave')
    print(f'verified: size={len(candidate)}, changed_bytes={len(changes)}, sha256={hashlib.sha256(candidate).hexdigest()}')
    print('offline verification only; see notes for hardware results; no deployment by this verifier')


if __name__ == '__main__': main()
