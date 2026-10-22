#!/usr/bin/env python3
"""Decode owned native-scope-filter BSS, never infer a live UI transaction."""
import argparse
import json
from pathlib import Path

import decode_reveal_origin_frontier as previous
import decode_reveal_native_scope as scope
import folderfollow_reveal_lineage_mips as lineage
import reveal_lineage_rows_mips as rows
import reveal_operation_journal_mips as operation
import reveal_native_scope_mips as core


FORMAT = 'lineage-rows-native-scope-v1'


def decode(data, *, capacity=1024, row_capacity=1024, operation_capacity=1024, scope_capacity=1024):
    prefix = lineage.memory_bytes(capacity) + rows.memory_bytes(row_capacity) + 16
    prefix += operation.memory_bytes(operation_capacity)
    total = prefix + core.memory_bytes(scope_capacity)
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise ValueError('snapshot must be an already-owned byte buffer')
    raw = bytes(data)
    if len(raw) != total:
        raise ValueError('snapshot size does not match native-scope format and capacities')
    scopes = scope.decode_snapshot(raw[prefix:], capacity=scope_capacity)
    result = previous.decode(raw[:prefix], capacity=capacity, row_capacity=row_capacity,
                             operation_capacity=operation_capacity)
    result = scope.annotate_frontier_snapshot(result, scopes)
    result.update(format=FORMAT, contents_current=False, coherent_capture=False,
                  autoscroll_authorized=False)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', type=Path)
    parser.add_argument('--capacity', type=int, default=1024)
    parser.add_argument('--row-capacity', type=int, default=1024)
    parser.add_argument('--operation-capacity', type=int, default=1024)
    parser.add_argument('--scope-capacity', type=int, default=1024)
    args = parser.parse_args(argv)
    try:
        result = decode(args.snapshot.read_bytes(), capacity=args.capacity,
                        row_capacity=args.row_capacity, operation_capacity=args.operation_capacity,
                        scope_capacity=args.scope_capacity)
    except (OSError, ValueError) as error:
        parser.exit(2, str(error) + '\n')
    print(json.dumps(result, ensure_ascii=True, indent=2))


if __name__ == '__main__':
    main()
