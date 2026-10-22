#!/usr/bin/env python3
"""Decode owned birth-observer BSS without associating queued causes to rows."""
import argparse
import json
from pathlib import Path

import decode_reveal_native_scope_stage as previous
import decode_reveal_queue_birth as birth
import folderfollow_reveal_lineage_mips as lineage
import reveal_lineage_rows_mips as rows
import reveal_operation_journal_mips as operation
import reveal_native_scope_mips as scope


FORMAT = 'lineage-rows-queue-birth-v1'


def decode(data, *, capacity=1024, row_capacity=1024, operation_capacity=1024,
           scope_capacity=1024, birth_capacity=1024):
    prefix = lineage.memory_bytes(capacity) + rows.memory_bytes(row_capacity) + 16
    prefix += operation.memory_bytes(operation_capacity) + scope.memory_bytes(scope_capacity)
    total = prefix + birth.memory_bytes(birth_capacity)
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise ValueError('snapshot must be an already-owned byte buffer')
    raw = bytes(data)
    if len(raw) != total:
        raise ValueError('snapshot size does not match queue-birth format and capacities')
    result = previous.decode(raw[:prefix], capacity=capacity, row_capacity=row_capacity,
                             operation_capacity=operation_capacity, scope_capacity=scope_capacity)
    observed = birth.decode(raw[prefix:], capacity=birth_capacity,
                            current_revision=result['known_contents_revision'])
    # Issued scope tickets, unlike active count, never decrease. A future
    # sample is inconsistent with this snapshot's final strict scope header.
    if any((event['scope'] & 0xFFFF) > result['native_scope']['issued']
           for event in observed['events']):
        raise ValueError('queue birth scope sample is beyond the final issued counter')
    # No pointer equality, metadata value or current-name lookup can join
    # this new journal to a row/renderer receipt. Preserve prior rejections.
    result.update(format=FORMAT, queue_birth_observation=observed,
                  birth_identity_transported=False, request_freshness_proven=False,
                  current_owner_proven=False, contents_current=False,
                  coherent_capture=False, autoscroll_authorized=False)
    result['limitations'].append(
        'Birth receipts have not been transported through the native queue/consumer; no request-to-row association is established.')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', type=Path)
    for name in ('capacity', 'row-capacity', 'operation-capacity', 'scope-capacity', 'birth-capacity'):
        parser.add_argument('--' + name, type=int, default=1024)
    args = parser.parse_args(argv)
    try:
        result = decode(args.snapshot.read_bytes(), capacity=args.capacity,
                        row_capacity=args.row_capacity, operation_capacity=args.operation_capacity,
                        scope_capacity=args.scope_capacity, birth_capacity=args.birth_capacity)
    except (OSError, ValueError) as error:
        parser.exit(2, str(error) + '\n')
    print(json.dumps(result, ensure_ascii=True, indent=2))


if __name__ == '__main__':
    main()
