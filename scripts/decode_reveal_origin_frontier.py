#!/usr/bin/env python3
"""Reject known stale starts using the immutable original renderer-entry mark.

This version has EXACTLY the operation snapshot's size. Only byte60 of each
allocated RENDER lineage receipt is extended: zero means unknown/unadmitted,
otherwise it is the fresh revision issued at original renderer entry, NOT a
counter sample taken later when the root receipt was minted. All other byte60
words remain zero. Already-owned input bytes are never changed.

Matching this frontier excludes a known intervening instrumented beginning
between that entry and the observed first fill. It does not establish an
actual first native execution, current playback/request/owner, a complete
writer set, settled contents, lifetime, capture coherence or UI permission.
In particular a stale UI/request that FIRST enters the renderer after reset
can receive a fresh entry revision and pass this bounded negative filter.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import struct

import decode_reveal_contents_revision as revision
import decode_reveal_operation_journal as base
import folderfollow_reveal_lineage_mips as lineage
import reveal_lineage_rows_mips as rows


FORMAT = 'lineage-rows-origin-frontier-v1'
ORIGINAL_ENTRY_REVISION_OFFSET = 60
LIMITATIONS = (
    'The immutable entry revision rejects known stale starts, not a fresh rendering of an already-stale UI or playback request.',
    'A matching original frontier does not establish playback/request identity, owner generation, query scope or retained lifetime.',
    'An already-active writer, uninstrumented mutation or recycled raw owner values can remain undetected.',
    'Later chunks of the same original renderer invocation are conservatively unadmitted once the known counter advances.',
    'This copied history does not prove first native execution, a complete writer set or capture coherence.',
)


def decode(data, *, capacity=1024, row_capacity=1024, operation_capacity=1024):
    """Canonicalize only the known extension, then retain all strict checks.

    Structural corruption/impossible counter chronology raises ValueError.
    A valid but stale/unknown original frontier narrows only operation-level
    historical completeness. Existing row-window rejection is NEVER repaired.
    """
    lineage_size = lineage.memory_bytes(capacity)
    revision_offset = lineage_size + rows.memory_bytes(row_capacity)
    total = revision_offset + revision.STATE_BYTES + base.memory_bytes(operation_capacity)
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise ValueError('snapshot must be an already-owned byte buffer')
    raw = bytes(data)
    if len(raw) != total:
        raise ValueError('snapshot size does not match origin-frontier format and capacities')
    current, *reserved = struct.unpack_from('<4I', raw, revision_offset)
    if current > revision.REVISION_MAX or any(reserved):
        raise ValueError('origin frontier: faulted counter or nonzero reserved revision state')
    allocated = struct.unpack_from('<I', raw)[0]
    if allocated == 0xFFFFFFFF or allocated > capacity:
        raise ValueError('origin frontier: faulted or invalid lineage allocator')
    canonical = bytearray(raw)
    original_entries = {}
    for index in range(allocated):
        start = lineage.HEADER + index * lineage.RECORD
        kind = struct.unpack_from('<I', raw, start + lineage.KIND)[0]
        stamp = struct.unpack_from('<I', raw, start + ORIGINAL_ENTRY_REVISION_OFFSET)[0]
        if kind != lineage.RENDER:
            if stamp:
                raise ValueError('origin frontier: entry stamp on a non-RENDER receipt')
            continue
        if stamp > current:
            raise ValueError('origin frontier: entry stamp is beyond the known counter')
        original_entries[index + 1] = stamp
        struct.pack_into('<I', canonical, start + ORIGINAL_ENTRY_REVISION_OFFSET, 0)

    # This changes only allocated RENDER+60 words, including zero/unknown ones.
    # Invalid magic, all unused tails and all other extension words survive.
    result = base.decode(canonical, capacity=capacity, row_capacity=row_capacity,
                         operation_capacity=operation_capacity)
    receipts = result['receipts']
    for receipt in receipts:
        original = original_entries.get(receipt['origin'], 0)
        receipt['original_entry_revision'] = original
        if receipt['kind'] == lineage.PRODUCER and original > receipt['producer_revision']:
            raise ValueError('origin frontier: producer revision predates its original entry')
    for event in result['operation_events']:
        original = original_entries.get(event['origin'], 0)
        if original > event['revision']:
            raise ValueError('origin frontier: operation event predates its original entry')
    for operation in result['operations']:
        origin = receipts[operation['origin'] - 1]
        original = origin['original_entry_revision']
        producer_id = operation['associated_producer']
        producer = receipts[producer_id - 1] if producer_id is not None else None
        start = operation['starting_revision']
        matches = (origin['kind'] == lineage.RENDER and original > 0
                   and original == start and producer is not None
                   and producer['producer_revision'] == original + 1)
        operation.update(original_entry_revision=original,
                         original_frontier_matches=matches,
                         observed_callback_sequence_complete_before_frontier=
                         operation['observed_callback_sequence_complete'])
        if not matches:
            operation['observed_callback_sequence_complete'] = False
            operation['reasons'].append('original-entry-frontier-mismatch')
    result.update(format=FORMAT, contents_current=False, coherent_capture=False,
                  autoscroll_authorized=False)
    result['limitations'].extend(LIMITATIONS)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', type=Path, help='local raw origin-frontier private BSS snapshot')
    parser.add_argument('--capacity', type=int, default=1024)
    parser.add_argument('--row-capacity', type=int, default=1024)
    parser.add_argument('--operation-capacity', type=int, default=1024)
    args = parser.parse_args(argv)
    try:
        result = decode(args.snapshot.read_bytes(), capacity=args.capacity,
                        row_capacity=args.row_capacity, operation_capacity=args.operation_capacity)
    except (OSError, ValueError) as error:
        parser.exit(2, str(error) + '\n')
    print(json.dumps(result, ensure_ascii=True, indent=2))


if __name__ == '__main__':
    main()
