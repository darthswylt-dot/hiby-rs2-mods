#!/usr/bin/env python3
"""Decode negative evidence from known native contents-boundary entries.

Format lineage-rows-content-revision-v1 is the existing lineage BSS, the
existing row-journal BSS, then a 16-byte private revision state. Only producer
receipt byte56 and journal record byte60 extend the earlier format. This
decoder validates those stamps, zeroes them in its OWN temporary byte copy,
and delegates every other structural/protocol check to the strict base parser.

An equal revision means only that no LATER instrumented boundary entry was
recorded. It does not prove idle/settled contents, complete writer coverage,
native object lifetime, a coherent capture, a host READY epoch or UI authority.
An old queued job can start after reset and take an equal producer stamp; an
already-active writer can continue after the stamp without another entry.
No native pointer reader, export, installer, device access or input mutation.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import struct

import decode_reveal_lineage_rows as base
import folderfollow_reveal_lineage_mips as lineage
import reveal_lineage_rows_mips as journal


FORMAT = 'lineage-rows-content-revision-v1'
STATE_BYTES = 16
PRODUCER_REVISION_OFFSET, EVENT_REVISION_OFFSET = 56, 60
REVISION_MAX = 0x7FFFFFFF
LIMITATIONS = (
    'Revision equality means only no observed later instrumented contents-boundary entry.',
    'A queued stale job starting after reset can have an equal producer revision and remains unproved.',
    'An already-active writer may continue after the producer stamp without another boundary entry.',
    'Global revisions conservatively mix owners; they are not per-owner generations or a settled contents epoch.',
    'The copied bytes do not establish coherent capture, native ownership, host READY or UI authority.',
)


def _counter(raw, offset, capacity, label):
    value = struct.unpack_from('<I', raw, offset)[0]
    if value == 0xFFFFFFFF or value > capacity:
        raise ValueError(label + ': faulted or invalid allocator')
    return value


def decode(data, *, capacity=1024, row_capacity=1024):
    """Reject known later boundaries without promoting equality to authority.

    Structural errors raise ValueError, including an impossible/future stamp.
    Observed protocol completeness is preserved separately. `complete` is
    narrowed by a known later entry; even True does NOT certify current rows.
    The caller supplies already-owned bytes and explicit buffer capacities.
    """
    lineage_size = lineage.memory_bytes(capacity)
    row_size = journal.memory_bytes(row_capacity)
    prefix_size = lineage_size + row_size
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise ValueError('snapshot must be an already-owned byte buffer')
    raw = bytes(data)
    if len(raw) != prefix_size + STATE_BYTES:
        raise ValueError('snapshot size does not match contents-revision format and capacities')
    current, *reserved = struct.unpack_from('<4I', raw, prefix_size)
    if current > REVISION_MAX or any(reserved):
        raise ValueError('contents revision: faulted counter or nonzero reserved state')
    allocated = _counter(raw, 0, capacity, 'lineage')
    events = _counter(raw, lineage_size, row_capacity, 'rows')
    canonical = bytearray(raw[:prefix_size])
    producer_revisions = {}
    for index in range(allocated):
        start = lineage.HEADER + index * lineage.RECORD
        kind = struct.unpack_from('<I', raw, start + lineage.KIND)[0]
        stamp = struct.unpack_from('<I', raw, start + PRODUCER_REVISION_OFFSET)[0]
        if kind != lineage.PRODUCER:
            if stamp:
                raise ValueError('contents revision: stamp on a non-producer receipt')
            continue
        if stamp > current:
            raise ValueError('contents revision: producer stamp is beyond known counter')
        producer_revisions[index + 1] = stamp
        struct.pack_into('<I', canonical, start + PRODUCER_REVISION_OFFSET, 0)
    for index in range(events):
        start = lineage_size + journal.HEADER + index * journal.RECORD
        producer = struct.unpack_from('<I', raw, start + journal.PRODUCER)[0]
        stamp = struct.unpack_from('<I', raw, start + EVENT_REVISION_OFFSET)[0]
        if producer not in producer_revisions or stamp != producer_revisions[producer]:
            raise ValueError('contents revision: event stamp does not mirror its producer')
        struct.pack_into('<I', canonical, start + EVENT_REVISION_OFFSET, 0)

    # Only the two explicitly versioned extension words were canonicalized.
    # Unknown fields, gaps, unused slots and every old strict check survive.
    result = base.decode(canonical, capacity=capacity, row_capacity=row_capacity)
    for receipt in result['receipts']:
        if receipt['kind'] == lineage.PRODUCER:
            receipt['producer_revision'] = producer_revisions[receipt['id']]
    for event in result['events']:
        event['producer_revision'] = producer_revisions[event['producer']]
    for window in result['windows']:
        stamp = producer_revisions[window['producer']]
        unchanged = stamp == current
        window.update(producer_revision=stamp, known_contents_revision=current,
                      observed_window_complete=window['complete'],
                      known_boundary_unchanged=unchanged, contents_current=False,
                      coherent_capture=False)
        if not unchanged:
            window['complete'] = False
            window['reasons'].append('known-contents-boundary')
    result.update(format=FORMAT, known_contents_revision=current,
                  autoscroll_authorized=False, contents_current=False,
                  coherent_capture=False)
    result['limitations'].extend(LIMITATIONS)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', type=Path, help='local raw revision-format private BSS snapshot')
    parser.add_argument('--capacity', type=int, default=1024)
    parser.add_argument('--row-capacity', type=int, default=1024)
    args = parser.parse_args(argv)
    try:
        result = decode(args.snapshot.read_bytes(), capacity=args.capacity,
                        row_capacity=args.row_capacity)
    except (OSError, ValueError) as error:
        parser.exit(2, str(error) + '\n')
    print(json.dumps(result, ensure_ascii=True, indent=2))


if __name__ == '__main__':
    main()
