#!/usr/bin/env python3
"""Decode an owned diagnostic fill/postfill operation journal, without authority.

The exact input is the contents-revision format followed by one bounded LOPR
journal. Events are grouped ONLY by immutable BORROW receipt ID, never by a
name, list, view, frame or job address. A complete observed callback sequence
does not repair the base decoder's known-boundary rejection, certify native
ownership or establish current/settled rows. No native memory is read here.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import struct

import decode_reveal_contents_revision as base
import folderfollow_reveal_lineage_mips as lineage
import reveal_lineage_rows_mips as rows


FORMAT = 'lineage-rows-content-revision-operation-journal-v1'
HEADER, RECORD = 16, 64
MAGIC = int.from_bytes(b'LOPR', 'little')
DEFAULT_CAPACITY = 1024
MAX_CAPACITY = (0x100000000 - HEADER) // RECORD
FIELDS = ('magic', 'kind', 'borrow', 'seq', 'origin', 'job', 'stack', 'site',
          'result', 'callee', 'panel', 'dest', 'view', 'revision',
          'reserved0', 'reserved1')
FILL_BEGIN, FILL_RETURN, POST_TARGET, BIND_BEGIN, BIND_RETURN, NORMAL_END, ERROR_END = range(1, 8)
SITES = {FILL_BEGIN: 0x48EC48, FILL_RETURN: 0x48EC5C,
         POST_TARGET: 0x48EC68, BIND_BEGIN: 0x4A0EE0,
         BIND_RETURN: 0x48F8E4, NORMAL_END: 0x48EC7C,
         ERROR_END: 0x48EDD4}
EXPECTED_KINDS = (FILL_BEGIN, FILL_RETURN, POST_TARGET, BIND_BEGIN,
                  BIND_RETURN, NORMAL_END)
FILL_CALLEE, POST_CALLEE = 0x48D280, 0x48F880
LIMITATIONS = (
    'Operation events are diagnostic history grouped by BORROW ID, not by raw-address equality.',
    'Observed callback completeness does not relax base row-window known-contents-boundary rejection.',
    'Expected revision steps do not exclude an already-active writer or a queued stale original invocation.',
    'A callback return or metadata rebind is not retained ownership, a settled epoch or host CompletedRows.',
    'Reservation order and copied bytes do not establish execution order across journals or capture coherence.',
    'The later native statement-finalize status and date-mode extra SQL work remain unobserved.',
)


def memory_bytes(capacity=DEFAULT_CAPACITY):
    if type(capacity) is not int or not 1 <= capacity <= MAX_CAPACITY:
        raise ValueError('operation capacity must fit a nonempty unsigned-32 journal')
    return HEADER + RECORD * capacity


def _events(raw, capacity, receipts, current):
    counter, *reserved = struct.unpack_from('<4I', raw)
    if any(reserved):
        raise ValueError('operations: nonzero reserved header')
    if counter == 0xFFFFFFFF or counter > capacity:
        raise ValueError('operations: faulted or invalid allocator')
    events = []
    for index in range(capacity):
        start = HEADER + index * RECORD
        record = raw[start:start + RECORD]
        if index >= counter:
            if any(record):
                raise ValueError('operations: nonzero unallocated slot')
            continue
        item = dict(zip(FIELDS, struct.unpack('<16I', record)))
        kind = item['kind']
        if item['magic'] != MAGIC:
            raise ValueError('operations: missing/unpublished allocated slot')
        if kind not in SITES or item['site'] != SITES[kind]:
            raise ValueError('operations: unknown kind or wrong source site')
        if item['seq'] != index + 1:
            raise ValueError('operations: noncontiguous sequence')
        if item['reserved0'] or item['reserved1']:
            raise ValueError('operations: nonzero reserved record words')
        if item['revision'] > current:
            raise ValueError('operations: revision is beyond the known counter')
        token = item['borrow']
        if not 1 <= token <= len(receipts) or receipts[token - 1]['kind'] != lineage.BORROW:
            raise ValueError('operations: event does not name a BORROW receipt')
        borrow = receipts[token - 1]
        if any(item[field] != borrow[field] for field in ('origin', 'job', 'stack')):
            raise ValueError('operations: BORROW invocation metadata mismatch')
        if kind not in (FILL_BEGIN, POST_TARGET) and item['callee']:
            raise ValueError('operations: nonzero unused callee')
        if kind in (FILL_BEGIN, POST_TARGET, BIND_BEGIN) and item['result']:
            raise ValueError('operations: nonzero begin/target result')
        if kind == BIND_BEGIN:
            if any(item[field] != borrow[field] for field in ('panel', 'view')):
                raise ValueError('operations: original panel/view association mismatch')
        elif any(item[field] for field in ('panel', 'dest', 'view')):
            raise ValueError('operations: nonzero unused binding payload')
        item['result'] = item['result'] - (1 << 32) if item['result'] & 0x80000000 else item['result']
        del item['magic'], item['reserved0'], item['reserved1']
        events.append(item)
    return events


def _operation(borrow, events, receipts, windows, current):
    reasons = []

    def reject(reason):
        if reason not in reasons:
            reasons.append(reason)

    kinds = tuple(event['kind'] for event in events)
    sequence = kinds == EXPECTED_KINDS
    if not events:
        reject('no-operation-events')
    if not sequence:
        reject('callback-event-sequence')
    if ERROR_END in kinds:
        reject('fill-error-end')

    queries = [item for item in receipts
               if item['kind'] == lineage.QUERY and item['parent'] == borrow['id']]
    query_ids = {item['id'] for item in queries}
    producers = [item for item in receipts
                 if item['kind'] == lineage.PRODUCER and item['parent'] in query_ids]
    if len(queries) != 1:
        reject('query-count')
    if len(producers) != 1:
        reject('producer-count')
    query = queries[0] if len(queries) == 1 else None
    producer = producers[0] if len(producers) == 1 else None
    window = windows.get(producer['id']) if producer is not None else None
    binds = [event for event in events if event['kind'] == BIND_BEGIN]
    bind = binds[0] if len(binds) == 1 else None
    associated = (query is not None and producer is not None and bind is not None
                  and bind['dest'] == query['dest'] == producer['dest'])
    if not associated:
        reject('row-observation-association')
    observed_rows = bool(window is not None and window['observed_window_complete'])
    if not observed_rows:
        reject('row-window-incomplete')

    start = events[0]['revision'] if sequence else None
    if sequence:
        fill, returned, post, binding, bound, end = events
        if fill['callee'] != FILL_CALLEE:
            reject('fill-target')
        if returned['result'] == -1:
            reject('fill-return-error')
        if post['callee'] != POST_CALLEE:
            reject('post-target')
        if bound['result'] != 0:
            reject('bind-return-failed')
        if end['result'] != bound['result'] or end['result'] != 0:
            reject('normal-end-result')
        expected = (start, start + 1, start + 1, start + 2, start + 3, start + 3)
        if tuple(event['revision'] for event in events) != expected:
            reject('revision-steps')
        if producer is None or producer['producer_revision'] != start + 1:
            reject('producer-revision')

    # Counter comparisons are only negative evidence. Incomplete/no-event
    # histories cannot establish the point after which a boundary was later.
    latest = max((event['revision'] for event in events), default=None)
    return dict(borrow=borrow['id'], origin=borrow['origin'], job=borrow['job'],
                stack=borrow['stack'], event_sequences=[event['seq'] for event in events],
                event_kinds=list(kinds), associated_query=query['id'] if query else None,
                associated_producer=producer['id'] if producer else None,
                row_observation_associated=associated,
                observed_row_window_complete=observed_rows,
                observed_callback_sequence_complete=not reasons, reasons=reasons,
                starting_revision=start, latest_observed_revision=latest,
                known_contents_revision=current,
                known_later_boundary=None if latest is None else current > latest,
                contents_current=False, coherent_capture=False,
                autoscroll_authorized=False)


def decode(data, *, capacity=1024, row_capacity=1024, operation_capacity=DEFAULT_CAPACITY):
    """Decode exact owned buffers; structural errors raise, gaps stay incomplete.

    Existing row windows and their rejection reasons are preserved verbatim.
    `observed_callback_sequence_complete` concerns historical evidence only;
    no complete/current/READY row object is returned by this extension.
    """
    prefix_size = lineage.memory_bytes(capacity) + rows.memory_bytes(row_capacity) + base.STATE_BYTES
    operation_size = memory_bytes(operation_capacity)
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise ValueError('snapshot must be an already-owned byte buffer')
    raw = bytes(data)
    if len(raw) != prefix_size + operation_size:
        raise ValueError('snapshot size does not match operation-journal format and capacities')
    result = base.decode(raw[:prefix_size], capacity=capacity, row_capacity=row_capacity)
    current = result['known_contents_revision']
    events = _events(raw[prefix_size:], operation_capacity, result['receipts'], current)
    grouped = {item['id']: [] for item in result['receipts'] if item['kind'] == lineage.BORROW}
    for event in events:
        grouped[event['borrow']].append(event)
    windows = {item['producer']: item for item in result['windows']}
    operations = [_operation(item, grouped[item['id']], result['receipts'], windows, current)
                  for item in result['receipts'] if item['kind'] == lineage.BORROW]
    result.update(format=FORMAT, operation_events=events, operations=operations,
                  contents_current=False, coherent_capture=False, autoscroll_authorized=False)
    result['limitations'].extend(LIMITATIONS)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', type=Path, help='local raw revision-format BSS followed by LOPR journal')
    parser.add_argument('--capacity', type=int, default=1024)
    parser.add_argument('--row-capacity', type=int, default=1024)
    parser.add_argument('--operation-capacity', type=int, default=DEFAULT_CAPACITY)
    args = parser.parse_args(argv)
    try:
        result = decode(args.snapshot.read_bytes(), capacity=args.capacity,
                        row_capacity=args.row_capacity, operation_capacity=args.operation_capacity)
    except (OSError, ValueError) as error:
        parser.exit(2, str(error) + '\n')
    print(json.dumps(result, ensure_ascii=True, indent=2))


if __name__ == '__main__':
    main()
