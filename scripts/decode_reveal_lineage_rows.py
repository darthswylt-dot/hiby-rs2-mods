#!/usr/bin/env python3
"""Strict offline decoder of an already-owned lineage + row-journal snapshot.

Input is exactly the two private BSS buffers, concatenated in that order.
Their capacities are explicit arguments, not inferred from magic or pointers.
This parser neither obtains a coherent capture nor reads any native object.
An observed complete window is NOT a whole folder, current list, CompletedRows
receipt, retained owner, cancellation fence, or permission to operate the UI.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import struct

import folderfollow_reveal_lineage_mips as lineage
import reveal_lineage_rows_mips as journal


ROW_HEADER, ROW_RECORD, ROW_MAGIC = journal.HEADER, journal.RECORD, journal.MAGIC
ROW_FIELDS = ('magic', 'kind', 'producer', 'seq', 'frame', 'stmt', 'dest',
              'mode', 'offset', 'ordinal', 'result', 'cue', 'truncated',
              'count', 'origin', 'reserved')
LINEAGE_FIELDS = ('magic', 'kind', 'origin', 'parent', 'view', 'panel', 'job',
                  'dest', 'site', 'stack', 'offset', 'request', 'stmt',
                  'flags', 'reserved0', 'reserved1')
ROW, TERMINAL, RESET, END = journal.ROW, journal.TERMINAL, journal.RESET, journal.END
INT_MAX = (1 << 31) - 1
LIMITATIONS = (
    'Input bytes are already owned; the decoder does not establish capture coherence.',
    'Reservation order is not a global native execution or ownership order.',
    'Complete means only the observed bounded producer window, not a whole folder or ready rows.',
    'Initial list count, query scope and folder total were not independently captured.',
    'Statement reset is observed; the later wrapper statement-finalize result is not captured.',
    'No row-parent/scope check is possible: a query scope is absent from this journal.',
    'Raw frame, statement, job, view and list values are diagnostic scalars, not lifetime leases.',
    'Native ownership, complete cancellation/writer coverage and UI authority remain unproved.',
)


def signed(value):
    return value - (1 << 32) if value & 0x80000000 else value


def row_memory_bytes(capacity):
    return journal.memory_bytes(capacity)


def _allocated(raw, *, capacity, record_size, magic, label):
    counter, *reserved = struct.unpack_from('<4I', raw)
    if any(reserved):
        raise ValueError(label + ': nonzero reserved header')
    if counter == 0xFFFFFFFF or counter > capacity:
        raise ValueError(label + ': faulted or invalid allocator')
    for index in range(capacity):
        start = 16 + index * record_size
        record = raw[start:start + record_size]
        if index >= counter:
            if any(record):
                raise ValueError(label + ': nonzero unallocated slot')
            continue
        if struct.unpack_from('<I', record)[0] != magic:
            raise ValueError(label + ': missing/unpublished allocated slot')
        yield index + 1, record


def _receipts(raw, capacity):
    receipts = []
    sites = {lineage.RENDER: 0x490758, lineage.INITIAL: 0x48F40C,
             lineage.BORROW: 0x48EB40, lineage.QUERY: 0x48D1B8,
             lineage.PRODUCER: 0x6ED624}
    parent_kinds = {lineage.BORROW: (lineage.RENDER, lineage.INITIAL),
                    lineage.QUERY: (lineage.BORROW,),
                    lineage.PRODUCER: (lineage.QUERY,)}
    for token, record in _allocated(raw, capacity=capacity, record_size=lineage.RECORD,
                                    magic=lineage.MAGIC, label='lineage'):
        item = dict(zip(LINEAGE_FIELDS, struct.unpack('<16I', record)))
        kind = item['kind']
        if kind not in (lineage.RENDER, lineage.INITIAL, lineage.BORROW,
                        lineage.QUERY, lineage.PRODUCER):
            raise ValueError('lineage: unknown kind')
        if item['flags'] or item['reserved0'] or item['reserved1']:
            raise ValueError('lineage: nonzero unused record words')
        if item['site'] != sites[kind]:
            raise ValueError('lineage: wrong source site for kind')
        item['offset'], item['request'] = signed(item['offset']), signed(item['request'])
        if kind in (lineage.RENDER, lineage.INITIAL):
            if item['origin'] != token or item['parent']:
                raise ValueError('lineage: invalid original invocation')
        else:
            parent = item['parent']
            if not 1 <= parent < token:
                raise ValueError('lineage: noncausal parent')
            previous = receipts[parent - 1]
            if previous['kind'] not in parent_kinds[kind]:
                raise ValueError('lineage: wrong parent kind')
            if any(item[field] != previous[field] for field in ('origin', 'view', 'panel')):
                raise ValueError('lineage: inherited original association mismatch')
            if kind == lineage.QUERY:
                if (item['job'] != previous['job']
                        or item['stack'] + 0x40 != previous['stack']):
                    raise ValueError('lineage: query/borrow payload mismatch')
            elif kind == lineage.PRODUCER:
                if (any(item[field] != previous[field]
                        for field in ('job', 'dest', 'offset', 'request'))
                        or item['stack'] + 0xAD0 + 0xBE0 + 0x80 != previous['stack']):
                    raise ValueError('lineage: producer/query payload mismatch')
        if kind in (lineage.RENDER, lineage.INITIAL, lineage.BORROW):
            if any(item[field] for field in ('dest', 'offset', 'request', 'stmt')):
                raise ValueError('lineage: nonzero unused payload')
        elif kind == lineage.QUERY and item['stmt']:
            raise ValueError('lineage: nonzero unused query statement')
        item['id'] = token
        del item['magic'], item['flags'], item['reserved0'], item['reserved1']
        receipts.append(item)
    return receipts


def _path(raw):
    end = next((index for index in range(0, len(raw), 2)
                if raw[index:index + 2] == b'\0\0'), None)
    if end is None:
        raise ValueError('rows: unterminated path within 260 code units')
    if any(raw[end:]):
        raise ValueError('rows: nonzero path padding')
    try:
        return raw[:end].decode('utf-16le', errors='strict')
    except UnicodeDecodeError as error:
        raise ValueError('rows: malformed UTF-16 path') from error


def _events(raw, capacity, receipts):
    events = []
    for sequence, record in _allocated(raw, capacity=capacity, record_size=ROW_RECORD,
                                       magic=ROW_MAGIC, label='rows'):
        item = dict(zip(ROW_FIELDS, struct.unpack_from('<16I', record)))
        if item['kind'] not in (ROW, TERMINAL, RESET, END):
            raise ValueError('rows: unknown kind')
        if item['seq'] != sequence:
            raise ValueError('rows: noncontiguous sequence')
        if item['mode'] or item['reserved'] or any(record[584:]):
            raise ValueError('rows: unsupported mode or nonzero reserved words')
        producer = item['producer']
        if not 1 <= producer <= len(receipts) or receipts[producer - 1]['kind'] != lineage.PRODUCER:
            raise ValueError('rows: event does not name a producer receipt')
        parent = receipts[producer - 1]
        item['offset'] = signed(item['offset'])
        if any(item[field] != parent[source] for field, source in
               (('frame', 'stack'), ('stmt', 'stmt'), ('dest', 'dest'),
                ('offset', 'offset'), ('origin', 'origin'))):
            raise ValueError('rows: producer invocation metadata mismatch')
        path_bytes = record[64:584]
        if item['kind'] == ROW:
            if item['truncated']:
                raise ValueError('rows: truncated or invalid path capture')
            item['path'] = _path(path_bytes)
        else:
            if item['cue'] or item['truncated'] or any(path_bytes):
                raise ValueError('rows: nonzero unused identity fields')
            item['path'] = None
        for field in ('ordinal', 'result', 'cue', 'count'):
            item[field] = signed(item[field])
        del item['magic'], item['reserved']
        events.append(item)
    return events


def _window(producer, events):
    reasons, rows, identities = [], [], set()
    seen = {TERMINAL: 0, RESET: 0, END: 0}
    phase, n = 'rows', 0

    def reject(reason):
        if reason not in reasons:
            reasons.append(reason)

    if producer['offset'] < 0:
        reject('invalid-offset')
    if not 0 <= producer['request'] <= INT_MAX:
        reject('invalid-requested-count')
    results = {'terminal_result': None, 'reset_result': None, 'end_result': None}
    for event in events:
        kind = event['kind']
        if phase == 'ended':
            reject('event-after-end')
            continue
        if kind == ROW:
            if phase != 'rows':
                reject('row-outside-row-phase')
            if event['ordinal'] != n:
                reject('row-ordinal-mismatch')
            if event['result'] != n:
                reject('append-result-mismatch')
            if event['count'] != n + 1:
                reject('append-count-mismatch')
            identity = event['path'], event['cue']
            if not event['path']:
                reject('empty-row-path')
            if identity in identities:
                reject('duplicate-row-identity')
            identities.add(identity)
            rows.append({key: event[key] for key in ('ordinal', 'path', 'cue', 'result', 'count')})
            n += 1
        else:
            seen[kind] += 1
            if seen[kind] != 1:
                reject('duplicate-' + {TERMINAL: 'terminal', RESET: 'reset', END: 'end'}[kind])
            if event['ordinal'] != n or event['count'] != n:
                reject('completion-count-or-ordinal-mismatch')
            if kind == TERMINAL:
                if phase != 'rows':
                    reject('terminal-out-of-order')
                if event['result'] != 101:
                    reject('query-not-complete')
                results['terminal_result'] = event['result']
                phase = 'reset'
            elif kind == RESET:
                if phase != 'reset':
                    reject('reset-out-of-order')
                if event['result'] != 0:
                    reject('reset-failed')
                results['reset_result'] = event['result']
                phase = 'end'
            else:
                if phase != 'end':
                    reject('end-out-of-order')
                if event['result'] != n:
                    reject('producer-end-result-mismatch')
                results['end_result'] = event['result']
                phase = 'ended'
    for kind, name in ((TERMINAL, 'terminal'), (RESET, 'reset'), (END, 'end')):
        if not seen[kind]:
            reject('missing-' + name)
    if not events:
        reject('no-events')
    if n > producer['request']:
        reject('rows-exceed-requested-count')
    return dict(producer=producer['id'], origin=producer['origin'], frame=producer['stack'],
                stmt=producer['stmt'], dest=producer['dest'], offset=producer['offset'],
                requested_count=producer['request'], observed_count=n, rows=rows,
                complete=not reasons, reasons=reasons, observed_window_only=True,
                whole_folder=False, **results)


def decode(data, *, capacity=1024, row_capacity=1024):
    """Decode exact owned buffers; corruption raises, incomplete windows report.

    Structural association/encoding errors raise ValueError. Otherwise every
    producer receipt appears in windows, with protocol errors/missing events
    reported as complete=False. No usable row-authority object is returned.
    """
    lineage_size = lineage.memory_bytes(capacity)
    row_size = row_memory_bytes(row_capacity)
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise ValueError('snapshot must be an already-owned byte buffer')
    data = bytes(data)
    if len(data) != lineage_size + row_size:
        raise ValueError('snapshot size does not match the two explicit capacities')
    receipts = _receipts(data[:lineage_size], capacity)
    events = _events(data[lineage_size:], row_capacity, receipts)
    grouped = {item['id']: [] for item in receipts if item['kind'] == lineage.PRODUCER}
    for event in events:
        grouped[event['producer']].append(event)
    windows = [_window(item, grouped[item['id']]) for item in receipts
               if item['kind'] == lineage.PRODUCER]
    return dict(receipts=receipts, events=events, windows=windows,
                autoscroll_authorized=False, limitations=list(LIMITATIONS))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', type=Path, help='local raw lineage buffer followed by row buffer')
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
