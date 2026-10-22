#!/usr/bin/env python3
"""Decode owned private reset/reconcile scope observations, without authority.

The packed header records issued tickets in bits0..15 and the active count in
bits16..30. Tickets never identify a native owner: they name private observed
invocations only. An unpublished issued slot, an in-progress close or a count
mismatch is incomplete evidence, not an empty guard. A CLOSED slot means the
instrumented function returned; its actual return value is not a success bit.

Quiet only excludes an observed open scope in these copied bytes. It does not
prove complete writer coverage, lifetime, current contents or coherent capture.
No native memory is read, and neither this parser nor its annotation helper
can authorize a UI action or repair an earlier decoder rejection.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path
import struct


FORMAT = 'native-scope-observation-v1'
HEADER, RECORD = 16, 32
DEFAULT_CAPACITY, MAX_CAPACITY = 1024, 0xFFFF
MAGIC = int.from_bytes(b'LSCP', 'little')
FAULT = 0xFFFFFFFF
RESET, RECONCILE = 1, 2
OPEN, CLOSING, CLOSED = 1, 2, 3
FIELDS = ('magic', 'kind', 'ticket', 'frame', 'rawarg0', 'rawarg1',
          'status', 'actual_result')
AUTHORITY_FLAGS = ('current_owner_proven', 'contents_current',
                   'autoscroll_allowed', 'coherent_native_snapshot',
                   'coherent_capture', 'autoscroll_authorized')
LIMITATIONS = (
    'Scope quiet is a diagnostic exclusion for the instrumented reset/reconcile invocations, not complete writer coverage.',
    'A closed scope records function return, not SQL success, settled contents, owner lifetime or a UI transaction.',
    'Issued but unpublished scopes, closing scopes and count mismatches cannot be treated as quiet.',
    'An empty guard does not establish that every relevant native scope was instrumented or observed.',
    'Copied scope bytes do not prove capture coherence or freshness of an earlier UI/playback request.',
)


def memory_bytes(capacity=DEFAULT_CAPACITY):
    if type(capacity) is not int or not 1 <= capacity <= MAX_CAPACITY:
        raise ValueError('native scope capacity must be an integer from 1 through 65535')
    return HEADER + RECORD * capacity


def _no_authority(result):
    result.update({field: False for field in AUTHORITY_FLAGS})


def decode_snapshot(data, *, capacity=DEFAULT_CAPACITY):
    """Decode an exact private buffer, retaining conservative transient states.

    Structural corruption and a terminal fault raise ValueError. Legitimate
    publication/closing transients and count disagreement return incomplete,
    non-quiet diagnostics. Input bytes are never modified or read indirectly.
    """
    total = memory_bytes(capacity)
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise ValueError('snapshot must be an already-owned byte buffer')
    raw = bytes(data)
    if len(raw) != total:
        raise ValueError('snapshot size does not match native scope format and capacity')
    state, *reserved = struct.unpack_from('<4I', raw)
    if any(reserved):
        raise ValueError('native scope: nonzero reserved header')
    if state == FAULT:
        raise ValueError('native scope: terminal fault state')
    if state & 0x80000000:
        raise ValueError('native scope: invalid high-bit state')
    issued, active = state & 0xFFFF, (state >> 16) & 0x7FFF
    if issued > capacity:
        raise ValueError('native scope: issued count exceeds capacity')

    records = []
    counts = {OPEN: 0, CLOSING: 0, CLOSED: 0}
    unpublished = 0
    for index in range(capacity):
        start = HEADER + index * RECORD
        record = raw[start:start + RECORD]
        if index >= issued:
            if any(record):
                raise ValueError('native scope: nonzero unissued slot')
            continue
        item = dict(zip(FIELDS, struct.unpack('<8I', record)))
        if item['magic'] == 0:
            # Reservation precedes publication. Other words may be any partial
            # mixture, including a result/status that is not yet meaningful.
            unpublished += 1
            records.append(dict(ticket=index + 1, published=False))
            continue
        if item['magic'] != MAGIC:
            raise ValueError('native scope: invalid published magic')
        if item['kind'] not in (RESET, RECONCILE):
            raise ValueError('native scope: invalid published kind')
        if item['ticket'] != index + 1:
            raise ValueError('native scope: noncontiguous published ticket')
        if not item['frame'] or item['frame'] & 3:
            raise ValueError('native scope: invalid published frame')
        if item['status'] not in counts:
            raise ValueError('native scope: invalid published status')
        if item['status'] == OPEN and item['actual_result']:
            raise ValueError('native scope: result in an open scope')
        # finish writes result while CLOSING before publishing CLOSED. Any
        # actual value during CLOSING is therefore a legitimate non-quiet
        # transient; it must never be interpreted as a completed return.
        counts[item['status']] += 1
        item['published'] = True
        item['actual_result_signed'] = (item['actual_result'] - (1 << 32)
                                        if item['actual_result'] & 0x80000000
                                        else item['actual_result'])
        del item['magic']
        records.append(item)

    matches = active == counts[OPEN] + counts[CLOSING]
    reasons = []
    if active or counts[OPEN]:
        reasons.append('native-scope-active')
    if unpublished:
        reasons.append('native-scope-unpublished')
    if counts[CLOSING]:
        reasons.append('native-scope-closing')
    if not matches:
        # CLOSED is published before active is decremented. A snapshot in
        # that interval can disagree without being structurally corrupt.
        reasons.append('native-scope-count-mismatch')
    quiet = (not reasons and counts[CLOSED] == issued and active == 0)
    result = dict(format=FORMAT, capacity=capacity, state=state,
                  issued=issued, active_count=active, open_count=counts[OPEN],
                  closing_count=counts[CLOSING], closed_count=counts[CLOSED],
                  unpublished_count=unpublished,
                  published_count=issued - unpublished,
                  counter_matches_records=matches,
                  scope_quiet=quiet, records=records, reasons=reasons,
                  limitations=list(LIMITATIONS))
    _no_authority(result)
    return result


def annotate_frontier_snapshot(frontier_result, scope_result):
    """Copy and conservatively narrow already-decoded frontier diagnostics.

    Only the existing operation completeness fields and window `complete`
    are narrowed. Row-window historical observations, previous reasons and
    prior frontier rejections remain intact. A quiet guard never repairs
    them, nor does either input establish coherent/current/authorized rows.
    """
    if not isinstance(frontier_result, dict) or not isinstance(scope_result, dict):
        raise ValueError('native scope annotation requires decoded result dictionaries')
    if type(scope_result.get('scope_quiet')) is not bool:
        raise ValueError('native scope annotation requires a boolean scope_quiet')
    result = deepcopy(frontier_result)
    scope = deepcopy(scope_result)
    quiet = scope['scope_quiet']
    _no_authority(scope)
    result['native_scope'] = scope
    result['scope_quiet'] = quiet
    _no_authority(result)
    for operation in result.get('operations', []):
        for field in ('observed_callback_sequence_complete',
                      'observed_row_window_complete'):
            if field in operation:
                operation.setdefault(field + '_before_scope', operation[field])
                if not quiet:
                    operation[field] = False
        if not quiet:
            reasons = operation.setdefault('reasons', [])
            if 'native-scope-not-quiet' not in reasons:
                reasons.append('native-scope-not-quiet')
        _no_authority(operation)
    for window in result.get('windows', []):
        if 'complete' in window:
            window.setdefault('complete_before_scope', window['complete'])
            if not quiet:
                window['complete'] = False
        if not quiet:
            reasons = window.setdefault('reasons', [])
            if 'native-scope-not-quiet' not in reasons:
                reasons.append('native-scope-not-quiet')
        _no_authority(window)
    limitations = result.setdefault('limitations', [])
    for limitation in LIMITATIONS:
        if limitation not in limitations:
            limitations.append(limitation)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', type=Path, help='local raw private LSCP scope buffer')
    parser.add_argument('--capacity', type=int, default=DEFAULT_CAPACITY)
    parser.add_argument('--frontier-snapshot', type=Path,
                        help='optional local raw original-frontier snapshot to narrow')
    parser.add_argument('--lineage-capacity', type=int, default=1024)
    parser.add_argument('--row-capacity', type=int, default=1024)
    parser.add_argument('--operation-capacity', type=int, default=1024)
    args = parser.parse_args(argv)
    try:
        result = decode_snapshot(args.snapshot.read_bytes(), capacity=args.capacity)
        if args.frontier_snapshot is not None:
            import decode_reveal_origin_frontier as frontier
            prior = frontier.decode(args.frontier_snapshot.read_bytes(),
                                    capacity=args.lineage_capacity,
                                    row_capacity=args.row_capacity,
                                    operation_capacity=args.operation_capacity)
            result = annotate_frontier_snapshot(prior, result)
    except (OSError, ValueError) as error:
        parser.exit(2, str(error) + '\n')
    print(json.dumps(result, ensure_ascii=True, indent=2))


if __name__ == '__main__':
    main()
