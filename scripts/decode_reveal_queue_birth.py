#!/usr/bin/env python3
"""Decode private queue-birth observations without granting request authority.

The LQBR journal observes a birth before one native enqueue, the numeric
allocated-copy identity and the generic append return. Its IDs are private receipts, not native owner
identities. They are not yet transported through the queue to a child renderer.
In particular, this parser never joins a request to row origins by address.

Equal revision samples and quiet observed scopes are negative diagnostics
only: neither establishes coverage, a coherent capture, native lifetime or a
fresh UI request. A nonzero append return remains an opaque observed scalar.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import struct


FORMAT = 'queue-birth-observation-v1'
HEADER, RECORD = 16, 64
DEFAULT_CAPACITY = 1024
MAX_CAPACITY = (0x100000000 - HEADER) // RECORD
MAGIC = int.from_bytes(b'LQBR', 'little')
FAULT = 0xFFFFFFFF
BIRTH, ENQUEUE_BEGIN, RETURN = 1, 2, 3
FIELDS = ('magic', 'kind', 'parent', 'origin', 'seq', 'engine', 'input',
          'copy', 'metadata', 'frame', 'site', 'result', 'revision', 'scope',
          'reserved0', 'reserved1')
SITES = {BIRTH: 0x8B428C, ENQUEUE_BEGIN: 0x8B42E0, RETURN: 0x8B42F0}
EXPECTED_KINDS = (BIRTH, ENQUEUE_BEGIN, RETURN)
AUTHORITY_FLAGS = ('current_owner_proven', 'contents_current',
                   'coherent_capture', 'autoscroll_authorized',
                   'request_freshness_proven')
LIMITATIONS = (
    'Private birth IDs are not yet transported through the native queue to a child renderer.',
    'Requests are grouped only by immutable private ancestry, never by engine, input, copy, metadata or frame address equality.',
    'An equal known-boundary sample does not prove complete writer coverage, current contents or a fresh UI request.',
    'Observed scope quiet excludes only the sampled known active scopes, not all native writers or owner destruction.',
    'A generic append return is an opaque scalar; even a nonzero value is not queue success, retained ownership or lifetime.',
    'Reservation order across independent births and copied bytes do not establish native execution order or capture coherence.',
    'Empty, partial and capacity-full journals do not establish complete request or enqueue coverage.',
    'These observations cannot authorize autoscroll or be attached to row origins by matching native pointer values.',
)


def memory_bytes(capacity=DEFAULT_CAPACITY):
    if type(capacity) is not int or not 1 <= capacity <= MAX_CAPACITY:
        raise ValueError('queue birth capacity must fit a nonempty unsigned-32 journal')
    return HEADER + RECORD * capacity


def _revision(value, name):
    if type(value) is not int or not 0 <= value <= 0x7FFFFFFF:
        raise ValueError(name + ' must be an integer from 0 through 2147483647')


def _scope_state(value):
    if value & 0x80000000:
        raise ValueError('queue births: faulted or invalid scope sample')
    issued, active = value & 0xFFFF, (value >> 16) & 0x7FFF
    if active > issued:
        raise ValueError('queue births: scope active count exceeds issued tickets')
    return issued, active


def _no_authority(result):
    result.update({field: False for field in AUTHORITY_FLAGS})


def _events(raw, capacity, current_revision):
    counter, *reserved = struct.unpack_from('<4I', raw)
    if any(reserved):
        raise ValueError('queue births: nonzero reserved header')
    if counter == FAULT or counter > capacity:
        raise ValueError('queue births: faulted or invalid allocator')
    events = []
    for index in range(capacity):
        start = HEADER + index * RECORD
        record = raw[start:start + RECORD]
        if index >= counter:
            if any(record):
                raise ValueError('queue births: nonzero unallocated slot')
            continue
        item = dict(zip(FIELDS, struct.unpack('<16I', record)))
        kind = item['kind']
        if item['magic'] != MAGIC:
            raise ValueError('queue births: missing/unpublished allocated slot')
        if kind not in SITES or item['site'] != SITES[kind]:
            raise ValueError('queue births: unknown kind or wrong source site')
        if item['seq'] != index + 1:
            raise ValueError('queue births: noncontiguous sequence')
        if item['reserved0'] or item['reserved1']:
            raise ValueError('queue births: nonzero reserved record words')
        _revision(item['revision'], 'queue birth revision')
        if current_revision is not None and item['revision'] > current_revision:
            raise ValueError('queue births: revision is beyond the known counter')
        issued, _ = _scope_state(item['scope'])
        if kind == BIRTH:
            if item['parent'] or item['origin'] != item['seq']:
                raise ValueError('queue births: invalid birth ancestry')
            if item['copy'] or item['result']:
                raise ValueError('queue births: nonzero unused birth payload')
            for field in ('engine', 'input', 'frame'):
                if not item[field] or item[field] & 3:
                    raise ValueError('queue births: invalid aligned birth ' + field)
        else:
            parent_id = item['parent']
            if not 1 <= parent_id <= len(events):
                raise ValueError('queue births: parent is not an earlier published event')
            parent = events[parent_id - 1]
            expected_parent = BIRTH if kind == ENQUEUE_BEGIN else ENQUEUE_BEGIN
            if parent['kind'] != expected_parent:
                raise ValueError('queue births: wrong parent kind')
            if any(item[field] != parent[field] for field in
                   ('origin', 'engine', 'input', 'metadata', 'frame')):
                raise ValueError('queue births: immutable parent binding mismatch')
            if item['revision'] < parent['revision']:
                raise ValueError('queue births: parent-chain revision regressed')
            if issued < (parent['scope'] & 0xFFFF):
                raise ValueError('queue births: parent-chain scope tickets regressed')
            if kind == ENQUEUE_BEGIN:
                if not item['copy'] or item['copy'] & 3:
                    raise ValueError('queue births: invalid aligned enqueue copy')
                if item['result']:
                    raise ValueError('queue births: nonzero enqueue-begin result')
            elif item['copy'] != parent['copy']:
                raise ValueError('queue births: enqueue copy binding mismatch')
        del item['magic'], item['reserved0'], item['reserved1']
        events.append(item)
    return events, counter


def _request(birth, events, current_revision):
    kinds = tuple(event['kind'] for event in events)
    sequence_complete = kinds == EXPECTED_KINDS
    returns = [event for event in events if event['kind'] == RETURN]
    returned = returns[0] if len(returns) == 1 else None
    reasons = []
    if not sequence_complete:
        reasons.append('enqueue-event-sequence')
    revision_equal = (sequence_complete and
                      all(event['revision'] == birth['revision'] for event in events))
    known_unchanged = (revision_equal and
                       (current_revision is None or current_revision == birth['revision']))
    if not known_unchanged:
        reasons.append('known-boundary-unchanged-not-observed')
    scopes_quiet = (sequence_complete and
                    all((event['scope'] >> 16) == 0 for event in events))
    if not scopes_quiet:
        reasons.append('known-scopes-quiet-not-observed')
    result = dict(birth=birth['seq'], origin=birth['origin'],
                  engine=birth['engine'], input=birth['input'],
                  metadata=birth['metadata'], frame=birth['frame'],
                  event_sequences=[event['seq'] for event in events],
                  event_kinds=list(kinds), birth_revision=birth['revision'],
                  birth_scope_state=birth['scope'],
                  observed_enqueue_sequence_complete=sequence_complete,
                  queue_return_observed=bool(returns),
                  append_return=returned['result'] if returned else None,
                  append_nonzero=(returned['result'] != 0) if returned else None,
                  known_boundary_unchanged=known_unchanged,
                  known_contents_revision=current_revision,
                  born_while_known_scope_active=(birth['scope'] >> 16) != 0,
                  observed_scopes_quiet=scopes_quiet, reasons=reasons)
    _no_authority(result)
    return result


def decode(data, *, capacity=DEFAULT_CAPACITY, current_revision=None):
    """Decode an exact owned LQBR buffer, with no native memory reads.

    Structural corruption and issued but unpublished slots raise ValueError.
    A well-formed missing or duplicated event is retained as an incomplete
    sequence. Cross-request reservation order is not a chronology assertion.
    ``append_nonzero`` compares a single raw return scalar only, not success.
    An optional current counter may narrow known-boundary observations; it
    can never establish coherence or request freshness.
    """
    total = memory_bytes(capacity)
    if current_revision is not None:
        _revision(current_revision, 'current revision')
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise ValueError('snapshot must be an already-owned byte buffer')
    raw = bytes(data)
    if len(raw) != total:
        raise ValueError('snapshot size does not match queue birth format and capacity')
    events, counter = _events(raw, capacity, current_revision)
    grouped = {event['seq']: [] for event in events if event['kind'] == BIRTH}
    for event in events:
        grouped[event['origin']].append(event)
    requests = [_request(event, grouped[event['seq']], current_revision)
                for event in events if event['kind'] == BIRTH]
    result = dict(format=FORMAT, capacity=capacity, counter=counter,
                  capacity_full=counter == capacity,
                  known_contents_revision=current_revision,
                  events=events, requests=requests, limitations=list(LIMITATIONS))
    _no_authority(result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', type=Path, help='local raw private LQBR journal')
    parser.add_argument('--capacity', type=int, default=DEFAULT_CAPACITY)
    parser.add_argument('--current-revision', type=int,
                        help='optional sampled known-contents revision')
    args = parser.parse_args(argv)
    try:
        result = decode(args.snapshot.read_bytes(), capacity=args.capacity,
                        current_revision=args.current_revision)
    except (OSError, ValueError) as error:
        parser.exit(2, str(error) + '\n')
    print(json.dumps(result, ensure_ascii=True, indent=2))


if __name__ == '__main__':
    main()
