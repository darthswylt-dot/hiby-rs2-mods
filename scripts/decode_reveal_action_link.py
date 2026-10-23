#!/usr/bin/env python3
"""Decode explicit historical action-to-BIRTH IDs without granting UI authority.

Both inputs must be already-owned exact raw journals. Native addresses only
check scalar bindings of explicit private IDs; they never select a parent.
The paint-list borrow ends before later native use, so an observed ancestry
does not prove a retained record, coherent payload, or current playback.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import struct

import decode_reveal_queue_birth as birth_decoder


FORMAT = 'action-birth-link-v1'
HEADER, RECORD = 16, 96
DEFAULT_CAPACITY = 1024
MAX_CAPACITY = (0x100000000 - HEADER) // RECORD
MAGIC = int.from_bytes(b'LALI', 'little')
FAULT = 0xFFFFFFFF
SOURCE, DELIVERY, EXPLORER, PAINT, PAINT_DELIVERY, BIRTH_LINK = range(1, 7)
FIELDS = ('magic', 'kind', 'parent', 'origin', 'seq', 'worker', 'queue',
          'record', 'source_frame', 'frame', 'site', 'caller', 'action',
          'param1', 'param2', 'resource', 'node', 'controller', 'engine',
          'input', 'metadata', 'birth', 'reserved0', 'reserved1')
SITES = {SOURCE: 0x4BACBC, DELIVERY: 0x4BA96C, EXPLORER: 0x4909A4,
         PAINT: 0x43C868, PAINT_DELIVERY: 0x4399E8, BIRTH_LINK: 0x8B428C}
CALLERS = {SOURCE: (0x42D61C,), DELIVERY: (0,), EXPLORER: (0x4BAA68,),
           PAINT: (0x490A10, 0x490A60), PAINT_DELIVERY: (0x43C918,),
           BIRTH_LINK: (0x45987C,)}
AUTHORITY_FLAGS = birth_decoder.AUTHORITY_FLAGS
LIMITATIONS = (
    'Only explicit nonreused private IDs link SOURCE, DELIVERY, EXPLORER, PAINT, PAINT_DELIVERY and the actual LQBR BIRTH.',
    'Addresses verify inherited scalars only; address reuse, equal counters, current controller and LPDI dispatch intent never select a parent.',
    'The native paint-list getter releases its bracket before subsequent native payload use. Four rectangle words are loaded separately after BIRTH, so a historical link can coexist with changed or torn geometry. Later removal targets current index zero, not the selected receipt. A known purge path uses a different controller mutex, so the paint bracket alone is not established as universal exclusion; this ancestry establishes neither a record lease, coherent payload nor selected-entry removal ownership.',
    'The observed general action1 source is not a coherent media identity, a proof of playback success, or universal Next/autoplay coverage.',
    'Missing, unclassified, coalesced, removed, exhausted and failed paths remain unknown; no journal occupancy establishes complete coverage.',
    'Historical source-to-BIRTH observation does not establish freshness, current contents, current UI ownership or autoscroll authority.',
)


def memory_bytes(capacity=DEFAULT_CAPACITY):
    if type(capacity) is not int or not 1 <= capacity <= MAX_CAPACITY:
        raise ValueError('action link capacity must fit a nonempty unsigned-32 journal')
    return HEADER + RECORD * capacity


def _no_authority(result):
    result.update({field: False for field in AUTHORITY_FLAGS})
    result.update(native_record_lease_proven=False,
                  native_payload_coherence_proven=False,
                  source_playback_identity_proven=False,
                  universal_playback_coverage_proven=False,
                  decision='deny')


def _aligned(value, extent, field):
    if not value or value & 3 or value + extent > 0x100000000:
        raise ValueError('action link: invalid aligned ' + field)


def _equal(item, parent, fields, description):
    if any(item[field] != parent[field] for field in fields):
        raise ValueError('action link: immutable ' + description + ' binding mismatch')


def _zero(item, fields, description):
    if any(item[field] for field in fields):
        raise ValueError('action link: nonzero unused ' + description + ' payload')


def _events(raw, capacity, births):
    counter, *reserved = struct.unpack_from('<4I', raw)
    if any(reserved):
        raise ValueError('action link: nonzero reserved header')
    if counter == FAULT or counter > capacity:
        raise ValueError('action link: faulted or invalid allocator')
    events, linked_births = [], set()
    common = ('worker', 'source_frame', 'action', 'param1', 'param2')
    for index in range(capacity):
        record = raw[HEADER + index * RECORD:HEADER + (index + 1) * RECORD]
        if index >= counter:
            if any(record):
                raise ValueError('action link: nonzero unallocated slot')
            continue
        item = dict(zip(FIELDS, struct.unpack('<24I', record)))
        kind = item['kind']
        if item['magic'] != MAGIC:
            raise ValueError('action link: missing/unpublished allocated slot')
        if kind not in SITES or item['site'] != SITES[kind]:
            raise ValueError('action link: unknown kind or wrong source site')
        if item['caller'] not in CALLERS[kind]:
            raise ValueError('action link: wrong original caller')
        if item['seq'] != index + 1:
            raise ValueError('action link: noncontiguous sequence')
        if item['reserved0'] or item['reserved1']:
            raise ValueError('action link: nonzero reserved record words')
        for field in ('worker', 'source_frame', 'frame', 'record'):
            _aligned(item[field], 4, field)
        if kind == SOURCE:
            if item['parent'] or item['origin'] != item['seq']:
                raise ValueError('action link: invalid SOURCE ancestry')
            _aligned(item['queue'], 4, 'source queue')
            _aligned(item['frame'], 0x40, 'source frame')
            if (item['frame'] != item['source_frame']
                    or item['record'] != item['frame'] + 0x18
                    or item['action'] != 1 or item['param2']):
                raise ValueError('action link: invalid general action1 source binding')
            _zero(item, ('resource', 'node', 'controller', 'engine', 'input',
                         'metadata', 'birth'), 'SOURCE')
        else:
            parent_id = item['parent']
            if not 1 <= parent_id <= len(events):
                raise ValueError('action link: parent is not an earlier published event')
            parent = events[parent_id - 1]
            if parent['kind'] != kind - 1:
                raise ValueError('action link: wrong parent kind')
            _equal(item, parent, ('origin',) + common, 'source')
            if kind == DELIVERY:
                _equal(item, parent, ('queue',), 'SOURCE queue')
                _zero(item, ('resource', 'node', 'controller', 'engine', 'input',
                             'metadata', 'birth'), 'DELIVERY')
            elif kind == EXPLORER:
                _equal(item, parent, ('queue', 'record'), 'DELIVERY')
                _aligned(item['frame'], 0x40, 'explorer frame')
                if item['frame'] + 0x40 != parent['frame']:
                    raise ValueError('action link: EXPLORER frame binding mismatch')
                for field in ('resource', 'node'):
                    _aligned(item[field], 4, field)
                _zero(item, ('controller', 'engine', 'input', 'metadata', 'birth'),
                      'EXPLORER')
            elif kind == PAINT:
                _equal(item, parent, ('resource', 'node'), 'EXPLORER')
                _aligned(item['frame'], 0x68, 'paint frame and caller rectangle')
                _aligned(item['controller'], 4, 'paint controller')
                if (item['frame'] + 0x40 != parent['frame']
                        or item['record'] != item['frame'] + 0x18
                        or item['engine'] != item['node']
                        or item['input'] != item['frame'] + 0x58):
                    raise ValueError('action link: PAINT frame/engine/input binding mismatch')
                _zero(item, ('queue', 'metadata', 'birth'), 'PAINT')
            elif kind == PAINT_DELIVERY:
                _equal(item, parent, ('resource', 'node', 'controller', 'engine',
                                      'metadata'), 'PAINT')
                _aligned(item['record'], 0x24, 'paint queue record')
                if item['input'] != item['record'] + 0xC:
                    raise ValueError('action link: PAINT_DELIVERY input binding mismatch')
                _zero(item, ('queue', 'birth'), 'PAINT_DELIVERY')
            else:
                _equal(item, parent, ('queue', 'record', 'resource', 'node',
                                      'controller', 'engine', 'input', 'metadata'),
                       'PAINT_DELIVERY')
                _aligned(item['frame'], 0x68, 'BIRTH frame ancestry')
                if item['frame'] + 0x68 != parent['frame']:
                    raise ValueError('action link: BIRTH_LINK frame binding mismatch')
                birth_id = item['birth']
                if not 1 <= birth_id <= len(births):
                    raise ValueError('action link: missing explicit LQBR BIRTH')
                if birth_id in linked_births:
                    raise ValueError('action link: duplicate observed LQBR BIRTH')
                birth = births[birth_id - 1]
                if (birth['kind'] != birth_decoder.BIRTH or birth['parent']
                        or birth['origin'] != birth_id):
                    raise ValueError('action link: external ID is not an LQBR BIRTH')
                _equal(item, birth, ('engine', 'input', 'metadata', 'frame'),
                       'LQBR BIRTH')
                linked_births.add(birth_id)
        del item['magic'], item['reserved0'], item['reserved1']
        events.append(item)
    return events, counter, linked_births


def decode(data, *, birth_data, capacity=DEFAULT_CAPACITY,
           birth_capacity=birth_decoder.DEFAULT_CAPACITY):
    """Strictly decode two exact owned byte buffers, without native reads.

    Public input deliberately excludes mutable predecoded dictionaries. An
    actual BIRTH ID must validate against the independent raw LQBR journal.
    Partial valid ancestry is retained as incomplete historical observation.
    """
    total = memory_bytes(capacity)
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise ValueError('snapshot must be an already-owned byte buffer')
    raw = bytes(data)
    if len(raw) != total:
        raise ValueError('snapshot size does not match action link format and capacity')
    birth_result = birth_decoder.decode(birth_data, capacity=birth_capacity)
    events, counter, linked_births = _events(raw, capacity, birth_result['events'])
    associations = []
    for event in events:
        if event['kind'] != BIRTH_LINK:
            continue
        chain, cursor = [], event
        while cursor['parent']:
            chain.append(cursor)
            cursor = events[cursor['parent'] - 1]
        chain.append(cursor)
        chain.reverse()
        item = dict(source=chain[0]['seq'], delivery=chain[1]['seq'],
                    explorer=chain[2]['seq'], paint=chain[3]['seq'],
                    paint_delivery=chain[4]['seq'], birth_link=event['seq'],
                    birth=event['birth'], event_sequences=[part['seq'] for part in chain],
                    observed_source_to_birth_chain=True,
                    historical_source_to_birth_associated=True)
        _no_authority(item)
        associations.append(item)
    associated_sources = {item['source'] for item in associations}
    result = dict(format=FORMAT, capacity=capacity, counter=counter,
                  capacity_full=counter == capacity, events=events,
                  associations=associations,
                  unassociated_sources=[event['seq'] for event in events
                                        if event['kind'] == SOURCE
                                        and event['seq'] not in associated_sources],
                  unassociated_births=[event['seq'] for event in birth_result['events']
                                       if event['kind'] == birth_decoder.BIRTH
                                       and event['seq'] not in linked_births],
                  complete_coverage_proven=False, limitations=list(LIMITATIONS))
    _no_authority(result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', type=Path, help='local raw private action-link journal')
    parser.add_argument('birth_snapshot', type=Path, help='local raw private LQBR journal')
    parser.add_argument('--capacity', type=int, default=DEFAULT_CAPACITY)
    parser.add_argument('--birth-capacity', type=int, default=birth_decoder.DEFAULT_CAPACITY)
    args = parser.parse_args(argv)
    try:
        result = decode(args.snapshot.read_bytes(), birth_data=args.birth_snapshot.read_bytes(),
                        capacity=args.capacity, birth_capacity=args.birth_capacity)
    except (OSError, ValueError) as error:
        parser.exit(2, str(error) + '\n')
    print(json.dumps(result, ensure_ascii=True, indent=2))


if __name__ == '__main__':
    main()
