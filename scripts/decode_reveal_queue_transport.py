#!/usr/bin/env python3
"""Decode owned queue receipts, never infer native lifetime or UI authority.

LQTR ancestry names an already-published LQBR ENQUEUE_BEGIN receipt and then
only prior LQTR records. Native addresses are numeric bindings, not join keys.
The generic append RETURN can be observed after a consumer callback: counters
from separate journals are not a shared clock. No rows/renderer association,
native memory read, request freshness or active scrolling is authorized here.
"""

from __future__ import annotations

import struct

import decode_reveal_queue_birth as birth


FORMAT = 'queue-birth-transport-v1'
HEADER, RECORD = 16, 64
DEFAULT_CAPACITY = 1024
MAX_CAPACITY = (0x100000000 - HEADER) // RECORD
MAGIC = int.from_bytes(b'LQTR', 'little')
FAULT = 0xFFFFFFFF
INSTALL, BORROW, HELPER, CALLBACK = 1, 2, 3, 4
FIELDS = ('magic', 'kind', 'parent', 'origin', 'seq', 'engine', 'node',
          'copy', 'metadata', 'frame', 'site', 'upstream', 'revision',
          'scope', 'reserved0', 'reserved1')
SITES = {INSTALL: 0x8B3CE8, BORROW: 0x8B4754,
         HELPER: 0x8B3FA0, CALLBACK: 0x439EC0}
AUTHORITY_FLAGS = birth.AUTHORITY_FLAGS
LIMITATIONS = (
    'Explicit immutable receipt ancestry is the only join; native pointer values are never registry keys.',
    'The allocation/type and exact-callsite premises are pinned source contracts, not arbitrary native-pointer provenance.',
    'A producer RETURN can follow a callback; reservation order across these two journals is not native chronology.',
    'Missing or duplicated producer events cannot be repaired by a complete consumer ancestry chain.',
    'Equal known-boundary samples and quiet known scopes do not prove writer coverage, native lifetime or a fresh UI request.',
    'Node address reuse and numeric bindings do not establish a retained native queue/view owner lease.',
    'Full, synthetic, coalesced and unclassified paths remain unadmitted; empty or capacity-full journals do not prove coverage.',
    'There is no row/renderer association, coherent capture, contents-current proof or autoscroll authority.',
)


def memory_bytes(capacity=DEFAULT_CAPACITY):
    if type(capacity) is not int or not 1 <= capacity <= MAX_CAPACITY:
        raise ValueError('queue transport capacity must fit a nonempty unsigned-32 journal')
    return HEADER + RECORD * capacity


def _unsigned(value, label):
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        raise ValueError(label + ' must be an unsigned-32 integer')


def _revision(value, label):
    if type(value) is not int or not 0 <= value <= 0x7FFFFFFF:
        raise ValueError(label + ' must be an integer from 0 through 2147483647')


def _scope_state(value):
    _unsigned(value, 'queue transport scope sample')
    if value & 0x80000000:
        raise ValueError('queue transport: faulted or invalid scope sample')
    issued, active = value & 0xFFFF, value >> 16
    if active > issued:
        raise ValueError('queue transport: scope active count exceeds issued tickets')
    return issued, active


def _no_authority(result):
    result.update({field: False for field in AUTHORITY_FLAGS})


def _aligned_extent(value, length, label):
    if not value or value & 3 or value + length > 0x100000000:
        raise ValueError('queue transport: invalid aligned/nonwrapping ' + label)


def _sample_order(child, parent):
    if child['revision'] < parent['revision']:
        raise ValueError('queue transport: parent-chain revision regressed')
    if (child['scope'] & 0xFFFF) < (parent['scope'] & 0xFFFF):
        raise ValueError('queue transport: parent-chain scope tickets regressed')


def _birth_history(result, current_revision, scope_issued):
    """Recheck event evidence; mutable/forged request summaries are ignored.

    The public input is an already strictly decoded LQBR result. Rebuilding
    its allocated records through the old parser also rejects accidental
    mutations before this second parser uses them. Only allocated slots are
    reconstructed, avoiding allocation according to an untrusted capacity.
    This does not authenticate a dump or establish coherent acquisition.
    """
    if not isinstance(result, dict) or result.get('format') != birth.FORMAT:
        raise ValueError('queue transport requires a strictly decoded LQBR result')
    declared_capacity = result.get('capacity')
    birth.memory_bytes(declared_capacity)
    count, events = result.get('counter'), result.get('events')
    if (type(count) is not int or not 0 <= count <= declared_capacity
            or not isinstance(events, list) or len(events) != count):
        raise ValueError('queue transport: invalid birth event count')
    inherited_revision = result.get('known_contents_revision')
    if inherited_revision is not None:
        _revision(inherited_revision, 'birth known contents revision')
    if current_revision is None:
        current_revision = inherited_revision
    elif inherited_revision is not None and current_revision < inherited_revision:
        raise ValueError('queue transport: final counter precedes the birth counter sample')
    owned_capacity = max(1, count)
    raw = bytearray(birth.memory_bytes(owned_capacity))
    struct.pack_into('<I', raw, 0, count)
    event_fields = tuple(field for field in birth.FIELDS
                         if field not in ('magic', 'reserved0', 'reserved1'))
    for index, event in enumerate(events):
        if not isinstance(event, dict) or set(event) != set(event_fields):
            raise ValueError('queue transport: malformed decoded birth event')
        for field in event_fields:
            _unsigned(event[field], 'birth event ' + field)
        values = dict(event, magic=birth.MAGIC, reserved0=0, reserved1=0)
        struct.pack_into('<16I', raw, birth.HEADER + index * birth.RECORD,
                         *(values[field] for field in birth.FIELDS))
    checked = birth.decode(raw, capacity=owned_capacity,
                           current_revision=current_revision)
    if scope_issued is not None:
        for event in checked['events']:
            if (event['scope'] & 0xFFFF) > scope_issued:
                raise ValueError('queue transport: birth scope sample is beyond the final issued counter')
    return checked, current_revision


def _events(raw, capacity, births, current_revision, scope_issued):
    counter, *reserved = struct.unpack_from('<4I', raw)
    if any(reserved):
        raise ValueError('queue transport: nonzero reserved header')
    if counter == FAULT or counter > capacity:
        raise ValueError('queue transport: faulted or invalid allocator')
    events = []
    for index in range(capacity):
        start = HEADER + index * RECORD
        record = raw[start:start + RECORD]
        if index >= counter:
            if any(record):
                raise ValueError('queue transport: nonzero unallocated slot')
            continue
        item = dict(zip(FIELDS, struct.unpack('<16I', record)))
        kind = item['kind']
        if item['magic'] != MAGIC:
            raise ValueError('queue transport: missing/unpublished allocated slot')
        if kind not in SITES or item['site'] != SITES[kind]:
            raise ValueError('queue transport: unknown kind or wrong source site')
        if item['seq'] != index + 1:
            raise ValueError('queue transport: noncontiguous sequence')
        if item['reserved0'] or item['reserved1']:
            raise ValueError('queue transport: nonzero reserved record words')
        _revision(item['revision'], 'queue transport revision')
        if current_revision is not None and item['revision'] > current_revision:
            raise ValueError('queue transport: revision is beyond the known counter')
        issued, _ = _scope_state(item['scope'])
        if scope_issued is not None and issued > scope_issued:
            raise ValueError('queue transport: scope sample is beyond the final issued counter')
        for field, extent in (('engine', 0x54), ('node', 20), ('copy', 16)):
            _aligned_extent(item[field], extent, field)
        _aligned_extent(item['frame'], {INSTALL: 0x28, BORROW: 0xC0,
                                        HELPER: 0xB8, CALLBACK: 0x38}[kind], 'frame')
        parent_id = item['parent']
        if kind == INSTALL:
            if not 1 <= parent_id <= len(births):
                raise ValueError('queue transport: missing explicit birth-journal parent')
            parent = births[parent_id - 1]
            if parent['kind'] != birth.ENQUEUE_BEGIN:
                raise ValueError('queue transport: install parent is not ENQUEUE_BEGIN')
            for field in ('origin', 'engine', 'copy', 'metadata'):
                if item[field] != parent[field]:
                    raise ValueError('queue transport: immutable enqueue binding mismatch')
            _aligned_extent(item['upstream'], 0x40, 'enqueue frame')
            if (item['upstream'] != parent['frame']
                    or item['frame'] + 0x28 != item['upstream']):
                raise ValueError('queue transport: install frame binding mismatch')
        else:
            if not 1 <= parent_id <= len(events):
                raise ValueError('queue transport: parent is not an earlier published event')
            parent = events[parent_id - 1]
            if parent['kind'] != kind - 1:
                raise ValueError('queue transport: wrong parent kind')
            for field in ('origin', 'engine', 'node', 'copy', 'metadata'):
                if item[field] != parent[field]:
                    raise ValueError('queue transport: immutable parent binding mismatch')
            if kind == BORROW:
                if item['upstream']:
                    raise ValueError('queue transport: nonzero borrow upstream')
            elif (item['upstream'] != parent['frame']
                  or item['frame'] + {HELPER: 0xB8, CALLBACK: 0x38}[kind]
                  != parent['frame']):
                raise ValueError('queue transport: child frame binding mismatch')
        _sample_order(item, parent)
        del item['magic'], item['reserved0'], item['reserved1']
        events.append(item)
    return events, counter


def _summary(install, route, births, birth_requests, returns, current_revision):
    enqueue = births[install['parent'] - 1]
    root = births[enqueue['origin'] - 1]
    producer = birth_requests[root['seq']]
    producer_returns = returns.get(enqueue['seq'], [])
    unique_return = producer_returns[0] if len(producer_returns) == 1 else None
    for returned in producer_returns:
        # INSTALL precedes this particular native append's return. Consumer
        # records have no corresponding order constraint against RETURN.
        _sample_order(returned, install)
    sequence_complete = producer['observed_enqueue_sequence_complete']
    return_matches = bool(unique_return and unique_return['result'] == install['node'])
    callback = route[-1] if route and route[-1]['kind'] == CALLBACK else None
    has_chain = callback is not None
    complete = has_chain and sequence_complete and return_matches
    observed = [root, enqueue, install, *route]
    if unique_return is not None:
        observed.append(unique_return)
    known_unchanged = (complete and all(event['revision'] == root['revision']
                                      for event in observed)
                       and (current_revision is None or current_revision == root['revision']))
    scopes_quiet = complete and all((event['scope'] >> 16) == 0 for event in observed)
    reasons = []
    if not has_chain:
        reasons.append('birth-to-callback-chain-not-observed')
    if not sequence_complete:
        reasons.append('enqueue-event-sequence')
    if not producer_returns:
        reasons.append('producer-return-not-observed')
    elif unique_return is None:
        reasons.append('producer-return-not-unique')
    elif not return_matches:
        reasons.append('append-return-node-mismatch')
    if not known_unchanged:
        reasons.append('known-boundary-unchanged-not-observed')
    if not scopes_quiet:
        reasons.append('known-scopes-quiet-not-observed')
    result = dict(
        install=install['seq'], enqueue=enqueue['seq'], birth=root['seq'],
        origin=root['seq'], engine=install['engine'], node=install['node'],
        copy=install['copy'], metadata=install['metadata'],
        borrow=route[0]['seq'] if route else None,
        helper=route[1]['seq'] if len(route) > 1 else None,
        callback=callback['seq'] if callback else None,
        event_sequences=[install['seq'], *(event['seq'] for event in route)],
        birth_event_sequences=list(producer['event_sequences']),
        producer_return_sequences=[event['seq'] for event in producer_returns],
        producer_return_observed=bool(producer_returns),
        unique_producer_return_observed=unique_return is not None,
        append_return=unique_return['result'] if unique_return else None,
        append_return_matches_node=return_matches,
        observed_enqueue_sequence_complete=sequence_complete,
        observed_birth_to_callback_chain=has_chain,
        observation_complete=complete,
        birth_revision=root['revision'], birth_scope_state=root['scope'],
        known_contents_revision=current_revision,
        known_boundary_unchanged=known_unchanged,
        observed_scopes_quiet=scopes_quiet, reasons=reasons)
    _no_authority(result)
    return result


def decode(data, birth_result, *, capacity=DEFAULT_CAPACITY,
           current_revision=None, scope_issued=None):
    """Decode exact owned LQTR bytes plus an already-decoded LQBR result.

    Missing/duplicate producer events remain incomplete observations. A
    malformed published ancestry or impossible parent sample order raises
    ValueError. ``current_revision`` narrows historical equality only; by
    default the birth parser's known counter is inherited. ``scope_issued``
    is an optional final known-scope ticket bound, not an owner guarantee.
    Both inputs are treated as owned observations, not coherent live state.
    """
    total = memory_bytes(capacity)
    if current_revision is not None:
        _revision(current_revision, 'current revision')
    if scope_issued is not None and (type(scope_issued) is not int
                                     or not 0 <= scope_issued <= 0xFFFF):
        raise ValueError('final issued scope counter must be an integer from 0 through 65535')
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise ValueError('snapshot must be an already-owned byte buffer')
    raw = bytes(data)
    if len(raw) != total:
        raise ValueError('snapshot size does not match queue transport format and capacity')
    checked_birth, current_revision = _birth_history(birth_result, current_revision, scope_issued)
    births = checked_birth['events']
    events, counter = _events(raw, capacity, births, current_revision, scope_issued)
    requests = {item['birth']: item for item in checked_birth['requests']}
    returns = {}
    for event in births:
        if event['kind'] == birth.RETURN:
            returns.setdefault(event['parent'], []).append(event)
    chains, installs = [], []
    for event in events:
        if event['kind'] == INSTALL:
            installs.append(_summary(event, [], births, requests, returns, current_revision))
        elif event['kind'] == CALLBACK:
            helper = events[event['parent'] - 1]
            borrow = events[helper['parent'] - 1]
            install = events[borrow['parent'] - 1]
            chains.append(_summary(install, [borrow, helper, event], births,
                                   requests, returns, current_revision))
    for install in installs:
        related = [chain for chain in chains if chain['install'] == install['install']]
        install['callbacks'] = [chain['callback'] for chain in related]
        if related:
            install['observed_birth_to_callback_chain'] = True
            install['observation_complete'] = all(chain['observation_complete'] for chain in related)
            install['known_boundary_unchanged'] = all(chain['known_boundary_unchanged'] for chain in related)
            install['observed_scopes_quiet'] = all(chain['observed_scopes_quiet'] for chain in related)
            install['reasons'] = list(dict.fromkeys(reason for chain in related for reason in chain['reasons']))
    result = dict(format=FORMAT, capacity=capacity, counter=counter,
                  capacity_full=counter == capacity, events=events,
                  installs=installs, chains=chains,
                  observed_birth_to_callback_chain=bool(chains),
                  observation_complete=bool(installs) and all(item['observation_complete'] for item in installs),
                  known_contents_revision=current_revision, known_scope_issued=scope_issued,
                  limitations=list(LIMITATIONS))
    _no_authority(result)
    return result
