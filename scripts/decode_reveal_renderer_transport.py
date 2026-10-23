#!/usr/bin/env python3
"""Decode explicit callback-to-renderer ancestry, never authorize the UI.

LQRD names a private LQTR CALLBACK ticket, then a private OUTER ticket, and
the actual pre-existing LNRG RENDER root. Numeric addresses only verify those
explicit associations; they never locate a receipt. All inputs are already
owned observations, not a proof of coherent acquisition or native lifetime.
"""

from __future__ import annotations

import struct

import decode_reveal_lineage_rows as lineage_decoder
import decode_reveal_queue_transport as transport
import folderfollow_reveal_lineage_mips as lineage


FORMAT = 'renderer-birth-transport-v1'
HEADER, RECORD = 16, 96
DEFAULT_CAPACITY = 1024
MAX_CAPACITY = (0x100000000 - HEADER) // RECORD
MAGIC = int.from_bytes(b'LQRD', 'little')
FAULT = 0xFFFFFFFF
OUTER, RENDER = 1, 2
FIELDS = ('magic', 'kind', 'parent', 'origin', 'seq', 'transport', 'lineage',
          'engine', 'widget', 'view', 'panel', 'frame', 'upstream',
          'descriptor', 'input', 'controller', 'job', 'revision', 'scope',
          'cache', 'site', 'reserved0', 'reserved1', 'reserved2')
SITES = {OUTER: 0x438248, RENDER: 0x49076C}
AUTHORITY_FLAGS = transport.AUTHORITY_FLAGS
LIMITATIONS = (
    'Only explicit CALLBACK, OUTER and existing RENDER-root ticket IDs associate these journals; addresses are not registry keys.',
    'The existing renderer entry revision is preserved; no new birth stamp or fresh UI cause is invented.',
    'Renderer entry advances the known counter, so literal all-sample equality is deliberately conservative and is not a freshness test.',
    'Missing or duplicate producer RETURN evidence remains incomplete even when renderer ancestry is observed.',
    'Full, synthetic, coalesced, unclassified and unbound routes remain unknown; empty or full journals do not establish coverage.',
    'Numeric cache, controller, view and widget bindings do not retain native objects or establish a UI-owner lease.',
    'Quiet sampled scopes and known-boundary diagnostics do not establish complete writer coverage or coherent capture.',
    'This parser associates an existing root only; it neither joins native rows by pointer nor grants contents-current or autoscroll authority.',
)


def memory_bytes(capacity=DEFAULT_CAPACITY):
    if type(capacity) is not int or not 1 <= capacity <= MAX_CAPACITY:
        raise ValueError('renderer transport capacity must fit a nonempty unsigned-32 journal')
    return HEADER + RECORD * capacity


def _no_authority(result):
    result.update({field: False for field in AUTHORITY_FLAGS})


def _canonical_transport(result, birth_result, current_revision, scope_issued):
    if not isinstance(result, dict) or result.get('format') != transport.FORMAT:
        raise ValueError('renderer transport requires a strictly decoded LQTR result')
    declared_capacity = result.get('capacity')
    transport.memory_bytes(declared_capacity)
    count, events = result.get('counter'), result.get('events')
    if (type(count) is not int or not 0 <= count <= declared_capacity
            or not isinstance(events, list) or len(events) != count):
        raise ValueError('renderer transport: invalid external transport event count')
    capacity = max(1, count)
    raw = bytearray(transport.memory_bytes(capacity))
    struct.pack_into('<I', raw, 0, count)
    fields = tuple(field for field in transport.FIELDS
                   if field not in ('magic', 'reserved0', 'reserved1'))
    for index, event in enumerate(events):
        if not isinstance(event, dict) or set(event) != set(fields):
            raise ValueError('renderer transport: malformed decoded transport event')
        for field in fields:
            transport._unsigned(event[field], 'transport event ' + field)
        values = dict(event, magic=transport.MAGIC, reserved0=0, reserved1=0)
        struct.pack_into('<16I', raw, transport.HEADER + index * transport.RECORD,
                         *(values[field] for field in transport.FIELDS))
    return transport.decode(raw, birth_result, capacity=capacity,
                            current_revision=current_revision, scope_issued=scope_issued)


def _lineage_receipts(result, current_revision):
    """Revalidate canonical receipt fields, not mutable operation summaries.

    The input is the exact prior combined decoder result. The two known
    extensions are validated separately while the old strict receipt parser
    validates all canonical native-lineage fields. No row/window output is
    promoted or rewritten by this narrower receipt-only reconstruction.
    """
    if (not isinstance(result, dict)
            or result.get('format') not in ('lineage-rows-origin-frontier-v1',
                                          'lineage-rows-native-scope-v1',
                                          'lineage-rows-queue-birth-v1',
                                          'lineage-rows-queue-transport-v1')):
        raise ValueError('renderer transport requires a strictly decoded lineage frontier result')
    receipts = result.get('receipts')
    if not isinstance(receipts, list):
        raise ValueError('renderer transport: missing canonical lineage receipts')
    capacity = max(1, len(receipts))
    raw = bytearray(lineage.memory_bytes(capacity))
    struct.pack_into('<I', raw, 0, len(receipts))
    fields = tuple(field for field in lineage_decoder.LINEAGE_FIELDS
                   if field not in ('magic', 'flags', 'reserved0', 'reserved1'))
    extensions = {}
    for index, receipt in enumerate(receipts):
        expected = set(fields) | {'id', 'original_entry_revision'}
        if isinstance(receipt, dict) and receipt.get('kind') == lineage.PRODUCER:
            expected.add('producer_revision')
        if not isinstance(receipt, dict) or set(receipt) != expected:
            raise ValueError('renderer transport: malformed canonical lineage receipt')
        if type(receipt['id']) is not int or receipt['id'] != index + 1:
            raise ValueError('renderer transport: noncontiguous lineage receipt ID')
        for field in fields:
            value = receipt[field]
            if field in ('offset', 'request'):
                if type(value) is not int or not -(1 << 31) <= value < 1 << 31:
                    raise ValueError('renderer transport: invalid signed lineage scalar')
            else:
                transport._unsigned(value, 'lineage receipt ' + field)
        original = receipt['original_entry_revision']
        transport._revision(original, 'original renderer entry revision')
        if current_revision is not None and original > current_revision:
            raise ValueError('renderer transport: original entry revision is beyond the known counter')
        extensions[index + 1] = {'original_entry_revision': original}
        if receipt['kind'] == lineage.PRODUCER:
            producer = receipt['producer_revision']
            transport._revision(producer, 'lineage producer revision')
            if current_revision is not None and producer > current_revision:
                raise ValueError('renderer transport: producer revision is beyond the known counter')
            if original > producer:
                raise ValueError('renderer transport: producer predates its original entry')
            extensions[index + 1]['producer_revision'] = producer
        values = dict(receipt, magic=lineage.MAGIC, flags=0, reserved0=0, reserved1=0)
        struct.pack_into('<16I', raw, lineage.HEADER + index * lineage.RECORD,
                         *(values[field] & 0xFFFFFFFF for field in lineage_decoder.LINEAGE_FIELDS))
    checked = lineage_decoder._receipts(raw, capacity)
    for receipt in checked:
        receipt.update(extensions[receipt['id']])
        root = checked[receipt['origin'] - 1]
        if receipt['original_entry_revision'] != extensions[root['id']]['original_entry_revision']:
            raise ValueError('renderer transport: inherited original entry revision mismatch')
        if root['kind'] == lineage.INITIAL and receipt['original_entry_revision']:
            raise ValueError('renderer transport: entry revision on INITIAL ancestry')
    return checked


def _events(raw, capacity, external, receipts, current_revision, scope_issued):
    counter, *reserved = struct.unpack_from('<4I', raw)
    if any(reserved):
        raise ValueError('renderer transport: nonzero reserved header')
    if counter == FAULT or counter > capacity:
        raise ValueError('renderer transport: faulted or invalid allocator')
    events, observed_roots = [], set()
    for index in range(capacity):
        start = HEADER + index * RECORD
        record = raw[start:start + RECORD]
        if index >= counter:
            if any(record):
                raise ValueError('renderer transport: nonzero unallocated slot')
            continue
        item = dict(zip(FIELDS, struct.unpack('<24I', record)))
        kind = item['kind']
        if item['magic'] != MAGIC:
            raise ValueError('renderer transport: missing/unpublished allocated slot')
        if kind not in SITES or item['site'] != SITES[kind]:
            raise ValueError('renderer transport: unknown kind or wrong source site')
        if item['seq'] != index + 1:
            raise ValueError('renderer transport: noncontiguous sequence')
        if item['reserved0'] or item['reserved1'] or item['reserved2']:
            raise ValueError('renderer transport: nonzero reserved record words')
        transport._revision(item['revision'], 'renderer transport revision')
        if current_revision is not None and item['revision'] > current_revision:
            raise ValueError('renderer transport: revision is beyond the known counter')
        issued, _ = transport._scope_state(item['scope'])
        if scope_issued is not None and issued > scope_issued:
            raise ValueError('renderer transport: scope sample is beyond the final issued counter')
        for field, length in (('engine', 0x54), ('widget', 4), ('controller', 4),
                              ('descriptor', 8), ('input', 20)):
            transport._aligned_extent(item[field], length, field)
        transport._aligned_extent(item['frame'], 0x200 if kind == OUTER else 0x30, 'frame')
        parent_id = item['parent']
        if kind == OUTER:
            if not 1 <= parent_id <= len(external):
                raise ValueError('renderer transport: missing explicit CALLBACK parent')
            parent = external[parent_id - 1]
            if parent['kind'] != transport.CALLBACK:
                raise ValueError('renderer transport: OUTER parent is not CALLBACK')
            if (item['transport'] != parent_id or item['origin'] != parent['origin']
                    or item['engine'] != parent['engine']):
                raise ValueError('renderer transport: immutable CALLBACK binding mismatch')
            if any(item[field] for field in ('lineage', 'view', 'panel', 'job', 'cache')):
                raise ValueError('renderer transport: nonzero unused OUTER payload')
            transport._aligned_extent(item['upstream'], 0xA4, 'callback frame')
            if (item['upstream'] != parent['frame']
                    or item['frame'] + 0x200 != item['upstream']
                    or item['descriptor'] != item['upstream'] + 0x18
                    or item['input'] != item['upstream'] + 0x90):
                raise ValueError('renderer transport: OUTER frame/descriptor binding mismatch')
        else:
            if not 1 <= parent_id <= len(events):
                raise ValueError('renderer transport: parent is not an earlier published OUTER')
            parent = events[parent_id - 1]
            if parent['kind'] != OUTER:
                raise ValueError('renderer transport: RENDER parent is not OUTER')
            for field in ('transport', 'origin', 'engine', 'widget', 'descriptor', 'input', 'controller'):
                if item[field] != parent[field]:
                    raise ValueError('renderer transport: immutable OUTER binding mismatch')
            if item['upstream'] != parent['frame'] or item['frame'] + 0x30 != item['upstream']:
                raise ValueError('renderer transport: RENDER frame binding mismatch')
            for field, length in (('view', 0x38A8), ('panel', 4), ('cache', 4)):
                transport._aligned_extent(item[field], length, field)
            if item['job'] != item['view'] + 0x38A4:
                raise ValueError('renderer transport: native template job binding mismatch')
            root_id = item['lineage']
            if not 1 <= root_id <= len(receipts):
                raise ValueError('renderer transport: missing explicit lineage root')
            if root_id in observed_roots:
                # The native root-capture site dominates this observer once
                # per invocation. A second receipt must not assign the same
                # captured rows to another callback, even if all addresses
                # happen to match after reuse.
                raise ValueError('renderer transport: duplicate observed lineage root')
            root = receipts[root_id - 1]
            if (root['kind'] != lineage.RENDER or root['origin'] != root_id
                    or root['parent'] or root['site'] != 0x490758):
                raise ValueError('renderer transport: lineage ID is not a RENDER root')
            if any(item[field] != root[source] for field, source in
                   (('frame', 'stack'), ('view', 'view'), ('panel', 'panel'), ('job', 'job'))):
                raise ValueError('renderer transport: explicit lineage root binding mismatch')
            entry = root['original_entry_revision']
            if entry > item['revision'] or entry and entry < parent['revision']:
                raise ValueError('renderer transport: impossible original entry revision order')
            observed_roots.add(root_id)
        transport._sample_order(item, parent)
        del item['magic'], item['reserved0'], item['reserved1'], item['reserved2']
        events.append(item)
    return events, counter


def decode(data, transport_result, lineage_result, *, birth_result,
           capacity=DEFAULT_CAPACITY, current_revision=None, scope_issued=None):
    """Decode owned bytes and canonical prior decoder outputs without mutation.

    ``birth_result`` is required because LQTR summaries do not contain its
    external LQBR ancestry. Parent summaries are ignored and reconstructed
    from canonical events/receipts. A valid root association is independent
    of full producer observation, boundary equality and sampled scope quiet.
    """
    total = memory_bytes(capacity)
    if current_revision is not None:
        transport._revision(current_revision, 'current revision')
    if scope_issued is not None and (type(scope_issued) is not int or not 0 <= scope_issued <= 0xFFFF):
        raise ValueError('final issued scope counter must be an integer from 0 through 65535')
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise ValueError('snapshot must be an already-owned byte buffer')
    raw = bytes(data)
    if len(raw) != total:
        raise ValueError('snapshot size does not match renderer transport format and capacity')
    known = []
    for parent in (birth_result, transport_result, lineage_result):
        if isinstance(parent, dict) and parent.get('known_contents_revision') is not None:
            value = parent['known_contents_revision']
            transport._revision(value, 'parent known contents revision')
            known.append(value)
    if current_revision is None and known:
        current_revision = max(known)
    if current_revision is not None and any(value > current_revision for value in known):
        raise ValueError('renderer transport: final counter precedes a parent counter sample')
    checked_birth, current_revision = transport._birth_history(birth_result, current_revision, scope_issued)
    checked_transport = _canonical_transport(transport_result, birth_result, current_revision, scope_issued)
    receipts = _lineage_receipts(lineage_result, current_revision)
    events, counter = _events(raw, capacity, checked_transport['events'], receipts,
                              current_revision, scope_issued)
    callbacks = {item['callback']: item for item in checked_transport['chains']}
    associations, outers = [], []
    for event in events:
        if event['kind'] == OUTER:
            item = dict(outer=event['seq'], birth=event['origin'], callback=event['transport'],
                        renderer_ids=[], lineage_roots=[], renderer_root_associated=False,
                        observation_complete=False)
            _no_authority(item)
            outers.append(item)
            continue
        outer = events[event['parent'] - 1]
        root = receipts[event['lineage'] - 1]
        chain = callbacks[event['transport']]
        birth = checked_birth['events'][event['origin'] - 1]
        complete = chain['observation_complete']
        entry = root['original_entry_revision']
        # Do not exempt the renderer's own bump or replace any old rejection.
        unchanged = (complete and entry > 0
                     and chain['known_boundary_unchanged']
                     and outer['revision'] == event['revision'] == entry == birth['revision']
                     and (current_revision is None or current_revision == birth['revision']))
        quiet = (complete and chain['observed_scopes_quiet']
                 and outer['scope'] >> 16 == 0 and event['scope'] >> 16 == 0)
        reasons = list(chain['reasons'])
        for valid, reason in ((unchanged, 'known-boundary-unchanged-not-observed'),
                              (quiet, 'known-scopes-quiet-not-observed')):
            if not valid and reason not in reasons:
                reasons.append(reason)
        item = dict(birth=event['origin'], callback=event['transport'],
                    outer=outer['seq'], renderer=event['seq'], lineage=event['lineage'],
                    lineage_root=event['lineage'],
                    transport=event['transport'], engine=event['engine'], widget=event['widget'],
                    view=event['view'], panel=event['panel'], job=event['job'],
                    cache=event['cache'], frame=event['frame'],
                    event_sequences=[outer['seq'], event['seq']],
                    transport_event_sequences=list(chain['event_sequences']),
                    birth_event_sequences=list(chain['birth_event_sequences']),
                    producer_return_sequences=list(chain['producer_return_sequences']),
                    producer_return_observed=chain['producer_return_observed'],
                    unique_producer_return_observed=chain['unique_producer_return_observed'],
                    append_return_matches_node=chain['append_return_matches_node'],
                    observed_enqueue_sequence_complete=chain['observed_enqueue_sequence_complete'],
                    observed_birth_to_renderer_chain=True, renderer_root_associated=True,
                    observation_complete=complete,
                    birth_revision=birth['revision'], outer_revision=outer['revision'],
                    renderer_revision=event['revision'], original_entry_revision=entry,
                    known_contents_revision=current_revision,
                    known_boundary_unchanged=unchanged, observed_scopes_quiet=quiet,
                    reasons=reasons)
        _no_authority(item)
        associations.append(item)
    for item in outers:
        related = [assoc for assoc in associations if assoc['outer'] == item['outer']]
        item.update(renderer_ids=[assoc['renderer'] for assoc in related],
                    lineage_roots=[assoc['lineage_root'] for assoc in related],
                    renderer_root_associated=bool(related),
                    observation_complete=bool(related) and all(assoc['observation_complete'] for assoc in related))
    result = dict(format=FORMAT, capacity=capacity, counter=counter,
                  capacity_full=counter == capacity, events=events, outers=outers,
                  associations=associations, renderer_root_associated=bool(associations),
                  observation_complete=bool(outers) and all(item['observation_complete'] for item in outers),
                  known_contents_revision=current_revision, known_scope_issued=scope_issued,
                  limitations=list(LIMITATIONS))
    _no_authority(result)
    return result
