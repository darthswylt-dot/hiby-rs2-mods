#!/usr/bin/env python3
"""Decode owned renderer bindings and link rows only by explicit lineage IDs.

Prior receipts/windows/operations and all their refusals remain unchanged.
These are historical cause associations, never current rows or UI authority.
"""
import argparse
import json
from pathlib import Path

import decode_reveal_queue_transport_stage as previous
import decode_reveal_renderer_transport as renderer
import folderfollow_reveal_lineage_mips as lineage
import reveal_lineage_rows_mips as rows
import reveal_operation_journal_mips as operation
import reveal_native_scope_mips as scope
import reveal_queue_birth_mips as birth
import reveal_queue_transport_mips as transport
import reveal_renderer_transport_mips as core


FORMAT = 'lineage-rows-renderer-transport-v1'
CAPACITY_NAMES = ('capacity', 'row-capacity', 'operation-capacity', 'scope-capacity',
                  'birth-capacity', 'transport-capacity', 'renderer-capacity')


def decode(data, *, capacity=1024, row_capacity=1024, operation_capacity=1024,
           scope_capacity=1024, birth_capacity=1024, transport_capacity=1024, renderer_capacity=1024):
    prefix = (lineage.memory_bytes(capacity) + rows.memory_bytes(row_capacity) + 16
              + operation.memory_bytes(operation_capacity) + scope.memory_bytes(scope_capacity)
              + birth.memory_bytes(birth_capacity) + transport.memory_bytes(transport_capacity))
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise ValueError('snapshot must be an already-owned byte buffer')
    raw = bytes(data)
    if len(raw) != prefix + core.memory_bytes(renderer_capacity):
        raise ValueError('snapshot size does not match renderer-transport format and capacities')
    result = previous.decode(raw[:prefix], capacity=capacity, row_capacity=row_capacity,
                             operation_capacity=operation_capacity, scope_capacity=scope_capacity,
                             birth_capacity=birth_capacity, transport_capacity=transport_capacity)
    observed = renderer.decode(
        raw[prefix:], result['queue_transport_observation'], result,
        birth_result=result['queue_birth_observation'], capacity=renderer_capacity,
        current_revision=result['known_contents_revision'], scope_issued=result['native_scope']['issued'])
    associations = []
    for association in observed['associations']:
        # The foreign key is the exact published LNRG root ID captured by the
        # new native renderer observer. No V/P/job/frame/name/address lookup.
        root = association['lineage']
        item = dict(
            renderer=association['renderer'], lineage=root, birth=association['birth'],
            callback=association['callback'], outer=association['outer'],
            renderer_root_associated=association['renderer_root_associated'],
            observation_complete=association['observation_complete'],
            producers=[receipt['id'] for receipt in result['receipts']
                       if receipt['kind'] == lineage.PRODUCER and receipt['origin'] == root],
            row_event_sequences=[event['seq'] for event in result['events']
                                 if event['kind'] == rows.ROW and event['origin'] == root],
            window_indices=[index for index, window in enumerate(result['windows'])
                            if window['origin'] == root],
            operation_borrows=[item['borrow'] for item in result['operations'] if item['origin'] == root],
            request_freshness_proven=False, current_owner_proven=False, contents_current=False,
            coherent_capture=False, autoscroll_authorized=False)
        item['observed_row_identity_associated'] = bool(item['row_event_sequences'])
        associations.append(item)
    result['limitations'] = [item for item in result['limitations']
                            if not item.startswith('Explicit birth identity reaches only inspected native callback entries.')]
    result['limitations'].append(
        'An explicit queued-birth chain is associated with captured renderer roots/rows only by immutable lineage IDs. This is historical cause evidence, not an original playback/UI cause, current owner, native lease, coherent capture or UI permission.')
    result.update(format=FORMAT, renderer_transport_observation=observed,
                  renderer_row_associations=associations,
                  birth_transport_target='existing-native-renderer-lineage-root',
                  renderer_identity_transport_enabled=True, renderer_identity_associated=bool(associations),
                  request_freshness_proven=False, current_owner_proven=False, contents_current=False,
                  coherent_capture=False, autoscroll_authorized=False)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', type=Path)
    for name in CAPACITY_NAMES:
        parser.add_argument('--' + name, type=int, default=1024)
    args = parser.parse_args(argv)
    try:
        result = decode(args.snapshot.read_bytes(), **{
            name.replace('-', '_'): getattr(args, name.replace('-', '_')) for name in CAPACITY_NAMES})
    except (OSError, ValueError) as error:
        parser.exit(2, str(error) + '\n')
    print(json.dumps(result, ensure_ascii=True, indent=2))


if __name__ == '__main__':
    main()
