#!/usr/bin/env python3
"""Join historical notification and renderer observations by explicit BIRTH IDs.

All previous renderer, row, request-age and independent LPDI evidence and
refusals remain unchanged. A notification-to-BIRTH receipt may stand without
a renderer. Neither association proves current playback, payload coherence,
native lifetime, complete notification coverage, or UI authority.
"""

import argparse
import json
from pathlib import Path

import decode_reveal_action_link as action_link
import decode_reveal_playback_dispatch as dispatch
import decode_reveal_playback_dispatch_stage as previous
import folderfollow_reveal_lineage_mips as lineage
import reveal_lineage_rows_mips as rows
import reveal_operation_journal_mips as operation
import reveal_native_scope_mips as scope
import reveal_queue_birth_mips as birth
import reveal_queue_transport_mips as transport
import reveal_renderer_transport_mips as renderer


FORMAT = 'lineage-rows-action-birth-link-v1'
CAPACITY_NAMES = (*previous.CAPACITY_NAMES, 'action-link-capacity')


def decode(data, *, capacity=1024, row_capacity=1024, operation_capacity=1024,
           scope_capacity=1024, birth_capacity=1024, transport_capacity=1024,
           renderer_capacity=1024, playback_dispatch_capacity=1024,
           action_link_capacity=1024):
    birth_offset = (lineage.memory_bytes(capacity) + rows.memory_bytes(row_capacity) + 16
                    + operation.memory_bytes(operation_capacity) + scope.memory_bytes(scope_capacity))
    birth_end = birth_offset + birth.memory_bytes(birth_capacity)
    prefix = (birth_end + transport.memory_bytes(transport_capacity)
              + renderer.memory_bytes(renderer_capacity)
              + dispatch.memory_bytes(playback_dispatch_capacity))
    total = prefix + action_link.memory_bytes(action_link_capacity)
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise ValueError('snapshot must be an already-owned byte buffer')
    raw = bytes(data)
    if len(raw) != total:
        raise ValueError('snapshot size does not match action-link stage and capacities')
    result = previous.decode(raw[:prefix], capacity=capacity, row_capacity=row_capacity,
        operation_capacity=operation_capacity, scope_capacity=scope_capacity,
        birth_capacity=birth_capacity, transport_capacity=transport_capacity,
        renderer_capacity=renderer_capacity,
        playback_dispatch_capacity=playback_dispatch_capacity)
    observed = action_link.decode(raw[prefix:], capacity=action_link_capacity,
                                  birth_data=raw[birth_offset:birth_end],
                                  birth_capacity=birth_capacity)
    notification_births, notification_renderers = [], []
    renderers_by_birth, rows_by_renderer = {}, {}
    for rendered in result['renderer_transport_observation']['associations']:
        renderers_by_birth.setdefault(rendered['birth'], []).append(rendered)
    for row_association in result['renderer_row_associations']:
        key = (row_association['birth'], row_association['renderer'], row_association['lineage'])
        rows_by_renderer.setdefault(key, []).append(row_association)
    for association in observed['associations']:
        item = dict(association, historical_notification_birth_associated=True)
        notification_births.append(item)
        for rendered in renderers_by_birth.get(association['birth'], ()):
            # The foreign key is the actual validated private LQBR BIRTH ID.
            # Numeric native fields, reservation adjacency and LPDI IDs are
            # deliberately absent from this parent selection.
            key = (rendered['birth'], rendered['renderer'], rendered['lineage'])
            for row_association in rows_by_renderer.get(key, ()):
                linked = dict(item, callback=rendered['callback'], outer=rendered['outer'],
                    renderer=rendered['renderer'], lineage=rendered['lineage'],
                    renderer_root_associated=rendered['renderer_root_associated'],
                    historical_notification_renderer_associated=True,
                    renderer_observation_complete=rendered['observation_complete'],
                    renderer_reasons=list(rendered['reasons']),
                    renderer_event_sequences=list(rendered['event_sequences']),
                    transport_event_sequences=list(rendered['transport_event_sequences']),
                    birth_event_sequences=list(rendered['birth_event_sequences']),
                    producers=list(row_association['producers']),
                    row_event_sequences=list(row_association['row_event_sequences']),
                    window_indices=list(row_association['window_indices']),
                    operation_borrows=list(row_association['operation_borrows']),
                    observed_row_identity_associated=row_association['observed_row_identity_associated'])
                # All false authority/lifetime/coherence fields from the
                # independently strict action association are retained.
                notification_renderers.append(linked)
    result.update(format=FORMAT, action_link_observation=observed,
                  notification_birth_associations=notification_births,
                  notification_renderer_associations=notification_renderers,
                  historical_notification_birth_associated=bool(notification_births),
                  historical_notification_renderer_associated=bool(notification_renderers))
    result['limitations'].append(
        'A historical general action1 notification reaches an actual queued BIRTH and captured renderer/row ancestry only through explicit private IDs. The native paint-list borrow is not retained across later use; this adds no payload coherence, playback identity, currentness, complete coverage or UI authority. Independent LPDI CALL_INTENT observations remain unjoined.')
    result.update({flag: False for flag in action_link.AUTHORITY_FLAGS})
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', type=Path)
    for name in CAPACITY_NAMES:
        parser.add_argument('--' + name, type=int, default=1024)
    args = parser.parse_args(argv)
    try:
        result = decode(args.snapshot.read_bytes(), **{
            name.replace('-', '_'): getattr(args, name.replace('-', '_'))
            for name in CAPACITY_NAMES})
    except (OSError, ValueError) as error:
        parser.exit(2, str(error) + '\n')
    print(json.dumps(result, ensure_ascii=True, indent=2))


if __name__ == '__main__':
    main()
