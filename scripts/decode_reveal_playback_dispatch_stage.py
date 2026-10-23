#!/usr/bin/env python3
"""Decode independent playback CALL_INTENT and renderer journals; never join them.

LPDI has no transported notification/paint foreign key. Neither equal target,
context, frame, descriptor nor coincident per-journal numbers create one.
The previous request-age annotation and all prior refusals remain intact.
"""
import argparse
import json
from pathlib import Path

import decode_reveal_request_age as previous
import decode_reveal_playback_dispatch as dispatch
import decode_reveal_renderer_transport_stage as renderer_stage
import folderfollow_reveal_lineage_mips as lineage
import reveal_lineage_rows_mips as rows
import reveal_operation_journal_mips as operation
import reveal_native_scope_mips as scope
import reveal_queue_birth_mips as birth
import reveal_queue_transport_mips as transport
import reveal_renderer_transport_mips as renderer


FORMAT = 'lineage-rows-renderer-playback-dispatch-v1'
CAPACITY_NAMES = (*renderer_stage.CAPACITY_NAMES, 'playback-dispatch-capacity')


def decode(data, *, capacity=1024, row_capacity=1024, operation_capacity=1024,
           scope_capacity=1024, birth_capacity=1024, transport_capacity=1024,
           renderer_capacity=1024, playback_dispatch_capacity=1024):
    prefix = (lineage.memory_bytes(capacity) + rows.memory_bytes(row_capacity) + 16
              + operation.memory_bytes(operation_capacity) + scope.memory_bytes(scope_capacity)
              + birth.memory_bytes(birth_capacity) + transport.memory_bytes(transport_capacity)
              + renderer.memory_bytes(renderer_capacity))
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise ValueError('snapshot must be an already-owned byte buffer')
    raw = bytes(data)
    if len(raw) != prefix + dispatch.memory_bytes(playback_dispatch_capacity):
        raise ValueError('snapshot size does not match playback-dispatch stage and capacities')
    result = previous.decode(raw[:prefix], capacity=capacity, row_capacity=row_capacity,
        operation_capacity=operation_capacity, scope_capacity=scope_capacity,
        birth_capacity=birth_capacity, transport_capacity=transport_capacity,
        renderer_capacity=renderer_capacity)
    observed = dispatch.decode(raw[prefix:], capacity=playback_dispatch_capacity)
    result.update(format=FORMAT, playback_dispatch_observation=observed,
                  playback_paint_cause_associated=False, callback_completion_proven=False,
                  playback_identity_proven=False, complete_playback_coverage=False)
    result['limitations'].append(
        'LPDI records only an intent to dispatch an optional playback callback, independently of paint journals. No transported playback/notification parent joins them; equal addresses or local IDs cannot repair that missing cause.')
    # Historical renderer/row associations may remain true; they confer no
    # playback cause, currentness, callback completion or UI authority.
    result.update({flag: False for flag in dispatch.AUTHORITY_FLAGS})
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
