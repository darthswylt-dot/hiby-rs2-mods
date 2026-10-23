#!/usr/bin/env python3
"""Decode an already-owned callback-transport snapshot; no row/UI authority."""
import argparse
import json
from pathlib import Path

import decode_reveal_queue_birth_stage as previous
import decode_reveal_queue_transport as transport
import folderfollow_reveal_lineage_mips as lineage
import reveal_lineage_rows_mips as rows
import reveal_operation_journal_mips as operation
import reveal_native_scope_mips as scope
import reveal_queue_birth_mips as birth
import reveal_queue_transport_mips as core


FORMAT = 'lineage-rows-queue-transport-v1'


def decode(data, *, capacity=1024, row_capacity=1024, operation_capacity=1024,
           scope_capacity=1024, birth_capacity=1024, transport_capacity=1024):
    prefix = (lineage.memory_bytes(capacity) + rows.memory_bytes(row_capacity) + 16
              + operation.memory_bytes(operation_capacity) + scope.memory_bytes(scope_capacity)
              + birth.memory_bytes(birth_capacity))
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise ValueError('snapshot must be an already-owned byte buffer')
    raw = bytes(data)
    if len(raw) != prefix + core.memory_bytes(transport_capacity):
        raise ValueError('snapshot size does not match queue-transport format and capacities')
    result = previous.decode(raw[:prefix], capacity=capacity, row_capacity=row_capacity,
                             operation_capacity=operation_capacity, scope_capacity=scope_capacity,
                             birth_capacity=birth_capacity)
    observed = transport.decode(
        raw[prefix:], result['queue_birth_observation'], capacity=transport_capacity,
        current_revision=result['known_contents_revision'], scope_issued=result['native_scope']['issued'])
    result['limitations'] = [item for item in result['limitations']
                            if not item.startswith('Birth receipts have not been transported')]
    result['limitations'].append(
        'Explicit birth identity reaches only inspected native callback entries. No association to renderer/rows or native live-borrow lease is established; generic nodes require 20 bytes.')
    result.update(format=FORMAT, queue_transport_observation=observed,
                  birth_identity_transported=True, birth_transport_target='439EC0-entry-only',
                  renderer_identity_associated=False, request_freshness_proven=False,
                  current_owner_proven=False, contents_current=False,
                  coherent_capture=False, autoscroll_authorized=False)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', type=Path)
    names = ('capacity', 'row-capacity', 'operation-capacity', 'scope-capacity', 'birth-capacity', 'transport-capacity')
    for name in names:
        parser.add_argument('--' + name, type=int, default=1024)
    args = parser.parse_args(argv)
    try:
        result = decode(args.snapshot.read_bytes(), **{name.replace('-', '_'): getattr(args, name.replace('-', '_')) for name in names})
    except (OSError, ValueError) as error:
        parser.exit(2, str(error) + '\n')
    print(json.dumps(result, ensure_ascii=True, indent=2))


if __name__ == '__main__':
    main()
