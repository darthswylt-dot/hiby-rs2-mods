#!/usr/bin/env python3
"""Decode private playback CALL_INTENT observations without granting authority.

An LPDI record freezes raw register scalars immediately before one inspected
native BA0 JALR. It does not observe arrival at the target, callback return,
playback completion/publication or a retained descriptor identity. In
particular, a target address is neither a registration certificate nor an
immutable parent for a later UI request. This parser performs no native reads
and never joins records by target, context, frame, player or descriptor values.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import struct


FORMAT = 'playback-dispatch-observation-v1'
HEADER, RECORD = 16, 64
DEFAULT_CAPACITY = 1024
MAX_CAPACITY = (0x100000000 - HEADER) // RECORD
MAGIC = int.from_bytes(b'LPDI', 'little')
FAULT = 0xFFFFFFFF
FAST, GENERAL = 1, 2
PLAYER, DESCRIPTOR = 0xADD368, 0xADD468
FIELDS = ('magic', 'kind', 'parent', 'origin', 'seq', 'frame', 'site',
          'return_pc', 'target', 'context', 'descriptor', 'player',
          'reserved0', 'reserved1', 'reserved2', 'reserved3')
SITES = {FAST: 0x42CC0C, GENERAL: 0x42D6A0}
AUTHORITY_FLAGS = ('current_owner_proven', 'contents_current',
                   'coherent_capture', 'autoscroll_authorized',
                   'request_freshness_proven')
OBSERVATION_FLAGS = ('callback_entry_observed', 'callback_completion_proven',
                     'playback_completion_proven', 'playback_publication_proven',
                     'owned_identity_proven', 'ba0_binding_proven',
                     'birth_parent_associated', 'complete_coverage')
LIMITATIONS = (
    'Each record is CALL_INTENT only, before the original native JALR; target entry, callback return and successful execution are not observed.',
    'Target and context are raw register scalars, not callable-address validation, a coherent BA0 registration binding or a native lifetime lease.',
    'The fixed descriptor address identifies no immutable owned media, coherent identity capture or completed playback publication.',
    'Private origin IDs identify only their own call-intent records; they are not playback invocation IDs or causal parents of queue BIRTH/UI requests.',
    'Records are never associated by equality of target, frame, context, player or descriptor addresses, or by a later current clock/publication.',
    'Reservation sequence does not prove callback completion order, and empty, partial or capacity-full journals never prove complete coverage.',
    'No revision/scope clock, native memory, current host publication or predecoded summary is accepted as evidence by this decoder.',
    'These observations cannot establish freshness, current contents, coherent capture or authorize autoscroll.',
)


def memory_bytes(capacity=DEFAULT_CAPACITY):
    if type(capacity) is not int or not 1 <= capacity <= MAX_CAPACITY:
        raise ValueError('playback dispatch capacity must fit a nonempty unsigned-32 journal')
    return HEADER + RECORD * capacity


def _deny(result):
    result['decision'] = 'deny'
    result.update({field: False for field in (*AUTHORITY_FLAGS, *OBSERVATION_FLAGS)})


def decode(data, *, capacity=DEFAULT_CAPACITY):
    """Decode one exact already-owned LPDI byte buffer, without native reads.

    Structural faults, reserved data, gaps and unpublished reservations are
    refused. A nonzero target is deliberately retained as an arbitrary raw
    uint32, including unaligned values; context may also be zero or unaligned.
    Neither value is dereferenced or treated as a causal/ownership identity.
    """
    total = memory_bytes(capacity)
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise ValueError('snapshot must be an already-owned byte buffer')
    raw = bytes(data)
    if len(raw) != total:
        raise ValueError('snapshot size does not match playback dispatch format and capacity')
    counter, *reserved = struct.unpack_from('<4I', raw)
    if any(reserved):
        raise ValueError('playback dispatch: nonzero reserved header')
    if counter == FAULT or counter > capacity:
        raise ValueError('playback dispatch: faulted or invalid allocator')
    events = []
    for index in range(capacity):
        start = HEADER + index * RECORD
        record = raw[start:start + RECORD]
        if index >= counter:
            if any(record):
                raise ValueError('playback dispatch: nonzero unallocated slot')
            continue
        item = dict(zip(FIELDS, struct.unpack('<16I', record)))
        if item['magic'] != MAGIC:
            raise ValueError('playback dispatch: missing/unpublished allocated slot')
        kind = item['kind']
        if kind not in SITES or item['site'] != SITES[kind]:
            raise ValueError('playback dispatch: unknown kind or wrong source site')
        if item['return_pc'] != SITES[kind] + 8:
            raise ValueError('playback dispatch: wrong original native return PC')
        if item['seq'] != index + 1:
            raise ValueError('playback dispatch: noncontiguous sequence')
        if item['parent'] or item['origin'] != item['seq']:
            raise ValueError('playback dispatch: invalid private self origin')
        if not item['frame'] or item['frame'] & 3:
            raise ValueError('playback dispatch: invalid aligned frame')
        if not item['target']:
            raise ValueError('playback dispatch: zero call-intent target')
        if item['player'] != PLAYER or item['descriptor'] != DESCRIPTOR:
            raise ValueError('playback dispatch: wrong fixed player or descriptor scalar')
        if any(item['reserved' + str(number)] for number in range(4)):
            raise ValueError('playback dispatch: nonzero reserved record words')
        del item['magic']
        for number in range(4):
            del item['reserved' + str(number)]
        item['observation'] = 'CALL_INTENT-only'
        _deny(item)
        events.append(item)
    result = dict(format=FORMAT, capacity=capacity, counter=counter,
                  capacity_full=counter == capacity,
                  observed_call_intents=len(events),
                  observation='CALL_INTENT-only', events=events,
                  limitations=list(LIMITATIONS))
    _deny(result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', type=Path, help='local raw private LPDI journal')
    parser.add_argument('--capacity', type=int, default=DEFAULT_CAPACITY)
    args = parser.parse_args(argv)
    try:
        result = decode(args.snapshot.read_bytes(), capacity=args.capacity)
    except (OSError, ValueError) as error:
        parser.exit(2, str(error) + '\n')
    print(json.dumps(result, ensure_ascii=True, indent=2))


if __name__ == '__main__':
    main()
