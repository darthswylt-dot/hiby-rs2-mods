#!/usr/bin/env python3
"""Strict SCRL decoder; snapshots are not atomic and indices are not selection."""
import argparse
import json
import struct
from pathlib import Path
from build_folderfollow_scroll_diag import SIZE, FIELDS, STRINGS


def decode(data):
    if len(data) % SIZE:
        raise ValueError('truncated record tail')
    for offset in range(0, len(data), SIZE):
        raw = data[offset:offset + SIZE]
        if raw[:4] != b'SCRL' or struct.unpack_from('<II', raw, 4) != (1, SIZE):
            raise ValueError(f'invalid header at {offset:#x}')
        row = {name: struct.unpack_from('<I', raw, pos)[0] for name, pos in FIELDS.items()}
        for name in ('scroll_y', 'height', 'content_height', 'cue_before', 'cue_after', 'sort', 'working_index'):
            if row[name] & 0x80000000:
                row[name] -= 1 << 32
        for name, (pos, size, encoding) in STRINGS.items():
            row[name] = raw[pos:pos + size].decode(encoding, errors='replace').split('\0', 1)[0]
        row['cue_changed_during_copy'] = row['cue_before'] != row['cue_after']
        row['time'] = struct.unpack_from('<II', raw, 0x10)
        yield row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log', type=Path)
    parser.add_argument('--all', action='store_true', help='include unchanged snapshots')
    args = parser.parse_args()
    previous = None
    for row in decode(args.log.read_bytes()):
        state = {key: value for key, value in row.items() if key != 'time'}
        if args.all or state != previous:
            print(json.dumps(row, ensure_ascii=False))
        previous = state


if __name__ == '__main__':
    main()
