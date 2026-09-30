#!/usr/bin/env python3
"""Read-only report of the interrupted MOVE capture and checkpoint footprint.

No device access, firmware mutation or causal crash/OOM assertion. /tmp
residency is documented from the deployment transcript, not measured here.
"""
import argparse
import hashlib
import json
from pathlib import Path

from decode_folderfollow_move_diag import decode, summary


CAPTURES = (
    ('startup', 'move_diag_install_backup_20260930/startup_snapshot.bin',
     'b0c08a2318b28e84b322963d5d6e8baff4abf7d0448b445432202e0574ec9ef8'),
    ('roots', 'move_diag_roots_20260930.bin',
     'dcf7102022af84a43386f7591226cb4843ac53395c0b8b63405e367e231a6fa2'),
    ('slayer_entry', 'move_diag_slayer_entry_20260930.bin',
     '7b771676016310d36eeca0b9a515d6be0e87e9607bdac61a12b9fc2903e73048'),
    ('slayer_next', 'move_diag_slayer_next_20260930.bin',
     '135dbe26c70b5866230f867edf6ed631242a6590217e1e9e76d85e71c8a2dc0b'),
    ('offscreen_recovered', 'move_diag_recovered_20260930.bin',
     'e181b61124075c46c6b9be3cc6ebe6ad2c48d8639014991de4545fd632a63222'),
)


def checked_bytes(path, expected):
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError(f'not the recorded capture: {path}')
    return data


def ns(row):
    seconds, nanos = row['time']
    if not 0 <= nanos < 1_000_000_000:
        raise ValueError('invalid snapshot timestamp')
    return seconds * 1_000_000_000 + nanos


def analyze(root):
    captures = [(stage, checked_bytes(root / name, sha))
                for stage, name, sha in CAPTURES]
    final = captures[-1][1]
    checkpoints = []
    for stage, data in captures:
        result = summary(decode(data))
        if not final.startswith(data):
            raise ValueError(f'{stage}: not a byte prefix of the recovered run')
        if not result['accepted_prefix']:
            raise ValueError(f'{stage}: unsettled or damaged prefix')
        checkpoints.append(dict(stage=stage, bytes=len(data),
                                events=result['events'], counts=result['counts']))
    rows = list(decode(final))
    snapshots = [r for r in rows if r['kind'] == 'snapshot']
    events = [r for r in rows if r['kind'] in ('setter', 'refresh')]
    gaps = [(ns(b) - ns(a), a['tick'], b['tick'])
            for a, b in zip(snapshots, snapshots[1:])]
    if any(delta <= 0 for delta, _, _ in gaps):
        raise ValueError('non-increasing recorded timestamps')
    largest = max(gaps)
    last_event = events[-1]
    associated = next(r for r in snapshots if r['tick'] == last_event['tick'])
    tail = []
    for row in reversed(snapshots):
        if any(row[k] != snapshots[-1][k] for k in
               ('cue_before', 'cue_after', 'scroll_y', 'folder', 'playback',
                'view', 'viewport')):
            break
        tail.append(row)
    logical = sum(len(data) for _, data in captures)
    rounded = sum((len(data) + 4095) // 4096 * 4096 for _, data in captures)
    return {
        'checkpoints': checkpoints,
        'all_checkpoints_are_exact_byte_prefixes': True,
        'final_status': rows[-1],
        'last_snapshot_tick': snapshots[-1]['tick'],
        'last_event': {k: last_event[k] for k in ('seq', 'kind', 'caller', 'tick')},
        'last_event_associated_snapshot_to_end_seconds':
            (ns(snapshots[-1]) - ns(associated)) / 1e9,
        'stationary_tail': {
            'cue_brackets': [snapshots[-1]['cue_before'], snapshots[-1]['cue_after']],
            'scroll_y': snapshots[-1]['scroll_y'],
            'samples': len(tail),
            'duration_seconds': (ns(tail[0]) - ns(tail[-1])) / 1e9,
        },
        'largest_snapshot_gap': {
            'seconds': largest[0] / 1e9,
            'from_tick': largest[1], 'to_tick': largest[2],
        },
        'last_ten_snapshot_intervals_seconds': [x[0] / 1e9 for x in gaps[-10:]],
        'checkpoint_copy_footprint_if_retained': {
            'logical_bytes': logical,
            'logical_mib': logical / 1048576,
            'rounded_bytes_assuming_4k_pages': rounded,
        },
        'limits': [
            'Recorded /tmp was tmpfs; retention/residency and RAM headroom were not measured.',
            'Checkpoint footprint is not measured RSS, MemAvailable or proof of OOM.',
            'Settled exported counters do not prove future I/O or rule out an unexported fault.',
            'No process exit status, prior-boot kernel trace or reset cause was retained.',
            'Snapshot time and event tick association are not event or reboot timestamps.',
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('artifacts', type=Path)
    args = parser.parse_args()
    print(json.dumps(analyze(args.artifacts), ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
