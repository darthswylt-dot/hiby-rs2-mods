#!/usr/bin/env python3
"""Read-only reanalysis of the two closed captures; never joins their timelines.

Stable sampled addresses are not object-generation/lifetime proof. FILL row
order is evidence for its own run only, not a live map for SCRL or a player.
"""
import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

from decode_folderfollow_scroll_diag import decode as decode_scroll
from decode_folderfollow_fill_diag import decode as decode_fill, sessions


SCROLL_SHA = 'e125d243d67dd4e3409aad9b8c572bb9b25625aebeec1c136899b3e42eda1423'
FILL_SHA = '7cd4a63322fc2c32d141572a7725d6c00a44b0b506972d00537deb6d257ff0fe'


def checked_bytes(path, expected):
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError(f'not the closed reference capture: {path}')
    return data


def ns(row):
    sec, nano = row['time']
    if not 0 <= nano < 1_000_000_000:
        raise ValueError('invalid timestamp')
    return sec * 1_000_000_000 + nano


def diagnose(scroll_path, fill_path):
    rows = list(decode_scroll(checked_bytes(scroll_path, SCROLL_SHA)))
    assert len(rows) == 2868
    assert all(ns(a) < ns(b) for a,b in zip(rows, rows[1:]))
    selected = [(i,r) for i,r in enumerate(rows) if r['explorer_valid']
                and '1987 USA Discovery Systems' in r['folder']
                and 'Slayer - Show No Mercy' in r['playback']]
    assert selected and not any(r['cue_changed_during_copy'] for _,r in selected)
    keys = ('controller', 'view', 'viewport', 'cache_owner', 'folder', 'playback',
            'pitch', 'height', 'cache_capacity', 'cache_start', 'cache_count')
    states = {tuple(r[k] for k in keys) for _,r in selected}
    assert len(states) == 1
    cue5 = [(i,r) for i,r in selected if r['cue_before'] == 5]
    first_moved = next(j for j,(_,r) in enumerate(cue5) if r['scroll_y'] != 0)
    stationary = cue5[:first_moved]
    assert stationary and all(r['scroll_y'] == 0 for _,r in stationary)
    # This particular interval has no filtered-out intervening records.
    assert [i for i,_ in stationary] == list(range(stationary[0][0],stationary[-1][0]+1))
    duration = (ns(stationary[-1][1])-ns(stationary[0][1]))/1e9
    assert duration > 25
    offsets = sorted({r['scroll_y'] for _,r in cue5})
    fill_records = list(decode_fill(checked_bytes(fill_path, FILL_SHA)))
    fills = list(sessions(fill_records))
    assert len(fills) == 10 and all(s['accepted_snapshot'] for s in fills)
    assert fill_records[-1]['kind'] == 'status'
    assert fill_records[-1]['reserved'] == fill_records[-1]['drained'] == 65
    slayer = next(s for s in fills if '1987 USA Discovery Systems' in s['folder'])
    sleep = next(s for s in fills if 'Sleep - 1998 - Jerusalem' in s['folder'])
    return {
        'scroll_records': len(rows), 'slayer_samples': len(selected),
        'slayer_cue_sample_counts': dict(sorted(Counter(r['cue_before'] for _,r in selected).items())),
        'sampled_identity_and_geometry_variants': len(states),
        'pitch_height': [selected[0][1]['pitch'], selected[0][1]['height']],
        'cue5_contiguous_zero_y_records': [stationary[0][0], stationary[-1][0]],
        'cue5_zero_y_sampled_duration_seconds': duration,
        'cue5_observed_y_values': offsets,
        'fill_accepted_sessions': len(fills),
        'fill_slayer_index_cue': [[m['index'],m['cue']] for m in slayer['mapping']],
        'fill_sleep_index_cue': [[m['index'],m['cue']] for m in sleep['mapping']],
        'limits': ['captures are separate runs; no shared timeline or pointer identity',
                   'stable addresses/counts do not prove generation or lifetime',
                   'matching cue brackets do not prove atomic path/view samples',
                   'neither capture records setter calls, mode flags or refresh dispatch'],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('scroll', type=Path)
    parser.add_argument('fill', type=Path)
    args = parser.parse_args()
    print(json.dumps(diagnose(args.scroll,args.fill), indent=2))


if __name__ == '__main__':
    main()
