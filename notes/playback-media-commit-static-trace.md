# Static trace of the playback media-item commit

Addresses refer to firmware 1.4 `hiby_player` SHA-256 `0fedb30f...`.

## Result

Ordinary Next/autoplay does not update property 24 through the public setter
at `0x42AB20`.  The playback worker has two direct copies into the global
`0xA88`-byte current-media record at `0xADD468`:

| Commit site | Path | Meaning |
| --- | --- | --- |
| `0x42CBD4` / copy at `0x42CBDC` | synchronous fast path in `0x42CAC0` | Same-backing-file/cue-compatible item switch. |
| `0x42CD54` / copy at `0x42CD5C` | asynchronous event-9 path in `0x42CC60` | General item commit before decoder/source setup. |

The general `0x42CD54` site is the primary passive diagnostic hook for
cross-file and cross-folder Next/autoplay.  The `0x42CBD4` site must also be
observed if cue transitions are to be covered.

## Why the public property setter was a false boundary

There are 69 direct `jal 0x42AB20` calls.  A complete local argument audit
resolves every call's property number, including three values inherited from
branch delay slots.  Only three calls set property 24:

- `0x4B55E8`: list selection;
- `0x531170`: clear/reset;
- `0x533C68`: record-operation selection.

No file-backed function pointer equals `0x42AB20`, and there is no direct call
to its internal property-24 branch `0x42AC00`.  Automatic transitions instead
use the two direct copies above.  The global-address audit found all relevant
constructions of `0xADD468`, including the setter, getter/callback paths,
clear path, and these two playback commits.

## Physical Next and autoplay converge

The stock Now Playing button tables identify:

```text
playing_plane_iv_next_song callbacks at 0xAA73F4...
  click callback 0x4EB640 -> enqueue event 2, parameter 0x00010002

playing_plane_iv_prev_song callbacks at 0xAA7454...
  click callback 0x4EB440 -> enqueue event 1, parameter 0x00010002
```

The decoder/player callback `0x42B2C0` dispatches event `0x501` to
`0x42B418`.  That completion path also enqueues worker event 2, with parameter
`0x00020001`.  Physical Next and natural end-of-track autoplay therefore enter
the same event-2 selection machinery while preserving different reason bits.

The forward chain is:

```text
physical Next 0x4EB640             decoder completion 0x501
        |                                  |
        +---------- enqueue event 2 -------+
                           |
                    worker case 2 at 0x42E600
                           |
                    forward selector 0x42A420
                           |
                 folder traversal 0x4E3620 as needed
                           |
                    selected item -> 0x42CAC0
```

## The two commit paths

### General cross-file path: `0x42CD54`

For a normal new item, `0x42CAC0` calls `0x42B180`.  That helper stages the
item through `0x428B40` and tail-enqueues event 9.  Worker case 9 begins at
`0x42E3A8`, retrieves the staged `0xA88`-byte item into `sp+0x18`, and calls:

```text
0x42E424  a0 = music-player context at global+0xBA4
0x42E428  a1 = staged item at sp+0x18
0x42E42C  jal 0x42CC60
0x42E430  a2 = transition/reuse value
```

`0x42CC60` performs initial bookkeeping and then commits the item before the
large decoder/open dispatch:

```text
0x42CD54  a0 = 0xADD468
0x42CD58  a1 = staged item
0x42CD5C  memcpy(a0, a1, 0xA88)
0x42CD64  load playback queue
0x42CD6C  flush/reset that queue through 0x450720
```

At `0x42CD54`, property 24 and its UTF-16 path at `0xADD46C` become current,
but `source+0x28/+0x230` can still describe the preceding decoder source.  The
only normal source-field writer remains `0x42BBE0`; it is not called directly
by `0x42CC60`, so the general path reaches that lifecycle boundary later than
the media-item commit.

### Same-backing-file fast path: `0x42CBD4`

`0x42CAC0` first compares item path/state against the active backing-file
state.  When the compatibility checks succeed, it avoids the asynchronous
open path and commits synchronously:

```text
0x42CBD4  a0 = 0xADD468
0x42CBD8  a1 = selected item
0x42CBDC  memcpy(a0, a1, 0xA88)
0x42CBF4  call 0x42CA00
0x42CA18  call 0x42BDE0
0x42BDE8  call source finalizer 0x42BBE0
```

This ordering is consistent with cue rows that change media identity and
absolute backing-file position without reopening the same audio image.

## Diagnostic consequence

A safe timing diagnostic should wrap only the two original `memcpy` calls. It
must not invoke Folder View helpers, `0x4E4B80`, property setters, or source
finalization.  For each site it should append a fixed record containing:

- commit-site identifier and caller return address;
- selected item ID and bounded UTF-16 item path (`item+0x4`);
- global property-24 ID/path before and after the original copy;
- direct snapshots of `source+0x28` and scalar `source+0x230`;
- inactive Folder View identity/path for correlation only.

The expected cross-folder ordering is: old global/source state before
`0x42CD5C`, new property-24 path immediately after it, and source path/position
catching up later.  That result would establish `0x42CD54` as the safe place
to stage a future folder-follow target without mutating the explorer stack.

## Source-finalizer timing boundary

The source finalizer has only three direct call sites: `0x42BC98` in wrapper
`0x42BC80`, `0x42BDE8` in the same-file wrapper, and `0x42DEB0` in the
clear/shutdown path.  Neither `0x42BC80`, `0x42BDE0`, nor `0x42BBE0` appears as
an aligned file-backed function pointer.  The second call to `0x42BC80`, at
`0x475670`, is part of an initialization/retry loop rather than a per-track
callback.  Static direct-call analysis therefore cannot assign an exact
instruction inside the general `0x42CC60` path at which the source fields
catch up.  The commit diagnostic must treat them as independent snapshots;
observing their later convergence is part of the test, not a precondition of
the hook.
