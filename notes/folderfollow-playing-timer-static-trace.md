# Live playing-plane timer and Folder View selection state

Addresses refer to firmware 1.4 `hiby_player` SHA-256 `0fedb30f...`.

## Stock mismatch path

The Now Playing constructor registers `0x4E90C0` at `0x4EAEBC-0x4EAED4` as a
100 ms callback with the `playing_plane` object as its context. Unlike the
inactive `0x4E24C0` main-category callback, the global playing-plane pointer at
`0xB8BACC` remained non-null during the reproduced stale Folder View state.

At `0x4E9160-0x4E9198`, the callback:

1. obtains the current explorer view through `0x4E5680`;
2. compares `(current_view+0xCC)->+0x4` with
   `(playing_plane+0x2C)->+0x4`;
3. when they differ, dispatches event 5 with value 0 to
   `current_view+0x78` through `0x4C0620`.

The jump table for `0x4C0620` is at `0x9489A4`. Entry 5 targets `0x4C06DC`,
which stores the supplied value directly into the internal view object at
`+0x5A4`. It does not rebuild or retarget the explorer stack.

Other stock callers establish the opposite transition. `0x492A54`,
`0x499F8C`, and `0x49A100` dispatch event 5 with value 1 while setting up or
activating a media list. Several mismatch/removal paths dispatch value 0.
Therefore `+0x5A4` participates in current-item/selection matching, but static
code alone does not prove that it is the visual highlighted-row value.

## Passive diagnostic candidate

`scripts/build_folderfollow_playing_timer_diag.py` redirects only the callback
pointer construction at `0x4EAEBC/0x4EAECC` to an RX-padding wrapper. The
wrapper always calls original `0x4E90C0` first and then records a compact
`0x100`-byte snapshot to inherited FD 9:

- callback context and global playing-plane pointer;
- playing-item and current-view media identity values;
- explorer/current-view/internal-list pointers;
- internal fields `+0x5A4/+0x5A8/+0x5AC/+0x5B0`;
- stable playback/source globals and original return value.

It calls only the proven read-only current-view getter after the original
callback. It performs no path lookup, view creation, stack destruction,
retargeting, or navigation-state write. The fixed 256-byte record at 10 Hz
limits telemetry to about 2.5 KiB/s.

## Hardware result: live owner, no cross-folder state transition

The 2026-09-14 Roots -> Slayer run completed without a process exit, reboot,
UI corruption, or input loss. The wrapper logged continuously from boot, which
hardware-confirms that `0x4E90C0` remains scheduled while Folder View is open.
Its context exactly matched global `0xB8BACC`, and the explorer, current view,
and internal-list pointers remained stable through the target transition.

During initial Roots playback/UI setup, internal field `+0x5A4` changed from 1
to 0. Returning to the highlighted Roots Folder View later restored it to 1.
However, physical Next from Roots to `Slayer - Evil Has No Boundaries` produced
no further sampled state change: `+0x5A4` remained 1 even though the user
confirmed that the Roots item was no longer highlighted and volume input still
worked. A direct live read after the transition found `+0x5A0=3` and
`+0x5A4=1`.

This refines the interpretation: `+0x5A0` is the list row/index used throughout
the renderer, while `+0x5A4` enables the current-item/selection-matching path.
The highlight disappears naturally because no row in the stale Roots list
matches the new playback item; it is not caused by a `+0x5A4: 1 -> 0` write at
the folder crossing. Event 5 is therefore not a folder-follow command.

Completed snapshot log:

```text
rs2_playing_timer_diag_complete_roots_evil.bin
size:    489472 bytes (1912 records)
SHA-256: 41904b62da9cd6d2f20340e4dea0545daf1a880e4fd7d957124ef6ee04685cb9
```

The important positive result is ownership: unlike `0x4E24C0`, `0x4E90C0` is
a hardware-confirmed recurring UI context available after both general and
same-file playback commits. A future functional candidate may consume a
staged path change here, but must still identify a safe stock method to update
the existing Folder View.
