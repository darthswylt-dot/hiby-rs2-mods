# Property-11 Folder View rebuild test

Prepared and run: 2026-09-15. Hardware status: **safe, partially successful,
not a complete folder-follow fix**.

## Purpose

This is the first functional candidate based on the complete stock storage-open
transaction rather than the failed raw destroy/build or equal-depth retarget
paths. The proven live `0x4E90C0` timer runs its original callback first and
then considers one Folder View rebuild.

The wrapper proceeds only when all of these conditions hold:

- the validated timer owner and its explorer/controller pointer are non-null;
- the current view is exactly the last `vg_listview_explorer` view;
- committed property 24 contains a non-empty full playback path;
- that path's derived parent `\\*` differs from the current Folder View path;
- property 11 does not already contain the same derived target as a retained
  failure marker.

For a stale view it writes the unchanged full property-24 file path to property
11 through stock setter `0x424F60`. It constructs only the matching drive root
(`a:\\*`, `b:\\*`, or `c:\\*`) as fallback and calls `0x495D40`. Stock
`0x495B80` consumes property 11 and rebuilds every explorer level through
`0x491E80`; `0x495D40` clears property 11 afterwards.

After the call, the wrapper resolves the new explorer pointer instead of
dereferencing the destroyed old view. If the resulting path still differs, it
stores the derived target in property 11 as a failure marker. That limits a
failed target to one attempt instead of repeating the destructive transaction
every 100 ms. A different playing folder naturally permits one new attempt.

## Artifact

```text
artifacts/hiby_player_1.4_sortfix_fullnav_wake_folderfollow_saved_path_rebuild_test
SHA-256 4c43e0a4853f94f9b0577b8fffd1d2ca9ae97dca1dc3d1f033c006565e7fddd6
size    7,133,528 bytes
```

The builder accepts either golden `c825a72e...` or recovered `02fd1dd...` and
normalizes the latter exactly to golden first. Relative to golden, it changes
only the timer callback construction at file offsets `0x0EAEBC/0x0EAECC` and
a `0x224`-byte wrapper at executable cave `0x988040`. The verifier reproduced
the exact output, counted 378 changed bytes and audited 27 control transfers.

Build and verify:

```powershell
python .\scripts\build_folderfollow_saved_path_rebuild.py `
  E:\platform-tools\hiby_player_02fd.bin `
  .\artifacts\hiby_player_1.4_sortfix_fullnav_wake_folderfollow_saved_path_rebuild_test

python .\scripts\verify_folderfollow_saved_path_rebuild.py `
  E:\platform-tools\hiby_player_02fd.bin `
  .\artifacts\hiby_player_1.4_sortfix_fullnav_wake_folderfollow_saved_path_rebuild_test
```

## Hardware result

The one-shot artifact booted normally and remained responsive throughout the
test. The user confirmed working volume after every relevant transition.

Observed sequence:

1. Roots in Russia began in its Folder View with the playing item highlighted.
2. On transition to Slayer, Folder View automatically changed to the card root
   and highlighted `Slayer - Discography`. It did not immediately reach
   `Show no mercy`.
3. Activating that highlighted folder opened the hierarchy to full depth; the
   playing Slayer item was highlighted and volume still worked.
4. Within `Show no mercy`, the highlight followed `The Antichrist` and then
   `Die by the Sword` without a redundant visible rebuild.
5. On transition to `Sleep - Part 1` from the deep Slayer view, the screen
   remained on `Show no mercy` with no highlight. After one Back action, the
   wrapper became eligible and automatically changed to the card root with
   `Sleep` highlighted.
6. Activating `Sleep` opened its track list with `Part 1` highlighted. Volume
   and navigation remained functional.

The process stayed alive and the failure marker prevented a 100 ms rebuild
loop. After playback stopped, terminating the test process triggered the
one-shot launcher's reboot. `/usr/bin/hiby_player` was restored with live
SHA-256 `0fedb30f91937eafb5baaf3c75422cdbde04a62fe8bac8eca3c7a88bb761da0e`;
the one-shot flag was absent.

## Interpretation

The stock property-11 transaction is safe on this UI owner, but one synchronous
`0x495D40` call visibly advances only to the card root and selects the first
saved-path component. The following ordinary activation completes the descent.
It does **not** consume a retained property-11 path: `0x495D40` clears that
property before returning. The deeper state that activation uses is still to
be identified. A second limitation is hardware-proven: in a deep
`Show no mercy` screen, the current view is not the same pointer returned as
the last `vg_listview_explorer`, so the conservative equality gate suppresses
the rebuild. One Back action exposes an eligible explorer view and the pending
Sleep target is then handled.

The next candidate should preserve the successful property-11 transaction but
replace the pointer-equality gate with a statically and passively validated
classification of deep Folder View screens. The first read-only view-depth
diagnostic unexpectedly exited, but a repeat run of the previously successful
playing-path logger confirmed the pointer mismatch during deep navigation;
see [view-depth results](folderfollow-view-depth-diag.md). The ordinary
activation that completes descent should be traced and scheduled, not
synchronously forced from the timer.

## Original intended hardware sequence

The run used the ordinary one-shot launcher.

1. Start a Roots in Russia track through `Music -> Files -> SD-card1 -> 01Flat`
   and leave its Folder View visible with the track highlighted.
2. Start or advance to Slayer in nested
   `02Nesteted -> Slayer -> Albums -> Show no mercy` while Folder View remains
   visible. Confirm that it changes to Show no mercy and highlights the playing
   track; immediately confirm volume.
3. Advance within Show no mercy. Confirm stable navigation and highlighting,
   with no redundant visible rebuild.
4. Start Sleep from flat `03Flat`. Confirm that Folder View changes to 03Flat,
   highlights Sleep - Part 1, and volume/Back still work.
5. Stop playback and restore the stock player before collecting results.

Do not test from Now Playing in the first run: the wrapper deliberately waits
until Folder View itself is current.
