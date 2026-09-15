# Live playing-plane path diagnostic

Prepared and run: 2026-09-15. Hardware status: **safe and successful**.

## Static result leading to this diagnostic

The discarded `c637...` test never reached `0x4919E0`, and that helper cannot
replace equal-depth sibling folders in any case. A better stock candidate is
`0x495D40(explorer, path)`, used by the Files storage-selection callback for
`a:\\*`, `b:\\*`, and `c:\\*`.

`0x495D40` first calls `0x495A40`. That helper acquires the explorer's virtual
lock through `+0x274`, walks the view list, collects every
`vg_listview_explorer`, removes them through the ordinary `0x43B240` API, and
releases the lock through `+0x278`. `0x495D40` then performs setup and calls
the generic creator `0x491E80` for the requested explorer path. This is a
complete stock UI transaction rather than the raw `0x4E4B20`/`0x4E4640`
permutation used by failed patches.

Its three direct callers are all in the storage-choice callback at
`0x49D3A0`; no stock caller passes a nested playback folder. The helper's
safety and path contract therefore remain unproven for folder-follow.

## Artifact

Input is normalized from the completed playing-timer diagnostic
`4927297b...` back to the validated `c825a72e...` golden binary. Output:

```text
hiby_player_1.4_sortfix_fullnav_wake_playing_path_diag_test
SHA-256 599cc5e2143aae7633da967f3ea819d0683d2b9d5b184fd799930e07d1c9dc01
size    7,133,528 bytes
```

The patch changes only the `0x4E90C0` timer callback pointer at file offsets
`0x0EAEBC`/`0x0EAECC` and a 0x214-byte wrapper in RX padding at virtual
address `0x988040`. Verification found 415 changed bytes and checked all 14
control-transfer delay slots.

## Passive record

The wrapper calls original `0x4E90C0` first and writes one 0x4A0-byte `PPTH`
record through inherited FD 9. It does not call `0x4E4B80`, `0x495A40`,
`0x495D40`, any view creator, destructor, retarget helper, property setter, or
navigation callback.

Each record contains:

- callback arguments, return value, and timestamp;
- playing-plane, explorer, and activity-main pointers;
- current and last Folder View pointers and explorer-view count;
- explorer lock/list fields used by the complete stock cleanup transaction;
- a bounded copy of committed property-24 path `0xADD46C`;
- a bounded copy of last Folder View path at view `+0x3DD8`.

The purpose is to establish the exact transformation required between the
full playback file path and the Folder View wildcard path, and to confirm that
the controller passed to the proven live timer is the same object on which
the stock complete transaction operates.

## Intended hardware sequence

If installation is requested, use the one-shot FD9 launcher and keep the test
short because the live timer writes about 11.8 KiB/s:

1. start Roots in Russia through `Music -> Files -> SD-card1 -> 01Flat`;
2. show its highlighted Folder View for a control sample;
3. advance to Slayer in nested `02Nesteted` and return to the stale Roots view;
4. advance or start Sleep in flat `03Flat` and sample once more;
5. confirm volume and ordinary Back input, then stop playback.

Decode the copied log with `decode_folderfollow_playing_path_diag.py`. No
functional mutation should be built until the log proves the path form and
controller state.

## Hardware result

The controlled run completed all three phases without UI corruption, input
loss, process exit, or reboot:

```text
Roots in Russia -> nested Slayer -> flat Sleep
```

The user confirmed the highlighted Roots control state and working volume.
After both cross-folder transitions, Folder View remained on Roots, its track
was not highlighted, and volume still worked.

The captured file is 3,761,568 bytes: 3,177 complete 0x4A0-byte records with
SHA-256:

```text
46da98a2aa21048d0a0920b999ffd56cc242b92a490560d7fdc5dd2ec81daf67
```

This was the analysis snapshot taken immediately after the three target
phases. After playback was stopped and the device rebooted to the stock
player, the closed final log contained 5,484 complete records (6,493,056
bytes), SHA-256:

```text
0a2bb3912b1cd6283b4b909b1325c5e17bbdfdd6b0d2a334194a077330088986
```

The live timer saw property-24 change from the Roots FLAC to the nested Slayer
FLAC and then to the Sleep FLAC while the last Folder View path remained:

```text
a:\\Roots In Russia...\\*
```

The exact transformation is therefore confirmed: take the committed
property-24 file path, remove the final filename component, and append `*` so
the result ends in `\\*`. This works for both deeply nested and flat targets.

The same explorer pointer remained at `playing_plane+0x3C`. Its virtual
callbacks were stable at `+0x274=0x437D20` and `+0x278=0x437DA0`, matching the
lock/unlock operations used by stock `0x495A40`. The explorer list sentinel,
current view, last Folder View, and count of two explorer views also remained
stable throughout the stale-view state.

The sampled value at global `0xB8BAC8` was consistently 1. Combined with the
registration guard in `0x4E5900`, this corrects its interpretation: it is the
`lg_activity_main` registration/status slot, not a live activity-object
pointer.

The data now supports a narrowly gated functional diagnostic using the proven
timer owner and the complete stock `0x495D40` transaction. It should derive
the `\\*` target in private storage, run only when the target differs from the
last Folder View path, and suppress repeated attempts until property 24
changes again.

Post-test cleanup succeeded: the one-shot flag was absent and the rebooted
device ran `/usr/bin/hiby_player`. The device-side final log was retained.
