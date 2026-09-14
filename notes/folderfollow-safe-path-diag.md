# Safe source-path telemetry candidate

This candidate is the next step after the static identification of
`source+0x28` as the inline playback path and `source+0x230` as the associated
absolute backing-file position in milliseconds.

## Artifact

```text
hiby_player_1.4_sortfix_fullnav_wake_folderfollow_safe_path_diag_test
size:    7,133,528 bytes
SHA-256: dfa618c017b35505fa654742c0193a155fac11c3eaf6c2b301e6bbb2163f52df
```

The builder accepts either the golden `c825a72e...` binary or recovered
`02fd1dd1...`, normalizes the latter back to the golden image, and refuses any
other hash.

Build and verify:

```powershell
python .\scripts\build_folderfollow_safe_pointer_diag.py --capture-path `
  E:\platform-tools\hiby_player_02fd.bin `
  E:\platform-tools\hiby_player_1.4_sortfix_fullnav_wake_folderfollow_safe_path_diag_test

python .\scripts\verify_folderfollow_safe_pointer_diag.py --capture-path `
  E:\platform-tools\hiby_player_02fd.bin `
  E:\platform-tools\hiby_player_1.4_sortfix_fullnav_wake_folderfollow_safe_path_diag_test
```

## Safety and byte scope

The callback redirection and the wrapper at virtual address `0x988040` are the
only changes relative to golden `c825a72e...`. The wrapper is `0x408` bytes in
a verified `0x780`-byte empty cave.

The candidate preserves the previously tested two-phase/durable-write design.
It still calls original `0x4E5FA0` exactly once with the original arguments and
returns its result. It performs no explorer mutation and does not call
`0x4E4B80`, `0x4E4B20`, `0x4E4640`, or `0x4919E0`.

For each phase it copies exactly 260 UTF-16 code units (`0x208` bytes) from the
proven inline buffer at `source+0x28`. The copy uses a seven-instruction bounded
loop with a fixed counter; it never dereferences scalar `source+0x230`.
The verifier checks both exact copy-loop bodies, their branch targets and delay
slots, the post-callback path clear, all direct call targets, the cave bounds,
the final return, and the full-file SHA-256.

The original pointer-only mode remains available and still reproduces its
hardware-tested SHA-256 `eba4b0c9...` byte-for-byte.

## Record format

Path-mode FFSP records use version 2 and size `0x320`. Existing metadata fields
through offset `0xB7` are unchanged. The bounded UTF-16 playback path occupies
`0x100..0x307`; the remainder is zero padding.

Each target gesture appends:

1. one phase-1 pre-callback record containing the pre-callback path;
2. one phase-2 post-callback record containing the post-callback path.

Thus a complete target event adds `0x640` bytes. The updated decoder accepts
both the old `0x100` records and new `0x320` records and prints
`playback_path=...` for version 2.

## Device launcher

Use `scripts/rs2_folderfollow_safe_path_diag_launcher.sh`. It writes a distinct
log and does not overwrite the earlier pointer-only hardware evidence:

```text
/mnt/sd_0/rs2_folderfollow_safe_path_diag.bin
```

## Hardware procedure

1. Exit the DAC screen and navigate through
   `Music -> Files -> SD-card1 -> 01Flat -> Roots in Russia`.
2. Start `Разные исполнители - Roots in Russia...`, open Now Playing, then
   swipe once to Folder View. Confirm the Roots folder/highlight and volume.
3. Return to Now Playing and use physical Next/autoplay without browsing until
   `Evil Has No Boundaries` in
   `02Nesteted/Slayer/Albums/Show no mercy` is playing.
4. Swipe once to Folder View and confirm the visible folder, highlight, and
   volume response.
5. Continue through the nested Slayer subtree and then to `03Flat/Sleep`,
   repeating one controlled swipe at the useful transitions.
6. Pull the log before any manual reboot and decode it with
   `decode_folderfollow_safe_pointer_diag.py`.

Expected evidence: `source+0x28` should follow the actual backing audio path
even while the displayed Folder View remains stale on Roots. Cue tracks that
share one FLAC should share the same path and be distinguished by
`source+0x230`.

## Hardware result: Roots -> Slayer -> Sleep

The 2026-09-14 run remained stable: playback, the volume wheel, and both swipe
directions continued to work. The final captured log contains 14 records
(`0x2BC0`, or 11,200 bytes), with every post-callback record reporting stages
`0x7FFF`.

```text
SHA-256: 94a4ae8071c9cb43913b2d21e7be65041be1356fd73ebbfdbe211d102ea17592
```

The first two event pairs were Roots controls. Both the pre- and post-callback
records contained the same UTF-16 backing path for the Roots FLAC, while
`source+0x230` was null.

After physical Next traversal reached `Evil Has No Boundaries`, the two event
pairs for a Folder View/Now Playing round trip contained this backing path both
before and after original `0x4E5FA0`:

```text
a:\Slayer - Discography\Albums\1983 - Show No Mercy\
  1987 USA Discovery Systems, Metal Blade 71034-2\
  Slayer - Show No Mercy (USA Metal Blade 71034-2, Discovery Systems).flac
```

For both Slayer events, `source+0x230` was `0x2EB64`, or 191,332 ms. This is
consistent with the absolute cue offset of `Evil Has No Boundaries` in the
single backing FLAC, rather than current elapsed playback time.

The traversal also captured a later Hell Awaits cue with backing path
`a:\Slayer - Discography\Albums\1985 - Hell Awaits\1988 USA Metal Blade
7 72297-2\Slayer - Hell Awaits (USA Metal Blade 7 72297-2).flac` and
`source+0x230 = 0x5BA40`, or 375,360 ms.

For `Sleep - Part 1`, both the transition event and the controlled swipe event
contained the same path before and after the callback:

```text
a:\Sleep - 1998 - Jerusalem\Sleep - Jerusalem.flac
```

Its `source+0x230` value was `0x1AA`, or 426 ms, exactly matching the locally
observed database `begin_time=426`. Folder View still displayed Roots with no
track highlighted, and the volume wheel continued to work.

The visible Folder View nevertheless remained on Roots and did not highlight
the old Roots composition. Across both Slayer callbacks, the player context,
explorer pointer, current and matching Folder View pointers, view count, state,
and list head/tail were all bit-for-bit unchanged before and after original
`0x4E5FA0`.

This establishes the key split directly on hardware: the source object already
contains an accurate playback backing path and cue offset at the gesture
callback, but the stock callback neither consumes them to retarget Folder View
nor synchronously changes the explorer/view state. A safe fix should therefore
carry `source+0x28` plus `source+0x230` into the deferred navigation owner; it
should not call the stateful `0x4E4B80` getter or replace the view stack inside
`0x4E5FA0`.
