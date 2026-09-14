# Crash-resistant folder-follow pointer diagnostic

This diagnostic supersedes the recovered `02fd...` raw-state wrapper, which
crashed during the 2026-09-14 Roots -> Slayer hardware test before its single
final record write.

## Artifact

```text
hiby_player_1.4_sortfix_fullnav_wake_folderfollow_safe_pointer_diag_test
size:    7,133,528 bytes
SHA-256: eba4b0c99ae0f0436a038d9db242b62176c9120bc79d64b6da40564288cf3a01
```

Accepted builder inputs are either the golden `c825a72e...` binary or recovered
`02fd1dd1...`. When given `02fd...`, the builder first removes only its callback
redirection and diagnostic cave and verifies that the normalized full-file hash
is exactly `c825a72e...`.

The candidate differs from the golden input only at callback instructions at
file offsets `0xEADB4` and `0xEADBC` and in the `0x3A4`-byte wrapper at file
offset `0x588040`, virtual address `0x988040`. Sorting, full-navigation, wake,
and audio-path bytes are unchanged.

Build and verify:

```powershell
python .\scripts\build_folderfollow_safe_pointer_diag.py `
  E:\platform-tools\hiby_player_02fd.bin `
  E:\platform-tools\hiby_player_1.4_sortfix_fullnav_wake_folderfollow_safe_pointer_diag_test

python .\scripts\verify_folderfollow_safe_pointer_diag.py `
  E:\platform-tools\hiby_player_02fd.bin `
  E:\platform-tools\hiby_player_1.4_sortfix_fullnav_wake_folderfollow_safe_pointer_diag_test
```

## Safety properties

For each target `a2=1,a3=1` callback event, the wrapper:

1. records candidate source fields, player/explorer pointers, and view state;
2. writes a complete phase-1 record to inherited FD 9;
3. calls original `0x4E5FA0` with the original arguments;
4. records the same pointer/state fields after the callback;
5. writes a complete phase-2 record;
6. returns the original callback result.

It records source-object field `+0x230` as an opaque value and never
dereferences it. It performs no UTF-16 copies, calls neither `0x4E4B80` nor any
view mutator, and does not destroy, build, or retarget explorer views.

The verifier confirms the exact call graph, 28 branch/jump delay slots, code
cave bounds, final return sequence, and absence of these calls:

```text
0x41FB80  UTF-16 copy
0x4E4B80  current-path helper
0x4E4B20  destroy explorer stack
0x4E4640  build Folder View
0x4919E0  retarget existing view
```

## Record format

Each `FFSP` record is `0x100` bytes. A normal event appends two consecutive
records, phase 1 then phase 2, for a total of `0x200` bytes. If the process
fails after entering the wrapper, the already-written phase-1 record remains
available. An odd record count or a final phase-1 record therefore identifies
an interrupted event.

The records contain raw pre/post values for:

- source object at global `0xADD360`;
- source fields `+0x24`, `+0x230`, `+0x414`, and `+0x730`;
- global value `0xA92744`;
- player context and explorer;
- current view, last matching Folder View, matching-view count;
- explorer state and list head/tail;
- original callback return and the phase-1 `write` return value.

Decode with:

```powershell
python .\scripts\decode_folderfollow_safe_pointer_diag.py `
  .\rs2_folderfollow_safe_pointer_diag.bin
```

## One-shot installation

The dedicated launcher writes a separate log and leaves earlier `FFDG` and
`FFRS` evidence untouched.

```powershell
adb push .\hiby_player_1.4_sortfix_fullnav_wake_folderfollow_safe_pointer_diag_test /data/hiby_player_sortfix
adb shell chmod 755 /data/hiby_player_sortfix
adb shell sha256sum /data/hiby_player_sortfix
adb push .\rs2_modding\scripts\rs2_folderfollow_safe_diag_launcher.sh /ui_data/player
adb shell chmod 755 /ui_data/player
adb shell touch /mnt/sd_0/RS2_SORTFIX_TEST
adb shell "sync; reboot"
```

Expected remote binary hash is `eba4b0c9...`. The launcher removes the flag
before starting the candidate and writes:

```text
/mnt/sd_0/rs2_folderfollow_safe_pointer_diag.bin
```

## Hardware procedure

1. Exit the DAC screen, wait ten seconds, then navigate through
   `Music -> Files -> SD-card1 -> 01Flat -> Roots In Russia`.
2. Start a Roots track, open Now Playing, wait five seconds, and note the log
   size before the control gesture.
3. Swipe once to Folder View, wait ten seconds, and record the visible folder,
   highlight, and one-detent volume response.
4. Return to Now Playing. Without browsing, use physical Next or autoplay to
   reach `02Nesteted/Slayer/Albums/Show no mercy/Evil Has No Boundaries`.
5. Note the log size before the target gesture, swipe once, wait ten seconds,
   and record the same UI/input observations.
6. Pull the log before any manual reboot. A completed control plus target test
   adds four records (`0x400` bytes) beyond any DAC/menu prelude.

If the process exits again, the final phase-1 record is the primary evidence;
do not rerun until it has been pulled and decoded.

## Hardware result: 2026-09-14

The complete Roots -> Show No Mercy -> Hell Awaits -> Sleep run succeeded
without a process exit, reboot, UI corruption, or loss of volume input. The
final log contains 16 records (eight complete phase-1/phase-2 pairs):

```text
E:\platform-tools\rs2_safe_complete_roots_slayers_sleep.bin
size:    4,096 bytes
SHA-256: dc4272a9d4778cc447b1e37081ae853a68e6cac7ca09dd88eac392d5c36cff6c
```

Every phase-2 record has stage bits `0x7FFF`; every phase-1 write returned the
full 256 bytes. Original `0x4E5FA0` returned zero throughout.

Folder View remained on Roots after playback crossed into Show No Mercy,
across the nested Slayer subtree, and then into flat `03Flat/Sleep`. The old
Roots track was not highlighted, but the volume wheel remained responsive.

All sampled explorer and view state remained identical across all eight event
pairs: player context, explorer, current view, last matching Folder View,
matching-view count (`2`), explorer state, list head/tail, source-object
pointer, fields `+0x24`, `+0x414`, and `+0x730`, and global `0xA92744`.

The only sampled value that tracked playback changes was source-object field
`+0x230`:

```text
Roots control events:       NULL
Evil Has No Boundaries:     0x0002EB64
later Slayer event:         0x0005BA40
Sleep Part I:               0x000001AA
final Sleep gesture:        0x000001AA
```

This proves why recovered `02fd...` crashed: `+0x230` is a small scalar, not a
valid process pointer, but that wrapper passed it to the UTF-16 copy helper as
an address. The safe build records it without dereferencing it.

Local database correlation gives `Sleep Part I` a `begin_time` of decimal 426,
exactly `0x1AA`. `Evil Has No Boundaries` has an `end_time` near decimal
191,200, close to observed `0x2EB64` (decimal 191,332). This strongly suggests
that `+0x230` belongs to cue/timing boundary state rather than being a database
row ID or path pointer. Its exact semantics still require static tracing.

The important folder-follow result is that playback-related scalar state
changes while the entire sampled Folder View/explorer state remains stale and
is not changed synchronously by `0x4E5FA0`.
