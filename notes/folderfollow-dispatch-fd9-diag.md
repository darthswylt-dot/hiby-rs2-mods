# Folder-follow dispatcher FD9 diagnostic

## Purpose

This is a non-stack-mutating telemetry build for the RS2 Folder View
transition. It is not another folder-follow fix candidate. It records the state seen by callback
`0x4E5FA0` for the target event `a2=1, a3=1`, calls the original callback, and
records the immediate post-callback state.

It deliberately does **not** call any of the navigation mutators used by the
failed experiments:

- `0x4916A0`
- `0x4919E0`
- `0x4E4B20`
- `0x4E4640`

The audio path is unchanged.

Post-test caveat: `0x4E4B80` was initially treated as a getter, but static
review shows that it also performs its normal internal synchronization and
finalization calls. The test caused no UI instability, but future telemetry
should read the underlying source fields directly instead of adding another
`0x4E4B80` call after the callback and describing it as purely passive.

## Artifact

Binary:

`hiby_player_1.4_sortfix_fullnav_wake_folderfollow_dispatch_fd9_diag_test`

Golden input SHA-256:

`c825a72e1078999f74822846d35c99971f9a660addd5f12d42d50a75f0b9b80e`

Diagnostic output SHA-256:

`6c274509946c57a642a5ae7f7a42910e6bc8abe28fba8155c973bb6a56c08912`

Size: `7,133,528` bytes, unchanged from the golden input.

## Exact binary changes

1. The callback registered at `0x4EADB4` now points to `0x988040`:
   - file offset `0x0EADB4`: `lui a1,0x4E` -> `lui a1,0x99`
   - file offset `0x0EADBC`, the `jal 0x459580` delay slot:
     `addiu a1,a1,0x5FA0` -> `addiu a1,a1,-0x7FC0`
2. A `0x280`-byte wrapper was written at virtual address `0x988040`, file
   offset `0x588040`, in an all-zero executable padding run.
3. No bytes outside those two callback instructions and the wrapper range
   differ from the golden input. There are 474 byte-level differences because
   zero words inside the wrapper remain byte-identical to the padding.

All 22 control-transfer delay slots in the wrapper were checked. Branches and
calls use NOP delay slots; the final `jr ra` delay slot restores the original
return value. The callback-registration `jal` retains the pointer-forming
`addiu` in its delay slot.

## Data collected

Each target callback appends one fixed `0x4A0`-byte record to:

`/mnt/sd_0/rs2_folderfollow_dispatch_diag.bin`

The launcher opens inherited file descriptor 9 once. The callback performs one
binary `write(9, record, 0x4A0)` after the original callback. It does not invoke
`system`, a shell, formatted logging, or file open/close calls in the UI path.

The record contains:

- monotonic entry and exit times;
- caller return address, original stack pointer, and original `a0..a3`;
- player-context and explorer pointers;
- current playback path from `0x4E4B80`;
- current-view pointer before and after the original callback;
- explorer fields at `+0x150`, `+0x298`, and `+0x29C` before and after;
- count of `vg_listview_explorer` views;
- last matching explorer-view pointer and its path at `view+0x3DD8`;
- return value of original `0x4E5FA0`.

Stage bits:

- `0x01`: target event
- `0x02`: player context obtained
- `0x04`: explorer obtained
- `0x08`: playback path obtained
- `0x10`: current view obtained
- `0x20`: view count sampled
- `0x40`: matching explorer view found
- `0x80`: original callback returned

## One-shot installation

The launcher truncates the diagnostic log, opens FD 9, starts the patched
player, and removes the one-shot flag before launch. If the player exits, it
closes the descriptor, syncs, and reboots. The next boot is stock because the
flag is already absent.

```powershell
adb push .\hiby_player_1.4_sortfix_fullnav_wake_folderfollow_dispatch_fd9_diag_test /data/hiby_player_sortfix
adb shell chmod 755 /data/hiby_player_sortfix
adb shell sha256sum /data/hiby_player_sortfix
adb push .\rs2_folderfollow_diag_launcher.sh /ui_data/player
adb shell chmod 755 /ui_data/player
adb shell touch /mnt/sd_0/RS2_SORTFIX_TEST
adb shell "sync; reboot"
```

## Physical-device procedure

After boot, wait 15 seconds before touching the player.

0. If the player shows the USB-storage or USB-DAC connection screen, exit that
   screen first and then wait ten seconds without any other input. Record the
   diagnostic-file size at this point. Exiting the connection screen may use
   the same `a2=1,a3=1` callback and therefore may create one or more prelude
   records. Those records are retained and classified separately; do not
   truncate the log while the patched process still has FD 9 open.

1. Start a track in a clearly identifiable folder **A** that has at least two
   tracks. Write down the folder name and track name.
2. Open Now Playing, wait five seconds, then perform the normal single gesture
   that returns to Folder View. Do not navigate further for ten seconds.
3. Record which folder/list is shown. To check physical input without changing
   navigation, turn the volume wheel by one detent and observe the response.
   The RS2 has physical Previous, Play, and Next buttons, but no Volume+
   button. Do not repeatedly operate a control if the UI does not respond.
4. Return to Now Playing. While remaining on Now Playing, let playback cross
   into a different, unmistakable folder **B** by autoplay or the physical
   Next button. Do not browse to folder B. If the active playback sequence
   cannot cross a folder boundary, stop and use the device's actual known
   reproduction route instead of substituting an `All`-list workflow.
5. After the folder-B title is visible, wait five seconds and use the same
   single return gesture. Do not navigate for ten seconds.
6. Record the exact visible hierarchy, selected row, and physical-button
   response. Stop the test there.

If the UI freezes, leave the device powered on and connected. Do not force a
reboot immediately: pull the diagnostic log and process state first. The
player may be rebooted after collection.

## Collection

```powershell
adb pull /mnt/sd_0/rs2_folderfollow_dispatch_diag.bin .
python .\decode_folderfollow_dispatch_diag.py .\rs2_folderfollow_dispatch_diag.bin
adb shell "ps | grep hiby"
```

The record count is the number of all target callback events, including any
USB/DAC-screen prelude. Each record is `0x4A0` (`1184`) bytes. Note the prelude
count before the music test; the two Folder View gestures should then be the
next two records. With no prelude, two gestures produce a `0x940` (`2368`)-byte
log.

## Installed one-shot state (2026-09-03)

- Running command: `/data/hiby_player_sortfix`
- Verified remote binary SHA-256:
  `6c274509946c57a642a5ae7f7a42910e6bc8abe28fba8155c973bb6a56c08912`
- One-shot flag: absent after launch, as intended
- Diagnostic log: present and empty before the first gesture
- Process FD 9: linked to
  `/mnt/sd_0/rs2_folderfollow_dispatch_diag.bin`
- Previous launcher backup:
  `/ui_data/player.pre_folderfollow_diag`
- Previous `c637...` test-binary backup:
  `/data/hiby_player_sortfix.pre_dispatch_diag`

## Hardware result

Control folder:

`Roots In Russia. Русский реггей 2 (2000)`

Target playback after crossing the folder boundary with the physical Next
button:

`Slayer - Evil Has No Boundaries`

Observed target result:

- Folder View remained on the old `Roots In Russia...` folder.
- The old track row was no longer highlighted.
- There were no shifted or overlapping panels.
- The volume wheel changed volume by one step, so input remained responsive.

The complete log contains three valid `0x4A0` records and has SHA-256:

`a76aefceaed2a8100afc066261755032a2137ef71d5ca4f7e125a0ce0d408dc2`

All three records have the same callback dispatcher return address
`0x004BAA68`, player context, explorer pointer, current-view pointer, explorer
state pointer, list head/tail, and last matching Folder View pointer. The
matching view path is the old `Roots In Russia...` folder and the explorer has
two matching views. Original `0x4E5FA0` returns zero and does not change any of
the sampled explorer fields before returning.

`0x4E4B80` returned `-1` with an empty path in every record. Stage bits are
`0xF7`: every probe except playback-path acquisition completed. Thus the
target callback has no usable playback path before the original callback, and
the original callback itself does not immediately retarget the existing
Folder View. Any stock navigation effect is deferred or owned elsewhere.

This explains why the pre-callback retarget/rebuild experiments could not use
the desired path reliably. The earlier `c4dc...` result, where calling
`0x4E4B80` after the original callback briefly produced the correct folder,
suggests a transient post-callback state window. The next safe investigation
is static: identify the source fields and state transitions inside
`0x4E4B80`, then observe those fields directly without consuming or mutating
the transition state.

After log collection the device was rebooted. `/usr/bin/hiby_player` is
running, the one-shot flag is absent, and the SD-card log hash matches the
local copy.
