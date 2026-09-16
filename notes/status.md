# Project status

Last reconstructed from the development log, hardware telemetry, and local
artifacts: 2026-09-03.

## Target

- Device: HiBy RS2
- Firmware: 1.4
- Player executable: MIPS32r2 ELF
- Original 1.4 `hiby_player` size: 7,133,528 bytes
- Original 1.4 SHA-256: `0fedb30f91937eafb5baaf3c75422cdbde04a62fe8bac8eca3c7a88bb761da0e`

Firmware 1.3 was used during the initial sorting work. All subsequent reverse
engineering and hardware validation moved to firmware 1.4.

## Confirmed milestones

### 1. Sorting fix

Artifact used during testing: `hiby_player_1.4_sortfix`

SHA-256:

```text
91d9e4a5d041512d26724953efbb3903f47c10b1c7a7e970bf160770254a7b8a
```

The original executable contains 14 occurrences of `COLLATE pinyin` and 18 of
`collate pinyin`. Replacing those 32 clauses with spaces changes 416 bytes,
does not change the ELF size, and restores the expected mixed-script folder
ordering.

### 2. Full folder traversal

Artifact used during testing: `hiby_player_1.4_sortfix_prev_lastchild_test`

SHA-256:

```text
d2849a8c45ce378d3ad2b2b7cf163e6fcb22d5b1670b5c5e528557945519905c
```

Confirmed behavior:

```text
Next/autoplay: 01_Flat -> Album1 -> Album2 -> 03_Flat
Previous:      03_Flat -> Album2 -> Album1 -> 01_Flat
```

The underlying defects were a comparison of local SQLite `rowid` values from
different parent lists, disabled recursive descent in the reverse direction,
and selection of the first rather than last child when entering a subtree in
reverse.

### 3. Wake refresh

Artifact used during testing:
`hiby_player_1.4_sortfix_fullnav_bkl3_force_refresh_test`

SHA-256:

```text
c825a72e1078999f74822846d35c99971f9a660addd5f12d42d50a75f0b9b80e
```

Confirmed scenario:

```text
Track A playing
-> screen off
-> automatic transition to Track B
-> Pause while the screen is off
-> screen on
-> Track B, its current time, and its progress bar are immediately displayed
```

Runtime diagnostics established that `BKL_5` is the screen-off path and
`BKL_3` is the screen-on path on this device. The successful patch performs a
metadata refresh and calls the stock progress refresh with `force=1` from the
actual `BKL_3` path.

## Latest hardware test: follow the current track folder

Latest artifact:
`hiby_player_1.4_sortfix_fullnav_wake_folderfollow_swipe_test`

SHA-256:

```text
c4dc1fe8b3601505dcbf243f2f4dda5f0c5dc0a959008e512e7d7d4927d12e62
```

Status: **failed; do not use as a release candidate**.

The Now Playing gesture callback was observed with `a2=1, a3=1` for the single
swipe back to Folder View. In the `c4dc...` build the original callback ran
before the old explorer stack was destroyed and rebuilt for the current
playback path.

Observed on hardware:

```text
Now Playing -> swipe back
-> the correct current-track folder appears briefly
-> the UI falls back to the Music root
-> the player hangs
```

The brief correct view is a useful positive result: current-track path lookup
works, and the stock path builder can construct the desired Folder View. The
failure is therefore most likely in stack/callback ordering rather than path
resolution.

## Failed rebuild-before-callback candidate

Artifact:
`hiby_player_1.4_sortfix_fullnav_wake_folderfollow_rebuild_before_callback_test`

SHA-256:

```text
5faa8c07da3ffaeba0ac1480ae0694319473112862b3b111bd9f4920d4c06eda
```

Base: the hardware-validated `c825a72e...` sorting + full-navigation + wake
refresh binary. Status: **failed on hardware; discard**.

For the observed `a2=1, a3=1` Now Playing exit gesture, the wrapper now does:

```text
0x4E4B80  get the current playback path while the old stack is intact
0x4E4B20  destroy the old explorer-view stack
0x4E4640  build Folder View for the saved path
0x4E5FA0  tail-call the original transition callback last
```

Other gestures pass directly to the original callback. The original callback
arguments are restored before the tail-call, and its return value is returned
directly to the dispatcher. The final disassembly has explicit `nop` delay
slots for every inserted branch, `jal`, and `j`.

Whole-file comparison against the golden input found 139 changed bytes, all
confined to the callback pointer at file offsets `0xEADB4`/`0xEADBC` and the
unused executable code cave at `0x51FB00-0x51FBBF`. No navigation, wake-refresh,
or audio-path bytes changed.

See [folderfollow-rebuild-before-callback-test.md](folderfollow-rebuild-before-callback-test.md)
for the byte manifest, disassembly, and exact one-shot ADB commands.

Moving stack destruction/building before original `0x4E5FA0` changed the
failure mode but did not make stack replacement safe. Without user input, Now
Playing transitioned through Music and Files to Files root. Later the browser
returned to a broad All list, views shifted and overlapped, input stopped
responding normally, and the player exited or crashed before an automatic
reboot. Together with `c4dc...`, this rules out further simple order
permutations of `0x4E4B20`, `0x4E4B80`, `0x4E4640`, and `0x4E5FA0`.

## Failed preserve-stack retarget candidate

Artifact:
`hiby_player_1.4_sortfix_fullnav_wake_folderfollow_preserve_stack_retarget_test`

SHA-256:

```text
c637effab37ff202c172a3f32a75f0d7cfbf309eec13ab8c5ecd1a89de1adfcc
```

This candidate avoided `0x4E4B20` and `0x4E4640` and intended to follow the
stock existing-view sequence around `0x4919E0`. Later FD9 telemetry proved
that its preceding `0x4E4B80` call returned `-1` in the target gesture state,
so the wrapper skipped directly to original `0x4E5FA0` and never reached
`0x4919E0`. Hardware still returned Folder View to the old folder and physical
buttons were temporarily unresponsive. Status: **failed; discard**, but not a
hardware test of `0x4919E0`.

Static analysis then showed that `0x4919E0` reconciles only differing path
depths and does nothing for equal-depth siblings. It cannot solve the required
`01Flat -> 03Flat` transition. See
[folderfollow-existing-view-contract.md](folderfollow-existing-view-contract.md).

See [folderfollow-preserve-stack-retarget-test.md](folderfollow-preserve-stack-retarget-test.md).

## Latest diagnostic: dispatcher FD9 telemetry

Artifact:
`hiby_player_1.4_sortfix_fullnav_wake_folderfollow_dispatch_fd9_diag_test`

SHA-256:

```text
6c274509946c57a642a5ae7f7a42910e6bc8abe28fba8155c973bb6a56c08912
```

Base: hardware-validated golden `c825a72e...`. The diagnostic does not destroy,
rebuild, or retarget explorer views. It records state for `a2=1,a3=1`, invokes
original `0x4E5FA0`, records the immediate post-callback state, and appends one
fixed binary record through inherited FD 9.

The controlled hardware test started in
`Roots In Russia. Русский реггей 2 (2000)`, advanced with physical Next until
`Slayer - Evil Has No Boundaries` was current, and returned to Folder View.
The old Roots folder remained visible, its old track was no longer highlighted,
and the volume wheel still responded normally. This reproduced the stale-folder
bug without UI corruption.

The three-record log has SHA-256:

```text
a76aefceaed2a8100afc066261755032a2137ef71d5ca4f7e125a0ce0d408dc2
```

All three records have stage bits `0xF7`. `0x4E4B80` returned `-1` and an empty
path before the callback. Player context, explorer pointer, current-view
pointer, explorer state, list head/tail, and the last matching Folder View were
stable across all records and unchanged immediately across original
`0x4E5FA0`; the original callback returned zero. The matching view path was the
old Roots folder and the explorer contained two matching views.

Therefore the target callback has no usable playback path before original
`0x4E5FA0`, and that callback does not synchronously retarget the Folder View.
The navigation effect is deferred or owned elsewhere. Static review also shows
that `0x4E4B80` performs internal synchronization/finalization and should not be
treated as a pure observational getter.

See [folderfollow-dispatch-fd9-diag.md](folderfollow-dispatch-fd9-diag.md) for
the byte scope, record format, corrected physical-device method, and decoded
result.

## Recovered later diagnostic: source-state telemetry

Local artifact `hiby_player_02fd.bin` has SHA-256
`02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87`.
Byte-level reconstruction proves that its base is exactly the validated
`c825a72e...` sorting + full-navigation + wake binary. Its only additional
layer is a passive `0x1200`-byte FD9 record wrapper at `0x988040`.

Unlike `6c274509...`, it does not call `0x4E4B80`. It snapshots candidate
global/path source fields and explorer state directly before and after original
`0x4E5FA0`, matching the planned next investigation. See
[02fd-archaeology.md](02fd-archaeology.md) for the complete byte decomposition,
recovered record layout, and later hardware result.

A 2026-09-14 hardware run obtained valid control records in Roots, then
reproduced the stale Roots view after physical Next reached Slayer. The target
record was not written: the patched process exited and the one-shot launcher
rebooted the device. The unchanged `02fd...` artifact must not be run again.
The safe successor later confirmed the cause: `+0x230` becomes a small scalar,
but `02fd...` passed it to a UTF-16 copy helper as an address.

## Successful safe pointer telemetry

Artifact SHA-256:
`eba4b0c99ae0f0436a038d9db242b62176c9120bc79d64b6da40564288cf3a01`.

The 2026-09-14 Roots -> Slayer -> Sleep run completed without a process exit,
reboot, UI corruption, or input loss. All eight phase-2 records have stage bits
`0x7FFF`. Folder View remained stale on Roots throughout; all sampled
explorer/view fields were unchanged. Source-object field `+0x230` alone changed
with playback: `NULL`, `0x2EB64`, `0x5BA40`, then `0x1AA`. The Sleep value
matches local database `begin_time=426`, pointing toward cue/timing state.

Complete log SHA-256:
`dc4272a9d4778cc447b1e37081ae853a68e6cac7ca09dd88eac392d5c36cff6c`.

See [folderfollow-safe-pointer-diag.md](folderfollow-safe-pointer-diag.md).

## Prepared passive UI-timer diagnostic

Static tracing recovered the three callback slots installed by `0x4E2C40`.
`0x4E2920` is the stock close/cleanup callback, not a recurring activation
callback; this explains why its correct current-path -> build sequence cannot
follow a later folder transition while Folder View remains open. The third
callback, `0x4E24C0`, is invoked by generic timed dispatch at `0x47C620` after
the constructor configures mode 2 and interval 200.

Artifact SHA-256:
`32c916ee3762568b06fe05279360b8d2b8f7de5e3ae47be37511e1c44baa3e8a`.

The new diagnostic wraps only this periodic callback candidate. It executes stock code
first, directly snapshots the proven property-24 path at `0xADD46C`, compares
it offline with the existing Folder View path, and writes fixed FD9 records.
It calls no path resolver, builder, destructor, or retarget helper. See
[folderfollow-ui-timer-static-trace.md](folderfollow-ui-timer-static-trace.md).

Hardware result: **safe but diagnostically negative**. The patched process and
its FD9 descriptor remained alive during the full Roots control and physical
Next transition to Slayer, but both FD position and log size stayed exactly
zero. The user confirmed the ordinary stale Roots view and working volume.
Thus `0x4E24C0` is not invoked in the target Files route and is not the live
UI-owner. The empty log has SHA-256 `e3b0c442...b855`.

## Prepared live playing-plane timer diagnostic

Static tracing found a separate 100 ms callback, `0x4E90C0`, whose
`playing_plane` owner remains live while the stale Folder View is visible. It
already compares the current explorer view's media identity with the playing
item. On mismatch it dispatches event 5 with value 0 through `0x4C0620`.

Event 5 has now been decoded completely: jump-table entry `0x4C06DC` stores the
argument at internal view `+0x5A4`. Stock list setup/activation paths pass 1;
one mismatch path passes 0. It participates in selection matching and is not a
folder retarget command.

Prepared artifact SHA-256:
`4927297b4ceebe3b7f8d4bb8854c632e2083d5212aa9f02c9182c9f213acf3fe`.

The passive wrapper calls original `0x4E90C0` first, then logs only a compact
256-byte snapshot of the same identity fields, the current-view pointers, and
`+0x5A4` state. It makes no navigation or view mutation. Static verification
found 362 changed bytes, confined to the two callback-pointer instructions and
the RX-padding wrapper; all 12 control-transfer delay slots are verified. See
[folderfollow-playing-timer-static-trace.md](folderfollow-playing-timer-static-trace.md).

Hardware result: **safe and diagnostically positive for ownership**. The timer
logged continuously while the user started Roots, returned to its highlighted
Folder View, and advanced with physical Next to Slayer. The context matched
global `0xB8BACC`, and the explorer/current-view/internal-list pointers stayed
live and stable. The patched process remained healthy and volume input worked.

The result also corrected the selection interpretation. `+0x5A4` changed
`1 -> 0` during initial playback/UI setup and returned to 1 with the highlighted
Roots Folder View, but it stayed 1 across the later Roots -> Slayer transition
even though the Roots highlight disappeared. Direct memory showed neighboring
row/index `+0x5A0=3`. Thus the stale list loses its highlight because none of
its rows matches the new playback item, not because the timer clears `+0x5A4`
at the crossing.

Completed 1912-record snapshot SHA-256:
`41904b62da9cd6d2f20340e4dea0545daf1a880e4fd7d957124ef6ee04685cb9`.

## Successful live path-contract diagnostic

Static analysis ruled out `0x4919E0` as a general sibling retarget and found
the complete stock storage-open transaction at `0x495D40`. It performs locked
explorer cleanup through `0x495A40`, restores a nested hierarchy from one-shot
UTF-16 property 11 through `0x495B80`, clears that property, and opens its
supplied drive root only as fallback. Stock callback `0x4BD100` is the sole
non-empty property-11 writer and saves `selected_item+0x3DD8`.

Artifact SHA-256:
`599cc5e2143aae7633da967f3ea819d0683d2b9d5b184fd799930e07d1c9dc01`.

The passive successor wrapped the already proven `0x4E90C0` timer and recorded
the committed property-24 file path, last Folder View wildcard path, explorer
lock/list fields, and activity-registration status. It performs no navigation
mutation.
See [folderfollow-playing-path-static-trace.md](folderfollow-playing-path-static-trace.md).

Hardware completed Roots -> nested Slayer -> flat Sleep safely. The 3,177
complete records prove that the timer sees each new full file path while the
last Folder View remains on Roots. The required target is exactly the parent
directory of property 24 followed by `\\*`. The explorer pointer and stock
lock/unlock callbacks remained stable. Log SHA-256:
`46da98a2aa21048d0a0920b999ffd56cc242b92a490560d7fdc5dd2ec81daf67`.
That hash identifies the immediate 3,177-record analysis snapshot. The closed
post-stop log has 5,484 complete records and SHA-256
`0a2bb3912b1cd6283b4b909b1325c5e17bbdfdd6b0d2a334194a077330088986`.
The device was then rebooted successfully to `/usr/bin/hiby_player`.

## Remaining work

1. Replace the `current_view == last vg_listview_explorer` gate used by the
   safe partial `4c43e0a4...` test with a validated classification that also
   recognizes deep Folder View screens. Hardware proved that the equality gate
   suppresses a Slayer -> Sleep transition until one Back action. The first
   passive active-vs-last view diagnostic unexpectedly exited before any view
   became active; do not reinstall it. See
   [folderfollow-view-depth-diag.md](folderfollow-view-depth-diag.md). The
   prior successful playing-path diagnostic already records both view pointers;
   reusing it during manual deep navigation was the lower-risk next measurement.
   That run confirmed two explorer objects alternate by depth: at the deep
   Show No Mercy release track list, `current_view=0x00ef171c` while
   `last_view=0x0122219c`; after one Back both equal `0x0122219c`. See the
   completed result in [folderfollow-view-depth-diag.md](folderfollow-view-depth-diag.md).
   Subsequent static audit found the failed diagnostic's concrete type-layout
   error: the `controller+0x298` view has an inline type string at `view+0`,
   but the wrapper treated its first four characters as a pointer. A v2
   artifact correcting those two loads and removing two unnecessary `+0x40`
   reads was built, statically verified, and then hardware-tested. It remained
   healthy through root, Roots playback, and deep Slayer navigation. Record
   2266 proves active path `...Show No Mercy\\1987 USA Discovery Systems...\\*`
   while the last explorer path remains parent `...Show No Mercy\\*`.
   Its exact-name comparison did not copy paths for suffixed
   `vg_listview_explorer##1` views; stock uses a prefix match instead.
2. Trace and schedule the ordinary activation that completes descent after
   `0x495D40` selects the first root component. `0x495D40` clears property 11,
   so that activation cannot consume a retained property-11 path. Do not
   force the remaining hierarchy synchronously from the 100 ms timer. See
   [folderfollow-saved-path-rebuild-test.md](folderfollow-saved-path-rebuild-test.md).
3. Stage the property-24 path at commit `0x42CD5C` and `0x42CBDC`, then consume
   the staged change only from this hardware-confirmed UI owner; do not rebuild
   or retarget from the playback worker.
4. Identify a confirmed UI-queue or complete stock navigation transaction that
   can replace an unrelated open Folder View. Do not use `0x4919E0` as a
   general retarget or invoke activity initialization from the 100 ms timer.
5. Trace the state transitions around the sole property-31 consumer at
   `0x4E4B80` and determine why it sometimes has no resolvable media ID.
6. Add a byte-level patch manifest for the confirmed full-navigation and wake
   fixes.
7. Remove `/etc/init.d/S99adb` after device testing is complete.
