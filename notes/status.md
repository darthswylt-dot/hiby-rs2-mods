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

Hardware-tested 2026-09-29: [active-view rebuild candidate](folderfollow-active-view-rebuild-test.md),
SHA-256 `6e872416...`, successfully followed Roots -> Slayer -> Sleep,
including Sleep directly from the deep Slayer list without Back. It recognizes both
explorer names by the stock prefix, compares the active path, and records every
attempted target to avoid timer loops when the stock transaction leaves the
active screen at the root. Instruction-level mock tests passed; full automatic
descent remains unresolved. Opening the selected folders showed the playing
track highlighted, and volume worked throughout. Stock `0fed...` was restored
and its live executable hash verified after the intentional end of the test.

An additional observed defect needs investigation: within Slayer, the highlight
moves beyond the visible rows without scrolling the list. This has not been
compared with stock/baseline behavior and is not yet a proven new regression.

The [initial selection/scroll trace](folderfollow-selection-scroll-static-trace.md)
corrects `internal+0x5A0` to a working enumeration index, not a proven persistent
playback selection. The traced `view+0x2A0C` rectangle controls redraw, while
the rendering path reads separate content offsets. No safe ensure-visible
operation or scrolling patch has yet been validated; no new build was installed.
Follow-up tracing identified stock playback-location helper `0x490E20`: it
resolves a view, obtains a database position from playback metadata, changes
vertical content offset via `0x8B43C0`, then refreshes via `0x490D00` and
`0x499C20`. Its lookup has a cue-aware SQL branch. This is a promising existing
path, not yet approved for periodic use: state gates, database cost, match
failure, active-view lifetime and manual-scroll policy need validation first.
Explorer-specific follow-up found type 2 and an empty constructor lookup key
at `view+0x3824`; the helper's recognized-key SQL route therefore cannot yet be
assumed valid for Files. Saved-database tests confirm cue-aware row positions
but also prove that a missing path returns zero, indistinguishable from row 0.
Slayer's 13 tracks share one FLAC path; Sleep Part I is row 1 because `covers`
precedes it. A read-only checker preserves these findings. No timer call or
new device build has been added.
The Files row path is now traced through `0x4327C0` and cache reader
`0x4994E0`, with folder-table fallback through `0x6F7CA0`/`0x6F2D20`.
The saved manager mapping resolves deep Slayer to `list_tb_5` and Sleep to
`list_tb_6`; these numbers are not runtime constants. The offline checker
validates all 20 entries and distinguishes missing folder/path/cue from row 0.
Date-sort SQL uses a different order, so rowid rank is not a universal scroll
target. Active cache/sort telemetry remains the next safe measurement.

1. Completed in the partial candidate above: replace the
   `current_view == last vg_listview_explorer` gate used by the
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

### Passive scrolling telemetry completed (2026-09-29)

SCRL candidate `5ae6d8195c1f7061cbc9cd0b6ed64e6fd3a623c7945a3218d84473f93777520e`
is built on normalized golden, without active-view folder-follow rebuilding.
Eleven offline instruction/mock/decoder tests pass. Exact bytes and patch scope
are checked separately. The user-authorized hardware run is complete; stock
recovery was verified via live executable hash `0fedb30f...` and absent test flag.
See [folderfollow-scroll-diag.md](folderfollow-scroll-diag.md) for limitations,
record format and hardware results. The dedicated one-shot launcher preserved
stock, and the final log contains 2,868 complete records.
Additional ELF audit confirms the five imported function entry points. Short
log writes are not retried and can invalidate framing; clock failure produces
zero timestamps. These known diagnostic limitations are documented, not fixed
in firmware. The artifact hash remains unchanged.

Post-run audit confirms cue advancement without viewport movement, followed
by successful manual scrolling. Stock bottom adjustment uses
`*(*(view+0x3B68)+0x1B8)+0x9C`, not the recorded raw `viewport+0x20`.
The Files lookup key stays empty. The raw database sort selector's address
chain is confirmed but its value `0x00BDA6C9` is unexplained. Do not derive
list order or scroll bounds from these two v1 labels. Read-only checker
`check_scroll_diag_findings.py` validates ten code anchors and the final log.

### Folder-fill diagnostic built, not installed (2026-09-30)

FILL v1 candidate `7e01a34b98584359a3b98312ae040d77feb93a75fe4bdbc4604913da32f1925d`
is ready for a separately authorized hardware test. It instruments the actual
mode-zero folder SQL producer: BEGIN, post-append ROW, raw terminal step result
and END. Producer hooks only populate a bounded append-only BSS buffer; the
original UI timer drains records to FD9. No scrolling or active-view rebuilding
is introduced. Buffer capacity is 512 events per process; loss invalidates the
offline mapping. Extra mapped memory is 304,028 bytes including alignment.

18 new instruction/mock/decoder tests and nine existing cache/fill model tests
pass; exact artifact/ELF/patch-scope verification passes. Current read-only
regression checker validates **67** stock anchors and 2,868 prior SCRL records
(the earlier ten-anchor statement above describes an earlier checker revision).
Runtime memory ordering, loader acceptance and device stability are untested.
See [folderfollow-fill-diag.md](folderfollow-fill-diag.md) for the artifact,
reproduction, capture limitations and one-shot test procedure. No device
installation, commit or push was performed in this build step.

### FILL v1 installed; initial startup verified (2026-09-30)

Following the user's explicit installation request, the new candidate and
dedicated one-shot launcher were deployed with verified backups in
`artifacts/fill_diag_install_backup_20260930/`. After one reboot, live PID 123
matches `7e01a34b...`, FD9 points to the FILL log, and the one-shot flag is absent.
Stock remains unchanged. The 10,144-byte startup snapshot decodes as 317 valid
status records with zero reservations and zero loss flags; no folder producer
sessions have run yet. Playback/highlight/volume and row capture await the
interactive Roots test. No commit or push was performed.

Roots stage subsequently passed: user confirmed playback, file highlight and
volume. The 63,536-byte snapshot `artifacts/fill_diag_roots_20260930.bin`
contains two accepted fills (card root: three rows; Roots: covers then FLAC),
11/11 events drained, raw terminal 101 for both, and no reported losses.
The diagnostic executable is still running with the expected hash. Deep Slayer
navigation and cue-row capture are the next interactive stage.

Slayer entry subsequently passed: user confirmed playback/highlight/volume.
The 108,576-byte Slayer snapshot contains six accepted fills and 40/40 events
drained, with no reported loss. The deep release list has 13 rows sharing one
FLAC path, cue 0..12 matching insertion indices 0..12 in this captured order.
All query offsets remain zero. Track switching and manual scrolling are next;
the test process is left running, with no commit or push.

Physical Next in Slayer also passed highlight/volume checks per user. The
148,608-byte snapshot retains the same six accepted fills and 40/40 events,
with zero loss flags; no new captured fill accompanied this switching interval.
Offscreen-highlight behavior and manual scrolling remain to be checked in
this FILL run.

Offscreen behavior is now reproduced in FILL: user reports the highlight left
the screen, the list did not follow, and volume still works. Snapshot
`artifacts/fill_diag_slayer_offscreen_20260930.bin` (176,032 bytes) still has
six accepted fills and 40/40 events with zero loss flags. No new captured fill
occurred. Manual scrolling is the next check; no viewport state is inferred
from FILL records themselves.

Manual scrolling also passed: user sees the highlighted composition again and
volume works. The 207,712-byte snapshot retains six accepted fills, 40/40 events
and zero loss flags. No new captured fill or nonzero query offset appeared;
cache-window refill remains untested with this small list. Sleep Part 1 is next.

Sleep Part 1 also passed playback/highlight/volume per user. The settled
244,560-byte snapshot `artifacts/fill_diag_sleep_20260930.bin` contains ten
accepted fills and 65/65 events with zero loss flags. Sleep's covers is row 0;
cue 0..5 map to rows 1..6, unlike Slayer's observed cue=row ordering. All query
offsets remain zero. Interactive stages are complete and saved, but the test
process is still running; explicit shutdown/recovery authorization is pending.
The offscreen-highlight defect remains, and no persistent-map or scrolling
fix is validated by this run. No commit or push performed.

FILL test shutdown was then explicitly authorized and completed. Test PID 123
received SIGTERM; the one-shot launcher rebooted. Live stock PID 121 now hashes
to `0fedb30f...`, with no test flag. Final closed log
`artifacts/fill_diag_final_20260930.bin` is 285,808 bytes, SHA-256
`7cd4a63322fc2c32d141572a7725d6c00a44b0b506972d00537deb6d257ff0fe`;
local/device hashes agree. All ten fills pass, 65/65 events drained, 7,729
status records, zero loss flags and no framing errors. Stock is running;
diagnostic files/backups remain preserved and unarmed. No commit or push.

### Files input-to-scroll route traced (2026-09-30)

Local investigation after FILL connected the explorer table callback
`0x49B000` to the input-state branch `0x496940` -> `0x4BA500` -> `0x8B43C0`
(relative content-y request `0x30002`). These handlers also mutate gesture and
scrollbar state; they are not safe drop-in playback-timer helpers. The generic
setter's return zero does not prove an offset change, and its clamp can become
negative for a smaller-than-viewport raw extent. A new read-only checker
validates 83 anchors plus explorer/resource names and passes 15 cases executing the
actual setter instructions with a mocked parent invalidation call.

The explicit stock setter -> `0x490D00` -> gated `0x499C20` pairing is the
redraw/refill lead. Runtime flags, safe view lifetime/dispatch, and a coherent
current row identity remain prerequisites. See
[manual scroll route](folderfollow-manual-scroll-route.md). No firmware or
device state changed; stock remains as verified at test shutdown. No new
commit or push in this research step.

The next static pass traced C+0x3C back to the selected `viewgroup` resource's
+0x0C through `0x43AD00`/`0x8B4120`; the actual flags are still unmeasured.
Raw extent C+0x20 is initialized only with mode bit 4, so its captured zero
does not alone establish a bug. The conditional redraw chain is now bound:
parent dirty rectangle -> `0x8B1420` -> `0x8B4660`/`0x8B3FA0` ->
C+0x48=`0x439EC0` -> `0x438200` -> widget+0x154=`0x4908A0` -> gated
`0x499C20`. Runtime widget selection, +0x8C rearming and owner/locking remain
unproven; no callback coverage is inferred from FILL. The redraw high bit
preserves tested low-bit setter behavior. No build or device operation.

### Queued rendering and deferred row refresh (2026-09-30)

The UI loop `0x43C980` calls both the queued-event dispatcher `0x454200`
(table entry 0x1001 -> `0x451CA0` -> render pass) and timer pump `0x473560`.
Explorer-bound `0x49B460` can arm ID 20 with interval 100 through `0x499240`;
explorer movement `0x49B000` cancels that timer. Callback `0x49A1A0` resolves
the selected view anew, checks V+0x70 bit 0, calls `0x499C20`, and removes
itself. It ignores registered data and does not require V+0x8C. This is a
separate route from the initialization/render-completion callback, not proof
that every manual scroll in FILL executed it. Actual OS thread, lifetime and
lock coverage remain unverified; ID 20 must not be repurposed.

The new read-only dispatch checker passes 42 anchors and eight executions of
the original callback/helper instructions with external calls mocked. See
[refresh dispatch](folderfollow-refresh-dispatch.md). No build, installation,
device call, commit or push in this step.

### Offscreen-highlight diagnosis refined (2026-09-30)

Closed SCRL reanalysis finds cue 5 at y=0 in 197 consecutive samples spanning
25.079197579 seconds before manual movement. All 821 deep Slayer samples
have the same sampled address/geometry/cache-summary tuple; this is not a
generation or atomicity proof. FILL is verified independently, not joined
to the SCRL timeline. A new hash-gated read-only report reproduces the result.

The leading hypothesis is a missing/ineffective reveal request, not a short
refresh delay. The exact cause remains open: existing logs contain neither
setter requests/results nor callback coverage. Row refresh calculates its
first row from the existing y; invoking it alone is not a demonstrated fix.
The [diagnosis and probe-site audit](folderfollow-scroll-diagnosis.md) specifies
the discriminating passive measurements and preserves build/install gates.
No firmware or device state was changed.

### MOVE v2 diagnostic built locally (2026-09-30)

Artifact `hiby_player_1.4_sortfix_fullnav_wake_move_diag_test`, SHA-256
`15cf4457e829692a52482c0b64a8b478f426f014b7cb31099ed6325a496c3f07`,
is built and exactly reproduced/verified. It records scoped original
content-y setter transactions (old/requested/returned y, flags/result/caller),
original row-refresh inputs and MSNP current-view/playback snapshots. Producers
use a bounded BSS buffer; the existing UI callback exports status and up to
eight events per invocation. Position/size and absent-parent setter calls are
excluded from event capture but retain original execution. No automatic
scrolling/folder following is added.

All 59 tests pass, including actual-source setter comparisons and logging
failure paths. The launcher syntax is checked. Scope is 1,246 changed bytes
against golden, 1,736 code bytes in the existing cave, and 98,368 bytes of
appended BSS. Hardware is untested; no device connection, installation,
arming, commit or push occurred. See [MOVE diagnostic](folderfollow-move-diag.md)
for the format, limitations and prepared Roots/Slayer/manual-scroll/Sleep run.

### MOVE v2 installed; initial startup verified (2026-09-30)

User explicitly authorized installation. Live stock PID 117 was hash-checked,
battery reported 100%/Full, and the test flag/MOVE log were absent. Previous
FILL executable and launcher were saved and hash-verified in
`artifacts/move_diag_install_backup_20260930/`. New files were staged,
hash-checked, syntax-checked and renamed into the existing test paths.
Stock remains unchanged (`0fedb30f...`). After one armed reboot, live PID 123
matches MOVE `15cf4457...`; FD9 points to its dedicated log, and the one-shot
flag is gone.

The 623,328-byte startup snapshot has matching local/device SHA-256
`b0c08a2318b28e84b322963d5d6e8baff4abf7d0448b445432202e0574ec9ef8`.
Strict decoding accepts 453 snapshots and 453 statuses, reserved=drained=0,
zero reported losses and no setter/refresh events yet. Startup/logging is
verified; playback/highlight/volume and the actual event probes await user
navigation through DAC -> Music -> Files -> SD-card1 -> Roots in Russia.
Test remains running. No commit or push performed. See
[MOVE diagnostic](folderfollow-move-diag.md) for deployment and limitations.

Roots playback/highlight/volume subsequently passed per user. Live PID 123
still matches the candidate. `artifacts/move_diag_roots_20260930.bin`
(2,513,056 bytes, SHA-256 `dcf7102022af84a43386f7591226cb4843ac53395c0b8b63405e367e231a6fa2`)
has 1,826 snapshots/statuses and five refresh events, all five drained and
zero reported losses; strict decoding accepts the exported prefix. Observed
refresh input flags C+0x3C are 2, y=0, pitch=80 and height=260. Final sampled
folder/playback identifies Roots. No scoped setter event yet: that probe and
offscreen/manual-scroll behavior remain to be tested. Deep Slayer is next;
test process remains running, no commit or push performed.

Deep Slayer entry also passed playback/highlight/volume per user. Snapshot
`artifacts/move_diag_slayer_entry_20260930.bin` (4,429,984 bytes, SHA-256
`7b771676016310d36eeca0b9a515d6be0e87e9607bdac61a12b9fc2903e73048`)
is accepted with 3,218 snapshot/status pairs, three setter transactions and
18 refresh inputs; all 21 events are drained and reported loss flags are zero.
Setters from `0x491DF4` request absolute y=0 and return y=0/result=0 with
flags=2. This validates zero-request capture, not scrolling. Final sample
identifies the deep Show No Mercy release, cue 0/0, cache count 13 and y=0.
Live PID 123/hash/FD9 remain verified. Physical Next, offscreen and manual
scroll checkpoints are next. No commit or push performed.

Slayer physical Next highlight/volume checks subsequently passed per user.
`artifacts/move_diag_slayer_next_20260930.bin` (6,004,128 bytes, SHA-256
`135dbe26c70b5866230f867edf6ed631242a6590217e1e9e76d85e71c8a2dc0b`)
extends the entry prefix, with 4,362 snapshot/status pairs and unchanged
21/21 event counts, zero reported losses. The 1,144 new snapshots show cue
brackets 0/0, 1/1 and 2/2 with sampled y=0; no new scoped setter/refresh
events were captured in this interval. This does not cover excluded calls
or direct writes. Offscreen reproduction and positive manual movement are
next. Live diagnostic PID 123/hash/FD9 remain verified; no commit or push.

### MOVE offscreen reproduced; run interrupted by reboot (2026-09-30)

User reports stationary list after highlight left the screen, with volume
working. An offscreen device copy completed (7,973,184 bytes, SHA-256
`e181b61124075c46c6b9be3cc6ebe6ad2c48d8639014991de4545fd632a63222`),
but USB disappeared before transfer. On reconnection, low uptime and stock
PID 118 showed a reboot. No reboot/signal/rearming command was issued by
this agent at this stage; the cause is unknown.

The persistent log was recovered as `artifacts/move_diag_recovered_20260930.bin`
with the same hash as the pre-reboot copy. Its prefix is accepted: 5,793
snapshot/status pairs, unchanged 21/21 events, zero reported losses. New cue
2/3/4 samples retain y=0; 468 cue-4 samples span 59.744035839 seconds without
a new captured scoped setter/refresh event. Nonzero manual scrolling remains
untested; absence conclusions retain the diagnostic scope limitations.
Stock live/hash and absent flag are verified. Current-boot dmesg reports an
unclean FAT unmount, not a prior-boot cause. Run is not rearmed; manual/Sleep
tests are pending. Files/logs remain preserved; no commit or push performed.

User subsequently confirmed spontaneous reboot. Treat MOVE as an unexpected
runtime failure and hold it from further device runs. A local read-only
review and exact artifact verification still pass, as do all 59 tests;
the root cause is not established. Last exported refresh is associated with
tick 2,656; snapshots continue to tick 5,793 (401.216096573 seconds after
the associated snapshot). Settled counters and clean framing do not rule
out an unexported fault or watchdog/reset outside this telemetry. No new
device connection, rearm, install, firmware edit, commit or push during this
audit. A future run needs process-exit/crash/reset evidence capture first.

### MOVE reboot investigation resumed locally (2026-09-30)

Two independent audits found no demonstrated hot-probe ABI/stack/control-flow
or snapshot/drain/ELF-layout error. The collection procedure has a new
memory-pressure candidate: five `/tmp` copies on recorded tmpfs, not removed
by the agent, total 21,543,680 bytes (20.545654 MiB) if retained. The last
copy completed just before reboot discovery. No saved RAM/RSS/OOM or child
exit status proves the mechanism, so the cause remains open.

A hash-gated read-only report verifies all checkpoints as exact byte prefixes
of the recovered log. The longest gap occurs at startup, not at the end;
final intervals remain approximately 128 ms. Three report tests bring the
suite to 62 passing tests; firmware/launcher hashes are unchanged. See
[MOVE reboot analysis](folderfollow-move-reboot-analysis.md) for the reviewed
facts, limitations and requirements for persistent exit/kernel/memory evidence
and a non-accumulating checkpoint procedure. No ADB/device access, firmware
edit, replacement launcher/build, install, rearm, commit or push in this step.

### Evidence-retention launcher prepared locally (2026-09-30)

Following the next user continuation, separate draft
`scripts/rs2_folderfollow_move_evidence_launcher.sh` was created, SHA-256
`1cdfed5423da735895993ae18755526cf0395b2c88ad82c138d29ba803f24f6e`.
It pins the unchanged MOVE candidate, creates fresh card-backed run files,
captures child stdout/stderr/raw wait status and three memory/kernel state
attempts, flushes the minimal exit marker before final probes, and keeps
one-shot recovery. Only a guaranteed prelaunch refusal falls back directly
to stock; uncertain supervisor failures always request reboot, not a second
player. It makes no tmpfs log copies and adds no timeout/retry.

All 21 new isolated mock-shell tests pass, as do all 83 repository tests,
shell syntax and whitespace checks. Two reviews addressed phase/FD/PID/wait
evidence issues. Hardware/BusyBox behavior is untested. Free-space admission
is not a growth cap; hard resets, unavailable storage or blocking sync can
still lose evidence. Host checkpoint collection still needs revision. See
[evidence launcher](folderfollow-move-evidence-launcher.md). No ADB/device
access, firmware change, installation, rearm, commit or push in this step.

### Direct-to-host checkpoint collection prepared locally (2026-09-30)

Following the user's go-ahead, `scripts/capture_move_checkpoint.py` replaces
the accumulating device `/tmp` checkpoint approach with a bounded read-only
ADB exec-out stream into a fresh host directory. Pre/post probes retain
memory/status and verify boot/PID/starttime/live MOVE hash/FD9/dev/inode.
The initial size freezes the prefix byte limit. stdout/stderr bounds apply
while reading, with no local text pipeline or device-side file copy.

Raw bytes and unsuccessful/partial evidence are retained; complete records
are strictly decoded without dropping valid unsettled events. Transfer and
after-probe failures do not suppress independent received-byte analysis.
Successful checkpoint acceptance requires exact transport, source coherence,
no partial record and an accepted loss-accounted prefix. No automatic retries
or device changes. Twenty-three new mock/local-subprocess tests pass; all
106 repository tests pass. Firmware and launcher hashes remain unchanged.
See [collector scope and limits](folderfollow-move-checkpoint-collector.md).
No ADB connection, deployment, rearm, commit or push; real BusyBox/head/stat/
exec-out support and hardware behavior await scoped verification.

### Read-only device compatibility check failed (2026-09-30)

Following the user's `check` command, actual RS2 gates were tested without
installation/rearm/MOVE launch/device-side copies/signals/reboot. exec-out
is rejected (`error: closed`); shell -T is rejected (PTY required); stat is
absent even as a BusyBox applet. Legacy shell loses remote exit status and
alters explicit CR/LF controls (10 bytes become 16). A matching 1376-byte
closed-log prefix contained no CR/LF, so it is not arbitrary binary safety.
Current collector is incompatible and remains held from live use.

Supported read-only commands, card mount/free-space parsing and memory were
recorded. Small negative sh -n control worked; full launcher syntax request
was refused as too long, so full syntax/runtime remain unverified. Boot ID,
stock PID 118/start ticks 418/hash 0fed..., absent test flag, installed old
launcher/candidate and persistent log hashes stayed unchanged. Post-reboot
stock memory is not evidence proving the earlier MOVE reboot cause.
See [complete device observations](folderfollow-move-device-compatibility.md).
Next gate is a separately authorized legacy-safe bounded transport/metadata
design, not installation or a weakening of source identity checks. No
functional script change, firmware change, commit or push in this step.
