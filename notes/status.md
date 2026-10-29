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
identifies the deep Show No Mercy release, cue 0/0, sampled total folder count
13 (`cache_count` wire field, clarified on 2026-10-05) and y=0.
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

### Bare-stock scrolling comparison (2026-10-01)

After migrating the project and ignored evidence to the current computer,
read-only device checks found stock PID 116, original `0fedb30f...` executable,
and no one-shot flag. Roots, nested Slayer releases, and Sleep are on the card.
The installed but inactive MOVE candidate remains `15cf4457...`; it was not
rearmed, started, replaced or signalled.

The requested Show No Mercy test was completed: physical Next advanced beyond
the visible rows without scrolling; manual scrolling revealed the highlighted
playing track and volume worked. This reproduces the symptom on unmodified
firmware, independently of the earlier golden-plus-probe runs. See
[stock baseline](folderfollow-scroll-diagnosis.md#unmodified-stock-comparison-2026-10-01).

The next local work prepares an explicitly framed ASCII transport and strict
identity checks for the legacy ADB environment. Initial read-only controls
confirmed `od -An -v -tx1 -N`, numeric colour-free `ls -Lndi`, `test -ef` for
both equal and different files, and mountinfo. Kernel fdinfo has no `mnt_id`;
that limitation must be handled explicitly, not silently dropped. No new
firmware or launcher installation is implied by these transport checks.

### Legacy transport passes stock-only byte controls (2026-10-01)

The legacy collector now uses a bounded ASCII hex envelope with explicit
nonce/completion/remote status, a separately held read FD and strict
pathname/player FD9/mount/process gates. The original native protocol and
strict record acceptance are retained. Encoded and decoded partial evidence
survive failed transfers; there are no device copies or automatic retries.

Actual stock controls passed all 256 byte values plus explicit CR/LF/NUL/FF,
an intentional remote exit status 37, and a 64-KiB closed-log prefix compared
with the known local recovery. Paired probes preserve the same stock PID 116,
boot/starttime, absent flag and installed/log hashes. Evidence is under
`artifacts/legacy_compatibility_20261001/`. See
[protocol, exact controls and limits](folderfollow-move-legacy-collector.md).

This removes the demonstrated byte-transport blocker, not the unexplained
MOVE reboot or missing auto-scroll. Full device launcher syntax/runtime and
a supervised live MOVE collection remain unvalidated. No device file write,
firmware installation, rearm, signal, reboot, commit or push in this step.

Final local validation: all 161 tests pass without skips (55 new tests),
all 62 Python scripts compile, and whitespace checks pass. The MOVE tests
now locate the preserved imported reference instead of silently skipping
six ELF-dependent cases due to the old workstation path. Firmware and
evidence-launcher hashes are unchanged.

### Full launcher syntax and read-only prerequisites pass (2026-10-01)

Following the user's request to check, the exact 6,535-byte evidence launcher
passed device `sh -n` with matching SHA-256, explicit remote status 0 and no
diagnostics. Compression plus stdout-only uudecode fits the old ADB command
limit (3,769 bytes). A nonexecuting valid control and rejected invalid control
passed first. No launcher source was installed, sourced or executed.

Required commands, direct rw card mount, 5,928,296 KiB free, executable/access
checks and selected safe BusyBox runtime primitives passed. A bounded host
backup of the current 817-byte installed launcher verifies as `522f0b1b...`;
the older migrated backup is a different version and remains preserved.
Paired probes preserve stock PID 116/boot/starttime, absent test flag and all
installed/log hashes. Evidence: `artifacts/move_launcher_preflight_20261001/`.
See [preflight scope, controls and remaining decision](folderfollow-move-launcher-preflight.md).

No device output file write, firmware/launcher replacement, flag creation,
signal, reboot, live MOVE run, commit or push occurred. Full launch/recovery,
output growth and the earlier spontaneous reboot remain unvalidated; an
actual one-shot run requires separate authorization.

### Launcher preflight final local validation (2026-10-02)

The interrupted final validation was rerun: all 183 repository tests pass
without skips, including 22 new preflight tests; all 64 Python scripts
compile and whitespace checks pass. Independent review verified the raw
device controls and exact installed-launcher backup without claiming a live
launch. No new device call, installation, flag write or reboot was made in
this continuation. The read-only check is complete; actual one-shot launch
and its known reboot risk remain a separate user decision.

### Authorized first supervised MOVE run (2026-10-02)

The user explicitly approved installation and testing. Fresh preflight passed;
the exact launcher `1cdfed54...` replaced backed-up `522f0b1b...` through a
verified same-filesystem staging rename. Candidate `15cf4457...` is unchanged.
One-shot boot launched PID 141/start700 in a fresh card run. The legacy host
collector accepted a 341,248-byte live prefix; the later closed log contains
1,503 snapshots and 16 settled/loss-free events (3 setters, 13 refresh).

Next advanced cue 0→5 while scroll_y remained zero. All instrumented setters
were earlier absolute zero-to-zero calls; none occurred during that cue
progression. User confirmed offscreen highlight/working volume, then clarified
that manual scrolling was not performed. A manual positive control remains
missing; no auto-scroll fix or probe-failure conclusion is justified yet.

An identity-guarded SIGTERM ended only the diagnostic child at uptime 207.68
(about 200.68 seconds after child start, exceeding the intended 180-second
window by 20.68 seconds). Supervisor recorded raw wait 255 and recovery intent;
stock PID 119/hash 0fed... returned after reboot, flag absent. All 21 closed-run
files were pulled and verified against device SHA-256. Old logs are intact;
new launcher stays installed, unarmed. No spontaneous reboot was observed,
but the prior cause/general stability remains unproven. No second run/rearm.
See [full run evidence and remaining control](folderfollow-move-supervised-run-20261002.md).

### Manual-only positive scroll control obtained (2026-10-02)

The user explicitly approved a second short run and confirmed down/up manual
scrolling with playback not started. Unchanged launcher/candidate booted
PID 142/start 665 in a fresh run; the flag was consumed. Strict closed decode
accepts 753 snapshots and 96 events with no loss: 79 nonzero relative setters
all move the matching Show No Mercy Files viewport. Requests come from
0x4BA67C/0x4BA5FC, with new_y=old_y+request and trajectory 0→385→−28→0.
Four timer-20 refreshes follow changing offsets. Cue is 0 and playback empty,
not an active first track. The whole 21-file run was hash-verified after pull.

Together with the first run's cue 0→5 / unchanged y / absent setter calls,
this supports a missing reveal request on the measured Next path. The setter
and its instrumentation work in Files. However, raw extent remains zero and
flags are 0x2, so automatic target bounds must not rely on that field or on an
assumed generic clamp. Safe row identity, UI-thread/lifetime and one-shot
playback-change policy remain necessary for a patch.

After user completion, an identity-guarded SIGTERM at uptime 111.14 ended
the child (~104.49 seconds after start). Wait status 255/SIGTERM evidence and
recovery intent were retained; stock PID 115/start 361/hash 0fed... returned,
flag absent. No spontaneous reboot, new firmware patch, third run or rearm.
See [manual control and comparison](folderfollow-move-manual-control-20261002.md).

### Local one-shot reveal model and ownership audit (2026-10-05)

Implemented `scripts/folderfollow_reveal_model.py`: a host-only executable
policy over immutable, coherent snapshots, not a firmware patch. It confirms
a new exact path/cue identity, resolves its unique row in a completed bounded
folder fill, computes a minimal checked/clamped target, and consumes each
transition once. Manual input (including an ongoing gesture), navigation,
generation changes, invalid geometry and expired readiness cancel the action.
Inactive/mismatching-folder changes do not cause delayed snap-back on return.
Final snapshot revalidation is explicit but is not a synchronization primitive.
Folder navigation/descent and a live adapter are not implemented here.

Corrected telemetry interpretation: historical `cache_count` is P+0x1E0,
the total folder count published before fill, not actual primary-list count
L+0x0C or evidence of completion. Existing wire names/layouts and diagnostic
firmware bytes are unchanged. Property-24 getter copies the full 0xA88-byte
descriptor; it must never receive a path-sized output buffer.

The bounded static audit found a real Files fill worker and its T+0x10 mutex.
It also established that private-worker teardown destroys that mutex and T
before removing V from the controller registry. A raw active-view lookup plus
worker lock is therefore not an established lifetime-safe adapter. List
reset, binding changes, raw-pointer writes and all manual-intent paths still
need a common ownership/invalidation contract. The narrow offset setter's
invalidation callees are arithmetic-only, but the entire refresh transaction
and safe acquisition of the owner remain separate prerequisites.

Validation: **249 repository tests pass, no skips**, including **56 new model
tests and 10 static contract tests**. All **67 Python scripts compile**;
whitespace checks pass (Git only warns about existing LF/CRLF conversion).
The static tests require the exact preserved reference hash and fail rather
than silently skip if it is absent or different.

No device access, new firmware build, installation, rearm, reboot, commit or
push in this step. Last verified stock recovery remains the 2026-10-02 result,
not a fresh assertion about the live device. See the
[model and limits](folderfollow-reveal-model.md) and
[worker/lifetime findings](folderfollow-reveal-ownership.md).

### Scalar MIPS reveal core and UI/gesture dispatch (2026-10-06)

Resumed from clean, pushed `bc2d56e`. Implemented
`scripts/folderfollow_reveal_mips.py`: 216 bytes of position-independent
MIPS32/O32 geometry code, not a patched ELF. It reads only the fifth scalar
stack argument, writes no memory, makes no external call and rejects invalid
rows, dimensions, overflow and manual overscroll. Seven instruction-execution
tests compare it with the model across over 20,000 cases, preserve the stated
ABI, check four relocation bases and enforce an instruction allowlist.
Independent review found no current arithmetic/ABI defect; its proposed
allowlist strengthening was applied. Hardware/pipeline/caller behavior is not
validated, and no live object adapter is included.

The bounded follow-up established a synchronous music activity chain:
init -> event/timer loop -> teardown, with the controller transition after
activity return. Timer dispatch itself does not acquire a mutex or make
removal a callback-completion barrier. The general Files-capable list reset
was then resolved as queued event 0x11A: 0x454200 -> table 0x926C4C/50 ->
0x452400 -> 0x491240. Music loop 0x43C980 dispatches this queue at 0x43C9A4,
before timer pump 0x43C9E4, establishing this particular route's serial
ordering. This does not prove every invocation's thread, both path-special
reset callers or background-refill serialization.

Gesture dispatch now distinguishes initial hit/contact (event4/0x49B460),
movement (event9/0x49B000, including synthetic inertia), release/settling
(event10/0x49B1A0), row activation (event7/0x49E560), and animation completion
(event100/0x49E7E0). The release handler may start inertia, and abort paths
do not establish event100 delivery. No existing scalar field is yet a proven
whole-interaction `manual_active` input. Five new static tests pin timer,
activity-transition, gesture-binding and queued-reset anchors without claiming
global thread safety.

Validation: **261 tests pass, no skips**; all **69 Python scripts compile**;
whitespace checks pass. New work is local and uncommitted in this step.
No device access, firmware image build, installation, rearm, reboot or push.
The safe owner/completion/cancellation adapter remains the next integration
gate, not another repetition of the old manual-scroll hardware test. See
[MIPS core](folderfollow-reveal-mips-core.md) and
[dispatch findings and precise remaining paths](folderfollow-reveal-dispatch.md).

### Copied-row publication protocol and narrowed integration contracts (2026-10-07)

Resumed from clean, pushed `5d9ce6a`. Added host-only
`scripts/folderfollow_reveal_publication.py`: one validated, bounded whole
fill per externally verified content generation. It copies exact path/cue
identities, checks every append, separately requires terminal 101 and matching
end/actual/total counts, and publishes immutable `CompletedRows` only after
completion. Reentry, incomplete/error events, duplicates and reported loss
invalidate the generation. Non-reused tickets reject late old events without
relabeling them as a new view, and exhaustion never wraps. A new activation
requires a strictly increasing content epoch, including across view changes.

This protocol consumes serialized, already-owned inputs. It is **not** a
thread-safe mailbox, MIPS hook, epoch acquisition mechanism or installable
firmware. The event bridge must invalidate before every relevant mutation,
report uncertainty and retain the target through the UI operation. Existing
historical FILL logs and live diagnostic formats/builders are unchanged.

The static pass closed several narrower questions:

- Normal stationary release clears G+0 before callbacks; a completed long
  press can release with neither event 10 nor 100. G is recognized software
  contact, separate from capture/animation. Orphan input, physical-input lag
  and H/G lifetime remain explicit limits; no live reader was installed.
- Both path-special reset conditions and the normal dialog-completion route
  are mapped. Their dialog mutex is not the Files worker mutex. Ordinary
  Files scopes can still undergo destroy/recreate in the containing operation.
  The raw descriptor rewrite uses substring guards and cannot be excluded
  for every Files path solely by type.
- The worker post-fill callback invokes P+0x410 and rebinds P+0x1BC under
  T+0x10. Render-side binding occurs before enqueue locking. Post-fill/wake-up
  also occurs without a verified successful complete query; stock append and
  terminal results are discarded at known points. This motivated the separate
  copied-row publication protocol instead of trusting a completion flag.
- The property-24 getter uses the real B+0x44 mutex. Two synchronous
  Next/Previous callers share its bracket, but the separate general event-9
  commit is not established to share it. Stable repeated reads remain a
  filter, not proof of a coherent copied identity.

Validation: **311 repository tests pass, no skips**, including 128 reveal
tests (22 new publication-policy tests and 43 total static-contract tests).
All **74 Python scripts compile**; whitespace checks pass. Tests exercise
all one-row event permutations, the 512-row bound, cancellation at every
fill stage, stale events, loss, reused epochs and pre-action cancellation.
They do not emulate stock concurrency or establish device safety.

No device access, firmware image build, installation, rearm, reboot, commit
or push in this step. Changes remain local. The next live-integration gate
is the owner/generation/invalidation event bridge, coherent playback
publication and retained UI target; no additional manual-scroll test is
requested. Last verified device state is still the October 2 recovery,
not a fresh live assertion. See [contact](folderfollow-reveal-contact.md),
[scope](folderfollow-reveal-scope.md), [publication](folderfollow-reveal-publication.md)
and the updated [dispatch constraints](folderfollow-reveal-dispatch.md).

### Passive MIPS event bridge built and verified (2026-10-08)

Connected selected Files fill, playback-copy, recognized-contact,
close/reset and current-refresh sites to a single private copied-event
buffer in a real ELF. The timer exports only private records and calls its
stock callback once. Added a strict decoder, deterministic builder/verifier
and separate RX/BSS layout helper. No setter, view lookup, additional query,
folder rebuild or stock-object retention was added. The reveal policy and
geometry core are **not enabled**; this is diagnostic capture, not the fix.

Built and verified local Git-ignored artifact:
`artifacts/hiby_player_1.4_sortfix_fullnav_wake_reveal_bridge_capture_20261008.bin`
(7,146,848 bytes), SHA-256
`7cc98a67a32dabce3b4d22b50b8dc847f5462d99d70d0ee04254a0ec272439a9`.
Baseline is normalized golden sorting/fullnav/wake, without folder-follow.
The old cave is untouched; a new RX load contains 3,424 code bytes and the
existing RW load gains 606,272 private buffer bytes plus alignment padding.
Loader acceptance, heap placement and runtime overhead remain untested.

Validation: **394 tests pass, no skips**, including 83 new bridge tests;
all **82 Python files under `scripts/` compile**. Instruction-level tests
exercise original calls exactly once, volatile/HI/LO preservation, delayed
branches, invalidated playback sources, short key packets, queue loss,
bounded copying and export. Three tests decode bytes emitted by the actual
new hook/timer instructions, including a complete producer window. This
does not emulate concurrency or establish stock-object lifetime safety.

Remaining gates are retained UI ownership/generations, full invalidation
coverage, coherent playback and whole-folder completion, then active
cancellation/reveal dispatch. A separate launch/recovery review is also
needed for the new ELF layout. No device access, installation, launch,
rearm, reboot, commit or push in this step; changes are local. See
[bridge format, artifact, validation and limits](folderfollow-reveal-bridge.md).

### Bridge launch prepared; read-only device preflight passed (2026-10-08)

Prepared a separate boot-only bridge launcher with a new candidate path,
one-shot flag and evidence directory, exact SHA/size admission checks and
a device-side best-effort 45-second TERM / 5-second KILL / 5-second recovery
reboot schedule. Signals require matching parent/child PID, start token and
live executable hash; the watchdog performs no card writes. There is no
direct stock fallback after any possible diagnostic launch and no retry.
Shell timing, check-to-signal races, I/O and reboot failures remain limits.

Read-only preflight passed on the connected RS2. Full launcher source
(5,769 bytes, SHA-256
`850691851dbf5cabbd244bae222e958e70885386e35ac6d425bd35f35342e32b`)
passed device syntax checking without execution, plus selected shell and
process-identity controls. Preserved an exact 6,535-byte backup of the
currently installed `1cdfed...` launcher in
`artifacts/reveal_bridge_preflight_20261008/installed_launcher.bin`.

Before/after: stock PID 116/start ticks 353, parent 105, boot
`29694ad6-f042-4245-8213-ecc0d3329140`, original `0fed...` live/on-disk hash;
both old and new flags absent, new candidate pathname absent, installed
launcher and old MOVE candidate unchanged. Card and data mounts were rw,
with 5,925,016/19,236 KiB free respectively. These current observations
replace the October 2 recovery only as the latest read-only device check,
not as a new diagnostic run or validation of memory headroom.

Validation: **449 tests pass, no skips**, including 24 launcher and 31
preflight tests; all **85 Python files under `scripts/` compile**. No
device-file writes, installation, arm, player signal, launch, reboot,
commit or push occurred. Next separately authorized action is staging and
one short loader/capture smoke test, initially without user interaction;
autoscroll remains disabled. See
[launch preparation, exact artifacts, evidence and execution checklist](folderfollow-reveal-launch-preparation.md).

### First bridge loader/timer/recovery smoke completed (2026-10-08)

With explicit user authorization, installed the exact bridge candidate
`7cc98a67...` at its separate `/data/hiby_player_reveal_bridge_7cc98a67` path
and the checked `85069185...` launcher at `/ui_data/player`, preserving a
fresh hash-verified old launcher backup. Armed only the new one-shot flag
and requested one boot-path test; no manual launch over stock or host
player signal was used.

Test boot `0753d7d3-2b0f-4490-895b-15cf7daeb675`, child PID 143/start 720,
confirmed the exact live ELF, private FD9 log and consumed flag. New RX
`0xC70000..0xC71000`, extended BSS and heap at `0xC71000` were observed
without overlap. The supervisor retained raw wait status 255, stdout
explicitly reported SIGTERM, and recovery status was 0/reboot_requested=1.
This agrees with the configured watchdog stop; an exact duration was not
measured from the evidence.

Recovery boot `c057dbc2-0cd2-4616-a6b0-5267f5862f92` runs original stock
PID 120/start 367/hash `0fed...`; no diagnostic child and both flags absent.
The installed new launcher/candidate remain **unarmed**. Original executable,
stock wrapper and old MOVE candidate hashes are unchanged.

All 9 closed run files (15,391 bytes) were copied directly to the host with
matching before/after remote and local size/hash checks. `bridge.bin` is
9,344 bytes, SHA-256
`947937251cdf94b620157b4112e71f712bf1832d71592773d02a4e79bf8d19a8`.
Strict decode accepts 292 intact RBST statuses, all counters/loss flags zero,
but **zero RBRG events**. This validates loader/timer/export/recovery only,
not Files/playback/contact hooks, volume behavior or autoscroll. Player
stderr contains 145 bytes of device warnings without a matched stock
baseline; supervisor/wait error files are empty.

No second run, rearm, firmware source change, commit or push. Existing
449-test validation remains the source baseline; the narrow hardware result
and limits are in [the smoke report](folderfollow-reveal-smoke-20261008.md).
Next separately authorized step is a bounded interactive event capture.

### First nonempty bridge event capture; scrolling/volume still pending (2026-10-12)

Read-only installation recheck passed; no reinstall/source change required.
A premature first run captured only timer statuses; the user confirmed no
actions occurred. The user now requires **instructions, then stop and await
explicit readiness before every launch**, and a stop after launch until the
user reports the outcome. Folder positioning alone is not readiness.

After a fresh `готов`, a separate unchanged 45-second run captured 139 events
and 296 statuses with an accepted prefix, no decode errors, no loss flags,
and final reserved=drained=139. Five completed Files windows include Show
No Mercy's 13 CUE entries; three accepted playback-copy pairs observe CUE
0 -> 1 -> 2. There are also 82 touch, 13 refresh and one view-close records.
These establish narrow capture coverage, not active autoscroll or complete
UI lifetime/identity guarantees.

The user did not have time for manual scrolling or volume; both remain
untested in this run. Nine closed files (98,586 bytes) have verified local
and before/after remote hashes. Recovery boot
`2eda0476-9c57-4fae-a509-255a6e1b13c7` runs stock PID 120/start 368/hash
`0fed...`; both flags absent and installed hashes unchanged. No rearm,
timer extension, firmware change, commit or push. See
[interactive result, evidence and readiness protocol](folderfollow-reveal-interactive-20261012.md).

### Manual scroll/highlight/volume follow-up passed (2026-10-12)

A separate explicit readiness confirmation authorized one unchanged short
run focused on scrolling and volume, without Next. The assistant stopped
after launch until the user's report. The user explicitly confirmed manual
down/up scrolling, preserved highlight and normal volume adjustment.

Capture is intact: 268 events and 304 statuses, accepted prefix/no errors,
final reserved=drained=268, no loss flags. Five completed Files windows,
one playback-copy pair for CUE 0, 206 touch and 22 refresh observations;
refresh offsets include 0 -> 270 -> 533 -> 328 -> 0 and 0 -> 214 -> 0.
Nine closed files (175,024 bytes) passed remote pre/post and local size/hash
checks. Visual highlight/volume correctness comes from the user's report,
not the trace alone; following Next and active autoscroll are not established.

Latest stock recovery boot `985e1da1-643c-4f86-ab44-1a76edbf537b`,
PID 120/start 369/hash `0fed...`, both flags absent and all installed hashes
unchanged. Candidate remains installed but unarmed; autoscroll is disabled.
No firmware/timer change, extra run, commit or push. See the follow-up section
of [the October 12 report](folderfollow-reveal-interactive-20261012.md).

### Host cancellation coordinator and narrowed live boundaries (2026-10-13)

Added host-only playback publication and a coordinator joining it to the
existing copied-row publication and reveal policy. Mutation BEGIN withdraws
authority and advances a non-reused revision; only its matching END can
publish. Actual clear is separate from a transient in-flight gap. Overlapping
writers, duplicate/late completion, loss and exhaustion fail closed. View,
content and gesture events revoke one-use proposals even after same-value
writes or A-to-B-to-A changes; stale/copy/foreign handles do not confer owner
authority. No live hook, firmware mailbox or setter invocation is implemented.

Independent review found a cancellation hole after an owner/content reset:
an unobserved track publication followed by a complete manual gesture could
become eligible at the first observation. Interaction changes now consume
that publication, and an in-flight fence handles gestures/lifecycle changes
between playback BEGIN and END. Twelve event-order regression cases ensure
that a gesture wholly before a later track change does not disable that new
transition, while overlapping or later gestures consume it.

The static follow-up pins two previously uncovered playback clear mechanisms,
the initialization extent, a potential scalar cue setter (without identified
direct property-17 use), and a general-copy caller whose source aliases the
current descriptor. It also resolves both deferred and synchronous object
close consumers: the latter includes Files navigation, and the timer does not
inherit the preceding controller lock. These are concrete integration limits,
not proof of complete writer coverage, runtime thread identity or retained UI
lifetime. See [playback boundary](folderfollow-reveal-playback-boundary.md) and
[UI owner boundary](folderfollow-reveal-ui-owner-boundary.md).

Validation: **530 tests pass, no skips** (79.502 s), including 81 new
coordinator/publication/static-contract tests. All **91 Python scripts compile**;
tracked and new files pass whitespace checks. The tested coordinator remains
an executable serialized-input contract, not an active firmware adapter.

No device access, firmware image build, installation, arm, launch, reboot,
commit or push occurred in this step. Changes remain local. The October 12
stock recovery is historical evidence, not a fresh statement about the live
device. Next work is coherent all-relevant-writer publication and lifecycle
invalidation within a retained UI transaction; another manual-scroll control
run is not requested. Details and the required readiness/launch protocol are
in [the coordinator report](folderfollow-reveal-coordinator.md).

### First firmware-connected mutation guard; active reveal still refused (2026-10-13)

At the user's request to connect the logic safely, implemented a 280-byte
MIPS atomic mutation guard and integrated it at nine original writer sites
in a separate offline ELF. Its packed private word withdraws readiness before
mutation, issues bounded non-reused tickets, accepts only matching completion,
and permanently faults on overlap, mismatch, exhaustion or bounded LL/SC
failure. READY is only instrumented-mutation completion, not a copied identity
or UI authority. Stock operations still execute once after guard failure.
No UI setter, pointer lookup, extra stock read or timer work was introduced.

Further static inspection found two more descriptor copies inside the general
commit (`42CF84`, `42D398`), beyond the old bridge's three. All five known
copies, preparation path clear, scalar cue store, full clear and initialization
are guarded with exact original delay-slot semantics. Descriptor address
escapes through the getter and indirect callbacks still require consumer
classification. A general transition can clear and recopy its item; interpreting
each mutation as a completed stop/new track would incorrectly reset policy.
Refresh also has a render-callback route, so an arbitrary intra-refresh offset
change is not yet admitted. These gates prevent enabling the full coordinator.

Built and independently verified local ignored artifact:
`artifacts/hiby_player_1.4_reveal_guard_stage_20261013.bin`, 7,145,148 bytes,
SHA-256 `c8b6d9544bfccf98375efb871029e5fbb6d292e17f3a198f2eaa06578b12749d`.
Added code is 1,724 bytes at BE0000; state is four bytes at BD4000 plus segment
alignment padding. Only 49 original bytes differ from normalized golden,
inside declared hooks and ELF fields. Separate RX/RW loads, deterministic
rebuild, strict instruction/transfer inventory and original calls/results
were checked. The old passive candidate/launcher were not changed.

Validation: **558 tests pass, no skips** (85.920 s), all **96 Python scripts
compile**, whitespace checks pass. Independent review exercised all nine
hook variants and found no concrete preservation/relocation defect. Instruction
interleavings test sticky fault/LL-SC behavior but do not prove the target CPU
memory model, loader behavior, stock threading or object lifetime.

This is **partial firmware integration, not an autoscroll fix or a proposed
hardware test**. The builder refuses active reveal; logical-transition grouping,
coherent copied publication and an owned UI action remain unfinished. No device
access, install, arm, launch, reboot, commit or push. See
[guard artifact, evidence and remaining contracts](folderfollow-reveal-guard-stage.md).

### General track-change grouping connected offline (2026-10-14)

Added entry/common-exit hooks around the stock general commit, beyond the nine
raw mutation hooks. Preparation and all three general copies now remain under
one unfinished scope until its matching normal completion. Its fixed original
frame and non-reused ticket are checked; preparation additionally needs its
current helper frame and saved return from the exact general caller. Explicit
writer kind prevents preparation/copy return-address confusion, which a new
regression test caught. Original calls, stores, stack, return value and HI/LO
remain preserved even when instrumentation faults.

Scope completion records exact success/failure (0/-1), not a coherent current
identity. A foreign writer can begin after the exit check and outlive scope
completion; an emitted-code test pins this allowed historical-READY case.
No reader, UI setter, timer, installer or active-reveal path is attached.
The host deferred-update API separately preserves the old policy baseline
through intermediate unknown/clear/recopy state and accepts only a final owned
value. Failed outcome consumes the transition; gesture/navigation cancellation
still fences it, and later new successful changes remain eligible.

Bounded static audits establish the complete normal general-function exit,
classify concrete descriptor consumers, and narrow the non-render refresh
route. They do not close indirect/alias writers, coherent copying or live UI
ownership. The apparent playback-related refresh producer is PNG-resource
completion, not a verified universal Next/autoplay trigger.

New ignored local artifact:
`artifacts/hiby_player_1.4_reveal_grouped_guard_stage_20261014.bin`, 7,146,352 bytes,
SHA-256 `cce0d3ddb5fbee1284f1e47ed6976421b78a9f7b882caea8f363b9a9998a4e57`.
Added code is 2,928 bytes at BE0000; private state is 20 bytes at BD4000 plus
alignment padding. Only 65 original bytes differ from normalized golden,
within eleven hook pairs and required ELF fields. The saved file passed the
standalone verifier. The October 13 artifact still rebuilds byte-for-byte.

Validation: **622 tests pass, no skips** (82.943 s); **100 Python scripts
compile**, whitespace checks pass. This includes 16 grouped emitted-byte
tests, 31 new static-contract tests and 17 new deferred-host-protocol tests.
Independent host review also checked 7,776 short event sequences. These are
offline checks, not hardware or whole-program concurrency certification.

**Still partial integration; not a working autoscroll or proposed player test.**
No device access, install, arm, launch, reboot, commit or push. The October 12
device state is historical only. Next: coherent final identity/all-relevant
writers, remaining logical routes, full-row/lifecycle publication and a retained
non-render UI transaction. See [grouped build and exact limits](folderfollow-reveal-grouped-stage.md).

### Synchronous same-file grouping and player-lock audit (2026-10-15)

Extended the offline guard with the narrow synchronous descriptor block in
`42CAC0`: entry `42CBD4`, completion `42CC20`. The whole function cannot use
the general-entry/exit contract because early returns have no frame and
asynchronous fallbacks also return zero without executing the fast copy.
The block has a fixed existing frame, optional descriptor callback and event
posting; all bounded normal routes reach the chosen completion. The trailing
backing-path copy is disjoint from the current descriptor.

General and fast scopes now use explicit kinds as well as original frame and
non-reused ticket. Wrong-kind inner copies, preparation in a fast scope, wrong
exits, overlap and unrelated writers fail closed; original stock operations
continue once. Fast completion preserves the arbitrary stock queue-result v0
and records only synthetic block completion, not verified playback success.
It must not be blindly converted to host `succeeded=True` or UI permission.

The stock mutex audit resolved actual pthread imports, null-attribute init and
discarded lock/unlock result handling. Getter/setter and all four direct
same-file callers share B+44, but general commit has no established matching
bracket, full clear follows its helper unlock, and initialization clears before
mutex creation. Calling the getter inside already-locked hooks risks recursive
acquisition without a recursive-mutex contract. No new getter/lock/read was
added. Unknown descriptor callback/alias writers remain an independent gate.

New ignored local artifact:
`artifacts/hiby_player_1.4_reveal_fast_grouped_guard_stage_20261015.bin`,
7,147,040 bytes, SHA-256
`0c587656d2bd169b6763bebf8ddf0f1103f65275b46e1f43f6604718e7f23d72`.
Added code: 3,616 bytes at BE0000; private state: 24 bytes at BD4000 plus
alignment padding. Eighty original bytes differ inside thirteen hook pairs
and required ELF fields. Standalone verification passed. Both October 13/14
build modes still reproduce their earlier artifact hashes exactly.

Validation: **658 tests pass, no skips** (99.516 s); **103 Python scripts
compile**, whitespace checks pass. Thirty-six new tests cover emitted fast
grouping (17), the exact fast-block contract (9), and stock mutex coverage (10).
Independent review found no actionable preservation/grouping defect. These
are offline checks, not target concurrency, loader or timing certification.

Active reveal remains refused. Final identity copying, all-relevant-writer
coverage and an owned full-row/UI transaction are not yet implemented.
No device access, install, arm, launch, reboot, commit or push in this step;
the previously recorded device state is historical. See
[new build and remaining limits](folderfollow-reveal-fast-grouped-stage.md),
[fast boundary](folderfollow-reveal-fast-boundary.md), and
[player-lock audit](folderfollow-reveal-player-lock.md).

### Shared source-finalizer boundary (2026-10-15)

Static tracing found that the fast same-file and general cross-file routes
both call `42CA00`, which finalizes source path/position and posts playback
state. The general route reaches it in its normal-success epilogue after the
open/setup work; the fast route reaches it after its descriptor copy and before
its optional callback/event post. This is a useful shared timing point, but not
a complete row or audible-playback certificate. A similar-looking `+BA0`
callback assignment in the media pipeline belongs to another object and does
not resolve the global player's callback. Source-object lifetime, descriptor
alias coverage, and UI transaction ownership remain open. The playback-state
message is not a substitute: it preserves a global path and player scalars,
not source property 31's backing-file position, and its direct receiver belongs
to the mutating recovery path. No firmware code/artifact or device operation
was performed in this audit. The 116 targeted folder-follow contract checks
passed. Property 31's direct setters are both in the source finalizer; property
32 also has a separate direct constant-value writer that a future owned capture
must fence as reset/invalidation. See
[source-finalizer boundary](folderfollow-reveal-source-finalizer-boundary.md).
Follow-up of the setter-input-copy candidate found that property 31/32 calls
are sequential, the setter does not report whether a live source accepted them,
and descriptor/source generations are not coherently fenced. Private copies are
diagnostic-only, not safe reveal authority. The 116 targeted contract checks
passed again; no firmware/device operation was made.

### Source and descriptor writer-generation recheck (2026-10-15)

Corrected the source-pointer global in the new boundary note to `0xADD360`
(`0xAE0000 + sign-extended 0xD360`), not `0xAED360`. Exact reference traces
show constructor publication at `0x424018` and teardown clear at `0x422B6C`
after destruction at `0x466A80`; no source-shared lock was identified. A
private lifetime epoch could reject our own samples if invalidated before
teardown, but cannot protect an in-flight stock setter from destruction.

The bounded property scan still finds only two direct setter calls each for
properties 31/32; property 24 has three direct callers, while property 17 has
no resolved direct caller despite its store branch. Offset-only path/cue scans
produce many colliding object references, including `+0x104` writes through
`*(a0+0x50)` and `+0x524` writes through a method argument. Their bases cannot
be proven equal to or distinct from B. Escaped D pointer-outs and the unresolved
player callback remain open aliases. A binary-wide `+0xBA0` sweep finds the two
player callback loads but no direct player-slot store; other same-offset
operations belong to stack/pipeline contexts, without excluding bulk/alias
writes. The writer/generation gate is therefore **not closed**; no snapshot is
promoted to active authority. Six exact-source finalizer contract tests pass.
No firmware/device change was made. See
[source-finalizer boundary](folderfollow-reveal-source-finalizer-boundary.md).

Follow-up resolved the second property-32 direct call at `0x5191AC`: it passes
`0x920AB4`, whose first UTF-16 code unit is NUL, so the effective source path
is cleared rather than set to a backing-file path. The method entry is present
as a function-pointer word at `0xAAE660`; no direct branch or `jal` to its
entry was found, so the dynamic caller remains unknown. Added an exact-source
contract check for this reset input. This narrows the known invalidation
semantics but does not close the alias/generation gate or change the reveal
disposition. No firmware/device operation was made.

The follow-up ELF/GOT pass found no symbol/GP metadata or relocation that
resolves the owner. `0x519140` is in a `.data` neighborhood with MSEB, lineout,
and balance UI labels and neighboring code pointers; this is suggestive UI
metadata, not proof of an event binding. Added a hash-gated neighborhood
contract check. Seven exact-source tests pass; no firmware/device operation
was made.

Follow-up on the Files lifecycle boundary resolved the name passed by row
navigation to `0x43B240`: it derives an explorer suffix from UTF-16 path depth
(`vg_listview_explorer##%d`), or uses the unsuffixed explorer name at root,
then closes that exact named object. After the path check at `0x49A240`, only
the zero-result path creates a replacement through `0x491E80`. Added an
exact-source contract for the name formats and ordering. This sharpens one
synchronous invalidation point but does not establish serialization or
complete lifecycle coverage. All 13 UI-owner contract tests pass. No player or
firmware action.

A second lifecycle route was classified: storage-root changes at three direct
sites call `0x495D40` with UTF-16 `a:\\*`, `b:\\*`, or `c:\\*`. That
transaction synchronously calls locked explorer cleanup `0x495A40`, attempts
saved hierarchy restoration and clears property 11, then uses `0x491E80` for
a root fallback only when restoration does not complete. Extended the exact
contract to pin the callers, arguments, and ordering. UI-owner tests now pass
14/14; thread ownership and full lifecycle coverage remain open. No device or
firmware action.

A bounded follow-up classified the 17 direct object-close calls in the
`0x490000..0x49FFFF` range where names were statically recoverable. The branch
at `0x49E66C` closes `vg_listview_m3ulist`, not Folder View; other recovered
names include the music/Tidal search widgets, main category/song list, and
menu. Dynamic call arguments remain unresolved, so this does not classify all
194 direct calls. A second helper at `0x527860` contains the same depth-derived explorer
close/check/recreate pattern, but no direct caller or pointer literal was
found; its only bounded address construction is stored in a local slot at
`0x527CD4` with no reload in the enclosing routine. Treat it as an unproven
reachability lead, not an owner/lifecycle guarantee. Seventeen UI-owner contract
tests pass. No firmware or player operation was performed.

The same caller pass found a generic named-list cleanup path: it walks eight
64-byte names from owner `+0x3BA8`, resolves them through `0x4E5320`, then
synchronously closes named entries. One route matches the static
`vg_listview_main_explorer`; other close branches pass slot-derived names.
This adds a concrete main-explorer invalidation route and a possible route for
other names present in the slots, but does not prove the per-depth explorer
name is present or establish a common UI thread. Eighteen UI-owner contract
tests pass; the UI-owner gate remains open. No firmware/player operation was
performed.

The storage-switch cleanup at `0x495A40` was then decoded and pinned: it scans
view names under the controller mutex for the `vg_listview_explorer` prefix,
copies up to 30 names into local 64-byte records, unlocks, and only then
synchronously closes those names through `0x43B240`. `0x495D40` calls this
before restoring the saved path and clearing the selected-item property. This
concretely covers storage-switch invalidation for the explorer-name family,
but not all Files lifecycle routes or their UI-thread ownership. Nineteen
UI-owner contract tests pass; the UI-owner gate remains open. No
firmware/player operation was performed.

The main-explorer opening route at `0x49DDC8` adds another synchronous cleanup
boundary. Before creating `vg_listview_main_explorer`, it calls `0x495260`,
which walks the controller's ordered view list at `+0x298` (also enumerated by
`0x4E5560`). The registration/destruction path resolves the list membership:
`0x491E80` stores the supplied owner at view+`0xD4`, creates the named list
widget at view+`0xCC`, and registers the view through `0x4E5280(owner,view)` in
that same list under the owner mutex. `0x495260` copies each registered
widget's name and synchronously closes it; destructor `0x493AC0` removes the
view from its parent list through `0x4E54A0` under that mutex. Thus a Folder
View created through `0x491E80` is covered when it shares the owner passed to
this cleanup. The October 16 follow-up below resolves owner propagation for
the ordinary constructor-bound callbacks and corrects the earlier missing
static-reference claim. The cleanup scan itself does not lock the list; it
closes synchronously and restarts from the head, which does not protect
against concurrent mutation. Twenty-one UI-owner
contract tests pass; the UI-owner/thread gate remains open. No firmware/player
operation was performed.

Caller-scoping also resolved `0x495060`'s fixed-name branches: its four
direct `0x49D000` callers name music album/song views, and its other fixed
caller names `vg_listview_songs_of_format`. The remaining syntactic call at
`0x49D18C` is inside `0x49D0E0`, for which bounded direct-caller,
address-construction, and aligned-pointer scans found no reference; keep it
unresolved rather than labeling it dead or an explorer route. Twenty-one
UI-owner contract tests pass. The lifecycle/thread ownership gate remains
open; no firmware/player operation was performed.

2026-10-16: Corrected the callback-reference conclusion. The handlers are
stored in data tables: main-category `0xA9D944 -> 0x49DCC0`, main-explorer
`0xA98970 -> 0x49D3A0`, and explorer `0xA98B7C -> 0x49E560`. The config
lookup copies these tables into the constructor and binds event 7 to
resource+`0x160`. `address-xrefs` only scans executable address forms;
`word-xrefs` finds the data pointers. The tool's scope label now states this.

Constructor and dispatch tracing proves `O+0x50 = V+0xD4 = supplied U` for
ordinary `0x491E80` views: `0x43AD00` passes U through descriptor+`0x34`,
`0x8B4120` stores it in O+`0x50`, and the event wrappers preserve O as the
handler's second argument. Main-category, storage restore/fallback, and Files
row navigation propagate U into subsequent view creation, so the standard
chain's owner identity is resolved. The input route also runs synchronously
through `0x43CA2C` and returns before the loop backedge to queued work and the
next timer pump. Broader thread uniqueness, alternate entry/rebinding,
unlocked-cleanup concurrency, and worker lifetime gates remain open.
Twenty-three UI-owner contracts pass; no firmware/player operation.

### Worker cancellation and last-use boundary (2026-10-16)

The worker audit now distinguishes master jobs from separately copied work
records. Shared cancellation disables master callbacks and clears work count,
but does not revoke an already-borrowed work record; its callbacks can begin
after cancellation returns. Private stop destroys/frees the wake semaphore
before waiting for completion, leaving a separate stop-read/`sem_wait` window.
Both are static interleaving counterexamples, not observed device failures.
Normal startup has a conditional handshake before constructor return, but
zero return also has a no-worker path and is not a success certificate.

Ordinary Files prefill is confirmed NULL; its actual runtime worker mode
remains unresolved. Constructor/render use shared mode for resource+`0x74==1`,
whereas destruction uses any nonzero value; the adapter must not conflate
them. Active reveal remains disabled. All 37 targeted contracts passed,
including 13 new lifecycle checks; the new script compiles and whitespace
checks pass. No firmware/artifact or device operation was performed.
See [worker-lifecycle boundary](folderfollow-reveal-worker-lifecycle-boundary.md).

The follow-up resolves fresh resource initialization: `lg_viewgroup` allocates
`0x178` zeroed bytes, copies only a `0x20`-byte prototype header, and its
constructor leaves mode `+0x74` zero. The inspected parser preserves the
resource pointer; default zero selects the private worker while unchanged.
Its unbounded name copy still needs valid terminated input evidence, so the
factory default is not automatically certified for the full parser output.
All five known direct setters to mode 1 are registered to other loaders,
not ordinary explorer's `0x49E360`. This narrows the initial-mode gate but
does not certify a reused/current resource or retain it through teardown.
Old diagnostic formats omit the field, and standalone heap/data dumps lack
base/capture provenance; no runtime value is inferred from them. Five new
hash-gated contracts cover factory initialization, constructor writes, parser
pointer registration, inspected attribute-helper fields and setter-to-loader
scope. All 42 targeted checks passed (18 lifecycle, 18 original static and
6 publication); compilation and whitespace checks passed. No device/firmware
action; the changes remain local and uncommitted.

The first authorized read-only device probe found original stock PID 124
(`0fedb30f...`) and demonstrated bounded process-memory reading without
stopping it. Both controller roots matched; repeated list/header reads found
only `vg_listview_all`, no registered explorer. Folder View's mode was not
read or inferred. Boot/start/hash/maps remained unchanged; evidence is saved
locally in `artifacts/worker_mode_readonly_20261016_all.json`. No install,
test launch, signal, device write or reboot. Further acquisition awaits the
user opening Folder View and confirming readiness; use fresh addresses then.

After the user opened Show No Mercy and confirmed readiness, a fresh read-only
probe observed two registered explorer levels, including the USA-edition
directory, both with resource mode 0. Each private-worker pointer's owner and
marker matched the audited layout. All 18 object-memory reads (1,796 bytes
per pass) matched on repetition; PID/start, boot, stock executable hash and
full maps stayed unchanged. Evidence is saved locally in
`artifacts/worker_mode_readonly_20261016_show_no_mercy.json`.

Thus the target's observed mode is private, not merely a factory-default
inference. This is run-specific sequential evidence, not a permanent mode
invariant, proof of live pthread startup or a lifetime lease. The earlier
private stop/wake-object limit still applies. No device mutation, install,
test launch, stop, signal or reboot; active reveal remains disabled.

### Two-phase host contents revocation (2026-10-16)

Implemented `begin_contents_change` / `finish_contents_change` in the host
coordinator. BEGIN removes rows/generation/proposals before mutation; END
requires the exact outstanding handle and explicit outcome, then publishes
only a fresh generation, not ready rows. Close/reopen and stale results cannot
revive old authority. Overlap/protocol mixing/unknown outcome fail closed;
tracks and gestures during the gap are consumed, while a later new transition
still works. Capturing rows from inside the stock operation needs separate
operation-bound staging and remains unimplemented.

Pinned a nonnull pre-close lead at `0x493B0C` before the closing marker and
earlier reset/scope/worker-refill boundaries. No hooks were emitted. Corrected
the old `0x4919E0` equal-depth no-op assertion: `0x491E2C` goes into reset,
not directly to return; valid-input reachability/semantics remain unproved.
The helper bytes match preserved stock and `02fd` reference. The earlier
historical status entry recording the no-op conclusion is superseded by this
correction and `folderfollow-existing-view-contract.md`.

Eighteen new lifecycle behavior tests and six source contracts passed; the
349-test reveal-focused run plus the six new contracts gives 355 passing
checks. Independent host review found no defect. These are local sequential
model/static checks, not runtime ownership or hardware safety certification.
No device access, firmware artifact, install, launch or reboot in this step;
active reveal remains disabled and changes are uncommitted. See
[coordinator](folderfollow-reveal-coordinator.md).

### Operation-bound host row staging (2026-10-16)

Implemented a persistent private row collector for one fill within the exact
outstanding contents-change phase. Public generation/rows stay absent until
matching successful END. Staging retains existing completeness/terminal/count
checks and adds exact parent-folder matching; wildcard/nested/mixed-scope
shapes are refused. Successful transfer reuses the ordinary validator and
consumes the generation's single-fill allowance, without querying the device.

Current promoted-job duplicate events now revoke rows and proposals, while
canceled older phase/owner callbacks remain ignored. Explicit subsequent
mutation invalidates staging, including after fill completion. Failed or
poisoned staging cannot silently fall back to generation-only readiness;
no-staging END compatibility is preserved. Original producer/query/destination
provenance, complete mutation reporting, thread handoff and real UI ownership
remain bridge obligations, not consequences of these host handles.

All 143 focused host tests passed, including 26 new staging cases. Independent
review found no readiness/handle bypass. Compilation and whitespace checks
passed. No device access, firmware/artifact build, install, test launch or
reboot; active reveal remains disabled and changes are still uncommitted.
See [coordinator staging](folderfollow-reveal-coordinator.md).

### Original fill/job provenance audit (completed 2026-10-19)

Separated the initial synchronous Files loader (`config+0x104=0x49E360`)
from the adjacent widget callback (`+0x16C=0x49CC80`) and NULL worker prefill.
Pinned original query destination/window/scope arguments and producer frame
carriers, plus both initial and later job ingress, master-to-work copying and
callback dispatch. Corrected the earlier worker note's loader label.

The worker carries original raw P/V words but Files resolves V/P anew by
name; its query destination comes from that resolved V, whereas scope comes
from the old copied job. A callback-time name or pointer match is therefore
not an original-operation association or a retained lifetime. Current global
query selectors are additional inputs, not frozen by the copied scope. No
new host receipt registry was added merely to move that trust assumption.
Native sidecar/copy association, invalidation, serialized delivery and actual
UI ownership remain open; active reveal is disabled.

Added 14 hash-gated provenance contracts. A 388-test reveal-focused run and
seven later-added checks passed (395 distinct checks); the separate 165-test
structural run is included in the 388, not counted twice. Independent review,
compilation and whitespace checks passed. No device access, binary build,
installation, launch, rearm or reboot. All changes remain local/uncommitted.
See [original-provenance audit](folderfollow-reveal-provenance.md).

### Native original-invocation transport (2026-10-19)

Implemented a separate offline MIPS stage, not just another host model.
Master/work elements gain a private four-byte tail while source template and
all prefix copies remain 708 bytes. Native list copies carry the original
invocation ID; separate non-reused borrow/query/producer receipts preserve its
ancestry through actual callbacks. Unknown enqueue origins stay zero/unbound.
No stock field is reused, pointer-keyed registry added, extra query/UI call
made, or host ready-row publication enabled. Fault/exhaustion/uncertainty stops
lineage while original instructions/query continue.

Independent review caught the same-origin/different-work-copy case; exact job
and original-frame checks plus regression tests were added. All 48 new focused
tests pass, including actual native segmented-list growth/copy and hostile ABI
tests. All 117 Python scripts compile; whitespace checks pass.

Saved and verified local ignored intermediate:
`artifacts/hiby_player_1.4_sortfix_fullnav_wake_lineage_stage_v1_20261019.bin`,
7,147,220 bytes, SHA-256
`f31239aa544c55959e9f75686a421489c8ea6d91e1ef6d30b01955d8c75ec139`.
Previous incomplete local output was renamed `.bin.disabled`, not overwritten.
No device access, install, launch, rearm, signal or reboot. Native lifetime,
complete writer/cancellation coverage, contents/playback generation association
and owned UI action remain open. Changes remain local/uncommitted; see
[native lineage stage](folderfollow-reveal-lineage-stage.md).

Final regression for this stage: **806 repository tests pass, no skips**
(134.251 s), including all 48 new lineage tests. Initial sandboxed execution
failed on legacy temporary-directory write/cleanup permissions; a repeat with
local test filesystem access passed, without changing tests or touching the
player. Saved candidate hash remains `f31239aa...c75ec139`; all 117 Python
scripts compile and tracked/new files pass whitespace checks.

### Provenance-bound native row journal (2026-10-19)

Added a separate offline diagnostic stage that captures actual append results,
SQL-step terminal, statement reset and producer END against the original
immutable producer receipt. Native calls still run once with their real
results preserved. Unsupported modes/unbound origins cannot supply row payload;
association failure, allocation/retry loss or exhausted storage permanently fail
closed. Captured-event ordering is separately checked by the decoder; omitted
native hooks are not independently detected. Paths are bounded and
truncated/malformed data is rejected.

The strict offline decoder checks exact ancestry, job/frame geometry and event
sequence, rather than grouping by reused native addresses. It marks only an
observed bounded producer window complete: never a whole folder, host ready
rows or permission to scroll. Reset `0x5C31C0` is distinct from the later
uncaptured wrapper finalization `0x5C30E0`. No telemetry acquisition/export,
contents-phase binding, retained owner or UI action was added.

All 68 new focused tests pass; independent review found no actionable defect.
Saved and deterministically verified ignored local intermediate:
`artifacts/hiby_player_1.4_sortfix_fullnav_wake_lineage_rows_stage_v1_20261019.bin`,
7,149,012 bytes, SHA-256
`408163fd6c2d529df2e04976b89e1b9c39f36dbba679dc5fb9520365bc133a81`.
The preceding lineage-only output remains byte-identical. No device access,
installation, launch, rearm, signal or reboot; automatic reveal is still off.
Changes remain local/uncommitted. See
[row journal stage](folderfollow-reveal-lineage-rows-stage.md).

Full repository regression: **874 tests pass, no skips** (169.922 s), including
the 68 new checks. All 126 Python scripts compile and tracked/new text files
pass whitespace checks. The test run used local temporary-file access, without
changing legacy tests or using any real player transport.

### Known contents-boundary revision filter (2026-10-20)

Added an offline MIPS diagnostic counter at eight known entry/attempt points:
renderer, Files worker, reset, reconciliation, named reset, close/navigation
attempt, postfill and panel binding. Each increments before native effects;
ordinary nested entries are allowed. Overflow/retry loss/malformed state faults
permanently, without changing the original call/replay/result behavior.

Producer receipts freeze a start revision; row events mirror it and compare
before additional native payload reads and before publication. The strict new
decoder preserves observed historical completeness but rejects windows after
a later known entry. It never reports current/settled contents or UI authority.
An already-active writer or stale queued job beginning after reset remains
unproved. Normal postfill/bind also invalidates the preceding window, so this
negative-evidence stage is not a ready-row publication gate.

All 58 new focused tests pass. Independent review found full-interval layout
and native jump-region checks missing from the public composition helper;
fixed with regression tests. The normal planned/saved layout was unaffected.
Both previous default outputs remain byte-identical. Saved and
deterministically verified ignored local intermediate:
`artifacts/hiby_player_1.4_sortfix_fullnav_wake_contents_revision_stage_v1_20261020.bin`,
7,151,032 bytes, SHA-256
`f4284cb5adf77111d9c114c4c8889c7cb95eefec5e50c757a21544e8568603ac`.
No device access, install, launch, rearm, signal or reboot; autoscroll remains
off. Exact original-invocation/contents-phase/owner association through normal
completion still needs implementation. Changes remain local/uncommitted; see
[contents revision stage](folderfollow-reveal-contents-revision-stage.md).

Full repository regression: **932 tests pass, no skips** (170.376 s), including
the 58 new checks. After the final helper-only jump-region argument check,
all 58 focused tests were rerun and passed (6.077 s); the saved output remains
byte-identical and verified. All 134 Python scripts compile; tracked/new text
files pass whitespace checks. No test used a real player transport.

### Exact borrowed-dispatch observation (2026-10-20)

Implemented a separate native diagnostic journal connecting actual worker fill,
postfill, binder entry and return events to the immutable original BORROW ID.
Native callback JALRs, RA and SP remain unchanged. Strict offline decoding
requires the exact event chain, original callback targets, one matching query/
producer/destination, original P/V consistency and historical row completeness.
A zero callback result or native state 2 cannot stand in for binding evidence.

Source audit found two branch-target hazards: missing-V/P paths enter the post
epilogue directly at E4, and error return jumps to the normal flag store EC80.
Custom replay covers those routes without skipping restored registers or the
forced-state write. No added native query, getter, lock, export or UI action.

All 60 new focused tests pass; independent review found no further actionable
defect. Saved and deterministically verified ignored local intermediate:
`artifacts/hiby_player_1.4_sortfix_fullnav_wake_operation_stage_v1_20261020.bin`,
7,153,904 bytes, SHA-256
`be40cecaa6172376f98cd8403477d16f609884347774564d19b7a95f881a49f8`.
The previous contents-revision output remains byte-identical.

Callback association is diagnostic only: normal postfill/bind still revokes the
base row window, and currentness/coherence/autoscroll remain false. Original
contents-phase identity, already-active writers/stale-start exclusion, retained
native ownership and host row publication remain open. No player access,
install, launch, rearm, signal or reboot; changes are local/uncommitted. See
[operation observation stage](folderfollow-reveal-operation-stage.md).

Full repository regression: **992 tests pass, no skips** (193.246 s), including
the 60 new checks. All 142 Python scripts compile; tracked/new text files pass
whitespace checks. Both new saved-file verification and prior-artifact hash
checks pass. No test used a real player transport.

### Original renderer-entry frontier (2026-10-21)

Added an offline filter that retains the exact returned revision of original
guarded renderer entry, rather than taking a fresh stamp when a queued producer
starts. Native SP+0x10 carries it to immutable RENDER+60; private lineage keeps
the original association. The actual Files worker entry must be the single
known boundary between original R and frozen producer R+1. Stale positive roots
fault before extra native row payload reads; INITIAL/zero roots are unadmitted.
Native callbacks still run; this does not stop stale stock list mutation.

All 40 new focused tests pass; independent review found no actionable defect.
Saved and deterministically verified ignored local intermediate:
`artifacts/hiby_player_1.4_sortfix_fullnav_wake_origin_frontier_stage_v1_20261021.bin`,
7,154,204 bytes, SHA-256
`c0db14bd8c1ec6df87eb4690ae55da8f6740e5c59faa9f14f51e6da168818601`.
All four preceding default outputs remain byte-identical. No new job/list
stride growth, UI action, native query, getter, lock, exporter or installer.

Fresh rendering of an already-stale UI/request, already-active writers, missing
aliases, retained owner lifetime and coherent capture remain unproved. Base
postfill/bind revocation is not relaxed; currentness/autoscroll stay false.
No device access, install, launch, rearm, signal or reboot. Changes remain
local/uncommitted; see [origin frontier](folderfollow-reveal-origin-frontier-stage.md).

Full repository regression: **1,032 tests pass, no skips** (181.294 s), including
the 40 new checks. All 148 Python scripts compile; tracked/new text files pass
whitespace checks. New saved-file verification and all prior output hashes
remain valid. No test used a real player transport.

### Known in-flight reset/reconcile exclusion (2026-10-21)

Added a private diagnostic scope guard for the exact reset/reconcile entries
and three normal-return epilogues. Packed active count increments atomically
with a non-reused ticket before publication, so issued-but-unpublished entries
remain visible. Exact kind/ticket/native-frame binding and one-shot close claim
prevent foreign/duplicate completion. Fault/exhaustion/retry loss is permanent.

Native prologues run once before storing the ticket at audited native SP+14.
Original renderer entry stays unadmitted if a known scope is open; closing it
later cannot relabel that origin. Extra row payload capture is skipped while
active before allocation, and faults on detected overlap after allocation.
Completion bumps the existing revision before releasing active count. Actual
native results/registers/RA survive and each original frame is popped once.
Stock callbacks still run: this is not a writer lock or lifetime lease.

The source audit also established that renderer a2 is a newly allocated cache
canvas descriptor, not an immutable UI request. This new exclusion narrows
known overlap only. Fresh UI/playback request identity, other writers/abnormal
exits, native retained lifetime, coherent handoff and final UI action remain
unproved. Normal postfill/bind revocation is unchanged; autoscroll stays off.

All 90 new source/core/decoder/composition checks pass. Independent read-only
reviews found no actionable defect. Previous default builders remain byte-
identical. Saved and deterministically verified ignored local intermediate:
`artifacts/hiby_player_1.4_sortfix_fullnav_wake_native_scope_stage_v1_20261021.bin`,
7,156,404 bytes, SHA-256
`404827620fc6addba436c1911eb89b72b633562d84331de9e0097ede9469b0d5`.
No device access, install, launch, rearm, signal or reboot. Changes are local /
uncommitted; see [scope stage](folderfollow-reveal-native-scope-stage.md) and
[source boundary](folderfollow-reveal-native-scope-boundary.md).

Full repository regression: **1,122 tests pass, no skips** (168.446 s), including
the 90 new checks. All 158 Python scripts compile; tracked/new text files pass
whitespace checks. An earlier full run had a single failure in an unchanged
25-ms mocked launcher watchdog test; all 24 launcher checks passed separately,
then the complete suite passed without parallel focused-test load. Neither
launcher nor tests were modified to hide it. The saved image remains verified;
all checks used local fixtures only, with no real player transport.

### Deferred request birth / fresh-callback counterexample (2026-10-21)

Traced the request earlier than cache-canvas allocation: nonnull repaint
`8B4280` makes a 16-byte rectangle copy and appends it to persistent C+34.
Native reset `491240` removes named cache canvases but retains this queue,
then appends a new nonnull repaint. Later rendering consumes the old entries
before freeing them. Full redraw is a coalesced flag without request identity;
its normal path also processes the pending queue after its full callback.

Added pinned source contracts for the six generic queue append callers, three
distinct paint borrowers, occupied metadata, destruction, native failure paths,
callback/outer-frame bindings and unretained current-name widget resolution.
No additional child-renderer stack word is available; callback/outer SP+14 are
only bounded future carrier candidates, not implemented request identity.

An instruction harness executes the actual reset/append/queue-borrow/cleanup
instructions with explicit resource/SQL/geometry/callback stubs. Old and new
marked repaint births differ in callback order but yield identical private
scope/frontier/row/operation bytes in the existing composed widget fixture.
Fresh renderer/producer stamps and scope quiet therefore cannot establish
request birth. This does not claim stale rows, a real UI run, complete native
scheduling or a retained owner; currentness/coherence/autoscroll stay false.

All 36 new focused tests pass. Independent reviews found no actionable defect
or overclaim. This follow-up changes tests/documentation only: no allocation
growth, tail read, metadata reuse, new firmware build, device action or commit.
The previous scope-stage changes remain local/uncommitted. See the
[request engine audit and executable counterexample](folderfollow-reveal-request-engine-boundary.md),
[callback frame audit](folderfollow-reveal-request-callback-boundary.md) and
[independent queue safety audit](folderfollow-reveal-request-queue-safety.md).

Full repository regression: **1,158 tests pass, no skips** (194.524 s). All 36
focused tests also pass after tightening the fixture's C allocation to exact
native size (6.242 s). All 161 Python scripts compile; tracked/new text files
pass whitespace checks. The prior saved scope-stage binary remains unchanged
and deterministically verified. No real player transport was used.

### Prepublication queue-birth observations (2026-10-21)

Implemented the first immutable diagnostic birth ID before native queue
allocation, linked to ENQUEUE_BEGIN and actual append return through native
invocation-local SP+14. Private receipts preserve exact ancestry and numeric
engine/input/copy/metadata/frame binding without dereferencing those values.
Null/full requests and C+44 early returns stay unobserved; loss/fault never
suppresses stock queueing. No allocation size, native tail, metadata or generic
append call/RA/delay/cleanup change. The final rectangle word remains in the
original append delay slot, so ENQUEUE_BEGIN is not confirmed publication.

The new journal distinguishes the prior old/new request-birth fixtures (birth
revision 0 versus 2) while their complete prior capture prefix stays identical.
It does not transport the ID through the native queue to the renderer or join
it to rows. Request freshness, retained owner, coherence/currentness and UI
authority remain false. Normal old row/frontier/scope refusals are unchanged.

Independent review found and reproduced an impossible future scope-issued
sample accepted by the combined parser; fixed and covered by a regression
test. Earlier active samples after normal close remain valid historical data,
not monotonic active-count claims. All 106 new focused checks pass: source,
core, standalone/combined parsers and native producer/counterexample integration.

Saved and deterministically verified ignored local intermediate:
`artifacts/hiby_player_1.4_sortfix_fullnav_wake_queue_birth_stage_v1_20261021.bin`,
7,159,132 bytes, SHA-256
`3f4d975087af7d31e2b60b6a0d6c5762585acd02658ed36cefb2152a78b79c7d`.
Previous default builds remain byte-identical. No device access, install,
launch, rearm, signal or reboot; changes remain local/uncommitted. See
[queue birth stage](folderfollow-reveal-queue-birth-stage.md) and
[source boundary](folderfollow-reveal-queue-birth-boundary.md).

Full repository regression: **1,264 tests pass, no skips** (183.884 s), including
the 106 new checks. All 171 Python scripts compile; tracked/new text files pass
whitespace checks. An initial full run repeated the known unchanged 25-ms mock
launcher watchdog failure; all 24 launcher tests passed separately (16.316 s),
then the complete suite passed unchanged. Saved image verification remains
valid. All tests used local fixtures; no real player transport was used.

### Repository checkpoint (2026-10-22)

The native-scope exclusion, deferred-request counterexample and prepublication
queue-birth observation above are grouped in this source-only checkpoint.
Latest full regression: 1,264 tests pass, no skips; all 171 Python scripts
compile. Firmware intermediates, raw snapshots, logs and temporary fixtures
remain excluded. Queue-consumer identity transport and active autoscroll are
not implemented by this checkpoint. No player operation or deployment.

### Explicit queue birth to native callback transport (2026-10-22)

A separate local diagnostic successor now transports an exact private birth
through widened generic node+10, queue BORROW, helper SP+14 and native paint
callback entry SP+14. Fresh invocation IDs preserve split/reentrant ancestry;
addresses never serve as registry/join keys. Full/synthetic/unknown routes
stay zero, and original rectangles, metadata, call/delay/RA and cleanup remain
unchanged. The node allocation grows 16 -> 20 for all six inspected list uses:
this changes memory pressure and possible allocation outcomes. It is not a
passive private-only extension or an approved device candidate.

130 new focused checks pass, including exact ABI/failure routes, original a3
forwarding, address-reuse/ABA histories, callback splits, full-tail queued loop,
consumer-before-RETURN causality, fault/exhaustion and strict combined decoding.
The callback entry executes in the instruction harness, but its remaining
lookup/widget body and selected native helpers are explicitly mocked. No
callback-to-outer/renderer/row association or native live-borrow lease is proved.
Original UI/playback cause, complete writer coverage, coherent capture,
retained owner and active scrolling remain unimplemented gates.

Saved and deterministically verified ignored local intermediate:
`artifacts/hiby_player_1.4_sortfix_fullnav_wake_queue_transport_stage_v1_20261022.bin`,
7,162,704 bytes, SHA-256
`754ea4f3b1a6351b4409f1229a84ac380d18365fa32ce91062489b08b2bedba6`.
901232 private BSS bytes, 19280 separate RX bytes, 33 hook pairs and 242
changed original bytes; no new external native call/RWX. Previous default
images remain byte-identical. Changes are local/uncommitted; hardware UNTESTED.
No device access, installation, launch, rearm, signal or reboot. See the
[stage report](folderfollow-reveal-queue-transport-stage.md) and
[source/frame premise](folderfollow-reveal-queue-transport-boundary.md).

Full repository regression: **1,394 tests pass, no skips** (212.286 s), including
the 130 new checks. All 181 Python scripts compile; tracked/new text files pass
whitespace checks. Independent source/ABI and decoder reviews found no
actionable issue. Previous default images retain their pinned hashes, and
the new saved default image is exactly verified. No device/network operation,
commit or push was performed.

### Explicit queued birth to renderer/root/row identity (2026-10-22)

Added two source observers at outer `438248` and renderer `49076C`, preserving
the original `439F90`, `438740`, `490764` calls/delays/return PCs and the existing
root observer `490758`. New LQRD OUTER binds an exact earlier CALLBACK; RENDER
binds OUTER and the actual existing LNRG root from native R+14. Occupied R+10
entry revision and R+14 root ID are never overwritten. A separate decoded
mapping associates captured row/producer/window/operation IDs only via exact
lineage origin IDs. Native addresses/names cannot repair missing ancestry.

Duplicate root IDs are refused; separate callbacks with identical native
addresses still yield distinct roots, and only the correct root receives
its captured rows. Missing/duplicate/wrong RETURN remains incomplete. All old
frontier/scope/window refusals and all currentness/ownership/UI false flags
remain in force. Original UI/playback cause, native lease, coherent handoff,
complete writer/cancellation coverage and active reveal are still unproved.

The instruction fixture executes actual callback, outer/child call boundaries,
child entry/list/getter/root/strcpy/new observer and native epilogues. Resource
lookups, outer geometry/cache middle and renderer job/SQL suffix remain
explicit fixtures, not a complete UI run. No device action occurred.

Saved and deterministically verified ignored local intermediate:
`artifacts/hiby_player_1.4_sortfix_fullnav_wake_renderer_transport_stage_v1_20261022.bin`,
7,166,664 bytes, SHA-256
`f42fac46890dc2eadbeba88f90ce5b82857d3045752b974b15d04bef263d2244`.
999552 private BSS bytes, 23240 separate RX bytes, 35 hook pairs and 259 changed
original bytes. No RWX/new native call. The prior generic-node 20-byte extension
is inherited unchanged; no further native allocation extension was added.
Changes remain local/uncommitted, hardware UNTESTED, scrolling disabled. See
[stage report](folderfollow-reveal-renderer-transport-stage.md) and
[source/frame contract](folderfollow-reveal-renderer-transport-boundary.md).

Full repository regression: **1,506 tests pass, no skips** (244.049 s), including
112 new renderer-association checks. All 191 Python scripts compile; tracked
and new text files pass whitespace checks. Independent reviews found no
actionable source/ABI/core/decoder issue. Previous default hashes remain intact,
the saved new default image is exactly verified, and firmware artifacts remain
ignored. No test or existing refusal was weakened. No player/network operation,
commit or push was performed.

### Host-only negative request-age assessment (2026-10-22)

Added `decode_reveal_request_age.py`, a strict raw-snapshot decoder annotation,
not a firmware/runtime/coordinator change. The existing renderer snapshot format
and every prior receipt/window/operation/flag/reason remain unchanged. New
`request_age_assessment` follows explicit canonical IDs, locates known global
revision/scope interference before OUTER, extra increments beyond the one own
renderer entry, and additional early-renderer increments. It never joins native
addresses or trusts mutable timing summaries.

Unknown entry zero and source-inconsistent positive marks cannot date an
interval; saturation is not masked/wrapped. Scope-issued and REV are sampled
separately and need not advance together. RETURN is a separate potentially
later branch; final worker/postfill/bind +3 and unrelated later increments are
not pre-render age evidence. A legitimate new request behind another paint can
be conservatively refused by the global counter; that is not proof of changed
contents for its specific owner. No-conflict cases remain unproven, never fresh.
All assessment objects say deny; all UI/currentness/ownership flags stay false.

59 new focused checks pass (1.335 s): 21 native integration/public API cases,
28 adversarial cases and 10 source/emission contracts. All 195 Python scripts
compile. No new builder, source hook, BSS field, allocation, firmware artifact,
capture policy, player operation or UI action. Existing saved firmware hashes
remain unchanged. Changes remain local/uncommitted. See the
[assessment report](folderfollow-reveal-request-age.md) and
[source/causality boundary](folderfollow-reveal-request-age-boundary.md).

Full repository regression: **1,565 tests pass, no skips** (244.464 s), including
59 new host-age checks. All 195 Python scripts compile; tracked/new text files
pass whitespace checks. The saved renderer-stage image remains exactly
verified with its unchanged `f42fac...` hash. No new firmware artifact, native
behavior change, player operation, commit or push. The new diagnostics always
deny action and do not waive any previous native/currentness/UI gate.

### Playback-cause staging and ambiguity contracts (2026-10-22)

Added 38 offline checks: 16 pinned original-source contracts, 12 actual
original-instruction staged-selection/player-queue fixtures, and 10 explicitly
unlinked host-model causality counterexamples. The source shows two channels:
event9 carries only [9,0], while the selected A90-byte record travels through
B+BB0. The worker selects count-1, copies A88 plus a separate transition,
unlocks and later clears the entire staged list under a new mutex bracket.
The native fixtures reproduce selection of B from queued A/B and discard of C
appended between those brackets, without changing original firmware bytes.

The final general callee is explicitly opaque in that fixture. Actual CC60
also flushes the player event queue at42CD6C; repeat-empty deliveries are
conditional on the fixture substitute retaining messages, not whole-player
predictions. Producer record+A8C is not a proved spare field; enlarging the
worker A88 copy would overwrite its live SP+AA0/AA4 event words. Neither a
FIFO event assumption nor later element address/count can identify a selected
record's original cause. BA0 and a universal playback-to-Files route remain
unresolved; player event11 is not UI event140.

Different modeled immutable playback parents produce identical later owned
host publications and identical independently injected renderer snapshots/age
reports. The source-shaped UI message is NOT delivered or claimed to be a
native playback notification. The report adds one explanatory limitation:
coverage of every playback publication by these UI clocks is not proved;
matching intervals do not recover original cause. Algorithm/format/refusal
gates are unchanged; all five authority flags remain false and decisions deny.

All 38 focused checks pass (1.534 s). All 198 Python scripts compile;
tracked/new text files pass whitespace checks. Independent source/ABI/model
reviews found no remaining actionable issue. Existing saved renderer image
is exactly verified with unchanged f42fac... SHA-256; no new artifact, hook,
allocation, BSS layout, player access, UI action, network, commit or push.
Changes remain local/uncommitted, hardware UNTESTED and scrolling disabled.
See the [source/causality boundary](folderfollow-reveal-playback-cause-boundary.md).

Full repository regression: **1,603 tests pass, no skips** (249.450 s),
including all 38 new checks. All 198 Python scripts compile; tracked and new
text files pass whitespace checks. The unchanged saved renderer-stage image
remains exactly verified, SHA-256
`f42fac46890dc2eadbeba88f90ce5b82857d3045752b974b15d04bef263d2244`.
No firmware behavior, artifact, test/refusal gate or device state was changed;
no commit/push/network operation was performed.

### Passive optional-playback dispatch intent (2026-10-23)

Added a separate offline builder/core/strict decoder and combined renderer
decoder for two exact BA0 JALR sites,42CC0C and42D6A0. Original target/context
loads and nonnull branches stay intact. Each wrapper replays the native delay,
sets the original RA=site+8, privately records register-derived scalars, restores
all volatile/HI/LO/SP and JR-t9 dispatches. The original callback returns directly
to its original continuation. Capture failure/full/fault never vetoes dispatch.
No native payload read, current-clock stamp, frame carrier, target dereference
or retained observer frame across the callback was introduced.

LPDI records are CALL_INTENT only, not callback entry/return, completed playback
publication, coherent identity or a parent for paint. They have an independent
nonreused ID namespace and no ancestry into BIRTH/renderer/rows. Strict combined
decoding preserves the earlier age/window/operation evidence and refusals; all
five authority flags stay false. Empty/partial/full history never proves coverage.

Source tracing now distinguishes fast event11 -> actions0/5 (ignored by explorer
490980) from GENERAL's separate action1 at42D614 -> explorer ->43C860/439900
paint-request list. General action1 PRECEDES BA0; the new later LPDI record cannot
become its parent by matching addresses, current state or reservation order.
Action record ownership, selected delivery, fanout/name resolution and explicit
notification-to-paint transport remain required. BA0 registration is unresolved.

All 101 focused checks pass (13.707 s):19 core,30 standalone decode,20 combined
decode,16 source and16 native-boundary/stage checks. Independent source/builder/
ABI and decoder/fixture reviews found no actionable issue. The original JALR
target-entry state is compared across every GPR and HI/LO; actual callback bodies,
hardware instruction modes, scheduler and native lifetime are not proved.
All 208 Python scripts compile; tracked/new text files pass whitespace checks.

Saved and exactly verified ignored local intermediate:
`artifacts/hiby_player_1.4_sortfix_fullnav_wake_playback_dispatch_stage_v1_20261023.bin`,
7,167,956 bytes, SHA-256
`a9a6f02fd48a3b57e27e3bb19c9e8c2b8329b6602cc12988091dfbb98c2abe2c`.
1,065,104 private BSS bytes (LPDI adds65,552),24,532 separate RX bytes,37hook
pairs and275 changed normalized-original bytes. Two narrowly declared JR-t9
tails; prior external-call/append/continuation inventories remain unchanged.
Peak additional recording stack240bytes is released before callback entry.
The prior16->20generic-node extension is inherited; no further native allocation
extension or RWX mapping. Earlier renderer image remains exactly verified with
its unchanged f42fac... hash. Previous builder defaults remain byte-identical.

No installer/export policy, device/network access, launch/signal/reboot/rearm,
UI action, commit or push. Changes are local/uncommitted, hardware UNTESTED,
active reveal/scrolling disabled. See the
[stage/source/verification report](folderfollow-reveal-playback-dispatch-stage.md).

Full repository regression: **1,704 tests pass, no skips** (290.486 s).
The first completed run had one failure in the unchanged legacy launcher
normal-exit/no-delayed-signal fixture (1,704 tests,305.411 s); that fixture uses
a25-ms mocked sleep. Its24 isolated checks passed (18.461 s), then the full
suite passed without parallel test load. No launcher, timer, assertion or
existing refusal was changed. All208 Python scripts compile; tracked/new text
files pass whitespace checks. Both saved artifact hashes are exactly verified,
with no installation/device/network action, commit or push.

### Explicit GENERAL notification through two queues to BIRTH (2026-10-23)

Added a separate passive offline stage carrying fresh nonreused SOURCE IDs
from GENERAL's actual action1 call42D614 through the action worker, exact
explorer callback, paint producer and selected paint-list delivery to the
actual existing LQBR BIRTH. The new combined raw-snapshot decoder then joins
existing renderer/root/row lineage only by that explicit BIRTH foreign key.
The later optional BA0/LPDI CALL_INTENT journal remains independent; equal
addresses, frames, payloads or local counters cannot select a parent.

Action element width16->20 and paint width32->36 each add one initialized ID
word; capacity requests and original native calls/delays/RAs remain unchanged.
Native dynamic-stride append/index/remove moves the whole record. Unknown
producers and every selected iteration clear/replace their carriers; exact
source/native-return gates precede any caller-frame read. The selected paint
tail is read once BEFORE the native getter unlock, then a fresh delivery ID
is frozen in the exact consumer frame. No post-unlock tail reread/address
registry is introduced. The old BIRTH recorder is invoked once, and its actual
result/state and native BIRTH carrier are preserved by the private link helper.

The six-kind96-byte LALI journal validates whole bounded ancestry and actual
private LQBR BIRTH bindings. Allocation/publication are bounded, magic-last,
nonwrapping and terminal on diagnostic loss. Overflowing frame/record extents
are refused in both emitted capture and ancestor validation, matching strict
host decoding. Same-address/same-fields ABA still cannot prove post-unlock
native payload coherence or lifetime. Native borrowed-body loads are unchanged;
all existing authority/lifetime/currentness flags stay false and decisions deny.

All146 focused checks pass (28.566 s):27 core,45 standalone decode,23 combined
decode,22 pinned source,21 native-path integration and8 build/verifier checks.
The native fixture executes actual constructors, both segmented FIFOs, worker,
fanout, explorer, paint getter/consumer and redraw/BIRTH path. Its full combined
snapshot associates SOURCE1 -> BIRTH1 -> renderer2 -> lineage1 -> producer4/
row-event1, while preserving old renderer/row structures and known-boundary
refusals. Identical queued payloads survive both FIFO head-address reuse with
distinct IDs. Under-lock tail capture, unknown routes, foreign callers, zero
parents, native allocation failure, engine/metadata change after unlock,
full/fault/failed-SC native liveness and GPR/HI/LO/nativeRA ABI are covered.
Registry/name resolution, scheduler, mutex services and existing renderer/SQL
jobs remain bounded fixtures, not whole-player concurrency or hardware proof.
Independent reviews found no remaining actionable issue.

Full repository regression: **1,850 tests pass, no skips** (297.274 s).
All219 Python scripts compile; tracked/new text files pass whitespace checks.
No legacy launcher/test timer, existing assertion or refusal was changed.

Saved and exactly verified ignored local intermediate:
`artifacts/hiby_player_1.4_sortfix_fullnav_wake_action_link_stage_v1_20261023.bin`,
7,176,916 bytes, SHA-256
`d4306357ec6b70153b15e98202dad1a7ad0615d02ea6bd9e0d53857844ab37a8`.
1,163,424 private BSS bytes (LALI adds98,320),33,492 separate RX bytes,42hook
pairs and310 changed normalized-original bytes. No RWX segment. The new private
frame chain is at most464 bytes, or624 including the inherited BIRTH observer
frame, excluding native/renderer/exception frames. The two native element
extensions and extra capture time remain real allocation/stack/timing risks.
Previous saved LPDI and renderer images are exactly reverified with unchanged
a9a6f02f... and f42fac46... hashes; prior builder defaults remain byte-identical.

No installer/runtime export policy, device/network access, launch/rearm/signal/
reboot, UI action, commit or push. Changes remain local/uncommitted, hardware
UNTESTED, active reveal/scrolling disabled. This closes the audited GENERAL
invocation-ID gap, not coherent playback publication, universal Next/autoplay
coverage, native retained ownership or an admitted UI transaction. See the
[source/stage/verification report](folderfollow-reveal-action-link-stage.md).

### Native paint payload and removal-ownership boundary (2026-10-23)

Follow-up to committed notification-link stage e113d59. No firmware/builder,
hook, BSS layout, native frame/allocation, snapshot format, installer or native
runtime behavior change. Two host-decoder limitation strings now explicitly name the
separate rectangle loads, current-index removal and known different-mutex
purge; association/refusal algorithms and all authority flags are unchanged.
One existing fixture comment clarifies468D40: it ignores a0, tests global
B896D0==0 and does not validate the passed controller/engine.

Added18 pinned-source and27 native-interleaving checks (45 total,4.859 s).
The native getter unlocks before consumer engine/metadata reads; BIRTH records
the rectangle address before allocation and four independent native loads.
Explicit mutation before successive loads yields a mixed old/new rectangle,
while historical SOURCE -> actual BIRTH remains structurally valid/deny-only.
An actual native index0 removal between loads moves the next36-byte element
over the selected address and produces each of the three torn prefixes.
Identical addresses/fields and a change/restore interval do not supply a lease.

The original consumer later removes whichever element is now index0. Both
43C980 and43CA60 loops have direct consumer calls; their mutual exclusion and
OS-thread identity remain unproved. A real known purge439780 ->4396C0 removes
paint entries under controller+274/+278 ->mutex+13C, whereas getter/append/
normal remove/destruction use+284/+288 ->mutex+148. The native fixture executes
that purge and actual13C callbacks after selected-ID publication, both after
unlock and in an explicitly injected interval while148 is held. It removes the
sole element, the consumer observes zero engine, and BIRTH is skipped while
the frozen delivery remains incomplete. This establishes the lock-protocol
gap, not actual simultaneous-thread scheduling or the user's hardware defect.

Tests keep scheduler, OS mutex/allocation services, bounded name comparison and
registry cleanup as explicit substitutions. Suspended registers, HI/LO and
diagnostic PC are restored around nested native calls on a separate stack.
Empty/head-moved/null-engine/full/fault/retry/mismatched-metadata/engine paths
preserve native behavior and every deny-only flag. Existing146 action-link
checks pass (33.365 s); independent source/fixture/decoder/documentation review
found no remaining actionable issue. The source census includes direct J/JAL,
integer and coprocessor branch forms, not computed/runtime entries.

A future handoff must separately establish stable acquisition, exact selected-
entry claim/removal and engine/controller retention. Merely copying under148
does not cover the known13C-only purge. An examined80-byte consumer-frame copy
layout is explicitly NOT implemented; changing native BIRTH.INPUT requires a
versioned owned-copy protocol, not relaxed old pointer bindings. Earlier
extraction would also change ordering and in-flight cancellation visibility.
See the [source and counterexample report](folderfollow-reveal-paint-payload-boundary.md).

Full repository regression: **1,895 tests pass, no skips** (313.633 s).
All221 Python scripts compile; tracked/new text files pass whitespace checks.
The saved action-link, LPDI and renderer images are exactly reverified with
unchanged d4306357..., a9a6f02f... and f42fac46... SHA-256 hashes. No new image
or native read/capture policy. No legacy launcher/test timer, existing assertion
or refusal was changed or weakened. Changes remain local/uncommitted; no
device/network operation, commit or push. Active reveal/scrolling remains
disabled and hardware UNTESTED.

### Host head-retained paint queue and owner retirement (2026-10-23)

Implemented `folderfollow_reveal_paint_queue.py`, a separate positive host
protocol, not a firmware/native-lock adapter. A single host Lock serializes
owner registration, enqueue, one exact retained-head claim, completion, purge,
retirement, close and accounting release. Payloads copy already-owned builtin
scalar/rectangle values before publication; this is not native acquisition
coherence. Caller-supplied iteration/hash/equality or rendering/cleanup/I/O
is never invoked under the queue lock.

The active entry remains at the FIFO head until exact identity-bound claim
acknowledgement. Another consumer cannot skip ahead or claim that same head.
Completion removes only that entry; duplicate/foreign/reconstructed/stale
tokens cannot remove a newer head. Purge retires matching owner generations,
removes unclaimed entries and cancels, but retains, a claimed entry. Its later
ack returns cancelled regardless of the caller's success outcome. Late old-
generation producers cannot republish even for identical names/engine words.

Owner accounting is releasable only after retirement and all references are
acknowledged. This is host bookkeeping only, never native free/detach authority.
A lost acknowledgement deliberately keeps the head and owner blocked, without
timeout takeover. Pending/cancelled entries and registered owners are bounded;
capacity rejection does not evict work or consume a ticket. Owner and entry
IDs share one persistent monotonic bounded counter, never reset/reused. Close,
uncertainty and exhaustion withdraw new work permanently but permit old exact
claims to acknowledge cancellation/cleanup. Every native lifetime, payload,
currentness, freshness and UI proof flag in returned snapshots stays false.

The new source contracts pin a local13C ->148 order for the known purge;
no reverse nested edge is found in the four classified148 bodies. Controller
teardown completes148 destruction before acquiring13C; an existing13C-held
459840 source call is documented without assuming arbitrary callback safety.
Actual4395A0 frees name/engine queue/engine/entry without the paint-purge148
protocol. Its56 encoded callers include50294C beyond the55 paired439780
purge callers. Therefore a later registry lock cannot itself retain an engine
already freed before selection. Detach/geometry change and destruction of
controller mutex objects are separate lifecycle obligations.

All95 new focused checks pass (1.128 s):47 basic,30 adversarial and18 pinned
source/lifecycle checks. All1,296 bounded four-event model sequences, six
purge/ack/close permutations, eight simultaneous host claimants, repeated
host purge/ack and close/ack races, and an Event-held cancelled claim pass.
Python-lock results are explicitly not native thread/lifetime evidence.
Independent reviews found no actionable issue. The existing coordinator,
raw decoders, firmware builders and LALI/BIRTH input bindings are not altered.
See the [host protocol and integration report](folderfollow-reveal-paint-queue.md).

Full repository regression: **1,990 tests pass, no skips** (321.386 s).
All225 Python scripts compile; tracked/new text files pass whitespace checks.
Saved action-link, LPDI and renderer images are exactly reverified against the
pinned source with unchanged d4306357..., a9a6f02f... and f42fac46... hashes.
No existing launcher/test timer, assertion or refusal was changed or weakened.
No device/network operation, new image, commit or push; these changes remain
local/uncommitted, scrolling disabled and hardware UNTESTED.

### Offline MIPS publication/claim/ack handoff (2026-10-23)

Added standalone `reveal_paint_handoff_mips.py`, not a firmware stage or an
owner-lifetime adapter. Its five entries publish, claim, complete, cancel and
close using actual controller148 callbacks and native segmented-list methods.
A distinct40-byte record preserves the existing36-byte body/LALI and adds a
non-reused nonce at0x24. Publication checks a separate logical pending limit;
the original64 initial-capacity request rounds to70 and is not a hard cap.

Claim copies36 bytes under148 and retains the head. Its private buffer is
valid until exact completion, not forever. Acknowledgement checks the active
nonce and bound list before header reads, reselects under148 and removes only
the matching head. Stock current-index removal shifting B onto A's old address
does not let A's late ack delete B. Cancel/close keep active accounting until
ack and do not free objects or remove the unclaimed tail. Private numeric
nonces are cooperative IDs, not host identity capabilities or native leases.

Review found that native grow failure455A08 can null the block table even
when count stays unchanged. Any raw append failure is now terminal, burns its
nonce and cannot be retried as though nothing changed. Header/storage guards
refuse cleanup from the lost-table state before native get; an old exact ack
is admitted only if old storage remains valid. Mutex acquisition failure does
not read state/list or unlock. Unlock failure denies success and publishes a
monotonic terminal fault without inventing rollback or known lock ownership.

All63 focused checks pass (4.943 s):25 basic instruction/ABI,21 adversarial and
17 pinned-source contracts. Actual original list/mutex callback bodies execute
with explicit bounded service substitutions. Tests include >70-slot growth,
two genuine allocation failures, a held claim after table loss, stale/wrong
ack, equal-address head replacement, malformed storage, no raw-engine/geometry
dereference, and twelve60-event oracle sequences. Independent final reviews
found no remaining actionable issue. Source/input coherence, controller/list/
mutex lifetime, complete stock purge/removal participation and retirement
continuations remain required. No existing LALI/BIRTH equality is relaxed.
See the [offline handoff and remaining integration report](folderfollow-reveal-paint-handoff.md).

Full repository regression: **2,053 tests pass, no skips** (321.134 s).
All229 Python scripts compile; tracked/new text files pass whitespace checks.
The standalone helper is4,640 code bytes,64 private state bytes and a128-byte
frame excluding native/service frames and list storage. Saved action-link,
LPDI and renderer images are exactly reverified with unchanged d4306357...,
a9a6f02f... and f42fac46... hashes. No existing launcher/test timer, assertion
or refusal was changed or weakened. No builder/image/installer/native runtime
integration, device/network action, commit or push. Changes remain local/
uncommitted; active scrolling disabled and hardware UNTESTED.

### Offline MIPS generation retirement and cooperative purge (2026-10-23)

Follow-up to committed faf635f. Added a separate44-byte protocol with the
original36 body, publication nonce at36 and captured owner ticket at40; the
old40 module, all builders/decoders, LALI/BIRTH equality and saved images are
unchanged. Owner and publication tickets share a persistent nonwrapping
serial. The bounded append-only owner table never reuses retired slots; full
owner capacity is backpressure without ticket burn or eviction. Publication
requires an issued live captured ticket and matching owned engine scalar;
late producers cannot adopt a new equal-engine generation implicitly.

Retire permanently revokes its generation and cancels its matching active
claim before queue selection/removal. An existing active head's list binding,
nonce and owner are checked before any purge mutation. Unclaimed matching
rows are removed by the actual raw method under148; retained rows advance
the index, removed rows recheck the same index. The active head/private copy
and relative order of other owners survive. Raw remove must return0 and
decrement count once. Unknown row owners, inconsistent engine/nonce, bad
headers/methods or partial failures cause terminal withdrawal, not rollback.

The local drained query requires retirement, no actual queued/active entry
for that generation and no fault. Empty live owners do not qualify; fault
suppresses positive drain even after a valid old cancelled acknowledgement.
Close stays narrow: withdraw/cancel only; explicit retire/drain can follow
close, but no destructor/free/detach/shutdown continuation is performed.
Retire/drain never grant native allocation lifetime or release authority.

All65 new focused checks pass (5.796 s):23 basic instruction/ABI,24 adversarial
and18 pinned-source contracts. Actual original raw list and mutex callback
bodies execute under bounded fixture services. Tests cover75-entry growth/
segment boundaries, adjacent matches, preserved active and unmatched FIFO,
same-engine generation ABA, late/duplicate acknowledgements, partial purge,
raw remove/count fault injection, two actual native allocation failure paths,
substituted mutex-wrapper failures, malformed owner state and full-state alias
checks. These are not lower pthread-error tests: native466DA0/DC0 mask that
status, so the default helper still requires a genuinely held guard. Ten70-event
generation/retained-head oracle sequences pass. Independent reviews found no
remaining actionable issue. Default emission is10,824 code bytes,328 private
state bytes and a160-byte helper frame, excluding native callees/list storage.
See the [retirement protocol and native integration limits](folderfollow-reveal-paint-retirement.md).

On2026-10-26 the fresh serial full repository regression passes: **2,118 tests,
no skips** (308.557 s). All233 Python scripts compile; tracked/new text files
pass whitespace checks. The first run had one failure in the unchanged25-ms
mock launcher normal-exit fixture; its24-test module passed separately and
the fresh full rerun is clean. No timer/assertion/launcher code was weakened.
An interrupted retry with no retrievable result is not counted as a pass.
Saved action-link, LPDI and renderer images are exactly reverified against the
pinned source with unchanged d4306357..., a9a6f02f... and f42fac46... hashes.
The old40-byte handoff and launcher files remain unchanged from faf635f.
No firmware/runtime installation, device/network action, commit or push;
these changes remain local/uncommitted, scrolling disabled and hardware UNTESTED.

### Native admission audit and checked raw mutex mode (2026-10-26)

The source audit confirmed a prerequisite already noted in the earlier player
lock study: native466DA0/DC0 overwrite pthread status with zero. Controller
paint148 and registry13C both use them. Their zero is not an acquisition or
release receipt; the older40/default44 tests substitute the wrapper result
and cannot establish actual lower-error handling. Factory466D60 also ignores
init status and destroy466DE0 ignores destroy status before freeing nonnull
storage. No device failure is inferred from these source facts.

The separate44-byte assembler now offers explicit `checked_mutex=True`.
It snapshots controller+148 once, checks its bounded nonaliasing pointer
extent, calls rawA5B960, and branches on the actual status BEFORE private/
input/queue access. Release calls rawA5B830 with the same saved pointer.
Either raw error denies the current result with v0=0/v1=exact raw status.
An uncertain release permits only helper-frame writes, not a shared terminal
fault store. Earlier effects are not rolled back; caller-side external
quarantine is mandatory after any raw error. There is no automatic sticky
withdrawal or proof of raw mutex initialization, ownership, lifetime or
recovery. The default10,824-byte emission remains byte-identical (SHA-256
b0b07d89... for the pinned fixture addresses); checked mode is opt-in only.

Registry creation4389E0 publishes its final old-tail link at438A58, before
unlock438A60. Construction alone is earlier and not admission: both direct
callers ignore4389E0 status, and its allocation-failure edge bypasses unlock.
A draft positive-admission observer relying on a callback-zero receipt was
removed before testing/integration. No creation hook is installed or emitted.

Deletion4395A0 and detach8B0760 still require fences before their first link
mutations and a checked deferred-continuation protocol. Moreover both outer
callers of inner shutdown43CB20 can unlink/free registry nodes BEFORE it;
the43CB38 worker fence is not a whole-controller lifetime boundary. Bounded
direct-call censuses do not establish coverage of computed callers/aliases.
See [checked mode, source anchors and remaining admission gates](folderfollow-reveal-paint-admission.md).

Serial focused verification: **124 tests pass, no skips** (8.732 s), comprising
30 source contracts,9 original-facade executable counterexamples,65 previous
retirement checks and20 checked-mode checks. All eight operations preserve
callee-saved registers/HI/LO through hostile raw services; errors deny success,
uncertain unlock is followed only by helper-frame reads/writes, and the same
captured pointer is used for release. Tests cover nonzero acquire with possible
ownership, failed release both held/released, surviving earlier effects,
guarded state/source reads and unchanged default bytes. Independent source,
implementation/test and documentation review found no actionable issue.
Checked emission is12,120 code bytes; default state328/helper frame160 are
unchanged, excluding nested native/library frames and list allocations.

Fresh serial full regression: **2,177 tests pass, no skips** (320.672 s).
All236 Python scripts compile; changed/new text has no whitespace errors.
Saved action-link, playback-dispatch and renderer-transport images were
exactly reverified against02fd with unchangedd4306357...,a9a6f02f... and
f42fac46... hashes. The40-byte module, builders, decoders, launcher and its
tests/timers/assertions are unchanged. This verification included no firmware
installation, device/network operation, commit or push. The subsequent user
request authorizes publishing these text-only offline prototypes/tests/reports;
no binaries, logs or installation steps are included. Active folder-follow/
scrolling stays disabled and hardware UNTESTED.

### Passive raw registry-lock/publication receipts (2026-10-26)

Follow-up to committedf79ca66. A separate offline MIPS prototype observes
the actual13C mutex argument before pthread_mutex_lock and its actual return
before native466DA0 forces zero. Four local instruction-fetch overrides
bracket native4389E0:438A00 begins fresh frame readiness and snapshots actual
callbackT9/S0;466DA8 checks the raw argument and transitionsARMED->ENTERED;
466DB0 captures rawV0 and transitionsENTERED->CAPTURED before replaying the
forced zero;438A58 completes the native final link store FIRST and consumes
the capture once before shared observation. Exact two-frame return PCs and
pinned controller/mutex bindings constrain the bounded route.

Only a captured zero permits journal reads/writes. Raw nonzero, missing or
invalid capture never even inspects a corrupt journal or writes shared fault.
The16-byte header and40-byte historical records store raw mutex, node/engine
scalars, native frame/caller and publication site. Dense prefix/schema and an
all-zero target prevent count rollback, skipped holes or dirty-slot reuse.
Fault is terminal and can be set only under the current proven local guard;
capacity saturation drops observation without changing native registration.
The journal is not an owner ticket, native lease, release or cleanup receipt.

Original registry/callback/wrapper instructions execute in the bounded
fixture. Raw failures still produce the original unchecked native node writes;
native allocation failure still bypasses unlock. The observer preserves these
defects, not repairs them. Existing44/40-byte cores, builders, decoders, saved
images and launcher/timers/assertions are unchanged. No owner generation is
issued from this stage and no producer adopts a latest-by-raw-pointer owner.

All four redirects are a coherent-fixture premise, not arbitrary partial-
installation safety. The192-byte extra bridge frame applies even to unrelated
calls of the global466DA0 wrapper; complete stack/timing coverage is unproved.
Stable genuine ABI/callback/stack/controller/mutex fields, valid initialized
ordinary13C guard, resolved imports, allocator guard discipline and retained
native storage remain caller premises. Bounds/return PCs do not authenticate
forged stacks or prove lifetime. Raw nonzero can still own a robust/unknown
mutex; earlier publication does not certify later unlock. Actual admission,
generation transport, cleanup continuations and native/UI authority stay gated.
See [raw registry receipt and remaining integration limits](folderfollow-reveal-registry-receipt.md).

Serial focused verification: **178 tests pass, no skips** (8.908 s), comprising
54 new registry checks (19 instruction/native/ABI,25 adversarial,10 pinned
source) and124 previous retirement/checked-paint-mutex checks. Tests preserve
native results/links/allGPRs/HI/LO/rawserviceSP/RA/arguments, validate final link
store before observation and magic before count publication, deny unverified
shared access, and cover trueFFFFFFFF error, possibly-held nonzero acquire,
raw unlock errors, stale/consumed/duplicate carriers, changed pre/post service
context and malformed/rolled-back/partial journal state. An intentionally
unsupported partial-redirect counterexample demonstrates why missing all three
freshness/capture hooks is not protected by the publication observer alone.

Independent source and implementation/fixture/adversarial/documentation reviews
found no actionable issue within the explicit coherent-hook/guard/lifetime
premises. Emission is2,196 code bytes,656 state bytes and192 bytes per bridge
frame, excluding native/library costs. All240 Python scripts compile and
changed/new text passes whitespace checks. No installable image, device,
network, commit or push operation; changes remain local/uncommitted, active
scrolling disabled and hardware UNTESTED.

Fresh serial full regression: **2,231 tests pass, no skips** (278.390 s).
All240 Python scripts compile; changed/new text passes whitespace checks.
Saved action-link, playback-dispatch and renderer-transport images are exactly
reverified against02fd with unchangedd4306357...,a9a6f02f...,f42fac46... hashes,
capture-only/scrollingFalse/hardwareUNTESTED. Existing44/40-byte implementations,
builders, decoders and launcher/timers/assertions remain unchanged fromf79ca66.
No device/network operation, firmware installation, commit or push. Changes
remain local/uncommitted; actual owner issuance and active scrolling stay gated.

### Offline receipt-bound historical owner issuance (2026-10-26)

An opt-in local composition now calls checked44-byte open_owner only after
fresh raw13C=0, route checks and complete passive receipt journal validation,
capacity and empty-target preflight. The callback receives an owned36-byte
snapshot of this exact native invocation, not a latest journal row or lookup
by engine/node/name. A separate48-byte immutable binding records the returned
logical owner ticket and its receipt sequence. Equal native engine scalars
produce distinct generations; no producer API or native generation carrier
is installed. Both old native registration callers still ignore its status.

New expected_mutex_address optionally pins the checked kernel's actual U+148
snapshot before raw acquisition. Equal/overlapping13C/148 objects are rejected
at composition, and a late actual-pointer mismatch denies before attempting
self-lock. Both old kernel modes without the pin remain byte-identical:
10,824/12,120 bytes; passive receiptdefaultNone also remains2,196 bytes with
unchanged labels. The optional callback and checked pin are not enabled in any
existing firmware builder. Composition checks complete cross-component RX/data/
controller/mutex extents, not merely entrypoints.

Binding schema/capacity/empty-slot checks precede owner allocation. Tickets and
receipt sequences are strictly increasing, not necessarily dense. Old pointer-
like fields are historical scalars, never followed. Raw148 errors suppress
positive binding and save exact status/quarantine only in the13C-protected
binding journal. An owner row may already have been minted on unlock error:
no readback, rollback, retire/close, retry or guessed unlock follows. Quarantine
stops this issuer only, not direct users of the44-byte API; full-instance
external quarantine/cooperative user coverage remains an integration gate.
Native13C release is still masked, so a binding is not a release/lifetime/free
receipt. The passive receipt can succeed while owner issuance is denied.

13C->148 is a new bounded lock edge, not universal deadlock freedom. Existing
source evidence finds no inverse nested edge in four examined paint sections
and shows sequential paint release before teardown registry acquisition.
All four redirects and genuine retained stable ABI/fields/initialized distinct
ordinary mutexes/imports remain premises. Shared-wrapper stack coverage is
unproved; simultaneous helper frames add192+192+160=544 bytes before native/
library costs. Native architecture/results are preserved in the fixture, not
timing, blocking, scheduling or progress. No producer-generation transport,
cleanup continuation, native lease or UI/currentness authority is enabled.
See [historical owner issuance and integration limits](folderfollow-reveal-registry-owner.md).

Serial focused verification: **232 tests pass, no skips** (13.573 s), including
54 new checks (21 basic/ABI/config,27 adversarial,6 pinned-source/emitted-CFG)
plus178 preceding receipt/retirement checks. Coverage includes raw errors and
ambiguous ownership, surviving orphan owner effects, no post-error owner-state
access, narrow quarantine with no reattempt, journal validation before minting,
non-dense owner history, actual late mutex changes, immutable owned snapshots,
full native and callback ABI, unchanged golden modes, code/data aliases and
bounded call-graph/lock-order evidence. All245 Python scripts compile and
changed/new text passes whitespace checks.

Fresh serial full regression: **2,285 tests pass, no skips** (297.750 s).
Independent source/adversarial and integration/ABI/extent/documentation reviews
found no actionable issue within the stated premises. Composed code is16,216
bytes (12,248 kernel+1,680 issuer+2,288 opt-in receipt); default private state
is656 receipt+784 bindings+328 owner bytes. Saved action-link, playback-dispatch
and renderer-transport images are exactly reverified against02fd with unchanged
d4306357...,a9a6f02f...,f42fac46... hashes, scrollingFalse/hardwareUNTESTED.
Existing firmware builders/decoders,40-byte core, launcher/timers/assertions
are unchanged; the44-byte extension is explicit opt-in with old emissions
preserved. No device/network operation, installation, commit or push; changes
remain local/uncommitted, actual producer integration and active scrolling gated.

### Offline explicit captured-carrier publication (2026-10-26)

A separate MIPS entry accepts U, owned36 and the exact creation-captured
(binding sequence, owner) pair. The instruction fixture retains that pair from
actual issuer registers at binding_committed, not by later engine/node/name/
latest-row lookup. Under pinned raw13C the adapter validates the complete
historical binding schema and exact pair, then invokes the actual checked/
pinned44-byte publish kernel under distinct148. It does not access owner state
directly or open/remint a generation. Retired same-engine identities cannot
adopt a replacement; an older live pair remains valid independently of later
equal-engine registrations. Pair validation does not authenticate its capture:
genuine creation-time retention and cooperative caller transport remain premises.

The composed guard rejects source/frame aliases into full receipt/binding/owner
state, controller, mutexes and native/generated RX before memory copy/frame
save/raw calls. The full creation prefix and receipt extent are explicit
descriptors; standalone omissions retain their nonaliasing caller premises.
The payload is snapshotted before raw services. An occupied next unissued
binding slot detects count rollback/dirty tails; full valid tables can still
publish an existing live owner. Positive nonce plus append index1 is success,
not raw failure. Zero/zero is ordinary denial without remint/retry/quarantine;
inner zero/nonzero status latches exact binding quarantine while13C is held.
That status may be raw148 or append failure, not necessarily pthread error.
Raw13C release error may follow successful append, returns zero/status and
performs no later shared access/write. Full-instance external isolation remains
required; no rollback, repair, cleanup or guessed unlock is introduced.

Pinned source contracts establish nine encoded native43C860 callers and the
missing owner argument, unsafe in-place44-byte native frame extension, occupied
engine/registry/callback layouts and constructor wrappers ignoring status.
No native producer, callback, queue or object layout transports the pair yet.
All such coverage, safe lifetime/free, checked cleanup and UI integration remain
gated. The in-memory44-byte queue fixture is not an installable firmware.
See [captured-carrier publication and native transport gaps](folderfollow-reveal-owner-carrier.md).

Serial focused verification: **290 tests pass, no skips** (17.310 s):58 new
checks (23 basic/ABI/extent,25 adversarial,10 pinned native-source contracts)
plus232 preceding receipt/issuance/retirement/admission checks. All250 Python
sources compile without file generation. Independent core/composition/source/
fixture and documentation reviews found no remaining actionable issue within
the stated caller premises; receipt-state aliases found in review were blocked
explicitly and tested, including boundary and full-prefix overlaps.

Default code is18,416 bytes (unchanged16,216 creation+2,200 adapter), SHA-256
`b085c15d00bff87ebb8211a574b5921a12f20030de42e7c7e7bbe426dae74394`
at the documented fixture addresses. Private state is unchanged at656 receipt+
784 bindings+328 owners. The160-byte adapter nests the160-byte kernel plus
native/library costs; aggregate stack and scheduling are not proven. No device/
network action, firmware installation, commit or push; changes stay local,
active scrolling disabled and hardware UNTESTED.

Fresh serial full regression: **2,343 tests pass, no skips** (334.985 s).
All250 Python sources compile;22 changed/new text paths pass whitespace checks.
Saved action-link, playback-dispatch and renderer-transport images are exactly
reverified against02fd with unchangedd4306357...,a9a6f02f...,f42fac46... hashes,
respectively33,492/24,532/23,240 code bytes and310/275/259 changed original
bytes. Each remains scrollingFalse/hardwareUNTESTED. Existing firmware builders/
decoders,40-byte core and launcher/timers/assertions are unchanged fromf79ca66.
No assertion or timer was weakened; no firmware image was built or modified.
No device/network action, installation, commit or push; all changes remain local.

### Text-only publication request (2026-10-26)

The user subsequently explicitly requested commit and push of the verified
offline receipt, historical owner issuance and captured-carrier publication
work above. Independent scope/security review found exactly22 expected text
files (7 Markdown+15 Python, including9 new test modules), no binaries, logs,
keys, secrets or unrelated configuration. The preceding fresh2343-test serial
regression and saved-image reverification remain the code verification record;
only this publication annotation changed afterward. Publication does not enable
native producer transport, cleanup, UI behavior or any player operation.

### Offline emitted per-invocation creation capture (2026-10-26)

Follow-up to committedf371c83. A new explicit register(U,descriptor20,out32)
wrapper copies the descriptor into its private frame and executes actual
4389E0 once. An opt-in issuer commit_callback receives the exact just-published
binding pair and owned request; emitted sink instructions, not a Python event
observer, retain it in that registration's private frame. The sink pins A1 to
the actual issuer snapshot before any request read and pins requestNativeSP to
actualsinkEntrySP+192receipt+192issuer, then wrapper=NativeSP+40. Exact wrapper
continuation, controller/engine, armed state and empty capture are checked.
An identical copied request or another valid armed same-engine frame cannot
replace this invocation. Scalar scope checks are not hostile-stack authentication.

Only native0 plus a fresh captured pair and independently owned write-once
out32 zero both before and after registration permit MAGIC-last export. NativeV0
and outaddress/zero are returned separately; preflight denial isFFFFFFFF/0
without entering native registration. There is no remint/retry/cleanup or latest
binding lookup. An earlier native node, owner or binding may already exist on
capture/export denial. The flags say HISTORICAL_RELEASE_UNOBSERVED: even raw13C
unlock error can export history because native wrappers discard its result.
This is not checked release, admission, a lease or permission to continue after
raw error. Full-instance external isolation and owned/mapped/coherent separate
input/output/nested stack remain premises. The sink saves its192-byte frame
before validation; no invalid-stack denial-before-write claim is made.

The local composer includes checked/pinned kernel, capture, opt-in issuer,
receipt and explicit producer adapter. Wrapper/source/output bounds cover full
states/controller/mutexes/native RX and exact full composed RX by a fixed-width
second pass. Only the wrapper's own frame is preflight-proved, not all deeper
native/library frames. Capture helper frames total160+192+192+192=736, plus
native registration40=776; the alternative kernel path totals744 before further
native/library costs. Aggregate stack availability, timing and progress are not
proved. Issuer commit_callbackNone keeps all earlier bytes/labels unchanged.

New source contracts expose the worker's earlier generation loss: only64-byte-
stride names are copied under the native registry callback bracket, then after
unlock4BAA20->43A0C0 and4BAA34->485DE0 find engine/resource again. Its strcpy/
fanout bounds are not proved; name lookup even loads node+8 after unlocking.
No current engine field or name equality can restore the selected generation.
The fifth callback argument is already occupied. Explicit creation capture is
a prerequisite only: no native explorer callback, worker, queue, object layout
or cleanup/free route consumes it yet. Real raw-unlock observation, owned
per-target pre-deferral context and retained native lifetime remain gates.
See [emitted creation capture and remaining native transport gaps](folderfollow-reveal-creation-capture.md).

Serial focused verification: **346 tests pass, no skips** (24.788 s):56 new
checks (18 basic/ABI,27 adverse/config,11 pinned source), plus290 previous
carrier/issuance/receipt/retirement/admission checks. Cases cover actual emitted
capture and no Python pair observer, double output preflight, exact request and
stack provenance, malformed/consumed/foreign contexts, full code/data aliases,
raw error partial effects, ALL-GPR/HI/LO, same-engine replacement/retirement,
and old byte-identity goldens. Independent implementation/composition/source/
fixture/documentation reviews found no remaining issue within these premises;
review-driven actual-depth and actual-request pins were added and tested.

Default composition is22,676 bytes (12,248 kernel+4,232 capture+1,708 issuer+
2,288 receipt+2,200 adapter), SHA-256
`90be0fdb56fa349782d7a5b89009661ca26484ad1beed25fb8628ddfc2383da5`
at the preceding documented fixture addresses. Private shared state remains656
receipt+784 bindings+328 owners; each independently retained output needs32
bytes. Old carrier18,416 and creation16,216 bytes retain their previous hashes.
No firmware image, installation, device/network action, commit or push. Active
scrolling stays disabled and hardware UNTESTED; changes are local/uncommitted.

Fresh serial full regression: **2,399 tests pass, no skips** (374.412 s).
All255 Python sources compile;10 changed/new text paths pass whitespace checks.
Old18,416-byte explicit carrier and new22,676-byte capture compositions are
exactly reverified against their documented hashes. Saved action-link, playback-
dispatch and renderer-transport images are exactly reverified against02fd with
unchangedd4306357...,a9a6f02f...,f42fac46... hashes, respectively33,492/24,532/
23,240 code bytes and310/275/259 changed original bytes. All remain scrolling
False/hardwareUNTESTED. Existing firmware builders/decoders,40-byte core and
launcher/timers/assertions are unchanged fromf371c83. No assertion/timer was
weakened, and no firmware image was built or modified. No device/network
operation, installation, commit or push; all changes remain local/uncommitted.

### Offline same-invocation raw13C release witness (2026-10-26)

The creation-capture assembler/composer now accept an explicit opt-in
checked_registry_release=True. DefaultFalse preserves all preceding22,676
bytes/labels, return semantics and historical flag1. Checked mode adds three
coherent local instruction-fetch redirects:438A60 observes actual T9 before
the original JALR/delay-slot effect;466DC8 checks actual A0 before raw unlock;
466DD0 captures actual V0 before native wrapper zeroing. All GPRs and HI/LO
are restored around displaced effects; the raw service keeps original SP,
pinned argument and RA466DD0. No firmware builder or native queue is changed.

Fresh private wrapper state progresses ARMED->SELECTED->ENTERED->CAPTURED and
is consumed once on native return. A separate status word preserves true
FFFFFFFF error distinctly from missing witness. W1C437DB0/W3C438A68, native
SP=W+40, wrapper=W+68 and exact wrapper native-return PC, saved raw/nativeSP,
mutex and wrapperU bind the route. Actual callback/argument are observed before
services, never guessed from later fields or clobbered registers. Release may
be observed even without owner issuance, but positive output also requires
the original fresh creation pair and all prior acquisition/issuance premises.

Checked output with flag2 REGISTRY_RELEASE_OBSERVED requires actual same-call
raw release0. Observed nonzero release returnsFFFFFFFF/exactstatus without
output; missing/invalid witness returnsFFFFFFFF/0. Actualrelease0 with no pair
or denied export returns0/0, not retry or continued-use permission. Native
acquisition failure still permits original unchecked native links with no pair;
allocation failure still omits unlock. No guessed unlock, retry, remint, close/
retire, cleanup or repair is introduced. Prior node/binding/owner effects can
survive failure; raw error requires full-instance external isolation.

After actual raw unlock, observer/wrapper processing uses only retained private
frames and successful exclusively owned output: no controller/journal/owner/
binding access or shared quarantine write follows uncertain release. A nonzero
service result can leave the mutex held or already released; no rollback or
recovery is inferred. Seven coherent old+new redirects and genuine retained
disjoint stack/route/service semantics remain premises, not arbitrary partial-
activation or forged-stack authentication. Initial observer192-byte saves occur
before validation. Global466DC0 callers also pay this save cost; four original
direct raw-unlock sites bypass it. No universal native synchronization coverage,
stack availability, scheduling/progress or native lifetime claim is made.

The bounded raw-release path is160 wrapper+40 registration+32 facade+32 raw
wrapper+192 observer=456 bytes before native/library costs, not simultaneously
nested with the earlier776-byte capture or744-byte owner-kernel paths. No shared
storage is added; the160-byte wrapper uses spare private slots. No native
explorer queue/fanout/callback/object layout/cleanup path consumes the record.
Pre-deferral per-target carrier retention, bounded snapshots and full lifetime/
cleanup participation remain integration gates. See [raw registry-release
witness and scope](folderfollow-reveal-registry-release.md).

Serial focused verification: **401 tests pass, no skips** (28.782 s):55 new
checks (20 native/emitted/ABI,23 adverse/config,12 pinned source), plus346 prior
capture/carrier/issuance/receipt/retirement/admission checks. Coverage includes
all3displaced architectural effects and rawSP/RA, forcedzero vs true error,
actual T9/A0 late changes, exact return-chain/private-scalar corruption, replay
without a second unlock, missing/stale hooks, either ambiguous release outcome,
no shared late access, full RX/state boundaries, strict bool and old byte goldens.
Independent source/core/fixture/documentation reviews found no remaining issue
under the stated premises; no assertion or timer was weakened.

Checked composition is25,716 bytes (12,248 kernel+7,272 capture/observers+1,708
issuer+2,288 receipt+2,200 adapter), SHA-256
`3c7b26a00fbd17bcd6c86719c21fa7ee5120ecaefcce1b4d9d6fb14332e6721c`
at the preceding fixture addresses. Default22,676 retains90be0fdb...2383da5;
private shared state656 receipt+784 bindings+328 owners and32 bytes per retained
owned output are unchanged. No firmware image, player/network operation,
installation, commit or push. Active scrolling disabled, hardwareUNTESTED;
all changes remain local/uncommitted.

Fresh serial full regression: **2,454 tests pass, no skips** (320.373 s).
All258 Python sources compile;14 changed/new text paths pass whitespace checks.
Old18,416/22,676 and checked25,716 compositions are exactly reverified against
their documented hashes. Saved action-link, playback-dispatch and renderer-
transport images are exactly reverified against02fd with unchangedd4306357...,
a9a6f02f...,f42fac46... hashes, respectively33,492/24,532/23,240 code bytes and
310/275/259 changed original bytes. Each stays scrollingFalse/hardwareUNTESTED.
Existing firmware builders/decoders,40-byte core and launcher/timers/assertions
are unchanged fromf371c83. No timer/assertion was weakened; no firmware image
was built or modified. No device/network operation, installation, commit or
push; all changes stay local/uncommitted, native explorer integration gated.

### Text-only capture/release publication request (2026-10-26)

The user subsequently explicitly requested commit and push of the verified
emitted creation-capture and opt-in raw registry-release work above. Scope is
exactly14 text files (5 Markdown+9 Python, including6 new test modules), with
no binaries, journals, keys, secrets or unrelated configuration. The fresh
2454-test serial regression and saved-image/hash reverification remain the code
verification record; only this publication annotation changed afterward.
Publication does not install firmware or enable native explorer transport,
cleanup, lifetime or UI authority. Hardware remains UNTESTED.

### Offline owned pre-deferral envelope (2026-10-27)

Local successor to committedacad6544. The new explicit68-byte envelope carries
the exact checkedGCAP32 and owned36 payload as values before deferral, without
storing a borrowed source pointer or resolving a later current owner by name.
Emittedpack snapshots/validates both inputs, requires observed-release flag2,
native result0, pinnedU, bounded positive sequences/owner and matching opaque
engine values. It accepts only independent zero output, checks all17 words
twice and publishes magic last. Schema checks are not capture authentication.

Emitteddispatch snapshots an exclusively owned envelope and marks its magic
CONSUMED before calling the actual checked producer with the saved pair and
stack-owned payload. It never rereads that source after publication. One valid
attempt consumes that buffer even on ordinary denial, full paint queue or raw
error; no retry/guessed unlock/cleanup is introduced. Different READY clones
can still publish distinct nonces: this is not global deduplication or an
exactly-once delivery guarantee. Invalid schema is not consumed or dispatched.

The fixture uses a separate typed nativeFIFO from456E60(capacity,68), real
455DA0->455BC0 append,4557E0 borrowed-head access and455860 removal. Under
explicit caller exclusivity it executes emittedpack into fresh owned work
BEFORE removal, requires remove0, then dispatches only that private copy.
Removal can immediately reuse the head address; its acknowledgement means
transport extraction, not rendering, paint completion, exact nonce ack or
native lifetime safety. It adds no shared queue guard, reservation, lock,
concurrent pop arbitration, scheduler or automatic failure isolation. Invalid
head/extraction failure requires external stop/isolation, not dispatch/retry.

Preallocated ten-element native segments are crossed without growth; append
is refused at actual allocatedQ+8 capacity. Native455980 growth retains its
NULL-realloc delay-slot clobber and partial allocation effects; it is not
transactional or repaired here. Nativeclear resets count only, not erasure,
owner revocation or drain. The substituted remove error tests caller control
flow only, not native remove failure/rollback safety.

The composition appends4,508 envelope bytes to the25,716 checked-capture prefix,
giving30,224 bytes. The preceding outerregister and explicitproducer RX-source/
frame guards extend over the exact tail through zero-defaultfollowing_code_bytes;
old instruction counts/labels/default bytes remain unchanged. New entries
protect the full composition before any source access or frame save. This is
not a universal inherited-entry certificate: observer save-before-validation
stack premises and direct owner-kernel RX/heap/list/stack premises remain.
Pack uses160 helper-stack bytes; dispatch nests160+160+160 before native/library
costs. Mapping, full stack availability, coherent exclusive inputs, caller queue
serialization and retained native storage remain explicit requirements.

No original explorer queue/fanout/worker/callback is wired. The native16/20-byte
stack payload, name-only snapshots, occupied fifth callback argument, unchecked
T+10 status, whole-program lock audit, bounded capture allocation, controller/
engine/resource retention and safe cleanup/free remain integration gates. Frozen
generation values grant neither a native engine lease nor UI authority.
See [owned deferred-envelope protocol](folderfollow-reveal-deferred-envelope.md).

Serial focused verification: **460 tests pass, no skips** (43.273 s), comprising
59 new checks (19 native FIFO/emitted/ABI,28 adverse/configuration and12 pinned
source checks) plus401 prior capture/release/carrier/issuance/receipt/retirement/
admission checks. Coverage includes stale generation at reused engine addresses,
active old cancellation/exact ack versus new generation, all17 dirty output
words before/after snapshot, full RX/state/frame boundaries, exact unsigned
extent endpoints, source mutation after copying, local replay versus clones,
ambiguous raw acquire/release outcomes, no late source/shared access, no-dispatch
after extraction denial and unchanged default hashes. Independent core/source/
composition reviews found no remaining issue under the stated premises.
Fresh serial full regression: **2,513 tests pass, no skips** (369.167 s).
All263 Python sources compile without writing files; all11 changed/new text
paths (4 Markdown+7 Python) pass whitespace checks. No timer/assertion was
weakened. Existing firmware builders/decoders,40-byte core and launcher remain
unchanged fromacad6544.

At the preceding fixture addresses the30,224-byte composition is exactly
reverified with SHA-256
`49687ac90583cc610cbca3bb1c12dc96c6bbed02fe4ba67ad64d2deaa8410df3`.
Old18,416-byte carrier,22,676-byte default capture and25,716-byte checked capture
retain their documented b085c15d...,90be0fdb...,3c7b26a0... hashes respectively.
Saved action-link/playback-dispatch/renderer-transport images are exactly
reverified against02fd with unchangedd4306357...,a9a6f02f...,f42fac46... hashes,
33,492/24,532/23,240 code bytes and310/275/259 changed original bytes. All three
remain autoscrollFalse/hardwareUNTESTED; no image was built or modified.

Shared state remains656 receipt+784 bindings+328 owners; each envelope/work
copy needs68 bytes plus separate FIFO storage. No new shared state/mutex, image
builder, firmware image, device/network operation, installation, commit or push.
Active scrolling remains disabled, hardwareUNTESTED; changes are local.

### Offline checked-T transport synchronization (2026-10-27)

The separate typed native68-byte FIFO now has emitted checked enqueue and
pop/dispatch entries with one distinct pinned retained ordinary nonrobust raw
mutexT. Stock workerT+10, original16/20-byte records and native worker callbacks
are not reused or connected. Actual rawA5B960/A5B830 results gate access rather
than status-erasing466DA0/466DC0. All cooperating access, including any future
clear/destroy/rebind/cleanup, must use this same T; initialized mutex/import
semantics, retained nonaliasing table/chunk/controller storage, adequate stacks
and callers entering without T/R/P/unreviewed reverse locks remain premises.

Enqueue first executes emittedpack into private68 before acquireT, retaining no
source pointer. Under acquire0, fault is checked before header; header pins
width68,chunk10,exact allocated count, bounded unsigned count and alignednonnull
table, deliberately not uninitializedQ+4. Full refuses before native growth.
Native APPEND must return the previous index and count must increase by1 under
T. Success after release0 is(index+1,0), not a native raw status or paint nonce.

Pop holds T over actualGET, head extent checks, emitted privatepack before
REMOVE, actualREMOVE0 and count decrement1. Only actualrelease0 permits emitted
dispatch through the existing R->P producer. No Q/fault/head/source access
follows release. Private READY work is never exported as a retry handle; removal
can already have taken effect before an uncertain release or publisher failure.
Every confirmed acquire has one release, no guessed unlock or automatic retry.
T is not held across R/P publication. Extraction FIFO does not order publication
between concurrent drainers; strict later order requires a single ordered
drainer or additional sequencing. Removal is not rendering/exact nonce ack.

Confirmed-held schema/head/append/remove postcondition faults latch1/2/3/4 in
one initially-zero4-byte word, never reset here. Future guarded queue operations
deny before queue access, but already extracted private work is not revoked.
Raw acquire errors return0/exactstatus without queue/fault access. Raw release
errors return0/exactstatus without late shared writes/accesses or dispatch,
even when append/remove already happened. Either ownership outcome requires
external whole-instance isolation; this does not implement a cross-thread
cancellation gate for other waiting/in-flight calls or promise rollback/free.

The source-pinned audit adds14 checks for actual pthread import relocations,
facade status erasure/ignored init status, capacity rounding/header/methods,
copy/count/index order, borrowed GET, growth table clobber and spare-slot REMOVE.
Precision: REMOVE traverses ceil(count/10) live chunks, not all unused allocated
chunks, but moves spare slots in the final live chunk. Complete valid retained
table and allocated chunks remain premises, not arbitrary corruption protection.
See [checked transport protocol and limits](folderfollow-reveal-deferred-queue.md).

The new fragment is3,976 bytes, after the30,224-byte envelope prefix, for34,200
bytes total. At the preceding receipt/binding/owner/U/R/P/CODE fixture addresses,
Q=01FF0000,T=01F20400,fault=01FE0000,slots40 gives SHA-256
`27c7d0fbad229b65ca81d4b0f9caf3d0581f8ba8a6ba599cf77f574dcc6fdd8b`.
Two-pass composition binds real emitted pack/dispatch and extends old outer RX
guards over the exact tail. Zero-default envelopefollowing_code_bytes preserves
the old30,224-byte golden; inherited internal-entry data/heap/initial-save and
nested-stack premises, including separation from newQ/T/fault, remain unchanged.
Pack path uses256+160 helper-stack bytes; dispatch256+160+160+160=736 before
native/library costs, not a complete stack-availability or scheduling proof.

Serial combined focused verification: **515 tests pass, no skips** (65.812 s),
including55 new checks (13 emitted/native/ABI with blocking two-CPU case,
28 adverse/configuration/boundary and14 pinned source) plus460 preceding
envelope/capture/release/carrier/issuance/receipt/retirement/admission checks.
The two-CPU fixture has independent SP/registers and shared retained memory and
T/R/P substitute locks. CPU2 has no queue/fault access while CPU1 holds T;
actual native extractions yield distinct private payloads and two unique paint
nonces. These locks are test substitutes, not native scheduler/hardware proof.
Coverage includes all fixed-state/native/generated RX source/frame starts/tails
before any access, borrowed-head outer-frame/new-state aliases, exact unsigned
extent endpoints and valid RX adjacency, strict descriptor/address/domain
checks, capacities10/10240 emission boundaries, counter postconditions,
raw status1/22/0x82/0xFFFFFFFF with either ambiguous ownership outcome, no late
queue/source access, no T-held R/P publication, backpressure/loss, retired equal
engine generations and distinct clone publications. One incorrectly chosen
overflow address in the new test fixture was corrected to actually cross the
jump-region boundary; no implementation or assertion/timer was weakened.
Independent core/source/composition/documentation reviews found no remaining
issue under the explicit premises. All268 Python sources compile without
writing files;17 changed/new text paths (5 Markdown+12 Python) pass whitespace.
Fresh serial full regression: **2,568 tests pass, no skips** (344.964 s).
The34,200-byte synchronized composition is exactly reverified against27c7d0fb...
at the explicit addresses above. Prior18,416/22,676/25,716/30,224-byte
compositions retain b085c15d...,90be0fdb...,3c7b26a0...,49687ac9... respectively.
Saved action-link/playback-dispatch/renderer-transport images are exactly
reverified against02fd with unchangedd4306357...,a9a6f02f...,f42fac46... hashes,
33,492/24,532/23,240 code bytes and310/275/259 changed original bytes. All retain
autoscrollFalse/hardwareUNTESTED. Existing firmware builders/decoders,40-byte
core and launcher/timers remain unchanged fromacad6544; no image was built or
modified, no timer/assertion weakened. Changes remain local/uncommitted.

Shared receipt656+bindings784+owners328 accounting stays unchanged; transport
adds retained fault4 and mutex24 plus its separate native header56/table/chunks.
No native engine/resource lease, fanout capture/allocation, cleanup/free, mutex
init/destroy, native queue lifecycle, worker callback or UI wiring is added.
No firmware image/device/network operation, install, commit or push; scrolling
disabled, hardwareUNTESTED and changes local.

### Text-only deferred transport publication request (2026-10-27)

The user subsequently explicitly requested commit and push of the verified
owned-envelope and checked-T queue work above. Scope is exactly17 text files
(5 Markdown+12 Python, including6 new test modules), with no binaries, journals,
keys, secrets or unrelated configuration. The515-test focused and2,568-test full
serial regression,268-source compilation and saved-image/hash reverification
remain the code verification record; only this publication annotation changed
afterward. There are114 new tests relative toacad6544 (59 envelope+55 queue).
Publication does not install firmware, replace the original worker queue,
provide cross-thread error isolation/native lifetime or authorize UI operation.
Hardware remains UNTESTED and active scrolling disabled.

### Offline first-constructor creation handoff (2026-10-27)

Local successor to committedf02b5fe. The explicit construct(U,request12,out48)
wrapper executes actual43AD00 once and preserves that invocation's creation
capture plus exact registration V0/V1 before native continuation discards them.
It does not redirect explorer492918 to the new API, replace any native worker,
retain objects or provide admission/error isolation. Request12 carries native
A1 mutable descriptor104, A2 callback and A3 context; these are not spare native
registers or an extension of the inner20-byte registration descriptor.

The wrapper guards dynamic/fixed extents before saves/descriptor access, checks
all12 output words zero before input reads and again after actual native return,
and requires NUL within descriptor's first64 bytes before native calls. Native
descriptor reads reach+64 and its+5C write is preserved. The guarded pointer is
retained, not reread from a later modified request. Coherent exclusive request/
descriptor/output, valid retained native resources/context and full stacks are
still premises. This bound is the new explicit input subset, not a native name
length guarantee for legacy callers. A dirty late output suppresses all export.

One coherent local registration-call override at43AE8C preserves the original
delayA1=constructorSP+50 and RA43AE94. The bridge validates native136 frame and
savedRA+84==emittednative_return BEFORE reading outer256 frame; legacy calls
tail-forward to original4389E0 without a new bridge frame or outer-context read.
Only a pinnedU/freshARMED bound route calls the actual checked register entry.
Private tag moves ENTERED->RETURNED; duplicate/reentrant bound entry invalidates
export, not reuses the old capture. ActualregisterV0/V1 and privateGCAP survive
native postwork. Scalar route/tag tests do not authenticate fabricated stacks.

Matching success exports exactGCAP32 only for flag2/native0, bounded sequences/
owner, exact privatecapture pointer and captured engine==actual constructorV0.
Otherwise output has CNFL and zero first32 body; its tail preserves actual
engine, actual observed registerV0/V1 and witness flags0missing/1seen/3matched.
Missing witness is distinct from observed zero. RegisterV1 can be a historical
private-stack scalar, not a future dereferenceable handle. NativeV0 is preserved;
V1 is exportedout48 or0. Body/tail precede magic; no emitted calls or native/
shared-object reads follow actual constructor return. No Python table/issuer
observation supplies a positive pair. GCAP can enter emitted pack and checked
68-byte transport/44-byte paint path; CNFL cannot substitute for a generation.
The recorded words are actual checked-register entry returns, not recovered raw
acquisition status: observed0/0 can mean quota/export denial or native masked
acquisition failure. No later table search assigns a cause or absence of effects.

Native continuation deliberately remains unsafe:43AE94 calls519FA0, which can
invoke8B43C0 setters and43A0C0 relookup even after registration/raw-release error.
The wrapper observes, not suppresses or isolates this. Missing resource/failed
validation andNULL engine paths can dereferenceNULL before any export. Native
registration allocation failure still omits unlock. No early epilogue, guessed
unlock, rollback, retry, rescan, cleanup/free, engine/resource lease or UI claim.
If uncertain release retained nonrecursive R, native continuation may reenter/
block on lookup; a returning UI test substitute proves neither native progress
nor that error reporting precedes unsafe work. No return means no promised export.
Engine/node deletion4395A0 and independent resource deletion493F50 still require
complete pre-mutation participation and retained contexts before worker wiring.
See [first-constructor capture scope](folderfollow-reveal-constructor-capture.md).

The fragment is5,876 bytes after the34,200-byte queue prefix, for40,076 bytes.
At the preceding fixture addresses withQ=01FF0000,T=01F20400,fault=01FE0000,
slots40 it has SHA-256
`3bf7a75351ea9c91d2ff629d1a24f6deb478a918b2fa2696217f8c250c000693`.
Two-pass composition binds actual checked register, supplies Q56/T24/fault4
exclusions and extends every old outer bulk-source RX guard over the exact tail.
Queuefollowing_code_bytes default0 preserves the preceding34,200 bytes/labels.
Inherited internal-entry mapping/data/heap/initial-save/nested-stack premises
remain. Bounded capture stack is256+136+160+776=1,328 bytes before additional
native/library costs, distinct from519FA0's320-frame/transitive UI path; no
complete stack/scheduler/cache/import/native-lifetime proof follows.

Pinned source15 checks pass (1.986 s), including13 encoded direct firstconstructor
callers and2 registration callers, real engine84 allocation, input/frame/ABI,
native statusloss, postworkUI/lookup andNULL/cleanup counterexamples. Indirect
coverage remains unproved; secondconstructor43AF00 is not intercepted.

Serial focused verification: **577 tests pass, no skips** (106.247 s), comprising
62 new checks (16 actualconstructor/ABI/path,31 adverse/boundary/configuration
and15 pinned source) plus515 preceding queue/envelope/capture/release/carrier/
issuance/receipt/retirement/admission checks. Actual43AD00,8B4120,8B0D00 and
4389E0 execute; allocator/libc/resource/setup/raw and519FA0UI-continuation/name
boundaries remain explicit hostile-ABI substitutes, not native UI completion.
Positive creation passes emittedpack, checked native68 FIFO and actual44 paint
publication; wrong/absent capture produces CNFL rather than latest-row repair.
Coverage includes full extra/fixed/native/generated RX request/output/descriptor/
outer-frame boundaries, all12 initial/late dirty output words, NUL64 limits,
exact unsigned endpoints, guarded-pointer reuse versus request mutation,
actualengine/status/capture mismatch, native savedRA before outer reads,
genuine legacy zero-frame fallback, foreign U, stale/duplicate/reentrant tags,
missing constructor/release hooks, preserved error/native-effects/UI continuation
and exact NULL-fault counterexamples. The new fixture alone adds missing LBU
interpretation; shared interpreters and production code were not changed for
the harness. Two incorrect new fixture expectations (displaced delay-slot trace
and shortened-RX assembly without matching extra exclusions) were corrected to
test actual published receipt/commit and the identical composed extent. No
existing assertion/timer was weakened. Independent core/source/composition/
documentation review found no remaining issue under the explicit premises.
All273 Python sources compile without writing files;10 changed/new text paths
(4 Markdown+6 Python) pass whitespace checks.
Fresh serial full regression: **2,630 tests pass, no skips** (396.598 s).
The40,076-byte constructor composition is exactly reverified against3bf7a753...
at the explicit addresses above. Prior18,416/22,676/25,716/30,224/34,200-byte
compositions retain b085c15d...,90be0fdb...,3c7b26a0...,49687ac9...,27c7d0fb...
respectively. Saved action-link/playback-dispatch/renderer-transport images are
exactly reverified against02fd with unchangedd4306357...,a9a6f02f...,f42fac46...
hashes,33,492/24,532/23,240 code bytes and310/275/259 changed original bytes.
All remain autoscrollFalse/hardwareUNTESTED. Existing firmware builders/decoders,
40-byte core and launcher/timers remain unchanged fromf02b5fe; no firmware image
was built or modified. No existing assertion/timer was weakened.
No firmware image, device/network operation, install, commit or push. Active
scrolling disabled, hardwareUNTESTED; all new changes stay local/uncommitted.

### Offline cooperative outstanding-operation ledger (2026-10-27)

Local successor to the constructor-capture work above. One initially-zero
ledger binds once to a genuine checkedGCAP32 plus three opaque externally
retained resource/callback/context words. Its separate native FIFO72 carries
an append-only token plus unchangedREADY68. Neither FIFO68 nor paint44 changes;
no stock worker, native cleanup or constructor caller is redirected to this API.
See [operation accounting scope](folderfollow-reveal-retained-operations.md).

Under a new distinct checked raw mutexM, enqueue validates the immutable bound
capture and reserves a nonreused operation BEFORE actual nativeAPPEND. A pop
copies the exact token/head before actualREMOVE, then leaves EXTRACTED outstanding
across M release, actual R->P publication and nonce binding under a fresh M
acquisition. Empty transport does not release this accounting. Successful
publication's actualV1 insertion index is retained independently across rawM
calls; it is not confused with pthread status. No M->R/P nesting is introduced.

Only exact PUBLISHED nonce can enter ACKING before actual checkedpaint.complete.
A terminal1/2/3 with successful release, followed by a successful M rebind, can
mark DONE. An early claim before nonce binding remains outstanding; early exact
complete refuses before calling paint.complete. Actual complete(0,0) stays
ACKING without retry: it conflates missing/wrong claim and post-REMOVE/schema
fault. A valid actual claim is a caller premise, and misuse may prevent drain.
Raw M/R/P error immediately returns without another lock/shared-state access,
guessed unlock, post-release fault latch, repair, retry or cleanup. Already
effective append/remove/ack is not rolled back. Whole-instance coordinated
isolation, including waiting/in-flight callers, remains an external requirement.

Close irreversibly stops new admission without purging published paint work.
Queued operations cancel only by successful exact closed pops; inflight and
published operations remain outstanding. Positive combined quiescence requires
CLOSED, healthy full ledger, all occupied rows DONE and actual FIFO72 empty,
then actual checkedpaint.retire and checkedpaint.drained outsideM. The old
count-only retirement cannot run while tracked acknowledgements are live.
Ordinary publish(0,0) may finish a local attempt but cannot bypass the checked
paint fault/drain barrier after partial native append. No result authorizes
native free, opaque callback invocation or UI operation.

Full schema validation covers reserved words, exact append-only row tokens,
state/nonce domains, unique positive historical nonces including DONE, and zero
unused tail. Opaque bundle words are not dereferenced or authenticated; actual
native lifetime/cleanup coverage is still required before any unlink/detach/free.
Native4395A0 engine deletion, separate493F50 resource deletion and constructor
519FA0 unsafe UI/lookup/error continuation remain unchanged and unwired.

At receipt01F50000,binding01F80000,owner01F70000,U01800000,R01F20300,
P01F20200,code01E80000,oldQ01FF0000,T01F20400,oldfault01FE0000,
ledger01F40000,Q7201FF1000,M01F20500, capacities16/16/64/40/16/40,
the exact composition is55,164 bytes: extended constructor prefix41,084 plus
new fragment14,080. SHA-256:
`8217a5c2c4a091c73892b76a5f95ae0d178b866e6253ffffb89bc6fad333acb8`.
New fixed storage is ledger320+FIFOheader56+mutex24, excluding all retained
native table/chunks and externally retained bundle/stack allocations. Default
constructor composition stays40,076/3bf7a753...; optional zero-default RX tail
and empty-default extra-data exclusions preserve old bytes/labels. New outer
guards cover complete composedRX and all new fixed data; inherited internal
entry, native heap/list/mapping/nonaliasing and transitive-stack premises remain.

Fresh serial focused verification: **642 tests pass, no skips** (146.975 s),
including65 new checks (19 actual lifecycle/native paths,31 adverse/ABI/boundary
and15 pinned native/emitted-source/composition checks) plus577 predecessors.
Actual43AD00 capture, native72 FIFO methods and checked44 paint methods execute;
resource/UI/heap/libc/raw services remain explicit bounded substitutes. Coverage
includes segment crossing, distinct clone tokens/nonces, capacity nonreuse,
immutable snapshots, exact closed cancellation/acknowledgement, deterministic
independent-CPU early-claim/close interleavings, raw acquisition/release/rebind
uncertainty, retained partial effects, ambiguous completion, healthy paint barrier,
dirty unused rows, duplicate historical nonces, fixed/generated/nativeRX/frame
aliases and exact unsigned2**32/signed0x80000000 extent boundaries. These fixtures
do not establish native scheduling, object leases or complete writer coverage.
Independent core/composition/protocol review found no remaining actionable issue.
The saved-index detail was corrected before the first test run; no preceding
assertion, timer, native helper or firmware builder was weakened or modified.
Fresh serial full regression: **2,695 tests pass, no skips** (426.535 s).
All278 Python sources compile without writing files. The55,164-byte composition
is exactly reverified against8217a5c2... at the canonical addresses above.
Prior18,416/22,676/25,716/30,224/34,200/40,076-byte compositions retain exact
b085c15d...,90be0fdb...,3c7b26a0...,49687ac9...,27c7d0fb...,3bf7a753...
hashes respectively. Saved action-link/playback-dispatch/renderer-transport
images are exactly reverified against02fd, retaining d4306357...,a9a6f02f...,
f42fac46..., code33,492/24,532/23,240 and310/275/259 changed original bytes;
all remain autoscrollFalse/hardwareUNTESTED. No firmware image was built or
modified. All16 changed/new text paths (5 Markdown+11 Python) pass whitespace
checks. No device/network operation, installation, launch, reboot, commit or
push; all constructor and operation-ledger changes remain local/uncommitted.

### Optional historical-capture cleanup intent (2026-10-27)

The native cleanup audit rules out simply gating the final engine/resource
delete pair.4395A0 deletes the first equal NAME, not a supplied captured engine
or generation; its masked R callbacks do not propagate actual raw errors.
Its first unlink439618 precedes all frees. The usual earlier439780 already
purges raw paint rows under R without P, then detaches parent membership through
8B0760. Explorer's493F44/493F50 pair follows optional worker shutdown493EB4,
list cleanup493EC8, controller/worker stores493F04/493F14, cache cleanup493F2C
and purge/detach493F38. Separate485320 resource cleanup forces zero after inner
operations rather than reporting an exact successful/deferred outcome.
The bounded source census still does not prove every teardown-arm entry.

An opt-in retained cleanup_intent_address word now enables explicit
prepare_cleanup(U,owned_zero48). None preserves the preceding55,164-byte
operation composition exactly. This entry calls no native detach/destructor,
name lookup, callback, continuation or free; it is not installed in a stock
caller. See [cleanup intent scope](folderfollow-reveal-cleanup-intent.md).

Before any save or shared-state access, full output/frame/fixed/nativeRX/
generatedRX guards and all12 zero output words are checked. Under confirmed M,
the full ledger must be healthy, CLOSED, all occupied rows DONE and FIFO72 empty.
Busy work refuses before consuming the sole attempt. The immutable GCAP32 plus
three opaque words are snapshotted, then the separate intent word irreversibly
moves0->1 before M release. Only confirmed release0 permits the actual existing
quiescent entry (including its own checked M and P retire/drained barrier).
Only exact barrier(1,0) and a second all12-word output-zero check can export
CINT48: magic0, historical boundGCAP32 at4..35 and opaque resource/callback/
context at36/40/44. Body precedes magic; success is outputpointer/0.

No failed/uncertain release, ordinary barrier denial or dirty late output resets
the reservation. Duplicate prepare refuses before the P barrier; deterministic
independent-CPU interleavings cover the gaps before barrier and before export.
Raw errors return without another lock/call/shared-state read/write; neither
gate nor output is repaired. Retained native bundle, all shared state, output,
mutexes, waiting/in-flight callers and future intent consumption remain external
cooperation/retention premises. CINT is historical captured accounting, not
current native identity, allocation lease, cleanup result or free permission.
A later native name relookup remains unsafe against untracked replacement;
holding R across unchanged native deletion would re-acquire ordinary R.

At the preceding canonical55,164-byte addresses plus intent01F20600, the opt-in
composition is58,948 bytes: constructor prefix41,420 plus retained fragment17,528.
SHA-256:
`1ec55000c87c58bedabd5e4f545ed665955b42f845c3efc4aea82e13949f54e0`.
The additional fixed state is one retained4-byte word, not a native reference
counter. New outer guards exclude it and the complete composed RX; inherited
internal-entry/heap/list/mapping/full-stack nonaliasing premises still apply.

Fresh serial focused verification: **50 tests pass, no skips** (48.304 s):
15 actual-path/lifecycle checks,20 adverse/ABI/boundary checks and15 pinned
native/composition contracts. Actual constructor capture, native FIFO72 and
checked paint44 completion precede real emitted preparation/barrier/export;
bounded raw/library/heap/resource/UI substitutes remain explicit. Coverage
includes live/open refusal without reservation, exact closed cancellation and
acknowledgement, clone accounting, one-shot races, all12 initial/late dirty
output words, M/P acquire/release uncertainty at both critical sections and
paint barriers, full fixed/RX/frame boundaries, signed/unsigned endpoints and
hostile-ABI preservation. No preceding assertion, timer or builder was changed.
Independent source/protocol/core/composition review found no actionable issue.
Fresh serial full regression: **2,745 tests pass, no skips** (470.577 s).
All281 Python sources compile without writing files. The58,948-byte opt-in
composition is exactly reverified against1ec55000... at the addresses above;
default55,164/8217a5c2... is unchanged. The preceding18,416/22,676/25,716/
30,224/34,200/40,076-byte compositions retain b085c15d...,90be0fdb...,
3c7b26a0...,49687ac9...,27c7d0fb...,3bf7a753... exactly. Saved action-link,
playback-dispatch and renderer-transport images retain d4306357...,a9a6f02f...,
f42fac46... and exact verification against02fd:33,492/24,532/23,240 code bytes,
310/275/259 changed original bytes, autoscrollFalse and hardwareUNTESTED.
All20 changed/new text paths (6 Markdown+14 Python) pass whitespace checks.
No firmware image, native cleanup installation, device/network operation,
launch, reboot, commit or push. Changes remain local/uncommitted.

### Read-only historical binding/current ring comparison (2026-10-27)

The next exact-unlink audit found an unresolved ABA: native node and engine
addresses can both be freed and reused while their historical48-byte binding
remains unchanged. A later live ring/field match under checked R cannot prove
continuous native incarnation. Native4389E0 allocates28-byte nodes, with links
and five descriptor scalars but no live binding sequence. Coherent publication
finishes at438A58. Besides name-selected4395A0 deletion, controller teardown
43CB20 independently unlinks/frees nodes at43CBB0..43CBC0, bypassing4395A0.
Missing/full issuance cannot veto unchanged native publication, so searching
the newest equal-pointer historical row cannot repair an uncaptured birth.

The new explicit audit_identity(U,exclusive_CINT48,owned_zero64) therefore
observes only. Full input/output/frame/fixed/nativeRX/generatedRX arithmetic
guards precede all input/output accesses and saves. All16 output words must
initially be zero before saves, source reads or consumption. A valid private
snapshot consumes owned CINT magic toCCNS before raw R acquisition;
malformed schema refuses before consumption. Copies remain independent attempts,
not global replay prevention. Under confirmed R the observer checks controller
fingerprints and full occupied binding prefix, then the exact captured sequence,
owner, engine and receipt sequence. It never adopts a latest-by-pointer identity.

Only the actual U+34 ring is followed. Every reached node's full28-byte extent
is guarded before read, previous links and final tail must agree, and the walk
must reach the sentinel within strict max_nodes1..1024 (default64). Historical
node addresses are not dereferenced just because the binding names them. Partial
matches before a bad/overlong/cyclic tail do not export. No engine/resource/name
object is read, no native/shared state is written, and no M/P, queue method,
callback, unlink, destructor or free is called. Current ring/controller/mutex
mapping, retention and common R writer synchronization remain caller premises;
these do not revive historical allocations or make their addresses current.

After actual raw release0 and a second16-word output-zero check, body-first/
magic-last RIAU64 carries kind1 MATCHING_FIELDS,2 NODE_ABSENT or3 ENGINE_MISMATCH,
historicalGCAP32, opaque context words, historical node, observed engine scalar
and completed scan count. Outputpointer/0 means diagnostic export only, never
generation match or native-free authority. Raw R acquire/release errors return
without further native/shared/input/output access, another lock, guessed unlock,
fault write or retry. CINT can already be consumed even though no output exists.
See [registry comparison limits](folderfollow-reveal-registry-identity.md).

The ABA fixture executes actual4395A0, its real unlink stores,8B3F00(NULLqueue),
8B4220 and8B0D20, with bounded strcmp/widget-destructor/free imports. A second
actual43AD00/4389E0 reuses the same84-byte engine and28-byte node through the
controlled allocator. Capacity1 denies a new historical binding/capture while
native publication still happens. OldCINT then yields MATCHING_FIELDS against
that new allocation, deliberately proving why this observation cannot authorize
deletion. The audit itself performs no native mutation. This setup exercises
the still-uncovered native cleanup path; it does not establish a continuous
allocation lease, complete native graph destruction or general allocator model.

At the preceding canonical addresses plus intent01F20600 and max_nodes64,
the composition is64,948 bytes:58,948 cleanup-intent prefix plus6,000 observer.
SHA-256:
`195de8d83670ed24f4301a2d01b78f3bd4e59f0efcfa6a5509101603b4dbcc1a`.
No new shared state is allocated. The retained composer's strict zero-default
following_code_bytes extends exact outer RX protection; its default55,164 and
opt-in58,948 bytes/labels remain unchanged. Internal-entry/native heap/list/
mapping/transitive-stack nonaliasing premises are not universally extended.

Fresh serial focused verification: **55 tests pass, no skips** (116.067 s):
15 actual-path/comparison/ABA checks,25 adverse/ABI/boundary checks and15 pinned
native-source/composition contracts. Coverage includes full ring/binding-prefix
validation, exact captured fields, absent-node no-dereference, scalar mismatch,
independent copies, raw acquire/release uncertainty, all16 initial/late dirty
output words, full source/output/node/frame/fixed/RX boundaries, budget/endpoints,
read-only stores, and hostile ABI. Receipt bounds were corrected to the actual
configured capacity before tests, not guessed from an unrelated1024 limit.
Independent source/protocol/core/composition reviews found no remaining issue
under the stated premises. No preceding assertion, native helper, timer or
firmware builder was weakened or changed.
Fresh serial full regression: **2,800 tests pass, no skips** (628.655 s).
All286 Python sources compile without writing files. The64,948-byte composition
is exactly reverified against195de8d8... at the canonical addresses above.
Preceding18,416/22,676/25,716/30,224/34,200/40,076/55,164/58,948-byte
compositions retain b085c15d...,90be0fdb...,3c7b26a0...,49687ac9...,27c7d0fb...,
3bf7a753...,8217a5c2...,1ec55000... exactly. The three saved action-link,
playback-dispatch and renderer-transport images retain d4306357...,a9a6f02f...,
f42fac46... with exact02fd verification:33,492/24,532/23,240 code bytes and
310/275/259 changed original bytes; autoscrollFalse, hardwareUNTESTED.
All26 changed/new text paths (7 Markdown+19 Python) pass whitespace checks.
No firmware image was built or modified, no native unlink installed, and no
device/network operation, launch, reboot, commit or push. All changes remain
local/uncommitted; live native identity/retention/cleanup integration is still gated.

### Independent historical native births (2026-10-28)

The next step separates birth observation from historical issuance quotas.
The receipt observer's opt-in birth_callback receives the actual invocation's
owned32 event after the final native publication store438A58 and fresh checked
raw R=0/controller gates, before any receipt header/row/capacity access. Existing
publication_callback ordering and zero-default bytes/labels stay unchanged.
The new event has no invented receipt/binding/owner sequence: U,R,node,engine,
nativeSP,caller,site438A5C,raw0. Caller-supplied callbacks must preserve ALL GPRs
and HI/LO, as must the emitted independent recorder.

The separate zero-initialized birth history has a16-byte header and40-byte
BRTH rows: magic,append-only token,U,R,node,engine,nativeSP,caller,site,raw.
Tokens are rowindex+1 and never reset/reused. Under the genuinely held common
ordinary R, the callback validates the full occupied prefix and entire unused
tail before append; corruption or exhaustion permanently latches FAULT=1.
Rows are committed body-first/magic-last then COUNT. Historical pointer words
are opaque and never dereferenced by the callback. Its initial192-byte full
register-save frame is an explicit validity/nonaliasing premise; subsequent
arithmetic/input/frame/fixed/RX exclusions precede input/controller/state loads,
not those initial saves. Schema checks do not authenticate forged events.

This is historical observation only, not the proposed live-incarnation sidecar:
there is no LIVE state, tombstone, exact-token query or native-free permission.
Native raw acquisition failure may still publish with no safely recordable
event. A healthy history therefore cannot certify continuous coverage, even
without reaching its own bound. Neither callback failure nor a full history
vetoes native publication or existing owner issuance. Whole-instance isolation,
all allocation/resource/callback lifetimes and stock caller continuations are
still independent integration gates.

The source census now pins four distinct controller-ring first-unlink sites:
439618,43CBB0,4E3F48,51A3E8. The latter outer shutdown loops release R before
reading/calling node callbacks and their unlink/free path, before43CB20.
Two pre-unlink observers would not provide complete coverage or a valid late
R guard. Native node+8 lookup escape, alias/computed writes and opaque callbacks
also prevent claiming an exhaustive lifecycle proof from encoded callsites.
See [independent birth scope](folderfollow-reveal-registry-birth.md).

The new local birth-stage branch composes explicit checked-release creation
capture plus the early callback; it does not replace later constructor/retained/
cleanup-intent/registry-observation compositions. The outer capture and birth
callback exclude the new state and exact full generated RX. Strict empty-default
extra_protected_data extends capture's own guards without claiming to extend
every inherited internal adapter or native heap/transitive-stack guard. The
generic creation composer requires a birth callback to lie entirely in its
advertised protected tail, outside its actual prefix and all fixed data.
No constructor/explorer/worker/unlink hooks, active scrolling or player work.

At the preceding seven canonical creation addresses and birth state01F38000,
the independent branch is28,088 bytes:26,232 guarded creation/receipt prefix
plus1,856 historical callback. Birth storage is656 bytes at capacity16.
SHA-256:
`0d40bc5bba95d1458af0cd79a7957377a034969fc45ff98fba27c495e3ce07b0`.
The extra guarded state and optional callback preserve all nine preceding
composition hashes with their defaults, including the64,948-byte diagnostic
branch195de8d8...; the new branch does not replace or retag those records.

Fresh serial focused verification: **67 tests pass, no skips** (11.160 s):
21 actual-event/ABI checks,25 adverse/boundary checks and21 pinned source/
composition contracts. Actual native publication precedes emitted recording
while old receipt/binding/owner limits, quarantine, ticket exhaustion and
nested P errors do not hide the independent event. Raw-acquisition errors,
missing/wrong witnesses and wrong bound routes cause no birth-state access,
even when unchanged native code still publishes. Coverage also includes all
historical prefix schema fields, full unused-tail validation, permanent faults,
scalar non-dereference, full GPR/HI/LO preservation, late raw-release errors,
protected-tail-only callbacks and new outer descriptor/output exclusions.
Direct synthetic equal events remain distinct historical entries, not proof
of authentic unique births or live incarnations. Independent source/protocol/
core/composition/fixture reviews found no remaining issue in the stated scope.
No preceding assertion, timer, native helper or firmware builder was changed.

Fresh serial full regression: **2,867 tests pass, no skips** (620.425 s),
with the local temporary-file/subprocess access required by the existing suite.
An earlier restricted run was interrupted after errors and is not counted as
a successful verification. All291 Python sources compile without file writes.
The28,088-byte branch is reverified at the addresses above against0d40bc5b...;
all nine old composition sizes/hashes remain exact. The three saved action-link,
playback-dispatch and renderer-transport images retain d4306357...,a9a6f02f...,
f42fac46... and exact02fd verification:33,492/24,532/23,240 code bytes,
310/275/259 changed original bytes, autoscrollFalse and hardwareUNTESTED.
All12 changed/new text files (4 Markdown+8 Python) pass whitespace checks;
independent scope review found no unexpected file, binary, log or secret pattern.
No image was built/modified, no stock lifecycle hook installed, no device or
network operation, launch, reboot, commit or push. Changes remain local.

### Four checked retirement frontiers, not confirmed deletion (2026-10-28)

The separate lifecycle-observation branch now pairs actual birth observations
with field-correlated retirement selection. It does not replace BRTH40, later
constructor/retained/cleanup-intent/RIAU branches or the saved firmware images.
An initially zero16-byte header precedes64-byte BRLC rows containing a nonreused
birth token, U/R/node/engine, exact birth frame/caller/site/raw0, state, retirement
site/frame/caller and two reserved zeros. State1 NO_RETIREMENT_OBSERVED is not
LIVE; terminalstate2 RETIREMENT_SELECTED is not DEAD or completed cleanup.

Birth callbacks append directly from the early native publication event,
independently of old receipt/binding/owner quotas. Under genuine ordinary R,
both callbacks validate the full occupied schema, global outstanding-node
uniqueness and all unused tail words. Birth collisions/full capacity, retirement
missing/mismatched/duplicate fields or admitted corruption permanently fault.
Retirement marks only a unique outstanding matching node/engine row, never
reviving a terminal row or minting a new token. Body/synchronized state2-last
commit is irreversible; a partial body with state1 faults on next admission.
A full healthy history may still mark an existing retirement. No positive
return record, LIVE query, token export or old-carrier retagging is supplied.

Eleven passive native redirects now cover fresh acquisition and four selected
frontiers.439618 and43CBB0 observe before replaying each first unlink pair.
4E3F18 and51A3B8 instead observe conservatively before the actual native unlock,
since their later callbacks/direct unlinks run without R. Empty sentinel
branches skip outer events. A selected callback can leave the node linked;
duplicate selection may fault conservatively without vetoing native cleanup.
The43CB20 witness remains captured across all nodes under one R acquisition
and is invalidated before release43CBD4. Two previously unused non-home scalar
locals10/14 carry per-scope readiness and exact raw acquisition status.

Global466DA8/466DB0 dispatchers classify the actual callback/native saved-PC
chain and pinned raw A0; registration/unknown routes fully restore and tailchain
the preceding receipt observer once. Actual raw V0 is captured before masking.
Failed/missing/wrong witnesses cannot access lifecycle state, even when native
code still unlinks/frees. All registers and HI/LO survive each bridge except
its precise displaced native effects; original native return PCs are retained.
The full16-pair coherent fixture map includes receipt and checked registration
release observers; arbitrary partial activation is not fail-closed.

New native/save-frame, input/current-node28 and fixed/native/generated RX
arithmetic exclusions precede observer loads. Raw N=W+40 overflow is explicitly
rejected before native-local access; direct executable endpoint tests cover it.
Initial full architectural-save stores remain an independent retained, mapped,
writable/nonaliasing frame premise, not a denial-before-store guarantee.
Unknown allocations/transitive stacks, real ordinary mutex semantics, complete
native resource/callback retention and coherent field stability remain external.

The new executable counterexample demonstrates that healthy state1 can outlive
a native raw-error deletion. A second raw-error publication with the same
node/engine field values can then be missed; a later checked retirement
correlates the new object's fields with the old historical record. This
deliberately proves the new terminal record is not authenticated continuous
incarnation. All four
known encoded frontiers do not solve missing raw-error events, escaped aliases,
sentinel reinitialization, complete graph destruction, safe caller continuation
or whole-instance isolation. No cleanup/free permission or native installation.
See [lifecycle observation scope](folderfollow-reveal-registry-lifecycle.md).

At the preceding canonical seven creation addresses plus state01F3A000,
the new branch is58,572 bytes:26,232 capture prefix,2,488 lifecycle callback
and29,852 retirement bridges. History is1,040 bytes at capacity16.
SHA-256:
`bfdee94f95de5d0b0a861dcfe18bb7ad8980f1a3df1556ae76532cd8c687b974`.
Exact complete generated RX is guarded by all new fragments and outer capture;
inherited internal-entry/native heap/stack obligations are not universally
extended. All ten preceding composition sizes/hashes remain exact, including
28,088/0d40bc5b... and64,948/195de8d8....

Fresh serial focused verification: **43 tests pass, no skips** (13.943 s):
16 actual-path/ABI tests,18 adverse/counterexample tests and9 pinned source/
configuration/composition checks. Actual registration and full4395A0 unlink
execute; bounded43CB8C..43CBDC and outer-loop sections have explicit entry/stop
boundaries. Pthread, allocation/free, strcmp, logging, paint/engine destruction
and callback imports are bounded substitutes, not complete object-graph cleanup.
Controlled28-byte node reuse after observed actual unlink mints a distinct token
while preserving the old terminal row, including old quota1 refusal. Additional
coverage includes three-node teardown, outer callback leaving links unchanged,
pre-unlink/pre-unlock event timing, full/dirty schema and tail, permanent faults,
each bridge's ALL-GPR/HI/LO boundaries, raw uncertainty/missing witnesses,
relocated native stores and unchanged native delete final architecture.

Fresh serial full regression: **2,910 tests pass, no skips** (676.168 s),
with the temporary-file/subprocess access required by the existing suite.
All297 Python sources compile without file writes. The58,572-byte composition
is reverified againstbfdee94f... at the addresses above. All ten preceding
composition sizes/hashes remain exact. The three saved action-link,
playback-dispatch and renderer-transport images retain d4306357...,a9a6f02f...,
f42fac46... and exact02fd verification:33,492/24,532/23,240 code bytes,
310/275/259 changed original bytes, autoscrollFalse and hardwareUNTESTED.
Independent source/protocol/core/bridge/composition/fixture/scope reviews found
no remaining issue within the stated observational boundary. All19 changed/new
text paths (5 Markdown+14 Python), including the preceding uncommitted birth
increment, pass whitespace/scope checks; no unexpected file or secret pattern.
No preceding assertion, timer, native helper or firmware builder was weakened.
No firmware image was built/modified, no native hook installed, no device or
network operation, launch, reboot, commit or push. Changes remain local and
uncommitted; safe native lifecycle/cleanup/UI integration is still gated.

### Exact owned birth-token handoff (2026-10-28)

The next separate local branch transfers the just-minted lifecycle token
directly from its actual birth commit into the exact registration invocation's
owned output. No node/engine/name/latest-row lookup is used. The optional
birth_commit_callback runs only after successful new row magic/count commit,
receiving U, the current lifecycle frame's owned32 snapshot and its actual token
in A2. Retirement, denied lifecycle birth or historical lookup never invokes
it; older issuance quotas do not gate it. None preserves previous bytes/labels.

The new register_birth(U,descriptor20,zero_out48) calls the actual existing
checked registration capture once. An all-GPR/HI/LO-preserving private sink
checks the exact nested frame relationship: request=L+0x90, native N=L+192+192,
checked capture C=N+40, outer W=C+160. Full extent/arithmetic exclusions precede
each deeper read; N+0x24 and the event caller must equal capture.native_return,
and C+0x70 must equal this outer's capture_return. Pinned C fields, its private
GCAP-output pointer W+0x10, both descriptor engine scalars and fresh W tag/zero
token/event must agree. The exact token/event are copied into W, not selected
from shared state. A fully scoped duplicate poisons export toINVALID without
reminting or overwriting the first token/event. Tags/bounds do not authenticate
fabricated frames or prove mapping, retention or unknown stack/heap nonaliasing.

BCAP48 is a distinct type: magic0, token4, owned event32 at8..39, actual native
result0 at40 and observed raw R-release0 at44. The event contains U,R,node,
engine,nativeSP,caller,site438A5C and actual raw acquisition0. There is no owner,
paint-health, native-reference, liveness or cleanup claim. No existing GCAP32,
CINT48, RIAU64, deferred FIFO or retained-operation format is extended/retagged.
Copying BCAP does not mint a second birth or enforce global replay prevention.
Future typed queue transport must carry this exact token explicitly.

Before any outer save/native call, full frame/descriptor20/output48 and known
fixed/native/generated RX guards, pairwise disjointness and all12 zero output
words must pass. The descriptor is snapshotted privately. After checked capture
returns, only W and the exclusive output may be accessed; no shared/native/input
read or additional service occurs. Nonzero checked V0 returns its exact V0/V1
using private restoration only, without any late output read/write. Native0
requires the exact private captured token/event plus a second12-word zero check
before body-first/magic-last BCAP export, returning0/outputpointer. Otherwise
ordinary0/0 leaves the output untouched. Raw-release error remainsFFFFFFFF/
exactstatus; missing witness/allocation failure remainsFFFFFFFF/0. The old
allocation-failure missing-unlock defect and native continuations are unchanged.

Checked registration's0/0 after owner/receipt denial still witnesses raw R
release0; a valid independent birth may therefore export BCAP without GCAP.
Nested P acquire/release uncertainty may likewise coexist with birth-only BCAP,
which grants no P health, owner issuance or safe reuse/cleanup. Raw R acquire
failure may still publish but cannot supply a fresh birth sink, so no BCAP.
Lifecycle fault/full/missing events refuse export without borrowing an old row.
All preceding missed-event ABA/alias/retention/error-isolation gates remain.
See [owned birth-capture scope](folderfollow-reveal-birth-capture.md).

The lifecycle composer's strict zero-default following_code_bytes advertises
the new tail without appending it. Its optional callback must fit wholly in
that protected tail outside actual emitted prefix/data. All enclosing capture,
lifecycle and retirement guards receive exact complete RX. At the preceding
canonical seven creation addresses plus state01F3A000, the new composition is
65,796 bytes:58,692 guarded lifecycle prefix plus7,104 outer wrapper/sink.
The optional composed lifecycle core is2,608 rather than default2,488 bytes;
the standalone default without four extra data extents remains2,104 bytes.
No additional shared state or native redirect is added:16 coherent fixture
hook pairs remain. SHA-256:
`76a95966f8e35f8053408b9a7cd0c472cabd0fed53ea9f1234af261a07331cb7`.
All eleven preceding composition sizes/hashes remain exact, including
58,572/bfdee94f...,28,088/0d40bc5b... and64,948/195de8d8....

Fresh serial focused verification: **44 tests pass, no skips** (24.933 s):
13 actual-handoff/ABI tests,15 adverse/boundary tests and16 pinned source/
configuration/composition contracts. Actual4389E0, fresh raw-result gates,
lifecycle commit, old optional owner issuance and native checked release execute;
allocation/pthread/cleanup imports remain the preceding bounded substitutes.
Coverage includes equal-engine distinct tokens, native node deletion/reuse,
quota/P-error independence, lifecycle fault/full, native allocation failure,
raw R errors/missing release, private-only error return, full initial/late
output dirtiness, complete fixed/RX/frame aliases, exact request/N/caller/
return/temp-output/descriptor gates, duplicate poisoning and ABI preservation.
An initial contract confused standalone/composed guard sizes; the expectation
was corrected without changing emitted behavior or weakening earlier checks.

Fresh serial full regression: **2,954 tests pass, no skips** (669.912 s),
with the temporary-file/subprocess access required by the existing suite.
All302 Python sources compile without file writes. The65,796-byte branch is
reverified against76a95966... at the addresses above, with16 coherent hooks
and exact complete RX guards. All eleven preceding sizes/hashes remain exact.
The three saved action-link, playback-dispatch and renderer-transport images
retain d4306357...,a9a6f02f...,f42fac46... and exact02fd verification:
33,492/24,532/23,240 code bytes,310/275/259 changed original bytes,
autoscrollFalse and hardwareUNTESTED. Independent protocol/core/composition/
fixture/source/scope reviews found no remaining issue in the stated historical
handoff boundary. All25 changed/new text paths (6 Markdown+19 Python), including
the preceding uncommitted birth/lifecycle work, pass whitespace/scope checks;
no unexpected file, binary, log or secret pattern was found.
No preceding assertion, timer, native helper or firmware builder was weakened.
No firmware image was built/modified, no stock producer/worker hook installed,
no device/network operation, launch, reboot, commit or push. Changes remain
local/uncommitted. Native lifetime/error isolation and active UI integration
remain independent gates; BCAP is not a LIVE certificate or free permission.

### Separate typed birth-token FIFO (2026-10-28)

The next local diagnostic branch carries the exact owned BCAP token/event and
an owned 36-byte payload through a separate preallocated native FIFO. It never
recovers a token by latest node/engine/name lookup or reinterprets any preceding
stock/GCAP32/READY68/retained-operation72 format. The new BQ84 record replaces
only BCAP's magic and preserves its remaining 44 bytes, then appends the payload.
The payload engine scalar must match the captured engine; historical node,
engine and native-frame words remain opaque, not live pointers or leases.

enqueue(U,exclusive_BCAP48,owned_payload36) guards complete frame/input extents
and known fixed/native/generated RX before any load/save, snapshots both inputs
privately and validates the complete schema. It consumes the source magic as
BCNS before raw T acquisition. This is one attempt per exclusive source, even
on full/fault/raw uncertainty; pre-existing clones remain independent and are
not globally deduplicated. Invalid inputs are not consumed. The separate native
56-byte header must have width 84, chunk 10, pinned allocated capacity (10..10240,
multiple of 10), count within capacity and nonzero aligned table. Header +04 is
not required zero because the pinned factory leaves it uninitialized. Full is
refused before APPEND/growth. Actual native index and incremented count must
both agree. No old producer/worker or explorer route is installed.

pop(U,zero_out84) checks all 21 output words before save/T. Under checked T it
validates GET's borrowed head against known extents, the entire invocation frame
and caller output, copies all 84 bytes privately before REMOVE, and validates
the complete BQ84 schema. Actual REMOVE zero and decremented count must agree.
After raw release zero it rechecks all 21 output words, copies the body and
commits magic last. Dirty late output refuses export after extraction without
requeueing. Extraction is not operation completion; concurrent drainers can
finish/export in another order. There is no paint dispatch, R/P service,
callback, engine/resource access, cleanup or native LIVE/use/free authority.

An initially zero retained fault word latches permanently under T: header 1,
head 2, append 3, remove 4. Actual nonzero raw acquire/release returns zero and
the exact status using private-frame restoration only: no late queue/header/
fault/source/output access, guessed unlock, rollback or retry. Synchronous
coordinated whole-instance isolation remains the caller's responsibility.
Correct initialized ordinary T, all cooperating users and retained, mapped,
nonaliasing table/complete chunks, exclusive buffers and full native/service
stack remain independent premises. Native REMOVE can shift 756 spare bytes even
at count 1. Bounds and immediate head/output disjointness do not certify unknown
heap graphs, native retention or transitive stacks. All earlier missed-event,
ABA, field stability and native unsafe-continuation gates remain unresolved.

Q/T/fault exclusions propagate through the parent outer capture, lifecycle and
retirement paths; complete generated RX includes the new tail. Strict empty/
zero-default extra-data/following-RX options preserve the preceding twelve
default compositions. The same 16 coherent fixture hook pairs remain; arbitrary
partial activation and older internal entries are not universally fail-closed.
At the preceding canonical seven creation addresses, lifecycle 01F3A000,
Q 01FF2000, T 01F20700 and fault 01F20800 with 40 allocated slots, the new stage
is 81,344 bytes: 74,724 guarded capture prefix plus 6,620 transport core.
SHA-256:
`95ced6cf23eeda0a1db56f0461d5a5dd331bdc0fa6bfd4b431e937fb799b80d9`.
The default BCAP-only stage remains 65,796/76a95966.... See
[typed FIFO scope](folderfollow-reveal-birth-queue.md).

Fresh serial focused verification: **59 tests pass, no skips** (108.576 s):
12 functional/native/ABI tests, 26 adverse tests and 21 pinned source/schema/
configuration/composition contracts. The actual native factory and APPEND/GET/
REMOVE paths execute, with retained complete chunks, bounded heap/libc/raw-mutex
substitutes and an explicitly controlled two-CPU interleaving after T release.
Coverage includes exact-token preservation across actual native node deletion/
reuse, source consumption and clones, full/no-growth and segment boundaries,
borrowed-head shift/private copy, permanent faults, raw uncertainty/private-only
return, all initial/late dirty output words, typed replay refusal, fixed/full-RX/
frame/head-output aliases and callee-saved/HI/LO restoration. Initial new test
expectations confused injected callback writes with emitted stores, adjacent
labels with ordered instructions, and an exact unsigned endpoint with wrapping.
Only the new test instrumentation/expectations were corrected; production bytes
and earlier assertions/timers were not changed to make the run pass.

The initial 3,013-test full run (765.983 s) had one failure in the unchanged
launcher fixture's test_normal_exit_preserves_fd_and_status_no_delayed_signal:
the watchdog signalled its bounded mock child despite a successful normal exit.
This fixture replaces sleeps with 25 ms and remains scheduler-sensitive.
All 24 launcher tests pass in a fresh isolated serial run (19.213 s). Neither
the launcher source, its assertions nor its timer were modified.

Fresh serial full regression: **3,013 tests pass, no skips** (748.232 s),
with the temporary-file/subprocess access required by the existing suite.
All 307 Python sources compile without file writes. The 81,344-byte composition
matches 95ced6cf...; all twelve preceding default sizes/hashes remain exact.
The three saved action-link, playback-dispatch and renderer-transport images
retain d4306357..., a9a6f02f..., f42fac46... and exact 02fd verification:
33,492/24,532/23,240 code bytes, 310/275/259 changed original bytes,
autoscroll False and hardware UNTESTED. Independent core, composition, fixture,
contract/source and scope reviews found no remaining issue within the stated
diagnostic transport boundary. All 31 changed/new text paths (7 Markdown and
24 Python), including preceding uncommitted birth/lifecycle/capture work, pass
whitespace/scope checks; the index is empty and no unexpected file, binary,
log or secret pattern was found. No earlier assertion, timer, native helper or
firmware builder was weakened. No firmware image file was built/modified,
no stock producer/worker hook installed, no device/network operation, launch,
reboot, commit or push. Changes remain local/uncommitted. Native lifetime,
whole-instance error isolation and active UI integration remain separate gates;
BQ84 extraction is neither a LIVE certificate nor completion/free permission.

### Exact-token historical queue consumer (2026-10-28)

The next separate local diagnostic branch consumes one native FIFO84 record
into private storage, completely releases T, then takes a fresh raw R observation
of the bounded lifecycle history. It never holds T and R together, searches for
the latest node/engine/name, dereferences historical native/payload pointers or
calls paint, callbacks, cleanup or native destruction. No old worker/producer
route is redirected. Both ordinary mutexes must be unheld on entry.

The new take(U,zero_out100) validates the complete output and contiguous known
consumer 192-byte plus nested pop 224-byte frames before output reads/save.
All 25 output words must be zero. After one successful typed pop and a complete
private BQ84 schema recheck, fresh raw R zero permits controller R/helper-binding
checks and read-only history validation. The entire occupied BRLC prefix, token
sequence/fixed fields/reserved words, allowed state/site schemas, global
outstanding-node uniqueness and every unused tail word must pass. Selection is
by the exact queued token, followed by equality of every birth word at 04..27,
not merely node/engine equality. A full healthy history is still comparable.
Faulted, malformed, missing or mismatched history refuses without writing/resetting
its fault or modifying any row. Tail validation counts remaining words rather
than requiring a representable one-past 32-bit address.

BOBS100 preserves BQ84 bytes 04..53 verbatim and appends observed state/site/SP/
caller at 54/58/5C/60. Both NO_RETIREMENT_OBSERVED and RETIREMENT_SELECTED are
exportable historical metadata, never LIVE/DEAD, native leases, paint admission
or unlink/free permission. Metadata is copied while R is held; only checked raw
R release zero and a second complete 25-word zero check permit body-first,
magic-last export. Empty/ordinary refusal is 0/0; successful export is out/0.
Later history refusal or dirty output loses an already-extracted item without
requeue, rollback, retry or completion acknowledgement. Multiple drainers may
export in another order from extraction.

Any actual raw T/R error returns 0/exact_status with private-frame restoration
only. No later output, shared table/header/fault or native access, guessed
unlock, service call or late fault write is permitted; a T error never enters
R work. Synchronous coordinated isolation of the WHOLE combined instance remains
external. Correct ordinary mutex semantics, coherent users/writers, mapped and
retained complete native chunks, exclusive nonaliasing buffers, heap graphs and
sufficient transitive native/service stacks are independent premises. The known
416-byte preflight is not universal protection against unknown heap aliases or
all inherited internal-entry/save-frame obligations.

Exact historical matching does not repair missed raw-error deletion/rebirth
events or authenticate a currently linked native incarnation. A retirement
after checked R release can invalidate any current-use interpretation before
BOBS export while the earlier owned snapshot remains unchanged. Earlier native
unsafe-continuation, P-health, lifecycle/alias/graph-retention and UI gates remain.
See [consumer scope](folderfollow-reveal-birth-consumer.md).

The BQ84 composer's strict zero-default following_code_bytes protects but does
not append the consumer tail. All preceding thirteen default compositions stay
exact; full generated RX extends through the queue, capture, lifecycle and
retirement prefixes. The same 16 coherent fixture hook source sites remain.
At the preceding canonical seven creation addresses, lifecycle 01F3A000,
Q 01FF2000, T 01F20700 and fault 01F20800 with 40 allocated slots, the new stage
is 85,044 bytes: 81,344 guarded queue prefix plus 3,700 consumer bytes.
SHA-256:
`765759c2a2ee7a29a2f6d7f0b9af90496d4ef0510a5d1fe809c6bb6fbd9db71f`.
The default queue remains 81,344/95ced6cf..., without a new shared allocation
or installer. Active scrolling remains disabled; hardware is UNTESTED.

Fresh serial focused verification: **61 distinct tests pass, no skips**
(187.184 s): 14 functional/native/ABI tests, 24 adverse tests and 23 source/
format/configuration/composition contracts. The actual native FIFO factory,
APPEND/GET/REMOVE, birth hooks and native deletion/reuse paths execute with
bounded raw-mutex, heap/libc and opaque cleanup substitutes. Tests cover both
observed states, exact old-token selection after observed same-address reuse,
complete prefix/uniqueness/tail corruption, full healthy history, opaque payload
and historical scalars, initial/late dirtiness in every output word, raw T/R
uncertainty with both ownership outcomes, no late access/retry/fault writes,
complete fixed/full-RX/combined-frame guards and callee-saved/HI/LO restoration.
A standalone retained history ending exactly at 2**32 exercises both a full
table and the last unused tail word without dereferencing a wrapped zero.
Deterministic distinct-stack CPU tests execute real deletion after checked R
release but before export and demonstrate out-of-order exports. The missed
raw-error delete/rebirth counterexample still exports only the old observation,
deliberately proving that exact historical comparison is not native liveness.
An initially imported test class was being discovered twice; its import was
namespaced without removing or weakening any assertion. Production behavior
was unchanged after the first successful focused run.

Fresh serial affected-module regression: **146 tests pass, no skips**
(140.632 s): the preceding BCAP capture, BQ84 transport and BRLC lifecycle
functional/adverse/contract suites. Combined with the 61 new tests, this step
has 207 fresh passing checks. The full project suite was not rerun in this
increment; its last complete 3,013-test result is recorded in the preceding
section, not claimed as a new run here. All thirteen preceding default
composition sizes/hashes are rechecked by the new contracts.

All 312 Python sources compile without file writes. The 85,044-byte branch
matches 765759c2... and the default BQ84 remains 81,344/95ced6cf.... The three
saved action-link, playback-dispatch and renderer-transport images retain
d4306357..., a9a6f02f..., f42fac46... and exact 02fd verification:
33,492/24,532/23,240 code bytes, 310/275/259 changed original bytes,
autoscroll False and hardware UNTESTED. Independent design/core/composition/
fixture/contract/source/scope reviews found no remaining issue within the
stated historical consumer boundary. All 37 expected changed/new text paths
(8 Markdown and 29 Python) pass whitespace/scope checks; the index is empty,
HEAD remains 1c2e9eba..., and no unexpected file, binary, log or secret pattern
was found. No old assertion, timer, native helper or firmware builder changed.
No firmware image file was built/modified, no producer/worker hook installed,
no device/network operation, launch, reboot, commit or push. Changes remain
local/uncommitted; native use, lifecycle completeness, error isolation and
active UI integration are still independent gates.

### Opt-in pre-mutation raw-acquisition gates (2026-10-28)

Baseline 98d9fc3 is published; the next separate local branch appends two
explicit admission gates to the historical consumer composition. Registration
438A10 is checked before its 28-byte node allocator, and name-delete 4395D4
before its first registry-ring load. The masked facade result is never enough:
the same invocation's existing private native witness must be CAPTURED with
actual raw acquisition zero. Registration additionally requires pinned U in
S0 and its native PTR equal R; deletion requires pinned U in S5 and its own
distinct retirement TAG namespace. No controller, history, ring, engine, name
or resource graph is read while the new gate decides admission.

Success preserves all GPRs and HI/LO, leaves witness locals unchanged for the
later observers and replays exact native effects. Registration enters allocator
4669E0 with original RA 438A18 and A0=28, not a relocated return address. Delete
replays the head load, S0/S3 branch and original 4395DC delay-slot load exactly
once on both paths, then continues at 4395F4 or 4395E0.

The new gate's own denial returns FFFFFFFF/exact captured nonzero raw status,
including FFFFFFFF itself; missing/incoherent evidence returns FFFFFFFF/0.
Denial accesses only genuine retained private/native frames. It never guesses
an unlock, retries, calls cleanup or mutates shared journals. Registration uses
the non-unlocking native epilogue 438A6C. The stock delete epilogue tail-calls
unlock and is therefore bypassed: its saved callee registers/RA and 56-byte SP
are restored locally before direct caller return. This is not a normalized
native error ABI: an admitted later allocation failure still leaves old V1
undefined/service-clobbered. Existing checked creation/BCAP wrappers overwrite
native V1 and do not automatically forward the new gate diagnostic.

These are bounded body-admission checks, not caller or whole-instance isolation.
Both encoded native constructor callers ignore registration failure and can
continue object/UI work. All 56 encoded direct delete callers ignore its return;
54 continue independent resource cleanup. No gate stops or rolls back that outer
work. Unknown raw ownership or missing witness still requires external synchronous
coordinated isolation, even if this local body did not mutate anything.

The stock prologues already wrote their 40/56-byte native frames. Fully mapped,
retained, writable and independently nonaliasing native and 192-byte bridge-save
frames are hard premises; there is no runtime invalid-stack preflight or safe
unwind guarantee for fabricated/unmapped/wrapping frames. Strict extra-data/RX
configuration only validates static placement, not arbitrary dynamic frames.
The inherited retirement raw-return observer can read U before reaching this
gate, so the new private-only refusal does not claim to remove earlier shared
reads after raw error. The exact source boundary is documented in
[gate scope](folderfollow-reveal-registry-acquire-gate.md).

Other controller teardown/outer-unlink paths remain ungated. Missing later
frontiers, full/faulted history, opaque callbacks, release errors, allocation-
failure missing unlock, escaped aliases and engine/resource retention remain
separate blockers. The known raw-error delete/rebirth body path is narrowed,
not all missing-event ABA routes. NO_RETIREMENT_OBSERVED remains not LIVE;
RETIREMENT_SELECTED remains not DEAD, completed deletion or free authority.

The parent's strict zero-default following_code_bytes protects the appended
tail without appending it or changing the preceding fourteen default hashes.
All preceding 16 coherent fixture hooks plus the two new sites are required:
the new stage exports 18 pairs, not an arbitrary-partial fail-closed installer.
At the preceding canonical seven creation addresses, lifecycle 01F3A000,
Q 01FF2000, T 01F20700 and fault 01F20800 with 40 allocated slots, the new stage
is 86,120 bytes: 85,044 guarded consumer prefix plus 1,076 gate bytes.
SHA-256:
`a4c3ec89cc4a7b01b2f385abfb5daf2146694a48a03118aaaaea756b524a4041`.
The default historical consumer remains 85,044/765759c2.... The new metadata
explicitly says native_callers_isolated=False and native_lifetime_proven=False.
No shared allocation, stock worker, UI hook, firmware file or installer is added;
active scrolling remains disabled and hardware is UNTESTED.

Fresh serial focused verification: **48 tests pass, no skips** (111.977 s):
11 native/ABI/composition-path tests, 11 adverse tests and 26 pinned source/
protocol/layout contracts. Actual native prologues, receipt/retirement hooks,
registration and name-delete instructions execute with the inherited bounded
raw/heap/libc/cleanup substitutes. The new tail-transfer allocator entry uses
the same bounded allocator substitute once, with original RA and size; it does
not reconstruct a node or issue a second allocation. Both delete branch paths
execute the original delay load exactly once.

Coverage includes each nonzero raw status with both possible ownership outcomes,
missing/corrupt witness and pinned scalar, missing begin/raw/new-gate redirects,
private-only memory/service boundaries from the new gate onward, negative
native callee/SP/RA/HI/LO restoration and positive ALL-GPR/HI/LO restoration,
unchanged witness consumption, observed deletion/reuse minting a new birth,
BCAP/FIFO/BOBS success and absence of raw-error allocation/publication/unlink/
free/unlock inside these two bounded bodies. A deliberate adversarial caller
ignores one refusal and attempts the other failing body; this is not permitted
error recovery or automatic re-use of an uncertain instance. Other tests retain
the missing later frontier, full/faulted-history and separate teardown gaps,
the allocator's undefined V1 and missing unlock, and older BCAP V1 masking.
All fourteen preceding default sizes/hashes, exact full generated RX, the 18
coherent source sites and encoded incoming-target/source-caller facts are
rechecked. No earlier assertion or timer was changed to obtain passing tests.

Fresh serial affected-module regression: **104 tests pass, no skips**
(187.492 s): historical consumer and lifecycle functional/adverse/contract
suites. Together with the 48 new tests, this step has 152 fresh passing checks.
The full project suite was not rerun in this increment; the preceding complete
3,013-test result and subsequent scoped runs remain historical results, not a
new full-run claim. All 317 Python sources compile without file writes.

The new 86,120-byte composition matches a4c3ec89...; the default historical
consumer remains 85,044/765759c2..., and all fourteen prior default sizes/hashes
are rechecked. The three saved action-link, playback-dispatch and renderer-
transport images retain d4306357..., a9a6f02f..., f42fac46... and exact 02fd
verification: 33,492/24,532/23,240 code bytes, 310/275/259 changed original bytes,
autoscroll False and hardware UNTESTED. Independent native-source, gate/core,
composition, fixture, contract and scope reviews found no issue within the
explicit bounded-body admission boundary. All 10 expected changed/new text
paths (4 Markdown and 6 Python) pass whitespace/scope checks; the index remains
empty, HEAD is the published 98d9fc3, and no binary, log, secret pattern or
unexpected path was found. No old assertion, timer, native helper or firmware
builder changed. No firmware image file was built/modified, no native hook
installed, no device/network operation, launch, reboot, commit or push. Changes
remain local/uncommitted. Stopping or isolating ignored native callers, remaining
mutation routes, complete graph lifetime and active UI integration are not
implemented by these two gates.

## 2026-10-28: scoped constructor registration-result stops (local, opt-in)

A separate offline composition now follows both native constructor registration
returns at 43AE94 and 43B038. These addresses are also shared joins for earlier
skipped-registration paths. The new gates therefore classify only a genuine
native return with saved S1 equal to pinned U and saved RA equal to that exact
hook PC. Only then does a nonzero saved V0 skip local 519FA0 and final name
postwork. V1 is never interpreted; the decision reads neither native SP+50 nor
an engine/name/controller graph. A wrong U/RA or zero status reproduces the
displaced native JAL, its original RA and delay A0=S1 exactly.

Stop restores every saved GPR and HI/LO, then enters the existing constructor
epilogue 43AEA8/43B04C. That epilogue returns its saved engine scalar and unwinds
the genuine 136/128-byte frame. No new NULL/status return convention, ownership
handle or V1 error ABI is introduced. No stop-path UI, free, unlock, retry,
cleanup or rollback is attempted. The complete native frames and separate
192-byte architectural-save frames must already be mapped, retained, writable
and independently nonaliasing; arbitrary invalid-stack recovery is not claimed.

This narrow stop is not whole-instance or outer-caller isolation. Thirteen
encoded direct first-constructor callers and 46 second-constructor callers
remain unchanged. They can still store, dereference or pass the returned engine
to later native code. Skipped-registration legacy NULL faults remain, as do
the second constructor's earlier NULL returns. Native registration masks raw
release errors as V0=0, which still admits the local UI continuation. Allocation
failure still skips native unlock. Other mutation paths, escaped aliases and
complete resource retention remain separate unresolved boundaries. No token,
history match or local return establishes lifetime or cleanup permission.

The acquire-stage parent's strict zero-default following_code_bytes reserves
the appended RX without appending it. The new composition contains 87,112 bytes:
86,120 guarded parent bytes plus 992 constructor-gate bytes. SHA-256:
`c13d8485f4644b90c1dd2029877a13626cd5d7231e6fa65c54ff6ec87f208dd8`.
Its 20 coherent fixture hook pairs include all 18 preceding sites plus these
two new sites; arbitrary partial activation is not a fail-closed installer.
The preceding 86,120/a4c3ec89... default remains byte-identical. Metadata says
constructor_status_continuations_gated=True and constructor_engine_return_preserved=True,
but native_callers_isolated=False, raw_release_proven=False and
native_lifetime_proven=False. No shared allocation, installer, firmware file,
worker dispatch or active scrolling is added; hardware remains UNTESTED.

Fresh serial source/layout verification: **26 new contract tests pass, no
skips** (17.114 s). They recheck both displaced pairs, saved U/RA/V0-only
classification, ignored V1, exact architecture restoration and stock engine
epilogues, original forward RA/delay effects, the 13/46 encoded caller counts,
legacy NULL/masked-result paths, strict static extents, final-tail rejection
for all ten fixed data roles, complete protected RX and all 20 coherent sites.
All fifteen preceding default composition sizes/hashes remain unchanged.
Fresh serial affected-parent regression: **48 acquire-gate tests pass, no
skips** (112.968 s); its optional zero-default reservation preserves the exact
old output.

The initial 15-test execution run (265.222 s) reported 20 failed subtests in
three new adverse tests, not a production-gate failure. A bounded diagnostic
confirmed that delay-slot NULL reads are recorded at their owning JAL PC
43AEA0/43B044, not 43AEA4/43B048. The same diagnostic showed the complete raw
sequence R acquire, nested P acquire/release, then R release; the new test had
incorrectly expected only the two R events. The corrected tests require the
exact unmapped-NULL exception and exact (read, owning PC, address 0, size 4)
record, and all four exact raw target/pointer/status events. No event filtering,
old assertion/timer change, production-core change or service relaxation was
used to address these test-observation mistakes.

Fresh complete serial execution rerun: **15 tests pass, no skips** (267.650 s):
6 native/ABI tests and 9 adverse tests, executing both actual constructors,
8B4120/8B0D00 and registration with inherited bounded service/libc substitutes.
Coverage includes every tested nonzero raw acquire result with either ownership
outcome, allocation failure with undefined V1, poisoned V1 on native success,
every tested nonzero V0 independent of V1, wrong U/RA forwarding, complete
architectural restoration before replay/stock unwind and private-only stop
accesses without later services. The same single-call bounded UI substitute
handles linked native calls and the emitted unlinked tail transfer.

Explicit counterexamples retain raw-release masking with both ownership
outcomes, missing acquire/continuation redirects, all tested skipped-registration
NULL paths and the unchanged second-constructor early NULL returns. The actual
explorer slice 492908..492930 still stores the stopped constructor's returned
engine at V+CC and passes it to the bounded 439680 enable-call boundary. The
opaque enable body is not executed or certified safe. This demonstrates the
remaining higher-caller gap, not a new approval for using that returned engine.

Together, this increment has **41 new + 48 affected-parent = 89 fresh passing
tests**. The complete project suite was not rerun; the earlier 3,013-test full
result and previous scoped runs remain historical evidence only. All 322 Python
sources compile without file writes. The three saved action-link, playback-
dispatch and renderer-transport images pass exact 02fd verification unchanged:
d4306357..., a9a6f02f..., f42fac46..., with 33,492/24,532/23,240 code bytes,
310/275/259 changed original bytes, autoscroll False and hardware UNTESTED.

Independent core/native, composition, fixture, contract and final scope reviews
found no remaining issue within the stated local-continuation boundary. The
corrected tests strengthen rather than filter the observed events. All 16
expected text paths (5 Markdown, 11 Python) pass whitespace/scope checks; the
index is empty and HEAD remains published 98d9fc3. No unexpected path or secret
pattern was found. No old assertion, timer, helper or firmware builder changed.
No firmware image file was created/modified, no hook installed, no player,
network, launch, reboot, commit or push operation occurred. Changes remain
local/uncommitted. Higher-caller isolation, masked release handling, remaining
mutation coverage, native lifetime and active UI integration are still separate
unfinished work.

## 2026-10-28: invocation-local explorer failure exit (local, opt-in)

A separate offline successor now narrows the exact explorer492918 caller gap.
The preceding first constructor gate has already saved its192-byte private
architecture and classified pinned U, registration return43AE94 and nonzero
registration V0. The successor splices only that generated stopped label's
initial HI restore pair (8FA80088/01000011), checking the original words before
replacing them in the returned prefix. No additional native source site changes.

The56-byte helper reads the genuine constructor's saved outer RA at private
SP+144. Only492920 selects a rewrite of that same private saved-return slot to
the appended abort_return trampoline. All other callers leave the slot unchanged.
Both paths replay the displaced HI restore exactly and resume parent stopped+8.
The parent restores all architecture and enters stock43AEA8, which returns its
saved engine scalar and unwinds136 bytes. Only the selected invocation then
enters the trampoline and stock explorer NULL exit492F84. That existing exit
sets V0=0 and unwinds its6096-byte frame without graph calls or cleanup.

Thus the selected failure bypasses492920's controller-home load,492924's V+CC
store,492928's enable call and all later work in this explorer invocation.
Jumping merely to492930 would be insufficient: later paths still read or
dereference V+CC. The other exit492F50 returns the partial view and is not used.
V1 is not reinterpreted and no constructor-wide NULL/status ABI or shared
failure mailbox is introduced. The raw engine still returns to a private
trampoline, not to the skipped explorer continuation.

HARD premises now include the genuinely mapped, writable, retained and
independently nonaliasing selected6096-byte explorer frame, in addition to the
136-byte constructor and existing192-byte private frame. These frames and
native/import/storage prerequisites are not authenticated by a scalar saved RA
or established by static layout checks. No invalid-SP recovery is claimed.

This is a bounded continuation stop, not rollback or whole-instance isolation.
Before registration explorer491E80 already allocated the view and buffers,
created resources, published a view alias at resource+7C, installed callbacks
and bound the resource table. Earlier widget/controller effects persist. The
later owner-list insertion has not happened yet, but that does not remove those
escaped aliases. No engine/view/name allocation is freed, no uncertain mutex
is unlocked, and abandoned graph ownership/retention, safe retry and cleanup
remain unresolved. There are188 encoded direct explorer491E80 callers; their
reaction to NULL is not isolated. Other first-constructor callers, the second
constructor, masked release failures and missing coherent hooks remain outside
the new guarantee. Historical events still grant no native-use or free authority.

The constructor-stage parent's strict zero-default following_code_bytes protects
the appended RX without appending it and preserves its87,112-byte/c13d8485...
default. The new composition is87,168 bytes: the guarded87,112-byte prefix with
one explicit8-byte generated splice plus56 helper bytes. SHA-256:
`540034a7349e240a95047fbb39b01a48dc8379669f1510d53c59e64992c888e9`.
It advertises20 inherited native pairs and one generated pair,21 coherent
instruction-fetch pairs total. The generated map matches the actual patched
prefix bytes; it is not merely an advisory fixture override. Arbitrary partial
activation remains unsupported, and no on-device installer is added.

Scope metadata reports explorer_failed_registration_continuation_stopped=True
and explorer_returns_native_null_on_classified_failure=True, but keeps
partial_graph_cleanup_proven=False, native_callers_isolated=False,
raw_release_proven=False and native_lifetime_proven=False. No shared allocation,
worker dispatch, image installation or active scrolling is added. Hardware
remains UNTESTED; no player operation is part of this step.

Fresh serial source/layout verification: **21 new contract tests pass, no
skips** (41.564 s). The vendor-source checks pin the two native epilogues,
the exact explorer call, later V+CC uses, existing escaped resource aliases,
callback binding, the188 encoded direct explorer callers and bounded incoming
edge facts. Generated-source checks separately pin the original parent restore
pair, sole saved-RA write, exact HI replay/resume and actual8-byte prefix patch.
All16 preceding default sizes/hashes, strict parent12-byte pair/resume extent,
complete outer RX, all ten final-tail data exclusions and the20-native/1-generated
coherent hook inventory are rechecked.

Fresh serial affected-parent regression: **32 tests pass, no skips** (75.101 s),
the26 constructor contracts and6 native/ABI tests. The preceding adverse suite
was not rerun in this increment; its earlier passing run remains historical.
The new execution fixtures start at the retained bounded492908 explorer slice,
not the opaque full491E80 setup. They seed the genuine prologue-established
6096-byte frame and separately mapped caller argument homes, then execute the
actual constructor, parent restore and both stock epilogues.

Preflight fixture review corrected the observation order so private-stop memory
checks precede the host's later V+CC assertion. A fixture-only reached-PC native
return boundary also admits either the original caller RA or emitted abort_return;
the enclosing interpreter then follows the actual native r31. It neither tests
status nor invents a host-side abort/unwind, catches an unmapped-return failure,
or reconstructs a native engine. No old test/helper, assertion or timer changed.

Fresh serial execution verification: **25 tests pass, no skips** (324.757 s),
10 native/control-flow tests and15 adverse tests. Actual first constructor,
registration, parent restore,136-byte stock constructor epilogue, emitted
abort trampoline and6096-byte stock explorer NULL epilogue execute in order.
The selected route restores all saved architecture before stock constructor
unwind, preserves HI/LO and outer callee/SP/RA state, leaves V+CC unchanged,
and makes no UI/name/enable/free/unlock/service call after the new scope entry.
Unrestricted post-entry memory checks allow only the retained frames and the
single targeted native saved-RA store; exact helper accesses are checked too.

Coverage includes raw1/22/82/FFFFFFFF with both possible acquisition ownership
outcomes, actual node allocation failure and its still-missing unlock, arbitrary
tested nonzero V0 and poisoned V1, unchanged success store/enable, nonexplorer
first-constructor fallback and unchanged second-constructor ABI. Sequential and
deterministically interleaved CPUs use independent native/private frames and
no shared failure latch. The bounded allocator cursor is explicitly handed
across the serial interleaving so retained live engines do not accidentally
alias. This adversarial uncertainty test is not permission to retry/reuse an
uncertain instance or evidence of a real scheduler/whole-instance lifetime.

Missing-splice counterexamples remove both the actual prefix patch and matching
fetch override; removing only either copy correctly leaves the other active.
Missing native status/acquire hooks, masked raw release errors with either
ownership outcome and skipped-registration NULL faults remain explicit gaps.
The raw-release counterexample still reaches UI, stores and enables the engine;
the local NULL exit grants no general release or native-use certificate.

This increment therefore has **46 new +32 affected-parent =78 fresh passing
tests**. The complete project suite was not rerun; earlier full/scoped counts
remain historical results, not a new full-run claim. All327 Python sources
compile without file writes. The three saved action-link, playback-dispatch
and renderer-transport images retain exact02fd verification and hashes
d4306357..., a9a6f02f..., f42fac46..., with33,492/24,532/23,240 code bytes,
310/275/259 changed original bytes, autoscroll False and hardware UNTESTED.

Independent native/core, composition, fixture, contract and scope reviews found
no remaining issue within the bounded explorer-exit contract. All22 expected
text paths (6 Markdown,16 Python) pass whitespace/scope checks. No unexpected
path or secret pattern was found; the index is empty and HEAD remains published
98d9fc3. No old test, timer, helper or firmware builder changed. No firmware
image file was created/modified, no hook installed, no player/network action,
launch, reboot, commit or push occurred. Changes remain local/uncommitted.
Masked release handling, abandoned graph retention/cleanup, other caller paths,
whole-instance coordination and active folder-follow integration remain
unfinished work, not implied by this one local failure exit.

## 2026-10-28: constructor-only raw-release result propagation (local, opt-in)

A separate offline successor now preserves the actual pinned raw R release
result for the two genuine constructor registration returns43AE94/43B038.
Native raw wrapper466DD4 and registration438A68 otherwise both force V0=0,
so changing only one return mask would not reach the existing status stops.
The new four-phase protocol uses no shared failure flag or graph lookup.

At438A60, only pinned S0=U and the two native saved callers select fresh
registration locals: TAG+10=0, STATUS+14=FFFFFFFF and RAW_SP+18=0, followed by
NRSL only if the actual saved T9 is437DA0. The preceding publication observer
has already consumed the old acquisition TAG; synchronous receipt/birth/issuer
callbacks have completed and native postpublication code does not read these
three receipt words. The old explicit checked-capture wrapper has a different
native saved caller and keeps its own unchanged release-witness storage.

At466DC8 the new bridge checks the raw32/facade32 saved return chain437DB0/
438A68 before following registration N=W+40, then checks the same constructor
caller, selected state, sentinel/zero locals and actual pre-service A0=R and
T9=437DA0. It records W and NREN. At466DD0 it checks the same chain, actual
saved raw-return RA466DD0, NREN and the exact stored W before capturing entry
V0 and publishing NRCP. Actual FFFFFFFF is an error value, not a missing marker.
These three bridges always restore all GPRs/HI/LO and tail-chain the preceding
release observers, which retain original callback/raw argument and return-PC
effects and execute each service once. Foreign/native checked-wrapper routes
continue through those old observers unchanged.

At438A68 a new completion check consumes NRCP for the pinned constructor route
and requires RAW_SP=N-40. Only then may it read STATUS. Zero preserves ordinary
native completion; nonzero becomes registration FFFFFFFF/exact raw status;
absent or incoherent evidence becomes FFFFFFFF/0. This is a scoped gate result,
not a normalized ABI for old allocation failures, foreign callers or raw APIs.
Both constructor status gates then skip local UI/name work; the specific
explorer492918 call can reach its existing NULL exit without storing/enabling
the returned engine. Other higher callers and whole-instance control remain
outside that local stop.

The completion pair has an independently entered second word:438A6C is reached
by native allocation-failure branch438A80 and the preceding acquire gate's
failure jump. Preflight source audit therefore required completion hook
(J new_complete, original8FBF0024), NOT a NOP delay. Its saved-RA load remains
executable at6C and runs exactly once in the completion J delay before the
new bridge saves architecture. Success replays only the V0-zero effect; denial
sets its scoped result. Both resume438A70 without another RA load. The old
independent6C failure paths remain unchanged. No old assertion/timer relaxation
was used to accommodate this shared-entry boundary.

All new decision accesses are retained private/native frames, never U fields,
engine/name graphs, shared journals or an extra raw service. Genuine mapped,
writable retained nonaliasing native40/facade32/raw32 frames and each192-byte
architectural-save allocation remain hard premises, as do all inherited stack,
import, ordinary-mutex and storage requirements. Scalar saved PCs, witness
states and static RX/data checks do not authenticate fabricated frames or make
arbitrary invalid-SP unwinds safe. Global observer redirects still require
sufficient stack even for unclassified routes.

Publication, birth history and possibly owner state already exist when release
fails; the new result does not unlink, undo history, free anything, guess mutex
ownership, retry unlock or revoke resource aliases. A nonzero release can still
leave R either held or released. Other release routes and foreign controllers,
missing completion activation, escaped resources, abandoned graph lifetime and
caller reactions remain separate boundaries. No historical match or local NULL
return grants cleanup, retry, native use or whole-instance isolation.

The parent explorer composition now has strict zero-default following_code_bytes:
it protects appended RX without appending it and preserves87,168/540034a7...
by default. The new composition contains89,140 bytes, its guarded87,168-byte
prefix plus1,972 release-gate bytes. SHA-256:
`03ec46d436914eef93a8aa118496608d59df4539926dc6272ff81449e50687de`.
Three known old native release redirects are checked and replaced by delegates;
completion adds one new native pair. The coherent inventory is21 native plus
one unchanged generated explorer splice,22 total. The old release_hooks map is
retained as observer provenance, not the new dispatch installation map.

Metadata reports constructor_registration_release_gated=True and
registration_release_failure_propagated=True, but native_callers_isolated,
raw_release_proven, native_lifetime_proven and partial_graph_cleanup_proven all
remain False. No installer, shared allocation, stock worker dispatch or active
scrolling is added; hardware remains UNTESTED. Fresh serial affected-parent
verification: **41 tests pass, no skips** (47.848 s), the21 explorer contracts
and20 existing explicit registry-release tests. New tests are recorded below
only after their serial run completes.

Fresh serial source/layout verification: **25 new contract tests pass, no
skips** (78.558 s). They pin all four source pairs, the preserved independent
438A6C failure entry and exact-once delay effect, private phase ordering and
17 preceding default hashes. They separately check the three exact predecessor
observer targets, full protected RX, strict legacy-entry/static-data extents,
all ten final-tail data exclusions and the21-native/1-generated coherent map.
The154-wrapper/five-raw-site census remains bounded source evidence, not a
claim of global release coverage. The new89,140/03ec46d4... composition and
unchanged87,168/540034a7... parent default both match their pinned hashes.

Verification resumed2026-10-29. Preflight separated the foreign-controller
case into two explicit scenarios: coherent acquisition admission already
refuses the foreign instance before release; a symmetric diagnostic removal
of that earlier hook in both old/new fixtures reaches the foreign release
and retains its legacy masked result. Both raw-service traces must match.
That partial-hook counterexample is not an allowed activation or retry policy.
An earlier execution attempt was interrupted before completion for this
review; no incomplete-run checks are counted as a passing suite.

The new execution fixture now reuses only deterministic assembled code and
metadata for identical, exact-type argument keys. The temporary cache wraps
25 explicit pure emitters/composers only during this fixture's construction;
all original functions restore in finally, including on construction error.
Every returned mutable metadata/label object is deep-copied. Machine memory,
registers, service inputs, outcomes and observations are never cached. Direct
production/source contracts remain outside that context. A new regression
compares cached and uncached03ec46d4... bytes, native error traces, a separate
success invocation, metadata independence, bool/int keys, invalid capacity
and restoration of every original assembler function. No old assertion,
timing threshold or service behavior was changed to accelerate the run.

The first completed execution run with that cache (35 tests,57.590 s) found
one new-test setup error: changing U+278 before acquisition invalidated the
old receipt binding and stopped before any release phase. The callback test
now keeps acquisition/publication intact and substitutes the actual T9 only
at release selection. It still requires unknown-result denial, a committed
birth/allocation, no R unlock and unchanged held-R uncertainty.

A subsequent full new-suite run (60 tests,141.308 s) confirmed that branch
but exposed a second observation mistake in the same new test: the inherited
observer tail-jumps to the native callback, so it does not enter the fixture's
linked-external call log. The test now requires exactly one actual callback
entry in the post-selection instruction trace and exactly one corresponding
raw P unlock. No production code, expected failure result, old assertion,
timer or raw-service substitute changed in either correction. These failed
runs are not counted as completed passing verification.

2026-10-29 fresh complete serial rerun: **60 new tests pass, no skips**
(134.479 s):16 native/ABI/cache tests,19 adverse tests and25 source/layout
contracts. Both actual constructors propagate observed raw1/22/82/FFFFFFFF
with either release-ownership outcome into the existing local status stops.
The specific explorer route performs its real NULL unwind without storing or
enabling the engine. Missing/incoherent phase evidence denies as unknown;
successful raw release retains the original native engine ABI and callback/raw
arguments/return PCs. Every dispatcher restores all GPRs/HI/LO before its
actual predecessor entry, and completion changes only its scoped V0/V1 result.

Coverage includes the exact-once438A6C saved-RA load on success, release error,
acquire refusal and native allocation failure; old checked BCAP success/error
outputs and architecture remain equal to uncached predecessor baselines.
Post-error accesses are restricted to retained private/native frames with no
extra service, graph/history mutation, unlock retry or free. Committed native
links, birth/owner history and allocations remain, proving no rollback claim.
Fresh same-frame reuse, separate CPU frames, V1 poison, wrong callback/actual
argument/return chain, corrupt tag/SP, registry-versus-paint statuses, foreign
routes and missing-hook counterexamples are checked. Adversarial second calls
and symmetric hook removals are not permission to reuse uncertain instances.

Together with the41 affected-parent checks, this increment has **101 passing
targeted tests**. The full project suite was not rerun; earlier full/scoped
counts remain historical evidence, not a new whole-project result. All332
Python sources compile without file writes. The three saved action-link,
playback-dispatch and renderer-transport files pass exact02fd verification
unchanged: d4306357..., a9a6f02f..., f42fac46...,33,492/24,532/23,240 code
bytes and310/275/259 changed original bytes, autoscroll False, hardware UNTESTED.

Independent native/core, stage, fixture/cache and scope reviews found no
remaining issue within this constructor-only propagation contract. All28
expected text paths (7 Markdown,21 Python) pass whitespace/scope checks; no
unexpected path or secret pattern was found. The index is empty and HEAD is
still published98d9fc3. No old test, timing threshold, native helper or firmware
builder changed. No firmware file was created/modified, no hook installed,
and no player/network action, launch, reboot, commit or push occurred. Changes
remain local/uncommitted. Other callers/release routes, complete graph retention
and cleanup, whole-instance coordination and active folder-follow integration
remain unfinished and are not supplied by this scoped release result.

## 2026-10-29: late explorer-destructor delete-result stop (local, opt-in)

The next offline successor stops only the remaining local destructor work
after the explorer's exact name-delete call returns a nonzero result. It is
not an implementation of partial-graph cleanup or a fence before cleanup.
The selected native pair493F4C/493F50 is8E240024/0C1214C8: a controller+24
load followed by resource-delete485320. A check at493F50 alone would already
have read the controller after uncertain deletion; the new check precedes it.

The new192-byte save preserves all30 non-SP GPRs and HI/LO before checking
only private savedS1=pinnedU, savedRA=493F4C and savedV0!=0. V1 is never a
classifier. Selected failure restores the complete entry architecture and
jumps to native493C98, whose pure epilogue preserves V0/V1, restores saved
RA/FP/S7..S0 and unwinds1208 bytes. It skips the U+24 load, resource delete,
resource callback, owner-list removal, later lists/resources/view frees and
the native493C7C continuation. No unlock, service, graph access or free occurs
on this new stopped path.

Zero status, another U or another RA forwards the original path after complete
architecture restoration. Replay loads A0=*(S1+24) once, then sets the resource
call's originalRA493F58 and tail-transfers to485320 with original493F54's
02602821 (A1=S3) as its delay. Native493F54 is not executed a second time.
Encoded J/JAL and conservative relative-branch scans show no incoming target
at493F4C,493F50 or493F54; computed/fabricated/runtime entries remain outside
that bounded census and genuine-route premise.

The native1208-byte destructor frame and separate192-byte save must already
be mapped, writable, retained and independently nonaliasing. Save precedes
classification. Scalar U/RA checks and strict static fixed-data/RX placement
do not establish native lifetime, authenticate a fabricated frame or make an
invalid SP/unwind safe. The new fragment reads neither controller fields nor
an engine/name/resource graph to decide the stopped path.

Earlier destructive work remains: the closing flag, worker/private/shared
cancellation, prior callbacks/frees, worker shutdown4C0A80, list destruction,
eight440620 calls, controller+F0 clear,4BDA20, cache unlink47AA20 and purge/
detach439780 all precede the final delete call. A late return cannot roll
those effects back or regain lost parent membership. Constructor-abandoned
view/resource aliases and allocation leases remain separate problems. The
existing raw-acquire gate prevents the name-delete body on refusal, but its
caller can only suppress additional later work here, not undo its earlier work.

Delete's raw-release error is still masked to native zero; the preceding new
release protocol applies only to constructor registration. Such a zero still
forwards resource cleanup. The49 encoded direct destructor callers and other
name-delete callers remain unisolated. This is neither whole-instance shutdown,
automatic retry permission nor a positive free/cleanup authority.

The release-stage parent's strict zero-default following_code_bytes protects
the appended RX without appending it and preserves89,140/03ec46d4... by
default. The new composition is89,640 bytes: the guarded89,140-byte prefix
plus500 gate bytes. SHA-256:
`996f66b14285bdb35490b4e4e2cbc380c2ed888a558323ea1828a58ebc246b1c`.
It advertises22 native pairs and the inherited one generated explorer splice,
23 coherent instruction-fetch pairs total. No on-device installer or firmware
file is added. Metadata says destructor_delete_failure_continuation_stopped=True,
but destructor_entry_fenced=False and earlier_cleanup_rolled_back=False;
native_callers_isolated, raw_release_proven, native_lifetime_proven and
partial_graph_cleanup_proven remain False. Active scrolling stays disabled
and hardware remains UNTESTED.

Fresh serial affected-parent regression for this destructor increment:
**27 tests pass, no skips** (84.182 s), the25 release-gate contracts plus
native constructor-release denial and exact-once shared6C delay/early-entry
checks. Fresh serial new source/layout verification: **21 tests pass, no
skips** (141.743 s). The latter pins18 preceding default hashes, native hook
and separate493F54 delay, genuine1208-byte unwind, earlier destructive order,
bounded49/56/54 caller census, full architectural restoration, strict fixed
layout, full appended RX and the23-pair native/generated inventory.

New fixture preflight corrected two observation assumptions before execution:
the protected89140-byte prefix must equal the parent assembled with a500-byte
following reservation, not its old default hash; exact U+24 load counts must
be taken before the host assertion itself reads that field. The missing-
acquisition-hook counterexample now primes a real node first, so actual native
unlink/free and subsequent resource continuation are visible after raw error.
No old assertion or timer was relaxed. The fixture enters only at493F40 and
seeds the prologue-established1208-byte frame; it does not simulate the earlier
cleanup as if those effects had been cancelled or rolled back.

Fresh serial execution verification: **15 tests pass, no skips** (34.715 s),
7 native/ABI/cache and8 adverse tests. The actual493F44 name-delete call,
existing acquire denial, emitted new gate and native493C98 unwind execute
from the bounded slice. Tested raw1/22/82/FFFFFFFF with either acquisition
ownership outcome preserves exact V0/V1 and outer saved registers/SP/RA/HI/LO
while making no later service/free or non-frame memory access after selection.
The controller+24 load is absent on that route. Native zero and foreign-scope
routes preserve complete entry architecture before the original resource
arguments, RA493F58 and single delay effect. Linked and emitted unlinked
resource transfers reach the same bounded hostile substitute exactly once;
the real opaque resource-deletion body is not certified by that substitute.

Coverage includes populated successful native unlink before resource cleanup,
arbitrary nonzero V0 and poisoned V1, wrong U/RA forwarding, unchanged direct
native delete ABI, missing new hook, actual masked delete-release error with
either ownership outcome, and populated unlink/free after a missing earlier
acquisition gate. Those counterexamples still forward the separate resource
call; the new gate does not repair zero-masked uncertainty or past mutation.
Cached/uncached code and native results match996f66b1..., metadata and machine
state remain separate, and all27 temporary assembler identities restore even
after invalid construction. No interpreter result or failure decision is cached.

This increment has **36 new +27 affected-parent =63 passing targeted tests**.
The full project suite was not rerun; earlier full/scoped counts remain
historical evidence only. All337 Python sources compile without file writes.
The saved action-link, playback-dispatch and renderer-transport files retain
exact02fd verification and hashes d4306357..., a9a6f02f..., f42fac46...,
33,492/24,532/23,240 code bytes and310/275/259 changed original bytes,
autoscroll False and hardware UNTESTED.

Independent native/core, composition, fixture/cache and scope reviews found
no remaining issue within this late local-stop boundary. All34 expected text
paths (8 Markdown,26 Python) pass whitespace/scope checks; no unexpected path
or secret pattern was found. The index is empty, HEAD remains published98d9fc3.
No old test assertion, timer, native helper or firmware builder changed. No
firmware file was created/modified, no hook installed, and no player/network,
launch, reboot, commit or push operation occurred. Changes remain local and
uncommitted. Destructor-entry policy, earlier cleanup effects, masked delete
release, graph retention/reclamation and outer caller coordination remain
unresolved. This gate is not a completed safe-cleanup implementation.
