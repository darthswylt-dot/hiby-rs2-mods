# MOVE v2 passive scrolling diagnostic

Field clarification (2026-10-05): historical `cache_count` means the sampled
total folder count at P+0x1E0, not actual cache population or fill completion.
The saved wire layout/name is unchanged. See the
[verified metadata distinction](folderfollow-reveal-model.md).

Built locally on 2026-09-30 following the
[offscreen-highlight diagnosis](folderfollow-scroll-diagnosis.md).
Hardware status: **TEST INTERRUPTED BY REBOOT; STOCK VERIFIED; CAUSE UNKNOWN**.
No device connection, installation, arming, commit or push was performed
during creation. Installation was subsequently explicitly authorized.

## Installation and initial device check (2026-09-30)

Before installation, live stock PID 117 matched `0fedb30f...`, battery was
100%/Full, and the one-shot flag and MOVE log were absent. Previous FILL
executable (`7e01a34b...`) and launcher (`0151c274...`) were pulled into
`artifacts/move_diag_install_backup_20260930/`; local hashes match the device.

The candidate and launcher were transferred into separate staging files,
hash-checked, made executable and renamed to `/data/hiby_player_sortfix` and
`/ui_data/player`. Device `/bin/sh -n` passed. Launcher SHA-256 is
`522f0b1bf6e064d52ae1965a7b2724ea4723a4c89f5d250ff1f50e52e38edf4b`.
Stock `/usr/bin/hiby_player` was not replaced and still matches `0fedb30f...`.
The flag was armed, files synced and the device rebooted once.

After boot, live `/proc/123/exe` matches the full candidate hash below,
FD9 points to `/mnt/sd_0/rs2_folderfollow_move_diag.bin`, and the flag is absent.
Log growth was observed from 250,432 to 623,328 bytes. A device-side copy was
pulled as `artifacts/move_diag_install_backup_20260930/startup_snapshot.bin`;
its local/device SHA-256 is
`b0c08a2318b28e84b322963d5d6e8baff4abf7d0448b445432202e0574ec9ef8`.
It contains 453 MSNP snapshots and 453 MSTS records, reserved=drained=0,
zero reported loss flags, no setter/refresh events and an accepted exported
prefix. This verifies startup and snapshot/status output, not hot-probe
execution, playback, highlighting, volume or continued I/O success.
Prior diagnostic logs are retained. The test process remains running;
no commit or push was performed. Next: leave DAC and manually navigate
Music -> Files -> SD-card1 -> Roots in Russia for the initial playback check.

### Roots stage confirmed (2026-09-30)

User reports playback, file highlight and working volume. Live PID 123 still
matches `15cf4457...`, FD9 points to the MOVE log, and the one-shot flag is
absent. Snapshot `artifacts/move_diag_roots_20260930.bin` is 2,513,056 bytes;
local/device SHA-256 matches
`dcf7102022af84a43386f7591226cb4843ac53395c0b8b63405e367e231a6fa2`.
Strict decoding accepts 1,826 MSNP snapshots, 1,826 MSTS records and five
refresh events, reserved=drained=5, with zero reported loss flags.

Recorded refresh callers are `0x490928` (two), `0x49A200`, `0x490DDC` and
`0x452FA4` (one each). All five observed inputs have C+0x3C=2, y=0,
height=260, pitch=80 and raw extent=0. The final snapshot is the Roots list
and its playing FLAC, cue brackets -1/-1, with y=0 and cache count 2.
These are non-atomic samples; refresh inputs do not prove successful refresh
completion. No scoped setter events have been captured yet, so the setter
probe is not hardware-validated by this stage. Playback/highlight/volume are
the user's observations, not inferred from telemetry.

Next: manually enter Slayer -> Albums -> Show No Mercy -> its release
directory, start Evil Has No Boundaries and leave the file list open for
highlight/volume confirmation before physical Next/offscreen/manual-scroll
checkpoints. Test remains running; no commit or push performed.

### Deep Slayer entry confirmed (2026-09-30)

User confirms playback, highlighted composition and working volume after
the requested Evil Has No Boundaries start. Live PID 123 still hashes to
`15cf4457...`, FD9 is the MOVE log, and the flag is absent. Snapshot
`artifacts/move_diag_slayer_entry_20260930.bin` is 4,429,984 bytes; matching
local/device SHA-256 is
`7b771676016310d36eeca0b9a515d6be0e87e9607bdac61a12b9fc2903e73048`.
Its accepted prefix contains 3,218 MSNP/MSTS pairs and 21 events: three
setter transactions and 18 refresh inputs. Reserved=drained=21; reported
overflow/contention/I/O losses are zero.

Since the Roots checkpoint, three setter events were captured from caller
`0x491DF4`, each absolute mode `0x20002`, requested/old/returned y=0,
flags=2, raw extent=0, height=260, result=0 and cue brackets -1/-1.
These demonstrate event capture and original return publication for zero-y
requests, not a successful scrolling/reveal request. Thirteen additional
refresh inputs have callers `0x490DDC` (five), `0x490928` (one), `0x49A200`
(three), `0x491CEC` (three) and `0x452FA4` (one). Pointer reuse across folder
navigation is not object-lifetime proof.

The final non-atomic snapshot identifies
`Slayer - Discography/Albums/1983 - Show No Mercy/1987 USA Discovery Systems, Metal Blade 71034-2`,
its playing FLAC and cue brackets 0/0, cache count 13, y=0, height=260,
pitch=80. This is consistent with the user's entry confirmation; title and
highlight/volume remain user observations. Next: physical Next twice to
The Antichrist and Die by the Sword with the file list open, no manual
scrolling, then save a separate checkpoint before reproducing offscreen
highlight. Test remains running; no commit or push performed.

### Slayer physical Next confirmed (2026-09-30)

User answered yes to highlight following each requested Next and working
volume. Live PID 123/hash/FD9 and absent flag remain verified. Snapshot
`artifacts/move_diag_slayer_next_20260930.bin` is 6,004,128 bytes; local/device
SHA-256 matches
`135dbe26c70b5866230f867edf6ed631242a6590217e1e9e76d85e71c8a2dc0b`.
It extends the decoded entry prefix exactly, with 4,362 snapshot/status pairs,
the same three setter and 18 refresh events, reserved=drained=21 and zero
reported loss flags. Strict decoding accepts the exported prefix.

The 1,144 new snapshots contain matching cue brackets 0/0 (739), 1/1 (16)
and 2/2 (389), each sampled y=0. Final folder/playback remains the deep Show
No Mercy release, cache count 13, pitch=80 and height=260. No new captured
scoped setter transaction or instrumented refresh input occurred in this
checkpoint interval. This is not absence proof for excluded setter modes,
absent-parent calls, other refresh routes or direct geometry writes.
Manual nonzero movement is still needed as a positive control.

Next: continue physical Next until highlight leaves the visible rows, do
not scroll manually or leave Files, wait about ten seconds, and report
whether the list follows and volume works. Save this checkpoint before
manual scrolling. Test remains running; no commit or push performed.

### Offscreen checkpoint and unexpected reboot (2026-09-30)

User reports that the list did not follow the offscreen highlight and volume
still worked. Before manual scrolling was requested, live PID 123/hash/FD9
and absent flag were checked. A device-side offscreen copy completed:
7,973,184 bytes, SHA-256
`e181b61124075c46c6b9be3cc6ebe6ad2c48d8639014991de4545fd632a63222`.
The USB device then disappeared before the pull. On reconnection, uptime was
40 seconds, stock `/usr/bin/hiby_player` was running as PID 118, and the
volatile `/tmp` copy was gone. No reboot, signal, rearming or test shutdown
command was issued by this agent during this checkpoint.

The persistent MOVE log survived with exactly the pre-reboot copy's size and
hash. It was saved locally as `artifacts/move_diag_recovered_20260930.bin`.
Strict decoding accepts 5,793 snapshot/status pairs and the unchanged 21
events (three setters, 18 refresh inputs), reserved=drained=21, zero reported
loss flags. Its decoded prefix matches the physical-Next checkpoint.
The 1,431 additional snapshots contain cue brackets 2/2 (772), 3/3 (191)
and 4/4 (468), all sampled y=0. Cue 4/y=0 spans 59.744035839 seconds.
Final samples still identify the deep release, cache count 13, pitch=80,
height=260. No new captured scoped setter/refresh event accompanies these
transitions. Excluded calls/direct writes and snapshot atomicity remain
outside this evidence; nonzero manual movement is not yet a positive control.

Stock recovery was verified via `/proc/118/exe` and `/usr/bin/hiby_player`,
both SHA-256 `0fedb30f...`; the test flag is absent. Current-boot dmesg reports
an unclean FAT unmount, but contains no prior-boot crash cause. No core was
found in the checked card-root paths or `/data`/`/tmp` listings. This does
not establish whether the test process crashed or the device reset for another
reason. The user subsequently confirmed that reboot was spontaneous.
Do not label this a successful
normal test shutdown or an automatic-scroll fix. Manual scrolling and Sleep
checks were not completed. Test is not rearmed; prior files and logs remain
preserved. Diagnose locally before proposing another device run. No commit
or push performed.

### Spontaneous reboot confirmed; initial local audit (2026-09-30)

User explicitly states that the player rebooted itself. Classify the run as
an unexpected runtime failure, not a user-requested shutdown. The mechanism
remains unknown: a player exit and launcher recovery, another software reset,
or hardware/watchdog reset cannot be distinguished by this log. Current-boot
FAT warnings are not a crash backtrace.

Read-only reproduction/scope/BSS checks still pass for the exact installed
`15cf4457...` artifact; all 59 repository tests pass again. Setter and
refresh wrappers, snapshot/drain stack frames, saving/restoration and tests
were reviewed without changing the executable. These mocked, single-thread
checks cannot validate device scheduling, lifetime, loader/heap interaction,
watchdog behavior or blocking filesystem latency. No concrete cause is
established by this audit; passing tests do not clear the artifact for reuse.

The recovered log has no reversed snapshot timestamps. Its last exported
event is refresh seq 20 associated with tick 2,656; the final snapshot is
tick 5,793, 401.216096573 seconds after the snapshot at that associated tick.
Tick association is not an event timestamp. Exported snapshot intervals
range from 0.090699378 to 5.217277215 seconds across the whole run; without
a control distribution or a prior-boot trace, this is not evidence of the
reboot cause. Final counters are settled (21/21, zero reported losses), not
proof that an unexported operation or post-log failure never happened.

The artifact is on hold: no automatic rearm/reinstall, no manual/Sleep test
claimed complete, no firmware fix or replacement build made. Future live
reproduction needs a reviewed plan that retains process exit/crash/reset
evidence; the current launcher/log do not provide it. This audit made no
device call, commit or push.

The resumed local investigation identified an additional collection-side
memory-pressure candidate: five distinct `/tmp`/tmpfs checkpoint copies,
not removed by the agent, total 21,543,680 bytes if retained. No RAM/OOM
measurement establishes causation. All checkpoints are exact byte prefixes
of the recovered run; the 5.217-second largest snapshot gap was at startup,
and final intervals remain approximately 128 ms. Independent code audits
found no demonstrated probe ABI/stack/ELF defect. See
[reboot analysis and evidence-retention requirements](folderfollow-move-reboot-analysis.md).
The read-only report adds three checks (62 total tests passing); firmware
and launcher are unchanged. No device access or rearm in this continuation.

A later user continuation prepared a separate
[evidence-retention launcher draft](folderfollow-move-evidence-launcher.md).
It retains raw child wait status, stderr and startup/running/end memory/kernel
attempts directly on the card, with prelaunch-only stock fallback and
post-launch recovery. Twenty-one mock tests pass (83 repository tests total).
The draft is not installed, and the firmware and installed launcher remain
unchanged. No device connection, rearm, commit or push.

## Artifact and scope

Artifact: `artifacts/hiby_player_1.4_sortfix_fullnav_wake_move_diag_test`

SHA-256:

```text
15cf4457e829692a52482c0b64a8b478f426f014b7cb31099ed6325a496c3f07
```

Source is the recognized recovered `02fd1dd1...` executable, normalized to
golden `c825a72e...` (sortfix/fullnav/wake). This diagnostic does not implement
automatic folder following or automatic scrolling. Test navigation should be
manual, as in SCRL and FILL. The player executable is 7,133,528 bytes.

The verifier confirms 1,246 changed bytes against golden, limited to:

- generic offset-setter entry `0x8B43C0..C4`;
- geometry reads inside row refresher `0x499CB4..B8`;
- the existing diagnostic timer callback pointer;
- 1,736 bytes in the existing 1,920-byte executable cave at `0x988040`;
- the final RW load's memory-size field at file offset `0xA8`.

The last change adds a zero-initialized BSS buffer at `0xBD4000`, with
98,368 bytes: a 64-byte header and 1,024 immutable 96-byte event slots.
The file length, executable segment permissions and file-backed payload sizes
are unchanged. Reproduction and ELF load-overlap checks pass.

## What gets captured

**MOVE setter event (kind 1).** Captures original caller return address,
render object C, request mode and requested y, old and returned y, C+0x3C
flags, parent, viewport height, raw extent, original return value, cue before
and after, and the last completed snapshot tick at entry. One slot is reserved
before the original function and published only after it returns. Relative
requests remain recorded as deltas; the decoder does not replace them with
an inferred absolute target.

Scope is `(request_mode & 0x20002) == 0x20002`, with non-null C/request/parent.
This includes combined x/y content requests and all widget names. Position
and size modes run through the original function without an event. In
particular, no-parent calls are deliberately excluded: stock returns before
reading the request, so the probe must not dereference a potentially invalid
request pointer. Absence of MOVE events cannot establish absence of those
excluded calls or direct writes to C+0x18 outside this setter.

**MOVE refresh event (kind 2).** At the original geometry-read point, captures
the refresher's saved caller, V, C, y/height/raw extent/flags/parent, pitch,
V+0x70, V+0x8C, current cue and snapshot tick. It is an observation of refresh
inputs, not a refresh completion or success record. It follows the original
null guards and replays the displaced height/pitch reads exactly once.
`new_y`, result and cue-after are unavailable for this event type.

**MSNP snapshot (0x540 bytes).** Reuses the hardware-tested SCRL snapshot
wrapper: original UI callback first, then current view resolution, bounded
view/folder/playback strings, cue brackets, viewport and cache summaries,
and monotonic-clock timestamp. Magic/version are MSNP/2 and offset +0x70
holds an incrementing snapshot tick. Existing SCRL v1 decoding remains intact;
the new decoder adapts only these records to the common field layout.

**MSTS status (32 bytes).** Contains version 2, reservations, exported events,
overflow/contention/I/O flags and capacity 1,024. Each successful UI drain
writes MSNP then MSTS, followed by up to eight available MOVE records.
A later MSTS with reservations=drained confirms that exported event prefix.

Timer-20 arm/reset/cancel events are not separately instrumented in this
version. Refresh callers can identify the previously traced timer,
render-completion and explicit routes, without modifying the stock timer
registry or adding a timer.

## Preservation and limits

Hot probes use memory operations, bounded LL/SC reservation (eight attempts),
integer arithmetic and publication barriers. They make no extra external
call, allocate nothing, and write only their own stack/BSS records. Scratch
registers are restored; probes do not use HI/LO or floating registers. The
setter wrapper executes the original function once and preserves its final
register state and return; the original prologue is replayed in a trampoline.

The post-call C read relies on the setter's existing object lifetime through
its return. Static inspection of the parent invalidation path found rectangle
operations, but concurrent destruction is not modeled by the tests. Snapshot
pointer/lifetime and non-atomic-copy limitations are inherited from SCRL.
No persistent pointer is later dereferenced by a separate consumer; the
drainer reads only copied records. Event addresses alone are not generation
proof, and events from another widget must not be attributed to Files solely
because playback happened nearby.

Event sequence is reservation order, not a total ordering of concurrent
execution or completion. Snapshot tick is an association hint, not an event
timestamp. A pending head slot blocks later export; it must yield an unsettled
capture rather than a claim that events were absent.

Slots are never reused. Overflow and reservation contention set sticky loss
flags while original execution continues. At capacity, later events are
lost and absence conclusions are invalid. The UI drainer writes to FD 9 only;
a short/error write freezes further output to avoid continuing a damaged
stream. Its sticky I/O flag might never reach the file. A clean decoded prefix
does not prove later I/O succeeded. Disk writes and snapshot stock calls can
still affect timing. A failed clock call retains the prior SCRL behavior of
zero timestamp fields without a separate clock-failure flag.

The decoder rejects damaged/truncated framing, invalid event scope/counters,
unknown versions, and mixed-run tick/sequence/counter histories. Its
`accepted_prefix` means only a settled, loss-accounted exported prefix;
hardware health and process generation must be checked separately.

## Local verification

The new suite has 17 tests. It executes emitted probe/drain instructions and
the actual source setter in content-y and other geometry scenarios, comparing
registers, object changes and parent calls with uninstrumented execution.
It also exercises absent-parent invalid requests, finite reservation retries,
last slot/overflow, blocked publication, eight-record drain cap, short/error
writes, cue-copy races, clock failure, non-explorer/null-context snapshots,
decoder corruption/mixed generations, and exact binary reproduction/scope.
The external parent/rectangle/snapshot/import calls are mocked; CPU ordering,
threading, real object lifetimes and device timing are not simulated.

All 59 repository tests pass. The dedicated launcher's shell syntax passes
`bash -n`. The independently read SHA-256 matches the reproducible build.

```text
python scripts/build_folderfollow_move_diag.py E:\platform-tools\hiby_player_02fd.bin artifacts/hiby_player_1.4_sortfix_fullnav_wake_move_diag_test
python scripts/verify_folderfollow_move_diag.py E:\platform-tools\hiby_player_02fd.bin artifacts/hiby_player_1.4_sortfix_fullnav_wake_move_diag_test
python -m unittest discover -s scripts -p test_folderfollow_move_diag.py -v
python scripts/decode_folderfollow_move_diag.py captured_move.bin
python scripts/decode_folderfollow_move_diag.py captured_move.bin --events
```

The builder refuses to overwrite an existing output artifact. Verification
rebuilds in memory and does not modify the candidate.

## Prepared hardware procedure

`scripts/rs2_folderfollow_move_diag_launcher.sh` uses the established one-shot
test path `/data/hiby_player_sortfix`, flag `/mnt/sd_0/RS2_SORTFIX_TEST`, and
dedicated log `/mnt/sd_0/rs2_folderfollow_move_diag.bin`. It refuses an existing
log so process generations are not appended. The flag is removed before
launch. Test exit syncs/reboots; next boot uses stock. This is exit recovery,
not a watchdog for a hung process. Installation remains a separate action.

After installation, verify the live candidate hash and observe these stages:

1. Leave DAC -> Music -> Files -> SD-card1 -> Roots in Russia. Start its
   composition, confirm highlight and volume, then inspect an initial log
   snapshot for MSNP/MSTS and valid counters. No current-call absence claim
   is needed at this startup stage.
2. Manually open the deep Slayer Show No Mercy release list and start
   Evil Has No Boundaries. Advance through The Antichrist and Die by the Sword.
   Confirm highlight/volume; pull a checkpoint before manual scrolling.
3. Advance until the highlight leaves the viewport. Leave that list open and
   stationary briefly, then collect another checkpoint. Compare MOVE setter
   requests and refresh callers with current-view/playback MSNP samples.
4. Scroll manually to the highlighted track. Confirm highlight/volume and
   collect another checkpoint. This provides a positive capture of the manual
   setter path and checks actual C+0x3C behavior without adding a scroll call.
5. Manually open Sleep and start Part 1; confirm highlight/volume. Retain the
   same path/cue-versus-row caution established by FILL's covers entry.
6. Wait for later statuses confirming all reservations drained, inspect all
   sticky loss flags, save the final log and verify stock recovery after exit.

Stop and recover if normal interaction regresses. Until these observations
are complete, this artifact remains a diagnostic test rather than a validated
autoscroll candidate.
