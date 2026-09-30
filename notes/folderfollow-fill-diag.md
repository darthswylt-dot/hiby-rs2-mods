# FILL v1: passive folder-list producer diagnostic

Built and installed 2026-09-30. **TEST COMPLETE / STOCK RECOVERY VERIFIED.**
This is a diagnostic executable, not an update image or an autoscroll fix.
It observes actual query/append order so the later scrolling investigation
does not have to infer an index from the cue number or unexplained sort field.

## Installation and initial device check (2026-09-30)

User explicitly authorized installation. Before deployment the running stock
PID 121 matched `0fedb30f...`; battery reported 100%, USB online, and the FILL
log and one-shot flag were absent. Previous executable (SCRL `5ae6d819...`) and
launcher (`3ccbf0c0...`) were pulled and hash-verified in
`artifacts/fill_diag_install_backup_20260930/`.

Both new files were staged separately, checked on-device, made executable and
renamed into the existing test paths. New launcher SHA-256:
`0151c274450706ec9fc571155dcf912ec9094f25834c2a2faf00af185d3e0617`.
Device `/bin/sh -n` passed. Stock `/usr/bin/hiby_player` remained unchanged.
The one-shot flag was armed, files synced, and the device rebooted once.

After reboot, live `/proc/123/exe` matches the full candidate hash below;
`/proc/123/fd/9` points to the dedicated FILL log, and the one-shot flag is gone.
The mapped RW region contains the added buffer. Log growth was observed from
4,128 to 10,144 bytes. Local `startup_snapshot.bin` in the backup directory
decodes as 317 valid FSTS records, final reserved=drained=0, loss flags all zero.
There are **no captured producer sessions yet**: startup/logging is verified,
not row instrumentation, playback, highlight, volume or runtime ordering.
The prior 3,854,592-byte SCRL log was left untouched. Await user navigation
through DAC -> Music -> Files -> SD-card1 -> Roots in Russia.

### Roots stage confirmed (2026-09-30)

User answered yes to playback, file highlight and working volume. Live PID 123
still matches `7e01a34b...`. Snapshot `artifacts/fill_diag_roots_20260930.bin`
is 63,536 bytes: 1,782 FSTS records and 11 producer events (two BEGIN, five ROW,
two TERMINAL, two END). Final status reserved=drained=11; overflow, contention
and I/O loss flags are zero. Both captured sessions pass the conservative
decoder, with requested limit 512, offset 0, terminal 101 and matching counts.

- Card root: indices 0 Roots, 1 Slayer - Discography, 2 Sleep; all cue=-2.
- Roots directory: index 0 covers (cue=-2), index 1 the FLAC (cue=-1).

These are captured list identities/order, not playback metadata measured by
this build; playback/highlight/volume are the user's observations. This verifies
the first real producer records and drain, not every error/concurrency case.
Next stage: manually enter the deep Slayer release folder and start Evil Has
No Boundaries; leave automatic scrolling and cache-refill conclusions pending.

### Slayer entry and cue rows confirmed (2026-09-30)

User confirmed Slayer playback, highlighted composition and working volume
after manual deep navigation and the requested Evil Has No Boundaries start.
Live PID 123 still matches the diagnostic hash. Snapshot
`artifacts/fill_diag_slayer_20260930.bin` is 108,576 bytes: 2,653 status records
and 40 events (6 BEGIN, 22 ROW, 6 TERMINAL, 6 END). All six sessions pass the
decoder; final reserved=drained=40, all loss flags zero, every terminal=101.

Four new fills follow the real hierarchy: Slayer -> Albums -> 1983 - Show No
Mercy -> 1987 USA Discovery Systems, Metal Blade 71034-2. Their row counts are
1, 2, 1 and 13. The release folder captures the same FLAC path for all 13 rows,
with distinct cue values 0..12 and corresponding insertion indices 0..12.
This proves why path alone is insufficient here; cue equals row only for this
observed ordering, not as a universal rule. All observed offsets are zero.
No cache-window refill or automatic viewport movement is established by this
snapshot. Next stage: physical Next within the open list, then manual scroll.

### Slayer physical Next confirmed (2026-09-30)

After the requested Next sequence through The Antichrist and Die by the Sword,
user reports that highlight follows each track and volume works. Snapshot
`artifacts/fill_diag_slayer_next_20260930.bin` is 148,608 bytes: 3,904 status
records and the same 40 producer events / six accepted fills. Final counters
remain 40/40 with all loss flags zero; live PID 123 still matches the candidate.
No additional captured folder fill occurred during this interval, consistent
with reuse of the already loaded list. This does not establish absence of
other uninstrumented activity or fix the offscreen-highlight issue. Next test:
advance beyond the visible rows without manually scrolling, observe viewport
behavior, then scroll manually to the highlighted row.

### Offscreen highlight reproduced (2026-09-30)

After the additional requested Next presses, user explicitly reports highlight
outside the screen, no automatic list scrolling, and working volume. Snapshot
`artifacts/fill_diag_slayer_offscreen_20260930.bin` is 176,032 bytes with 4,761
status records and the unchanged 40 producer events / six accepted fills.
Final reservations=drained=40; all loss flags zero; live PID 123 matches the
candidate. No additional instrumented fill occurred during this interval.

The failure is therefore reproduced while the previously captured complete
13-row Slayer fill is available as historical evidence. This alone neither
proves the live cache is unchanged nor locates the missing scroll operation:
FILL has no viewport/playback telemetry. The viewport observation is supplied
by the user. No fix was expected from this passive build. Next: manually scroll
down without choosing another track, reveal the playing highlight and verify
volume; then inspect whether that action generated any new captured fill.

### Manual scroll restores visible highlight (2026-09-30)

User confirms the playing composition is highlighted after manual scrolling
and volume still works. Snapshot
`artifacts/fill_diag_slayer_manual_scroll_20260930.bin` is 207,712 bytes:
5,751 status records and the same 40 events / six accepted fills. Final
reservations=drained=40, all loss flags zero, all captured query offsets zero;
live PID 123 still matches the candidate. No newly instrumented fill occurred
during manual scrolling. The small 13-row release list therefore did not
exercise a nonzero-offset producer refill in this run; no general conclusion
about cache mutation or larger lists follows. Next stage: manually navigate
to Sleep, start Part 1, return to Files and check highlight/volume.

### Sleep passed; interactive capture complete (2026-09-30)

User confirmed Part 1 playback, highlight and working volume after navigating
manually to Sleep and returning to the list. Snapshot
`artifacts/fill_diag_sleep_20260930.bin` is 244,560 bytes, SHA-256
`3a8c79ccc5b5fcd85b6396054778efb98061f3f40adc6d14eefe6ea569c5aa3c`.
It contains 6,440 status records and 65 events (10 BEGIN, 35 ROW, 10 TERMINAL,
10 END). All ten captured fills pass the decoder. Final reserved=drained=65;
all loss flags zero. Live PID 123 still matches `7e01a34b...`.

Four additional fills captured navigation through Albums, Slayer, card root
and Sleep, with 2, 1, 3 and 7 rows respectively. Sleep has covers at index 0
(cue=-2), then one shared FLAC path with cue 0..5 at indices 1..6. Thus the
Part 1 identity cue=0 is at row index 1, contrasting with Slayer's cue=0 at
index 0. The diagnostic directly observes this insertion-order difference;
it is not derived from the undocumented sort value or assumed cue arithmetic.

Results of this limited run: normal playback/highlight/volume checks passed
for Roots, deep Slayer and Sleep. Physical Next moved Slayer highlight beyond
the viewport without automatic scroll; manual scrolling revealed it again.
All captured sessions completed with terminal 101 and consistent append/count
records, with no reported event loss. No new instrumented fill appeared during
Slayer Next/manual-scroll intervals. Every query offset was zero, so nonzero
cache windows, lifecycle-wide map validity and concurrency/error paths remain
unvalidated. This build does not fix autoscroll and cannot alone locate the
missing viewport action. The settled snapshot is saved; the diagnostic process
is still running pending explicit end-of-test/recovery authorization. No commit
or push has been performed.

### Authorized shutdown and stock recovery (2026-09-30)

User explicitly approved ending the diagnostic and rebooting to stock. Before
shutdown, a separate pre-stop snapshot confirmed ten accepted fills, 65/65
events drained and zero loss flags. Live test PID 123 matched the candidate;
the one-shot flag was absent. SIGTERM was sent only to that confirmed PID.
The one-shot launcher then synced and rebooted the device.

After reboot, live `/proc/121/exe` matches stock SHA-256
`0fedb30f91937eafb5baaf3c75422cdbde04a62fe8bac8eca3c7a88bb761da0e`.
The one-shot flag remains absent; the diagnostic process is no longer running.
The test executable and launcher remain staged but are not armed. Old logs and
backups were preserved; no firmware/stock executable was replaced.

Final closed log: `artifacts/fill_diag_final_20260930.bin`, 285,808 bytes,
SHA-256 `7cd4a63322fc2c32d141572a7725d6c00a44b0b506972d00537deb6d257ff0fe`.
Local and device log hashes agree. Decoding yields 7,729 status records plus
65 producer events: ten BEGIN, 35 ROW, ten TERMINAL, ten END. All ten fills
are accepted, final reserved=drained=65, loss flags zero, no framing errors.
This supersedes the running-state descriptions in the chronological stages
above. No commit or push was performed.

## Artifact and baseline

- File: `artifacts/hiby_player_1.4_sortfix_fullnav_wake_fill_diag_test`
- Size: 7,133,528 bytes (unchanged).
- SHA-256: `7e01a34b98584359a3b98312ae040d77feb93a75fe4bdbc4604913da32f1925d`
- Input: recovered `02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87`.
- Normalized golden: `c825a72e1078999f74822846d35c99971f9a660addd5f12d42d50a75f0b9b80e`.

The normalizer accepts only the two known hashes. Golden retains the known
sortfix/fullnav/wake baseline, **without active-view folder-follow rebuilding**.
This build does not call ensure-visible, change offsets, retarget a folder,
build a persistent map, or change SQL. Do not expect an automatic cross-folder
jump. It does not include SCRL viewport/playback telemetry; its purpose is to
measure the folder-list producer. Original timer callback `0x4E90C0` still runs
once before every diagnostic drain, with its result preserved.

The builder imports instruction helpers/constants from the historical
view-depth module, but never invokes its failed historical wrapper.

## Byte-level patch scope

Offsets are relative to the file; hook addresses are virtual addresses.
There are 1,024 changed bytes relative to normalized golden, only within:

| Location | Change |
| --- | --- |
| File `0xA8`, 4 bytes | Last RW PT_LOAD `p_memsz`: `0x167CA4` -> `0x1B2040` |
| VA `0x6ED624`, 8 bytes | BEGIN: jump `0x988040`; replay both displaced additions |
| VA `0x6ED6E8`, 8 bytes | ROW: call `0x9880F8`; preserve original argument delay slot |
| VA `0x6ED704`, 8 bytes | TERMINAL: call `0x9881C0`; preserve original `a0=s0` delay slot |
| VA `0x6ED7D4`, 8 bytes | END: jump `0x988270`; replay both displaced restores |
| File `0xEAEBC` and `0xEAECC`, 4 bytes each | Timer callback pointer -> `0x9884A0` |
| VA `0x988040`, `0x58C` bytes | Wrappers and recorder; within the verified `0x780` empty cave |

ROW calls the original indirect append exactly once, then captures its return
and the still-live descriptor before producer ordinal advancement. The shared
branch destination `0x6ED6F4` is untouched. TERMINAL captures raw SQL-step v0,
then tail-jumps to original reset `0x5C31C0` with return address `0x6ED70C`.
END captures the count return, not an independently successful SQL outcome.

Added zero-initialized BSS buffer: `[0xBD4000, 0xC1E040)`, 303,168 bytes.
Total ELF memory-size increase including alignment padding: 304,028 bytes.
File contents/length and the segment's `p_filesz` are unchanged. The verifier
checks the buffer is beyond existing file-backed data and does not overlap
another load segment. Loader acceptance, RAM headroom and runtime memory
ordering remain hardware checks, not claims established by the offline model.

## Capture and loss policy

Only producer `0x6ED5C0`, mode 0, and caller return addresses `0x6F8BF4`
(ordinary folder query) / `0x6F8E0C` (date-order folder query) are captured.
The list, frame, statement, saved query offset and caller identify each fill.
BEGIN records the requested limit and original folder filter. ROW copies path,
cue, append return and actual list count. TERMINAL records the raw final step
code; END records the producer return and list count. A BEGIN without terminal
or end is not accepted. Invalid arguments returning before BEGIN, statement
preparation failures outside this producer and nonmatching modes/callers are
outside coverage; an absent session never proves a successful empty query.

Producer hooks perform only bounded memory reads/writes: no database query,
allocation, UI call or file write. Each record is reserved with at most eight
LL/SC attempts. Slots are never reused. Payload precedes SYNC and final magic
publication. The single UI-timer consumer checks magic then SYNC and drains
at most one immutable record per callback to pre-opened FD 9.

There are 512 records total for the entire process, **not per folder**.
A successful N-row fill uses N+3 records. Overflow and exhausted reservation
retries set sticky loss flags; they do not block producers indefinitely.
After capacity is exhausted the diagnostic requires a fresh process, even
after all existing records have been drained. There is no wraparound/reset.

These measures reduce perturbation, not eliminate it: path copying takes time,
list/path lifetime is assumed from the traced producer context, and SD writes
can still delay the UI timer. The mock tests do not simulate real multicore
ordering, faults, hardware LL/SC behavior or concurrent list mutations. There
is no device-side persistent mapping or lifetime guarantee after a fill ends.

## Stream and conservative decoder

All integers are little-endian. There are two interleaved record types:

- `FSTS`, 32 bytes: magic, version=1, reservations, drained, overflow,
  contention_loss, io_error, capacity=512.
- `FILL`, `0x250` bytes: 16-word header followed by a 260-unit UTF-16LE field
  at +0x40 and padding. Header: magic, version=1, event (1..4), sequence,
  producer frame, statement, list, mode, offset, ordinal, result, caller,
  cue, truncation, list count, reserved=0.

At BEGIN ordinal=0/result=requested limit/string=folder. At ROW result is
append return/string=path/cue is copied. TERMINAL result is the raw step code;
END result is the producer count. Unused string/cue fields stay zero. Strings
are limited to 259 units plus NUL; longer strings are marked, not silently
accepted. Sequences begin at zero for each process and never repeat in a run.

The decoder rejects malformed framing, invalid metadata and invalid UTF-16.
Session acceptance requires initially empty list, supported scope, nonnegative
offset/limit, ordinal and append index 0..N-1, actual count progression,
untruncated identities, raw terminal 101, matching end counts, and unique
path/cue identities. Any lost event, orphan, sequence gap, counter regression
or global loss flag invalidates all sessions in that snapshot. It also requires
a **later status confirming reserved=drained=exported event count**.

Accepted output is a historical fill snapshot: `index = query_offset + ordinal`.
It is not evidence that the list remains current, that every producer path was
covered, or that this is an immediately usable scroll target.

Short/error writes disable all later logging; there is no retry which might
conceal a broken record. Consequently the new io_error flag might never reach
the file. A last all-zero status alone cannot certify a clean shutdown or no
later failure. A complete, settled capture certifies only its exported prefix;
repeated snapshots and process health must also be checked during a test.

## Offline verification

From the repository root with the configured Python runtime:

```text
python scripts/build_folderfollow_fill_diag.py E:\platform-tools\hiby_player_02fd.bin artifacts/hiby_player_1.4_sortfix_fullnav_wake_fill_diag_test
python scripts/verify_folderfollow_fill_diag.py E:\platform-tools\hiby_player_02fd.bin artifacts/hiby_player_1.4_sortfix_fullnav_wake_fill_diag_test
python -m unittest discover -s scripts -p test_folderfollow_fill_diag.py -v
python scripts/decode_folderfollow_fill_diag.py captured_fill.bin
python scripts/decode_folderfollow_fill_diag.py captured_fill.bin --events
```

18 emitted-instruction/mock/decoder tests pass: original call/argument/return
preservation, successful fill, failed append/SQL termination, mode/caller
filter, last slot, bounded contention retries, overflow, unpublished slots,
status/record write failures, truncation, partial stream, unsettled/lost
snapshot, duplicate identities, scope mismatch, nonzero-offset mapping, empty
completed query, missing terminal after bind failure, reuse after clear, and
rejection of unknown source bytes.
The nine previous cache/fill model tests also pass. Read-only regression audit
still validates 67 stock-code anchors and all 2,868 final SCRL records.
The dedicated launcher's shell syntax was checked with `bash -n`.

## Hardware procedure (installation authorized and completed above)

Use `scripts/rs2_folderfollow_fill_diag_launcher.sh` with the established
one-shot layout: test executable `/data/hiby_player_sortfix`, flag
`/mnt/sd_0/RS2_SORTFIX_TEST`, stock executable untouched. The flag is removed
before launch. On test exit the launcher syncs/reboots; next boot falls back
to stock. This is recovery after exit, not a watchdog for a hung process.

The dedicated log is `/mnt/sd_0/rs2_folderfollow_fill_diag.bin`. Existing log
presence refuses a new test and falls back to stock: archive it explicitly
before arming another run. Do not append generations or overwrite old logs.
Prepare/review the launcher and executable backup before any installation.

1. Start with the documented route: leave DAC -> Music -> Files -> SD-card1
   -> Roots in Russia. Start its composition. Confirm playback, highlight and
   volume; collect a first log snapshot and verify that real BEGIN/ROW/END
   sessions appear. Stop the experiment if normal interaction regresses.
2. Navigate **manually** to Slayer - Discography -> Albums -> Show No Mercy
   -> the release directory. Confirm the actual displayed folder before
   interpreting its rows. Start Evil Has No Boundaries, then switch tracks
   through The Antichrist / Die by the Sword; confirm highlight and volume.
   Next alone need not produce any fill, because it can reuse a loaded list.
3. Scroll manually beyond the viewport to exercise cache refill; inspect
   snapshots for nonzero query offsets if such refills occur. No forced
   scrolling or SQL query is added for this purpose.
4. Navigate manually to Sleep, play Part 1 and confirm highlight/volume.
   Folder entries such as covers count toward row positions; cue alone must
   never substitute for the recorded append position.
5. Stop navigating and wait for later statuses with reservations=drained.
   At one record per roughly 100 ms callback a full buffer needs about 52 s,
   but measured counters, not elapsed time, determine completion. Pull and
   validate a settled snapshot before ending the process. Save a final copy,
   then verify stock recovery and absent one-shot flag separately.

The build-only step performed no installation; the subsequent explicitly
authorized installation is recorded above. No playback action, commit or push
was performed during installation. The test process is left running.
