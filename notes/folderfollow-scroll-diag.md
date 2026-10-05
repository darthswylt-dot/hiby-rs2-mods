# Passive scroll diagnostic — test complete, stock recovery verified

## Deployment update (2026-09-29)

User authorized installation and then requested a repeat. Before the repeat,
stock was running; the candidate and launcher hashes still matched. The prior
88,787,328-byte log was preserved on the card as
`/mnt/sd_0/rs2_folderfollow_scroll_diag.previous.bin`. The one-shot flag was
armed again and the device rebooted. Live `/proc/123/exe` matches candidate
SHA-256 `5ae6d8195c1f7061cbc9cd0b6ed64e6fd3a623c7945a3218d84473f93777520e`.
The flag was consumed, and the new log reached 231,168 bytes. Interactive
playback/scroll behavior has not yet been confirmed for this run.
Launcher: `scripts/rs2_folderfollow_scroll_diag_launcher.sh`; prior device
launcher and candidate are backed up in `artifacts/scroll_diag_install_backup`.
Stock `/usr/bin/hiby_player` remains unchanged (`0fedb30f...`).

### Interactive result

User confirmed highlight and volume in Roots, deep Slayer, after manual Slayer
scrolling, and Sleep Part 1. Physical Next in Slayer moved the highlight below
the screen without automatic scrolling; manual scrolling revealed it again.

Local live-log snapshot `artifacts/scroll_diag_interactive_20260929.bin` contains
3,017,280 bytes / 2,245 complete SCRL records; strict decoding succeeded.
Zero-based record indices:

- 1037: Slayer cue 0, pitch 80, viewport height 260, scroll_y 0.
- 1320/1327/1333/1340/1347: cue 1/2/3/4/5 respectively, scroll_y stays 0.
- 1544..1562: cue remains 5 while manual scrolling raises scroll_y from 33 to
  330. Slayer cache capacity/start/count remain 512/0/13.
- 1901: Sleep playback path, cue 0, scroll_y 0, cache count 7.

This confirms that the observed offset follows manual scrolling but not the
tested playback changes. It does not yet identify a safe automatic scroll call.
Two telemetry interpretations need rechecking: `content_height` stays zero even
during scrolling, and `sort` is 12429001, outside the previously identified
small mode values. Do not use these fields to derive bounds/order until the
base pointer and field semantics are corrected or otherwise explained.
After explicit user approval, diagnostic PID 123 was terminated with SIGTERM.
The one-shot launcher rebooted the device; live `/proc/119/exe` is now stock
`/usr/bin/hiby_player`, SHA-256
`0fedb30f91937eafb5baaf3c75422cdbde04a62fe8bac8eca3c7a88bb761da0e`.
The test flag is absent. Final log is saved locally as
`artifacts/scroll_diag_final_20260929.bin` (3,854,592 bytes); the earlier live
snapshot and previous-run log remain preserved.

The preparation/audit notes below describe the state before this deployment.

The SCRL diagnostic observes the active explorer after the original timer
callback. It does not call navigation, row lookup, property setters or the
scroll setter, and does not attempt to fix scrolling.

Artifact: `artifacts/hiby_player_1.4_sortfix_fullnav_wake_scroll_diag_test`

SHA-256: `5ae6d8195c1f7061cbc9cd0b6ed64e6fd3a623c7945a3218d84473f93777520e`

Base is normalized golden `c825a72e...`, **not** the active-view folder-follow
candidate `6e872416...`. Therefore navigate to Slayer and Sleep manually for
this experiment; automatic cross-folder following is not part of this build.
Only the timer callback pointer and a 0x220-byte wrapper in the existing cave
change from golden. No installation, commit or push was performed.

## Record and limitations

Count-field correction (2026-10-05): the historical `cache_count` wire field
reads P+0x1E0, the **total folder count**, published before population. Actual
primary-list population is L+0x0C. Neither count proves successful completion.
The v1 field name and binary layout stay unchanged for saved-log compatibility;
earlier references to cache count 13/7 mean this raw total, not a ready cache.
See [the reveal model and integration limits](folderfollow-reveal-model.md).

Fixed-size 0x540-byte SCRL v1 records go to FD 9. The launcher must provide this
descriptor to a new diagnostic log before any device test. The wrapper records
active inline view name, explorer wildcard and lookup key, viewport offset and
extent, row pitch, cache capacity/start/count, working enumeration index,
database sort mode, playback path and cue IDs before/after the path copy.
Absent objects leave zero-valued fields; use pointer/validity fields, not zeros
alone, to interpret availability.

The enumeration index is **not** the playing selection. Matching cue IDs do not
prove an atomic snapshot. Null checks do not guarantee object lifetime or
protection against concurrent mutation. Existing stock copy/callback routines
are still invoked. At ten callbacks per second log traffic is 13,440 bytes/s;
blocking storage writes can affect timing. This is experimental instrumentation,
not a claim of hardware safety.

## Offline checks

- `test_folderfollow_scroll_diag.py`: eleven tests, including both explorer names,
  a short non-explorer object, null context/controller/view and child pointers,
  mocked register/stack/return preservation, no object writes, call allowlist,
  branch delay slots, malformed-record rejection, maximum-length unterminated
  strings, signed cue values, repeated samples, changed cue during copying,
  and mocked clock/write failures.
- `verify_folderfollow_scroll_diag.py SOURCE CANDIDATE`: exact reproducibility
  and byte-level scope against normalized golden.
- `decode_folderfollow_scroll_diag.py LOG`: strict framing and changed-state
  JSON output (`--all` retains identical samples). Partial final records are
  rejected, not silently ignored.

Mocks do not execute stock firmware routines or model threading, actual pointer
lifetimes, UI timing, storage errors or asynchronous signal behavior.

### Additional audit (2026-09-29)

ELF relocation targets independently confirm the imported entry points:
clock_gettime `0xA5B380`, write `0xA5B4A0`, strncpy `0xA5B6E0`,
strncmp `0xA5BA40`, memset `0xA5BC60`. Disassembly of `0x41FB80`
confirms copying at most 259 UTF-16 code units and appending a terminator;
its one-code-unit read-ahead remains within the 260-unit source field.
The mock now models this bounded code-unit behavior rather than decoding the
whole source string before truncation. Record fields do not overlap, and the
record ends before saved arguments/registers in the stack frame.

Error-path finding: `write` is attempted once and its result is ignored. A short
write can corrupt record framing; subsequent records do not repair it. A failed
write loses that sample. The mock verifies that these return values do not
replace the original callback result, **not** that logging succeeds. Likewise,
a failed clock call leaves zero timestamp fields without a separate error flag.
These are known telemetry limitations; the firmware bytes were not changed.
Device deployment remains pending, including the dedicated one-shot launcher.

## Next authorized hardware experiment

Prepare a dedicated one-shot launcher with FD 9 and stock recovery before
installation. Installation requires the user's next explicit instruction.

1. Exit DAC, Music -> Files -> SD-card1 -> Roots in Russia; start playback and
   verify highlight and volume.
2. Manually open the deep Show No Mercy release track list; start Slayer.
3. Advance tracks until the highlighted row goes below the visible region;
   note when this happens without changing the view.
4. Scroll manually to the current track; compare viewport/cache state before
   and after manual scrolling.
5. Manually open Sleep and start Part 1; check cue/path and folder state.
6. End the one-shot run, confirm stock recovery, retrieve and decode the log.

Decide on a scroll target only after matching runtime sort/cache behavior to
the static row-source trace. Do not use an absent SQL lookup's zero result as
proof that the playing item is row zero.
