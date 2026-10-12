# Passive reveal integration bridge (2026-10-08)

Follow-up: [launch preparation and read-only device preflight](folderfollow-reveal-launch-preparation.md)
now provide a separate 45-second best-effort diagnostic launcher and verified
backup of the existing launcher. The subsequent
[authorized smoke run](folderfollow-reveal-smoke-20261008.md) confirmed loader
acceptance, timer export and stock recovery. It recorded only statuses, not
events. The [October 12 interactive follow-up](folderfollow-reveal-interactive-20261012.md)
then captured completed observed Files windows, playback-copy pairs, touch,
refresh and view-close events without reported loss; the user confirmed
manual scrolling, preserved highlight and volume in the focused follow-up.
List-reset coverage and the active-autoscroll gates remain open, and
autoscroll is disabled. The installed launcher/candidate are unarmed.
The rest of this note records the preceding offline-build stage and its
original validation limits.

## What is connected

`scripts/build_reveal_bridge_diag.py` now produces a real patched MIPS ELF,
not another host-only model. It connects selected Files producer, playback,
contact, close/reset and refresh sites to one bounded private event buffer.
Timer 10 exports copied records to inherited FD 9 after calling its original
callback exactly once. The matching decoder checks exported observations.

This is **capture only**, not an autoscroll fix or a release candidate.
It does not call the reveal geometry core, select a target, move a list,
resolve a view, issue a query, rebuild a folder, or retain stock objects.
The existing host publication/policy models are not a live firmware adapter.
In particular, observing a reset does not yet implement cancellation.

The source normalizer uses the preserved `02fd...` reference or exact
`c825...` golden build. The resulting baseline is sorting + full traversal +
wake refresh, **without automatic folder-follow**. It does not combine old
diagnostic wrappers or reuse their code cave. No old diagnostic builder,
wire format, installed launcher or device file was changed.

## Built artifact and reproducibility

Local, Git-ignored output:

`artifacts/hiby_player_1.4_sortfix_fullnav_wake_reveal_bridge_capture_20261008.bin`

- Size: **7,146,848 bytes**.
- SHA-256: `7cc98a67a32dabce3b4d22b50b8dc847f5462d99d70d0ee04254a0ec272439a9`.
- Added code: 3,424 bytes, at `0xC70000`, file offset `0x6D0000`.
- Private zero-filled buffer: 606,272 bytes at `0xBD4000`, ending `0xC68040`.
- Original-file differences against normalized golden: 75 changed bytes,
  all within declared hook pairs, timer pointer words and ELF header fields.

From the repository root:

```powershell
python -X utf8 scripts/build_reveal_bridge_diag.py artifacts/import-20261001/hiby_player_02fd.bin artifacts/hiby_player_1.4_sortfix_fullnav_wake_reveal_bridge_capture_20261008.bin
python -X utf8 scripts/verify_reveal_bridge_diag.py artifacts/import-20261001/hiby_player_02fd.bin artifacts/hiby_player_1.4_sortfix_fullnav_wake_reveal_bridge_capture_20261008.bin
```

The builder refuses to overwrite an existing output. The verifier passed
against the saved file. It checks the exact deterministic output, original
patch scope, segment layout, hooks/delay slots and emitted control-flow
inventory. Neither command installs or runs firmware.

## ELF layout and untested loader boundary

The old `0x988040..0x9887C0` cave is too small for the combined probes and
remains untouched. `scripts/reveal_bridge_elf.py` extends only the existing
RW load's `p_memsz`, and replaces the final unused `PT_NULL` header with a
separate appended RX `PT_LOAD`. Original program-header count, entry point,
other headers and original segment permissions remain unchanged.

The new segment is 64 KiB aligned, does not overlap either original load or
the extended BSS, and remains in the original MIPS direct-jump region. No
writable-executable load is added. The pre-existing executable GNU stack
header is unchanged; this is not a claim that the whole process has no W+X.

**Target loader acceptance, heap placement, available memory, timing and
hardware behavior are untested.** Offline ELF validation does not close
that boundary. No installer for this hash/size was prepared or armed.

## Selected observations

All addresses refer to the exact normalized firmware 1.4 reference.

| Events | Hook sites | Copied evidence |
| --- | --- | --- |
| 1–4: begin/row/terminal/end | `0x6ED624`, `0x6ED6E8`, `0x6ED704`, `0x6ED7D4` | Selected mode-0 fills: frame, statement/list tokens, caller, requested/window offset, ordinal, actual list count, append/terminal/end results and path/cue |
| 5–6: playback before/after copy | `0x42AC0C`, `0x42CBDC`, `0x42CD5C` | Source identity before the original `memcpy`; completion references the preparation sequence and records the actual return value |
| 7: recognized raw contact | `0x8B4CC0` | Raw types 2/3, G/H tokens, prior G state and coordinates |
| 8–9: close/reset entry | `0x493AC0`, `0x491240` | Numeric argument tokens only |
| 10: current Files refresh | `0x499CB4` | Borrowed current V/C tokens, type 2, numeric list token, pitch, height, offset and inline folder scope |

Producer capture accepts only the two known Files callers `0x6F8BF4` and
`0x6F8E0C`, mode 0 and a non-null list. Stock append runs exactly once with
its original-frame argument. An append result of zero is the valid index
for row zero; subsequent successful results must match their row ordinal.
Terminal capture preserves the original finalize tail call.

Playback capture checks source non-nullness, four-byte alignment and the
expected `0xA88` size before extra source reads. It never rereads the source
after `memcpy`. An unreadable capture is recorded as empty path plus
`truncated=1`; the original call still runs, but the decoder rejects the
identity pair. This check is not a general pointer-validity proof.

Touch capture does not read the packet when G is null, and does not read
coordinate fields for type-1 short key packets or unknown types. The
displaced conditional branch is relocated correctly, not copied with its
old PC-relative offset. Refresh uses the current invocation's borrowed V/C,
not a timer lookup; it never follows the recorded list token.

Hot probes save/restore volatile integer registers and HI/LO. Stack locals
are outside the O32 outgoing argument-home area. Playback and append wrappers
preserve the post-call result state. This is ABI preservation, not a proof
that the additional observation latency is harmless on hardware.

## Buffer, wire format and decoder

The private BSS starts with a 64-byte header and 1,024 non-reused 592-byte
slots. Reservation has at most eight LL/SC attempts. Capacity and contention
loss set sticky flags; there is no wrapping, overwriting or unbounded retry.
Slot publication uses `sync` before the final magic store. The reader checks
magic and uses an acquire `sync` before exporting payload. A publication hole
stops draining, rather than skipping a reserved slot.

Each timer invocation calls stock once, then writes one 32-byte `RBST` v1
status and at most eight `RBRG` v1 event records. It follows only permanent
private BSS. A short/failed write sets sticky I/O error and disables later
exports, while stock timer callbacks continue. This bounds operation count,
not blocking duration: FD 9 must be an exclusively owned regular diagnostic
file in any future launch, not a pipe or shared stream.

Event headers are sixteen little-endian uint32 values:
`magic, version, event, seq, frame, statement, list, mode, offset, ordinal,
result, caller, cue, truncated, list_count, reserved`.
Their interpretation depends on the event, as listed above. In playback end,
`statement` is the preparation sequence or `0xFFFFFFFF` on reservation loss;
in refresh, `frame/statement/list` are V/C/list tokens and
`offset/ordinal/result` are y/pitch/height.

Path storage is 260 UTF-16LE code units at `0x40`, followed by eight zero
padding bytes. Copying reads at most 260 source units, writes at most 259,
and retains a zero terminator. Overlong paths are marked unusable; the
decoder rejects malformed UTF-16 or nonzero padding instead of resyncing.
Status words are `magic, version, reserved, drained, overflow,
contention_loss, io_error, capacity`.

```powershell
python -X utf8 scripts/decode_reveal_bridge_diag.py <captured-log>
python -X utf8 scripts/decode_reveal_bridge_diag.py <captured-log> --events
```

The decoder requires contiguous event sequences, monotonic status/loss
fields and a final status **after** the last event, with reserved = drained =
observed event count and no reported loss. The final confirmation normally
requires a later timer tick after the last record was exported. A torn or
unconfirmed tail cannot certify even an otherwise plausible window.

Producer grouping rejects overlapping/reused scopes, missing or conflicting
events, append/count mismatches, duplicates, truncation and missing terminal
101/end. Accepted results are completed **observed windows**, not certified
whole-folder snapshots. Playback pairs check the preparation reference,
caller/frame and captured identity; overlapping copies remain explicitly
labelled and do not establish a global current identity.

## Validation and remaining integration gates

Full suite: **394 tests pass, no skips**. This includes 83 new bridge tests:
13 ELF-layout, 7 build/verifier, 48 decoder and 15 emitted-instruction tests.
All **82 Python files under `scripts/` compile**. Three end-to-end tests feed
actual emulated hook and timer output into the decoder: a valid playback
pair, an unreadable source and a complete two-row producer window.

The instruction harness exercises delay slots, mapped/aligned reads, hostile
callee clobbers of volatile registers/HI/LO/argument-home words, source
invalidation during `memcpy`, original calls exactly once, queue exhaustion,
bounded string copying, timer drain limits and short writes. It is not a
CPU, pipeline, concurrency, loader or stock-object-lifetime simulation.

Before enabling the existing one-shot policy and geometry core, still needed:

1. A retained UI owner and non-reused content/view generation, with coverage
   of every relevant reset, inline replacement, close and scope change.
2. Coherent playback publication, including clear paths, and whole-folder
   completion/total evidence. Queue reservation order is not stock mutation
   completion order; pointer tokens are not ownership or generations.
3. Owned contact/animation state and cancellation through the actual UI
   transaction. Touch records alone do not cover lost input, settling or
   object replacement.
4. A separately reviewed bounded diagnostic launch/recovery path for this
   new ELF layout, followed by real loader and observation evidence.

No ADB/device access, installation, launch, rearm, reboot, commit or push was
performed in this step. The October 2 stock recovery remains historical,
not a current device assertion. This bridge advances passive integration;
it does not resolve the remaining active-autoscroll safety gates.
