# Original renderer-entry frontier (2026-10-21)

Separate **offline diagnostic filter**, continuing the
[borrowed-dispatch observer](folderfollow-reveal-operation-stage.md). An old
original renderer job crossing a later known contents entry cannot acquire a
fresh identity merely by starting its producer after that entry. This is not
current-list/owner proof, a complete contents transaction or an active reveal.
No device access, install, launch, rearm or reboot occurred.

## Freeze the original entry

The custom `0x4906F8` hook in `build_reveal_origin_frontier_stage.py` preserves
the preceding three NULL guards. It replays the native 0x30-byte prologue/RA
store once, allocates its private 0x80-byte save frame, calls revision `bump()`
once, and stores its **actual returned ticket** at native renderer `sp+0x10`.
It restores volatile state/HI/LO and resumes remaining native saves at 490700.
Failure stores zero, replacing old stack bytes with an unadmitted carrier.
The old entry wrapper is not chained or called a second time.

This is the entry's own historical ticket, not a subsequent global-counter
read. If another caller advances the counter before bump returns, the original
entry still carries its earlier ticket. Root mint at `0x490758` copies that
same native-frame word into immutable RENDER record byte 60 before magic-last
publication. Later jobs retain the original root through private lineage;
callbacks never relabel it using the current name, address or counter.

Native +0x10 is outside O32's four home words, below the existing root-ID +0x14
and saved-register area starting +0x18. Source checks find no direct/derived
use of +0x10 in the renderer and no fifth outgoing argument. Pre-root callees
have bounded non-null/leaf-path premises, not arbitrary indirect-callee proof.
Source V==0 and native lifetime are not repaired or certified by a ticket.

The native prologue precedes the private frame deliberately. From the old
pre-prologue 0x80 wrapper, future native +0x10 would alias saved t9. Implemented
ordering keeps the carrier above our private frame. Tests preserve hostile
t9/v0/RA/HI/LO and prove one prologue, one bump and no +0x14 collision.

## Refuse stale-start payload capture

After the existing private PRODUCER/frame and frozen/current revision checks,
the optional row core follows only its already-validated private ORIGIN index:

- INITIAL and zero/unbound renderer roots are ignored before additional native
  offset/count/cue/path reads. No current-revision fallback supplies a ticket.
- Positive original renderer revision R requires frozen producer revision R+1:
  the actual Files worker entry is the single admitted known boundary between
  renderer entry and producer start. A positive mismatch/high-bit ticket faults
  row capture permanently before those extra payload reads.
- Existing before-count/prepublication revision checks remain. None establishes
  a lifetime lease or an atomic native-list read transaction.

The original stock fill/append/reset still runs. This filter does **not** stop
stale stock work from mutating a list: it withholds diagnostic acceptance and
our additional row-payload reads. Earlier active-frame/scalar transport reads
retain their previous source/lifetime premises. No worker locking repair is made.

Entry R1 followed by boundary R2 before its root mint still freezes R1, not R2.
A queued old root after reset therefore cannot pass with a fresh producer
sample. Repeated chunks and unrelated owners can be conservatively rejected;
this is not a per-owner generation or first-BORROW registry. An earlier BORROW
without an actual fill need not consume the original frontier.

## Strict versioned interpretation

`decode_reveal_origin_frontier.py` uses `lineage-rows-origin-frontier-v1`, the
same snapshot size as the prior operation format. Only allocated RENDER+60 is
extended; every other lineage byte60 remains zero. The decoder checks bounds
and impossible chronology (entry after producer/event/current), clears only
that extension in an owned temporary copy, then retains every prior strict
operation/row/revision check. Input bytes are not changed; the old decoder
rejects raw nonzero extension data rather than guessing a version.

Receipts and operations expose `original_entry_revision`. Operations preserve
the previous observed result as `observed_callback_sequence_complete_before_frontier`
and add `original_frontier_matches`: positive RENDER R must equal FILL_BEGIN's
R and its associated producer must have R+1. A stale/unknown start narrows
`observed_callback_sequence_complete` with `original-entry-frontier-mismatch`.
No implicit current-generation handle, host `CompletedRows` or UI action exists.

Base row windows and their revocation remain unchanged: even a matching origin
and callback chain does not exempt ordinary postfill/bind. All currentness,
capture-coherence and autoscroll flags stay false.

A stale UI/playback/request that *first enters the renderer after reset* can
receive a genuinely fresh ticket and still pass this negative filter. Already
active writers, missed aliases, recycled raw owners, incomplete scope/total and
incoherent capture remain unproved. Entry freshness is not request/playback
freshness, settled contents, complete writer coverage or retained lifetime.

## Saved local candidate and checks

Git-ignored local intermediate, **not installed or hardware validated**:
`artifacts/hiby_player_1.4_sortfix_fullnav_wake_origin_frontier_stage_v1_20261021.bin`.

- Size 7,154,204 bytes; SHA-256
  `c0db14bd8c1ec6df87eb4690ae55da8f6740e5c59faa9f14f51e6da168818601`.
- RX code 10,780 bytes at `0xC90000`, file offset `0x6D0000`.
- Private BSS remains 737,344 bytes at `0xBD4000`; operation journal remains
  65,552 bytes at `0xC78030`. No native template/job/list stride grows again.
- Exact saved-file verification passed: same 23 hooks/two strides and declared
  ELF spans, 170 changed original-file bytes. Full composed intervals, native
  jump region, original guards/saves/call anchors and 23 tail transfers are
  checked, including the retained unused old entry tail plus the new tail.
- No extra native query/getter/lock, UI setter/refresh, exporter or installer.
  All four preceding default image hashes remain exact, including operation
  `be40cecaa6172376f98cd8403477d16f609884347774564d19b7a95f881a49f8`.

All 40 new checks pass: eight source, fifteen decoder and seventeen emitted-
stage/image tests. They cover historical return-token races, prologue/scratch/
ABI, zero/fault/exhaustion, immutable root publication, delayed mint, queued
stale work, repeated chunks, INITIAL/unbound roots, payload suppression, strict
format/capacity/tamper checks and unchanged old outputs. Actual emitted capture
and callback observers execute; native SQL/append/binder bodies are bounded
hostile-ABI stubs. Independent review found no actionable defect.

Full repository regression: **1,032 tests pass, no skips** (181.294 s), including
all 40 new checks. All 148 Python scripts compile; tracked/new text files pass
whitespace checks. Saved-file verification and older output hashes pass. The
full run used local temporary-file access, without changing legacy tests or
using any real player transport.

These are not target CPU/cache/scheduler, native-owner or coherent-acquisition
proof. Positive integration still needs original request/playback/contents-phase
association, complete mutation/overlap handling and retained ownership through
publication and final UI action. No physical test is requested.
