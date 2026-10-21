# Exact borrowed-job callback observation (2026-10-20)

Separate **offline diagnostic intermediate**, following the
[known-boundary revision filter](folderfollow-reveal-contents-revision-stage.md).
This connects observed fill/query/row/postfill/bind facts to the exact original
BORROW receipt. It is not yet a native contents-phase handle, settled generation,
retained-owner transaction, host ready rows or permission to scroll. No player
access, installation, launch, rearm or reboot occurred.

## Original call sites and branch-safe observers

`build_reveal_operation_stage.py` retains the actual native callback JALRs at
`0x48EC54/74`, their delay slots, original worker SP and return PCs
`0x48EC5C/7C`. No observer frame is held across a native callback. Immutable
BORROW ID from the existing worker `sp+0xAA0` identifies each dispatch; there
is no new native scratch slot, pointer-address registry or current-name lookup.
Source/direct-frame premises remain bounded, not a native lifetime proof.

| Observer source | Raw observation / exact displaced control-flow treatment |
| --- | --- |
| `0x48EC48` | FILL_BEGIN: load original callback once, preserve it, replay branch/delay, then original fill JALR or null path |
| `0x48EC5C` | FILL_RETURN: preserve actual result; replay v1=-1, conditional error branch and original a0 delay |
| `0x48EC68` | POST_TARGET: load original post callback once, replay branch/delay, then original post JALR or null path |
| `0x4A0EE0` | BIND_BEGIN only after exact postfill return ancestry; then existing revision bump and original prologue |
| `0x48F8E4` | BIND_RETURN-tagged postfill epilogue observation, before original s0 restore / SP pop / return |
| `0x48EC7C` | NORMAL_END: observe actual incoming result, then original forced v0=2 and job-state store |
| `0x48EDD4` | ERROR_END: preserve error-report return, then force v0=2, replay displaced common flag store, resume EC84 |

Two branch-target hazards constrain this implementation:

- Native missing-V/P paths enter `0x48F8E4` directly. Patching E0/E4 as an
  ordinary J/NOP pair would skip s0 restoration on those routes. The E4 custom
  epilogue covers them and replays the original stack pop exactly once.
- The fill=-1 path runs `0x467160`, then branches from EDD4 to EC80, bypassing
  NORMAL_END. Since the normal hook also replaces EC80's store, ERROR_END
  explicitly replays that store and continues at EC84, never at the patched NOP.

The BIND_RETURN tag alone does **not** prove a binder ran. Postfill can return
zero with no resolved V and no binding, or return another value on other early
routes. Worker state 2 and wake also occur after failure. The decoder therefore
requires positive call/entry/return evidence, not a zero return or state flag.

At binder entry the original unallocated binder SP is postfill frame F:
live RA must be `0x48F8E0`, saved `F+0x2C` must equal `0x48EC7C`, and worker
SP is `F+0x30`. Only after those gates does the observer read the private worker
borrow carrier. Cached V comes from native stack slot `F+0x20`; P/list are
actual binder argument scalars. Worker s1 remains the exact job across postfill.
Return observation likewise gates live/saved postfill RA before the worker
carrier read. Foreign calls bypass observation but still execute original
native behavior and the existing global bind-entry revision notification.

## Private immutable operation journal

`reveal_operation_journal_mips.py` captures seven event kinds into permanent
private BSS: a 16-byte header followed by 1,024 non-reused 64-byte records by
default. It reads only its own frame, an already-owned seven-scalar wrapper
block, the private lineage ledger and private revision state. No saved native
job/view/list/panel/statement pointer is dereferenced by the core.

Zero BORROW is ignored before metadata access. Nonzero BORROW must validate
privately with exact original worker frame and actual job address. BIND_BEGIN
also checks original numeric P/V equality. These remain consistency checks,
not owner leases. Revision is sampled historical evidence, not frozen mutation
ownership. Allocation is bounded to eight LL/SC attempts; loss, exhaustion,
association failure or private fault permanently faults the journal. Payload
precedes sync/magic-last publication; no reset, reuse or recovery exists.
O32 preserved state and HI/LO survive, including on failure.

Sixteen u32 fields are magic `LOPR`, kind, BORROW ID, sequence, original origin,
actual job, worker SP, source site, actual result, original callback target,
panel, destination, cached view, sampled revision and two zero reserved words.
Kinds are FILL_BEGIN=1, FILL_RETURN=2, POST_TARGET=3, BIND_BEGIN=4,
BIND_RETURN=5, NORMAL_END=6, ERROR_END=7. Callback targets are recorded only
for kinds 1/3; binding scalars only for kind 4; unused fields remain zero.

## Strict offline association, not readiness

`decode_reveal_operation_journal.py` accepts exactly
`lineage-rows-content-revision-operation-journal-v1`: the complete previous
contents-revision snapshot followed by the complete operation journal. Explicit
capacities, fault/reserved state, contiguous magic/sequence publication, unused
slots, source sites, kinds, allowed fields and revision bounds are checked.
Every event must match an immutable original BORROW, not a reused address.
Every BORROW appears in the report, including one with no operation events.

An `observed_callback_sequence_complete` report requires the exact six-kind
sequence 1,2,3,4,5,6, original Files trampoline target `0x48D280`, post target
`0x48F880`, fill not returning -1, binding return zero and matching normal-end
result. It also requires one exact descendant QUERY/PRODUCER, a historically
complete observed row window and binding destination equal to that actual
query/producer destination. Original P/V must match. Duplicates, gaps, a missing
bind or post target, failure, multiple queries/producers and reused histories
cannot acquire this diagnostic association.

The narrow expected entry-revision samples are R, R+1, R+1, R+2, R+3, R+3:
Files entry, postfill entry and binder entry account for those increases.
Producer start must have R+1. Extra known entries reject the sequence, and a
later final counter remains negative evidence, not an owner generation.

**The earlier contents-revision rejection is never relaxed.** Ordinary successful
postfill/bind still leaves the base row window `complete=False` with its original
known-boundary reason, even when callback association is observed. A null post
target has no post/bind entry bump, so its base historical window may remain
complete; the operation is nevertheless incomplete and UI authority stays off.
All top-level/per-operation currentness, capture-coherence and autoscroll flags
remain false. No host `ContentChangeHandle` or `CompletedRows` is constructed.

Already-active writers, stale original jobs starting after reset, missed aliases,
scope/total completeness, native retained lifetime, coherent acquisition and
mutation after capture remain unproved. Query-wrapper finalization is still
uncaptured; native fill/postfill returns are not independent SQL certificates.
This stage records an actual callback relationship, not a successful whole
contents transaction or an exemption from cancellation.

## Saved local candidate and checks

Ignored local intermediate, **not installed or hardware validated**:
`artifacts/hiby_player_1.4_sortfix_fullnav_wake_operation_stage_v1_20261020.bin`.

- Size 7,153,904 bytes; SHA-256
  `be40cecaa6172376f98cd8403477d16f609884347774564d19b7a95f881a49f8`.
- Appended RX code 10,480 bytes at `0xC90000`, file offset `0x6D0000`.
- Private BSS 737,344 bytes at `0xBD4000`; operation journal adds 65,552 bytes
  at `0xC78030`, after the unchanged lineage/row/revision layout.
- Exact saved-file verification passed: 23 hook sites, 22 native tail transfers,
  two strides and declared ELF-header spans; 170 changed original-file bytes.
  Original callback JALRs/delays and selected epilogue anchors remain unchanged.
  Full private extents, RX/RW separation and the native jump region are checked.
- Added RX code's native calls remain the original query/reset and indirect append once.
  No additional query, native getter/lock, UI setter/refresh, export or installer.
  The previous default contents-revision output remains exactly `f4284cb5...603ac`.

All 60 new tests pass: nineteen journal-core, seven source contracts, seventeen
decoder and seventeen emitted-stage/image checks. They cover actual original
JALR instructions and exact RA/SP, generated lineage/row/revision/observer code,
branch/delay/epilogue replay, ABI and HI/LO, error/NULL/missing-bind routes,
same-address distinct BORROWs, capacity/fault/retry loss, strict parsing and
image/region tampering. Native SQL/append/binder bodies remain explicit bounded
stubs, not a real SQL engine or live ownership implementation. Independent
review found no further actionable defect after the branch-target corrections.

Full repository regression: **992 tests pass, no skips** (193.246 s), including
all 60 new checks. All 142 Python scripts compile and tracked/new text files
pass whitespace checks. The full run used local temporary-file access, without
changing legacy tests or invoking a real player transport. Saved-file hashing
and deterministic verification pass; the prior default artifact is unchanged.
These are bounded source/emulator/model checks, not target CPU, cache,
scheduling, native ownership or capture-coherence certification.

No physical trial is requested. The next positive gate still needs original
contents-phase association before mutations, complete writer/overlap coverage
and retained ownership through final publication/action. Observed callback
ancestry supplies evidence for that work, not a reason to enable reveal now.

## Original-entry filter follow-up (2026-10-21)

The separate [origin frontier filter](folderfollow-reveal-origin-frontier-stage.md)
freezes the exact revision returned at original renderer entry and checks it
before additional row-payload capture. An old root crossing a later known
boundary cannot become acceptable merely by starting its producer afterward.
Fresh rendering of an already-stale request and native retained lifetime still
need independent treatment. This observer's default image remains byte-identical;
neither candidate was installed or launched in the follow-up.
