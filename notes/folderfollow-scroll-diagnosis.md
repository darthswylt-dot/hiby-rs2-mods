# Offscreen highlight: diagnosis and measured scroll path

Update 2026-10-02: the [paired MOVE controls](folderfollow-move-manual-control-20261002.md)
close the previously missing positive setter observation. Next advanced
cue 0→5 without a setter or y change; manual-only input produced 79 nonzero
relative setters, every one moving the matching Files viewport, with clean
final accounting. This directly supports a missing reveal request on the
observed Next path, not a rejected nonzero request. Safe row targeting and
patch placement remain implementation work; no fix is installed.

2026-09-30. Read-only analysis of closed local captures and source code.
No new firmware, deployment, device access, commit or push.

## Finding

### Unmodified-stock comparison (2026-10-01)

The user reproduced the same visible behavior on the original firmware 1.4
executable, SHA-256 `0fedb30f91937eafb5baaf3c75422cdbde04a62fe8bac8eca3c7a88bb761da0e`,
verified live as PID 116 before the test; the one-shot test flag was absent.
Starting at the top of the Show No Mercy list and advancing with physical Next
to a track below the visible rows did not scroll the list. Manually scrolling
revealed the highlighted playing track; volume remained responsive.

This closes the previously missing bare-stock comparison: the symptom does
not require the sorting/traversal/wake changes or folder-follow instrumentation.
It does not identify the exact missing request or prove the absence of every
offset-setter call. The earlier MOVE reboot and full live collector/launcher
validation remain separate unresolved issues; later stock-only byte controls
for the [legacy transport](folderfollow-move-legacy-collector.md) passed.

At the original 2026-09-30 analysis, the defect was a persistent mismatch between playback/highlight and viewport
position, not simply a brief visual delay. The strongest current hypothesis
is a missing or ineffective request to reveal the playing row. The exact
cause was unresolved: neither then-existing capture recorded the original
offset-setter calls or requested values. The subsequent MOVE comparison above
now distinguishes absence of an observed Next-path request from a rejected
nonzero request, with the stated scope limits.

## New quantitative check of SCRL

The closed SCRL capture has 2,868 records, SHA-256
`e125d243d67dd4e3409aad9b8c572bb9b25625aebeec1c136899b3e42eda1423`.
The deep Slayer interval contains 821 samples. Across those samples there
is one observed tuple of controller/view/render/cache-owner addresses,
folder, playback file, pitch, height, cache capacity/start/count. Pitch is
80 and viewport height 260. No cue-before/cue-after mismatch appears.

At zero-based records **1347..1543** (197 consecutive, unfiltered samples),
cue 5 remains playing with content y=0. The timestamps span **25.079197579
seconds** (186.041742061 to 211.120939640 in the capture clock). Subsequent
samples with cue 5 show manual movement through y=33,52,74,...,330.
The unchanged sampled addresses do not exclude object reuse or intermediate
changes; matching cue brackets do not make the snapshot atomic. Nevertheless,
the recorded persistence and the user's manual-scroll observation rule out
describing this incident merely as a short refresh delay.

Do not infer the current row index from cue alone. The independent FILL run
has ten accepted fills and 65/65 drained events. Its Slayer list has cue
0..12 at rows 0..12, but Sleep has a covers entry first and cue 0 at row 1.
These establish ordering for that run only. SCRL and FILL were separate
process runs; their pointers and timelines must not be joined.

## Why a row refresh alone is not a demonstrated fix

At `0x499CB4..CE8`, `0x499C20` reads current height, pitch and content y,
then calculates height/pitch and y/pitch. At `0x499D18`, it adds the visible
slot to the calculated first row and fetches that row at `0x499D44`.
The inspected logic therefore follows the existing viewport, not a supplied
playing-row target. A direct-call scan of `0x499C20..0x49A160` contains no
call to `0x8B43C0`; this is not a transitive side-effect proof for every
callee. Forcing more refreshes is not evidence that content y will change.

The [dispatch investigation](folderfollow-refresh-dispatch.md) identified
both initialization/render-completion and delayed ID-20 refresh routes.
V+0x8C is a gate in the former, not a universal refresh flag. Forcing it to
one, borrowing timer ID 20, writing C's extent, or calling a gesture handler
would introduce behavior rather than diagnose which original route ran.

## Minimum discriminating passive capture

The next hardware observation requires a separately created and authorized
diagnostic build; the missing fields cannot be decoded from unused zeros in
SCRL or FILL. Capture original execution, not extra calls:

| Observation | What it distinguishes |
| --- | --- |
| Content-y setter entry/exit: caller, C, request mode, requested y, old/new y, C+0x3C, parent | No request vs no-op/clamp/failure vs successful offset mutation |
| Original row-refresh entry: caller, V, C, pitch, y, height | Initial-render vs explicit vs deferred refresh at a particular viewport |
| Timer-20 arm/reset/cancel/fire; V selected when firing | Whether manual input cancellation/defer behavior actually occurred |
| Periodic current view + playback path/cue and offset | Correlate track changes and detect a later offset reset, without retaining pointers |

Interpret only a complete, scoped, loss-accounted capture. A zero setter
return is not proof of movement, and "no event" is not proof of no call if
the scope filter rejected it or the buffer overflowed. An offset change
followed by a later reset requires finding that later writer, not assuming
the first setter failed. If setters never receive a changed target on Next
but work during manual input, the missing reveal-request hypothesis gains
direct support. If y changes but the visible rows do not, investigate refresh
and drawing instead.

### Probe-site audit, not an implementation

- Generic setter entry `0x8B43C0` starts with `27BDFFD0 AFBF002C`
  (48-byte frame, saved return address). It is shared by other widgets and
  request modes. Scope and event-volume controls are required; a global
  unfiltered probe would not be an appropriate default.
- Manual route call `0x4BA5F4` has delay-slot `AFA3001C` (store to caller
  stack); `0x4BA674` has `24E70002` (finish request mode). These slots must
  execute exactly once in any later wrapper. Instrumenting only these two
  calls cannot establish the absence of other content-y writers on Next.
- `0x499CB4..CBC` reads C+0x10, V+0x4C and C+0x18 immediately before
  division. This is a compact place to observe the original refresh inputs,
  without asking the database for additional rows.
- Refresh calls `0x49A1F8` and `0x490920` have different delay slots and
  different argument provenance. Their return addresses distinguish the
  timer and render-completion routes at a common refresh-entry probe.

Producer probes should use bounded memory-only records, explicit loss and
publication accounting, and no extra SQL, rendering, allocation or file I/O.
Drain through the previously audited UI callback, with a versioned stream
and fail-closed decoder. Adding a new callback, asynchronous reader of saved
pointers, or reusing FILL's format unchanged is not justified by this audit.
Exact buffering, entry/exit pairing, register/HI/LO preservation and lifetime
assumptions still need implementation-time review and offline tests.

## Reproduce the evidence

The new script verifies both closed-capture hashes before analysis and keeps
the runs separate. It asserts timestamp order, the contiguous stationary
cue-5 interval, accepted fills, and drained event counts; it makes no device
connection and writes no firmware.

```text
python scripts/diagnose_folderfollow_scroll_capture.py artifacts/scroll_diag_final_20260929.bin artifacts/fill_diag_final_20260930.bin
python scripts/check_folderfollow_scroll_route.py E:\platform-tools\hiby_player_02fd.bin
python scripts/check_folderfollow_refresh_dispatch.py E:\platform-tools\hiby_player_02fd.bin
```
