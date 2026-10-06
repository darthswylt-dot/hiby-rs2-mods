# One-shot current-row reveal: local executable model

2026-10-05. **Host-only preparation, not a firmware fix or a deployable ELF.**
No device access, installation, rearm or reboot in this step. The last hardware
recovery was verified on 2026-10-02; this note does not assert today's live
device state. Source: `scripts/folderfollow_reveal_model.py`.

Local validation: 56 model tests plus 10 hash-gated static contract tests;
the full repository suite passes 249 tests without skips. All 67 Python
scripts compile. Tests do not implement or validate a live firmware adapter.

2026-10-06 continuation: the [216-byte MIPS geometry core](folderfollow-reveal-mips-core.md)
now implements the scalar calculation in emitted instruction bytes. The
[UI/gesture follow-up](folderfollow-reveal-dispatch.md) records concrete serial
activity and gesture bindings; a safe live adapter is still not established.

## Implemented behavior

Inputs are immutable, owned snapshots, with externally established playback
identity and non-reused view/content/manual-input generations. Those live
contracts are prerequisites, not facts established by this Python model.

- First valid playback sample establishes a baseline without moving the list.
- A different exact `(path, signed cue)` needs two consecutive equal samples.
  Returning to the committed identity before confirmation does not scroll.
  Repeated equality filters jitter; it does not make a concurrent read atomic.
- Changes are observed even outside Files. A change first seen in an inactive
  or different folder is consumed, without a deferred jump on later return.
- Only the already active playback folder is eligible. This model performs no
  navigation and does not implement cross-folder following or root descent.
- A new manual-input epoch, navigation/view change or content-generation
  change cancels a pending reveal, including before identity confirmation.
  An explicit `manual_active` input also blocks a new reveal during an ongoing
  gesture/settling interval; an unchanged epoch or offset does not mean input
  has ended. Unknown/non-boolean activity fails closed. The adapter still
  needs to supply this state from a verified gesture lifecycle.
- A confirmed transition may wait for ready rows for a bounded budget (default
  eight observations, not a measured wall-clock deadline). It expires rather
  than resurfacing later. Missing/invalid ready targets consume the attempt.
- After finding a unique exact row, calculate the minimum movement needed to
  show the whole row. Already-visible rows consume the change without moving.
  The model emits at most one proposal, never a repeated snap-back each tick.
- `validate_action` models a final check of identity, generation, full copied
  row map, geometry and manual-input epoch. Rejecting a proposal consumes it.
  This check is **not** a lock, safe executor or permission to retain live
  pointers. The actual setter/refresh still needs one owned UI transaction.

Initial map scope is deliberately a complete, zero-offset mode-zero fill of
at most 512 rows. `CompletedRows.from_fill` requires explicit terminal 101,
initial count zero, append results 0..N-1, actual final count N, same-generation
total N, valid copied identities and no duplicate identities. Callers must
already have validated one non-interleaved, loss-free producer session. This
is not a parser or validator for arbitrary FILL logs, and separate hardware
runs must never be joined to manufacture a current generation.

The lower-level `CompletedRows` constructor only validates representation;
neither constructor proves that a fill is still the current live list.

## Geometry examples and limits

For 13 rows, pitch 80 and viewport height 260:

| Target row (zero-based) | Starting y | Proposed y |
| --- | --- | --- |
| 2, already completely visible | 0 | 0 (no action) |
| 3, partly below viewport | 0 | 60 |
| 5, offscreen | 0 | 220 |
| 12, last row | 0 | 780 |
| 0, above viewport | 220 | 0 |

These are model calculations using dimensions observed on hardware, not
measured results of a new patch. In Sleep, a directory precedes the music;
cue 0 resolves to row 1, not row 0. Path prefixes and case folding cannot
substitute for exact identity. Signed cue values remain distinct.

Bounds are `0..max(0, count*pitch-height)`, with signed-32-bit overflow checks.
Reject invalid/zero pitch or height, rows outside count, rows taller than the
viewport and existing offsets outside the bounds. Do not normalize transient
negative manual overscroll (observed down to -28), use raw C+0x20 as an extent,
or assume that the setter clamps the observed flags=2 case.

## Corrected static contracts

Verified against recovered firmware SHA-256
`02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87`.

P is the Files cache owner; L is the primary list. The diagnostic wire name
`cache_count` is retained for compatibility, but its actual meaning is total:

| Field | Role | Writer/helper |
| --- | --- | --- |
| P+0x1E0 | Total folder count, published before fill | 0x4A07E0 via P+0x400 |
| P+0x1DC | Window start | 0x4A0800 via P+0x404 |
| P+0x1E4 | Requested window length | 0x4A0820 via P+0x408 |
| P+0x1D4 | Modulo capacity | 0x4A0840 via P+0x40C |
| L+0x0C | Actual populated primary-list count | 0x455DC0 getter |

Constructor 0x4A08E0 installs these four callbacks at 0x4A0928/934/940/94C.
0x495140 calls 0x6F76E0; 0x49514C..158 publishes its total before the fill at
0x49519C. Actual list count is read at 0x4951A4. Total=13 or 7 in telemetry
is not a completion certificate.

Do not interchange row-reader argument orders:
`0x4994E0(V,out,index)` versus `0x4327C0(folder,index,out)`. Their zero result
alone does not establish populated output. Primary slots require capacity,
start, actual population and modulo checks; extra descriptors carry a trailing
absolute index at +0xA88 that is absent from the ordinary 0xA88-byte copy.
Neither helper is now being called from a timer.

Playback property getter `0x42AD60(24,dst,NULL)` copies **0xA88 bytes** from
0xADD468 at 0x42B048..05C; path is descriptor+4, cue is +0x424. Never pass
a path-sized buffer. Source callbacks around the getter do not by themselves
prove atomicity against direct playback commits 0x42CBDC/0x42CD5C.

## Integration leads, not implemented claims

Timer-10 interception at 0x4EAEBC/0x4EAECC can run original 0x4E90C0 once,
preserve its return/ABI, and then resolve active view via 0x4E5680. No raw
view or cache pointer should be retained across ticks. The playing-plane
teardown clears its global and removes timer 10 before freeing children,
but that does not prove every current-view lifetime or reentrancy condition.

The audited setter/refresh pair is
`0x8B43C0(C,&{x,y},0,0x20002)` then `0x490D00(U,exact_active_name)`.
The latter resolves the view again and can refill through 0x499C20. Do not
use the generic library helper 0x490E20 with Files' empty lookup key, synthesize
manual gestures, hijack timer 20 or call the setter from a fill worker.

Movement entry 0x49B000 cancels the stock timer 20 before the inspected manual
movement path; it is a candidate pending-reveal cancellation hook, not proven
coverage of all manual intent. The two measured setter callers are later
movement evidence, not enough by themselves to cover every gesture/navigation.

Use a separate reveal-only wrapper on normalized golden for an initial future
candidate, or explicitly redesign both policies together. Do not append this
policy behind active-folder-rebuild unconditionally: its shared property-11
marker can be cleared by navigation and does not ensure manual-browsing safety.
Such a separate candidate would not include active-folder-follow behavior;
the two features must not be silently conflated or one called a replacement.

## Remaining barrier before producing firmware

A complete copied producer map still needs an active-generation ownership
contract through reveal. Lists can be cleared/refilled in place or destroyed,
and metadata is updated after some refills. Raw getter 0x4557E0 does not pin
rows. An unchanged pointer/count or generation recheck cannot prevent reuse
or a mutation immediately after the check. The visible-row callback exposes
a local descriptor/index but cannot discover an arbitrary offscreen row.

The [bounded ownership audit](folderfollow-reveal-ownership.md) now confirms
a separate Files fill worker and a teardown ordering that makes a bare
`resolve V -> read T -> lock T+0x10` unsafe to assume. Its mutex is destroyed
before the view is removed from the registry. Consequently, even keeping the
registry lock does not by itself retain T. Generation counters alone cannot
repair this lifetime gap. Next work must identify an owner-serialized UI hook
or a valid retention mechanism before taking the worker mutex, then establish
all scope/mutation invalidation and manual-input coverage. No firmware
writer/installer is provided by the model; no extra manual-scroll run is
needed merely to repeat the earlier positive control.
