# Reveal coordinator: cancellation and playback publication

2026-10-13. **Host-only implementation; not an installable firmware or a live
UI adapter.** This step follows the successful passive
[October 12 manual-scroll/highlight/volume test](folderfollow-reveal-interactive-20261012.md).
That test did not enable or establish autoscroll. No player access, new binary,
installation, launch, rearm or reboot occurred in this step.

## Implemented boundary

`scripts/folderfollow_reveal_coordinator.py` connects the existing copied-row
publication and one-shot reveal policy to new
`scripts/folderfollow_reveal_playback.py`. Inputs are coherent, already-owned
values supplied in serialized event order. Providing those inputs from real
stock threads is a remaining requirement, not an effect of this code.

Playback BEGIN withdraws readiness and advances a bounded, non-reused revision
before mutation. END must match its outstanding ticket. Same-value writes,
clear/restore and A-to-B-to-A sequences cannot validate a proposal from before
the write. Overlapping writers, late/duplicate completion, missing events and
revision exhaustion disable publication permanently for that instance. A
completed `None` means a real clear; a not-ready `None` is a transient gap.
The latter does not erase the prior track baseline on an ordinary Next.

The coordinator supplies abstract view/content generations and identity-bound
handles for this model. Reopening the same path creates a different owner;
refilling or sorting the same owner requires a new content generation BEFORE
mutation. A worker's late result retains its original fill handle, never the
currently active generation. Row publication still requires the complete
bounded map, explicit terminal 101, successful append ordinals and matching
total/final counts. An old pointer, equal folder name or a post-fill callback
cannot create this authority.

Manual input starts unknown, not idle. Recognized contact, animation or an
unsettled gesture prevents reveal. Every interaction change consumes pending
work, including a track publication not yet observed by the reveal policy.
A fence captured at playback BEGIN also consumes the transition if a gesture
or lifecycle change occurs before END, even if the final values look unchanged.
A gesture finished before a later track BEGIN does not suppress that later
transition. Unknown input or lost-event coverage disables the instance.

Each proposal is usable once, in the issuing instance, until the next
observation or invalidating event. Consumption checks the exact issued object,
current owner, playback readiness/revision, cancellation fence, copied rows,
manual state and fresh geometry. Rejection also consumes it. Returning an
`Action` is **not** retaining a stock object or executing a setter; the eventual
adapter must preserve an owned transaction through both setter and refresh.

## Regression found during independent review

After owner/content reset, the policy had no previous observation context.
If B was published but not observed, a complete manual gesture could fail to
cancel it: there was no candidate yet, and the later first observation could
start a fresh reveal. The fix consumes the current ready playback baseline
on interaction changes and fences in-flight publication against intervening
events. Tests cover both orders, observations omitted during the gesture,
contact already active at BEGIN, and owner/content changes during a write.
Malformed geometry on a ready observation also consumes an unobserved change.

The tests include CUE values different from row ordinals, same-file track
changes, stationary contact, inertia, stale/copied/foreign handles, ABA,
actual clears, failed/duplicate fills, bounded readiness waits, one-use
rejection and non-wrapping counters. The 13-CUE/80-pixel/260-pixel geometry
fixture uses measured dimensions, not an assertion of live ownership.

## What the static follow-up establishes

Two hash-gated contract suites inspect the exact preserved `02fd...` reference:

- [Playback boundary](folderfollow-reveal-playback-boundary.md): preparation
  can clear the path before the general copy; shutdown can clear the whole
  descriptor; a general caller can use the destination as its own source.
  The potential scalar cue setter is distinguished from observed/directly
  identified use. The three existing copy hooks do not cover all invalidation
  or prove coherent source ownership.
- [UI owner boundary](folderfollow-reveal-ui-owner-boundary.md): a deferred
  close consumer runs before the timer, but there is also a synchronous
  close facade, including an identified Files navigation call. Its record
  lookup releases the lock before callback use. The timer inherits neither
  a retained Files owner nor the controller's earlier mutex bracket.

These findings constrain implementation; they do not establish runtime
thread identity or eliminate indirect callers.

## Next live-integration gates

Validation for this step: **530 repository tests pass, no skips** (79.502 s),
including 40 coordinator/cancellation tests, 20 playback-publication tests and
21 new playback/UI-owner static-contract tests. All **91 Python scripts
compile**. Independent review exercised the cancellation orderings; the six
valid writer/gesture orders with and without content reset are now retained
as twelve regression cases. Tracked and new files pass whitespace checks.
These results establish the host protocol only, not stock concurrency.

1. Cover all relevant playback mutation/clear entries with a coherent copied
   identity protocol. Overlap/loss must revoke, not publish a plausible value.
   An aliased source and nested preparation clear need explicit treatment;
   simply counting the existing three memcpy pairs is insufficient.
2. Establish lifecycle invalidation before create/rebind, teardown and reset,
   plus worker/list mutations. Classify relevant synchronous-close and direct
   lifecycle callers against a real retained UI ownership contract. Model
   epochs are not stock lifetime tokens.
3. Carry validated full-row publication and complete recognized interaction
   state to that owner, with a checked lock order. Execute one reveal in the
   same ownership boundary as its final checks and refresh. No timer lookup
   followed by an unretained worker lock is justified by this step.

Only after these gates are implemented and reviewed should a separate active
candidate be built. No additional manual-scroll test is requested now.
For any future authorized run: give instructions, end the turn and await a
fresh explicit readiness confirmation, launch once, then stop until the user
reports completion. Do not automatically rearm or extend the watchdog.

Later 2026-10-13: the first [MIPS mutation-guard stage](folderfollow-reveal-guard-stage.md)
has been connected to nine known stock mutation sites in a separately verified
intermediate ELF. It does not port/enable this complete coordinator or close
the active UI gate. New repeat-copy and pointer-escape findings are recorded
there; the no-binary statement above describes this earlier host-only step.

## Deferred whole-update publication (2026-10-14)

The additional `begin_update` / `finish_update` API keeps final identity unknown
until a complete logical update ends. Its intermediate preparation clear and
repeat copies never become independent completed clears; the prior policy
baseline survives the in-flight gap. The adapter must prove that those writes
belong to this particular invocation and supply a coherent owned FINAL value.
Nested BEGINs are still a permanent protocol fault, not implicit grouping.

The coordinator's `playback_update_begin` / `playback_update_finish` pair also
requires an explicit boolean stock-success outcome. A failed update consumes
the actual final value as baseline without revealing it; it does not pretend
the descriptor rolled back or prevent a later new successful transition.
Unknown outcome, malformed final identity, mismatched completion mode and
duplicate/stale completion permanently disable publication. Final `None` is
an actual completed clear; intermediate unknown state remains not-ready.

Seventeen added tests cover these semantics and all six valid writer/gesture
orders, navigation/refill/close while final identity is unknown, mode mixing,
source copying, invalid input, overlap and exhaustion. The focused total is
77 tests (28 publication and 49 coordinator/cancellation). Independent review
also exercised 7,776 five-event sequences without finding an invariant failure.
These are host-model checks, not stock scheduling or cross-thread ownership.
The separate [grouped MIPS stage](folderfollow-reveal-grouped-stage.md) records
operation completion only; it does not provide the final identity this API needs.
