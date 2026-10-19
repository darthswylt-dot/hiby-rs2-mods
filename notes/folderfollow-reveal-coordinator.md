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
refilling or sorting the same owner requires revoking the old content generation
BEFORE mutation. The two-phase API below withholds a replacement until verified
completion. A worker's late result retains its original fill handle, never the
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

## Two-phase contents revocation (2026-10-16)

The read-only [Show No Mercy observation](folderfollow-reveal-worker-lifecycle-boundary.md)
found mode 0 and private-worker-shaped state in two registered explorer levels.
This narrows the observed route; it does not supply a retained object or prove
that mode is immutable. No further device access or firmware change is made
in the present implementation step.

`RevealCoordinator` now separates **revocation before mutation** from
**generation publication after verified completion**:

1. `begin_contents_change(view)` immediately revokes rows, fill handles,
   pending policy work and issued proposals. It returns an identity-bound,
   immutable `ContentChangeHandle`, retaining only the abstract host owner.
   `generation` and `rows` are both absent throughout the change; observation
   returns `await-contents-publication`. Neither a new fill nor an old callback
   can publish against this gap.
2. `finish_contents_change(handle, folder, succeeded=...)` accepts only the
   outstanding exact handle. Verified success issues a fresh non-reused
   content generation, but **not ready rows unless matching validated staging
   is available** (the later extension below). Failure or invalid final scope
   deactivates the host owner; unknown outcome disables the instance. Close
   and activation of another owner cancel the phase; its late completion is
   ignored and cannot reopen or corrupt the newer owner.

Playback/gesture events during the gap are consumed as baseline, including
transitions whose BEGIN/END straddle either boundary. A later new track change
after successful completion and full row publication still works. Overlapping
contents BEGINs and mixing legacy `replace_contents` into an open phase are
protocol faults. The original single-boundary API remains for serialized,
already-owned inputs; it is not an in-flight stock reset protocol.

Important bridge obligation: a stock fill may occur **inside** reset/rebind,
before contents END. Its copied rows need separate bounded staging tied to
the original operation/owner, or another independently proved full fill.
The ordinary `begin_fill` deliberately cannot run while generation is absent.
The later extension below adds private host staging; neither API discovers
stock job ownership, marshals threads, or turns a callback's return into
verified completion. Relabelling a late job with the generation current at
END remains forbidden.

### Source-backed revocation leads, not emitted hooks

At destructor `0x493B0C`, a null guard has established `a0=s0=V`; the original
`0x4B8`-byte frame and saved return address already exist. Its eight bytes
`24020001 / AE020044` set the closing marker. A future bridge could revoke its
own state **before** replaying those words and resuming `0x493B14`, without
reading V/T/R/C to perform revocation. Before that pair the only call clears
a local stack buffer; after it, view-field reads and cleanup begin immediately.
Waiting until private stop `0x493BF4` is therefore too late for this purpose.
This is a proposed event boundary, not lifetime acquisition or a stock-worker
repair. Register preservation and serialized delivery remain unimplemented.

Reset/refill also needs earlier boundaries independent of destruction:

| Inspected boundary | Why revocation cannot wait until later binding |
| --- | --- |
| `0x491240(U,V)` | Reads/frees old lists starting `0x491260/26C` |
| `0x4919E0(U,old path,target)` | Changes scope at `0x491AD4/1D54` before common frees |
| `0x494A00(U,name)` | Resolves V then frees at `0x494A4C/A64`; exact explorer producer still unproved |
| `0x4906E0(W,context,request)` | Changes template/binding before enqueue lock; guarded linear entry is `0x4906F8` |
| `0x48D080(T,job)` | Files worker clears lists at `0x48D120/170` before refill |
| `0x48F880(T,job)` | Post-fill name resolution/binding is already too late to revoke earlier list changes |
| `0x4A0EE0(P,new list,window...)` | Binding store `0x4A0F2C` cannot replace revocation before reset/free |

`0x4906E0` starts with a PC-relative branch, not a simple relocatable
prologue; blindly copying its first eight bytes into a cave is incorrect.
The original two words at guarded `0x4906F8` are `27BDFFD0 / AFBF002C`.
No such trampoline or any other lifecycle hook is emitted in this step.

These are a **minimum inspected surface**, not all writer/alias coverage.
Some boundaries nest within one stock operation. A bridge must prove that
relationship before grouping them, rather than submitting overlapping host
BEGINs or skipping invalidation. Opaque raw pointer tokens alone cannot
identify a non-reused owner. The ordinary synchronous input/deferred-close
ordering remains limited to the already audited loop invocation; arbitrary
callers cannot directly call this sequential model without a handoff protocol.

The new `test_folderfollow_reveal_lifecycle.py` has 18 host tests, including
all six valid playback/contents boundary orders, stale/forged handles, close,
same-path reuse, error/exhaustion, gestures and a later successful reveal.
`test_folderfollow_reveal_lifecycle_contract.py` adds six hash-pinned source
contracts. Independent implementation review found no actionable host defect.
The reveal-focused run passed 349 tests; the six added source contracts passed
separately (355 total). This is not a device or runtime concurrency test.

## Operation-bound staged rows (2026-10-16)

The coordinator can now retain **private, bounded copies** from one fill
inside an outstanding contents change. It does not publish the staged
generation or rows through its public properties before contents END.

`begin_staged_fill(change, folder, ...)` requires the exact active
`ContentChangeHandle` and permits only one attempt per phase. It issues an
identity-bound `StagedFillHandle` carrying that change, a private generation
and a non-reused ticket. The bridge must associate this handle with the
original producer **before its mutations**; a current view name, folder,
list address or callback-time lookup cannot admit an older job.

`append_staged`, `terminal_staged` and `finish_staged_fill` reuse a separate
persistent `RowPublication`. Its private tickets/epochs survive cancellation,
close and owner replacement; the collector is not recreated each phase.
The original checks remain: at most 512 unique copied identities, exact
ordinal/append/count agreement, complete zero-offset mode-zero fill, and
explicit terminal 101 before fill completion. Empty completed fills are
valid; signed CUE values remain identities, not row ordinals.

Staging additionally requires `identity.folder() == captured folder` exactly.
This first supported shape excludes nested/other-folder rows, wildcard-leaf
identities and case/prefix reinterpretation; it is not support for every
directory-row encoding. Exact parent matching narrows mixed-scope mistakes
but still cannot prove a worker's actual query/destination association.
`finish_staged_fill` returns only a boolean, never a ready snapshot.

On successful contents END, current phase/owner, exact final folder, complete
staged receipt and absence of faults are checked **again**. The coordinator
then issues the fresh public generation and replays the already validated
copied rows through the ordinary publication validator. The internal replay
represents accepted original append/terminal/end facts, not a new database
query or newly invented SQL completion evidence. It consumes that generation's
single-fill allowance and preserves ordinary ticket bookkeeping; a subsequent
ordinary `begin_fill` for the same generation is rejected, not a second fill.
The bounded transfer has no callbacks or externally observable intermediate
ready state under the model's serialized-call assumption. Failure disables
publication rather than exposing a partial transfer.

A duplicate/extra append, terminal or fill END for the still-current promoted
producer revokes public rows and issued proposals. Its exact stage handle is
therefore retained after promotion. Once a new phase, owner, reset or close
cancels it, those old callbacks are harmless stale events instead. A second
staged BEGIN, malformed current event, or `invalidate_staged_fill(change)`
after another mutation poisons the stage; success END cannot silently fall
back to generation-only publication. A failed stock outcome discards staging
and deactivates the owner; an unknown outcome disables the instance.
For compatibility, invalid final-folder representation also deactivates
without a permanent fault; a different **valid** final folder is a fatal
scope mismatch. Both paths withhold rows/generation and consume the phase.
No-staging-requested END retains the earlier generation-only behavior.

The bridge must report every relevant later mutation, including changes
after a staged fill completed but before contents END. It must still establish
the actual producer/operation/owner/query/destination relationship, admit
nested writes correctly, serialize events, report uncertainty/loss and retain
the real UI objects through the final action. The model cannot detect an
omitted event or a coherent-looking falsely associated producer. No firmware
hook, cross-thread mailbox, memory fence, live pointer reader or UI call is
introduced here; active reveal remains disabled.

The follow-up [native provenance audit](folderfollow-reveal-provenance.md)
separates initial Files loading from copied renderer jobs and pins how the
physical-folder query passes its original destination/window/scope to the
producer. This narrows the bridge's capture points without implementing
native token transport or turning a callback-time lookup into authority.

`test_folderfollow_reveal_staging.py` adds 26 tests for these boundaries,
including old ordinary producers predating the phase, same-folder reuse,
copies/forgeries, 0/512 rows, source copying, current-versus-stale duplicates,
mutation/loss, counters, failed/unknown completion, playback/gesture overlap
and a later successful transition. All 143 focused host checks passed
(26 staging, 49 coordinator, 18 lifecycle, 22 row publication, 28 playback).
Independent review found no readiness or handle-fencing bypass. No player
access, firmware/artifact build, install, launch or reboot in this step.

### Native transport follow-up (2026-10-19)

The separate [lineage-only intermediate](folderfollow-reveal-lineage-stage.md)
now carries original invocation IDs through actual native master/work copies
and distinct borrow/query/producer receipts. It never calls this host API,
publishes ready rows or treats its numeric original V/P as a retained native
owner. The coordinator's contents-change handle still needs independent native
operation/epoch association and complete invalidation before live staged input
can be admitted. No active autoscroll or player installation was enabled.
