# Host-only negative request-age assessment boundary

2026-10-22. This is an additional assessment of already-owned observations,
not a firmware change, device test or installation proposal. It introduces no
new image builder, native hook, BSS field, counter, allocation or UI action.
The existing renderer-transport format and its strict decoder remain the
source of evidence; a host assessment is appended without changing that
parent format, prior receipts, rows, operations, windows or refusal reasons.
Autoscroll remains disabled and hardware is UNTESTED.

The source reference remains `artifacts/import-20261001/hiby_player_02fd.bin`,
7,133,528 bytes, SHA-256
`02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87`.
`scripts/test_reveal_request_age_contract.py` pins the necessary source and
the existing builder's emitted entry behavior. Its in-memory assembly writes
no firmware file and does not add a new firmware format. Larger callback,
queue, renderer and row source contracts remain separate; this note does not
repeat their global caller/lifetime proof obligations.

## Evidence is associated only by explicit immutable receipts

The already implemented chain is BIRTH/ENQUEUE -> INSTALL/BORROW/HELPER/
CALLBACK -> OUTER -> the actual existing LNRG RENDER root. The renderer root
then parents the existing worker/query/producer/row receipts. Only explicit
published IDs associate these histories. Numeric C/W/V/P/job/frame/descriptor
values do not locate or repair a missing receipt; repeated native addresses
do not merge requests. Missing/duplicate producer RETURN remains incomplete.

Let B be the BIRTH revision sample, O the OUTER revision sample, E the original
renderer-entry ticket frozen into the root, and R the later renderer-association
revision sample. All are historical private diagnostic values, not UI epochs.
The named native path orders these observations as follows:

- OUTER observer `438248` precedes the original child call `438740`.
- The child guarded entry hook `4906F8` precedes root capture `490758`.
- Root capture precedes the later association at `49076C`.

Calls and independently reserved records in different journals do not provide
a universal wall-clock ordering. The source/identity chain justifies the
particular parent-child relations above, not ordering every unrelated event.

## Exactly one own entry increment, and why entry zero is different

The existing emitted `contents_render_entry` wrapper replays the native frame
allocation/save first, calls `contents_bump` exactly once, freezes that call's
own returned ticket at native SP+10, restores native state and resumes at
`490700`. It does not chain through the older entry wrapper or replay the
native prologue twice. The bump's result is its successful reservation's own
historical value even if another invocation advances the counter before it
returns; it is not a later reload of the global counter.

The independent scope check can erase that returned ticket to zero when an
audited scope is active or faulted. A zero ticket therefore means unadmitted
or unknown original entry, not time zero. It must not be used to calculate an
entry gap or to claim that R>0 describes an interval after a known zero entry.
By contrast **BIRTH revision zero is valid**: no instrumented revision may have
been issued when that original queued invocation was observed.

Successful revision values are unique, positive and monotonic through
7FFFFFFF. Exhaustion, malformed state or bounded LL/SC failure permanently
faults the counter and returns zero; values are not masked/wrapped back into
new tickets. Strict parent decoding continues to reject faulted state. Host
arithmetic must not normalize a fault, wrap O+1 or make an unknown E positive.

## Useful refusals, never a passing freshness certificate

For a structurally accepted explicit chain:

| Observation | Bounded negative conclusion |
| --- | --- |
| O>B | At least one known instrumented increment occurred after the birth sample and before the outer sample. |
| E>O+1, with E>0 | In addition to this renderer's one own increment, another known increment occurred before its entry reservation. |
| R>E, with E>0 | A further known increment occurred after that entry reservation and before the later renderer sample. |
| E=0 | The original entry is unknown/unadmitted; no entry-relative interval can be inferred. |
| Active known scope sampled on the relevant chain | The observation overlaps an audited open scope at that sample; quiet/current ownership is not established. |

These are global diagnostic boundaries, not identified writes to this exact
folder/view. A legitimate newly queued request can sit behind another paint;
that earlier renderer's own increment can make O>B for the later one. Such
conservative refusal is allowed. It is not proof that the later request's
specific UI owner or contents were stale, nor proof that its native execution
was incorrect. Naming the report as a freshness pass would overstate it.

E=O+1 and R=E mean only that these particular intervals contain no extra
observed known increments. They do not exclude an earlier open writer, an
unclassified writer or cause, recycled objects, pending work, concurrent free,
opaque callback behavior, capture races or original playback/UI mismatch.
No combination yields `request_freshness_proven`, current owner/contents,
coherent capture, native retention or autoscroll authority.

## RETURN and later operation phases are not pre-render age

The native generic append publishes its new node before returning to producer
`8B42F0`. Another permitted native invocation can consume the queued node
while that producer is paused before its RETURN observer. The RETURN receipt
may consequently be sampled **after** CALLBACK, OUTER and RENDER. Its explicit
parent and actual return-node comparison remain necessary historical evidence,
but its later revision must not be moved into a supposed birth-to-entry window.
Missing RETURN stays incomplete; a complete renderer chain does not invent it.

The ordinary accepted operation has its own later instrumented entries:
worker `48D080` (reached by `48D280`'s direct jump), postfill `48F880` and binder
`4A0EE0`. For the exact observed normal callback sequence beginning at revision
S, existing checks expect `[S, S+1, S+1, S+2, S+3, S+3]`, and the producer freezes
S+1. These known increments occur after the renderer association; a final
counter above E does not locate an earlier queued-age problem. Do not subtract
three from a global counter or exempt old row-window refusals to turn this
pattern into a fresh/current result. Later independent work can also advance
the counter, and incomplete callback histories cannot prove these own steps.

## Native scope and contents revision are not one atomic clock

The reset/reconcile wrapper calls private scope BEGIN before its independent
revision bump and before the remaining native effects. BEGIN atomically raises
issued/active before its slot publication, so even a paused unpublished entry
is already active. There is a real interval where the scope-issued ticket has
advanced but revision has not. Revision and scope are also sampled separately.

On native return, the wrapper bumps revision **before** private scope END
decrements active. Thus a completed revision bump can coexist with an active
scope during close. No fixed equality, multiplier or minimal revision delta
can be imposed on scope-issued changes. Samples of active scopes and changed
issued counts are independent negative evidence, not grounds to repair an
apparently unchanged revision interval. Already-open scopes can also predate
B and leave B=O while still forcing E=0.

Coherent copied acquisition, exhaustive writer coverage and native lifetime
remain independent obligations. This assessment is a host-side explanation
of known refusal evidence only, with the player's behavior untouched.

The subsequent [playback-cause boundary](folderfollow-reveal-playback-cause-boundary.md)
pins a separate blind spot: the player message and selected staged media
record are different channels. Event 9 selects the last record and later
clears the entire staged list, across two separate mutex brackets. A later
coherent playback publication may be identical for different original parents
while UI-counter histories are indistinguishable. Thus these UI samples do
not establish coverage of every playback change or original playback causality.
The new counterexamples do not claim a native playback -> UI event140 edge.
