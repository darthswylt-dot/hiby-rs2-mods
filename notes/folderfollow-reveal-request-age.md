# Host-only reject-only request-age report

Local follow-up, 2026-10-22. No firmware change, new image, native hook, BSS
layout, allocation, payload-read policy or UI behavior is introduced here.
No player connection, install, launch, signal, reboot or rearm. Existing
renderer-transport artifacts and their hashes remain unchanged. Changes are
local/uncommitted; scrolling stays disabled and hardware is UNTESTED.

The explicit [renderer/root/row association](folderfollow-reveal-renderer-transport-stage.md)
now has a read-only host assessment of **known global interference**. This is
not a request freshness certificate or a native runtime gate. It is entirely
separate from the host coordinator's model owner/content-generation handles;
a queued-paint receipt cannot manufacture those handles, rearm a proposal or
mutate/cancel another current model owner by raw native address.

## Public interface and unchanged evidence

`scripts/decode_reveal_request_age.py` accepts only the same already-owned raw
snapshot and seven explicit capacities as the strict renderer decoder. It
first runs that existing decoder. Malformed headers, unpublished records,
ancestry, counters, unknown layouts and dirty tails still fail there before
assessment. Decoded dictionaries are not accepted as public input.

The parent `lineage-rows-renderer-transport-v1` format, rows, receipts,
operations, windows, completeness fields, limitations and refusal reasons are
unchanged. The sole additional top-level key is `request_age_assessment`, with
nested format `request-age-rejection-v1`. All observations are recomputed by
following canonical explicit event/root IDs, not mutable summary timing fields
or V/P/job/frame/name/metadata equality. Input bytes and parent structures are
not modified.

Every assessment and every request has `decision="deny"`; all five existing
current-owner, contents-current, coherent-capture, request-freshness and
autoscroll-authority flags stay false. `status="rejected"` reports specific
negative/unsupported/incomplete evidence. `status="unproven"` means only that
these particular negative tests found no additional conflict. **Neither status
permits a native action.** Unassociated roots/births/outer invocations are
listed separately; an empty report never proves complete coverage.

## Only source-justified causal intervals

The main sampled path is explicit BIRTH -> ENQUEUE -> INSTALL -> BORROW ->
HELPER -> CALLBACK -> OUTER. A positive revision advance anywhere on this
particular path is known global boundary evidence before the outer sample.
Reservation order across unrelated requests is not a global clock; each chain
is assessed independently, including when later-reserved births carry lower
revision values than unrelated earlier slots.

Let B be the BIRTH sample, O the OUTER sample, E the frozen original renderer
entry ticket and R the later renderer-association sample. The source contract
proves exactly one own increment between O and a valid positive E. Thus:

- O>B identifies observed global interference before the outer sample.
- E>O+1 identifies additional known increments beyond that one own entry.
- R>E identifies additional increments during the early renderer interval,
  but only when E is positive and source-consistent.

E=0 is unknown/unadmitted, **not time zero**: entry-relative metrics are null.
A positive E<=O is source-inconsistent and refused; it is not used to invent
an early-body increment either. Arithmetic is nonwrapping: MAX-1 -> MAX is the
last valid own step, and OUTER=MAX cannot wrap O+1 into a new valid ticket.
See the pinned [source and emitted-code boundary](folderfollow-reveal-request-age-boundary.md).

The older literal `known_boundary_unchanged` field is not modified. The new
arithmetic locates negative evidence; subtracting the one known entry step
does not turn any earlier equality/currentness refusal into acceptance.

## Global interference is deliberately conservative

Executed native-boundary fixtures demonstrate the distinction:

| Queued history | B | O | E | R | Host age status |
| --- | ---: | ---: | ---: | ---: | --- |
| Uninterrupted request/renderer | 0 | 0 | 1 | 1 | Unproven; no authority |
| Request queued before actual reset | 0 | 2 | 3 | 3 | Rejected; pre-outer known increment |
| New request after reset, behind the reset's pending paint | 2 | 3 | 4 | 4 | Rejected conservatively; earlier renderer advanced the global counter |
| New request after prior paint drained | 3 | 3 | 4 | 4 | Unproven; no authority |

The third case is not proof that the new request's particular view/list was
stale or incorrect. The counter covers multiple known entry attempts; it does
not identify a write to this specific owner. Conversely, matching interval
steps cannot exclude already-open or unclassified writers, native lifetime
races, an original playback/UI mismatch or an incoherent external capture.

## Separate scope observations and unordered branches

Packed scope samples are assessed independently. Scope-issued advance is
additional global negative evidence even if REV did not change; an active
known scope is a separate unadmitted-context reason. The two fields are loaded
separately, and scope BEGIN becomes visible before its independent revision
bump. Quiet samples with increased issued count and equal REV are permitted
observations, not malformed input and not grounds for inventing an atomic
clock relation. A later scope close never erases an earlier active sample.
Final non-quiet/partial scope state is a snapshot-level refusal, not a newly
invented overlap before the renderer.

Producer RETURN is a **separate branch**, not part of the main time path. It
may be recorded after the consumer/root already ran. Missing/duplicated/wrong
RETURN keeps observation incomplete; a late higher RETURN revision or scope
ticket does not become pre-render age evidence. Its samples are reported
separately for transparency, without relocation into the causal path.

Likewise the final global counter can advance through normal later worker,
postfill and bind entries (the existing accepted operation has its own +3),
or other independent work. `later_revision_advance` is informational only.
Those increments are not moved backwards, subtracted from the final counter
to manufacture an epoch, or used to relax old row/frontier/scope refusals.

The separate [playback-cause counterexamples](folderfollow-reveal-playback-cause-boundary.md)
also expose the missing proof that these UI samples cover every playback change.
Player event order and a coherent later publication cannot recover an absent
original playback parent. The older playback guard is not composed/sampled
by this image. One additional explanatory limitation now states this clock-
domain gap in the report; its algorithm, format and deny-only gates are unchanged.

## Verification and remaining work

All 59 focused checks pass (1.335 s): 21 native-fixture/public-API integration
checks, 28 adversarial arithmetic/causality/input cases, and 10 pinned
source/emission/counter-contract checks. They include actual reset histories,
before/after-entry boundary injections, active then closed scopes, ordinary
later +3 and unrelated later increments, consumer before RETURN, ABA reuse,
same-REV/new-issued scope samples, independent reservation order, unknown and
unsupported entry marks, saturation, public malformed data and exact old
output preservation.

An additional root review tightened unsupported positive entry handling:
E==O with R==O+1 must be refused for unsupported order, not described as an
extra early-body increment. This now has a concrete regression. No existing
gate or test was weakened.

The underlying instruction fixtures still substitute resource/geometry/cache
and worker/SQL portions exactly as documented by the renderer stage. These
are not hardware, scheduler, exhaustive native-writer, retained-owner or
coherent-capture proofs. Original playback/UI request-generation association,
complete lifetime/cancellation/writer coverage, owned handoff and final guarded
UI transaction remain required before any active candidate can be admitted.

Full repository regression: **1565 tests pass, no skips** (244.464 s), including
all 59 new checks. All 195 Python scripts compile; tracked and new text files
pass whitespace checks. The saved renderer-transport artifact remains exactly
verified with SHA-256
`f42fac46890dc2eadbeba88f90ce5b82857d3045752b974b15d04bef263d2244`.
No new firmware artifact was generated, no existing test/refusal was weakened,
and no player, commit, push or external-network operation was performed.
