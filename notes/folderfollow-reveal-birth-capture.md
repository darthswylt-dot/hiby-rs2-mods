# Exact owned birth-token capture, not live-object authority

2026-10-28. This separate offline branch carries the token minted by the
[field-correlated lifecycle observer](folderfollow-reveal-registry-lifecycle.md)
directly to the registration invocation that caused that birth. It does not
recover a token by searching for the latest node, engine, name or table row.
The existing missing-event counterexample remains unresolved: the token
identifies one recorded birth, not an allocation lease or proof that the object
is still alive. No firmware image, hook installation or player operation is
provided.

## Event origin and private handoff

The lifecycle core has an optional all-register/HI/LO-preserving
`birth_commit_callback(U, owned32_event, token)`. It runs only after the new
row's magic and table count have been committed. It receives the exact newly
minted row-index token and this invocation's owned event snapshot. A refused
birth, retirement observation or historical-row lookup never invokes this
callback. Omitting the option preserves the preceding lifecycle bytes and
labels.

`register_birth(U, descriptor20, zero_out48)` calls the existing checked
registration capture once with private descriptor/output storage. Its passive
`birth_sink` accepts only the exact coherent nested route: lifecycle frame,
receipt frame, native40-byte registration frame, checked capture160-byte frame,
then this outer192-byte invocation. The owned event pointer, native saved
return address, checked capture's saved outer return, private GCAP output pointer
and freshly armed private tag must all agree before a token is copied. These
bounded stack checks distinguish the intended invocation; they do not
authenticate fabricated stacks or establish mapping/retention.

The sink preserves every GPR and HI/LO. It does not choose a latest row, mint a
second token or infer identity from equal node/engine fields. A duplicate on the
same fully scoped route invalidates the outer export instead of reusing the
earlier capture. The lifecycle history remains an observation of an already
committed native publication; a capture refusal cannot veto, undo or safely
retry that native action.
Copying a BCAP does not mint a new birth or provide global replay prevention;
the owned-output and coherent-route premises are not record authentication.

## BCAP48 and checked return boundary

The exclusively owned48-byte output is initially all zero and has this layout:

| Offset | Meaning |
| --- | --- |
| 00 | `BCAP` magic, committed last |
| 04 | Exact newly minted lifecycle birth token |
| 08,0C | Observed controller and pinned registry mutex |
| 10,14 | Actual published node and engine scalar |
| 18,1C | Native registration frame SP and caller |
| 20,24 | Publication site438A5C and actual acquisition status zero |
| 28,2C | Native registration result zero and observed raw release status zero |

The complete frame, descriptor20 and output48 arithmetic, fixed/native/generated
RX exclusions, pairwise disjointness and all twelve zero output words are
checked before the outer architectural save or native call. The final export
checks all twelve output words again and commits its magic last. Independent
retained, writable and nonaliasing nested frames, input/output and all native
objects remain caller premises; arithmetic guards do not establish them.

Successful checked native registration plus a valid exact birth sink returns
native zero and the output pointer. Checked native zero without an admitted
birth capture returns zero/zero and leaves the output untouched. A witnessed
raw-release error preserves the underlying checked result `FFFFFFFF` and its
exact status; missing release evidence preserves `FFFFFFFF`/zero. On these
errors the outer return path touches only its own private frame: it performs
no late output, shared-table or native-object read, no service call, guessed
unlock or retry.
Native allocation failure also preserves the preceding missing-unlock defect;
this wrapper does not repair that unsafe native continuation.

Old receipt/binding/owner quotas, or a paint-mutex/owner-issuance refusal, can
deny GCAP issuance after native publication while still permitting this
birth-only BCAP export if the actual birth sink and checked raw release both
succeed. BCAP therefore asserts no paint-mutex health, owner issuance,
registration rollback, native-object liveness or safe continuation. Conversely,
lifecycle overflow/fault or a missing birth event denies BCAP rather than
recovering an older token by address.

## Composition and remaining gates

`reveal_birth_capture_stage.assemble` takes the seven canonical
receipt/binding/owner/U/R/P/code arguments plus `lifecycle_address`. It composes
the checked registration capture, lifecycle observer and the four previously
bounded retirement frontiers, then appends the new outer wrapper/sink. The
optional lifecycle commit callback must lie wholly in the explicitly advertised
following RX tail, outside the emitted lifecycle-stage prefix and fixed data.
Strict aligned, nonwrapping extents and exact full generated RX are resolved
in two passes. Omitting the callback and following tail preserves the old
lifecycle composition; all eleven preceding default composition hashes remain
contracted.

No existing GCAP32, CINT48, RIAU64, deferred FIFO or retained-operation format is
extended or reinterpreted. A future typed queue must transport BCAP's exact token
explicitly; it must not discover or replace it by a latest-by-address lookup.
This branch is not a constructor/explorer redirect and does not patch existing
native producer/worker calls.

The separate [typed birth-token FIFO](folderfollow-reveal-birth-queue.md) now
implements that transport as BQ84: the exact BCAP body plus an owned 36-byte
payload. Its source is consumed before the transport attempt, and extraction
exports only a private copy after checked T release. Empty-default fixed-data
and following-RX options preserve this BCAP-only composition's bytes and labels;
the new stage extends those exclusions through the complete composed tail.
Neither enqueue nor extraction adds liveness, dispatch or cleanup authority.

Missing raw-acquisition events can still allow native deletion and same-address
rebirth without a safely writable observer event. The earlier healthy-history
counterexample therefore remains valid. Full computed-writer/alias coverage,
controller reinitialization, lifetime of the complete resource/engine graph,
synchronous whole-instance error isolation and safe native continuation are
separate gates. There is no LIVE query, native use/unlink/free authorization,
cleanup callback or automatic recovery here. Active scrolling remains disabled;
hardware is UNTESTED. Local serial verification results are recorded in
[status](status.md).
