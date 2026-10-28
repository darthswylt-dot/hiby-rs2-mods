# Independent historical native births, not live generations

2026-10-28. This optional local branch records actual native registry
publications independently of the older receipt, binding and owner quotas.
It closes a historical-observation gap identified by the
[current-registry comparison](folderfollow-reveal-registry-identity.md).
It does not provide continuous lifetime coverage, a live-identity query,
tombstones, native deletion, cleanup permission or an allocation lease.
No firmware image, installed hook or player state is changed.

## Event and append-only history

The all-register-preserving callback is `observe(U, owned32_event)`. Its eight
input words are the actual controller, pinned registry mutex, published node,
engine scalar, native registration SP, native caller, publication site
`438A5C`, and raw acquisition status zero. The coherent caller must freshly
confirm raw R=0 for this exact native invocation and genuinely still hold that
ordinary mutex. An arbitrary schema-correct event or fabricated native stack
cannot authenticate that premise.

The callback privately snapshots the input. Node, engine, native SP and caller
remain historical scalar values: this callback never dereferences them. It
validates the pinned controller fields, input/private-frame arithmetic and
known fixed/native/generated RX exclusions before history accesses. As with
the preceding observers, its initial all-register/HI/LO save stores occur
before validation. Independently retained, writable and nonaliasing save
storage remains a caller premise, not a denial-before-store guarantee.
Known fixed-range checks cannot prove mapping, arbitrary native-allocation
nonaliasing or the lifetime of transitive native stacks and resource graphs.

The history is initially zero, has a 16-byte header and fixed 40-byte rows:

| Offset | Meaning |
| --- | --- |
| 00 | `BRTH` row magic, committed after the body |
| 04 | Nonreused token, equal to row index plus one |
| 08 | Controller scalar |
| 0C | Pinned registry-mutex scalar |
| 10 | Published native-node scalar |
| 14 | Engine scalar copied at publication |
| 18 | Native registration SP scalar |
| 1C | Native caller scalar |
| 20 | Publication site `438A5C` |
| 24 | Freshly observed acquisition raw status zero |

Capacity is a strict integer in 1..1024, default 16. Header words are count,
permanent fault and two zero reserved words. Before appending, the callback
validates the complete occupied prefix and every unused tail word. The body
is written first, followed by synchronization, row magic, synchronization and
the updated count. Tokens and rows are never recycled, reset, replaced by
address or interpreted as references that retain native allocations.

Full storage or an admitted malformed history latches its own permanent fault
under confirmed R rather than silently accepting a dropped birth. Invalid
event/route/extents refuse without accessing that history. Faults and refusals
do not undo native publication or change the native return values. All GPRs
and HI/LO, including V0/V1, are preserved on every callback path. There is no
separate positive return receipt, query or claim that the node remains live.
The token is not inserted into GCAP32, CINT48, RIAU64 or deferred work records.
A future owned birth-token transport must originate at the exact event;
looking up the latest row by node/engine address cannot supply that provenance.

## Independence from older issuance quotas

The optional `birth_callback=(entry, RX_start, RX_bytes)` in the passive
registration observer executes after replaying the final native link store
at `438A58` and validating the fresh per-call raw-zero guard, but before the
first receipt-journal access. Consequently an already full/corrupt receipt
journal or a later binding/owner refusal does not suppress an independently
admitted birth-history event. The event does not borrow or guess a receipt,
binding or owner sequence. The old owner-issuance callback remains separate.

Both callback RX tuples are strict, bounded and mutually disjoint; omitting
the new callback preserves the preceding code bytes and labels. The composed
creation branch accepts a birth callback only inside its explicitly advertised
protected RX tail, outside the actual preceding code and every fixed data
extent; an unadvertised external callback is rejected. All four
coherent acquisition/publication redirects, genuine native calling frames,
stable pinned callbacks/mutex fields and common R synchronization remain
premises. A partial activation is not a fail-closed installation strategy.

Native `4389E0` still ignores the masked acquisition result and may publish
after the actual raw service failed. The new observer does not access shared
history without a confirmed raw-zero witness, so that native birth can remain
unobserved. A previous history entry or fault-free header therefore cannot
establish complete birth coverage. Native allocation failure still bypasses
unlock; constructors still ignore registration status and continue through
opaque UI/name work. This branch supplies no retry, guessed unlock, uncertain
service recovery or whole-instance isolation. Checked release observation in
the enclosing registration capture remains distinct from historical birth
observation; a birth can precede a later failed release.

## Why this is deliberately not a live sidecar

Pinned native source establishes at least four controller-registry unlink/free
paths. The first two are not sufficient cleanup coverage:

| Native path | First unlink | Relevant boundary |
| --- | --- | --- |
| Name-selected engine deletion `4395A0` | `439618` | Inside its native masked R scope; frees name, paint queue, engine and node afterward |
| Controller teardown `43CB20` | `43CBB0` | Separate native masked R scope; directly unlinks/frees nodes without calling `4395A0` |
| Outer shutdown region `4E3EFC..4E3F78` | `4E3F48` | Reads the node under R, releases R, then invokes an opaque callback or directly unlinks/frees before `43CB20` |
| Outer shutdown region `51A39C..51A410` | `51A3E8` | Same release-before-callback/direct-unlink shape, independently preceding `43CB20` |

The name-delete frame is 56 bytes, with three unused non-home scalar slots
at +10/+14/+18; controller-teardown's 40-byte frame has only +10/+14 free.
Raw-wrapper SP W has callback return `437D30` at W+1C and the enclosing native
return at W+3C (`4395D4` or `43CB9C`), with native SP W+40. Those concrete
gates could classify genuine same-call acquisition observations, but they
neither authenticate fabricated stacks nor preserve ownership after release.
In particular a fresh acquisition receipt cannot justify writes at the two
outer shutdown paths' later, natively unlocked first-unlink sites.

The known native initializer also writes both sentinel links at
`439AE4`/`439AE8`. Native `43B120` exposes node+8 after releasing R; its callers
can set close flags and call opaque node callbacks. Encoded direct-call,
field-store and intrusive-link-pattern censuses do not classify every escaped
alias, computed call, rebound callback or runtime writer. The four known paths
are concrete missing integration boundaries, not a proof of exhaustive
destruction coverage. Native object/resource destruction and safe caller
continuation remain additional independent gates.

Therefore this history has no LIVE state, address-to-current-token lookup,
historical-to-live promotion, tombstone transition or native unlink entry.
Even a birth token with matching node/engine addresses is only historical:
allocator reuse can make a later node look identical. A genuine continuous
allocation lease or a complete birth/tombstone protocol would require further
work; this step deliberately claims neither.

## Local composition and verification scope

`reveal_registry_birth_stage.assemble` accepts the preceding seven canonical
receipt/binding/owner/controller/R/P/code arguments plus a separate
`birth_address`. It composes an opt-in checked-release **registration** capture
and the early observer, not the native constructor/explorer, retained-operation
or cleanup-intent branch. Full generated RX protection is resolved in two
passes. The outer creation capture and birth callback exclude the new history;
inherited internal-entry/native heap/list/stack nonaliasing premises are not
universally extended to every earlier adapter or native method.

Hash-pinned source contracts preserve the actual publication point, native
node representation, masked mutex callbacks, native frames and the four known
destructive paths. Configuration checks cover strict callback tuples, invalid
state extents/capacities, full RX composition and unchanged hashes of all nine
preceding compositions. Executed fixture coverage and exact serial test counts
are recorded in [status](status.md) only after verification. These checks are
not native hardware scheduling, complete lifecycle interception or safe-free
proofs. Active folder-follow remains disabled and hardware UNTESTED.

The later [field-correlated retirement branch](folderfollow-reveal-registry-lifecycle.md)
now observes the four known frontiers under fresh R, including conservative
pre-unlock selection in the outer loops. Its separate BRLC64 records do not
change BRTH40 or authenticate continuous incarnation: an executable missed-event
counterexample still prevents live/free authority.
