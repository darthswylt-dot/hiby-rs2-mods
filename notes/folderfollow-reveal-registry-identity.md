# Offline current-registry observation, not generation or unlink authority

2026-10-27. This optional local successor to the
[one-shot historical cleanup intent](folderfollow-reveal-cleanup-intent.md)
compares an exact historical binding with the current native registry under
checked raw R. It does not unlink, free, detach, look up a name, call an engine,
resume teardown or install a stock hook. No firmware or player state changes.

## Exact historical request and a separate observation

The explicit entry is `audit_identity(U,exclusive_CINT48,owned_zero64)`. CINT48
must come from the preceding checked local protocol, with its exclusive coherent
storage externally retained. Its copied GCAP32 is historical capture, not a
native object lease. Schema and arithmetic checks do not authenticate a forged
record or stop a caller from copying a valid CINT into independent storage.

Before checked R acquisition, an admitted request is snapshotted privately and
its magic irreversibly changes from `CINT` to `CCNS`. This prevents a second
attempt with that same owned input; independent CINT copies remain independently
auditable. Consumption does not mean R was acquired, a match was found, a result
was exported, or any cleanup occurred. There is no rollback or automatic retry.

With confirmed raw R=0, the observer validates the complete occupied historical
binding prefix and resolves the exact supplied binding sequence, owner, engine
and receipt sequence. It does not adopt a latest row by engine/node address or
name. All old binding fields remain historical scalar evidence. A malformed,
quarantined or inconsistent prefix refuses rather than repairing/resetting it.

The current native ring is reached only from the actual controller's U+34
sentinel. Every reached node's full28-byte extent is guarded before its first
read. The bounded walk validates previous-link consistency and the final
sentinel/tail relationship; it must complete at the sentinel within `max_nodes`
(default64, bounded1..1024). A cycle, corrupt relationship, arithmetic alias or
excess length refuses. The historical node address is never dereferenced just
because the historical row named it: it is read only if reached in that walk.
Names and engine objects are never dereferenced. Scalar extent checks cannot
establish that a reached native allocation is mapped, alive or exclusively
retained; those remain caller premises for the entire operation.
Owned buffers and private/transitive stacks must also remain independent of
all other native/shared allocations. Known fixed/node exclusions do not prove
nonaliasing with unknown engine/resource graphs. Historical pointer words are
not dereferenced outside the current walk or revived as live allocations.

After the full scan, only confirmed raw R release=0 permits export into the
separate64-byte output. All16 output words must be zero initially and again
before export. The body is committed before `RIAU` magic. Layout:

| Offset | Meaning |
| --- | --- |
| 00 | `RIAU` magic, committed last |
| 04 | Kind1 matching fields,2 historical node absent,3 engine scalar differs |
| 08..27 | Exact historical GCAP32 |
| 28 | Opaque resource scalar from CINT |
| 2C | Opaque callback scalar from CINT |
| 30 | Opaque callback-context scalar from CINT |
| 34 | Historical node address from the exact binding row |
| 38 | Current node's engine scalar, or zero if the historical node is absent |
| 3C | Number of current nodes scanned in the completed walk |

Kinds describe current address/field observations only. In particular kind1 is
**not** an incarnation match, retained-reference receipt, cleanup permission or
proof that this is still the object originally captured. The original CINT,
constructor diagnostic48, GCAP32 and RIAU64 remain distinct record types.

Success is `(out64,0)`; ordinary refusal is `(0,0)`. Any raw acquisition or
release error returns `(0,exact_status)` immediately, with no additional native
or shared/input/output access, service call, guessed unlock, late fault store,
rollback or recovery. The input may already be consumed and effects of an
uncertain raw service are not inferred from the returned error. Full-instance
external isolation and retention of all native, private and synchronization
storage are still required; an error does not cancel other waiting/running users.

## Why a matching live address cannot authorize exact unlink

Pinned02fd registration4389E0 allocates28 bytes at438A10/14, not12. Its node
layout is next+0, previous+4, engine+8, close flag+0C, another copied field+10,
callback context+14 and callback+18. The five non-link scalars are copied
directly from the native descriptor at438A20..44. No independent incarnation
counter is present in that complete representation. The controller initializes
both sentinel links to U+34 at439ADC..AE8.

The final coherent publication store is438A58 (old-tail.next=newnode), after
U+38 and the new node's two links are written and before unlock438A60. The
existing creation observer captures that event under a fresh checked raw guard.
It does not continuously retain the native allocation after return. The48-byte
binding row keeps its issuance sequence, owner, controller/mutex and historical
node/engine/frame/caller/site/raw-status/receipt words in a separate append-only
table; the native node has no matching live sequence field.

Native4395A0 selects the first equal engine NAME, not a captured generation.
Its first unlink439618 precedes name free43962C, paint-queue destruction43963C,
engine destruction439644 and node free43964C. Independently, controller
teardown43CB20 walks the same ring, unlinks nodes at43CBB0/43CBB4, clears their
links at43CBB8/43CBC0 and frees them at43CBBC. This loop bypasses4395A0. Either
path can allow an allocator to reuse the historical node address; engine
allocation addresses can likewise be reused.

Consequently an old historical row and a newly allocated node/engine may have
identical addresses, scalar fields and neighbor links. Checked R protects the
current walk, not the missing interval between original birth and observation.
Even comparing all28 bytes would not distinguish that ABA. The adversarial
fixture must preserve the old record and reconstruct a replacement at the same
addresses, including a replacement publication with no new captured row: kind1
must still mean only matching fields, never recovered incarnation authority.

A latest-by-address row cannot repair this gap. Historical issuance may refuse
because its bounded table is full or a nested P service is uncertain, while
unchanged native4389E0 has already published the node. Such a birth can have no
new binding row at all. Constructor43AD00 also ignores registration's result
and continues through its opaque UI/name continuation.

Before a positive exact-unlink API, either a genuine externally enforced
continuous allocation lease must already cover the original native bundle, or
a separate live birth sidecar must participate in **every** publication and be
tombstoned **before every** unlink/free, including controller teardown. Birth
coverage must fail closed on missing/full/ambiguous events; a partially observed
append-only history cannot stand in for that sidecar. All existing user/cleanup
bypasses, safe native caller continuation and resource-graph lifetimes remain
independent integration gates. This observer deliberately supplies none of them.

## Local composition and verification boundary

`reveal_registry_identity_stage` composes the explicit observer after the
opt-in cleanup-intent prototype. Complete outer generated RX guards cover the
new tail. The retained composer's zero-default, strict aligned-integer
`following_code_bytes` extends advertised protection without appending bytes
itself. Default55,164-byte retained and opt-in58,948-byte cleanup-intent
compositions preserve their exact previous bytes/labels when that argument is0.
Inherited internal-entry, native heap/list/mapping/nonaliasing and transitive
stack premises remain; outer guards are not a universal native allocation proof.

Hash-pinned source contracts cover the concrete node representation, sentinel,
publication and both destructive paths described above. Executed observer
fixtures cover exact-prefix/full-ring validation, independent input consumption,
raw-error and output boundaries, and the deliberately unresolved ABA case. They
are not hardware scheduling or native lifetime proofs. Exact verification counts
and composition hashes belong in [status](status.md) after serial verification.
All changes remain local, active folder-follow disabled, hardware UNTESTED; no
image build, installation, device/network operation, commit or push occurs here.
