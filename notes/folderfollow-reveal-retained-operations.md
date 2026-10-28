# Offline retained-context operation accounting

2026-10-27. Successor to the [first-constructor capture](folderfollow-reveal-constructor-capture.md).
This is an explicit bounded operation ledger for one already externally retained
controller/engine/resource/callback bundle. It follows cooperating work beyond
transport extraction through publication and exact paint acknowledgement.
It does not acquire an actual native allocation lease, connect the stock worker,
intercept deletion, invoke callbacks/UI or authorize a native destructor/free.

## One immutable bound context, not a new native object layout

The initially-zero private ledger has a64-byte header:

| Offset | Meaning |
| --- | --- |
| 00 | Context state:0 unbound,1 open,2 closed |
| 04 | Terminal local fault |
| 08 | Append-only operation count |
| 0C | Reserved zero |
| 10..2F | Exact checked GCAP32 |
| 30 | Opaque resource scalar |
| 34 | Opaque callback scalar |
| 38 | Opaque callback-context scalar |
| 3C | Reserved zero |

`bind(U, owned44)` snapshots GCAP32 followed by those three opaque words. It binds
the context once and never replaces, reopens or recycles it. The GCAP must carry
the checked release witness, pinned controller, bounded binding/owner/receipt
identities and successful native registration result. These schema checks do
not authenticate capture or establish native memory ownership.

The constructor's out48 is NOT this bind44 layout: its last16 bytes are native
engine, registration return words and witness diagnostics. A caller must
explicitly combine its genuine positive GCAP32 with the separately retained
resource/callback/context values. Opaque words are copied and compared as
scalars, not dereferenced, called, resolved by name or treated as retained
allocation proofs. Descriptor, callback ABI and native object layouts stay unchanged.

Every operation occupies one append-only16-byte row: token at0, state at4,
paint nonce at8 and reserved zero at12. Token is its one-based row index and is
never reused, even after DONE. State is RESERVED1, QUEUED2, EXTRACTED3,
PUBLISHED4, ACKING5 or DONE6. Before publication the nonce is zero; PUBLISHED
and ACKING require a positive bounded nonce. DONE retains its historical
positive nonce after acknowledgement, or zero after cancellation/denial.
Historical positive nonces remain unique. The complete occupied schema and
zero unused tail are checked under the same guard. A full operation table
refuses admission rather than wrapping, reusing or hiding old records.

## Admission and transport share one new checked guard

The instance adds a distinct retained native FIFO headerQ72 and initialized
ordinary nonrobust24-byte mutexM. The72-byte row is token32 followed by exact
READY68. It is not the preceding [transport68](folderfollow-reveal-deferred-queue.md),
controller+128's paint44 or the original worker's action16 list. All list table
and complete allocated chunks, including spare slots touched by native REMOVE,
must remain valid, mapped and nonaliasing for the full operation lifetime.

`enqueue(U, owned_READY68)` first runs the actual emitted packer into private
storage before acquiring M. Its source must be coherent, exclusive and retained,
not an unguarded borrowed list element. Under actual raw acquire0 it validates
the ledger/header, requires OPEN and exact agreement with the bound GCAP, and
checks preallocated queue and ledger capacity. It reserves a new outstanding
row BEFORE actual native APPEND copies token+READY72. Exact old insertion index
and incremented count are checked before changing RESERVED to QUEUED.

Admission and append use one critical section: close cannot slip between a
positive admission decision and the corresponding reservation. Native growth
is never requested; its partial allocation and NULL-table-clobber behavior is
unchanged. An ambiguous/postcondition failure does not discard the reservation,
claim rollback, remint a token or permit automatic retry.

Copies of a READY68 are still separate intentional operations: each gets a new
token and may receive a distinct paint nonce. This is not global deduplication,
capture authentication, callback exactly-once delivery or arbitrary clone revocation.

## Extraction is not completion

`pop_dispatch(U)` acquires M, checks fault and both schemas, then borrows actual
GET index0. The complete borrowed72-byte head is guarded before any token or
envelope read. Token, QUEUED state and exact context must correspond. Both token
and READY are copied into owned private storage BEFORE actual REMOVE: that
method can immediately relocate the next row into the same address.

After confirmed remove0/count decrement, an OPEN context changes the exact row
to EXTRACTED. Only successful raw M release permits actual envelope dispatch
through the existing checked R->P publisher. No M is held across R/P. Positive
publication nonce is rebound to the same EXTRACTED token under a fresh confirmed
M acquisition, changing it to PUBLISHED. The EXTRACTED row remains outstanding
through that gap, even when the transport queue is already empty.

When CLOSED, the same exact successful extraction changes QUEUED to DONE without
publishing it. A context closed after extraction may still have an already
admitted publisher running; its EXTRACTED/PUBLISHED/ACKING row keeps it outstanding.
Cooperating consumers serialize extraction, not necessarily later publication.
Strict publication order requires a separately established single ordered drainer.

An ordinary publisher(0,0) can finish the local attempt as DONE, but is NOT proof
that native APPEND had no effects. Existing paint code can append at index0,
then detect a bad count, latch fault and return(0,0). Consequently local all-DONE
and FIFO-empty are insufficient for positive combined quiescence.

## Exact acknowledgement, including the early-claim gap

`complete(U, nonce, outcome)` accepts outcome0/1 and finds exactly one PUBLISHED
row with that historical nonce under M. It changes that row to ACKING before
releasing M, then calls the actual checked paint.complete without M held.
Only a positive terminal paint result1/2/3 with successful raw release allows
a fresh M acquisition to change the same ACKING row to DONE. Positive raw
insertion indices and retirement removal counts are not pthread error statuses.
Duplicate/wrong nonce or a non-PUBLISHED row cannot call paint.complete or release
another operation's outstanding accounting.

The actual paint claim is still a prerequisite; this ledger does not invent
a claim from a known publication nonce. A concurrent paint consumer can claim
the actual44-byte row before the publisher has rebound the nonce in this ledger.
An early complete then refuses BEFORE invoking paint.complete; the valid active
claim and private work must remain retained until a later explicit exact complete
after binding. No callback, object use or claim is initiated by this ledger.

If the actual checked complete returns(0,0), ACKING is deliberately left in place
with no retry or recovery transition. The result merges harmless missing/wrong
active claim with schema/post-REMOVE faults and potentially changed queue state.
It is not a witnessed harmless NOT_CLAIMED status. Calling complete after bind
but without the required actual claim can therefore permanently prevent drain.
A recoverable distinction would require extending the actual paint helper's
outcome protocol, not guessing from zero or re-reading the latest object.

## Close, then combined quiescence; no native free

`close(U)` only changes OPEN to CLOSED under M. It never reopens admission,
silently clears transport rows, calls old paint retirement or destroys storage.
Exact closed pops can cancel QUEUED rows, and valid existing paint acknowledgements
can finish PUBLISHED work. RESERVED, EXTRACTED, PUBLISHED and ACKING are all
outstanding regardless of transport count.

`quiescent(U)` first requires a healthy CLOSED ledger, every occupied row DONE
and actual Q72 count0 under M. After confirmed release it calls checked
paint.retire for the pinned bound owner, then checked paint.drained, outside M.
Only their actual successful results can produce positive combined quiescence.
Raw errors stop immediately without reacquiring M or touching shared state.

Old paint.retire removes unclaimed rows and reports only the number removed,
not their exact nonces. Running it while ledger operations are outstanding
would strand or incorrectly release accounting; it is not a ledger cancellation
mechanism. Checked paint fault suppresses positive drained, including faults
after a partially effective append/removal. Active claim, unexpected native
references or direct old writers cannot be erased by an empty transport queue.

Even positive combined quiescence is only this cooperating operation protocol's
observation. It does not establish complete native-user coverage, engine/resource
leases, parent membership, callback completion outside this API, external-thread
join, safe teardown continuation, free authorization or a reusable allocator.

## Raw errors and external retention remain hard boundaries

Only actual raw acquire0 permits ledger/list access. A nonzero M acquire or
release, or a forwarded raw R/P error, returns exact status and stops: no guessed
unlock, extra lock, late ledger/fault write, rollback, retry, object access or
cleanup. Such a result may follow an already effective append/remove/ack and may
or may not leave a mutex held. Existing nonterminal reservations are deliberately
not cleared. Other waiting/in-flight callers are not magically cancelled; all
continued use requires external whole-instance isolation/coordinated shutdown.

Under confirmed M ownership, schema/header/head/postcondition/rebind faults can
latch a terminal local fault. The latch is not a cross-thread gate after uncertain
release and is never reset here. No entry initializes/destroys a mutex, allocates
or frees a native object, clears/rebinds a queue, invokes UI, calls the opaque
callback, wakes a worker or performs a constructor continuation.

All storage, genuine checked capture and the single bound native bundle must
already be retained externally before bind and throughout every outstanding
operation and error path. Complete cleanup participation is required before the
first native unlink/delete/detach mutation, not just at final free. Stock engine
deletion4395A0, explorer's separate resource deletion493F50, paint queue cleanup,
parent detach and controller shutdown still bypass this local ledger.

The constructor still ignores registration status and continues through519FA0,
which can execute widget setters and registry lookup before returning. A later
bind cannot isolate or retain that earlier continuation. Missing resource,
allocation failure, NULL name loads and masked raw acquisition failures remain
the preceding constructor-capture gates, not repaired admission paths.

## Composition and verification scope

The new fragment follows the explicit constructor composition. Two-pass assembly
binds the actual pack/dispatch and checked paint complete/retire/drained entries,
protecting the complete generated RX extent. Constructor following_code_bytes
zero and extra_protected_data empty preserve its previous bytes/labels/hash.
Additional constructor exclusions protect new ledger/Q72/M data, distinct from
the preceding Q68/T/fault allocations.

These extensions protect the named outer source-taking entries, not every
inherited internal label. Earlier capture/envelope/queue internal entry callers
retain their documented source, fixed-storage, heap/list and nested-stack
nonaliasing premises, now including new retained data. Native table/chunks,
borrowed head72, exclusive sources and every private frame must be separate
from all fixed state and native/generated RX. Standalone protected_code=None
knows only its own fragment and supplied entry words; surrounding callee RX
separation remains a caller premise. Arithmetic guards do not prove mapping,
complete transitive stacks, import semantics, fairness or whole-program lock order.

Tests use actual emitted capture, pack, native segmented FIFO methods, explicit
publisher and checked paint claim/complete with bounded import/allocator/service
substitutes. Hash-pinned02fd contracts preserve the native FIFO behavior,
constructor's unsafe continuation and independent deletion gates. Emitted paint
contracts pin ambiguous zero outcomes, post-mutation faults, count-only retire
and private-stack-only raw-error exits. None is hardware or native lifetime proof.

Fresh exact test counts, emitted sizes/hashes, unchanged predecessor compositions
and preserved firmware-image verification are recorded in [status](status.md).
No firmware image, installed hook, player/network operation, commit or push is
performed by this stage; active scrolling stays disabled and hardware UNTESTED.
