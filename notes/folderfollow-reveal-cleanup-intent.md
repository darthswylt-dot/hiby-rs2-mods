# Offline one-shot cleanup intent, not native cleanup permission

2026-10-27. Optional successor to [cooperative operation accounting](folderfollow-reveal-retained-operations.md).
This step prepares an exact historical-capture diagnostic after the cooperating context
has closed and drained. It does not call, intercept, resume or authorize any
native detach/destructor/free. No stock teardown caller or firmware image changes.

## Explicit opt-in and one irreversible reservation

The retained composition accepts `cleanup_intent_address=None` by default.
That default preserves the preceding emitted bytes, labels and hash. An explicit
aligned, distinct, externally retained4-byte word enables `prepare_cleanup(U,out48)`.
The word starts at zero, shares the existing checked M guard, and is never reset,
reused, initialized or freed by this API. Its storage remains separate from
the ledger, FIFO72/header/chunks, native controller/mutexes, generated/native RX,
sources and all private/transitive stacks. Optional fixed-data exclusions and
full composed RX guards do not establish mapping or native allocation leases.

The caller must already have explicitly closed admission and finished or exactly
cancelled every operation. The new entry does not close automatically, pop queued
work, recover ACKING/EXTRACTED reservations or invent acknowledgements. Under
confirmed raw M acquisition it validates the full ledger, CLOSED state, all
occupied rows DONE, empty actual FIFO72 and unused intent word. A busy context
refuses before consuming the word. Once ready, it copies the immutable checked
GCAP32 and three opaque resource/callback/context words into private storage,
then reserves the intent word0->1 while M is still held.

Reservation occurs BEFORE releasing M or attempting the checked paint barrier.
Thus a competing prepare cannot enter that barrier after another prepare has
won. After confirmed M release the winner calls the existing exact quiescent
entry, which performs its healthy CLOSED/allDONE/empty check and actual checked
paint.retire then paint.drained outside M. No new M->R/P nesting is introduced.
Only exact barrier(1,0) permits an export. A consumed reservation stays consumed
after ordinary barrier refusal, dirty output, a raw error or successful export;
there is no automatic retry, gate rollback or implicit cleanup continuation.
Reservation means only that this one-shot attempt was admitted: it does not mean
the barrier ran, a record was exported, or native cleanup began or completed.

## Owned CINT48 is a diagnostic, not a callable teardown ticket

The output must be an exclusive, retained, aligned and fully zero48-byte extent.
It is independently checked before use and again after the opaque barrier. On
successful export the layout is:

| Offset | Meaning |
| --- | --- |
| 00 | `CINT` magic, committed last |
| 04..23 | Exact historical bound GCAP32 |
| 24 | Opaque resource scalar |
| 28 | Opaque callback scalar |
| 2C | Opaque callback-context scalar |

The native words are copied and compared as scalars, never dereferenced or
called. The snapshot does not revalidate a current native allocation, registry
node, name or object graph; its identities are the historical bound capture.
CINT48 is neither the constructor's diagnostic out48, GCAP32, bind44,
READY68 nor a FIFO72/paint44 row. It contains no destructor address, continuation
or success receipt. No consumer of CINT is installed by this step.

Successful export returns `(out48,0)`; ordinary refusal returns `(0,0)`; a raw
M/R/P error returns `(0,exact_status)` immediately without another service call,
lock, shared access, guessed unlock, late fault store, rollback or recovery.
Other in-flight/waiting native users are not cancelled by this return. The full
instance, native bundle, all synchronization and private output must remain
externally retained; raw-error continuation requires coordinated isolation.

## Why the apparent final engine/resource delete pair is too late

Pinned02fd native `4395A0` takes the masked registry callback at4395CC, then
finds the FIRST node whose engine name equals its supplied string at439600.
It does not accept the captured engine/generation identity. Its first neighbor
unlink is439618, before name free43962C, engine paint-queue destruction43963C,
engine destruction439644 and node free43964C. Neither this body nor the preceding
raw purge establishes a native retained reference. The tail invokes registry
unlock, whose wrapper overwrites raw status with zero. All56 encoded direct
delete callers ignore that result before their later cleanup;54 immediately call
independent resource deletion485320. No defer/deny/continue handshake exists.

The usual preceding `439780` is itself destructive: under R it invokes raw
paint-list purge4396C0 without acquiring P, then detach8B0760. Detach can mutate
neighbor links at8B07A0/8B07AC, parent head at8B0810, clear engine parent+40 at
8B07C8 and free the attachment at8B07CC. A fence at final engine free misses
already-purged work and lost parent membership. Native facade unlock also masks
detach success/failure. The one direct exception50294C has no preceding439780
in its bounded body; computed callers remain outside this encoded census.

Explorer's engine delete493F44 and separate resource delete493F50 are even later
than several other cleanup obligations. The teardown arm at493EA8 can call
worker shutdown4C0A80 at493EB4 (first object stores4C0AA8), destroy the V+2A08
list at493EC8 and clear it493ED0, and clean eight entries through440620. It then
clears controller+F0 in the493F00 delay slot493F04, calls4BDA20, clears V+3B90
at493F14, calls cache-canvas cleanup47AA20 at493F2C, and calls purge/detach439780
at493F38. Cache cleanup already unlinks a matching node at47AAB4. A full bundle
fence must precede those earlier actions, not merely either final delete call.
This bounded audit does not establish every branch/alias/callback entering
teardown, prove outer lock ownership, or make493EA8 an installable universal hook.

Independent resource deletion485320 first finds metadata by name and detaches
its viewgroup from its parent through45A5A0 at4853A8. It recursively deletes
children through485280, then484700 unlinks metadata at4850EC, destroys its object
at485104, releases handles and optional CC state, and frees the metadata node
at48518C. The outer485320 ignores both inner results and forces zero4853D4;
zero therefore is not proof that resource cleanup succeeded or was safely deferred.

## Remaining boundary before any native integration

A local positive quiescent/CINT result describes only cooperating operation
accounting. Existing native callbacks, parent membership, cache-canvas state,
worker users, name lookup, constructors and outer controller/resource teardown
still bypass it. A closed ledger does not atomically bind a later delete-by-name
call to its captured engine against an untracked registry replacement. Holding
R while entering unchanged4395A0/439780 would re-acquire their ordinary R guard;
keeping M across R/P helpers would introduce forbidden new nesting. This step
does neither.

Before live cleanup, complete native creation/user/cleanup participation,
externally established allocation leases, exact identity under the actual
registry guard, checked error outcomes and safe caller continuation must be
proved together. CINT does not fill any of those gaps, authorize a free, or
retroactively protect the constructor's earlier opaque UI continuation.

Hash-pinned source contracts cover these exact native boundaries. Emitted tests
cover the opt-in one-shot protocol and output/raw-error boundaries with explicit
bounded native-service substitutes; they are not hardware scheduler or lifetime
proofs. [Status](status.md) records exact verification counts and composition
hashes. Active folder-follow remains disabled, hardware UNTESTED; no image,
device, network, installation, launch, reboot, commit or push is performed here.
