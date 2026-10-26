# Native admission boundaries and checked paint-mutex prototype

2026-10-26. Offline follow-up to the [44-byte generation-retirement prototype](folderfollow-reveal-paint-retirement.md).
Reference:02fd,7,133,528 bytes, SHA-256
`02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87`.
No firmware builder, installed hook, player operation or automatic scrolling.

## Status masking is not an acquisition receipt

The [earlier player-lock audit](folderfollow-reveal-player-lock.md) already
recorded that466DA0/DC0 erase pthread return status. The same wrappers serve
controller paint148 and registry13C callbacks, so this limitation also applies
to later queue prototypes. This is a source fact, not an observed device fault.

| Controller callback | Mutex field | Wrapper | Raw imported service |
| --- | --- | --- | --- |
|437CE0 paint lock |148 |466DA0 |A5B960 pthread_mutex_lock |
|437D60 paint unlock |148 |466DC0 |A5B830 pthread_mutex_unlock |
|437D20 registry lock |13C |466DA0 |A5B960 pthread_mutex_lock |
|437DA0 registry unlock |13C |466DC0 |A5B830 pthread_mutex_unlock |

The raw lock returns at466DB0, but466DB4 forces v0=0. Unlock similarly forces
zero at466DD4. The138/140 facades use the same masking wrappers. A callback
zero therefore cannot certify acquisition or release. In particular, storing
that zero in the caller's stack does not create an independent guard receipt.

Factory466D60 allocates24 bytes, passes the allocation to pthread_mutex_init
with null attributes even if allocation returned null, ignores init status,
and returns the saved pointer. Destroy466DE0 ignores pthread_mutex_destroy
status, frees nonnull storage and returns zero. A nonnull/aligned pointer is
not evidence of successful initialization or retained lifetime.

The older40-byte and default44-byte fixtures inject nonzero results at the
466DA0/DC0 boundary, above the masking instructions. Those tests establish
handling of substituted wrapper failures, not detection of real lower-service
errors. Their guarded queue properties retain a valid-held-guard premise.
No40-byte implementation or existing saved image has been changed here.

## Explicit checked44-byte mode

`reveal_paint_retirement_mips.assemble(..., checked_mutex=True)` emits a
separate opt-in instruction variant. DefaultFalse retains the original bytes:
at state1F50000/controller1700000/code1E80000 the10,824-byte default hashes to
`b0b07d89e0643272907cc2f512f4f3f24b816bcbb95cabb280b09945cc7214b4`.
The flag accepts only a literal bool, not an implicitly truthy configuration.
Checked emission is12,120 code bytes, with the same328-byte default private
state and160-byte helper frame. This excludes native/library frames, allocated
list storage, import resolution and any runtime loading/cache requirements.

Checked mode preserves controller/callback binding checks, snapshots controller
+148 once, and checks a nonnull aligned nonwrapping24-byte extent separate
from the full private state, controller and helper frame. It saves that pointer
in frame+64. It calls raw lockA5B960 and later raw unlockA5B830 on that same
captured object; it never reloads a replacement pointer for release. These PLT
entries use pinned absolute GOT slots; normal resolved import execution remains
a caller premise, not something the instruction stub proves.

All eight operations share this bracket. A nonzero raw lock result returns
v0=0/v1=the exact32-bit status before reading private state, publication input
or queue storage. It makes no speculative unlock call. A nonzero raw unlock
result also returns0/status, but writes only its own retained stack frame:
there is no shared post-unlock FAULT store. Earlier owner/queue effects may
already have happened. This is denial of the current result, not rollback,
safe retry, a drain certificate or an automatically persistent withdrawal.

After any raw error the caller must quarantine the instance externally and
resolve guard/lifetime state before any further operation. There is no new
in-helper latch or recovery scheduler. Nonzero does not universally mean that
the mutex is unowned: robust/unknown mutex types are outside the tested
ordinary nonrobust-mutex model. Neither a guessed unlock, destructor nor
arbitrary shared-memory fault write is justified by that error alone.

Successful operation results and44-byte owner/nonce format remain the same.
The caller still supplies a valid initialized mutex, retained controller/list/
segments/owned input and a separate writable stack through all nested services.
Extent checks do not establish any of those lifetimes or repair stock init,
destroy, status masking or nonparticipating writers. The mode does not provide
a checked13C admission receipt or permit native freeing.

## Registry publication is later than construction

Engine constructor8B4120 allocates and initializes its84-byte object; it does
not register a generation in the controller. The two encoded admission callers
construct first (43AE64/43B00C), then call4389E0 (43AE8C/43B030). Both ignore
registration status and reload their saved engine pointer. A nonnull outer
return is not proof that registry admission succeeded.

4389E0 calls the13C lock callback at438A08, then allocates a28-byte registry
node at438A10 without inspecting the callback result. It copies five input
scalars, including engine word at node+8, without retaining engine/name memory.
No unused node field has been established as generation storage.

Publication stores controller+38, node next/previous links, and finally
old_tail+0 at438A58. The boundary438A5C is after all four link stores, before
native unlock at438A60. An observation at allocation/first-link publication
would be too early. However, neither a forced-zero lock callback nor a copied
raw engine word makes438A5C an independently admitted generation boundary.
Allocation failure branches438A80 to the epilogue without native13C unlock;
an observer must not silently claim to repair that native path.

A preliminary positive-registration observer was discarded before testing or
integration because it relied on the masked callback result. No replacement
creation hook is emitted, installed or called by this step. Connecting admission
still requires an actual13C receipt and checked148 use, an independently captured
generation carrier, complete creation/user coverage and a failure continuation.

## Cleanup must close admission before earlier outer mutations

Resource deletion4395A0 needs a fence before439610/first registry unlink store
439618, not merely before engine free439644. Name free43962C and engine queue
destruction43963C happen earlier. Its56 encoded callers ignore native status;
the tail return is registry-unlock result, not a deferred-delete receipt.

Detach8B0760 needs a fence before8B0794/first neighbor mutation8B07A0. Its
known caller439804 is inside439780, whose tail unlock does not propagate
detach success/failure as a deferred continuation protocol.

The inner shutdown43CB20 first calls a worker at43CB38. Both encoded outer
callers, however, walk registry nodes and can invoke node callbacks, unlink
and free nodes BEFORE that inner function:4E3F48..58 and51A3E8..F8. The first
also destroys controller+290 at4E3F6C before calling43CB20 at4E3F74. Thus an
inner43CB38 fence is too late for whole-controller lifetime. Outer admission
must close before these earlier walks and unknown callbacks as well.

Encoded direct-call censuses and pinned local instruction checks are bounded
evidence, not proof against computed callers, aliases or rebound callbacks.
A local retired/drained owner result never authorizes any of these native
continuations. Full lifecycle integration and active folder-follow remain gated.

## Verification scope

Source checks pin the wrappers, facades, raw PLT entries, registration stores,
caller status loss and earlier outer cleanup. Separate executable tests run
the original facade/wrapper bodies through hostile raw-service stubs; checked
mode tests inject errors at the actual raw import boundary. Bounded instruction
fixtures do not establish pthread internals, scheduling, hardware concurrency,
cache behavior, import resolution or native object lifetime.

All **124 focused checks pass, no skips** (8.732 s):30 pinned source contracts,
9 executable original-status counterexamples,65 earlier retirement checks
and20 checked-mode checks. The latter cover all eight entries, hostile raw
ABI, exact error return, changed controller+148 after acquisition, malformed/
aliased mutex extents, equal default emission, effects surviving unlock error,
and ambiguous acquire/release ownership. After uncertain raw unlock, every
executed data access is confined to the helper frame. Independent review of
implementation, tests, native source and documentation found no actionable
issue; this does not remove the explicit lifecycle/initialization premises.

Fresh serial repository regression: **2,177 tests pass, no skips** (320.672 s).
All236 Python scripts compile, and changed/new text passes whitespace checks.
No launcher timer, assertion or production launcher was changed. Saved
action-link, playback-dispatch and renderer-transport images are exactly
reverified against02fd with unchanged hashesd4306357...,a9a6f02f...,f42fac46...
(full values are in the retirement report). The40-byte module, existing
builders/decoders and all installable images remain unchanged.

Test totals and the final repository regression are recorded in
[status](status.md). No installable image is produced. Verification was local
and preceded the user's separate authorization to commit/push these text-only
changes. Hardware UNTESTED; scrolling stays disabled.
