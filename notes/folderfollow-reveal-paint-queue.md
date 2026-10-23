# Host paint queue: retained claim, cancellation and deferred owner accounting

2026-10-23. Positive host-only implementation following the
[native payload/removal audit](folderfollow-reveal-paint-payload-boundary.md).
This is not a MIPS patch, native lifetime lease, installable candidate or UI
adapter. No player connection, installation, launch, rearm, signal, reboot,
timer or scrolling action. Existing diagnostic builders, layouts, images and
LALI/BIRTH pointer bindings remain unchanged.

## Implemented protocol boundary

`folderfollow_reveal_paint_queue.py` implements a single bounded host queue
over **already-owned input values**. One private host mutex serializes owner
registration, publication, claim, completion, cancellation and owner-accounting
release. The producer must provide a coherent source before publication; a
Python list-to-tuple copy cannot establish coherence of a borrowed native
rectangle. Controller/engine words remain uninterpreted numeric values.

The queue retains its head until the one exact active claim is acknowledged.
A second consumer receives no claim while that head is active, including after
cancellation. It cannot skip ahead to B while A is still in flight. Claimed
entries finish in publication order; removal of unclaimed entries is reported
separately by cancellation. This is not proof that both original native UI
loops are serialized. No timeout,
takeover or forced owner release is used.

| Operation | Serialized effect |
| --- | --- |
| `open_owner` | Mint an identity-bound host owner generation, even for repeated names/raw words |
| `enqueue` | Copy bounded scalar payload and issue a fresh entry ID for an admitted owner |
| `claim` | Bind one immutable payload/one-use token to the exact retained FIFO head |
| `complete` | Acknowledge only that issued token, remove only its entry and report completed/failed/cancelled |
| `purge` / `retire` | Revoke affected owner handles before accepting more work; remove unclaimed matching entries and cancel the claimed one without deleting it |
| `release_owner` | Drop retired host accounting only after no queued/claimed entry refers to it |
| `close` / `uncertain` | Irreversibly stop new publication/claims, cancel the active one and retire owners; an existing token can still acknowledge cleanup |

A cancelled completion can retire accounting but cannot report successful
completion. Duplicate, reconstructed, copied, stale or foreign claim objects
cannot remove another head. An equal name, controller/engine word or numeric
ticket does not turn such an object into an issued capability.

Purge retires matching owner generations as well as their entries. A producer
holding an old owner handle cannot republish after purge, even when a new
generation has exactly the same name/engine words. Opening a new generation
does not revive the old one. Acknowledging/releasing an old generation must
not cancel or remove the new generation's work.

`release_owner` concerns **host bookkeeping only**, not permission to free a
native pointer. The model does not retain, free, detach, dereference or verify
an actual controller/engine. A native adapter would need a separate retained
resource transaction and reliable acknowledgement after all native uses end.
An equal/recycled raw address is not that transaction.

## Boundedness, validation and ordering

Owner and entry tickets share one persistent bounded monotonic counter. IDs
are not reset after purge, completion, owner release, close or uncertainty.
Exhaustion is terminal and cancels pending work rather than wrapping into a
previous ticket. Queue capacity includes the cancelled active head until
acknowledgement; registered owner accounting is bounded separately by the
same capacity. Capacity rejection cannot evict another pending operation or
reuse an ID.

Payloads, handles and snapshots contain owned immutable values. Mutable source
rectangles are copied/validated before entering the queue lock, and exact
built-in types prevent arbitrary producer iteration/equality callbacks inside
the critical section. No renderer, resource destructor, supplied callback,
sleep, thread join, native setter or I/O is invoked while holding this lock.
Completion receives the caller's explicit boolean outcome; it is not proof
that a native callback ran, returned successfully or stopped using a pointer.

The public snapshot reports host queue state only. Its native record lease,
payload coherence, object lifetime, current owner/contents, request freshness,
coherent capture and autoscroll authority proof flags remain false. This
component is not attached to `RevealCoordinator`, a raw-snapshot decoder or
the firmware. No host token is manufactured from a native address or journal.

## Native lock-order evidence and remaining integration

New pinned-source contracts separate a useful local order from an actual
native lifecycle solution:

- The known purge caller439780 holds controller registry mutex13C before
  calling4396C0 at4397F8. A paint mutex148 around that inner list operation
  would introduce the local order **13C ->148**, not the reverse.
- The four inspected148 sections (append/get/remove/destroy) contain only
  their bounded list/memory work; no nested13C acquisition was found there.
  Teardown43CB20 finishes paint destruction at43CB84, including its148
  unlock, before acquiring13C at43CB94. This is not a reverse nested edge.
- There is an existing13C-held path through459840 at43A444, between registry
  acquisition43A3F4 and unlock43A450. This source precedent is not permission
  to hold arbitrary locks across callbacks or to infer all indirect behavior.
- Resource removal4395A0 independently frees its name, engine paint queue,
  engine via8B4220 and registry entry under13C. It does not use the paint
  purge or148 protocol. The bounded encoded census has55 callers of439780
  and56 of4395A0;50294C is the extra direct resource-removal call without a
  preceding439780 in that function body. A queued engine can therefore not
  be assumed retained merely by taking13C at a later selection.
- Separate detach helper8B0760 unlinks an attachment, clears engine+40 and
  changes geometry; freeing that attachment is not itself proof of freeing
  the engine. Controller teardown also destroys its mutex objects. Both
  cancellation and controller lifetime need explicit coverage.

These are bounded original-source findings, not a proof of a unique native
thread, exhaustive alias/writer coverage or a universal absence of lock cycles.
The host queue has **one different host lock**; it does not install either
native mutex order or intercept existing mutation paths.

Porting the protocol would require all paint producers, selection/removal,
purge, direct resource deletion/detach and controller teardown to participate.
The adapter must retain its selected native owner before use, fence cancelled
in-flight work, preserve native ordering/cleanup/failure behavior, and keep
original-record evidence distinct from an owned copy. Moving BIRTH.INPUT to
a consumer-owned buffer requires a separately versioned receipt; existing
LALI equality must not be relaxed or silently relabelled. Active folder-follow
and scrolling remain disabled until those independent gates are satisfied.

## Verification

All **95 new focused checks pass** (1.128 s):47 basic protocol checks,30
adversarial checks and18 pinned native source contracts. The host checks cover
mutable-source copying, immutable returned values, exact issued handles,
head-retained FIFO, duplicate/foreign/stale acknowledgement, cancellation
before completion, reopening equal raw words with a fresh owner, bounded
retained accounting, malformed inputs, capacity rejection and terminal
nonwrapping exhaustion/uncertainty/close.

Adversarial coverage includes all1,296 length-four sequences over six model
operations, six purge/ack/close permutations and four actual **host-thread**
fixtures: eight simultaneous claimants, twenty purge/ack races, twenty
close/ack races, and an Event-held claim cancelled before acknowledgement.
The thread fixtures use bounded barriers/events and joins, not sleeps or
timers. They exercise this host object's locking only, not native scheduler,
13C/148 or firmware concurrency. No callback/destructor or native action is
substituted into the queue itself.

Independent protocol/implementation, adversarial-fixture and source/lifecycle
reviews found no actionable issue. Earlier payload-interleaving counterexamples
remain unchanged as evidence about the unmodified native implementation.
Full repository regression: **1,990 tests pass, no skips** (321.386 s).
All225 Python scripts compile; tracked and new text files pass whitespace
checks. The saved action-link, playback-dispatch and renderer-transport images
are exactly reverified against the pinned source with unchanged SHA-256 hashes
`d4306357ec6b70153b15e98202dad1a7ad0615d02ea6bd9e0d53857844ab37a8`,
`a9a6f02fd48a3b57e27e3bb19c9e8c2b8329b6602cc12988091dfbb98c2abe2c`
and `f42fac46890dc2eadbeba88f90ce5b82857d3045752b974b15d04bef263d2244`.
No existing launcher/test timer, assertion or refusal was weakened. No new
firmware artifact is produced by this step; changes remain local/uncommitted.
No device/network operation, commit or push. Hardware UNTESTED; active
folder-follow and scrolling remain disabled.

The next [offline MIPS handoff prototype](folderfollow-reveal-paint-handoff.md)
implements publication, a retained head/owned byte copy and exact nonce-based
acknowledgement against actual native list methods. It does not port this
host object's owner-generation retirement or establish native lifecycle
retention. Its distinct40-byte format remains outside firmware builders.
