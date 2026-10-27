# Offline checked transport queue guard

2026-10-27. Successor to the [owned pre-deferral envelope](folderfollow-reveal-deferred-envelope.md).
This composes emitted enqueue and pop/dispatch entries around a separate native
68-byte FIFO. It does not connect, resize or replace the original worker queue,
reuse stock T+10, initialize a mutex, install firmware or authorize native UI.

## One distinct guard for cooperating access

Each instance pins its own retained56-byte native list headerQ, initialized
ordinary nonrobust24-byte mutexT and initially-zero4-byte fault word. These
allocations are distinct from each other, receipt/binding/owner/controller
storage, registryR, paintP and native/generated RX. All cooperating transport
access must use the same T, including any future clear, destroy, rebind or
cleanup. Direct native bypasses are not made safe by these wrappers.

The entries call actual raw pthread imports A5B960/A5B830, not native facades
466DA0/466DC0 that discard their results. Only actual acquire0 permits access
to the fault word, queue header, table or elements. Callers must enter without
already holding T, R/P or other locks that introduce unreviewed reverse edges;
there is no recursive-mutex, arbitrary callback or whole-program lock proof.
Actual mutex initialization, retained storage and import semantics are premises,
not inferred from the native mutex factory's unchecked initialization result.

Under T, fault is checked first. Nonzero prevents further queue access. A valid
header must have width68, chunk10, exactly the configured allocated slot count,
unsigned count<=that capacity and nonnull aligned table. Capacity is a positive
multiple of10 in10..10240, not an arbitrary later header value. The uninitialized
nativeQ+4 word is deliberately ignored. Native methods are called directly at
audited bodies, not through rebound method-pointer fields.

These are bounded schema checks, not arbitrary memory-corruption protection.
The whole retained pointer table and all allocated native chunks must remain
mapped, nonaliasing and valid, including the spare slots copied by REMOVE in
the final live chunk. REMOVE traverses ceil(count/10) live chunks, not every
unused allocated chunk. Neither the header nor head checks prove table/block
ownership, mapping, lifetime, immutable native methods or sufficient stacks.

## Enqueue snapshots before acquiring T

`enqueue(U, owned_READY68)` first executes the actual emitted envelope packer
into zero private stack68. The source must remain coherent and exclusively
owned through that snapshot; no source pointer is retained or reread afterward.
Malformed schema is refused without a raw call. The source is not consumed:
several intentional copies remain possible, with no global deduplication claim.

After acquire0 and the fault/header checks, full count refuses before native
APPEND455DA0. No native growth is allowed: its partial allocations and NULL
table clobber are unchanged. Otherwise APPEND copies private68 under T. Both
the actual returned previous index and Q+C==oldCount+1 are required before
success. After successful raw release, success returns(index+1,0), so the first
append is(1,0); ordinary denial returns(0,0). This return convention is not the
native insertion index, a paint nonce or rendering acknowledgement.

## Pop copies and removes under T, then releases before publishing

`pop_dispatch(U)` has no external work-buffer output. After acquire0 and the
same checks, empty returns ordinary denial after release. For a live head:

1. Actual GET4557E0 borrows index0 while T is held.
2. Head arithmetic/fixed-state/outer-frame guards run before source access.
3. Actual emitted pack copies head32 and head+32 payload36 into private68.
4. Actual REMOVE455860 must return0 and Q+C must equal oldCount-1 under T.
5. Actual raw release0 is required before the existing envelope dispatcher.
6. Dispatcher consumes that private copy and calls the existing checked R->P
   publisher, forwarding its actual nonce/index/status unchanged.

The borrowed head is never used after removal; the next record can immediately
occupy its address. No Q/fault/head/source access follows actual T release.
An ambiguous release cannot expose a returned READY work handle or trigger
dispatch. T is never nested into R/P by these entries. Native library/service
behavior and external callers can still introduce edges outside this bounded
path; no complete lock-graph or scheduling/progress guarantee is supplied.

The guard serializes FIFO extraction by cooperating consumers, not their later
publication. Once T is released, another consumer can publish first. Strict
publication order requires a separately established single ordered drainer or
additional sequencing protocol. Transport removal acknowledges extraction only,
not paint success/completion, owner drain or engine/resource lifetime. A later
ordinary publisher denial/error loses that extracted transport item without an
automatic retry. Existing paint claim and exact nonce acknowledgement remain.

## Fail closed only where ownership is confirmed

Invalid header, invalid head/pack, append postcondition mismatch and remove
postcondition mismatch latch fault1/2/3/4 respectively while T is confirmed held.
The latch is never reset here. These failures return(0,0) only after successful
release; they grant no repair, cleanup or retry authority. Native append/remove
may already have had effects, and controlled substitute tests are not native
transactional-failure proofs. Fault prevents future guarded queue operations,
not revocation of other consumers' already extracted private records.

Any nonzero raw acquire returns(0,exactStatus) without queue/fault access or a
guessed unlock, even if the mutex may now be held. Any nonzero raw release
returns(0,exactStatus), with no subsequent queue/fault/source access, shared
fault write, dispatch, rollback or repeated unlock. An append/remove may already
have happened and release may or may not have released T. All continued use
requires external whole-instance isolation/coordinated shutdown. This code
does not supply that cross-thread cancellation gate: other waiting/in-flight
callers are not magically stopped by returning an error to one caller.

No reset, clear, destroy, mutex init/destroy, wake-up, retry, rescan, allocator,
native free or engine dereference is added. Frozen generation is not a lease.
The original worker's16/20-byte payload, name-only fanout/relookup, callback ABI,
bounded capture allocation, cleanup participation and retained controller/
engine/resource storage remain integration gates.

## Composition and verification scope

The new fragment is appended to the existing checked capture/envelope prefix.
Two-pass composition binds the actual emitted pack/dispatch entries and extends
outer register/producer/pack/dispatch RX guards across the exact queue tail.
Zero-default following_code_bytes preserves the preceding envelope bytes and
labels. The composer checks lengths/labels and full extent metadata; advertising
a tail in a standalone prefix still requires actually appending that exact tail.

The new entries guard full dynamic/fixed extents before source access or saves,
including Q/T/fault and the outer256-byte frame. Standalone protected_code=None
only knows its own RX and the two entry words; complete surrounding RX separation
remains a caller premise. Old inherited entries retain their prior data/heap/
initial-save/nested-stack separation premises, including separation from new
Q/T/fault storage. This is not a universal certificate for every internal entry.

Enqueue snapshot or held-pop pack nests256+160 helper bytes. Dispatch nests
256+160+160+160=736 helper bytes before native/library costs, distinct from the
earlier creation776-byte sink path. No arithmetic guard proves complete nested
stack availability, storage lifetime, raw import behavior or scheduler fairness.

Tests execute actual emitted capture, pack, transport wrappers, native segmented
FIFO methods and checked publisher/44-byte paint queue. Raw imports, heap/libc
and blocking test locks remain bounded substitutes, not hardware or a native
thread-scheduler proof. Positive generations are not reconstructed in Python.
The emitted queue fragment is3,976 bytes and its prefix30,224 bytes, giving
34,200 bytes of composed code. With the preceding receipt/binding/owner/U/R/P/
CODE addresses, Q=01FF0000, T=01F20400, fault=01FE0000 and40 allocated slots,
the SHA-256 is
`27c7d0fbad229b65ca81d4b0f9caf3d0581f8ba8a6ba599cf77f574dcc6fdd8b`.
Receipt656+bindings784+owners328 storage is unchanged; the separate transport
adds one retained fault4 and mutex24 besides its native header56/table/chunks.
Serial focused verification passes515 tests without skips (65.812 s), including
55 new cases:13 emitted/native/ABI,28 adverse/boundary/config and14 pinned source.
This includes forced blocking between independent CPU stacks, counter/status
substitutions, both ambiguous raw ownership outcomes, full state/RX/frame
boundaries, exact unsigned endpoints, valid RX adjacency and old byte goldens.
All268 Python sources compile without writing files; all17 changed/new text
paths pass whitespace checks. No assertion/timer was weakened.
Fresh serial full regression passes2,568 tests without skips (344.964 s).
The new34,200-byte composition and all preceding18,416/22,676/25,716/30,224-byte
compositions are exactly reverified against their documented hashes. Saved
action-link/playback-dispatch/renderer-transport images retain their documented
d4306357...,a9a6f02f...,f42fac46... hashes and unchanged verification against02fd,
with autoscrollFalse/hardwareUNTESTED. Existing firmware builders/decoders,
40-byte core and launcher/timers remain unchanged fromacad6544; no image was
built or modified. All changes remain local/uncommitted.
Exact identity, counts and fresh regression results are recorded in [status](status.md).
No device/network operation, firmware image change, installation, commit or push;
active scrolling disabled, hardware UNTESTED, changes local.
