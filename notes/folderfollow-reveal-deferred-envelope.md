# Offline owned generation envelopes before deferral

2026-10-26. Successor to [raw registry-release capture](folderfollow-reveal-registry-release.md).
This adds explicit pack and consume-once dispatch helpers and tests a separate
typed native FIFO. It does not widen or connect the original explorer action
queue, supply queue arbitration/locks, retain native engines or authorize UI.

## Values, not a pointer to a later current owner

An envelope is68 bytes: the exact checked GCAP32 output followed by all36 owned
payload bytes. No source pointer, name or latest-table lookup is retained.
`pack(U, capture32, payload36, out68)` snapshots both inputs into a private frame.
It requires GCAP magic, observed-release flag2, native result0, exact U, bounded
positive binding/owner/receipt values and equal opaque engine scalars in capture
and payload. The receipt sequence is bounded by this composition's configured
receipt capacity; binding sequence has the same bound, owner uses ticket_limit.

Destination is independently owned, zero and write-once. The complete zero
check occurs before source reads and again after snapshot/schema validation.
All body words precede GCAP magic publication. Accepted pack returns(out68,0);
refusal returns(0,0) without calling a mutex, table, list, engine, UI or allocator.
Arithmetic/source/output/frame alias guards precede the first access/save, but
mapping, exclusive ownership, coherent data and nested-stack validity remain
caller premises. Schema and flag checks do not authenticate actual capture.

`dispatch(U, exclusively_owned68)` validates a private snapshot, marks only
that owned input's magic CONSUMED before any publication/raw call, then passes
its saved binding sequence, owner and stack-owned36 payload to the actual
explicit producer adapter. The returned nonce and index/status are unchanged.
A positive append index is success, not a raw mutex error. Invalid schema is
not consumed; a valid attempt is consumed even on retirement, backpressure,
ordinary denial or ambiguous raw error. No source is reread after that call.

This prevents repeat use of the same owned work buffer. It does NOT prevent
cooperating callers from making several distinct envelopes from one capture,
authenticate copies, deduplicate arbitrary clones or promise global exactly-once
delivery. It grants no retry or cleanup authority. An error can follow an
already appended paint record; full-instance external isolation remains required.
The prior quarantine/partial-effects rules are unchanged and no new shared
fault write is attempted after an uncertain release.

## The tested FIFO is explicit and caller-exclusive

The fixture creates a separate native list through456E60(initial_capacity,68),
not controller+128's44-byte paint list. Real455DA0->455BC0 append,4557E0 get
and455860 remove execute. Their dynamic width copies all68 bytes, including
generation, across native ten-element segments. Original source32/payload36/
pack storage can be changed after append without changing the queued values.

The extraction order is:

1. Get the borrowed head under separately established caller exclusivity.
2. Emitted pack copies head32 and head+32 payload36 into fresh owned work68.
3. Remove the native head; require actual remove success before dispatch.
4. Dispatch that private work, never the old borrowed head pointer.

Removal relocates full-width following elements and can reuse the same head
address immediately. Copying after removal would adopt the next record. Native
remove0 acknowledges transport extraction only, NOT successful publication,
rendering, paint completion, owner drain or native lifetime/free safety. The
existing paint claim and exact nonce acknowledgement remain separate.

The native fixture's queue is serialized/caller-exclusive, not a scheduler or
a new shared queue protocol. The helpers do not implement get/remove/append,
lock acquisition, raw T+10 status observation, reservations, deferred retention,
concurrent pop arbitration or failure quarantine. Invalid head/failed extraction
does not authorize dispatch/retry; an independent cooperating caller must stop/
isolate that queue. A substituted remove failure tests only caller control flow,
not arbitrary native corruption or a transactional-remove guarantee.

The baseline preallocates native storage and refuses append at actual allocated
Q+8 capacity. Requested capacity rounds to ten-element chunks; it is not an
exact logical ceiling. The tests cross segment boundaries without growth.
Native455980 growth is not transactional: a NULL realloc result may overwrite
Q+0 in a branch delay slot and chunk allocation may leave partial effects.
Nothing here repairs, retries or proves rollback for failed growth. Native
clear only resets count, not erasure, revocation or drain of retained copies.

## Source-taking entries protect the appended code too

The new composition appends a4,508-byte envelope fragment to the25,716-byte
checked capture prefix. Its two-pass full RX descriptor and static extent
checks cover the whole emitted region. The preceding capture wrapper and
producer's source/frame exclusions are extended over the exact new tail by
`following_code_bytes`; otherwise an old prefix entry could accept an address
inside the new helper's code as writable output or payload.

The extension changes RX literals only, not prior instruction counts, labels,
entrypoints or native routes. Default0 preserves all earlier byte hashes.
Composers advertising a tail must actually append exactly that generated code;
this composer checks lengths/labels and full extent metadata. Standalone helper
protected_code=None knows only its own fragment and publication-entry word;
complete surrounding RX separation remains an explicit caller premise there.

The extension protects the outer source-taking register wrapper and explicit
producer, plus the new envelope entries. It is not a new guard certificate for
every inherited internal label. Receipt/issuer/sink/release observers retain
their prior initial save-before-validation stack/nonaliasing premises; direct
owner-kernel entries retain their prior RX/heap/native-list/stack separation
requirements. Complete nested native/library stacks are not preflight-proved.

Pack is a160-byte leaf helper. Dispatch nests160 envelope+160 producer+160
owner-kernel helper bytes before actual list/library frames. These are distinct
from creation's776-byte sink and744-byte owner path; they are not all nested
together. No arithmetic guard proves complete stack availability or scheduling.
The nested publisher retains the bounded13C->148 edge; the helpers introduce
no transport mutex acquisition. Queue access/copy must be serialized separately
and completed before publication, not casually nested into a new reverse edge.

## What remains unwired

Native4BAC80 still builds16 bytes at its64-byte frame'sSP+18; the diagnostic20-
byte extension reaches savedS0+2C. A capture32 cannot fit there. The worker
still snapshots only names, later re-resolves engine/resource after registry
unlock and supplies an occupied selected-action fifth argument. That original
path does not consume these envelopes. Known local T+10->13C then T+10->148
edges and masked T status are source observations, not whole-program lock proof.

Actual owner-scoped fanout capture, bounded snapshot allocation/copy, checked
queue guard and lifecycle participation, retained controller/engine/resource
storage, callback ABI changes and safe cleanup/free remain gates. A frozen
generation does not make dereferencing a freed native engine safe; no engine
dereference, native callback or UI operation is added in this step.

## Verification and identity

The fixture obtains capture32 from emitted registration/issuer/release code,
then uses emitted pack, native FIFO copies/removal and emitted dispatch through
the actual checked producer and44-byte paint queue. No Python pair observation,
later binding lookup or friendly publisher substitute supplies positive data.
Raw services/allocators/libc boundaries remain hostile-ABI stubs, not hardware.

Default composed code is30,224 bytes: unchanged-layout25,716 prefix with extended
RX guard literals plus4,508 envelope. At the preceding fixture addresses its
SHA-256 is`49687ac90583cc610cbca3bb1c12dc96c6bbed02fe4ba67ad64d2deaa8410df3`.
Shared accounting stays656 receipt+784 bindings+328 owners; each exclusive
envelope/work copy needs68 bytes plus separate native FIFO storage. No new
shared arbitration/claim/owner-state table or mutex is introduced.

Exact test counts and fresh regression results are recorded in [status](status.md).
The2026-10-27 serial focused run passes460 tests without skips (43.273 s),
including59 new checks:19 emitted/native FIFO/ABI,28 adverse/configuration and
12 pinned-source cases. All263 Python sources compile without writing files.
Fresh serial full regression passes2,513 tests without skips (369.167 s).
All11 changed/new text paths pass whitespace checks. Old18,416/22,676/25,716-
byte compositions retain their documented hashes. The three saved action-link,
playback-dispatch and renderer-transport images are exactly reverified against
02fd with unchangedd4306357...,a9a6f02f...,f42fac46... hashes and unchanged
autoscrollFalse/hardwareUNTESTED status. No timer/assertion was weakened;
firmware builders/decoders,40-byte core and launcher remain unchanged fromacad6544.
No image, player/network operation, installation, commit or push; active scrolling
disabled and hardware UNTESTED. Changes remain local.

The [checked transport-guard successor](folderfollow-reveal-deferred-queue.md)
adds a distinct raw mutex around cooperating accesses to a separate typed FIFO.
It does not change this predecessor's defaults, connect the original worker,
deduplicate clones or supply native lifetime/whole-instance isolation authority.
