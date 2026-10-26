# Offline explicit captured-carrier publication

2026-10-26. Local successor to [historical owner issuance](folderfollow-reveal-registry-owner.md).
This adds a separate explicit producer entry, not a native producer ABI change,
firmware image, installed hook, lifetime lease, cleanup or UI authority.

## Capture once; never recover the latest owner by address

The new MIPS interface is
`publish(U, owned36, captured_binding_sequence, captured_owner)`.
The fixture captures the pair from the actual issuer registers at the
`binding_committed` event, after binding publication and before callback return.
That label adds no instruction or byte to the preceding creation composition.
The fixture retains the pair independently; it does not reconstruct it from
the newest row, equal engine, node, name or controller address.

The adapter validates the exact presented pair in the immutable historical
binding table and requires its engine scalar to match the owned payload. It
does not read the engine object or mint, remint, repair or replace a generation.
A retired pair remains denied even when a newly registered object has the same
engine scalar. Conversely, an older still-live pair is not replaced merely
because a later registration has an equal engine. Full binding/owner tables
still permit publication by an existing live pair; no new owner slot is needed.

This is pair validation, NOT authentication of capture. A caller that supplies
an entirely known replacement pair cannot be distinguished from that pair's
genuine holder. Creation-time capture, retention, coherent independently owned
payload and cooperative use are explicit caller premises. The API is not a
capability boundary or proof of native lifetime/current UI selection.

## Guarded publication and ambiguous errors

Before any frame save, payload read or raw service, the entry rejects malformed
input/stack and overlap of its own frame/source with complete configured receipt, binding and owner
state, controller, both mutexes, pinned native RX and generated RX. Composition
passes the whole creation prefix and receipt extent; standalone omission of
either optional descriptor retains the respective nonaliasing caller premise.
These checks do not establish mapping, ownership, aggregate nested stack bounds
or arbitrary heap lifetime.

The adapter copies all nine owned words before the first hostile raw call.
It acquires pinned raw13C, validates the binding header and complete dense
binding prefix, exact pair and payload engine, then calls the actual emitted
checked/pinned44-byte publish entry, which acquires distinct148. Owner tickets
and receipt sequences are strictly increasing, not necessarily dense. If the
binding table is not full, its next unissued slot must be entirely zero; count
rollback or an interrupted dirty tail cannot hide a previously issued binding.
All binding accesses are under13C; owner/queue accesses are delegated to the
actual checked kernel under148. Release uses the same pinned13C pointer.

A positive nonce is success. Its second result is the native append index,
which may be1 or larger: nonzero index is NOT a raw error. A zero nonce with
zero status is ordinary denial, for example retired/closed/full/faulted core;
it does not trigger minting, retry or binding quarantine. Core-internal partial
effects or a terminal fault are not claimed to roll back.

A zero nonce with nonzero inner status quarantines only the binding table,
while13C is still held. The exact status is retained, but numeric status alone
does not distinguish raw148 failure from native append failure. A raw148 unlock
error can leave an appended record; no owner-state readback, cleanup, guessed
unlock or recovery follows. Existing binding quarantine blocks this adapter
and issuer, not direct clients of the older44-byte API.

Raw13C acquisition failure returns zero/status without binding/owner access or
guessed unlock. Raw13C release failure returns zero/status even if publication
already happened. There are no subsequent shared accesses or quarantine writes:
that service may already have released13C. All raw errors require full-instance
external isolation; neither local flag nor a returned zero proves no effect.
Robust/unknown mutex ownership and safe recovery are not implemented here.

The adapter uses a160-byte frame and preserves the standard callee-saved
registers, SP/RA and HI/LO through hostile service ABI. It does not promise all
volatile registers. A nested publish adds the kernel's160-byte helper frame,
plus native list/library stack. The preceding issuance path still requires
192+192+160 helper bytes. Per-frame bounds do not prove aggregate stack,
blocking/scheduling, initialized mutexes or whole-program13C->148 lock order.

## Native transport remains a separate integration gate

Pinned source checks find nine encoded direct calls to native43C860:
490634,490A08,490A58,497918,4A6F44,4DC714,515584,51D064,51DB98.
The bounded scan includes J/JAL and aligned file-backed pointer literals, not
all computed indirect entries, runtime code or callback rebinding.

Native43C860 has four arguments and no independently admitted owner. Its64-byte
frame contains the original32-byte payload, diagnostic word and saved RA;
writing44 bytes in place would overwrite RA and caller storage. Native queue
width alone therefore cannot install this protocol. Constructor wrappers ignore
registration status and return only a raw engine. The84-byte engine allocation
has no verified spare generation field; its tail contains callback context.
The28-byte registry node likewise has no generation slot. The queued explorer
callback's fifth argument is already occupied by selected-action data.

Consequently no native call, object layout, callback or worker transports the
pair yet. Looking up a current generation in an engine extension would allow a
late old producer to adopt a replacement; it is not an acceptable substitute
for retaining the creation-time carrier. Allocation/copy/queue/callback/free
coverage, failed-creation handling, retained engine/controller lifetime,
checked cleanup continuations, full-instance quarantine and UI transactions
remain unimplemented. Four coherent receipt redirects remain a fixture premise;
the earlier unsupported partial-installation counterexample is not repaired.

## Verification and byte identity

The fixture executes original registry, queue-constructor and list instructions and the
actual emitted receipt, issuer, adapter and checked kernel. Only raw services
and allocator/libc boundaries are bounded hostile-ABI substitutes. Its44-byte
queue-constructor override exists in memory only, not a firmware artifact.
Tests cover same-engine ABA, live historical identities, swapped/invalid pairs,
private payload snapshots, exact claim/ack/retirement, backpressure, schema and
tail corruption, raw failures/partial effects, alias boundaries and golden bytes.
Source and independent implementation/fixture reviews are bounded evidence,
not native scheduling, lifetime or complete integration proof.

Serial focused verification: **290 tests pass, no skips** (17.310 s):58 new
checks (23 basic/ABI/extent,25 adversarial,10 pinned native-source contracts)
and232 preceding receipt/issuance/retirement/admission checks. All250 Python
sources compile without file generation. Fresh full results are in status.

Default code is18,416 bytes: unchanged16,216-byte creation composition followed
by2,200-byte adapter with full receipt/prefix guards. At the prior fixture
addresses (code1E80000, receipt1F50000, bindings1F80000, owners1F70000,
U1800000, registry1F20300, paint1F20200), SHA-256 is
`b085c15d00bff87ebb8211a574b5921a12f20030de42e7c7e7bbe426dae74394`.
Default private state stays656 receipt+784 bindings+328 owner bytes; the adapter
allocates no new shared state. Earlier unpinned/default kernel modes, passive
receipt bytes and creation prefix remain byte-identical. Optional queue_capacity
forwarding changes no default bytes. Exact regression counts and saved-image
reverification are recorded in [status](status.md).

Fresh serial full regression: **2,343 tests pass, no skips** (334.985 s).
All250 Python sources compile;22 changed/new text paths pass whitespace checks.
Saved action-link, playback-dispatch and renderer-transport images are exactly
reverified against02fd with unchangedd4306357...,a9a6f02f...,f42fac46... hashes,
scrollingFalse/hardwareUNTESTED. Existing firmware builders/decoders,40-byte
core, launcher/timers/assertions are unchanged fromf79ca66. No assertion or
timer was weakened, and no firmware image was built or modified.

The verification above involved no device/network action, installable image,
commit or push. The subsequent explicit user request authorizes publication of
these text-only offline prototypes, tests and reports to GitHub, not installation
or native producer integration. Active scrolling is disabled and hardware is UNTESTED.

The [emitted creation-capture successor](folderfollow-reveal-creation-capture.md)
replaces Python-only pair observation with a separate explicit wrapper and
owned historical output. It preserves this composition's bytes and does not
wire the native explorer path or certify masked registry release.
