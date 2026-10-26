# Offline raw13C receipt at native registry publication

2026-10-26. Follow-up to committedf79ca66 and the
[checked paint-mutex/admission audit](folderfollow-reveal-paint-admission.md).
This is a passive executable MIPS observation prototype, not native owner
admission, a firmware stage, an installed hook or permission to use/free an
engine. No device, network, UI, commit or push operation belongs to this step.

## What is observed

The native4389E0 registry path calls13C lock437D20 through466DA0. That wrapper
forces zero after pthread_mutex_lock, so its callback result cannot identify
raw failure. The new prototype records the actual raw result BEFORE masking,
but only after checking the actual argument passed to that service. Its
immutable receipt links a raw-zero acquisition to a completed native registry
link publication during that invocation.

This proves neither successful mutex initialization nor native object lifetime.
It is not an owner ticket, current engine identity, release receipt or deferred
cleanup certificate. Captured raw nonzero does not universally mean no lock is
owned; robust/unknown mutex behavior is outside the ordinary-mutex fixture.
Nothing calls the44-byte owner's open_owner/publish/retire API from this stage.
That core, its checked mode and all existing firmware builders remain unchanged.

## Four instruction-fetch redirects, not an image builder

The module emits standalone bridge bytes and a local fixture's instruction
overrides. It has no installation command, image-writing CLI or builder import.
All four redirects must be present for a valid observation:

| Native site | Bridge | Displaced behavior preserved |
| --- | --- | --- |
|438A00 | begin |Load actual callbackT9 and setS0 before observation; resume438A08 |
|466DA8 | raw_call |Call rawA5B960 with originalSP/A0 and returnPC466DB0 |
|466DB0 | raw_return |Capture rawV0, then replay nativeLWRA and forcedV0=0 |
|438A58 | published |Replay final old-tail link store FIRST, then load native unlock callback |

This is a coherent-instrumentation premise, NOT proof that every arbitrary
partially activated hook subset fails closed. For example, retaining only the
publication observer can reuse a stale frame left by a prior allocation failure
if all three freshness/capture hooks are absent. Atomic activation/removal and
complete installation validation are separate unimplemented gates.

Each bridge preserves all non-SP GPRs and HI/LO around its observation, then
restores the nativeSP before continuing. Its192-byte local frame is separate
from native/service frames; the caller must supply sufficient retained writable
stack for every bridge and all nested services. Three previously unused locals
in the existing40-byte native frame are used outside o32 argument homes:
N+10 readiness, N+14 pinned mutex, N+18 raw status. Original saves remain at
N+1C/20/24. The extra observer stack/carrier writes are intentional new effects;
no unchanged timing, cache or arbitrary stack-consumer equivalence is claimed.
The two raw bridges are in the shared466DA0 wrapper: their extra192-byte frame
is needed by EVERY native lock call reaching those sites, including unrelated
controllers/mutexes rejected after the save. Stack coverage across audio,
timers, other threads and all wrapper users is not established by this fixture.

begin first executes the original callback load andS0 assignment. It therefore
checks the actual restoredT9 that438A08 will call, not just a later controller
field. It freshly invalidates all carrier fields, then arms only the pinned
controller, known13C callback pair and pinned mutex object.

At raw_call, original wrapperSP=W=N-0x40. The two saved return PCs must be
W+1C=437D30 and W+3C=438A10, andS0 must be the pinned controller. The bridge
consumes readiness, checks the armed carrier and actualA0 against the pinned
mutex, and changes the per-frame state toENTERED before the raw service. Wrong
scope is ignored without touching unrelated outer-frame locals. The native raw
argument homes, SP and raw return address are retained.

raw_return checks the same bounded native frame chain and consumesENTERED.
Only then does it save the actual32-bit rawV0 and publishCAPTURED in the private
carrier. This distinguishes a genuineFFFFFFFF status from a missing capture.
It then replays the native forced-zero result exactly. At published, the final
native link store executes before observation; readiness is consumed once,
even when the raw result is not zero. OnlyCAPTURED/zero/pinned-mutex plus the
known controller/callback binding permits ANY shared journal read or write.
Missing/invalid capture does not inspect even a corrupted journal or publish
a shared fault. It simply preserves the native continuation.

## Bounded historical journal

The private header is16 bytes: count, fault, reserved0, reserved1. Each40-byte
record containsR13C magic, monotonic sequence, controller, pinned mutex, native
registry node scalar, engine scalar, original nativeSP, native callerRA,
publication site438A5C and captured raw status0. No old engine/name/mutex
allocation is dereferenced to validate these historical scalars.

The issued prefix is checked for magic, dense sequence, controller/mutex/site
binding and zero status. All words of the next slot must be zero. Count
rollback cannot overwrite a published record; skipped holes, corrupt prefix,
reserved header data or a dirty unpublished slot cause a monotonic fault,
but only while the current pinned raw-zero guard has been established. No
rollback or repair is attempted. The complete body precedes magic publication,
and a barrier precedes count publication. Full capacity is bounded observation
backpressure: later native registrations still run but no new receipt is stored.
Capacity1..1024 is supported; storage is16+40*capacity bytes,656 by default.
The journal is append-only and must not be reset/recycled while visible.

This sequence is a local historical identifier, not an unforgeable capability
or owner generation. Equal engine words can occur in separate receipts, and
no latest-by-raw-pointer lookup is exposed to adopt a replacement generation.

## Native defects and remaining prerequisites are preserved

On raw lock failure, the original code still allocates/publishes nodes and
attempts unlock because its wrappers hide the error. This observer does NOT
make that native path safe. It refuses shared observation without a proven
local raw-zero receipt while preserving that original behavior in the fixture.
On native allocation failure,438A80 still bypasses unlock and returns-1.
On unlock error, an earlier acquisition/publication receipt remains historical:
it is not retrospectively upgraded into evidence of successful release.

Bounds and return PCs are not authentication against forged stack frames or
non-ABI callbacks. Premises include genuine pinned native execution, stable
controller callback/mutex fields, a live initialized ordinary13C mutex, resolved
imports, retained native controller/registry/node/source and independent private
stack/code/state storage. No foreign unlock or lifetime mutation may intervene;
the allocator is a hostile ABI service stub, not proof that arbitrary allocator
replacement code respects the guard. The native mutex factory ignores init
status, so a nonnull pointer cannot establish those premises.

Assembler extents reject wrapping, alignment/alias errors and overlap with the
exact02fd original executable range400000..A5BFA0. The bridges stay within the
native MIPS jump region. These checks do not prove heap mappings, stack depth,
cache/loader behavior, scheduling or full native mutation/cleanup coverage.
They do not establish unused native data/GOT storage for code or journal
placement; separately mapped nonaliasing private memory remains a premise.
The original02fd image remains7,133,528 bytes with SHA-256
`02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87`.

Generation issuance still needs an independently captured carrier reaching
all producers and a checked lifecycle/continuation protocol. Resource delete,
detach and earlier outer shutdown mutations remain uncovered. There is no
native owner lease, UI transaction or automatic scrolling authority here.

## Verification scope

Tests execute original4389E0, registry callbacks and status-masking wrappers,
with only allocator/raw pthread bodies replaced by bounded hostile-ABI stubs.
The local fixture compares original and observed final native registers, HI/LO,
links, allocation and raw-service call arguments, checks each bridge boundary,
and exercises malformed/stale/missing captures and corrupted journals. Pinned
source contracts establish instruction/stack/site premises, not arbitrary
runtime caller coverage. Totals are recorded in [status](status.md).

Serial focused verification: **178 tests pass, no skips** (8.908 s):54 new
checks (19 native/bridge instruction and ABI,25 adversarial,10 pinned source)
plus124 preceding paint retirement/checked-mutex checks. All four bridge
boundaries preserve registers/HI/LO except displaced native effects. Original
and fully observed registration retain the same native results, links and
raw-service SP/RA/arguments. Tests cover the genuineFFFFFFFF raw status,
possibly-owned nonzero acquisition, failed release, exact scope/argument
changes before/after the service, allocation-failure freshness, consumed tags,
prefix rollback/holes/corruption and all dirty target words.

One explicitly unsupported partial-redirect counterexample demonstrates stale
capture reuse with unheld-guard journal writes; it is a passing test of a known
installation limitation, NOT a supported fail-closed configuration. All four
coherent redirects remain mandatory. Independent source, implementation,
fixture/adversarial and documentation review found no actionable defect within
the stated premises, not evidence that those premises hold on hardware.

Default emission is2,196 code bytes and656 private-state bytes with a192-byte
bridge frame. Code at1E80000/state1F50000/controller1800000/mutex1F20300 has
SHA-256`cce29e67b8a80688a5ed4c1f6dd83799cff15df71e7c5e2072607938ae815ff7`.
These sizes exclude native/library stack and loader/cache/runtime requirements.

Fresh serial full regression: **2,231 tests pass, no skips** (278.390 s).
All240 Python scripts compile; changed/new text passes whitespace checks.
The saved action-link, playback-dispatch and renderer-transport images are
exactly reverified against02fd with unchanged SHA-256 valuesd4306357...,
a9a6f02f... andf42fac46... (full hashes in the earlier retirement report).
All three remain capture-only, active scrollingFalse and hardwareUNTESTED.
Existing44/40-byte cores, builders/decoders, launcher/timers/assertions and
installable images are unchanged fromf79ca66. No device/network operation,
installation, commit or push was performed.

No installable image is produced. Changes remain local/uncommitted; hardware
UNTESTED and active folder-follow/scrolling disabled.

An opt-in [historical owner-issuance successor](folderfollow-reveal-registry-owner.md)
now receives an owned current-invocation snapshot only after all receipt checks.
DefaultNone keeps this passive emitter's bytes/labels unchanged. The successor
adds a distinct checked148 guard and a separate binding/quarantine table; it
does not turn this raw receipt into a native lease or producer admission API.
