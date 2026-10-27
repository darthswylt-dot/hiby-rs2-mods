# Offline same-invocation raw registry-release witness

2026-10-26. Opt-in successor to [emitted creation capture](folderfollow-reveal-creation-capture.md).
The default historical capture is byte-identical. New checked mode observes
the actual raw13C release argument/result before native wrappers mask status.
It does not install firmware, route native explorer work, retain native objects
or authorize cleanup/free, UI actions or retry after any uncertain operation.

## Three observations, one fresh invocation

`checked_registry_release=True` adds three coherent local instruction-fetch
redirects. At438A60, the release-call observer checks actual T9 before the
original JALR and its original A0=S0 delay-slot effect. At466DC8, the raw-call
observer checks actual A0 before pthread_mutex_unlock. At466DD0, the raw-return
observer captures actual V0 before replaying LWRA and forced V0=0. The raw
service still sees its original native SP, A0 and RA466DD0. Every observer
preserves all registers and HI/LO except its displaced native effects.

The explicit wrapper initializes a fresh private state every invocation:
ARMED -> SELECTED -> ENTERED -> CAPTURED. Native-return processing consumes it
once, including failure paths. Status is a separate word, so FFFFFFFF is a real
observed error, not confused with a missing tag. In the coherent retained-stack
route, missing, wrong, stale or replayed events cannot promote the tag. No status is guessed from native0, current
controller fields, a later mutex reacquisition or an already issued owner.

At raw-wrapper SP=W the saved PCs must be437DB0 atW+1C and438A68 atW+3C.
Native registration SP=N=W+40, and the explicit wrapper isV=N+28=W+68 (hex).
N+24 must name that wrapper's exact native continuation. Pinned U and fresh
wrapper state, saved native/raw SP and mutex scalar bind the observations to
the same invocation. The pre-call actual callback and mutex argument must
match the expected437DA0 and independently pinned13C allocation. Raw-return
does not trust clobbered T9/A0 or reread shared U after the service.

The release witness can be observed even when owner issuance was denied.
Positive output still requires the original fresh creation pair, which itself
depends on coherent acquisition/receipt/checked issuance. An observed raw-zero
release alone does not prove prior acquisition or initialize/retain a mutex.
The original unchecked native writes after failed acquisition remain unchanged.

## Checked return values and output

Output stays32 bytes and is still independently owned/write-once, with body
before magic. The old flag1 is HISTORICAL_RELEASE_UNOBSERVED. Only a captured
same-invocation raw release0 permits flag2, REGISTRY_RELEASE_OBSERVED; this is
bounded release evidence under the declared service/stack premises, not a
native lifetime lease or complete admission certificate.

| Checked outcome | V0 | V1 |
| --- | --- | --- |
| Native0, fresh pair and observed raw release0 | 0 | Owned output address |
| Observed nonzero raw release | FFFFFFFF | Exact raw32-bit status |
| Missing/invalid release witness or native allocation failure | FFFFFFFF | 0 |
| Observed release0 but no captured pair / denied export | 0 | 0 |

Only V0=0 with V1=output means an exported record. A positive error status in
V1 when V0=FFFFFFFF is NOT an output pointer. Zero/zero is not permission to
retry or keep using the instance: it can include original unverified acquisition
or preceding issuance failure, dirty output and already committed side effects.
All raw errors still require full-instance external isolation. The helper never
retries, guesses an unlock, remints, retires/closes, cleans up or repairs state.

On release failure native node/binding/owner effects can already exist. No
failure record is written to caller output, no shared quarantine is written
after uncertain release, and no shared controller/journal/owner/binding access
follows the actual raw service. Only retained disjoint private native/observer/
wrapper frames are used for the witness; successful export uses the exclusively
owned caller output. A service may have already released the mutex despite a
nonzero result, or may still own it. Neither outcome grants a recovery path.

Native allocation failure still skips unlock; the wrapper cannot manufacture
a witness or compensate for it. Native forced-zero instructions still execute:
checked-mode error reporting is an explicit new outer API, not a repair of
original synchronization behavior or preservation of its outward return mask.
DefaultFalse retains the old return ABI, labels and all emitted bytes.

## Scope and retained premises

The four earlier receipt redirects plus these three release redirects form
one coherent local fixture. Tests removing individual new observers bound
those negative cases, not arbitrary partial activation. The earlier unsupported
acquisition partial-hook counterexample is not repaired or supported here.
Scalar saved-PC/frame checks do not authenticate hostile fabricated stacks.

Every new observer saves192 bytes before validation. Initially mapped/retained/
nonaliasing observer and native stack frames are caller premises, not a denial-
before-store promise for invalid SP. The global466DC0 wrapper has many unrelated
callers: they also pay the192-byte save/restore even when rejected. Four direct
raw unlock sites (57E208,706D4C,708FAC,70B46C) bypass that wrapper entirely.
The source census is bounded
to encoded J/JAL and selected relative branches, not all computed targets or
runtime-generated code. Stack, mutex allocation/initialization, resolved imports,
ordinary service semantics, stable fields and cooperative synchronization remain
necessary; no universal mutex, stack, scheduling or deadlock claim is made.

Observer frames are separate, not simultaneously nested. At raw release the
bounded explicit depth is160 wrapper+40 registration+32 facade+32 raw wrapper+
192 observer=456 bytes before raw-service/library costs. This does not add to
the776-byte creation-sink path or744-byte owner-kernel path simultaneously.
No sum proves available stack, loader/cache behavior, progress or native lifetime.

No native explorer queue, name-fanout, callback, engine layout or cleanup path
consumes this output yet. In particular, the known worker name-relookup boundary
still loses generation. A retained per-target context captured before deferral,
bounded snapshot/copy handling and full lifecycle participation remain gates.

## Local verification and identity

The fixture executes original registration, callback/wrapper and raw-service
entry/return instructions plus emitted observers. Only raw pthread/allocator
boundaries are bounded hostile-ABI substitutes. It compares all architectural
effects of displaced instructions, not native scheduling or object lifetimes.

DefaultFalse keeps22,676 composition bytes and SHA-256
`90be0fdb56fa349782d7a5b89009661ca26484ad1beed25fb8628ddfc2383da5`.
CheckedTrue is25,716 bytes:12,248 kernel+7,272 capture/observers+1,708 issuer+
2,288 receipt+2,200 adapter; SHA-256
`3c7b26a00fbd17bcd6c86719c21fa7ee5120ecaefcce1b4d9d6fb14332e6721c`
at the preceding fixture addresses. Private shared storage stays656 receipt+
784 bindings+328 owner bytes and32 bytes per independently retained output.
The existing160-byte wrapper uses previously spare private slots for witness
tag, status, native/raw SP and mutex; no new shared table is allocated.

Counts and fresh regression results are recorded in [status](status.md).
Serial focused verification: **401 tests pass, no skips** (28.782 s):55 new
checks (20 native/emitted/ABI,23 adverse/configuration,12 pinned source) plus
346 preceding capture/carrier/issuance/receipt/retirement/admission checks.
Coverage includes actual callback/argument replacement despite unchanged
controller fields, complete saved return-chain rejection, private witness
corruption and replay, all-register/HI/LO/native service ABI, ambiguous error
ownership, no shared late access, fresh-stack reuse, output write-once and
expanded RX/data boundaries. Independent core/source/fixture/documentation
reviews found no remaining issue under the declared caller premises.

Fresh serial full regression: **2,454 tests pass, no skips** (320.373 s).
All258 Python sources compile;14 changed/new text paths pass whitespace checks.
The old18,416/22,676 and opt-in25,716 compositions are exactly reverified against
their documented hashes. Saved action-link, playback-dispatch and renderer-
transport images are exactly reverified against02fd with unchanged
d4306357...,a9a6f02f...,f42fac46... hashes, scrollingFalse/hardwareUNTESTED.
Existing firmware builders/decoders,40-byte core, launcher/timers/assertions
remain unchanged fromf371c83. No firmware image was built or modified; no timer
or assertion was weakened.
No image/file installation, device/network action, commit or push; active
scrolling disabled and hardware UNTESTED. All changes stay local.

The [owned deferred-envelope successor](folderfollow-reveal-deferred-envelope.md)
copies this checked capture with an owned payload before explicit deferral.
It preserves default bytes and does not connect native explorer fanout or add
queue arbitration, a native lease or UI authority.
