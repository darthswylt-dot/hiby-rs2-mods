# Fresh admission for the dialog's +10 acquisition

2026-10-30. This separate optional offline successor to the
[refresh callback gate](folderfollow-reveal-refresh-callback-gate.md) requires
a fresh actual zero from the dialog's +10 acquire before its next graph reads.
It is an acquisition prerequisite only. It does not add a callback-error
release, skip cleanup after an admitted callback, or establish dialog/worker
ownership and lifetime.

The native callsite belongs to `47C740`. This gate covers every genuine
invocation of that function's +10 acquire route. It does not classify a pinned
controller U at runtime. U/R and other fixed addresses participate in static
layout exclusions; no controller or dialog graph is followed after an
uncertain acquire to recover a scope decision.

## Native boundary and three private native locals

Dialog H is retained in S0. The native function has a 104-byte frame D,
saving S0/S1/RA at `5C/60/64`. Its 64-byte name buffer occupies `18..57`.
Stack words `10/14/58` have no native loads, stores or address constructions
in this body and lie outside the `00..0F` argument homes. The inspected calls
use at most three register arguments; the completion callback receives A0=H
and A1 loaded from H+50.

The acquisition pair at `47C794/798` is `0C119B68/8E040010`: call `466DA0`,
with A0 loaded from H+10 in the delay. The new begin hook retains that exact
delay instruction, executing the load once before the helper saves its entry
architecture. The captured actual A0
supplies the receipt's mutex pointer M. It does not reread H+10 when deciding
admission or after a raw error. Restoring the architecture and supplying
native return `47C79C` before entering `466DA0` preserves the native call
relation and argument effects.

The raw wrapper has 32 bytes, so its frame W is D-32; this route does not use
the extra `437D20` controller facade. W+1C contains `47C79C`. The raw call at
`466DA8` reaches `A5B960`, the import for `pthread_mutex_lock`, and returns
at `466DB0`. The actual V0 is still available there. Native `466DB4` then
overwrites V0 with zero, so the facade result cannot prove acquisition.

The second new native pair is `47C79C/7A0 = 8E02003C/8C450000`. These are
the first post-acquire graph reads: H+3C, then the pointed-to name. Refusal
precedes both. Its pure exit is native `47C814`: load RA/S1/S0, JR RA and
SP+=104. That suffix does not overwrite V0/V1 or call a service.

## Freshness across the actual raw service

Three native words belong only to this live invocation:

| D offset | Role | Changes |
| --- | --- | --- |
| `10` | State tag | Fresh ARMED, then ENTERED, CAPTURED, and ADMITTED on accepted zero |
| `14` | M | Actual A0 captured from the one original H+10 load |
| `58` | Raw evidence | FFFFFFFF sentinel, then actual W, then actual raw V0 |

The begin phase overwrites all three words before the facade call, including
the raw sentinel. The raw-call dispatcher selects the direct saved-return
chain `47C79C`, requires fresh ARMED/sentinel state, and compares actual A0
with M. It binds the actual W before advancing to ENTERED. The raw-return
dispatcher requires native raw return `466DB0`, the same saved caller chain,
ENTERED and the matching raw SP. It captures saved actual V0 before facade
masking, overwrites the SP word with that status and advances to CAPTURED.
Caller-clobbered A0/T9 after the service are not substitutes for the pre-call
argument snapshot.

The admission gate consumes CAPTURED. Only captured actual zero advances to
the distinct ADMITTED state. It then restores the complete architecture and
HI/LO, replays the two original graph reads once and resumes `47C7A4`.
ADMITTED is a local admission state; it is not a reusable CAPTURED witness,
durable ownership receipt, lifetime lease or permission to release a mutex.

Captured nonzero returns `FFFFFFFF/exact_raw` in V0/V1. Missing or incoherent
evidence returns `FFFFFFFF/0`. Refusal restores all other registers, HI/LO
and SP, then uses native `47C814`. It performs no guessed unlock, destroy,
free, callback or post-error H/U lookup. A nonzero status may still leave
ownership uncertain for robust or unknown mutex semantics; no recovery is
invented here.

## Preserve the existing global raw observers

The preceding composition already redirects `466DA8/466DB0` to the retirement
raw-call/raw-return entries. Their registry scope begins with W+1C=`437D30`
and a recognized deeper registry return. The direct dialog return `47C79C`
does not match. Their fallback restores all state and delegates to the older
receipt observers, whose registry-return check also rejects this dialog route.
The original raw call and forced-zero return still execute exactly once.

The new two raw dispatchers delegate to those current retirement entries
after restoring every register and HI/LO. They replace the two existing
native hook values rather than duplicating the service or bypassing the older
observers. Foreign raw routes retain their prior behavior. The actual service
still receives its original SP/argument homes and native return `466DB0`.

## Worker, callback and caller obligations remain separate

Before +10 acquire, `47C740` has already called the +0C lock, release and
destruction facades at `47C77C/784/78C`. All their statuses are masked. The
destruction facade ignores raw destroy failure and frees nonnull storage,
without clearing H+0C. This gate cannot undo that earlier processing.

The worker's `47C6E8` +0C release is not thread termination. It still reads
H+14 at `47C6F0`, may free it at `47C6FC`, and clears it at `47C704` before
returning. Neither a +10 raw-zero receipt nor this earlier +0C call sequence
proves worker quiescence, safe reentry or the lifetime of H and its mutexes.
The native mutex factory does not check allocation before initialization and
discards the initialization result; its returned pointer is not an
initialization receipt.

An admitted invocation retains the native completion callback, its existing
classified refresh/callback gates, and the subsequent dialog cache, detach,
name and resource cleanup. It still calls release `466DC0` and destruction
`466DE0` using values loaded from H+10, then forces V0=0. This increment does
not propagate a callback failure through that surrounding cleanup or certify
its matching release result.

On admission refusal, the dialog returns to its existing callers. Normal
consumer `47CC20` calls H+6C at `47CC8C`, ignores the result, changes completion
flags, removes H from the global list, optionally calls H+7C and frees H.
Close-by-name consumer `47CF80` calls H+6C at `47D004`, likewise ignores the
result, removes H and frees it. Their continuation and the worker's possible
remaining accesses are outside this gate. No safe-retention or whole-instance
isolation claim follows from preventing these local graph reads.

## Hard premises and offline composition

Genuine native route/ABI, mapped writable retained D104/W32 and each separate
192-byte architectural save, sufficient transitive stack and ordinary service
cooperation remain hard premises. Simultaneously live frames, H/M allocations,
fixed state and native/generated RX must be independently nonaliasing. Static
exclusions do not validate arbitrary SP, initialization, mapping or lifetime;
saved return PCs and tags do not authenticate forged frames. All four new
redirects and the inherited observers must operate coherently. Arbitrary
partial activation is not an installer-level fail-closed guarantee.

The separate successor accepts the same 11 canonical addresses and bounded
options. Strict zero-default `following_code_bytes` protects later RX without
appending it. The preceding callback default remains 92,600 bytes, SHA-256
`e76f86cc4cea0ecb445eee4eb712e14993004f3a42138e2b7150831899b9f7c4`.
The successor appends 1,632 bytes, for 94,232 bytes total, SHA-256
`6469c7baf0e41b95efbf4992cc74bdb3116ed1e044d84aa3fcffa0d780c0a4f6`.
Its canonical generated begin address is `01E969B8`. The accompanying source
contract pins these values; completed serial results are recorded in
[status](status.md).

Its prefix is the guarded parent unchanged; only the new helper is appended.
The hook inventory replaces two raw native pairs and adds the begin/admission
pairs, giving 26 native plus three unchanged generated pairs, 29 coherent
pairs total. These are offline bytes and fetch-override metadata, not a saved
firmware image edit, installer or device action. Whole-instance caller
isolation, global raw-release proof, native lifetime, partial-graph cleanup,
rollback and destructor-entry fencing remain false.

Metadata sets `dialog_acquire_failure_admission_gated=True` for this local
prerequisite. It does not add a dialog callback-error release or cleanup stop.

Source contracts use the preserved 7,133,528-byte 02fd reference, SHA-256
`02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87`.
They pin the native frames, unused locals, graph boundary, status masking,
worker/caller residuals, private protocol, exact delegates, strict layout and
complete composition. Three named valid outputs provide deep-copied snapshots.
During the contract class, only the 35 unchanged parent assemblers use the
preceding callback fixture's pure cache; the new core/stage stay unwrapped.
Class cleanup restores parent identities, including after failure. Distinct
new invalid/extension configurations still call the actual new code. No CPU,
native execution state or execution results are cached. Full earlier worker,
callback and cleanup bodies are not certified by bounded execution fixtures.

Active scrolling remains disabled and hardware UNTESTED. No firmware image,
device/player access, installation, launch, reboot, network, commit or push
operation is supplied by this increment.

Completed serial verification:21 new source/layout contracts and19 new native/
adverse/cache tests pass, plus41 selected affected-parent checks:81 distinct
passing targeted tests, no skips. Three preliminary cases overlap the full
execution run and are not counted twice. The independent fully uncached37-
module construction matches the cached bytes and native outcome; the source
class separately memoizes35 unchanged parents. Exact times, fresh image hashes
and remaining limitations are recorded in [status](status.md). The full project
suite and hardware were not rerun.
