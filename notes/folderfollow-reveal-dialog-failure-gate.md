# Classified dialog error exit with one guarded release attempt

2026-10-30. This separate optional offline successor to the
[dialog acquisition gate](folderfollow-reveal-dialog-acquire-gate.md) carries
an already-classified callback failure through the surrounding dialog. It
skips that invocation's dialog graph cleanup, preserves the original callback
V0/V1 and can attempt one raw release of the acquisition's saved M under
additional ownership premises. It never destroys or frees M, retries a failed
service, or supplies whole-instance cleanup and lifetime coordination.

## Carry classification through the actual saved return

The inherited refresh/callback route has already classified pinned U, the
destructor failure and the exact wrapper/callback returns. Its generated
`first_abort_return` and `second_abort_return` pairs are respectively
J `4AECD8`/NOP and J `450DAC`/NOP. The new stage verifies those two actual
parent pairs before replacing them with jumps to its preserving helpers.
It does not test a generic V0 at native `47C7D0`: ordinary callback results
0 and 1, and the null-callback route, must retain their native behavior.

Each new helper saves all 30 non-SP GPRs and HI/LO in 192 private bytes. At
the first entry SP denotes the genuine 5,312-byte callback frame B, with
saved RA at `14BC`. At the second it denotes the genuine 40-byte B frame,
with saved RA at `24`. Only exact saved return `47C7D0` selects an enclosing
dialog. That is the native return from callback JALR `47C7C8`, whose delay
passes A0=H; A1 was loaded from H+50.

On a match, only that B.savedRA word changes to the new common `error_return`.
The helper restores the complete architecture and replays its original jump
to the full native callback epilogue. Foreign saved callers retain their RA
and preceding callback escape. The native callback suffix restores callee
registers, loads the selected saved RA and unwinds B. Consequently the common
entry is reached with genuine dialog frame D at B+`14C0` or B+`28`.

This return PC carries the failure classification even when acquisition
evidence is missing. The code needs no shared mailbox, extra ERROR tag or
native `47C7D0` hook. Missing release evidence cannot accidentally turn a
classified error back into ordinary dialog cleanup.

## Consume admission evidence before one new raw service

Native D is 104 bytes, saving S0/S1/RA at `5C/60/64`; its `18..57` name
buffer remains untouched. The preceding acquisition protocol owns D+10 as
TAG, D+14 as the actual mutex scalar M and D+58 as raw evidence. Admission
has replaced CAPTURED with ADMITTED only after actual raw acquire zero.

At `error_return` the new helper saves all architecture in a separate
192-byte frame and consumes D+10 before checking it. Only ADMITTED together
with D+58=0 permits an attempt, **under the separate hard premise of live,
initialized ordinary M and continuous same-thread ownership**. ADMITTED
alone does not prove those properties. No intervening callback, transitive
callee or other participant may unlock/relock, destroy or transfer M during
the acquisition-to-error handoff. Those cooperation and lifetime premises
are not established by source fingerprints or a raw-zero result.

The permitted path writes ATTEMPTING before loading the saved scalar M from
D+14 into A0. It makes exactly one direct JAL to raw `A5B830`, the resolved
`pthread_mutex_unlock` import. This is a new service call with a generated
return PC, not a claim to reproduce native wrapper return `466DD0`. The
private frame leaves o32 argument homes `00..0F` free; saved GPRs occupy
`10..84` and HI/LO occupy `88/8C`. Its 192-byte size preserves native
eight-byte stack alignment. The service must obey the ordinary ABI,
including SP and callee-saved S7, which retains D.

The first instruction at `release_return` stores actual V0 to D+58 before
any restore or masking. Zero records RELEASE_ZERO; nonzero records
RELEASE_ERROR. Neither outcome retries or destroys/frees M. If admission
proof is absent or its raw status is nonzero, NO_RELEASE with D+58=0 records
that no service was attempted. These distinct tags distinguish an actual
zero release result from the absence of a call.

The original callback V0/V1 remains in the private save throughout the service.
Every outcome restores both words, all other saved registers and HI/LO, then
enters native `47C814`. That pure D104 epilogue loads RA/S1/S0, returns and
unwinds 104 bytes without changing V0/V1. The recorded release outcome is
only evidence in this live D frame; it is not a durable journal or a value
automatically reported to the outer caller after the frame is popped.

## Native cleanup and observers left outside the selected route

The selected return bypasses all of native `47C7D0..47C810`: cache removal
`47AA20`, detach `439780`, name deletion `4395A0`, resource deletion `485320`,
the later masked release and destroy/free facades, and the final V0=0
overwrite. It never reloads H+10 after failure. The original callback result
is not reinterpreted to select this route.

Ordinary callbacks, the null-callback branch at `47C7BC` and foreign enclosing
callers keep their preceding native continuations. The bounded encoded census
finds only that branch targeting `47C7D0`, with no incoming targets at
`47C7D4/7D8/7DC`. No new native hook at any of those addresses is installed.
Computed entries and fabricated frames are not excluded by that census.

The new direct import call does not pass through native `466DC0` or the
global redirects at `466DC8/466DD0`. Those preceding observers classify
constructor/registry deletion chains; this new generated dialog service has
neither their `437DB0` facade return nor their deeper native callers. Ordinary
native releases retain all existing observers. Global raw-release coverage
is not inferred from this additional qualified call.

Earlier dialog +0C lock/release/destruction calls already happened. The
worker still accesses H+14 after its +0C release at `47C6E8`; this gate does
not prove worker termination or undo earlier destruction. The two outer
consumers, `47CC20` and `47CF80`, still ignore the dialog result, change
completion state, remove H from the global list and free it. A raw release
failure can leave M ownership uncertain, and skipping cleanup does not
establish a safe subsequent container free or retry policy. The retained
operation context and escaped aliases receive no new allocation lease.

## Frames, static layout and separate offline composition

Genuine native routes, retained mapped writable simultaneously live nonaliasing
B5312/40, D104 and private192 frames, sufficient transitive stack and import/service
cooperation remain hard premises. Live frames and M/H allocations must not
alias each other, fixed state or native/generated RX. Scope PCs and tags do
not authenticate frames, validate arbitrary SP, prove mapping or repair
partial activation. The two new redirects and every inherited phase must
operate coherently.

Strict static layout excludes U's complete `28C` bytes, R's 24 bytes and
declared fixed data from native/generated RX. Both verified generated parent
eight-byte pairs must be disjoint and precede the helper. Complete protected
RX contains them and the full new fragment. U/R are static declarations,
not new runtime object lookups or release-ownership checks.

The stage uses the same 11 canonical addresses and bounded options. Strict
zero-default `following_code_bytes` protects later RX without appending it.
The preceding default remains 94,232 bytes, SHA-256
`6469c7baf0e41b95efbf4992cc74bdb3116ed1e044d84aa3fcffa0d780c0a4f6`.
The successor adds 1,068 bytes for 95,300 bytes total, SHA-256
`92f44f4def0777f77207b6d0c9a1ad973b88f9e667c3919b3b095200b0aa668e`.
Its canonical parent pair addresses are `01E969A8/01E969B0`, with new first
scope `01E97018`, second scope `01E9715C` and error return `01E972A0`.
Only those two pairs change in the guarded parent prefix; the helper is
appended. Native hooks remain 26, generated hooks become five, total 31.

Metadata sets `dialog_callback_failure_cleanup_stopped=True`,
`dialog_callback_failure_exact_result_preserved=True` and
`dialog_failure_release_attempt_guarded=True`. Global raw-release proof,
native lifetime, partial-graph cleanup, outer-caller isolation, rollback and
destructor-entry fencing remain false. Completed serial checks are recorded
in [status](status.md). These are offline bytes and fetch-override metadata,
not a saved firmware image edit or installer.

Contracts use the preserved 7,133,528-byte 02fd image, SHA-256
`02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87`.
Three named valid compositions expose deep-copied snapshots. Only the 37
unchanged parent assemblers use the previous fixture's pure cache during
this source-contract class; the new core and stage stay unwrapped. Class
cleanup restores their identities, including after failure. Distinct new
invalid/extension configurations still call the actual new code. No CPU,
native execution state or execution results are cached. Bounded fixtures do
not certify full earlier bodies, physical ownership or native scheduling.

Active scrolling remains disabled and hardware UNTESTED. No firmware image,
device/player access, installation, launch, reboot, network, commit or push
operation is supplied by this increment.

Completed serial verification:21 new source/layout contracts and18 new native/
adverse/cache checks pass, alongside39 selected affected-parent tests:78
distinct targeted tests, no skips. Three strengthened branch-target source
cases were rechecked separately and are not additional distinct tests. The
new-emitter equivalence check leaves both new assemblers unwrapped under the
unchanged37-parent cache; it does not claim a fully uncached39-module run.
Exact times, image hashes and remaining limits are recorded in [status](status.md).
The full project suite and hardware were not rerun.
