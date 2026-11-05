# Admission of one factory after dialog quarantine

2026-11-05. This separate optional offline successor to the
[worker terminal tail](folderfollow-reveal-worker-terminal-tail.md) serializes
one native factory, `47D720`, with the protected dialog consumers. It refuses
new admission while their independent Q word is BUSY, QUARANTINED or unknown.
The other four factories, all unknown callers and the complete native lifetime
of existing objects remain outside this frontier.

## Why the factory coverage is deliberately limited

Guarding registration `47C9E0` would be too late. The factory ignores its
result and continues through the optional H+70 initializer, UI work and worker
launcher `47C840`. An internal registration refusal can therefore leave a
created task unregistered while a worker is still started. Admission precedes
lookup, allocation, publication, callbacks and launch instead.

Returning NULL at every factory entry is unsafe. The pinned native RX contains
51 encoded direct callers of `47D180`, one of `47D4A0`, two of `47D720`, 157 of
`47D960` and 21 of `47DCE0`. Some expect an unconditional nonnull result:

- `45336C -> 47D180` is followed by `453384: SW ...,H+50` in the delay of its
  configurator call. There is no NULL check.
- `4A4F1C -> 47D180` is followed by `4A4F2C: SW 1,H+5C`.
- `5091A8 -> 47D960` retains H in S1. If a later independent allocation
  succeeds, `5091E0` writes its pointer into H+58 without checking H.
- `50BAB4 -> 47D960` similarly retains H in S0 and writes H+58 at `50BAD8`.

Other factories have callers which propagate the returned H upward, so an
immediate local NULL check would not prove complete caller safety either.
Those entries are not silently included in this stage.

The two encoded direct callers of `47D720` discard its result:

- `4A4EAC` enters a native return suffix at `4A4A18`, which sets V0=1 before
  returning. No returned H is followed.
- `4EC450` continues with `466A80(S0+58)`, clears that old field and returns.
  S0 is a pre-existing input context, not a copy of factory V0. That old
  context's own lifetime and cleanup authority remain separate premises.

The gate consequently uses NULL/zero for its before-body refusal only within
this genuine entry and these verified direct caller contexts. Encoded call
censuses are not authentication and do not exclude unknown computed calls,
foreign entries or later changes to native code.

## The native frame and the unused owner word

Factory `47D720` allocates F568 and saves RA/S4/S3/S2/S1/S0 at
`234/230/22C/228/224/220`. Its memset buffer is `[F+18,F+214)`, its found-H
and new-H locals are `F+214/F+218`, and `F+21C` is unused padding. A full-body
SP memory/address census finds no access or address materialization for21C.
The two native returns are `47D784` and `47D944`, each with SP+=568 in delay.

The entry hook replaces `47D720:27BDFDC8/AFBF0234`. A complete private192 save
precedes any native object or list access. Its future F+21C owner word is
private P+A4, since192-568+21C=A4. This lies after the saved GPR/HI/LO area
through P+8F. A successful claim writes QF72 there, restores the entry state
and replays the displaced native prologue pair.

The early leave pair at `47D77C` and created leave pair at `47D93C` both load
S1/S0 from `224/220`. At those frontiers RA/S4/S3/S2 and the actual native
result have already been restored. The gate can preserve them, consume its
owner stamp and replay the two stack loads before the native JR/SP delay.
No post-release object or list work remains in either suffix.

`47CA40` can find an already listed object and place it in F+214. The factory
then returns that H through its early suffix. Refusal must precede lookup;
checking only before new allocation would still allow reuse after quarantine.
The initialized native list's four-byte element and buffer/call bounds remain
cooperative ABI premises. A malformed or overrunning callee is not ruled out
by an unused-slot census.

## Shared admission, leaves and progress limits

The stage uses the existing distinct process-lifetime four-byte Q word,
canonical `01F20900`, with READY=0, BUSY=1 and QUARANTINED=2. It does not reset
Q, allocate runtime storage or reuse the transport fault word. Before coherent
quiescent activation, the owner must map/retain/initialize Q and exclude native
invocations already in flight, as required by the preceding retention stage.

Entry saves30 non-SP GPRs and HI/LO in192 bytes and uses bounded LL/SC to claim
READY->BUSY. BUSY, any other nonzero state or exhausted attempts returns0/0
without executing the native factory body. Successful admission retains Q
across lookup, allocation, publication, initializer and launcher; there is no
borrowed entry and no unconditional clearing of BUSY belonging to another call.

Each leave consumes a valid current-frame QF72 stamp and attempts only
BUSY->READY with bounded LL/SC. QUARANTINED and unknown values are never cleared.
Missing stamp evidence leaves Q unchanged. Exit SC exhaustion latches quarantine
instead of reopening it. Every leave preserves the actual native V0/V1 and
register state. A late fault cannot undo work the admitted body already did;
returning a fabricated NULL after publication would not perform rollback.

The retry limit bounds only the atomic loops, default8 with strict limits1..64.
The native body, indirect H+70 initializer, UI services and worker-start wait
are not bounded by this stage. If any does not return, Q remains BUSY. No timeout,
exception unwinder, progress guarantee, thread join or ownership recovery is
introduced. Calls nested under an already BUSY protected consumer are refused;
the two checked callers must tolerate that same NULL policy.

An already admitted factory is not cancelled when a foreign callback publishes
Q=2 inside it. The native body may still initialize, publish or launch its task
before reaching the leave gate; its actual H result is retained. This stage
stops future admission and preserves quarantine. It does not implement rollback
or stop all work already in progress after a fault.

Genuine mapped retained independently nonaliasing live F568/private192 frames,
native/import stack and register ABI cooperation, sufficient transitive stack,
proper native buffer/list bounds, ordinary cacheable LL/SC/SYNC semantics and
coherent activation remain hard premises. Stamps and saved return PCs do not
authenticate forged frames. Other factories and aliases can still mutate or
publish objects outside Q, so this is not global dialog creation isolation.

## Offline composition and verification scope

Core API is `assemble(U,R,code_base,guard_address,*,retry_limit=8,
protected_code=None,extra_protected_data=())`; `hook_words(labels)` supplies
three native pairs. Fixed full U/R/Q/extra data extents and native/generated RX
are checked for strict integer types, alignment, nonwrap and nonoverlap.
The stage keeps the preceding eleven canonical addresses and capacity options,
required guard and strict `following_code_bytes`, protecting later RX without
appending it. No new generated splice is introduced.

The worker-terminal parent remains99,164 bytes by default, SHA-256
`6449ade76e68805fd8857f7a2f9346e5605b3ba04de42bbc71e962fff3b8d4c0`.
The new stage appends its helper to the parent recomposed with complete RX
protection and preserves that guarded prefix exactly. Its inventory becomes
36 native and seven generated pairs,43 total. Exact new bytes, hashes and final
serial results are recorded in [status](status.md).

The helper is1,336 bytes and the complete composition100,500 bytes, SHA-256
`b885d43ec36a534a0bd0d3c9957a51df7eb274266533c309fde0901a5d5f572a`.
Its protected99,164-byte parent prefix is
`a61f33f9bf5e83949926e0d81d97f3e30aef3ef6720265def58afc97e78c46fb`.
The parent's existing complete-RX bounds are extended; no new generated source
pair is patched. Canonical enter/early-leave/created-leave addresses are
`01E9835C/01E9856C/01E98700`.

Metadata names guarded_factory_address=47D720 and the two checked direct
callers. known_factory_admission_guarded is true; all_dialog_factories_guarded,
factory_body_runtime_bounded, factory_refusal_universal_caller_safety_proven
and native_factory_cleanup_rolled_back remain false. Existing worker, mutex
ownership, buffer free-authority and global native lifetime limitations are
preserved.

Source checks pin the preserved02fd image, native frames/tails/direct callers,
the other factories' NULL counterexamples and strict static composition. Three
named valid outputs are deep-copied. Only43 unchanged parent assemblers use
pure fixture caches; the new core/stage remain unwrapped. Temporary function
identities restore on normal and exceptional exits. CPU state, native services
and execution results are not cached; this is not a fully uncached45-function
composition or a hardware scheduler/lifetime certificate.

This is offline code/metadata and bounded tests. No firmware image, installer,
player access, installation, launch, reboot, commit or push is supplied. Active
scrolling remains disabled and hardware UNTESTED.

Final serial validation passed without skips:22 new source/layout cases
(6.405 s),16 new execution cases (7.136 s) and35 preceding worker-tail cases
(5.954 s):73 distinct targeted tests. One source fixture initially expected
NOP instead of the actual `MOVE A3,zero` at4EC454; that expectation was corrected
to the pinned word00003821. No production bytes changed for this correction.

Execution follows native entry/NULL/lookup/existing-result paths and both
stack-only tails. A fixed PC cut at47D78C supplies a created H and jumps to
47D8F0 identically in baseline/new fixtures; allocation and middle graph work
are not simulated. Registration, initializer, view update and startup are
bounded services. The two actual caller JAL/NULL continuations execute. Q-only
epoch interleavings use distinct live stacks; they model emitted instructions,
not target hardware ordering. Missing hooks/stamps are explicit limitations.

In the initializer-fault case Q becomes2 inside an already admitted factory;
native startup still runs and the actual H result survives, while subsequent
admission is refused. Exit-SC exhaustion also retains the actual result and
quarantines; no rollback or bounded startup claim is inferred from these tests.
