# Admission of the second factory through its checked NULL chain

2026-11-05. This optional offline successor to the
[first factory admission gate](folderfollow-reveal-factory-admission-gate.md)
adds `47D4A0` to the same process-lifetime Q exclusion. The direct wrapper checks
NULL, and its only encoded upper caller discards the returned H. These exact
native routes support before-body refusal; computed/foreign callers and the
other three factories remain outside the added coverage.

## Closing the transitive NULL path

The only encoded direct call to `47D4A0` is `4F87C0` in wrapper `4F8760`.
`4F87C8` tests V0 and skips `SW 1,H+5C` at `4F87D0` when NULL. The wrapper
stores the result in its80-byte frame's local+40 at `4F87EC`, executes its
ordinary UI/global work, then restores that same result at `4F8800`.
That local is not an outgoing O32 argument.

The two UI facades `4771A0/477180` use newly assigned A0=1 and A1=globalBB20/0.
They overwrite V0 from A0 and rebuild A2 from A1 before their own native tail
calls. The returned factory H is not passed to them. The existing global state
and callbacks can still have their ordinary effects; rejection does not skip
the wrapper's remaining work or certify its native allocation lifetimes.

The only encoded direct caller of `4F8760` is `4A326C`. It next assigns all four
arguments for `477600`: A0=callback4A1800, A1=its pre-existing S0, A2=0 and A3=23.
There is no save, dereference or propagation of factory V0. The native leaf
`477600` overwrites V0 at `477608`. The subsequent `469180` call and common
epilogue `4A3118` likewise require no returned H, and the epilogue returns1.

This closes only the checked encoded chain, not every possible indirect call.
It does not justify NULL refusal for the three remaining factories. In
particular, the known `47D180/47D960` callers which dereference H unconditionally
remain as documented counterexamples to a blanket factory gate.

## A separate owner stamp in the same native frame layout

`47D4A0` uses F568, like `47D720`, but its entry pair is
`27BDFDC8/AFB10224`: the second word saves S1, not RA. The owner word remains
unused F+21C, initially private P+A4 under the complete192-byte entry save.
The secondary stamp is QF4A, distinct from the primary gate's QF72.

Its memset buffer is `[F+18,F+214)`, its found/new H locals are214/218 and its
saved registers occupy220..234. Incoming fifth/sixth arguments are read at
F+248/F+24C, equal to the caller's oldSP+10/+14. Those slots remain outside
the new saves and owner stamp. A complete SP memory/address census finds no
native use or materialized pointer for F+21C; native buffer/call bounds and
initialized list semantics remain independent cooperation premises.

The selected late early-return pair is `47D4F8:8FB10224/8FB00220`, followed by
`47D500 JR RA` and SP+=568 in delay. The created-return pair is the same at
`47D6E8`, followed by `47D6F0 JR RA` and its SP delay. RA/S4/S3/S2 and the actual
native V0 have already been restored before each late pair. The bounded native
function has exactly those two returns. Encoded references reveal no bypass
into an entry delay or selected tail interior; computed entries are premises.

The primary emitter's implementation is factored into a private parameterized
routine while its original public API and default bytes remain unchanged.
The secondary public wrapper selects only its hook table and QF4A stamp. The
same bounded atomic policy preserves registers and HI/LO, requires READY->BUSY
before body work, and refuses BUSY/quarantine/unknown states or exhausted
attempts with0/0 before native frame or input access.

Both leaves consume a current-frame QF4A stamp, attempt only BUSY->READY, never
clear quarantine or unknown state, and latch quarantine on exit SC exhaustion.
Missing owner evidence leaves Q unchanged. Actual native V0/V1 are preserved
on every leave. The shared Q word, canonical01F20900, is retained and initialized
by its owner before quiescent coherent activation; no runtime reset or setup
allocator is provided.

## Escaped H, progress and work already admitted

The known H+70 initializer from wrapper descriptor+20 is `4F8620`; H+74 is
`4F8540` and H+78 is zero in that descriptor. Initializer `4F8620` resolves a UI
resource through `485DE0`, publishes H with `459320` at `4F8660` and installs
handler `4F86A0` through `459500` at `4F8670`. The setter merely writes the
resource's+138 handler; it does not immediately invoke it.

The later handler recovers H through `459340` and calls unguarded configurator
`47D0A0` at `4F86F4`. Thus the initializer does create an escaped alias; this
secondary gate does not fence every later widget/resource access. Opaque UI
resolution/import work and worker startup remain outside any progress proof.

The gate holds Q across the admitted factory body. A nonreturning initializer,
UI service or `47C840` startup wait can keep Q BUSY indefinitely. Its retry bound
applies only to the atomic loops; no body timeout or exception unwinder is
introduced. Nested protected entries are refused rather than granted a borrowed
claim, and cooperating callbacks must tolerate refusal without waiting for a
protected consumer to succeed while Q is held.

If a foreign callback publishes quarantine inside an already admitted factory,
that body is not cancelled. It may still publish, initialize or launch a task
and return its native H before the leave gate observes Q=2. The gate preserves
the actual result and terminal state; it cannot undo those effects. This is
future-admission protection, not rollback or cancellation of all in-flight work.

Genuine retained mapped independently nonaliasing live frames and allocations,
sufficient stack, imported/native ABI and buffer bounds, cacheable coherent
LL/SC/SYNC and whole-process Q mapping/initialization remain hard premises.
An encoded caller census, owner stamp or saved PC does not authenticate forged
frames or establish mutex ownership, buffer free authority or native lifetimes.

## Composition and bounded validation

The core keeps the primary public API `assemble(U,R,code_base,guard_address,
*,retry_limit=8,protected_code=None,extra_protected_data=())`. Static full
U/R/Q/extra/native/generated RX extents are checked for strict types, alignment,
nonwrap and nonoverlap. The stage keeps the preceding eleven addresses and
capacity options, required independent guard and strict following RX extent.

Its parent remains100,500 bytes by default, SHA-256
`b885d43ec36a534a0bd0d3c9957a51df7eb274266533c309fde0901a5d5f572a`.
The secondary helper is appended to the parent recomposed with complete RX
protection, without a new generated splice. The hook inventory becomes39 native
and seven generated coherent pairs,46 total. Exact new hashes and final serial
results are recorded in [status](status.md).

The helper is1,336 bytes and the complete composition101,836 bytes, SHA-256
`193532af1c92cc1b454184bbc95e7bbe77e1e07ff2ed8b3a70bbfa654a45b0ff`.
The protected100,500-byte parent prefix has SHA-256
`2ebeeeff65ae19a2d2cf92c70cae269c4ebce12a59483fc2291608d3cc4c80db`.
It includes the parent's existing extended complete-RX bound materializations
and is preserved exactly. Canonical enter/early-leave/created-leave addresses
are `01E98894/01E98AA4/01E98C38`.

Metadata identifies secondary_guarded_factory_address=47D4A0, direct caller
4F87C0 and wrapper caller4A326C, with guarded_factory_addresses=(47D720,47D4A0).
known_secondary_factory_admission_guarded is true; all_dialog_factories_guarded,
factory_body_runtime_bounded, universal caller safety and cleanup rollback remain
false. Existing initialization, ownership, worker lifetime and buffer free
authority limitations are preserved.

Source contracts pin the preserved02fd image and the actual NULL chain, frame,
incoming argument slots, initializer/handler escape, hook sites and strict
static composition. Only45 public parent assemblers are cached for fixture
construction, including the refactored public adapter whose original default
emission is pinned. The two new public assemblers and shared private emitter
remain unwrapped. Three valid named outputs are deep-copied and every temporary
function identity restores after normal and exceptional exits. CPU state, native
service outcomes and execution are not cached. A full uncached47-function chain,
all native/import services and hardware scheduling are not certified.

This increment supplies offline code/metadata and tests, without an image,
installer, player access, installation, launch, reboot, commit or push. Active
scrolling remains disabled and hardware UNTESTED.

Final serial checks passed without skips:38 preceding factory source/execution
cases (9.727 s),17 new execution cases (10.995 s) and18 new source/layout cases
(7.167 s):73 distinct targeted tests. The old public API and complete default
parent hash are preserved after extracting the shared private emitter. The
primary/secondary helpers at the same code address differ in exactly seven
scope/stamp/replay words; no execution results or shared private emission are
memoized.

The execution fixture follows the actual native entry, fifth-argument load,
NULL/lookup branches and both late return suffixes. The sixth-argument load is
checked separately using its actual native instruction because the created
body has a fixed PC cut47D508->47D69C. The cut supplies a created H identically
for baseline/new runs; allocation and middle graph work remain opaque.
Registration, initializer, view update and startup are bounded services. Actual
wrapper4F8760 and upper JAL4A326C/return instructions execute; their earlier
caller frame state is supplied. UI services are bounded, not a hardware UI test.

Both factories' mutual exclusion, separate-stack SC conflicts, preserved
quarantine and continued in-flight startup after an initializer fault pass.
The other factory's frame stamp cannot release this claim. Missing redirects,
violated callee ABI and unguarded escaped handlers remain explicit limits.
