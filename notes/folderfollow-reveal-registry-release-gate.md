# Constructor-scoped raw-release propagation, not publication rollback

2026-10-28. This optional offline successor to the
[explorer failure exit](folderfollow-reveal-explorer-failure-gate.md) closes a
specific masked-result gap. Native registration4389E0 previously forcedV0 to
zero after its release callback, even if the actual raw registry release had
failed. The constructor status gates therefore continued UI/name work. This
separate composition propagates release uncertainty only for pinnedU and the
two exact native constructor registration callers43AE94/43B038.

Publication already happened before release. A reported error does not remove
the node, undo owner/history effects, revoke escaped aliases, retain any graph,
prove mutex ownership or permit retry/free. No cleanup, extra unlock, rollback,
whole-instance quarantine, installer or player operation is introduced.

## Four phases in the same private native registration frame

The native40-byte registration frame has three non-home scalar locals10/14/18.
The acquisition receipt already uses all three; they are not simultaneously
available as a second witness. Reuse begins only after publication consumed
that receipt: its observer executes the final native link store, reads and
clears the acquisitionTAG before quota/history/callback branches, and completes
all synchronous observers before native438A60. The native438A60..438A7C tail
does not read those locals. The new protocol is restricted to constructor
callers, not the explicit checked-capture wrapper route.

| Native offset | Release-phase meaning |
| --- | --- |
| 10 | Fresh SELECTED, ENTERED or CAPTURED tag |
| 14 | Actual raw status, initially FFFFFFFF |
| 18 | Exact raw-wrapper SP, initially zero |

At438A60 selection classifies savedS0=pinnedU and native savedRA at+24 equal
to43AE94 or43B038. It first clears the new tag, initializes statusFFFFFFFF
and rawSPzero, then selects only actual savedT9=437DA0. A different callback
still executes through the inherited observer; missing fresh evidence later
denies constructor continuation without claiming to undo that callback.

At raw-call site466DC8 the two saved return frames must identify the exact
registration release chain. With raw-wrapperSP=W, W+1C is437DB0, W+3C is438A68,
and native registrationSP=N=W+40 (hex). Only after those gates may the native
caller and witness be read. A fresh SELECTED tag, initial status/rawSP and
the actual saved raw argumentA0=R and callbackT9=437DA0 permit ENTERED and
record that exactW. A later sharedU+13C reload cannot reconstruct this argument.

At466DD0 actual rawV0 is captured before masking. The bridge requires the same
frame chain, constructor caller, ENTERED tag, exact recordedW and actual saved
returnRA466DD0. Post-serviceA0/T9 are caller-clobbered and are not consulted;
no controller or graph is reread. The actual status is stored separately from
CAPTURED, soFFFFFFFF is an observed error, not a missing-witness sentinel.

At438A68 completion consumes the tag once. It requires CAPTURED and recorded
W=N-40 before reading the status. Rawzero retains native success. Observed
nonzero returnsV0=FFFFFFFF andV1=that exact32-bit status. Missing/incoherent
evidence returnsFFFFFFFF/zero. This is an explicit constructor-scoped release
outcome, not a normalization of native allocation failure, arbitrary callbacks
or other release APIs. The native constructor still returns its saved engine
through the preceding status-stop epilogue; the selected explorer still uses
its separate existingNULL exit. V1 is not used as a classifier by those gates.

## Preserve the independently entered native epilogue word

The completion pair is `438A68: moveV0,zero;438A6C: loadRA,+24(SP)`.
438A6C is also independently entered by native allocation-failure branch438A80
and the preceding acquisition gate. It cannot be replaced byNOP as a displaced
delay instruction. The new completion redirect preserves that literalLWRA at
438A6C as its jump delay, so both independent failure entries remain intact.

Thus complete's bridge receivesRA already restored by the original source
load. It classifies through native savedRA atN+24, not an invented incomingRA
value. Rawzero/foreign completion restores all architecture, performs the
original V0zero effect, and resumes438A70; denial restores all other registers,
sets the scopedV0/V1 result and also resumes438A70. The original nativeLWRA
executes once, rather than being erased or replayed twice. Registration's
allocation-failure missing-unlock defect is unchanged.

## Delegate existing observers without changing their native service ABI

The three earlier native release-hook sites438A60,466DC8,466DD0 now dispatch
through the new private witness bridges. Every route restores all30 non-SP
general registers andHI/LO before tail-chaining the exact preceding capture
observer entry. The inherited observer still performs each original native
effect/raw service once, using original438A68/466DD0 returnPCs. The bridge does
not make a second raw call, reconstruct a result or read shared state.

Explicit checkedGCAP/BCAP creation wrappers have a different native caller
continuation. They do not enter this constructor protocol, while the older
release observers retain their own fresh outer-wrapper state and checked API.
The retained `release_hooks` metadata continues to identify those old observer
entries for provenance; the final coherent-hook map explicitly gives the new
dispatcher overrides precedence at the three replaced sites.

The global466DC0 wrapper has154 encoded directJ/JAL callers. Four direct raw
unlock sites57E208,706D4C,708FAC,70B46C bypass it;466DC8 is the fifth direct
raw site. Their mere existence does not grant complete release or caller
coverage. Wrong controllers, other registration callers, unrelated wrapper
users, native teardown and computed routes retain their preceding behavior.
SavedPCs and tags are scope witnesses, not authentication of fabricated frames.

## Hard premises and remaining uncertainty

The native40-byte registration,32-byte callback facade,32-byte raw wrapper
and separate192-byte save frames must already be mapped, writable, retained
and independently nonaliasing with native/heap/shared/RX allocations. Saving
occurs before classification, including for rejected global-wrapper users.
Static fixed-data/legacy-entry/fullRX checks do not validate arbitrarySP,
establish object or mutex lifetime, prove available aggregate/transitive stack
or make invalid unwind safe. Ordinary service semantics and coherent redirects
remain premises.

A raw release error can leaveR held or can occur after release; neither outcome
permits an extra unlock or recovery. Native publication, resource/view aliases,
callback binding and earlier widget/controller mutations remain. No shared
history, owner, registry ring or graph is modified after the uncertain result
by this new layer. Constructor UI/name work is stopped for classified errors;
the selected explorer operation returnsNULL without reclaiming its partial
graph. Other outer callers may still act on returned engines orNULL results.
Whole-instance caller isolation, retention, rollback and cleanup remain false.

All new and inherited redirects must be coherent. Missing/replaced selection,
raw-call, raw-return, completion or earlier acquisition/continuation hooks are
not an arbitrary-partial fail-closed installer protocol. A diagnostic fresh
tag does not authenticate stale/forged native stack contents or globally revoke
escaped aliases. Active scrolling and native worker/UI integration stay disabled.

## Separate composition and evidence

`reveal_registry_release_gate_stage.assemble` takes the same11 canonical
addresses and bounded options. It protects the appended completeRX through the
parent explorer stage's strict zero-default `following_code_bytes`, without
appending that advertised tail twice. It checks the exact three preceding
capture-hook overrides before replacing them and adds native completion438A68.
The output distinguishes21 native pairs and the inherited one generated
explorer splice,22 coherent pairs total. No saved image is rewritten or installed.

All17 prior default compositions retain their hashes, including explorer87,168
bytes with SHA-256
`540034a7349e240a95047fbb39b01a48dc8379669f1510d53c59e64992c888e9`.
The new composition is89,140 bytes:87,168 guarded prefix bytes plus1,972
release-gate bytes. Its SHA-256 is
`03ec46d436914eef93a8aa118496608d59df4539926dc6272ff81449e50687de`.
Completed serial checks are recorded in [status](status.md). Metadata records
constructor_registration_release_gated=True and
registration_release_failure_propagated=True while keeping
native_callers_isolated=False,raw_release_proven=False,
native_lifetime_proven=False andpartial_graph_cleanup_proven=False.

Source contracts use the preserved7,133,528-byte02fd image, SHA-256
`02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87`.
They pin the independent438A6C entry, native frame/return chain, safe phase
ordering of local reuse, exact legacy delegation, bounded154/five-site census,
private-only protocol, static configuration/fullRX and all prior hashes.
Execution remains bounded native/service substitution, not hardware scheduling,
mutex ownership, graph lifetime or cleanup proof. Hardware is UNTESTED.
No device/network operation, launch, reboot, installation, commit or push is
part of this step.

Verification completed2026-10-29:60 new serial checks and41 affected-parent
checks pass. The new fixture caches only exact deterministic assembly outputs,
with deep-copied metadata and exception-safe restoration; native execution and
each invocation's state/results remain uncached. Cached/uncached equivalence,
the direct source contracts and all remaining limitations are recorded in
[status](status.md). The full project suite and hardware were not rerun.

A separate [destructor continuation successor](folderfollow-reveal-destructor-continuation-gate.md)
adds a late caller-local stop after the explorer's name-delete call. It does
not reclaim an abandoned constructor graph, undo earlier teardown or cover
delete's masked raw-release result. This stage's strict zero-default
following_code_bytes now protects the appended RX without appending it; its
89,140-byte/03ec46d4... default remains unchanged.
