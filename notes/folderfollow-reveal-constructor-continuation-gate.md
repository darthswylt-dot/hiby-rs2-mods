# Scoped constructor registration-result stops, not caller isolation

2026-10-28. This optional offline successor to the
[registry acquisition gates](folderfollow-reveal-registry-acquire-gate.md)
checks the otherwise ignored registration result in both native constructors.
A genuinely classified nonzero result bypasses that constructor's local
UI/name continuation and enters its existing engine-return epilogue. Higher
callers still receive the engine pointer. This is not whole-instance isolation,
native cleanup/rollback, release certification, a lifetime lease, safe retry/free
authority, an image builder or a player installation. No device operation occurs.

## Exact sites and a private architectural decision

| Constructor | Replaced UI-call pair | Original UI return | Stop at stock epilogue |
| --- | --- | --- | --- |
| First43AD00, native frame136 | 43AE94/43AE98 | 43AE9C | 43AEA8 |
| Second43AF00, native frame128 | 43B038/43B03C | 43B040 | 43B04C |

Both replaced pairs are `jal519FA0; A0=S1`. At either gate the complete non-SP
general-register architecture and HI/LO are saved into a separate192-byte frame
before any scope check. Classification then reads only that private snapshot's
saved S1, RA and V0. It does not read U, a native object, the saved engine at
native SP+50, native registration witness locals or any shared journal. V1 is
saved/restored but never interpreted as a raw status or a missing-result marker.

Only saved S1 equal to pinned U **and** saved RA equal to the corresponding
registration return (43AE94 or43B038) classify an actual matching registration
return. The native registration calls are43AE8C/43B030, each with its original
`A1=SP+50` delay slot. A classified nonzero saved V0 takes the stop path. Zero
V0, another U, or another RA takes the original forward path. These scalar
scope tests are not authentication of fabricated invocations or forged frames.

Stop restores all saved registers and HI/LO, restores native SP, and jumps to
the stock epilogue. No new service, cleanup, unlock, name/graph lookup, UI call,
shared write or retry occurs on that path. The stock epilogue loads its saved
outer RA, loads the engine scalar from native SP+50, restores native callee
registers and unwinds136/128 bytes. The returned V0 is therefore still the
saved engine, not registration failure, NULL, a new owner handle or a normalized
raw-error diagnostic. This deliberately preserves the native return ABI without
claiming that higher callers safely handle an unsuccessfully registered engine.

Forward restores the same architecture, then recreates the displaced call's
original RA43AE9C/43B040 and delay effect A0=S1 before transferring to519FA0.
It does not expose a relocated gate return address to that opaque native callee.
The subsequent saved-engine load and name call437EE0 remain unchanged.519FA0
can itself change widgets through8B43C0 and relookup engines through43A0C0;
it is not a harmless fixture return in the real native image.

## Important unchanged cases

The first constructor's missing-resource and failed-validation branches still
reach43AE94 without having called registration. Their saved RA comes from the
earlier resource/validation call, not43AE94, so they forward the old UI/name
continuation and retain its NULL-engine dereference. Engine allocation returning
NULL likewise skips registration in both constructors and forwards the old
NULL-fault path; the gate does not invent a safe failure return.

The second constructor's missing-resource and failed-validation branches are
different: they already go to43B04C/43B050 and return the zero saved engine
without passing through this gate. That existing distinction is preserved.

The preceding acquire gates can return a nonzero registration result before
node allocation/publication after an incoherent or nonzero acquisition witness;
this new layer stops only the matching constructor's immediate continuation.
Registration allocation failure can also produce a nonzero V0 with an older,
undefined or service-clobbered V1. The new gate consequently tests V0 alone and
does not reinterpret V1 as a globally normalized error ABI. The native
allocation-failure branch still skips registry unlock; there is no repair here.

Raw registry **release** is still masked to zero by the native facade, and
4389E0 also forces its successful-body result to zero. A raw release error can
therefore still return V0=0 and forward UI/name work. Historical checked release
observation elsewhere in the composition does not make this constructor gate
an end-to-end release-error barrier. If the preceding acquisition gate is
omitted, the native body can likewise publish links after a masked raw acquire
error and later return zero; a post-registration status check cannot veto those
already performed native effects.

Pinned source has13 encoded direct calls to the first constructor and46 to the
second. These callers are not isolated or redirected by this step. For example,
the explorer at492918 still stores the returned engine atV+CC and enables it.
Encoded J/JAL and conservative relative-branch inventories also find no incoming
target to either replaced delay instruction43AE98/43B03C. Neither census covers
computed JR/JALR targets, aliases, runtime changes, fabricated returns or arbitrary
partial activation. All inherited redirects and both new pairs must be coherent;
the local hook map is not an installable fail-closed activation protocol.

## Hard stack, allocation and continuation premises

The original native prologues have already written their136/128-byte frames.
The gate's192-byte architectural save also occurs before classification. Each
native frame and its corresponding private save frame must be genuinely mapped,
writable, retained and independent of fixed/native/heap/RX allocations; sufficient aggregate and
transitive service stack is a hard premise. Static address declarations and
scalar U/RA checks provide no dynamic malformed-SP, wrapping, mapping or lifetime
preflight and do not make an invalid native unwind safe.

Strict static configuration excludes the full28C-byte controller,24-byte R,
extra fixed data, pinned native RX and complete generated RX from overlap.
Those exclusions change configuration validation, not runtime frame handling.
No mutex allocation, retained native bundle, already escaped worker alias or
resource graph is inspected or protected by this new fragment. Earlier native
mutations and all independent cleanup paths remain outside its scope. Synchronous
whole-instance coordination after uncertain raw results remains an external
obligation; returning an engine is not evidence that such coordination happened.

## Separate opt-in composition and evidence

`reveal_constructor_continuation_gate_stage.assemble` takes the preceding
canonical11 addresses and bounded options. It appends992 bytes after the86,120-byte
acquisition-gate prefix and advertises all20 coherent instruction-fetch pairs:
the previous18 plus43AE94 and43B038. It introduces no new shared allocation,
native caller redirection, stock queue producer, renderer or active folder-follow.
The parent acquisition stage's strict aligned-integer `following_code_bytes`
protects but does not append an advertised tail; default zero preserves its
preceding bytes, labels and hooks. All15 preceding default compositions retain
their exact hashes, including86,120 bytes with SHA-256
`a4c3ec89cc4a7b01b2f385abfb5daf2146694a48a03118aaaaea756b524a4041`.

At those canonical receipt/binding/owner/U/R/P/CODE addresses, lifecycle01F3A000,
Q01FF2000, T01F20700 and fault01F20800, the new composition is87,112 bytes.
SHA-256:
`c13d8485f4644b90c1dd2029877a13626cd5d7231e6fa65c54ff6ec87f208dd8`.
The full outer protected RX includes the entire prefix and new tail. Scope flags
are constructor_status_continuations_gated=True and
constructor_engine_return_preserved=True, but native_callers_isolated=False,
raw_release_proven=False and native_lifetime_proven=False. Inherited historical
release/consumer labels are observations, not contradictory lifetime guarantees.

Contracts use only the preserved7,133,528-byte02fd vendor source, SHA-256
`02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87`.
They pin native words, scoped classification, exact replay/unwind/engine ABI,
unchanged skipped-registration/masked-result paths, bounded encoded inventories,
all20 coherent redirects and the preceding default hashes. Execution fixtures
remain bounded native/library substitutes, not OS scheduling or retained-object
proof. [Status](status.md) records completed serial verification counts. This
step performs no image build, installation, launch, reboot, device/network action,
commit or push; hardware remains UNTESTED and active scrolling disabled.

A separate [explorer failure successor](folderfollow-reveal-explorer-failure-gate.md)
now splices only this first gate's generated stopped restore pair. On the exact
492920 outer return it retargets the current private constructor return slot,
allowing the unchanged stock constructor unwind to reach the stock explorer
NULL exit. Other callers keep this stage's engine-return behavior. Earlier
resource/view aliases and mutations remain, and there is no cleanup or complete
caller isolation. This stage's strict zero-default following_code_bytes now
protects but does not append a reserved tail; its 87,112-byte/c13d8485... default
remains unchanged.
