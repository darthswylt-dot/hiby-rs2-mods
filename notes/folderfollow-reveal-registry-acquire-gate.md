# Bounded registration and name-delete acquisition gates

2026-10-28. This is a separate offline extension of the
[historical birth consumer](folderfollow-reveal-birth-consumer.md). Two explicit
instruction-fetch redirects refuse entry to selected native work unless the
same invocation captured actual raw-zero acquisition of the pinned ordinary
registry mutex R. This narrows two masked-failure paths; it does not isolate
their callers, certify native lifetime or connect the queue to painting.
No firmware image, installer or player operation is supplied.

## Exact placement and admission

| Gate | Replaced pair | Work refused before admission |
| --- | --- | --- |
| Registration | 438A10 allocator JAL and its size-28 delay slot | Native node allocation and subsequent publication |
| Name delete | 4395D4 first ring-head load and 4395D8 branch | Ring traversal, name lookup and unlink/free inside this routine |

The native lock callback has already returned at each gate. Its facade zero
is insufficient: the ordinary stock wrappers overwrite the actual raw result.
The new gate reads only the current invocation's retained native frame and its
private architectural-save frame. It does not reread U's fields, follow the
registry or engine graph, consult shared history, call a service, or guess an
unlock while deciding admission.

Registration requires the saved S0 scalar to equal pinned U, the existing
receipt TAG at native SP+10 to be CAPTURED, PTR at +14 to equal pinned R and
the actual raw acquisition status at +18 to be zero. Name deletion requires
saved S5 to equal pinned U and its own retirement TAG/raw locals +10/+14 to
be CAPTURED/zero. The two CAPTURED namespaces are distinct. They are genuine
per-invocation witnesses under coherent entry/raw-call/raw-return hooks, not
authentication of forged native frames or a substitute for initialized,
retained ordinary-mutex semantics.

The gates leave these witness locals unchanged. The existing publication and
retirement observers can still consume the same invocation's evidence later.
All general registers and HI/LO are saved before checking locals. Successful
admission restores the complete gate-entry architecture before native replay.

Registration recreates allocator entry with the original RA 438A18 and A0=28,
then transfers to the actual 4669E0 allocator. It does not substitute a relocated
return address. Delete replays `lw s0,+34(s5)`, the original S0/S3 branch and
`lw s1,0(s0)` delay instruction exactly once. It continues at 4395F4 on the
taken path or 4395E0 on fallthrough, never executing native 4395DC twice.

## Denial is local, not whole-instance quarantine

A missing or incoherent witness returns FFFFFFFF/0. A coherent CAPTURED
nonzero actual acquisition status returns FFFFFFFF/exact_status. The latter
includes FFFFFFFF as a possible real raw status; it is not a missing marker.
Only these gate-denial paths define this diagnostic V1 result. After an
admitted native body runs, its older ABI still applies: in particular allocator
failure can return V0=-1 with an undefined or service-clobbered V1. Testing only
V0=-1/V1!=0 is therefore not a globally normalized raw-error classifier.

Denial uses only retained private/native frame storage, no service, native
graph load, shared journal mutation, guessed unlock, cleanup, retry or rollback.
Registration jumps to its ordinary non-unlocking epilogue at 438A6C. The stock
delete epilogue tail-calls U's unlock callback, so denial cannot use it. Instead
the gate restores the genuine 56-byte native frame's saved callee registers
and RA and returns directly to its caller without selecting an unlock.

An uncertain raw result can imply uncertain mutex ownership. Synchronous
coordinated isolation of the whole combined instance remains an external
requirement, not implemented by local return or a late shared fault write.
Existing checked creation/BCAP wrappers have their own return ABI and do not
automatically preserve the new gate's V1 diagnostic.

The pinned native source has 56 encoded direct name-delete callers. They
ignore its result; 54 immediately continue independent resource cleanup. Both
encoded registration constructor callers also continue without testing the
registration result. The gate does not stop that outer work or undo mutations
that preceded deletion. It must not be described as safe native continuation,
an end-to-end raw-error quarantine or a complete deletion transaction.

## Hard frame and coverage premises

The genuine native prologues have already written their 40-byte registration
or 56-byte delete frames before these gates. Each bridge then saves into a
separate 192-byte architectural-save allocation before validation. Fully
mapped, retained writable frames, sufficient nested/transitive service stack,
and independent nonaliasing of those frames with every fixed/native/heap/RX
allocation are hard entry premises. There is no runtime malformed-stack
preflight or promise to unwind invalid, wrapped, unmapped or aliased frames.

Strict configuration excludes pinned U's full 28C-byte extent, R's 24 bytes,
declared extra fixed data, native RX and the complete generated RX from static
overlap. Extra fixed extents affect layout validation only: they emit no
dynamic frame guards and cannot prove allocation mapping or ownership.
The preceding raw-return observer can already read controller bindings before
this new gate; placing a gate here does not retroactively remove those reads.

The native registration allocation-failure branch still skips unlock; the gate
does not repair it. Controller teardown 43CB20 and both outer unlink paths
4E3F48/51A3E8 remain outside these two gates. Escaped aliases, opaque callbacks,
missed events, raw release errors and same-address reuse remain separate
coverage/retention problems. Historical state 1 remains NO_RETIREMENT_OBSERVED,
not LIVE; state 2 remains RETIREMENT_SELECTED, not DEAD or proof of free.
There is no new lease, current-incarnation query, free authority or painting
permission.

Contracts use the preserved local 02fd vendor source, size 7,133,528, SHA-256
`02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87`.
They pin displaced native words, both branch outcomes and the separately
replayed delete delay. The encoded J/JAL and conservative relative-branch
census checks incoming targets to both pairs and 4395DC. Absence in that bounded
census does not prove absence of JR/JALR, computed or runtime-patched targets.
All preceding coherent redirects plus both new gates must participate;
arbitrary partial activation is not a fail-closed installation scheme.

## Separate opt-in composition

`reveal_registry_acquire_gate_stage.assemble` takes the same canonical addresses
and bounded options as the historical consumer. It appends only the two-gate
fragment and advertises all 18 coherent fixture hook pairs: the preceding 16
plus 438A10 and 4395D4, with no source-site conflicts. No new shared allocation,
stock queue producer, consumer worker or UI hook is added.

The consumer's new optional `following_code_bytes` reservation extends exact
generated RX protection through all inherited guards without appending those
reserved bytes. Its default zero preserves the complete preceding 85,044-byte
consumer and SHA-256
`765759c2a2ee7a29a2f6d7f0b9af90496d4ef0510a5d1fe809c6bb6fbd9db71f`;
all fourteen preceding default composition hashes remain unchanged.

At the preceding canonical receipt/binding/owner/U/R/P/CODE addresses,
lifecycle 01F3A000, Q 01FF2000, T 01F20700 and fault 01F20800 with 40 native
allocated slots, the new composition is 86,120 bytes: the guarded 85,044-byte
consumer prefix plus the 1,076-byte gate core. SHA-256:
`a4c3ec89cc4a7b01b2f385abfb5daf2146694a48a03118aaaaea756b524a4041`.

The stage explicitly reports registration_and_delete_acquire_gated=True,
native_callers_isolated=False and native_lifetime_proven=False. These are
scope labels, not hardware certificates. Fixtures use bounded service/heap
substitutes and genuine pinned native instructions; they do not establish OS
scheduling, real pthread behavior or complete lifecycle coverage. Active
scrolling remains disabled and hardware is UNTESTED. Current serial totals are
recorded in [status](status.md).

A separate [constructor continuation composition](folderfollow-reveal-constructor-continuation-gate.md)
now adds two scoped stops after genuine registration returns. A nonzero native
status skips that constructor's local UI/name continuation but still returns
its saved engine scalar; higher callers remain unchanged. This does not turn
this earlier acquire-only stage into caller isolation. Its optional strict
zero-default `following_code_bytes` now protects appended RX without appending
it; the 86,120-byte default and a4c3ec89... hash remain unchanged.
