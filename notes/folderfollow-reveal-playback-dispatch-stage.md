# Passive playback callback-dispatch intent stage

2026-10-23. Local offline diagnostic build, **not an autoscroll fix or a
deployment proposal**. No player connection, install, launch, rearm, signal,
reboot, new timer, queue injection or UI setter. Hardware remains UNTESTED.
Changes are local/uncommitted; no commit, push or network action occurred.

## New source distinction: general action1 is not fast event11

The [previous cause audit](folderfollow-reveal-playback-cause-boundary.md)
separated player event messages from selected staged media. The new pinned
`test_reveal_playback_dispatch_contract.py` follows another asynchronous
boundary and distinguishes two materially different routes:

- Fast's player event11 (`42CC18`, handler `42E32C`) yields
  `4BAC80(0,0,0)` for its zero event parameter, or `(5,1,0)` for the nonzero
  branch. Explorer callback `490980` admits **only action1**, immediately
  returning for actions0/5. This route is therefore not itself an established
  Files reset, reconcile or paint notification. Now Playing's action0 callback
  instead sets a lazy-refresh flag; its later loop reads property24 again.
- General commit separately calls **`4BAC80(1,B+38,0)` at `42D614`**.
  Explorer's action1 branch can call `43C860` at `490A08` (or `490A58`),
  producing a 32-byte paint request and calling `439900` at `43C8A4`.
  That helper appends to object+128 under its +284/+288 method bracket.
  This is a concrete conditional route to a paint-request list, not a direct
  reset/reconcile, completed paint or bound LQBR request.

Action sender `4BAC80` resolves the **current** controller and appends a
16-byte `[1,parameter1,parameter2,action]` record at `4BACD8`. Its worker
`4BA880` selects FIFO element zero, resolves current controller again and
fans out to name-resolved resources through resource+150 at `4BAA60`.
Explorer's binding to `490980` is installed at `4928B0`. These operations
carry no additional immutable playback/notification parent. Dropping registry
brackets and resolving names again does not retain a controller/resource or
prove that a later paint still describes the earlier media operation.

**General action1 is queued BEFORE the optional BA0 call.** The new BA0
journal below must never be assigned as its causal parent by reservation
order, matching frame, current track or coincident ID. Fast and general still
have different source order and eligibility. Universal Next/autoplay cause
coverage and immutable delivery-to-paint transport remain unproved.

## Exact optional callback boundary, not a late current-state sample

The actual B+BA0 registration/target remains unresolved. A further bounded
audit found an interior pointer escape B+B90 through `4292F4 -> 64ADBC`
command20B to an unresolved dynamic method. It neither proves a BA0 write nor
excludes one. Initialization and absence of a literal field store do not prove
that the slot stays null. The diagnostic therefore observes the **already
loaded t9 target of the actual invocation**, not an inferred registration.

Only these two additional source pairs are changed:

| Original source pair | Kind | Original native continuation |
| --- | --- | --- |
| `42CC0C/42CC10`: JALR ra,t9; addiu a1,s4,-11160 | FAST | `42CC14` |
| `42D6A0/42D6A4`: same pair | GENERAL | `42D6A8` |

The original target loads, nonnull branches and context loads remain intact.
A zero target therefore follows its original skip branch without capturing
or dispatching. On the admitted source path, the wrapper:

1. Replays the original delay's a1 computation once. It uses s4, not RA/t9.
2. Reconstructs RA=original site+8, then saves the full original target-entry
   volatile state and HI/LO. Native SP and callee-saved registers are retained.
3. Copies seven register-derived scalars into its own metadata block and calls
   only the private append-only recorder. It does not reread B+BA0/B98 or read
   callback, context or descriptor memory.
4. Restores that state and SP, then performs **JR t9; NOP**. The callback sees
   its original RA/arguments/t9 and returns directly to its original native
   continuation, with no observer frame retained across the callback.

Dispatch is unconditional after observation. Zero/failed publication,
exhaustion, bad diagnostic bindings and permanent journal faults cannot veto
the original call, change its arguments or synthesize a success result.
There is deliberately no post-callback receipt or completion claim.

This preserves the bounded normal target-entry ABI, not arbitrary timing,
exception/instruction-mode behavior, self-inspection or native data coherence.
The original JALR instruction is relocated, not left at its original PC;
odd/unknown targets are captured as raw words, not validated or dereferenced.
Extra private recording changes pre-call timing. D remains borrowed mutable
global media; freezing its **address** does not copy or retain its identity.

## LPDI journal and strict decoding

`reveal_playback_dispatch_mips.py` emits a separate 16-byte header plus
64-byte records. Its `capture(kind, owned_metadata)` copies
`[frame,site,return_pc,target,context,descriptor,player]` once. It validates
the two known site/kind/return combinations, aligned nonzero frame, fixed
B=`ADD368`/D=`ADD468`, and nonzero target. Target/context otherwise remain
uninterpreted words, including zero context or odd/unmapped target values.

Each LPDI record contains magic, kind, parent=0, origin=self, its nonreused
sequence, those seven scalars and four zero reserved words. A bounded
eight-attempt LL/SC allocator never wraps/reuses IDs, permanently faults on
loss and publishes magic last. A racing publication cannot erase global
fault. Reserved but unpublished records are rejected by snapshot decoding.
The core touches only private BSS, wrapper-owned metadata and its own frame;
there are no native calls, clocks, pointer registries or native frame carriers.

`decode_reveal_playback_dispatch.py` accepts only an exact already-owned raw
LPDI buffer. It rejects bad sizes/capacities/header/allocator, dirty unused
slots, missing magic, invalid sequence/self-origin/site/return, unknown schema
and reserved data. It reports **CALL_INTENT only**: not target arrival,
callback completion, playback publication, coherent identity, a current BA0
binding or BIRTH parent. Empty/partial/full buffers never prove coverage.

`decode_reveal_playback_dispatch_stage.py` decodes the unchanged renderer plus
request-age prefix and the independent LPDI tail. All old rows, windows,
operations, age assessments and refusal reasons remain unchanged; the new
format adds a separate observation and four false proof flags. No LPDI ->
BIRTH/renderer/row join is invented, even for identical ID1 or frame/context/
target values. Every LPDI object says deny, all five authority flags remain
false and the old native/currentness/UI gates stay closed.

## Memory, artifact and exact verification

The separate builder reassembles the previous renderer stage at its new RX
address and appends the recorder/wrappers. Previous builder defaults and saved
images remain byte-identical. The earlier generic-node 16 -> 20-byte extension
is inherited unchanged; no additional native allocation or payload extension
is introduced here. This remains a real memory-pressure/timing experiment.

Default LPDI adds **65,552 private BSS bytes**. Peak additional recording stack
is 240 bytes (wrapper90 + core60), released before native callback entry.
The complete intermediate has 1,065,104 private bytes at BD4000, LPDI at
CC8080 and 24,532 separate RX bytes at CE0000, with no RWX segment. There are
37 hook pairs, including two narrowly declared indirect JR-t9 tails. Shared
verification admits those tails only at their exact new labels; every prior
external call, indirect append, native continuation and layout check remains.

Saved ignored local artifact:
`artifacts/hiby_player_1.4_sortfix_fullnav_wake_playback_dispatch_stage_v1_20261023.bin`,
7,167,956 bytes, SHA-256
`a9a6f02fd48a3b57e27e3bb19c9e8c2b8329b6602cc12988091dfbb98c2abe2c`.
It is deterministically verified against the pinned 7,133,528-byte reference
`02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87`.
275 normalized-original bytes differ, only in declared hook/stride/ELF spans.
No installer, launcher, runtime export policy or device transport was added.

The preceding renderer image is also exactly reverified with unchanged SHA
`f42fac46890dc2eadbeba88f90ce5b82857d3045752b974b15d04bef263d2244`.

## Verification scope and next causal boundary

All **101 focused checks pass** (13.707 s): 19 emitted-core checks, 30 strict
standalone decoder checks, 20 combined-prefix/decoder checks, 16 original
source contracts and 16 native-boundary/stage checks. They cover concurrent
reservation/publication and fault races, ABI and all-register/HI/LO comparison
against original JALR target-entry state, immutable loaded arguments after
global-slot changes, null skip, native continuations, synthetic callback return,
unconditional dispatch after fault/full/failed SC, nested callbacks, raw odd
targets without fetch, exact layout/build tamper refusals and prior hashes.

The instruction fixture intercepts the original JALR only **after** its native
target/RA/delay computation; relocated JR stops at the same pre-fetch boundary.
Synthetic callback bodies and two native continuation stubs are explicit test
substitutions. They do not prove the actual unresolved callback body, hardware
instruction mode, source lifetime, whole-player scheduling or UI success.
Independent source/builder/ABI and decoder/fixture reviews found no actionable
issue. Full regression results are recorded in [status](status.md).

Full repository regression: **1,704 tests pass, no skips** (290.486 s).
All 208 Python scripts compile and tracked/new text files pass whitespace
checks. An earlier run had one failure in the unchanged legacy normal-exit
launcher fixture, which uses a 25-ms mocked timer; its 24 isolated tests then
passed (18.461 s), followed by the clean full rerun above. Neither launcher,
test timer nor protection/refusal was modified to obtain that result.

The next meaningful cause receipt belongs to the **exact earlier action
record** and its selected delivery, not this later optional BA0 observation.
Its payload/copy/dequeue/removal/fanout and subsequent paint-request ownership
need explicit immutable IDs and lifetime/source audits. Unknown, coalesced,
removed, failed and unclassified paths stay unknown; current counters or raw
addresses cannot repair missing ancestry. Coherent playback/row publication,
complete invalidation/cancellation coverage and a retained UI transaction
remain separate prerequisites before active reveal can be admitted.
