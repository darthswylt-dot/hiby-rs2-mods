# Callback-to-renderer receipt association source boundary

Offline source audit, 2026-10-22. No device access, deployment, launch, reboot,
active scrolling or retained UI action is authorized. Hardware is UNTESTED.
The explicit preceding queue transport already widens generic nodes to 20
bytes; this next association must not change that decision or rewrite any
preceding builder/default image.

Pinned reference: `artifacts/import-20261001/hiby_player_02fd.bin`, 7,133,528
bytes, SHA-256
`02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87`.
`scripts/test_reveal_renderer_transport_contract.py` verifies the source and
fails rather than skipping for a different/missing reference. Addresses and
offsets below are hexadecimal; native frame sizes use explicit `0x` prefixes.

## Two new observations, without changing the old renderer root

| Site | Original pair | Resume |
| --- | --- | --- |
| Outer `438248/24C` | `00C0A021 / 00E08821` (`s4=a2; s1=a3`) | `438250` |
| Renderer association `49076C/770` | `AE113B50 / 8E4201BC` (store cache descriptor; load native P+1BC) | `490774` |

The earlier lineage root hook at `490758/75C` remains unchanged, as do original
`490760` argument move, `490764` native call and its `490768` delay load. The
new renderer observer runs after that call, not by inserting another native
call or changing its return PC. Before replaying its pair it must preserve
the actual native v0 result, all other live volatile state and HI/LO, and later
replay the native store/load exactly once. Its own private save frame is
separate from native frames and outgoing arguments.

An OUTER receipt names the exact already-published LQTR CALLBACK ID. A RENDER
association receipt names that OUTER ID and the exact already-published LNRG
RENDER root ID. These IDs and private immutable ancestry are the join keys.
Native C/W/V/P, descriptors or frames are only consistency fields, never an
address registry or substitutes for a missing receipt. There is no new queue
tail read, native name lookup, V/P resolution or UI operation.

## Outer hook: bind the actual callback invocation

The native outer frame O has size 0x200 and saved RA O+1FC. Before the new hook,
the prologue saves incoming callback s0/s1/s2/s3 at O+1D8/1DC/1E0/1E4. Those
values are callback C, resolved W, original callback input descriptor and
controller. Incoming fp is saved at O+1F8 **before** `438240` replaces fp with W;
that saved incoming fp is the queued node on the classified chain, not W.

The C/a3/controller guards precede `438248`. At this pair s0=C, fp=W and
s3=controller loaded natively from C+50; a2 is the pointer to callback coordinate
locals and a3 is the callback's original input descriptor. Replay `s4=a2;
s1=a3` once and initialize O+14 to zero. Let B=O+200 be callback native SP.
Before reading its private carrier, a bounded candidate requires:

1. `[O+1FC] == 439F98`, the original callback-to-outer continuation.
2. `[O+234] == 8B40EC`, the original queued helper-to-callback continuation.
   The full-redraw continuation `8B4998` is unsupported.
3. a2==O+218 (B+18), C matches saved callback C O+1D8, W matches O+1DC,
   input a3 matches O+1E0, and current controller s3 matches O+1E4.
4. Read B+14=O+214 only after the frame gates. Validate the exact private
   LQTR CALLBACK receipt and its native frame B and engine C; do not obtain a
   replacement ID from C, W, a descriptor, name or a current revision sample.
5. Publish a distinct private OUTER receipt bound to O, B, C, W, input,
   coordinate pointer and controller. Store only that new ID at O+14.

Unknown source/zero parent leaves zero while original rendering continues.
Private fault must not suppress the native callback or grant a new UI cause.
These are invocation-local numeric checks, not evidence of a retained native
owner or an atomic relationship between the callback's two resource lookups.

The complete inspected outer body has no direct access or formed address at
SP+14. Native fifth outgoing arguments occupy SP+10, and local buffers begin
at SP+20 or above. SP+14 is not universally free memory: correct actual callee
ABI, bounded native buffers and absence of unrelated alias writes remain
premises. The apparently unused upper SP+1B4 is not an alternative: the native
`sprintf("canvas_%s", name)` buffer starts at SP+140.

## Renderer hook: associate the actual existing root

The outer call at `438740` passes a0=W=fp, a1=C=s0 (in its original delay) and
a2 from outer SP+1B0. That last value is a newly created cache-canvas descriptor,
not the immutable queued cause. The child null-guards all three arguments,
allocates its 0x30-byte native frame R and saves original RA at R+2C.

The child's native selected item yields P in s2 at `490744`. `459340(P)` is only
a null guard followed by the native P+7C read in its return delay; its result
V moves into s0 through the old renderer pair at `490758`. The existing private
root is published there with STACK=R, VIEW=V, PANEL=P, JOB=V+38A4 and SITE=490758.
Root ID is already stored in native R+14 when the new `49076C` hook is reached.

At `49076C`, after original call `490764` and delay `490768`:

| Evidence | Native source |
| --- | --- |
| V, P | s0, s2 |
| C, W | s3, fp |
| Current cache descriptor | s1 and outer SP+1B0 = R+1E0 |
| Saved outer C | R+18 |
| Original callback input descriptor | R+1C (saved outer s1) |
| Controller | R+24 (saved outer s3) |
| Coordinate pointer | R+28 (saved outer s4) |

**Live s4 is no longer the coordinate pointer**: the original call delay
`490768` has loaded V+DC into it. Likewise live s0 is now V, not original W.
The renderer itself does not modify fp; maintaining W in fp depends on the
normal ABI of its actual native callees. No V/P/descriptor reread is needed
to record these scalars.

For O=R+30 and B=R+230, required ancestor gates are ordered:

1. Own saved RA `[R+2C] == 438748` before outer-frame reads.
2. Outer saved RA `[R+22C] == 439F98` before callback-frame reads.
3. Callback saved RA `[R+264] == 8B40EC` before consuming an ancestor carrier.
4. C/s3==`[R+18]`, cache/s1==`[R+1E0]`, and the exact private OUTER receipt
   from `[R+44]` binds frame O plus C, W/fp, input R+1C, coordinates R+28 and
   controller R+24. Its published ancestry names the exact earlier CALLBACK;
   a reused address or a fresh callback timestamp does not recover this link.
5. Validate the separate explicit root ID read from R+14 as private kind
   LNRG.RENDER, STACK=R, VIEW=s0, PANEL=s2, JOB=s0+38A4, SITE=490758. No INITIAL
   root, foreign renderer frame, missing publication or guessed root is admitted.

The existing R+10 original-entry revision and R+14 lineage root are occupied.
This association must read them as needed without replacing either, allocating
another native scratch word or changing the old lineage record. Its own
separate private journal provides the new cross-ledger association. O+14 at
R+44 and callback carrier B+14 at R+244 are distinct ancestors, not child slots.

## Bounded control-flow result and limits

The encoded named-entry CFG shows `438248` dominates cache creation `438724`
and child call `438740`. It shows old root site `490758` dominates new observer
`49076C`, which in turn dominates both normal enqueue sites `49080C/490878`.
It does not prove every indirect/native entry, exception or callee behavior.

A global aligned executable-word scan includes J/JAL, ordinary/likely,
REGIMM and COP branches. It finds no encoded target to either word of either
new hook pair. The only external direct edge into the inspected outer body
is `439F90 -> 438200`. No aligned file-backed pointer literal equals any of the
four hook words. Computed entries, opaque aliases, lifetime races, unwind and
arbitrary corruption remain outside those bounded facts.

This establishes a candidate path for attaching the original queued receipt
to an actual renderer lineage root. It does not establish original UI/playback
freshness, native C/W/V/P/job retention, complete writer/cancellation coverage,
settled contents, coherent acquisition, a safe UI transaction or authorization
to scroll. Historical equality of private revision samples must not become a
native ownership lease. Unsupported and full/synthetic paths remain unknown;
existing row/frontier/scope rejections must not be repaired by the new join.
