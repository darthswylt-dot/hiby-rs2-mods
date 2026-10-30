# Destructor-scoped name-delete release propagation

2026-10-29. This optional offline successor to the
[destructor continuation gate](folderfollow-reveal-destructor-continuation-gate.md)
addresses that gate's masked delete-release counterexample. Native `4395A0`
tail-calls registry unlock after restoring and popping its frame. The raw
wrapper then forces V0 to zero, so a real unlock error previously reached
`493F4C` as apparent success and the destructor continued resource cleanup.
The new layer captures the actual result for that exact destructor call and
feeds an explicit nonzero result to its existing late continuation stop.

Registry unlink, name/paint-queue/engine/node frees and earlier destructor
effects can already have happened. This layer does not roll them back, fence
destructor entry, establish retention or provide safe cleanup/retry permission.

## A carrier in the still-live destructor frame

Let D be the genuine 1,208-byte destructor frame's SP, and N the name-delete
frame's SP. While deletion is active, `N=D-38` hex. After its native tail
unwinds 56 bytes, the callback facade uses `D-20`, then the raw wrapper uses
`W=D-40`. The old delete frame is no longer preserved: its former `N+14`
becomes raw `W+1C`, overwritten by saved return `437DB0`. Its former saved
outer return also becomes the facade's saved-return slot. Release evidence
cannot safely remain in the popped N frame.

The protocol instead uses three scalar words in the still-live D frame:

| D offset | Meaning |
| --- | --- |
| 14 | Fresh ARMED, SELECTED, ENTERED or CAPTURED tag |
| 18 | Actual raw status; initialized to FFFFFFFF |
| 1C | Exact raw-wrapper SP; initialized to zero |

These words lie beyond the ordinary four-word argument home area `D+00..0F`.
The full pinned native `493AC0..494A00` body has no direct load/store or stack
address construction for them. Passed buffers begin at `D+20`. The adjacent
`D+10` is deliberately avoided because native `494180` and `49483C` use it for
outgoing fifth arguments. This bounded nonuse and ordinary ABI cooperation
are separate from runtime mapping, aliasing and native lifetime premises.

## Five coherent phases preserve the native service ABI

1. **Begin at `4395C0`.** Before delegating the exact preceding retirement
   observer, saved A0 must equal pinned U and native saved return `N+34` must
   equal `493F4C`. With `D=N+38`, the layer clears its tag, sets status to
   FFFFFFFF and raw SP to zero, then writes ARMED. Initialization occurs before
   acquisition and the delete body, so reused stack contents do not supply a
   fresh release witness. The existing acquisition observer and denial path
   continue with their original native ABI.
2. **Select at `439658`.** This is the common native tail. The empty-ring
   branch enters it directly after loading T9 in its delay; no-match and
   successful-removal paths pass through `439654`. After scope checks, selection
   consumes ARMED and requires its initialized status/raw-SP values plus actual
   saved T9=`437DA0`. Only then does it write SELECTED. The displaced RA and S4
   loads execute once, and native restoration resumes at `439660`. The original
   tail still restores all callee state, sets A0 from S5 and jumps through T9
   with its original 56-byte unwind.
3. **Raw call at `466DC8`.** Preserved S1 must equal pinned U. The saved frame
   chain must be `W+1C=437DB0` and `W+3C=493F4C` before accessing `D=W+40`.
   A consumed SELECTED tag, initialized status/raw SP, actual saved A0=pinned R
   and saved T9=`437DA0` permit ENTERED and record exact W. A later U+13C
   reload cannot reconstruct the argument actually supplied to the service.
4. **Raw return at `466DD0`.** The same saved frame chain, exact recorded W,
   ENTERED tag and actual saved return RA=`466DD0` are required. The layer
   captures actual saved V0 before masking, stores status separately from
   CAPTURED and delegates the preceding constructor-release observer. It does
   not consult caller-clobbered post-service A0 or T9. FFFFFFFF remains a valid
   captured error value, distinct from absence of a capture.
5. **Complete at `493F4C`.** Saved S1 and RA identify this destructor return.
   Completion consumes the tag. An incoming nonzero V0 is preserved exactly,
   including V1; the earlier acquisition-denial path need not have reached
   release selection. For incoming zero, only CAPTURED plus recorded `W=D-40`
   permits status classification: raw zero preserves native zero, actual
   nonzero becomes `FFFFFFFF/exact_status`, and missing or incoherent evidence
   becomes `FFFFFFFF/zero`. The layer restores the remaining architecture and
   delegates the exact preceding destructor gate, which stops local cleanup on
   the propagated nonzero result without interpreting V1.

Every phase first saves all 30 non-SP general registers and HI/LO into 192
private bytes. Delegation restores the full original architecture, except the
explicit completion V0/V1 result on a newly classified failure. The original
raw return `466DD0`, facade return `437DB0`, callback return `493F4C`, SP and
callee state are preserved. No second raw service, relocated return PC, extra
unlock, graph lookup, shared fault write or native free is introduced.

The four delegated generated entries are distinct preceding RX: the retirement
delete-begin observer, the two constructor-release raw observers and the
destructor continuation gate. Constructor registration and explicit checked
capture wrappers retain their existing observer chain. The new final coherent
hook map replaces four existing native redirects and adds only `439658`.
Historical hook maps remain provenance and are not the final override map.

## Earlier effects and other routes remain outside this result

The selected `4395A0` body may already have unlinked the registry node at
`439618`, freed its name at `43962C`, destroyed its paint queue and engine,
and freed the node at `43964C`. A raw error can occur after release or leave
ownership uncertain; neither outcome justifies another unlock or a retry.
No result from this protocol proves successful destruction, repairs the
partially changed graph or revokes earlier escaped `resource+7C=view` aliases.

The destructor has also already performed closing, worker/private/shared
cancellation, callbacks, list destruction, controller stores, cache unlink
and purge/detach before this delete call. The existing late stop bypasses
later independent resource deletion and remaining view cleanup; it does not
undo any earlier effect or supply a policy before the first destructive action.

There are 56 encoded direct name-delete calls, 49 direct destructor calls and
154 direct users of the ordinary raw-release wrapper. Only pinned U's exact
`493F44 -> 493F4C` deletion receives this protocol. Other name-delete callers,
controller teardown, direct raw-unlock sites and opaque/computed routes remain
uncovered or retain their earlier masked results. Outer callers can continue
work after the destructor returns. The bounded encoded branch/J/JAL census
does not exclude computed entries, fabricated stacks or runtime patches.

All five new phases and inherited acquisition/observer/continuation hooks must
participate coherently. Fresh tags distinguish this invocation's phases under
that premise; they are not authentication and do not provide a fail-closed
installation protocol for arbitrary partial activation. In particular,
missing initial admission or missing final continuation can restore unsafe
paths. Synchronous whole-instance coordination remains external.

## Hard frames, static exclusion and opt-in composition

The genuine native 56-byte delete frame, 1,208-byte destructor frame, 32-byte
facade, 32-byte raw wrapper and every separate 192-byte architectural save
must be mapped, writable and retained for each frame's live use. Simultaneously
live frames must be independently nonaliasing with one another and native,
heap, shared and RX allocations. The popped delete frame is deliberately
reused by later calls; it is not required to remain disjoint or preserved
after its lifetime ends. Sufficient transitive stack, ordinary service/ABI
semantics, coherent buffers and genuine native entry are hard premises.
Saves occur before classification. Scalar U/RA checks do not validate SP,
mapping or lifetime or make fabricated/unmapped/aliased unwinds safe.

Static layout excludes U's full `28C` bytes, R's 24 bytes, declared extra
fixed extents and complete native/generated RX from overlap. All four legacy
entries must be distinct aligned generated RX preceding the new fragment;
the advertised complete RX must contain every delegate and all emitted code.
Extra exclusions add no runtime memory guard or allocation lease.

`reveal_delete_release_gate_stage.assemble` takes the preceding 11 canonical
addresses and bounded options. Strict zero-default `following_code_bytes` in
both parent and successor protects an advertised later RX tail without
appending it. The parent keeps its default 89,640 bytes and SHA-256
`996f66b14285bdb35490b4e4e2cbc380c2ed888a558323ea1828a58ebc246b1c`.
All 19 preceding default compositions retain their hashes. The canonical
successor is 91,940 bytes: the guarded 89,640-byte prefix plus the 2,300-byte
delete-release gate. Its SHA-256 is
`332b5cf381ecd46f117651638d992475b8ceed505721f66c8cc1eeecdba58364`.
Completed serial verification is recorded in [status](status.md).

The result advertises 23 native pairs and the inherited one generated explorer
splice, 24 coherent pairs total. Metadata adds
`destructor_name_delete_release_gated=True` and
`delete_release_failure_propagated=True`. Destructor-entry fencing, earlier
cleanup rollback, complete caller isolation, global raw-release proof, native
lifetime and partial-graph cleanup remain false.

Source contracts require the preserved 7,133,528-byte 02fd source, SHA-256
`02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87`.
They pin tail entry variants, frame reuse, private carrier nonuse, phase ABI,
exact delegation, complete RX and preceding hashes. Execution fixtures retain
bounded service substitutes and do not establish native scheduling, mutex
ownership, full destructor execution or graph lifetime. Completed serial
counts are recorded in [status](status.md). Active scrolling stays disabled;
hardware remains UNTESTED. No saved image, installer, player/device, network,
installation, launch, reboot, commit or push operation is supplied here.

Completed serial verification:28 new source/layout contracts and26 native/
adverse/cache checks pass, alongside36 affected-parent checks:90 targeted
tests total, no skips. All342 Python sources compile; the three saved images
retain exact02fd verification and their previous hashes. The complete project
suite and hardware were not rerun. Exact times and limitations are recorded
in [status](status.md).

The separate [refresh failure successor](folderfollow-reveal-refresh-failure-gate.md)
consumes the explicit destructor result in one existing refresh caller before
it overwrites that result and may recreate a view. It does not change this
stage's default bytes or provide a policy for higher callbacks and other
destructor callers.
