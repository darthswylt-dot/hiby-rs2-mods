# Scoped destructor continuation stop after an explicit delete failure

2026-10-29. This optional offline successor to the
[constructor release gate](folderfollow-reveal-registry-release-gate.md) stops
one demonstrated outer continuation after name deletion returns nonzero.
The [acquisition gate](folderfollow-reveal-registry-acquire-gate.md) can refuse
the body of native `4395A0`, but destructor `493AC0` previously ignored that
result and immediately deleted the separate resource. The new composition
stops that invocation's remaining destructor work. It does not undo cleanup
already performed, retain the partial graph, fence destructor entry, isolate
the outer callers or provide native cleanup permission.

## Exact native hook and private decision

The single new native instruction-fetch redirect replaces `493F4C/493F50`,
whose source words are `8E240024/0C1214C8`: load the resource manager from
controller `S1+24`, then call independent resource deletion `485320`.
Its original call delay at `493F54`, `02602821` (`A1=S3`), remains in the
vendor source. The redirect's own delay is NOP; a forwarded route replays the
original delay exactly once while entering the actual resource deletion.

Before deciding, the gate saves all 30 non-SP general registers and HI/LO in
192 private bytes. Only three scalar values in that save are consulted:
saved `S1` must equal pinned U, saved RA must equal `493F4C`, the return from
the actual `jal 4395A0` at `493F44`, and saved V0 must be nonzero. V1 is
preserved but never interpreted as a raw status or a failure marker.
No mutex, native object, engine/name, registry ring, journal, queue or shared
failure mailbox is read to make this decision. The pinned R participates in
static layout exclusion only.

The matching nonzero route restores the entire saved architecture and SP,
including V0/V1 and HI/LO, then jumps to native destructor epilogue `493C98`.
That epilogue loads RA from `SP+4B4`, FP and S7 through S0 from `4B0..490`,
and returns while unwinding its existing 1,208-byte (`4B8`) frame. It performs
no graph load, callback, unlock, cleanup or free. Native NULL failure already
uses the same epilogue with V0=-1. The stopped route preserves the result that
actually arrived; it does not synthesize a new success or cleanup receipt.

Every other route restores the complete gate-entry architecture before
executing the original load `A0=*(S1+24)`. Only after that load does it recreate
the original resource-call RA `493F58` and jump to actual `485320`, with
`A1=S3` in the jump delay. This ordering preserves the original load's RA
context, the actual call ABI and the single execution of its delay word.
There is no extra resource call, relocation return address or second execution
of native `493F54`.

## Earlier teardown remains effective

This is a late continuation stop. It does not prevent the earlier closing
write `V+44=1` at `493B10`, the call to `4916A0`, `48F800` at `493B3C`,
`4B8D60`, earlier list deletion, or `49ADA0`. The private branch has already
called worker shutdown `48F520`; the shared branch has already called
cancellation `48EE20`, whose work-list clear does not revoke an already
borrowed worker copy. An optional opaque `V+4224` callback and freeing
`V+3BA4` can also precede the later cleanup arm.

The `493EA8` arm can already have called worker shutdown `4C0A80`, destroyed
and cleared `V+2A08`, and cleaned eight entries through `440620`. It clears
controller `+F0` in the `493F00` call delay, calls `4BDA20`, clears `V+3B90`,
calls cache cleanup `47AA20`, and calls purge/detach `439780` before the
name-delete call. Cache cleanup already unlinks a node; purge/detach can
discard paint work, remove parent membership and free an attachment.
Returning from the destructor cannot restore those effects or make that
partially changed graph safe for reuse.

The new stopped route bypasses independent resource deletion `485320`, the
resource's `+42C` callback, clearing `V+D0`, later controller-list removal,
remaining list/resource destruction and final view free `493FDC`. It adds
no compensating free, unlock, retry, rollback or recovery. Resource creation
already supplied the escaped `resource+7C=view` alias; the constructor failure
exit and this later stop do not revoke it. Absence of a particular owner-list
membership does not prove exclusive ownership or permission to reclaim it.

The earliest audited nonnull preclose pair is still
`493B0C/493B10 = 24020001/AE020044`, before the first view-field mutation.
Only a private stack-buffer clear precedes that pair. An actual entry fence
would need its own coordinated policy there: the later name-delete acquisition
result does not yet exist, and this composition installs no such entry gate.

## Remaining failure and caller boundaries

The acquisition gate defines its explicit delete-denial result as
`FFFFFFFF/exact raw status`, or `FFFFFFFF/zero` for missing or incoherent
evidence. These are selected by this destructor's nonzero-V0 test. The test
does not distinguish every possible native or custom-callback error by V1.

Ordinary name-delete completion still tail-calls the native registry unlock
facade. Its raw release wrapper forces V0 to zero, so an actual nonzero delete
release can still reach this gate as zero and forward into resource cleanup.
The preceding release gate is scoped to constructor registration; it does not
repair this delete-release path or prove complete raw-release coverage.
Missing acquisition or continuation redirects likewise retain unsafe native
paths. All declared hooks must participate coherently; this is not a
fail-closed installer for arbitrary partial activation.

The pinned image contains 56 encoded direct name-delete calls; 54 immediately
continue to independent resource deletion. This new gate covers the one
destructor sequence at `493F44`, not those other callers. There are also 49
encoded direct callers of destructor `493AC0`. Outer callers can continue
iteration, replacement, creation or unrelated work after its return; their
failure handling is not isolated by this stop. The conservative encoded J/JAL
and relative-branch scan finds no incoming target to `493F4C`, `493F50` or
`493F54`. It cannot exclude computed entries, runtime patches or forged returns.

## Hard frames, static layout and separate composition

The genuine destructor prologue has already written its native save slots.
Its complete 1,208-byte frame, the gate's separate 192-byte save and every
transitive native/service stack must already be mapped, writable, retained
and independently nonaliasing with heap, native/shared data and native or
generated RX. Saving happens before classification, including foreign or zero
result paths. Saved U/RA scalars are scope checks, not authentication.
There is no dynamic SP, mapping, wrapping or lifetime validation and no promise
to unwind fabricated, unmapped or aliased frames safely.

Strict configuration excludes U's full `28C` bytes, R's 24 bytes, declared
extra fixed data and complete native/generated RX from overlap. Extra fixed
extents affect only layout validation; they add no allocation lease or runtime
guard. A declared protected RX extent must contain the complete emitted gate.

`reveal_destructor_continuation_gate_stage.assemble` takes the preceding 11
canonical addresses and bounded options. The parent release stage's strict
zero-default `following_code_bytes` reserves the appended RX throughout all
inherited guards without appending it. The new stage appends the gate and
advertises its one native pair alongside the inherited hooks: 22 native pairs
and one generated explorer splice, 23 coherent pairs total. No saved firmware
image or installer is modified.

All 18 preceding default compositions retain their hashes, including the
89,140-byte release composition with SHA-256
`03ec46d436914eef93a8aa118496608d59df4539926dc6272ff81449e50687de`.
The canonical successor is 89,640 bytes: the guarded 89,140-byte prefix plus
the 500-byte destructor gate. Its SHA-256 is
`996f66b14285bdb35490b4e4e2cbc380c2ed888a558323ea1828a58ebc246b1c`.
Completed serial verification counts are recorded in [status](status.md).

Metadata sets `destructor_delete_failure_continuation_stopped=True`, while
`destructor_entry_fenced`, `earlier_cleanup_rolled_back`,
`native_callers_isolated`, `raw_release_proven`, `native_lifetime_proven` and
`partial_graph_cleanup_proven` remain false. These are bounded scope labels,
not native retention, successful cleanup or hardware certificates.

Source contracts require the preserved 7,133,528-byte 02fd image, SHA-256
`02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87`.
They pin the source pair and separate delay, genuine unwind, earlier effects,
bounded caller census, private decision, replay ABI, static layout, complete RX
and unchanged preceding defaults. The native execution fixture enters only at
`493F40`, immediately before this delete-call sequence; the preceding cleanup
order is pinned statically, not executed as a full teardown by that fixture.
Execution fixtures use bounded service substitutes and do not prove native
scheduling, mutex ownership or lifetime.
Active scrolling remains disabled and hardware UNTESTED. No player/device,
network, installation, launch, reboot, commit or push is part of this step.

The separate [delete-release successor](folderfollow-reveal-delete-release-gate.md)
adds a fresh private witness for this one destructor's actual name-delete
unlock result. It delegates this unchanged continuation gate after propagating
an observed release error; earlier unlink/free effects still remain. This
stage now accepts strict zero-default `following_code_bytes`, protecting a
successor's RX without appending it or changing these default bytes.

Completed serial verification:21 new source/layout contracts and15 native/
adverse/cache checks pass, alongside27 affected-parent checks. The complete
project suite and hardware were not rerun. Exact times, cache isolation and
unchanged saved-image verification are recorded in [status](status.md).
