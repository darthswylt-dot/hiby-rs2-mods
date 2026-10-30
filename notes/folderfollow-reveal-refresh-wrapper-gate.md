# Scoped wrapper exit after the classified refresh failure

2026-10-29. This optional offline successor to the
[refresh failure gate](folderfollow-reveal-refresh-failure-gate.md) closes one
known higher-wrapper continuation. After `4AD880` calls refresh `4ACBC0` at
`4AD8D8`, an explicit refresh failure could still reach `4ACE40(V)` at
`4AD8F4`. That helper reads V+3DD8 and can change a property even though the
destructor has already left a partially changed graph. The new composition
escapes this exact wrapper invocation while preserving the actual V0/V1.

Earlier operation work and cleanup remain effective. This is a bounded return
rewrite and native unwind, not rollback, graph retention, completed cleanup,
safe retry/free authority or coordination of the higher callbacks.

## Reuse the existing private failure decision

At the wrapper return, S0 is the view, S1 the descriptor, S2 the operation mode
and S3 a flag. None supplies a pinned controller scalar. The native wrapper
also has unused words at +10/+14/+18, but using them as a receipt would need
an additional fresh producer/consumer protocol. This composition instead
uses the preceding refresh gate's existing classified stopped route.

That route has already saved all 30 non-SP general registers and HI/LO in 192
private bytes and classified saved S2=pinned U, saved destructor return
RA=`4ACD94` and saved V0 nonzero. The new helper neither repeats that decision
nor guesses a controller from a view after failure. It creates no extra frame,
shared latch, queue, failure mailbox or witness carrier. V1 is preserved and
never interpreted as a raw-status marker.

Only the generated `gate_stopped` entry is spliced. Its original restore pair
is `8FA80088/01000011`, loading saved HI into T0 and restoring HI. The separate
resume word at stopped+8 is `8FA8008C`, the existing saved-LO load. These words
are checked against the actual generated parent prefix; they are not reported
as another native vendor instruction pair.

## Retarget one actual saved return

With helper SP still pointing to the parent's private save, the native refresh
frame begins at SP+192. Its saved outer RA is at native offset `484`, so the
helper reads private `SP+544` hex. Only exact value `4AD8E0`, the original
return from `jal 4ACBC0` at `4AD8D8`, selects the wrapper escape.

On that match only, the helper retargets the current refresh frame's saved
outer-return slot to its emitted `abort_return`. It does not overwrite the
wrapper frame's separate saved caller RA. Other refresh callers retain their
original return. Both outcomes replay the displaced HI pair exactly once
and resume the original stopped restore at parent stopped+8.

The unchanged parent restores the complete saved architecture and SP before
entering native refresh epilogue `4ACCE4`. That actual epilogue restores RA and
S4 through S0, unwinds 1,160 bytes and preserves V0/V1. The selected invocation
now reaches `abort_return` with SP pointing to its genuine 48-byte wrapper
frame, instead of resuming the wrapper's `4AD8E0` continuation.

The abort thunk jumps to native `4AD904`, with original `lw RA,+2C(SP)`
(`8FBF002C`) in its jump delay. That supplies the wrapper's genuine saved
outer RA exactly once. The native suffix then restores S3/S2/S1/S0 from
`28/24/20/1C`, executes JR RA and unwinds 48 bytes in its delay. It has no
V0/V1 overwrite, graph access, callback, service, unlock or free.

Entering `4AD8FC` directly would be insufficient: `4AD900` sets V0 from S1,
which is still the descriptor when the wrapper's earlier result-copy delay
is bypassed. The selected path explicitly skips that instruction and preserves
the actual result through both native unwinds. It introduces neither a new
return code nor a V1 classification rule.

## Earlier work and higher callers remain outside

Before calling refresh, the wrapper can run `4ACFC0`, `42C280`, `4ACEC0`,
`4AD1E0` and `4ACA40`. The refresh function has already captured its name,
scope and list state, and the destructor has already performed its earlier
closing, worker cancellation, callbacks, unlink, purge/detach and possible
name/paint-queue/engine/node frees. The new escape reverses none of them and
does not revoke escaped view/resource aliases.

The unselected wrapper path retains its exact native branch/result behavior.
The other refresh destructor call at `4ACD1C`, tail caller `4AD860`, other
destructor callers, computed entries and the separate `4ADBCC -> 4ACE40`
continuation remain outside this escape. Missing earlier acquisition, release,
refresh or generated-splice hooks can restore unsafe native continuations;
coherent activation is a premise, not a fail-closed installer for arbitrary
partial activation.

There are two encoded direct wrapper callers. `450D60` calls at `450D9C` and
ignores the result before freeing its operation context. `4AEC60` calls at
`4AEEE0`, immediately overwrites V1 and compares V0 with 1. Its error branch
reads dialog+58, frees the context at `4AECCC`, clears +58 and exits; it does
not retry the wrapper on that path. Other code can interpret a nonzero word such as
FFFFFFFF as true. The exact local return does not isolate those callers,
retain their native objects or authorize additional cleanup.

The enclosing dialog `47C740` is another separate boundary. It calls ordinary
lock acquisition for dialog+10 before the callback, ignores the callback result,
then performs cache removal, purge/detach, name/resource deletion and the
matching lock release/destruction. A direct jump to its pure epilogue would
skip those synchronization obligations. A later error exit there needs an
explicit checked lock/release policy; this wrapper escape supplies none.

The bounded J/JAL and conservative relative-branch census has no incoming
targets at `4AD8D8`, `4AD8DC`, `4AD8E0`, `4AD8E4` or `4AD904`. Native branches
to `4AD8FC` and `4AD900` retain their existing routes. This encoded evidence
does not authenticate a fabricated saved return or exclude computed/runtime
entries; the generated helper is an interior route under its parent's failure
decision and is not an arbitrary callable API.

## Hard frames, static layout and separate opt-in composition

The parent's 192-byte private save, genuine 1,160-byte refresh frame and
selected 48-byte wrapper frame must already be mapped, writable and retained
for their live use. Their native prologues have already written saved state.
All simultaneously live frames must be independently nonaliasing with one
another, native/heap/shared allocations and native/generated RX. Sufficient
transitive stack, genuine native routes, ordinary ABI/service cooperation and
coherent inherited/new redirects remain hard premises.

Scalar U/RA checks and the exact saved outer return are scope checks, not
authentication. Static placement does not validate arbitrary SP, wrapping,
mapping or lifetime and does not make a forged, unmapped or aliased unwind
safe. There is no malformed-stack recovery or native allocation lease.

Strict static configuration excludes U's full `28C` bytes, R's 24 bytes,
extra declared fixed data and complete native/generated RX from overlap.
The declared parent stopped region reserves 12 bytes: its replaced pair and
separate resume word. It must precede the helper, and protected RX must contain
both that complete region and the entire emitted helper. These exclusions
provide no dynamic memory guard or ownership proof.

`reveal_refresh_wrapper_gate_stage.assemble` uses the preceding 11 canonical
addresses and bounded options. Parent and successor strict zero-default
`following_code_bytes` reserve later RX without appending it. The parent keeps
its 92,444-byte default and SHA-256
`88c32e213641ce6731c4e6eeef00f7fbf2487cef4976d061e27ec1c682e46d85`.
All 21 preceding default compositions retain their hashes. The canonical
successor is 92,500 bytes: the guarded 92,444-byte prefix plus the 56-byte
wrapper helper. Its SHA-256 is
`b10314826317ea55438b21abcb4de04825346d3c593c132ec6cdd7921b74e696`.
The canonical generated parent stopped address is `01E967E4`.
Completed serial verification is recorded in [status](status.md).

The new composition patches only the verified generated HI pair in the guarded
prefix and appends its helper. The resume word is verified and preserved.
Its hook inventory contains the unchanged 24 native pairs and two generated
pairs, including the earlier explorer splice, 26 coherent pairs total. The
new pair is present in the returned bytes and advertised as an idempotent
instruction-fetch override; it is not a new vendor hook or a saved image edit.

Metadata sets `refresh_wrapper_failure_continuation_stopped=True` and
`refresh_wrapper_exact_result_preserved=True`. Whole-instance caller isolation,
destructor-entry fencing, earlier cleanup rollback, global raw-release proof,
native lifetime and partial-graph cleanup remain false.

Source contracts require the preserved 7,133,528-byte 02fd image, SHA-256
`02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87`.
They distinguish generated splice words from native source facts, pin both
frames/unwinds and the return relation, and check private accesses, strict
layout and the complete guarded prefix. The contract suite emits each exact
valid default/guarded composition once per class and supplies deep-copied
metadata for repeated inspection. This local output cache does not wrap an
assembler, cache native execution or bypass distinct invalid/extension inputs;
the preceding hash chain and direct core checks remain uncached. Body-cut
execution fixtures use prologue-established frame state and bounded service
substitutes; they do not prove full earlier cleanup, native scheduling or
higher callback safety.
Active scrolling remains disabled and hardware UNTESTED. No firmware image,
installer, player/device, network, installation, launch, reboot, commit or push
operation is supplied by this increment.

Completed serial verification:23 new source/layout contracts and20 new native/
adverse/cache tests pass, alongside20 affected-parent tests:63 distinct targeted
tests total, no skips. One higher-callback source case was strengthened after
the full contract run and rechecked in the following41-check execution run;
that recheck is not counted as another distinct test. All352 Python sources
compile, and fresh saved-image hashes remain unchanged. Exact image verifier
passes belong to the earlier delete-release increment. The full project suite
and hardware were not rerun. Times, corrected callback behavior and remaining
dialog synchronization obligations are recorded in [status](status.md).
