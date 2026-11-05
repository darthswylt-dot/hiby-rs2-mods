# Detach the worker's final buffer before its terminal release

2026-11-02. This separate optional offline successor to the
[dialog retention stage](folderfollow-reveal-dialog-retention-gate.md) removes
one concrete direct post-release access through the worker's H pointer.
It does not establish worker termination, continuous mutex ownership,
permission to free an arbitrary pointer, or complete native lifetime safety.

## The original completion signal precedes the last H accesses

The generic worker at `47C580` uses a 56-byte W frame. Its saved RA/S5/S4/S3/
S2/S1/S0 occupy `34/30/2C/28/24/20/1C`. It acquires C=H+0C and releases the
startup H+08 lock; the starter's H+08 wait therefore acknowledges startup.
The starter `47C840` calls `466BA0`, which uses `pthread_create` with
`pthread_attr_setdetachstate(...,1)`. It does not join the thread at completion.
Five encoded native callers of the starter are `47D3B8`, `47D6CC`, `47D920`,
`47DC5C` and `47E000`. The thread's actual return remains `JR RA` at `47C724`,
with `SP+=56` in its `47C728` delay slot.

H+18 is a loop handshake. The worker checks it at `47C654`, acquires H+10,
clears H+18 at `47C670` in the release delay, then continues its loop. The
completion byte +1C is also insufficient evidence: `47C6D4` writes it to every
matching-name object found in the global list, not just this worker's own H.
Poll `47CC20` uses that byte to dispatch H+6C to completion `47C740`.

The old worker tail releases H+10 at `47C6E0`, then C at `47C6E8`. It still
reads H+14 at `47C6F0`, conditionally calls `466A80` at `47C6FC` and clears
H+14 at `47C704`. Completion's C lock/unlock/destroy sequence at
`47C77C/47C784/47C78C` does not constitute thread termination and masks raw
results. Even an ordinary successful C handoff therefore precedes the old
worker's final access through H. The previous stage's error retention did not
remove this successful-path ordering defect.

## One native redirect and a 56-byte tail

The new redirect replaces `47C6E8` with J helper, preserving its original
`LW A0,H+0C` delay instruction `8E04000C`. It then executes:

1. Capture `S1=H+14` while H is still directly available.
2. If S1 is nonzero, store zero into H+14 before releasing C.
3. Execute SYNC, then call the same native `466DC0(C)` once.
4. If the retained S1 is nonzero, call the same native `466A80(S1)` once.
5. Jump to the complete native stack-only epilogue at `47C708`.

No new private frame, Q claim, raw-release observation, retry, destroy or H free
is added. S1 is already saved in W+20 and has no following native use besides
its restore at `47C71C`. Cooperative imported callees must retain callee-saved
registers according to the existing O32 ABI. The helper does not preserve every
caller-saved argument/register value from the old instruction ordering; A0
after the release is set from retained S1 before the NULL test. The worker's
original native frame restores its caller's saved registers and return address.

After the C release returns, the helper performs no direct memory access
through H. Its only remaining optional service uses the retained pointer.
An explicit SYNC orders the earlier field store before the existing release
under the stated MIPS memory semantics; no barrier is inferred from the masked
unlock's unverified result. A structural SYNC check is not target cache or
scheduler proof.
The native `466A80` wrapper reads ptr-4, checks a header, may update global
accounting and calls imported `free`; a zero-header path logs with `printf`.
The wrapper contains no native indirect H callback. These source facts do not
exclude allocator hooks, import reentry or aliases of ptr with H/its mutexes.

The original NULL path reaches `47C70C` after restoring RA in a branch delay.
The new NULL path instead reaches `47C708` and performs that same valid stack
load before the common restores. An encoded census of pinned native RX finds
only the old NULL branches `47C5B0/47C6F4 -> 47C70C` into the final tail; it
finds no encoded direct entry into the hook delay or skipped `47C6F0..47C708`
body. Unknown/computed/foreign entries remain outside this exact frontier.

## Changed ordering and hard limits

H+14 is deliberately detached before release/free, whereas stock clears it
after the optional free. This is a visible ordering change. Correct use of
this optional stage requires no other participant to depend on the old field
visibility or concurrently replace the field, and requires any nonnull pointer
to be independently retained, owned/freeable and distinct from H, its mutexes
and other live allocations. Static U/R/Q/RX exclusions do not establish these
dynamic facts. The callback at H+78 receives H and prevents a universal native
H+14 writer/observer proof. The bounded worker/starter range contains only the
initial zero store at `47C8A8` and the old tail clear at `47C704`.

The C acquire/release facades remain masked. A failed actual release still
returns the facade's native zero and still reaches the old optional free
policy; the new code neither authorizes nor certifies that behavior. It also
does not prove continuous C ownership, successful thread creation, a retained
H allocation before capture, or that every other alias stops using H. Earlier
callbacks and the matching-name completion byte retain their original behavior.
The semantic claim is removal of this worker tail's direct post-C H accesses.

The worker does not acquire the retention stage's global Q word. Holding that
word throughout a worker could reject the close facade needed to request a
stop. Waiting for Q in the tail could cycle with a consumer holding Q while
waiting for C. The existing protected consumers continue their preceding
policy, including terminal quarantine on classified dialog errors; this tail
does not widen that policy to all native participants.

Genuine native routes, coherent quiescent activation, mapped retained W56,
cooperative stack/register ABI, retained independently nonaliasing allocations,
and authority for the existing optional free remain hard premises. There is
no runtime installer enforcing them. Arbitrary partial activation is not a
fail-closed lifetime protocol and native/import fault unwinding is not added.

## Composition and bounded checks

Core API is `assemble(U,R,code_base,guard_address,*,protected_code=None,
extra_protected_data=())`; `hook_words(labels)` returns the one native pair.
U+28C, R+24, the independent Q+4, declared fixed roles and full native/generated
RX extents are validated for strict integer/alignment/overflow/nonoverlap.
The helper neither reads Q nor initializes any shared memory.

The stage keeps the preceding 11 addresses and required `guard_address` plus
its existing capacity/retry options. Its `following_code_bytes` protects later
RX without appending it. The 99,108-byte parent remains unchanged by default,
SHA-256 `c0ed5db6dcc4a668fe2532ffde5ca3c874c354c97860acb24d56e14f0d4180d3`.
The new composition appends 56 bytes to the parent composed with complete RX
protection, without patching any parent code bytes. Total size is 99,164 bytes.
Its SHA-256 is
`6449ade76e68805fd8857f7a2f9346e5605b3ba04de42bbc71e962fff3b8d4c0`.
The separately composed protected prefix has SHA-256
`4f83e6252ba521ccb96049b6471cf214bea1c79dcba023b655b44a49727134ba`.
It differs from the default parent only through the parent's existing complete
RX-bound materialization; it is preserved exactly, with no new generated splice.
Canonical helper entry/captured/release-return/finish are
`01E98324/01E98334/01E98340/01E98354`. Hook inventory becomes 33 native and
seven generated pairs, 40 total. Exact checks and final validation results are
recorded in [status](status.md).

Metadata sets `worker_post_terminal_release_H_access_removed=True` and
`worker_tail_field_detached_before_release=True` for this bounded direct-access
claim, and `worker_terminal_release_status_masked=True` to expose the retained
policy. It leaves `worker_termination_proven`, `worker_terminal_release_proven`
and `worker_buffer_free_authority_proven` false, preserving the preceding
retention stage's scoped flags and all unresolved global safety flags.

Source contracts pin the preserved 02fd image and genuine source/frame/entry
boundaries, actual imported thread/free symbols, the exact emitted tail and
strict static layout. Three named valid composition outputs are deep-copied.
Only 41 unchanged parent assembler functions use the preceding pure fixture
cache; the new core/stage remain unwrapped for distinct inputs. Temporary
identities restore on ordinary and exceptional exits. CPU state, native service
outcomes and execution results are not cached. Full uncached43 composition,
complete imported services, target scheduling/cache ordering and all native
alias lifetimes are not certified by these bounded checks.

This increment supplies offline code/metadata and tests. It creates no firmware
image or installer and performs no device/player access, launch or reboot.
Active scrolling remains disabled and hardware UNTESTED.

Final serial checks passed without skips: 20 new source/layout cases (5.048 s),
12 independent execution plus three full-composition integration cases (15 total,
2.404 s), and 25 preceding retention source/layout cases (5.688 s): 60 distinct
passing targeted tests. The integration fixture initially expected a displaced
DD4 instruction at its old trace PC; it now checks the actual DD8 resume and
the owning JR PC, with result/SP/source checks covering the replay and delay.
No production bytes changed for that fixture correction.

The independent interpreter executes the actual W56 prologue and native masked
release wrapper, with a fixed cut across the earlier worker loop. Unmapping or
poisoning H at the bounded raw-release return breaks the stock tail while the
captured-buffer tail completes without direct H access. Missing hooks, invalid
H before capture and a callee violating S1 retention remain counterexamples.
The three integration cases execute the complete composition's inherited raw
call/return dispatchers, including a chosen raw error that retains the lock
while the old free policy continues. That outcome is an explicit limitation,
not release permission. One case also unmaps H at the raw service and follows
every inherited return dispatcher without further H access. Q remains
quarantined and untouched by the worker.
