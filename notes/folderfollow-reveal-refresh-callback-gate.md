# Scoped callback exits after a classified refresh failure

2026-10-30. This separate optional offline successor to the
[refresh wrapper gate](folderfollow-reveal-refresh-wrapper-gate.md) stops two
known callbacks after the same classified refresh error. It preserves the
actual V0/V1 through the native refresh, wrapper and callback unwinds. It
does not skip the surrounding dialog, reverse earlier effects, finish cleanup
or establish ownership of retained operation contexts.

The inherited refresh gate has already classified saved S2=pinned U, saved
destructor return RA=`4ACD94` and nonzero V0 in its retained 192-byte private
save. The inherited wrapper helper has additionally selected the genuine
refresh saved return `4AD8E0`. The new helper is an interior continuation of
those decisions. It introduces no new error code, V1 marker, shared receipt,
object lookup or extra stack frame.

## Select only the two native wrapper callers

The splice replaces the first generated LUI/ORI pair at the wrapper helper's
`selected` label. That pair loads the parent's `abort_return` address into T0;
the separate resume word at selected+8 is `AFA80544`, the existing write of
T0 to the current refresh frame's saved outer return. Both the exact generated
pair and resume word are verified against the actual guarded parent prefix.
They are not additional vendor instruction hooks.

Let P be the inherited private-save SP. The genuine 1,160-byte refresh frame
begins at P+`C0`, and the genuine 48-byte wrapper frame W begins at P+`548`.
W's saved caller RA at native offset `2C` is therefore P+`574`. The new helper
reads that word once. Exact `4AEEE8` selects the first callback escape; exact
`450DA4` selects the second. Other saved wrapper callers retain their original
return word and the existing wrapper escape.

On a match, only W's saved caller RA is retargeted to the corresponding new
callback thunk. All outcomes replay the displaced parent's LUI/ORI pair once
and resume at selected+8. The parent still writes its own `abort_return` into
the refresh frame's saved RA at P+`544`. Its complete architectural restore
and native refresh epilogue `4ACCE4` run as before.

The parent wrapper thunk then loads W's saved caller RA in the jump delay to
`4AD904`. That genuine native suffix restores S3/S2/S1/S0 and unwinds 48 bytes,
without the `4AD900` V0 overwrite. A selected callback thunk is reached with
SP=P+`578`, the genuine callback frame. It jumps directly to that callback's
full native epilogue, with no call, graph access, service, unlock or free.

## Exact callback exits and omitted context cleanup

The first callback, `4AEC60`, has a `14C0`-byte frame, 5,312 bytes. Its native
prologue saves RA at `14BC` and S4/S3/S2/S1/S0 at
`14B8/14B4/14B0/14AC/14A8`. Its wrapper call is `4AEEE0`, with mode S4 in
the delay and genuine return `4AEEE8`. The new thunk jumps to `4AECD8`, which
loads the genuine saved RA, restores those five saved registers and returns
with SP+=`14C0`. That complete suffix preserves both V0 and V1.

The bypassed native pair at `4AEEE8` is `24030001/1443FFF6`: it first overwrites
V1 with 1, then branches on V0!=1 to `4AEEC8`. That concrete error path reads
dialog+58, frees the nonnull operation context through `466A80` at `4AECCC`,
clears dialog+58 and exits. It does not retry the wrapper. The success path
can call `4AE9A0` before converging on the same context cleanup.

The context is a native `CF0`-byte allocation made at `4AF79C`. Its descriptor
is copied to context+50 before publication into dialog+58 at `4AF7E4`. The
selected stop skips the later context read/free/clear; it does not acquire a
lease for that allocation, its descriptor, the dialog or any escaped view.
This selected path leaves dialog+58 untouched. Later independent
cleanup or container destruction remains outside this gate.

The second callback, `450D60`, allocates its 40-byte frame only when A1 is
nonnull. It saves S0 at `20` and RA at `24`, retains the operation context in
S0 and resolves a view through `4E5680` before calling the wrapper at
`450D9C`. The call delay supplies descriptor=context+50, and its genuine
return is `450DA4`. The new thunk jumps to `450DAC`: restore RA/S0,
SP+=`28`, JR RA/NOP. V0/V1 remain exact.

Its bypassed return pair `0C119AA0/02002021` calls `466A80` on that operation
context. Other native branches from `450D78` and `450D90` legitimately enter
the same free path without a wrapper call; they are not redirected by this
classified saved-return rewrite.

Both callbacks have already resolved borrowed view/controller pointers and
may have performed earlier property, list, file or operation work. Earlier
wrapper, refresh and destructor effects also remain effective. Neither
callback body contains an explicit lock acquire/release/destroy facade call
or a JALR. This bounded source fact does not prove that every transitive
callee has no obligations; ordinary ABI and service cooperation remain hard
premises.

## The dialog is a separate error and lock boundary

Dialog `47C740` uses a 104-byte frame, saving RA/S1/S0 at `64/60/5C`. It
calls the acquisition facade on the pointer loaded from dialog+10 before
invoking the callback at `47C7C8`, with A0=dialog and A1 loaded from dialog+50.
The callback's genuine return is `47C7D0`. The acquisition facade masks its
raw status; successful lock ownership remains a premise, not a source-proven
fact.

The dialog ignores the callback result. After return it still calls cache
removal `47AA20`, purge/detach `439780`, name deletion `4395A0` and resource
deletion `485320`. It then calls the matching release facade `466DC0` and
destruction/free facade `466DE0` on the pointer loaded from dialog+10, and
forces V0=0 at `47C810`.
The new callback exits preserve this entire surrounding continuation.

Jumping straight to the dialog's pure `47C814` epilogue would skip those
matching native release and destruction obligations. Entering its
release suffix alone would still require a separate raw-result and ownership
policy. This increment supplies neither route and cannot claim that the
classified failure reaches the dialog's caller unchanged.

The bounded J/JAL and conservative relative-branch census has no incoming
targets at `4AEEE0/E4/E8/EC/F0` or `450D9C/DA0/DA8/DAC/DB0`.
`450DA4` has the two ordinary branches noted above. Native `4AECD8` has one
incoming branch from `4AEED4`; `4AECDC` has five existing branches that already
supply RA elsewhere. The new first thunk enters the full epilogue at
`4AECD8`, including its RA load. These encoded facts do not authenticate a
fabricated saved return or exclude computed/runtime entries.

## Hard frames, layout and offline composition

The private 192-byte save, native 1,160-byte refresh frame, 48-byte wrapper
frame and selected 5,312-byte or 40-byte callback frame must be genuine,
mapped, writable and retained for their live use. All simultaneously live
frames must be independently nonaliasing with each other and native, heap,
shared and RX storage. Sufficient transitive stack and coherent inherited/new
redirects remain hard premises. Scalar saved-return checks are scope checks,
not authentication, arbitrary-SP validation or malformed-stack recovery.

Static checks exclude the complete U `28C` bytes, R's 24 bytes, declared
fixed data and native/generated RX from overlap. The parent selected pair
plus separate resume word reserve 12 generated bytes; its existing wrapper
abort thunk reserves eight. Both regions must precede the new fragment, and
complete protected RX must contain them and the full new helper. These
declarations prove neither runtime mapping nor allocation lifetime.

The successor accepts the same 11 canonical addresses and bounded options.
Strict zero-default `following_code_bytes` protects later RX without appending
it. The preceding wrapper default remains 92,500 bytes with SHA-256
`b10314826317ea55438b21abcb4de04825346d3c593c132ec6cdd7921b74e696`.
The successor contains that 92,500-byte guarded prefix plus a 100-byte helper,
92,600 bytes total, with SHA-256
`e76f86cc4cea0ecb445eee4eb712e14993004f3a42138e2b7150831899b9f7c4`.
Its canonical generated parent selected and abort addresses are
`01E96930/01E9694C`; the new helper begins at `01E96954`. These values are
pinned by the accompanying source contract after serial composition
verification; completed results are recorded in [status](status.md).

The composition changes exactly one verified pair in the guarded generated
prefix and appends its helper. The native hook map remains unchanged at 24
pairs. The new generated splice brings the generated map to three pairs and
the coherent total to 27. This is an offline returned byte sequence and
instruction-fetch override inventory, not a saved firmware image edit or
installer.

Metadata sets `refresh_callback_failure_continuations_stopped=True` and
`refresh_callback_exact_result_preserved=True`. Whole-instance caller isolation,
dialog exit fencing, earlier cleanup rollback, global raw-release proof, native
lifetime and partial-graph cleanup remain unproved. No new free, unlock,
retention or retry authority is introduced.

Contracts use the preserved 7,133,528-byte 02fd source with SHA-256
`02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87`.
They pin the native frames/returns/epilogues, context cleanup and surrounding
dialog obligations, generated splice/replay, private accesses and strict
layout. Three exact valid compositions are retained once per class and exposed
as deep-copied snapshots. During this contract class only, the preceding
fixture's pure assembly cache wraps the 33 unchanged parent assembler
functions. The new callback core and stage remain unwrapped: each distinct
new invalid or extension configuration still calls them directly, with
unchanged parent outputs eligible for memoization. Class cleanup restores
all parent function identities even after test failure; a nested-error check
also verifies restoration and separation from the new core/stage. No CPU,
native execution state or execution results are cached. Older published
contract suites and independent fully uncached execution/equivalence checks
remain separate. Body-cut execution fixtures do not execute or prove the
full earlier cleanup, transitive services or dialog scheduling.

Active scrolling remains disabled and hardware UNTESTED. No firmware image,
device/player access, installation, launch, reboot, network, commit or push
operation is supplied by this increment.

Completed serial verification:23 new source/layout contracts and19 new
native/adverse/cache tests pass, alongside20 affected-parent tests:62 distinct
targeted tests, no skips. Two initial preflight cases were repeated by the
full execution run and are not counted twice. The parent-only contract cache
and independent fully uncached execution comparison are distinct checks.
Exact times, source/image hashes and remaining boundaries are recorded in
[status](status.md). The full project suite and hardware were not rerun.
All357 Python sources compile, and fresh primary/source-image hashes remain
unchanged. Exact saved-image verifier passes remain historical; this increment
does not repeat them or establish a complete dialog/worker lifetime policy.
