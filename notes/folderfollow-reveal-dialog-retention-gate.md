# Terminal retention for the known dialog consumers

2026-10-30. This separate optional offline successor to the
[dialog failure gate](folderfollow-reveal-dialog-failure-gate.md) suppresses
its unconfirmed direct unlock and prevents the known completion/close paths
from subsequently mutating, unlinking or freeing H after a classified error.
A dedicated atomic control word blocks reentry into those protected bodies.
This is deliberately broad fail-closed behavior, not completed cleanup,
universal native lifetime protection or an automatic recovery policy.

## Ownership was audited, not inferred from ADMITTED

The callback call/return chain is synchronous, and the two completion callback
bodies do not directly load or release H+10. That does not establish continuous
M ownership. The transitive route contains list/controller methods and the
conditional V+4224 call at `493C38`, without a closed alias/thread proof.

H is published into resources through `459320`, whose actual store at `459330`
sets resource+7C. Initialization `4AE180` supplies H to resources and installs
widget handlers. `4AF008 -> 459340` reconstructs H and `4AF020 -> 47D0A0`
can operate on its +10 mutex; another handler has the analogous
`4AF0C8/4AF0E4` route. The configurator's masked acquire/release are
`47D0C4/47D0DC`. Other known clients include the worker, completion handler,
flag setter `47C9A0` and list registration `47C9E0`.

The native mutex factory does not check allocation before initialization and
discards the initialization result. Actual acquire zero and an ADMITTED tag
therefore cannot be promoted into a verified initialized/live allocation or
continuous ownership lease. The new protected error route performs no direct
raw unlock, masked unlock, destroy, free or retry. The earlier optional release
body remains in the unchanged parent bytes but its ordinary error entry is
redirected before that body can execute.

## One independent process-lifetime control word

Q is a separate aligned four-byte word, canonical address `01F20900`, with
READY=0, BUSY=1 and QUARANTINED=2. It is distinct from the existing transport
fault word F at `01F20800`; the error path does not obtain storage through H
or write a transport-owned fault allocation after native uncertainty.

Q must be normal cacheable coherent memory, mapped and retained for the process
lifetime. Its owner initializes it to zero before quiescent coherent activation
of all redirects, when no protected native invocation is already in flight.
No reset routine is provided. QUARANTINED is terminal; unknown nonzero values
also refuse future admission. The assembler supplies bytes and metadata, not
runtime allocation, initialization or an installer enforcing these premises.

The protected entries claim READY->BUSY through bounded LL/SC before their
native object/list accesses. The default is eight attempts; strict configured
limits are 1..64. BUSY, a nonzero fault value or exhausted entry attempts returns
FFFFFFFF/0 with the native body unentered. This also rejects recursive entry.
The claim remains held across the entire protected body and any borrowed close
invocation. Synchronization relies on the stated LL/SC/SYNC and cache-coherence
premises, not observed mutex ownership.

## Native frames, owner stamps and common tails

Normal consumer `47CC20` has a 48-byte O frame, saving RA/S3/S2/S1/S0 at
`2C/28/24/20/1C`. The full native epilogue begins `47CCD0`. Every framed
return traverses `47CCD8`, after RA and S3 are restored. Its protected leave
pair is `8FB20024/8FB10020`; replay resumes at `47CCE0`, where only the S0
stack load, JR RA and SP+=48 remain.

Close-by-name consumer `47CF80` also has 48 bytes, saving RA/S4/S3/S2/S1/S0
at `2C/28/24/20/1C/18`. Every nonnull framed return traverses `47D03C`, after
RA and S4 are restored. Its leave pair is `8FB30024/8FB20020`; replay resumes
at `47D044`, where only stack restoration and return remain. The original
null-A0 branch returns without allocating O or claiming Q. The new preserving
entry still needs its separate 192-byte save even for null/rejected calls.

The full-body stack census finds no O+10 access, SP-derived buffer argument
or outgoing stack-argument store in either consumer. A successful independent
entry stamps that word with QOWN. With a 192-byte entry save P, future O+10
is P+`A0`, original SP-32, after the saved GPR/HI/LO area ending P+`8F`.
It is padding in that temporary save and the same word becomes O+10 after
the native prologue. Callee argument homes `00..0F` remain separate.

The synchronous facade `47D060` must also be protected: it calls flag setter
`47C9A0` before reaching `47CF80`, so guarding only the close scan would leave
that known M operation exposed. Its 32-byte F frame saves RA/S0 at `1C/18`,
with unused F+10. An atomic facade claim stamps QFAC there, at private P+`B0`.
Its inner close call has actual return `47D084`; that exact return, the current
QFAC stamp and Q=BUSY permit the inner close to borrow the existing claim.
The borrowed O frame uses QBOR and its leave does not clear the facade's Q.

At native facade leave `47D084`, the pair loads RA/S0. Normal owner release
replays it and resumes `47D08C`, preserving the native V0=0 behavior. A
quarantined/fault outcome replays it and resumes `47D090`, bypassing that
overwrite so the child's exact error pair survives. Every facade path uses
this common tail; there is no separate native null return.

Owned leaves consume their current-frame stamp and use bounded LL/SC only
for BUSY->READY. They never clear QUARANTINED or another non-BUSY value.
Exhausted owner release attempts latch QUARANTINED instead. Missing stamps
do not authorize a Q release. Once a leave releases Q, only private stack
restoration and return remain, so another admitted consumer cannot overlap
its predecessor's remaining H accesses. Stamps and saved PCs remain scope
evidence under genuine-frame/ABI premises, not authentication.
An exit-side SC fault can occur after ordinary native work has completed;
its terminal latch does not undo any earlier successful-path free.

## Both classified errors latch Q before the native dialog unwind

The callback-error splice replaces the first generated pair of the preceding
`error_return` entry, `27BDFF40/AFA10010`. A new complete private save takes
over at the original D104 SP, latches Q=2 with SYNC, and never enters the old
release attempt. It records QDCB with status zero in D's owned `10/58` words,
invalidating the old ADMITTED state without reading M at D+14.

The acquisition-denial splice replaces `8FA80088/01000011` at the preceding
`gate_denied` restore. That route already owns its 192-byte save and RAW90.
The helper latches Q=2, copies the retained raw diagnostic into D+58 and writes
QDAD at D+10. It replays the exact HI pair and resumes at the verified next
word `8FA8008C`; the original restore still supplies FFFFFFFF/exact raw, or
FFFFFFFF/0 for missing acquisition evidence.

Both routes inspect only D.savedRA at +64. Exact `47CC94` or `47D00C` selects
one of two new outer-return thunks, J `47CCD0`/NOP or J `47D034`/NOP. Only
that saved stack word changes. The actual D104 epilogue still runs and
establishes the genuine O frame before the outer thunk. Foreign saved callers
keep their return; Q remains latched. Original callback V0/V1 and HI/LO are
preserved rather than classified again.

This bypasses the known post-completion H flag writes, list unlink, optional
H+7C callback and H free. The outer leave sees Q=2 and does not reopen it.
Future protected poll, close and facade entries reject before their native
bodies can repeat the already-processed +0C completion sequence. Q is global
to this composition, so the terminal stop also blocks otherwise unrelated
dialogs handled by these consumers; that breadth is intentional.

## Exact coverage and remaining limits

Earlier +0C processing remains effective. The worker still accesses H+14
after its +0C release at `47C6E8`; no worker-termination proof is added. Widget
handlers, configurators, other H aliases and unknown/computed entries outside
the protected consumers are not universally fenced. The higher music-loop
paint unlock at `43C9DC` remains on its original path. No new H field lookup,
M operation or service is performed by either classified retention helper.

Normal pre-error native callbacks and cleanup keep their existing behavior.
The protected code prevents the covered consumers' frees after error; it does
not prove every other native participant will retain H or refrain from M use.
Genuine mapped writable independently nonaliasing simultaneously live frames,
native/import ABI cooperation, sufficient transitive stack and coherent hooks
remain hard premises. No layout check validates arbitrary SP, initialization
or dynamic allocation lifetime. Quiescent activation is required to exclude
already-running unguarded instances of the protected functions.

The stage accepts the preceding 11 canonical addresses plus required
`guard_address`, bounded `retry_limit` and zero-default `following_code_bytes`.
Following RX is protected without being appended. Its preceding default is
95,300 bytes with SHA-256
`92f44f4def0777f77207b6d0c9a1ad973b88f9e667c3919b3b095200b0aa668e`.
The new helper adds 3,808 bytes for 99,108 total, SHA-256
`c0ed5db6dcc4a668fe2532ffde5ca3c874c354c97860acb24d56e14f0d4180d3`.
Canonical callback/denial splices are `01E972A0/01E96EDC`; new callback entry
begins at `01E97444`. The inventory is 32 native and seven generated pairs,
39 coherent pairs total. The checked values and serial results are recorded
in the companion source contract and [status](status.md). The guarded prefix
changes only the two verified generated source pairs; native redirects are
returned as metadata.

Metadata sets `unconfirmed_dialog_unlock_suppressed=True`,
`known_dialog_outer_frees_guarded=True`, `known_dialog_reentry_guarded=True`
and `known_dialog_close_facade_guarded=True` for these exact frontiers.
`dialog_ownership_proven=False` and `dialog_failure_release_attempt_guarded=False`
make the protected policy explicit. Global caller isolation, raw-release proof,
native lifetime, partial-graph cleanup, rollback and destructor-entry fencing
remain false. Runtime guard reset is unsupported.

Source contracts use the preserved 7,133,528-byte 02fd image, SHA-256
`02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87`.
They cover the native common returns and unused stamp words, exact inherited
splices, atomic Q/stamp transitions, no-service error paths and strict static
layout. Three named valid outputs expose deep-copied metadata. Only the 39
unchanged parent assemblers use the preceding fixture's pure cache; new core
and stage remain unwrapped for distinct configurations. Cleanup restores
function identities even after failures. No CPU or native execution results
are cached, and bounded fixtures do not certify native scheduling or lifetime.

Active scrolling remains disabled and hardware UNTESTED. No firmware image,
device/player access, installation, launch, reboot, network, commit or push
operation is supplied by this increment.

Completed final serial verification:25 new source/layout contracts and25 new
native/adverse/cache tests pass, alongside39 affected-parent cases:89 distinct
passing targeted tests, no skips. Deterministic Q/H interleavings use separate
live stacks and a dedicated shared Q epoch; they are not target cache/scheduler
proof. The fixture's ordinary D cleanup tail remains explicitly bounded.
Exact times, ownership audit findings and fresh source/image hashes are recorded
in [status](status.md). The full project suite and hardware were not rerun.
