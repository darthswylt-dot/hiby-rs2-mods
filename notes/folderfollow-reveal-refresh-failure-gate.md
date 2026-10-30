# Scoped refresh exit after an ordinary destructor failure

2026-10-29. This optional offline successor to the
[delete-release gate](folderfollow-reveal-delete-release-gate.md) addresses one
remaining caller gap. Native refresh `4ACBC0` calls view destructor `493AC0`
at `4ACD8C`, then its branch delay unconditionally replaces the returned status
with 1. The populated-list route can recreate the view and restore its offset
despite an explicit destructor failure. This new gate stops that refresh
invocation's remaining work and preserves its nonzero result.

The destructor and its earlier cleanup already ran. This is a local caller
exit, not rollback, an entry fence, retained ownership, cleanup completion or
coordination of the higher callback chain.

## Exact decision before native success masking

The new native instruction-fetch pair is `4ACD94/4ACD98`, source words
`1680FFD3/24020001`: branch on S4 nonzero to `4ACCE4`, with V0=1 in its delay.
It follows the actual `jal 493AC0` at `4ACD8C`, whose return RA is `4ACD94`.
Checking after `4ACD98` would lose the incoming failure status.

The gate saves all 30 non-SP general registers and HI/LO into 192 private
bytes before reading only its saved S2, RA and V0. Saved S2 must equal pinned U,
saved RA must equal `4ACD94`, and saved V0 must be nonzero to select the stop.
Native `4ACBC0` already established S0=V and S2=*(V+D4). The decision does not
reload the controller, view, widget, name, mutex, registry or queue after the
destructor result. V1 is preserved without interpretation.

On a selected failure, the helper restores the entire saved architecture and
SP, including V0/V1 and HI/LO, and jumps directly to native epilogue `4ACCE4`.
It bypasses both the original branch delay and the separate V0=1 instruction
at `4ACCE0`. The epilogue loads RA from `SP+484`, restores S4 through S0 from
`480..470`, and returns while unwinding 1,160 bytes (`488`). It has no result
overwrite, graph access, service, callback, unlock or free. Native NULL input
already uses that epilogue with V0=-1. This gate preserves the result that
arrived; it does not introduce a normalized status or interpret V1 as a marker.

## Exact branch replay for zero or foreign invocations

Other invocations restore the complete original architecture before replaying
the S4/nonzero branch. The branch's destination is relocated to a local taken
label; copying its original PC-relative instruction unchanged would branch to
the wrong address. The original `24020001` delay effect executes exactly once
on both outcomes. The taken route jumps to `4ACCE4`; fallthrough resumes at
`4ACD9C`. Native `4ACD98` is bypassed, so its delay is not executed again.

The native S4 distinction remains: null/empty primary-list paths set S4=1 and
return the original success convention after destruction. Populated ordinary
paths use S4=0, recreate through `491E80` at `4ACDA4`, then can restore a bounded
offset through `8B43C0` at `4ACDF0`. A selected failure bypasses all that later
constructor, new-view dereference and offset-setting work. Zero remains the
preceding destructor ABI; it does not certify successful cleanup or absence
of errors elsewhere.

The earlier native function has already copied its view name and scope into
stack buffers, read the named widget's offset and primary-list count, and
performed its path tests. The containing operation can also have changed
external state before calling refresh. The gate does not reverse those effects
or any of the destructor's closing, worker cancellation, callbacks, unlink,
purge/detach, name/engine/node free or partial resource cleanup.

## Bounded caller coverage and higher continuation

This covers the ordinary non-Tidal, non-special-prefix call at `4ACD8C`.
The same function has another destructor call at `4ACD1C`; that route still
forces V0=1 in its separate return sequence and is outside this gate.
The `recent` and `music_search_` prefix branches use different reset calls.
The earlier [scope audit](folderfollow-reveal-scope.md) pins these distinctions;
they are path predicates, not a complete view-type or lifetime classification.

There are 49 encoded direct destructor callers. This hook covers one return
site. Encoded entry routes to `4ACBC0` are the call at `4AD8D8` and tail jump
`4AD860`; the latter is called at `4AEC1C`. The conservative J/JAL and relative
branch census finds no incoming target to `4ACD94`, `4ACD98` or `4ACD9C`.
Computed entries, fabricated returns and runtime patches remain outside that
bounded evidence and genuine-entry premise.

Higher callbacks remain active. Wrapper `4AD880` stores the refresh result and
can call `4ACE40(V)` when its S3 flag is nonzero and the result differs from 1;
that helper reads V+3DD8 and can update a property. Callback `450D60` ignores
the result before freeing its operation context. The inspected `4AEC60`
completion callback compares against 1, then reads/frees its operation context
and clears dialog+58 on this error path; it does not retry the wrapper there.
A nonzero word such as FFFFFFFF can also be treated as true by an unclassified caller.
Preserving the local result does not quarantine those continuations, retain
the view or establish whole-instance isolation. The list-destructor loop and
gesture-chain candidates found in the same audit are deliberately deferred.

Missing preceding raw acquisition/release or continuation hooks can retain
masked failures and unsafe paths. All new and inherited redirects must be
coherent; this is not a fail-closed installation protocol for arbitrary partial
activation. No retry, extra unlock, rollback, graph reclamation or free
permission follows from a stopped refresh or a zero result.

## Hard frames, static layout and separate composition

The genuine 1,160-byte native refresh frame and separate 192-byte private save
must already be mapped, writable and retained during their live use. All
simultaneously live frames must be independently nonaliasing with one another,
native/heap/shared storage and native/generated RX. Sufficient transitive
stack, genuine native routes and ordinary service/ABI cooperation are hard
premises. Saving precedes classification; scalar U/RA checks do not authenticate
fabricated invocations. There is no dynamic SP, mapping, wrapping or lifetime
validation and no promise of a safe malformed unwind.

Strict static layout excludes U's full `28C` bytes, R's 24 bytes, declared
extra fixed data and complete native/generated RX from overlap. A declared
protected RX extent must contain the complete fragment. Extra extents affect
layout validation only; they do not add runtime frame guards or allocation
leases. R is used for static exclusion and is never inspected by this gate.

`reveal_refresh_failure_gate_stage.assemble` takes the preceding 11 canonical
addresses and bounded options. Strict zero-default `following_code_bytes` in
the parent and successor protects advertised later RX without appending it.
The parent default remains 91,940 bytes with SHA-256
`332b5cf381ecd46f117651638d992475b8ceed505721f66c8cc1eeecdba58364`.
All 20 preceding default compositions retain their hashes. The canonical
successor is 92,444 bytes: the guarded 91,940-byte prefix plus the 504-byte
refresh gate. Its SHA-256 is
`88c32e213641ce6731c4e6eeef00f7fbf2487cef4976d061e27ec1c682e46d85`.
Completed serial verification is recorded in [status](status.md).

The new result advertises 24 native pairs and one inherited generated explorer
splice, 25 coherent pairs total. It sets
`refresh_destructor_failure_continuation_stopped=True`; caller isolation,
destructor-entry fencing, earlier cleanup rollback, global raw-release proof,
native lifetime and partial-graph cleanup remain false. These are scope labels,
not successful cleanup, native retention or hardware certificates.

Source contracts require the preserved 7,133,528-byte 02fd image, SHA-256
`02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87`.
They pin the native frame, pair/delay, pure unwind, earlier/later work, bounded
caller census, private decision, exact replay and complete static RX. Body-cut
execution fixtures seed prologue-established native state; they do not execute
or certify the whole earlier cleanup, higher callback chain or native scheduling.
Active scrolling stays disabled and hardware remains UNTESTED. No firmware
image, installer, player/device, network, installation, launch, reboot, commit
or push operation is supplied by this increment.

Completed serial verification:20 new source/layout contracts and20 new native/
adverse/cache checks pass, alongside26 affected-parent checks:66 targeted tests
total, no skips. All347 Python sources compile. Fresh hashes confirm the three
saved images are unchanged; their exact verifier passes belong to the preceding
increment. The full project suite and hardware were not rerun. Exact times,
bounded-substitute coverage and remaining limits are recorded in [status](status.md).

The separate [wrapper successor](folderfollow-reveal-refresh-wrapper-gate.md)
splices this gate's already-classified stopped route. For the genuine4AD8E0
saved outer return, it redirects the refresh unwind into a pure wrapper unwind,
skipping that invocation's4ACE40 view work. This stage's default bytes remain
unchanged; other callbacks and refresh routes are still outside that successor.
