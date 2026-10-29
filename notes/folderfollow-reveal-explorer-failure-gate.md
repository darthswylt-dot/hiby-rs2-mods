# Scoped explorer failure exit, not partial-graph rollback

2026-10-28. This optional offline successor to the
[constructor continuation stops](folderfollow-reveal-constructor-continuation-gate.md)
addresses one demonstrated higher-caller gap. After failed registration, the
first constructor previously returned its saved engine to explorer491E80;
492924 stored it at view+CC and492928 enabled it anyway. This separate
composition prevents that specific explorer continuation. It neither frees the
partial graph nor establishes whole-instance isolation, retained ownership,
safe retry, cleanup, an image or a player installation.

## A generated-code splice, not a new vendor instruction pair

The existing first-constructor gate has already saved all30 non-SP general
registers and HI/LO into192 private bytes, classified savedS1 as pinnedU,
classified savedRA as registration return43AE94, and selected nonzero savedV0.
Only its generated `first_gate_stopped` entry is spliced. The source words
there are `8FA80088/01000011`: load savedHI intoT0, then restoreHI. These are
checked against the exact preceding generated assembly, not represented as
bytes from the vendor executable.

The helper uses the existing frame; it allocates no new frame, shared latch,
queue, ownership slot or failure mailbox. It reads the current native
constructor's saved outer return at privateSP+192+84, offset144. Only an exact
value492920 selects the explorer escape. This is the native return from the
specific `jal43AD00` at492918. Nonmatching first-constructor callers retain
the preceding saved-engine return convention. The second constructor and its
status gate are unchanged. V1 is never interpreted as a raw status or marker.

On the selected route only that invocation's private native saved-return slot
is retargeted to emitted `abort_return`. Both outcomes replay the displacedHI
pair exactly once and resume the old first-gate restore at `first_gate_stopped+8`.
The unchanged parent restores the complete saved architecture and nativeSP,
then executes actual stock constructor epilogue43AEA8. That epilogue still
loads the saved engine intoV0, restores its native callee registers and unwinds
136 bytes. Its savedRA now transfers to `abort_return` with the restored
explorerSP, rather than492920. The escape jumps directly to explorer's existing
NULL epilogue492F84.

Explorer491E80 has a6096-byte frame (17D0). Its NULL epilogue loads savedRA at
17CC, setsS0 to zero andV0 fromS0, restoresFP/S7..S0 from17C8..17A8, and returns
withSP+=17D0. Thus the outer explorer operation returns its nativeNULL result;
no new constructor status/engine handle ABI is introduced. There is no UI,
name lookup, enable, cleanup, unlock, free, scan or retry on this bounded exit.

Simply skipping492928 and resuming492930 would be insufficient: later492944,
4929C4,4929F4 and493270 still use or dereference view+CC. The ordinary
epilogue492F50 also returnsS0, the partial view, unlike the nativeNULL epilogue.
The escape consequently bypasses the entire remaining explorer function.

## Earlier effects deliberately remain, and may already have escaped

Before this point491E80 has allocated the16952-byte view, eight2376-byte
objects and a mutex. Resource creation43D400 at4926E4 has already populated
view+3B68. The call459320 at49274C writes resource+7C=view. Callback setters
at4928A8..4928E4 and binder43C020 at492900 already change resource callbacks;
an earlier widget method at492820 has also executed. Controller+F0 and other
view/resource fields have been mutated.

The later owner-list insertion4E5280 at492A3C is bypassed, but absence of that
list membership does not prove exclusive ownership: the resource+7C alias
already exists. ReturningNULL does not erase these mutations, revoke aliases
or justify freeing anything. This diagnostic stop deliberately leaves the
partial graph allocated and earlier effects in place. It provides no drain,
graph rollback, coherent cleanup, quarantine or permission to retry.

The native registration allocation-failure edge still omits registry unlock.
Raw release failures remain facade-masked to nativeV0=0 and do not select the
parent stopped route. Missing acquisition hooks may likewise permit unchecked
publication followed by zero; missing continuation/splice hooks restore the
demonstrated unsafe continuation. Coherent activation is a premise, not an
installation or atomic fail-closed protocol.

There are188 encoded direct calls to491E80. Their behavior after aNULL result
is not globally classified here: callers can continue unrelated work, perform
fallback/relookup or act on already escaped objects. Other first-constructor
callers, the second constructor, computed entries, runtime aliases and forged
frames remain outside this specific explorer exit. Native-callers-isolated,
raw-release-proven, native-lifetime-proven and partial-graph-cleanup-proven all
remain false.

## Hard frame premises and separate opt-in composition

The existing192-byte private save, native136-byte constructor frame and
6096-byte explorer frame must be genuinely mapped, writable, retained and
nonaliasing with native/heap/shared/RX storage. Both native prologues have
already written their save slots. Scope constants and an exact savedRA are
not authentication. No dynamic malformedSP, wrapping, mapping or lifetime
recovery is supplied, and arbitrary helper entry is not an admitted API.
The helper is an interior route after the parent's exact failure decision.

Strict static layout excludesU,24-byteR, extra fixed allocations and complete
native/generatedRX from overlap. The declared generated parent stop reserves
12 bytes: its replaced pair and first resume word. It must precede the helper,
and any advertised protectedRX must contain both regions. These declarations
do not prove runtime stack mapping or ownership.

`reveal_explorer_failure_gate_stage.assemble` uses the preceding11 canonical
addresses and options. It extends complete outerRX protection, patches only
the verified parentHI pair in that guarded prefix, and appends the helper.
The returned hook inventory distinguishes20 unchanged native pairs from one
generated-code pair,21 total. The generated pair is present in the returned
bytes and advertised as an idempotent instruction-fetch override. It is not
a twenty-first vendor source hook. No saved firmware image or installer is
modified by this composition.

The parent constructor stage's strict aligned `following_code_bytes` protects
but does not append the helper range. Its zero default retains87,112 bytes
and SHA-256
`c13d8485f4644b90c1dd2029877a13626cd5d7231e6fa65c54ff6ec87f208dd8`.
All16 preceding default compositions retain their documented hashes. Exact
canonical composition is87,168 bytes:87,112 guarded prefix bytes plus the
56-byte helper. Its SHA-256 is
`540034a7349e240a95047fbb39b01a48dc8379669f1510d53c59e64992c888e9`.
Completed serial test counts are recorded in [status](status.md).

Contracts use the preserved7,133,528-byte02fd source, SHA-256
`02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87`.
They pin native save/unwind words, the generated splice separately, earlier
escaped aliases, bounded caller inventories, exact fullRX coverage and all
prior default hashes. Execution fixtures retain bounded service substitutes;
they are not native scheduling, graph destruction or hardware proof. Active
scrolling stays disabled and hardware UNTESTED. No player installation,
launch, reboot, device/network operation, commit or push is part of this step.

A separate [constructor release-gate successor](folderfollow-reveal-registry-release-gate.md)
now supplies a nonzero registration result when either genuine constructor's
actual pinned raw release is nonzero or its fresh evidence is missing. The
existing local constructor/explorer stops can then run. It does not change
this stage's default or repair earlier publication, escaped aliases or cleanup.
This stage's strict zero-default following_code_bytes reserves the successor
RX without appending it; its87,168-byte/540034a7... default remains unchanged.
