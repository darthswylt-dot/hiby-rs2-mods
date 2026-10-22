# Known native reset/reconcile scope boundary

Source-only audit, 2026-10-21. Active reveal remains disabled. This note does not
request a player launch, install or physical test.

Reference: `artifacts/import-20261001/hiby_player_02fd.bin`, 7,133,528 bytes,
SHA-256 `02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87`.
All addresses below are original ELF virtual addresses, not new code addresses.
The structural tests require this exact input; no missing-input skip is used.

## What a bounded open-scope filter can establish

The existing entry-only contents revision can reject a known boundary crossed
after a renderer began. It does not distinguish a writer that entered earlier
and is still active. These two inspected native functions have bounded entry /
normal-return pairs that can support a *negative* open-scope filter. They do
not form a universal list mutation transaction and do not retain any UI owner.

| Function | Native frame | Entry words | Normal return words |
| --- | --- | --- | --- |
| Reset `491240` | `48` | `27BDFFB8 AFBF0044` | `4913F0: 03E00008 27BD0048` |
| Reconcile `4919E0` | `258` | `27BDFDA8 AFB3024C` | `491D08: 03E00008 27BD0258`; `491E68: 03E00008 27BD0258` |

Hexadecimal offsets/frames are used in the table. Each exit is `JR RA` with the
native frame pop in its delay slot. Every normal path from the named entry
reaches one of the listed exits with native RA reloaded after the last call.
There is no other reachable return or direct non-call escape in either bounded
body. The analysis treats native calls as returning normally; it does not
instrument exceptions, unwind, `longjmp`, termination or unknown computed entry.
A missing observed end must remain open/unknown or fault, never imply quietness.

A global aligned executable-word census includes direct J/JAL, ordinary and
likely branches, REGIMM and COP branch encodings. It finds **no direct target to
either word of any exit pair**, and no target to entry+4. From outside each
body, all encoded direct inbound edges target the named entry only:

- Reset JAL callers: `45259C`, `4A2D18`, `4A5ED4`, `4ACE0C`, `4ACE20`, `532AC4`.
- Reconcile JAL callers: `492B8C`, `494038`.

This is not an all-indirect-call or arbitrary control-flow proof. Scanning an
executable word that happens to be data can overcount possible direct targets;
absence of an encoded direct target does not rule out a runtime function pointer.

## Native carrier and wrapper obligations

Within reset `491240..49144C` and reconcile `4919E0..491E70`, native `SP+14`
has no direct memory access or locally derived address. All native SP uses are
enumerated by the pinned test:

- Reset memory offsets: `10,20,24,28,2C,34,38,3C,40,44`; derived argument `SP+20`.
- Reconcile memory offsets: `10,228,22C,238,240,244,248,24C,250,254`; derived
  arguments `SP+20`, `SP+228`, `SP+238`.

`SP+10` is actually used as the fifth outgoing argument: `SW zero,10(SP)` at
`4912B0` and `491C00` before the native `+410` binder call. It is not available
for a private carrier. `SP+14` is outside the four O32 argument homes but would
be a sixth argument; absence of its use relies on these inspected call shapes
and valid actual callee ABI. It is not a universal callee/alias/stack-write proof.

An entry wrapper must replay its displaced native prologue first, then allocate
its own observer frame and write the private ticket to **native** `SP+14`.
Reconcile's second displaced word saves **s3**, not RA: native RA is saved later
at `491A08`. The observer must preserve original entry RA until that native save.
An exit wrapper runs after native s-register/RA restoration and must preserve
the actual native v0, volatile registers and HI/LO, then pop the original frame
exactly once and return through original RA. It must not replay JR as a call,
double-pop the native frame, infer success from v0, or mint an end without its
exact private invocation binding.

Raw entry arguments are not a universal `(owner,view)` pair. Reset preserves
`a0` as U in s2 and `a1` as V in s0. Reconcile preserves `a0` as U in s1,
`a1` as old UTF-16 path in s2, and `a2` as target path in s3. A diagnostic table
must name copied entry values `raw_arg0` / `raw_arg1`, without dereferencing or
pretending that reconcile arg1 is a retained view.

## Return is not successful mutation or destruction

Reset has no normalized return value. The flag-zero branch can retain masked
v0=0 from `4913C4`; the callback branch can retain `499C20`'s return; the null-V
path retains the logger return before rejoining the common epilogue. An end
receipt can mean only that this native invocation returned normally.

Reconcile's `491D08` epilogue returns the resolved V/null loaded from local
`SP+238` (reloaded after the optional callback). Its `491E68` epilogue forces
v0=0 at `491E64`. Neither value is SQL/append/RESET success or a settled-list
certificate. Native nested callbacks/producers can execute inside these scopes.

The existing close-attempt pair `493B0C/10` only sets `V+44=1`; it is not a
scope end or proof of death. Actual free(V) is much later at `493FDC`, and parent
navigation can return without freeing V. Do not close a writer scope or grant
ownership merely because a close attempt was observed.

## Renderer argument is not immutable UI-request provenance

The apparent renderer “request” argument has a narrower meaning. In the
inspected `438200` outer-render path, cached-descriptor lookup `47AB40` at
`43843C` writes `SP+1B0`; NULL branches at `438448` to the cache-miss path.
That path calls `47A920` at `438724` with output pointer `SP+1B0`, then loads
the resulting descriptor into a2 at `438738` and invokes W+148 at `438740`.

`47A920` brackets `47A6E0` with C+27C/C+280 callbacks and writes its return
through the supplied output pointer. `47A6E0` allocates a fresh `70`-byte node
at `47A73C`; the returned descriptor is **node+8**, preserved at local SP+18
and returned by `47A898`. Requested coordinate at node+58 and height at node+68
therefore appear as descriptor+50/+60, exactly the renderer loads at
`49078C/490790`. The allocation can fail and return NULL; that is not a receipt.

Consequently this descriptor is service/cache-canvas data newly created during
rendering, not a pre-existing immutable UI/playback request. A fresh descriptor
stamp can be minted after reset even when the outer cause is stale. Descriptor
address equality or a new stamp here cannot close the original request-freshness
gap. An open-reset/reconcile filter narrows known overlap only; it does **not**
solve stale UI request entry, request/playback association, full writer coverage,
native ownership, coherent snapshot acquisition or the final UI transaction.

`scripts/test_reveal_native_scope_contract.py` pins the exact pairs, global
direct entry/exit census, SP carrier premises, RA restoration on bounded normal
paths, argument/result meanings and descriptor allocation/forwarding chain.
These are structural source checks, not target CPU/scheduler or hardware safety
certification.
