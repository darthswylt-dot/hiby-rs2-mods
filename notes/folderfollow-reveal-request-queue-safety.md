# Queued paint request safety audit

Independent offline source audit, 2026-10-21. No player access, installation,
launch, signal, rearm or reboot. No native allocation-size change or request
token transport is implemented by this audit. Autoscroll remains disabled;
hardware is **UNTESTED**.

Reference: `artifacts/import-20261001/hiby_player_02fd.bin`, SHA-256
`02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87`.
Addresses below are reference ELF virtual addresses. `C` denotes the engine
paint object, not the controller or a retained current UI owner.

## Safety verdict

A completed, observed reset does not prove that the next paint callback was
requested after that reset. A rectangle already in `C+34` can remain queued
across reset `491240`, then be consumed after the reset's native scope has
closed. The callback resolves a widget by the object's current name; a later
renderer-entry ticket or newly allocated cache-canvas descriptor does not
recover the queued rectangle's birth identity.

This is a source-permitted sequence, not an assertion that a particular player
run has exercised it. It does not establish a use-after-free, a thread model,
or that every callback taking this route is stale. It establishes the missing
provenance needed before admitting such a callback as a fresh UI request.

The [engine boundary audit](folderfollow-reveal-request-engine-boundary.md)
examines the callback/request carriers. The existing
[native scope exclusion](folderfollow-reveal-native-scope-stage.md) rejects
known overlap; a scope that has already closed cannot by itself identify an
older queued cause.

## Concrete reset / old queue / later consumption sequence

The following assumes the original native preconditions: usable `C`, non-null
`C+44`, allocations succeeding, the wrapper's global gate allowing dispatch,
and a later engine paint pass. No concurrent writer is required for this
sequence.

1. Before reset, `8B4280(C, old_rect, metadata)` takes its non-null rectangle
   branch. It allocates **16 bytes** at `8B42B0`, copies rectangle words 0..C
   at `8B42D8..42EC`, and calls
   `8B3CC0(C+34, copied_rect, metadata)` at `8B42E8`.
2. `8B3CC0` allocates a separate 16-byte list node. Its fields are payload at
   0, metadata at 4, previous at 8 and next at C. At `8B3CF0..3D24` it walks
   to the tail and appends, rather than replacing the existing queue. The
   empty-list branch publishes the first node at `8B3D40..3D4C`.
3. Reset `491240` calls `47AA20` at `4913A8`, with controller `U` and the name
   loaded from `*(V+CC)`. `47AA20` locks the controller, walks `U+50`, unlinks
   matching cache-canvas nodes and frees their backing data and nodes
   (`47AA68..47AB10`). This is not the engine's `C+34` queue. The inspected
   reset/cache-removal bodies do not clear that queue or invoke its deletion
   path.
4. Reset then calls `459840(C=V+CC, rect=reset_SP+20, a2=0)` at `4913B8`.
   The rectangle argument is **non-null**, including the alternate `V+6C=0`
   route through `491420..49142C`. `459840` checks the global gate via
   `468D40`, then forwards the same arguments to `8B4280` at `459874`.
   Consequently this reset can append a new rectangle *after* the old one.
   Its non-null branch does not set the full-redraw bit or flush the queue.
5. Reset returns through `4913F0/4913F4`. A later `8B4660` reaches the queued
   loop: `8B4748` loads `C+34`; `8B4754/4758` load node payload and metadata;
   `8B475C` calls `8B3FA0(C, payload, metadata)`; `8B4764..476C` advance to
   the next node. Thus an earlier queued rectangle can be processed after
   reset's normal return.
6. `8B3FA0` uses the queued rectangle for intersection/split geometry and
   calls `C+48` at `8B40E4` with a newly built stack descriptor. `439EC0`
   uses `C+0` (name) in the lookups at `439F34` and `439F5C`, then invokes
   `438200` at `439F90`. None of these original queue fields contains a
   reset generation or immutable UI-request token.

After the queued callbacks, `8B4774` calls `8B3F00(queue, 1)`, whose
`8B3100` payload callback frees each rectangle; list cleanup frees its node.
`8B4788` clears `C+34`. Deletion after processing does not establish that a
rectangle was born after reset.

## Full redraw does not erase this provenance gap

Only the null-rectangle branch of `8B4280`, at `8B437C..4398`, ORs
`40000000` into `C+3C`. It does not replace or clear `C+34` there.

In `8B4660`, a pre-existing full-redraw bit selects `8B4920`. That path
constructs a full descriptor and calls `C+48` at `8B4990`, then updates buffer
bounds at `8B49A8..49B4`. It subsequently loads `C+34` at `8B49B8` and, when
non-null, branches back to **the same queued loop at `8B4754`**. Full redraw
therefore does not mean that pending rectangles were discarded. Its full
callback also has no stored original request identity and must remain
`unknown` under a future queued-receipt scheme.

There is a distinct failure route: failed buffer creation at
`8B4914 -> 8B4BB0` frees `C+34` without those queued callbacks, clears it at
`8B4BBC`, and returns zero. That failure path must not be confused with the
ordinary full-redraw path.

## Bounded producer / consumer inventory

The executable direct-call scan finds six calls to generic append `8B3CC0`:

| Call site | Target list / payload origin |
| --- | --- |
| `8B083C` | Window/engine list at entry object +28; not paint `C+34`. |
| `8B0E30` | Local list at `SP+5C`; new 16-byte rectangle. |
| `8B0EA4` | Local list at `SP+58`; new 16-byte rectangle. |
| `8B0FB4` | Entry context +2C; newly allocated 44-byte geometry record. |
| `8B1060` | Callback-supplied target list; the found registration in `8B0D40` passes its local `SP+18` list. |
| `8B42E8` | Paint queue `C+34`; new 16-byte rectangle from `8B42B0`. |

No aligned file-backed literal or executable address construction for
`8B3CC0` was found by the inspection helper. That scan is not a universal
proof against arbitrary computed aliases or unclassified indirect entry.

The three direct calls to `8B3FA0` are materially different:

| Call site | Rectangle source | Third argument |
| --- | --- | --- |
| `8B475C` | Current `C+34` node's payload | Current node's metadata |
| `8B4A14` | Existing native buffer geometry at buffer +14 | Zero |
| `8B4AF8` | A 16-byte rectangle within a stack geometry array | Zero |

No aligned pointer literal or executable address construction for `8B3FA0`
was found. The queued invocation's return PC is `8B4764`; the other two
invocations do not establish a 20-byte allocation. An unconditional read of
`rect+10` in `8B3FA0` would therefore be out of bounds on legitimate native
paths.

The engine object's allocation is 84 bytes (`8B4134/4138`) and is zeroed by
`8B414C/4150`, so `C+34` begins empty. The inspected destructor `8B4220`
frees `C+44`, then `C`; it has no explicit queue flush. This audit does not
infer a general lifetime lease or a spare safe field from that observation.

## Minimum guards for any future receipt transport

Extending only the allocation at `8B42B0` from 16 to 20 bytes is **not yet an
approved implementation**. A future design would need, at minimum:

- Exact pinned source words and inbound-flow checks for every changed pair;
  no broad assumptions about all callers of generic list or paint helpers.
- Positive provenance that the allocation being read is the successfully
  extended queued allocation, with its tail initialized before publication.
  A matching pointer, rectangle contents or current generation is not that
  provenance. Exhaustion, missing publication and ambiguous origin fail
  closed; IDs cannot be reused.
- A strict queued-callsite gate before any `rect+10` read: original return PC
  `8B4764`, exact current loop/node/payload relationship, expected frame and
  scalar bindings. The `8B4A14`, `8B4AF8`, full-redraw and unknown routes must
  not read that tail and must not gain a fabricated receipt.
- Unmodified native metadata. Queue `a2` is stored at node+4; `8B3FA0`
  preserves it in `s5` and writes it into callback descriptor `SP+68` at
  `8B40E8`. It is already used, not a spare token slot.
- Exact invocation-local propagation through all geometry splits and callback
  frames. A global current-request pointer or unretained pointer registry
  cannot prove which request a nested/re-entered callback belongs to.
- Explicit rejection across observed reset/reconcile boundaries and open
  scopes, plus unknown handling for unclassified writers and original
  full-redraw causes. A birth token still would not prove retained UI owner,
  settled contents, coherent capture, cancellation or native lifetime.
- Preserved original allocation-failure behavior, callback ordering/results,
  native memory ownership, ABI and cleanup. A larger allocation is a native
  behavioral change, not merely private diagnostic state.

These are necessary checks, not a claim that they suffice. The current safe
outcome is to record the missing queued-cause identity and keep active reveal
and scrolling disabled.
