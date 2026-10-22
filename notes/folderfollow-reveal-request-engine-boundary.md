# Deferred paint rectangles are not immutable UI requests

2026-10-21. Local source audit only. Reference:
`artifacts/import-20261001/hiby_player_02fd.bin`, 7,133,528 bytes, SHA-256
`02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87`.
No device access or firmware patch. The new
`scripts/test_reveal_request_engine_contract.py` pins the bounded facts below.

## There is an earlier, copied paint-region carrier

`459840(C,rect,metadata)` checks the global redraw-enabled predicate
`468D40` and forwards the three original arguments to `8B4280`. This is not
a lock acquisition or a retained-view check. In the inspected nonnull-rect
branch, `8B4280` allocates **16 bytes** at `8B42B0`, then copies exactly four
rectangle words at `8B42D8/DC/E0/EC`. It calls
`8B3CC0(&C+34,rect_copy,metadata)` at `8B42E8`. The input rectangle can be
stack-local; the queued copy precedes deferred rendering.

The generic helper allocates a second **16-byte** list node. All four words
are occupied: payload at +0, the unmodified third argument at +4, previous
link at +8, and next link at +C. There is no native spare ticket field in
either allocation. The third argument is not a request-generation field.

The encoded direct-call census for `8B3CC0` is:

| Call | Classified destination in the inspected caller |
| --- | --- |
| `8B083C` | Parent +28 object list; metadata is the parent |
| `8B0E30` | Temporary region-copy list at local SP+5C |
| `8B0EA4` | Temporary split-region-copy list at local SP+58 |
| `8B0FB4` | Engine +2C result list, holding 2C-byte result descriptors |
| `8B1060` | Caller-supplied selected-object work list |
| `8B42E8` | Render object C+34 rectangle-copy queue |

There is no aligned file-backed word equal to `8B3CC0` in this reference.
That and the six encoded calls are a bounded source census, **not** a proof
against indirect entry, computed aliases, memory corruption, or other writes
through an aliased list-head pointer.

## Borrowing and deletion occur inside the render pass

`8B4660` reads C+34 at `8B4748`. For each list node it loads payload and
metadata at `8B4754/58`, and calls `8B3FA0(C,payload,metadata)` at
`8B475C`, with return address **8B4764**. Only after these callbacks does it
call `8B3F00(head,1)` at `8B4774`, then zero C+34 at `8B4788`.
`8B3F00(...,1)` selects `8B3100`, which frees each payload; `8B3E00` also
frees each list node. The separate render-canvas allocation at `8B490C`
branches on nonzero return to `8B4BB0`; this failure cleanup has the same
mode-1 delete at `8B4BB4` and zeroes C+34 at `8B4BBC`. It is not the queue
copy's allocation-failure path: the initial 16-byte copy failure returns -1
at `8B43B4` before publication, whereas generic node-allocation failure
returns without linking a node. No diagnostic patch changes these behaviors.

The queue copy is not modified on the inspected `8B4280 -> 8B4660 ->
8B3FA0` route: the latter constructs and modifies stack-local subrectangles.
However, `8B3FA0` also has two other direct callers, `8B4A14` and `8B4AF8`.
They supply a cache rectangle and a stack-generated rectangle respectively,
both with metadata zero. Neither proves a queued allocation exists. Reading
an appended word from every `8B3FA0` input would therefore be out of bounds
on these native routes. The queued route must at least distinguish the exact
`8B4764` return address before any hypothetical extension read.

At `8B40E4`, C+48 receives a pointer to a **20-byte stack descriptor**:
two rectangle pointers at +0/+4, zeros at +8/+C, and the original queue
metadata at +10 (stored in the call delay slot at `8B40E8`). Metadata remains
native payload; it must not be silently repurposed because one consumer
appears not to read it. `8B3FA0`'s native frame is B8 bytes. SP+14 has no
direct SP-relative access or locally formed address in that bounded function;
this is only a local carrier premise, not an indirect-callee ABI guarantee.

No retained native queue/view ownership follows from the list traversal.
These helpers contain no established whole-transaction owner lease. In
particular `8B4280` continues to read the copy after publishing it to C+34;
a patch must not assume an independently running consumer cannot free it.
The existing UI-owner boundary remains required.

## Full redraw has no per-request identity

For a null input rectangle, `8B4280` does **not** allocate a request. It ORs
`40000000` into C+3C at `8B4398` and invalidates the parent rectangle.
Multiple causes therefore coalesce in one mutable bit. The render pass can
also set this bit at `8B1510`. `8B4660` clears it at `8B46E8` before dispatch.
The full-render C+48 call at `8B4990` uses newly constructed stack rectangles
and a descriptor whose +8 is 1 and +C/+10 are zero. It is not borrowing an
immutable queued UI-request carrier. A queued-only filter cannot admit this
branch by inventing a new stamp when the full-render callback starts.

Parent invalidation also merges rectangles into parent+14 through
`8B06E0 -> 8B3140`. `8B1420` produces fresh selected-region descriptors
through `8B0D40`, renders them, frees them, and clears the parent's four
dirty-region words at `8B1550..5C`. Those temporary descriptors represent
derived paint geometry, not an original folder/playback cause.

## The render object persists while reset queues another repaint

`8B4120` allocates and zeroes **84 bytes** for C, copies the render callback
to C+48, and copies its context to C+50. The two inspected viewgroup
constructors supply callback `439EC0` and controller U as context.
The C teardown in `4395A0` first unlinks the controller registry entry,
frees its name, deletes the C+34 payload queue, calls `8B4220(C)` (which
deletes C+44 then C), and frees the registry entry, while bracketed by the
controller's +274/+278 callbacks.

That deletion is different from list reset `491240`. Reset calls cache-canvas
cleanup `47AA20` at `4913A8`, then reloads the existing V+CC C pointer and
queues a new nonnull rectangle through `459840` at `4913B8`. The inspected
reset body does not explicitly flush C+34 or replace V+CC; it does not prove
that previously queued paint geometry belongs to the new folder generation.
Indirect callbacks and aliases remain outside this bounded negative claim.
Reconcile `4919E0` also calls `490D00` at `491CBC`; the latter reloads V+CC
and passes nonnull local SP+18 to `459840` at `490DB0`. Neither explicit
reset/reconcile repaint should be mislabelled a null-rectangle full redraw.
In these two bodies and `490D00`, there is no encoded non-SP-base word store
with displacement +34 or +CC. This narrow syntactic check still does not
cover indirect callback writes or computed aliases.

`439EC0` does not receive a frozen W/V from the queued copy. At callback
time it reads C+50, looks up resources by C's name through `485DE0` and
`485420`, resolves W through `439E20`, then calls `438200` at `439F90`.
Consequently even a genuinely old copied paint rectangle can lead to a
fresh cache-canvas descriptor and fresh renderer-entry mark after reset.

## Consequence for a diagnostic extension

This audit identifies a real **pre-existing paint-region allocation** on one
route; it does not identify an immutable UI/folder/playback request with a
retained owner. A future exact-source extension would need to prove both
allocation coverage and borrowed transport before adding an appended field,
stamp it before publication, preserve all original metadata/geometry and
allocation-failure behavior, and leave synthetic/full/coalesced routes
unadmitted. The six-call census alone does not authorize a rect+10 read or
an allocation-size patch. No pointer registry or extra native tail read is
added here.

Current-request freshness, full writer coverage, coherent capture, native
view lifetime and the final UI transaction remain separate unsolved gates.
These source tests do not authorize active scrolling or hardware installation.

## Executable age counterexample, not an active fix

`scripts/test_reveal_request_freshness_gap.py` runs the pinned native reset
body, the redraw facade, the nonnull queue producer, generic native append,
the queued-loop/cleanup segment and `8B3FA0`'s descriptor builder in the
instruction harness. Allocator, resource/cache, SQL/list binder and in-bounds
geometry helpers are explicit hostile-ABI stubs. The queued-loop starts at
`8B4740` with its required live scalars; earlier surface-selection branches
are not simulated. No player, firmware output or new runtime read is involved.

The callback at `439EC0` is an explicit external harness stub. Its optional
widget-to-job work uses the previously tested composed lineage/row/operation
fixture, not a claim that all omitted widget/SQL routines or scheduling execute
in that way. The callback source contracts separately establish the native
lookup/frame chain. Thus this is not proof of stale rows, a use-after-free,
complete UI execution, or an observed hardware interleaving.

The bounded tests nevertheless establish a concrete information gap:

- An old rectangle survives the executed reset; reset appends another rectangle.
- Both callbacks then run after the scope closes. The old rectangle's metadata
  is preserved and supplied to the callback first.
- In the composed diagnostic fixture, original renderer R=3, producer R+1=4,
  exact callback association and scope quiet can all pass for this old cause.
  Contents-current, coherence and autoscroll authority still correctly stay false.
- Queueing the same marked rectangle *after* reset changes its relative native
  callback order but yields **identical entire private capture bytes** and
  decoded reports. The existing format has no request-birth information with
  which to distinguish those two fixtures. No counter or capture byte is forged.

Seven instruction/counterexample tests and 29 pinned source contracts pass.
This validates the need for an upstream immutable birth receipt; it does not
validate a particular implementation. In particular, a fresh callback stamp,
quiet scope, current name or newly allocated canvas is not a substitute.

The next design must bind a justified receipt before queue publication, preserve
original metadata and failure/cleanup semantics, distinguish all native borrow
sources before any added read, and carry only that already-frozen identity
through the callback frames. Full/coalesced/synthetic/unclassified routes remain
unknown. See [callback frame boundary](folderfollow-reveal-request-callback-boundary.md)
and the independent [queue safety audit](folderfollow-reveal-request-queue-safety.md).

Full repository regression: **1158 tests pass, no skips** (194.524 s). After the
fixture-only tightening of C's mapped allocation to its exact native 0x54 bytes,
all 36 focused tests were rerun and passed (6.242 s). All 161 Python scripts
compile and tracked/new text files pass whitespace checks. The preceding
saved scope-stage firmware remains byte-identical and deterministically
verified, SHA-256
`404827620fc6addba436c1911eb89b72b633562d84331de9e0097ede9469b0d5`.
No firmware change or player operation was needed for this follow-up.
