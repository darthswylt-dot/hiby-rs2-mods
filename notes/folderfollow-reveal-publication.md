# Reveal publication: scope rebinding and worker post-fill callback

2026-10-07, bounded local audit of reference
`02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87`
(7,133,528 bytes). No binary change or device action. This supplements
[ownership](folderfollow-reveal-ownership.md) and
[dispatch](folderfollow-reveal-dispatch.md); it does not establish a live adapter.

## Rebinding is not confined to the UI loop

Constructor 0x4A08E0 installs 0x4A0EE0 into P+0x410 at
0x4A0908..910. That method unconditionally stores its nonnull list argument
into P+0x1BC at 0x4A0F2C after reading its count. It then updates geometry
and row widgets through 0x4A0B40 at 0x4A0FB8. Neither its entry nor that
store establishes a new generation or independent successful fill.

Two concrete caller classes reach the same method:

- Reset 0x491240 frees V+0x64/+0x68 at 0x49126C/280, invokes its loader
  V+0x4218 at 0x49129C, then calls P+0x410 at 0x4912B8. Construction also
  calls P+0x410 at 0x492820. The already-established queued event 0x11A
  reaches this reset serially with timers in that particular music-loop
  invocation; this does not serialize it with the fill worker.
- The worker invokes job+0x2BC at 0x48EC74, after the job+0x2C0 fill call
  at 0x48EC54, while T+0x10 remains held from 0x48EC34 to 0x48EC84.
  The relevant callback is 0x48F880. It resolves V using job+0x48's name
  at 0x48F8A4, obtains P=V+0x3B68 and V+0x64, then calls P+0x410 at
  0x48F8D8. Thus the P+0x1BC store also runs on the known background worker.

Binding of this worker callback is explicit: 0x490780..788 writes
0x48F880 into V+0x3B60, which is +0x2BC of the job template V+0x38A4.
Enqueue 0x48F180 copies 0x2C4 bytes at 0x48F1B4..1C0 under T+0x10,
and resolver 0x48E980 writes the Files fill callback into job+0x2C0
at 0x48EA34. This is a copied job template, not a retained V/list generation.

Other inspected reset-like paths free both lists directly and subsequently
call P+0x410: 0x491BB0/BC8 -> 0x491C08 and
0x494A4C/A64 -> 0x494AA4. Consequently hooking only 0x491240 misses those
local reset implementations. Their entire Files applicability and outer
thread/cancellation coverage were not established by this bounded pass.

## The V+0x64 bind precedes enqueue locking

0x4928D0 installs 0x4906E0 into widget W+0x148 through 0x459540
(store at 0x459548). Renderer 0x438200 calls W+0x148 at 0x438740.
This gives a concrete render callback route, not universal thread ownership.

Inside 0x4906E0, the last child P is resolved through W+0xFC and its
associated V through 0x459340. It then:

- copies request data into the V-resident job template;
- reads P+0x1BC at 0x490770 and stores V+0x64 at 0x49077C;
- installs the post-fill callback at 0x490788 and copies the scope at
  0x4907B8..7C4;
- only afterwards calls enqueue at 0x49080C, or shared-worker enqueue at
  0x490878 (both 0x48F180, whose lock is at 0x48F198).

The visible T+0x10 acquisition therefore does not protect the preceding
binding/template writes. No common caller-held ownership bracket between
these changes, UI reset, and worker publication was proved. The render path
waits for controller+0x144 after W+0x148 returns (0x438764..76C); the worker
signals that object at 0x48EC90. That wait/signal is useful local ordering,
not a universal list-generation or SQL-completion certificate. No new lock
should be wrapped around the callback without checking enqueue reentrancy.

## A post-fill callback exists, but is not a completion certificate

For Files, 0x48D080 invokes 0x6F7CA0 at 0x48D1B8 and writes the new
window start/requested length through P+0x404/+0x408 at 0x48D1C8/1D8.
The worker's +0x2BC callback occurs after those calls on this branch.
However:

- 0x48D108 can skip refill and still reach the same zero-return path;
- the fill return is not checked before those metadata setters;
- producer 0x6ED5C0 advances its ordinal at 0x6ED6F0 without checking
  the append result left in v0;
- terminal step result reaches 0x6ED704 in v0, but that call overwrites it;
- the folder-query wrapper discards the producer return at 0x6F8BF4..BFC,
  explicitly setting its return accumulator to zero;
- even the worker's explicit -1 fill-error branch at 0x48EC60 goes through
  0x48EDCC..DD8 to job+4=2 at 0x48EC80 and then signals the renderer.

Neither job+4=2, the renderer wake-up, nor P+0x410 implies complete rows.
The post-fill handler also resolves the view again by name; it does not
check a captured generation against the newly resolved view before binding.

## Concrete next-hook contract, not an implementation

There is no single established hook supplying both a valid copied row map
and complete reset cancellation. The next bounded adapter design should
combine these already identified observation stages:

1. Begin a fresh *loading* generation before a proven folder-query fill,
   copying scope, destination token, mode, offset and requested length.
   Invalidate before any relevant reset/rebind; a reused pointer is not a
   generation. P+0x410 and W+0x148 entries are rebinding leads, but do not
   replace the earlier reset/free/scope-change cancellation points.
2. At post-append 0x6ED6F0, copy the producer-owned descriptor identity and
   append result, before the ordinal increment. The previously audited
   mode-zero frame has descriptor at sp+0x20, path at sp+0x24 and cue at
   sp+0x444. Accept index zero; reject any append/index inconsistency. Use
   copied values only, never retained descriptor or active-cache pointers.
3. Capture the terminal step before 0x6ED704 and cover early/bind errors.
   Require successful termination and loss-free, consistent row events;
   a producer/wrapper return or matching count alone is insufficient.
4. On the verified worker refill branch, after 0x48D1D8 and before handing
   rows to P+0x410, a hook could publish that independently validated copied
   snapshot. The initial synchronous fill needs its separate completion
   path. Publication must match the generation captured at begin; a callback
   name or list address must not relabel an old job as the current scope.
5. A UI consumer may use only an owned immutable snapshot with proved
   cancellation/ownership. The missing common reset/rebind protocol and
   live target lifetime remain gates; T+0x10 alone does not close them.

No active-cache scan, extra database query, live setter or firmware hook is
introduced here. `test_folderfollow_reveal_publication_contract.py` pins
the narrow original-instruction anchors with the required reference hash;
it does not assert global concurrency safety or complete mutator coverage.

## Executable publication protocol (host only)

`scripts/folderfollow_reveal_publication.py` now implements `RowPublication`,
the missing staging/validation step before `CompletedRows`. This is a
sequential event model over already-owned inputs, **not a cross-thread
mailbox or live adapter**. No firmware hook, memory fence or generation
acquisition has been emitted. The original FILL diagnostic decoder is
unchanged; its historical records must not be relabelled as a current view.

The bridge must first call `activate` with a verified `ViewGeneration`.
Content epochs must strictly increase across all views for the lifetime of
this protocol instance. `activate(None)` cancels without resetting the epoch
or ticket counter. Each activation permits exactly one whole, zero-offset,
mode-zero fill with initially empty output and verified total <=512. A new
fill or stock mutation needs a fresh generation **before** the mutation.

`begin` issues a non-reused ticket. Each `append` requires the next ordinal,
the same successful append index, actual count=ordinal+1, a unique exact
path/cue identity and a terminated representable UTF-16 path of at most 259
code units. Index zero and signed cue -1 are supported. Paths sharing an
audio image remain distinct through their cue number; cue is never a row.
The collector stores new immutable identities, not producer/list pointers.

Only a separately received SQL terminal 101, then an end event with matching
actual/return/total counts, produces an immutable `CompletedRows`. Ready
state is never exposed while loading, even after the terminal alone. Reentry,
duplicate rows/terminal/end, partial counts, loss reports and unexpected
same-ticket events revoke ready state and poison that generation. Late events
from an old ticket are ignored without contaminating a newer fill. Ticket
exhaustion disables further fills instead of wrapping.

The event bridge must serialize calls, preserve this instance while events
remain outstanding, report loss/uncertainty, and invalidate on every relevant
stock scope/list mutation. The class cannot detect an omitted invalidation,
a coherent-looking torn input, or all events missing from an unobserved fill.
Those are precisely the remaining live-hook/ownership obligations. Returned
snapshots cannot be revoked in caller memory: a UI action still needs current
generation/rows revalidation and retention through setter/refresh.

22 protocol tests cover publication ordering, all one-row event permutations,
512 rows, invalid/malformed inputs, incomplete/duplicate/error endings,
every cancellation stage, old events after rebinding, reported loss, reused
epochs, non-wrapping tickets and integration with `RevealModel` followed by
pre-action cancellation. They model serialized bridge events, not stock
threads, MIPS instruction ordering or device behavior.
