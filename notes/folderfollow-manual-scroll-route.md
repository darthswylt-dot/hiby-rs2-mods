# Files scrolling route after the FILL hardware run

2026-09-30. Static/local investigation only; stock remains running on the
player. No firmware build, installation, device call, commit or push in this
step. This follows the completed [FILL run](folderfollow-fill-diag.md).

Further follow-up: [UI event loop and delayed refresh](folderfollow-refresh-dispatch.md)
connects queued rendering and timer dispatch to the same inspected loop and
identifies a separate self-removing timer route that does not require V+0x8C.
The +0x8C gates below apply specifically to the render-completion callback,
not to every visible-row refresh.

## What the capture settles, and what it does not

The final FILL log contains ten complete accepted fills, including Slayer's
13 cue rows and Sleep's covers + six cue rows, with 65/65 events drained and
zero reported losses. All offsets are zero. Neither physical Next nor manual
scrolling produced another captured fill in the Slayer intervals. Thus a SQL
refill on every track change is not supported by these observations.

The visible failure is unchanged: highlight moves beyond the viewport, volume
works, and manual scrolling reveals the highlight. FILL does not sample the
viewport or prove continued validity of a list after the captured fill. The
earlier SCRL run independently measured manual offset changes 0 -> 330 while
physical Next left offset zero. Neither run records which scrolling callback
actually executed, so the route below is static evidence, not a runtime trace.

## A Files-specific input path reaches the offset setter

The data table at `0xA98B34` contains `vg_listview_explorer`; its callback
word at name+0x40 (`0xA98B74`) is **0x49B000**. This is distinct from the
main-category record naming `0x49DB60` at `0xA9D93C`; the latter must not be
mislabelled as the explorer callback. Table identity alone does not prove
which event was dispatched in the measured run.

The explorer-associated path is:

1. `0x49B000` resolves owner state, processes input through `0x4B9D60`, and
   branches on controller `+0xD8`. State 2 at `0x49B110..114` reaches
   `0x49B178..188`: computed vertical delta -> a3, UI object -> a2, owner
   object -> a1, controller -> a0, then **0x496940**. Other branches and
   gestures do not necessarily take this route.
2. `0x496940` resolves the view through `0x459340`, checks `0x495920` and
   view `+0x6C`, compares names, and selects a mode using view `+0x41E0`.
   On the ordinary content route it sets view `+0x80=1`, passes view `+0x7C`
   as a mode argument, and calls **0x4BA500** at `0x4969E8`.
3. `0x4BA500` sets controller `+0xF0=1`, obtains layout bounds from
   `0x4B9BA0`, reads current object `+0x18`, applies delta/boundary arithmetic
   (including one-third damping on one overscroll branch), and calls
   **0x8B43C0** at `0x4BA5F4` or `0x4BA674`, with flags **0x30002**:
   relative vertical content offset.
4. `0x496940` also handles scrollbar state through `0x4BE3E0`; it may create
   the scrollbar and schedule a timer when absent. This is more than an
   isolated offset setter and is not an appropriate shortcut for a playback
   timer. Its alternative mode calls `0x4BA6A0`, which uses **0x10002** to
   change the object's y position (+0x08), not content y (+0x18).

No claim is made that every input path is covered or that all held locks are
identified. These functions should not be invoked with synthetic gesture
state to implement automatic following.

## Exact setter behavior, checked against emitted stock instructions

`scripts/check_folderfollow_scroll_route.py` validates the source hash, 83
instruction/data anchors and the explorer/resource names, then executes the original
content-offset instructions at `0x8B43C0..0x8B4654` against mock memory.
It does not reimplement the setter as a high-level formula. Delay slots,
signed comparisons, MOVN/MOVZ, saved registers and the parent-null return are
included. The parent invalidation call **0x8B06E0 is mocked**; no UI scheduling,
allocation or concurrency is simulated.

Fifteen cases pass. Important results (synthetic input flags, not captured
runtime flags):

- Request flags `0x20002` mean absolute y; `0x30002` mean relative y.
- Object flags `+0x3C & 4` allow the content-offset path. With flags=4,
  negative and above-extent values are stored without clamping. Unchanged
  x/y skips parent invalidation on this branch.
- With flags=12 (bits 4 and 8), the setter clamps using raw object's
  `+0x20 - +0x10`. For extent=1040 and viewport=260, a large requested y
  becomes 780. But extent=0 produces **-260**, even from a positive request:
  the upper limit is negative after the lower-bound operation.
- Without bit 4, bit 2 controls whether y is stored. Flags=2 stores y;
  flags=0 or flags=1 leaves y unchanged but still calls parent invalidation
  and returns zero. Thus zero return is not proof of scrolling.
- Missing parent at +0x40 returns -1 without modifying y or notifying.
- Setting the redraw high bit `0x40000000` preserves the tested behavior of
  modes 2, 4 and 12; the setter itself leaves the object flags unchanged.

This corroborates the earlier warning about `C+0x20`: SCRL recorded zero in
that field, whereas browser end-of-content calculations use
`Q+0x9C`, Q=`*(*(view+0x3B68)+0x1B8)`. The object's **actual +0x3C flags**
must be established before assuming which setter branch applies. They were
not recorded by SCRL v1 or FILL. Do not substitute Q's extent into C, change
flags, or trust generic clamping based on these static tests.

## Offset mutation and visible-row refresh are separate steps

The setter's notification at `0x8B45B8` goes to parent `0x8B06E0`, which
intersects/merges rectangles through `0x8B3220` / `0x8B3140`. The inspected
function does not directly call `0x499C20`. Therefore 'setter succeeded' does
not by itself prove that visible row descriptors were regenerated.

An explicit stock pairing is established in playback-location helper
`0x490E20`: offset setter at `0x490F48`, then **0x490D00** at `0x490F54`.
`0x490D00` resolves a view by exact name, requires positive pitch, reads the
new content offset, requests redraw through `0x459840`, and conditionally
calls **0x499C20** at `0x490DD4` when view `+0x70 & 1` is enabled.
This makes it an existing redraw/refill route, not a proven safe timer API.
The database-based locator inside `0x490E20` is still unsuitable as an
unvalidated Files lookup because its constructor lookup key is empty.

At `0x499CB4..0x499CE8`, the row refresher calculates viewport-height/pitch
and content-offset/pitch. `0x499D18` adds visible slot to that first-row index;
`0x499D44` fetches the row via the ordinary reader `0x4327C0`. This connects
pixel offset to the insertion indices measured by FILL, but does not make a
past fill snapshot a safe current cache map.

The separately registered callback `0x4908A0` can also call `0x499C20`, but
it requires view `+0x70 & 1`, internal list, view `+0x8C`, and callback-object
`+0x78`. It clears +0x8C afterwards. The newly traced gesture path sets
**view+0x80**, not +0x8C. Do not conflate these flags or claim a complete
runtime setter -> callback -> refill sequence from the static links below.

## Where the scrolling flags originate

Notation here distinguishes render object C, widget W, and resolved view V.
The constructor at `0x492918` calls `0x43AD00`; its result is stored at
V+0xCC (`0x492924`). That helper obtains the resource named `viewgroup`
through `0x4862A0` at `0x43AD54`. At `0x43AE40..4C`, resource **+0x0C**
is copied to temporary descriptor D+0x18 (D=sp+0x18). `0x8B4120` then copies
D+0x18 to **C+0x3C** at `0x8B4184..88`.

This is resource-derived state, not a literal flags=2/4/12 in the Files
constructor. The `viewgroup` branch of `0x4862A0` selects a node from the
resource manager's list at manager+0xD378 (`0x48676C..798`), bracketed by
indirect manager callbacks. Neither the actual selected node's +0x0C nor
those callbacks' locking semantics have been measured here.

`0x8B4120` zero-initializes C, then copies initial x/y only if bits 1/2 are
set, and raw extents C+0x1C/+0x20 **only if bit 4 is set**
(`0x8B41DC..1F0`). Thus C+0x20=0 is compatible with a non-bit-4 object; it
does not establish a broken extent. This is a possible explanation of SCRL's
zero, not proof of the live flags or their later values.

The inspected redraw writers preserve the low mode bits: `0x8B4280`'s
whole-object branch ORs `0x40000000` at `0x8B4390..398`, render pass
`0x8B1420` can OR the same bit at `0x8B1508..510`, and `0x8B4660` clears
it with `0xBFFFFFFF` at `0x8B46B8..6E8`. This is not an exhaustive alias
analysis of all writes to C, nor a proof that runtime mode flags never change.

## Conditional dispatch from dirty rectangle to the list callback

The constructor provides two concrete callback bindings:

- `0x43AE50..58` sets D+0x2C=`0x439EC0`, copied to **C+0x48** by
  `0x8B418C..190`. This is the render callback, distinct from C+0x4C's
  event callback `0x43B320`.
- `0x4928C0..C4` registers **0x4908A0** through `0x459520`, whose store
  at `0x459528` targets **W+0x154**. W is not V: the callback resolves
  V from W through `0x459340` at `0x4908BC`.

The inspected dispatch is:

1. Offset setter `0x8B43C0` invalidates the parent's child rectangle through
   `0x8B06E0`. That helper merges into parent+0x14 via intersection/union;
   it does not synchronously invoke the list callback.
2. Render pass **0x8B1420** reads that dirty rectangle, obtains regions
   through `0x8B0D40`, and calls **0x8B4660** for each selected render
   object at `0x8B1514`. It clears parent+0x14/+0x18/+0x1C/+0x20 after
   the pass. Commands 1/2 through `0x4729E0` bracket rendering; their exact
   synchronization contract is not established here.
3. `0x8B4660` uses content offsets in coordinate conversion and dispatches
   **C+0x48** at `0x8B4990` on its full-render branch. The queued-region
   branch uses **0x8B3FA0**, with another C+0x48 dispatch at `0x8B40E4`.
4. Bound callback **0x439EC0** resolves a widget through resource/name
   lookup and `0x439E20`, then calls **0x438200** at `0x439F90`.
   `0x438200` renders child areas and finally, if present, calls
   **W+0x154** at `0x438300`.
5. For the constructed list widget with W+0x154=`0x4908A0`, this reaches
   the previously described gates and **0x499C20** at `0x490920` only
   when all required state is present. V+0x8C is cleared on the inspected
   completion paths. Ordinary child rendering also has W+0x12C/+0x134
   callbacks via `0x437F40`; no +0x8C-driven refresh does **not** mean
   that no pixels can be repainted.

One ordinary caller of the render pass is `0x451CA0` (`jal 0x8B1420` at
`0x451CB8`, mode zero); its address occurs beside event code 0x1001 at
`0x926BDC..BE0`. Two further direct calls are inside `0x8B16A0`, at
`0x8B1724` and `0x8B18B8`. These are leads for owner/event-loop analysis,
not identification of a safe playback-thread entry point.

This closes the static callback-binding gap, **conditionally** on the selected
render object/widget, the render branches and callback gates. It does not
show which callbacks ran in SCRL/FILL, how often V+0x8C is rearmed, or that
the entire chain runs under one safe owner/lock. In particular, the observed
manual scrolling must not be labelled a call to `0x499C20` without telemetry.

## Concrete next work

Before any autoscroll candidate, close two independent contracts:

1. Row identity/lifetime: obtain a coherent current path+cue -> absolute row
   for the active folder and the current list generation. Do not query SQL on
   every timer tick, assume cue=row, or keep a map alive solely by pointer/count.
2. UI transaction: verify the actual C+0x3C flags, Q+0x9C bounds, and
   offset-change -> redraw/refill dispatch under the existing UI owner. The
   static callback bindings above narrow the capture points, but do not
   supply the missing runtime evidence. Capture C and W/V identities and
   V+0x8C/W+0x78 gates alongside offset and C+0x3C; avoid dereferencing
   saved pointers after their owner's callback has returned. The
   `0x490D00` pairing is an audited lead; it still needs lifetime/reentrancy
   checks. A later passive probe could record original setter caller, flags,
   input y and before/after y, correlated with the active view, without
   invoking any extra scrolling call.

Only then choose a change-triggered minimal reveal policy which leaves an
already-visible row and intentional manual browsing alone. The gesture
handlers above carry input state and scrollbar side effects, so they should
not be repurposed as ensure-visible helpers.

## Reproduction

```text
python scripts/check_folderfollow_scroll_route.py E:\platform-tools\hiby_player_02fd.bin
python scripts/mips_static_trace.py E:\platform-tools\hiby_player_02fd.bin table 0xA98B34 26
python scripts/mips_static_trace.py E:\platform-tools\hiby_player_02fd.bin dump 0x49B000 0x49B19C
python scripts/mips_static_trace.py E:\platform-tools\hiby_player_02fd.bin dump 0x496940 0x496BAC
python scripts/mips_static_trace.py E:\platform-tools\hiby_player_02fd.bin dump 0x4BA500 0x4BA73C
python scripts/mips_static_trace.py E:\platform-tools\hiby_player_02fd.bin dump 0x8B43C0 0x8B4654
python scripts/mips_static_trace.py E:\platform-tools\hiby_player_02fd.bin dump 0x490D00 0x490E20
python scripts/mips_static_trace.py E:\platform-tools\hiby_player_02fd.bin dump 0x43AD00 0x43AE90
python scripts/mips_static_trace.py E:\platform-tools\hiby_player_02fd.bin dump 0x8B4120 0x8B420C
python scripts/mips_static_trace.py E:\platform-tools\hiby_player_02fd.bin dump 0x8B1420 0x8B15AC
python scripts/mips_static_trace.py E:\platform-tools\hiby_player_02fd.bin dump 0x8B4660 0x8B49A0
python scripts/mips_static_trace.py E:\platform-tools\hiby_player_02fd.bin dump 0x439EC0 0x439FC0
python scripts/mips_static_trace.py E:\platform-tools\hiby_player_02fd.bin dump 0x438200 0x438480
```
