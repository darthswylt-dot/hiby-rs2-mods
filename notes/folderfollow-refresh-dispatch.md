# UI event loop and delayed list refresh

2026-09-30. Local static follow-up to
[manual scrolling](folderfollow-manual-scroll-route.md). No build, device
operation, commit or push. The last hardware state remains the stock player
verified at the end of FILL; it was not queried again in this step.

## Main result

There are at least two distinct routes to visible-row refresh. The render
completion callback `0x4908A0` uses V+0x8C, but the delayed callback
**0x49A1A0 does not**. Both queued rendering and the timer pump are called
from the same inspected UI loop `0x43C980`. This is a concrete caller-context
link, not proof that every UI mutation is serialized or that arbitrary calls
from another timer would be safe.

Use C for render object, W for resource/widget, V for resolved list view,
and U for the controller. The same numeric offset on these types is not the
same field.

## Queued rendering belongs to the UI event loop

`0x43C980` loops until U+0x134 requests exit. Its body includes:

- `0x454200` at `0x43C9A4`: dispatch a queued event;
- deferred redraw processing `0x43C900` at `0x43C9AC`;
- other input/housekeeping functions, followed by **0x473560** at
  `0x43C9E4`: pump registered timers.

`0x454200` resolves context through `0x475320`, checks `0x8B1F60`, and
dequeues a 20-byte message through `0x450600` at `0x45424C`. On success it
matches message+4 against 128 pairs starting at **0x926B94**, then invokes
the matched callback with U and the message (`0x454294..2A4`). This validates
the earlier table interpretation: **0x1001 -> 0x451CA0** at
`0x926BDC..BE0`. That handler calls `0x8B1420` in mode zero at `0x451CB8`.
It also calls `0x466E20(10)` and `0x4E1E80(0,U)`; it is not a minimal
render-only helper to call directly.

The alternate loop `0x43CA60` also pumps timers at `0x43CA9C` and dispatches
through `0x4542C0`. The two loops' mutual exclusion and actual OS thread
identity have not been established. `0x4E4AC0` calls `0x43C980`, and
`0x4E3E5C..60` installs that function into U+0x25C, which `0x4E3DE0` invokes.
This establishes a controller lifecycle path, not a complete thread audit.

The render-bracketing helper `0x4729E0` is also not evidence of a UI mutex:
it replaces a0 with global `0xA9273C`, tests it for negativity, and sends
requests `0x80044660`/`0x80044661` through import trampoline `0xA5BE90`.
The import/device semantics were not resolved here. Do not interpret the
commands 1/2 as proven lock/unlock protection around all view accesses.

## Timer 20: deferred, resettable, self-removing refresh

The helper **0x499240(interval, data)** uses timer **ID 20 (0x14)**, not
a 20-unit interval. `0x4736A0(20)` tests existence. If absent, it calls
`0x4738A0(20, interval, 0x49A1A0, data)` at `0x499274`; if present it calls
`0x4737A0(20, interval)`, which updates interval and zeros elapsed time
(`0x47386C..874`). The latter does not replace callback data.

The registry starts at `0xB89B78`, with 24-byte records:

| Offset | Meaning in the inspected pump/registration code |
| --- | --- |
| +0x00 | timer ID |
| +0x04 | interval |
| +0x08 | accumulated elapsed count |
| +0x0C | processed marker for the pump pass |
| +0x10 | callback data |
| +0x14 | callback address |

At `0x473628..630`, the pump invokes the callback as **(ID, data)**.
`0x49A1A0` saves ID but does not consume data. It instead:

1. Obtains the global controller via `0x43D200`.
2. Calls `0x4E5680` -> `0x4E5560` to select a current view when the timer
   fires. The selector enumerates U+0x298, collects each V's C+0x38 sort key,
   sorts using `0x4E3DC0`, and returns the first record's V. It brackets the
   lookup with U+0x2A4/+0x2A8 callbacks, but releases that bracket before the
   refresh. Neither a retained lifetime reference nor a held lock across the
   ensuing row refresh is established.
3. If V exists and **V+0x70 bit 0** is set (`0x490B40(V,0)`), calls
   `0x499C20(V,V+0xCC)` at `0x49A1F8`. It does not inspect V+0x8C,
   W+0x78, or the originally registered data pointer.
4. Calls `0x49A160(ID)` on both refresh and no-refresh paths; that helper
   removes the timer via `0x473A00` if still registered. The refresh return
   value does not suppress removal.

This is a useful stock pattern: defer work, resolve the currently selected
view at execution time, then remove the timer. It does **not** provide an
exact Files name/path/generation check, a playback-row mapping, or an offset
change. Do not hijack ID 20 or reuse it as an autoscroll timer: it is shared
stock state with existing input cancellation/reset behavior.

## Connection to Files input, and cancellation

The explorer callback table at `0xA98B34` has **0x49B460** at name+0x4C
(`0xA98B80`). That handler resolves V through `0x459340`, saves C+0x18 in
V+0xA0, and checks `0x4991A0`. One branch then requires the input-state
check, controller+0xF0=1, V+0x41E0=0, and a content offset within
`0 .. W+0x9C - C+0x10`. With V+0x78 present, it schedules
**0x499240(100,V)** at `0x49B584`. The interval is the literal 100; no
timing-unit or real latency claim is needed for this result.

The previously traced explorer movement callback **0x49B000 cancels ID 20**
at `0x49B078..07C`, before its input processing and offset mutation.
Thus the delayed refresh is tied to input lifecycle, not necessarily a
per-movement row refill. Another direct registration occurs at `0x49B704`
inside `0x49B5C0`; that function's binding to the explorer record was not
established here. Do not label it a measured Files callback.

There is also a literal call at `0x49AC80`; its nearby straight-line path
first calls `0x490B40(NULL,0)` at `0x49AC18`, which returns zero and exits.
The existence of that call instruction alone is not evidence of a viable
registration path. No complete reachability analysis of alternate entries
was performed.

## V+0x8C: evidence remains bounded

The positively identified set-to-one is in the list constructor at
**0x4926D8**, before creation of the internal list at `0x4926E4`.
The render callback clears it at `0x490900` or after refresh at `0x49092C`.
A scan of literal +0x8C stores found many unrelated structures, including
widget geometry; those are not evidence of rearming this V field.

An initialization/first-render role is consistent with this evidence, but
"written only once" is not proven: alias-based, shifted-base, indirect or
bulk writes are not excluded. Crucially, repeated normal refresh need not
rearm +0x8C at all, because the timer and explicit `0x490D00` routes bypass
that gate. No hardware callback coverage is inferred from FILL/SCRL.

## Checks and next measurement

`scripts/check_folderfollow_refresh_dispatch.py` checks the recognized source
hash and **42 instruction/data anchors**. It executes the original instructions
of `0x49A1A0`, `0x49A160` and `0x490B40` in **eight cases**. Resolver,
row-refresh and timer-registry calls are mocked; volatile registers are
clobbered, saved registers/stack checked, and callback data is an unmapped
pointer to catch accidental use. Cases cover absent/current view, bit-0
gating with +0x8C=0, missing timer, and refresh failure followed by removal.
They do not simulate the queue, timer timing, selector internals, row changes,
threading or pointer lifetime.

For a later authorized passive build, the useful paired observations are:
original setter caller + C/flags/y; original `0x499C20` caller + V/C/current
offset; ID-20 arm/cancel/fire and selected V; render-callback gates. Capture
values while original code owns the objects; do not retain pointers or make
extra refresh/SQL/scroll calls. This distinguishes deferred/manual refresh
from initial-render refresh without changing scrolling behavior.

```text
python scripts/check_folderfollow_refresh_dispatch.py E:\platform-tools\hiby_player_02fd.bin
python scripts/mips_static_trace.py E:\platform-tools\hiby_player_02fd.bin dump 0x43C980 0x43CA60
python scripts/mips_static_trace.py E:\platform-tools\hiby_player_02fd.bin dump 0x454200 0x4542B0
python scripts/mips_static_trace.py E:\platform-tools\hiby_player_02fd.bin dump 0x473560 0x473690
python scripts/mips_static_trace.py E:\platform-tools\hiby_player_02fd.bin dump 0x499240 0x4992AC
python scripts/mips_static_trace.py E:\platform-tools\hiby_player_02fd.bin dump 0x49A160 0x49A218
python scripts/mips_static_trace.py E:\platform-tools\hiby_player_02fd.bin dump 0x49B460 0x49B5A4
```
