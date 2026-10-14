# Reveal integration: the non-render refresh routes

2026-10-14. Read-only inspection of the 7,133,528-byte reference
`artifacts/import-20261001/hiby_player_02fd.bin`, SHA-256
`02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87`.
The companion `test_folderfollow_reveal_nonrender_contract.py` pins the
instructions and tables below. No device access or firmware modification.

## Result

There is an explicit queued, non-render call to refresh at **0x452F9C**.
It is a narrower integration lead than hooking every invocation of refresh
`0x499C20`, which also runs within rendering. However, neither this route
nor timer 20 retains the selected view after lookup. The inspected triggers
also do not establish a callback on every Next/autoplay commit. The active
setter gate therefore remains closed: no safe borrowed-owner action window
has been established by this follow-up.

## Queued event 0x140 has two different refresh routes

The event table contains `0x140 -> 0x453940` at `0x926D74/78`.
`0x454200` dequeues a 20-byte message, matches message+4, then synchronously
calls the handler with `(U, message)` at `0x4542A0`. The music loop invokes
this dispatcher before its redraw processing and timer pump. These are
ordering facts for the inspected invocation, not global thread ownership.

`0x474380(event, parameter1, parameter2)` copies the scalar arguments into
message+4/+8/+0x0C and sends the message through `0x4504E0` at `0x4743E8`.
Copying a parameter that happens to be a pointer does not retain its target.

The handler dispatches on message+8:

| Parameter1 | Inspected route |
| --- | --- |
| 1 | `0x4A2C80` |
| 2 | `0x4A5E20`, with parameter2 |
| 3 | `0x452E80`: resolve current V and arm delayed refresh |
| 4 | `0x494A00`, with parameter2 |
| Other | `0x452EC0`: selected/name-resolved V, then possible direct refresh |

In the default route, nonzero parameter1 is treated as a name and copied to
a stack buffer, then resolved with `0x4E5320` (`0x452F18`). Zero parameter1
instead selects the current view with `0x4E5680` (`0x452FC0`). After geometry
and mode-specific work, `0x490B40(V,0)` checks V+0x70 bit 0 at `0x452F88`.
If true, the stock code calls `0x499C20(V,V+0xCC)` at **0x452F9C**.
This route does not pass through the render callback `0x4908A0`.

Both resolver variants release controller+0x2A8 before returning:
`0x4E53A0` for the named lookup, `0x4E5640` for the current-view lookup.
There is no retained-owner token in the inspected queue/handler chain.
The existing teardown/worker ordering in the [owner audit](folderfollow-reveal-ownership.md)
and [close-dispatch audit](folderfollow-reveal-ui-owner-boundary.md) still applies.

## Timer 20 is not limited to manual scrolling

Parameter1=3 takes `0x4539C0 -> 0x452E80`, which resolves the current view
and calls `0x49A220(V,100)` at `0x452E9C`. The small wrapper swaps its
arguments and tail-jumps to `0x499240(100,V)`.

That helper registers timer ID 20 with callback `0x49A1A0` at `0x499274`,
or changes the interval if already registered. The timer callback ignores
its data argument, resolves the current view anew, checks bit 0, calls
refresh at `0x49A1F8`, and removes the timer on both paths. Existing manual
handlers also arm/reset/cancel this same stock timer. It is therefore a
shared delayed-refresh mechanism, not an autoscroll mailbox or a retained V.
See [the earlier timer analysis](folderfollow-refresh-dispatch.md).

`0x450F00` explicitly posts `(0x140,3,0)` at `0x450F30..3C`. Its four
direct callers are handlers `0x4526A0`, `0x4526C0`, `0x4526E0`, and
`0x452700`, bound to events 0x11D, 0x11F, 0x121, and 0x124. The explicit
upstream event mapper `0x474480` has two direct callers, `0x7150F8` and
`0x7151C0`. This is not a proven Next/autoplay completion chain; the runtime
meaning and exhaustive producer coverage of these four events is not claimed.

## The playing-plane worker lead is resource-specific

The apparent playback-adjacent producer at `0x4E9BFC..08` posts
`(0x140,0,7)`. The 15-entry action table at `0x94BBD0` maps **action 14**
to its containing branch `0x4E9BCC`. A direct action-14 setter at
`0x44569C` follows the UTF-16 extension comparison with **`png`** at
`0x92302C`; the neighboring action-13 branch uses `lrc` at `0x923024`.
Consequently, this positive route is an image/resource-completion refresh,
not evidence of a callback for every media commit. Parameter2=7 takes the
extra branch at `0x45304C`, then rejoins the direct-refresh bit check.

Similarly, the same-file commit `0x42CBDC` invokes its registered playback
callback at `0x42CC0C` and enqueues player event 11 at `0x42CC18`.
Neither operation is the queued Files event 0x140 in the inspected block.
This pass does not establish that either eventually reaches `0x452F9C`,
nor exclude additional indirect paths. A resource completion that sometimes
follows a track change is insufficient as the reveal scheduling contract.

## Narrow next boundary

For a future authorized passive diagnostic, the existing call site
`0x452F9C` can distinguish non-render refresh from the renderer and timer
routes without adding a UI call. It must not retain V/C after returning or
interpret a successful lookup as lifetime proof. The guard can consume only
copied event/generation information; it cannot yet call the setter here.

Before active integration, separately establish (1) lifetime/serialization
covering synchronous close and worker rebind, (2) complete coherent row and
playback publication, and (3) a scheduling event after Next/autoplay that
does not depend on manual scrolling, artwork completion, or drawing. No new
timer, queue injection, forced refresh, worker lock, or offset mutation is
introduced by this note or its static tests.
