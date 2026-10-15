# Reveal integration: object close dispatch and owner boundary

2026-10-12. Local, read-only inspection of the 7,133,528-byte reference
`artifacts/import-20261001/hiby_player_02fd.bin`, SHA-256
`02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87`.
The companion `test_folderfollow_reveal_ui_owner_contract.py` pins the
concrete instructions below. No device access, firmware change, or claim of
whole-program thread ownership. This closes the narrow callback-consumer
question left in [scope](folderfollow-reveal-scope.md), not the complete
[lifetime gate](folderfollow-reveal-ownership.md).

## The registered callback has both deferred and synchronous consumers

Let U be the controller, and R a 0x1C-byte node in its object list at U+0x34.
`0x4389E0` allocates R and copies these fields from its five-word argument:

| Node field | Meaning established by these consumers |
| --- | --- |
| R+0 / R+4 | Linked-list links |
| R+8 | Graphic object, with name at object+0 |
| R+0x0C | Deferred-close request flag |
| R+0x10 | Other copied field; no new lifetime interpretation |
| R+0x14 | Callback context |
| R+0x18 | Close callback |

Dialog construction supplies callback `0x47D060` and D as its context
through `0x47D310..324 -> 0x43AF00`. That wrapper writes the callback and
context at stack+0x60/+0x5C before registering stack+0x50. Ordinary list-view
construction similarly supplies `0x493AC0` and V at `0x49290C..91C ->
0x43AD00`; the latter copies its a2/a3 through s6/s5 and stack+0x60/+0x5C.
Thus R+0x18 is not merely a dialog-worker shutdown callback: it can be the
Files view destructor itself.

### Deferred close is a positive UI ordering anchor

`0x43B200(U,name)` obtains R+8 through `0x43B120`, then stores one at
(R+8)+4, i.e. R+0x0C (`0x43B228`). It does not call R+0x18 inline.

`0x437A60(U)` is the deferred consumer. Under U+0x274 it walks U+0x34,
selecting a node whose R+0x0C is nonzero (`0x437A9C..AC`, and the loop at
`0x437AB0..C4`). It resolves the graphic resource by name through
`0x485DE0`, releases U+0x278 at `0x437B00..0C`, obtains resource+0x7C through
leaf helper `0x459340`, and tail-calls R+0x18 at `0x437B28..44` with that
value. Dialog construction writes D into that resource+0x7C at
`0x47D350..358 -> 0x459320`.

The two direct linking callers of `0x437A60` are exactly:

| Close-pump call | Subsequent timer-pump call |
| --- | --- |
| `0x43C9D4`, music loop | `0x43C9E4` |
| `0x43CA94`, second controller loop | `0x43CA9C` |

They run the selected close callback synchronously before the timer pump in
each inspected invocation. This direct-call census is not a proof that no
indirect caller, alternate entry, or concurrent loop invocation can exist.

### There is also a public synchronous close facade

`0x43B120(U,name)` releases U+0x278 at `0x43B190..198`, then returns R+8
at `0x43B1A0`. It is an unretained record pointer, not a token that keeps a
view alive.

`0x43B240(U,name)` calls that resolver at `0x43B248`. For a nonnull result,
it loads callback (R+8)+0x10 and context (R+8)+0x0C, checks each for null,
then tail-jumps to the callback at `0x43B270`. Its complete 0x40-byte body
has one direct call (the resolver), no queue operation, no thread identity
check, and no lock retained across the callback. This is the same R+0x18
consumer despite the different load displacement.

The reference has 194 direct calls to `0x43B240`. They have **not** all been
classified by thread or target name. This pass does not claim any one of
them is an observed concurrent Files teardown. It does rule out treating
all object-close requests as deferred UI-loop work merely because the
`0x437A60` route is deferred. A concrete Files navigation call at
`0x49E714` uses this synchronous facade with a generated name, before the
subsequent create at `0x49E734 -> 0x491E80`. This agrees with the established
event-7 activation route and makes entry-time lifecycle invalidation
necessary even within a single UI invocation.

The generated identity is now resolved at the call site: row navigation scans
the current UTF-16 path for backslashes, subtracts one from that count, and
formats `vg_listview_explorer##%d` when the result is positive. For the root
case it formats the unsuffixed `vg_listview_explorer`. Both paths synchronously
close the selected name through `0x43B240`, then call `0x49A240` with the
current path. Only when that helper returns zero does the route call
`0x491E80` to create a replacement with that path; a nonzero result skips the
create. This gives a precise path-depth-derived invalidation lead for the
stock row-navigation route; it does not prove uniqueness of the suffix,
thread serialization, coverage of other navigation/lifecycle paths, or
retention safety for our own state.

Storage switching has a separate stock lifecycle path. Exactly three direct
calls to `0x495D40` were found, at `0x49D4A8`, `0x49D524`, and `0x49D560`,
passing UTF-16 `b:\\*`, `c:\\*`, and `a:\\*`, respectively. The common
transaction calls locked cleanup `0x495A40` first, then attempts saved-path
hierarchy restoration through `0x495B80` and clears property 11. A successful
restore returns without a fallback create; otherwise `0x491E80` creates the
unsuffixed explorer using the supplied drive-root path. This is another
concrete synchronous invalidation route, distinct from per-row navigation.
It still does not establish a shared UI-thread/serialization contract for
external state, nor does it cover every direct close-facade caller.

For a dialog target, either consumer can invoke `0x47D060 -> 0x47CF80 ->
D+0x6C`, with the final indirect call at `0x47D004`. The known `0x47C740`
completion callback then waits for its worker and invokes D+0x74. Those
local worker-completion locks do not marshal an arbitrary facade caller
onto the music-loop thread.

## The visible controller locks are distinct and do not retain Files

Base-controller construction `0x439A20` installs:

| Controller callback pair | Implementations | Mutex field |
| --- | --- | --- |
| +0x26C / +0x270 | `0x437CC0` / `0x437D40` | U+0x138 |
| +0x274 / +0x278 | `0x437D20` / `0x437DA0` | U+0x13C |

The music loop acquires U+0x138 at `0x43C9C4`, calls normal dialog completion
and the deferred-close pump, then **unlocks it at `0x43C9DC` before the
timer pump at `0x43C9E4`**. Therefore the stock timer callback does not
inherit that bracket. The object-record lookup bracket is U+0x13C, a
different mutex from both U+0x138 and the music view-registry U+0x290.
Neither close consumer holds its object-record lookup bracket across the
callback. No recursive acquisition, retained owner, or cross-thread Files
lifetime guarantee follows from these brackets.

## Precise integration consequence

The deferred close path is now explained; it is no longer an anonymous
callback that needs an unspecified search. The unresolved boundary is the
**synchronous facade and every relevant direct lifecycle entry**, together
with private/shared-worker rebinding. In particular:

1. A timer-to-resolver-to-worker-lock adapter is still not justified. Its
   raw V/T/C can outlive the lookup bracket, and teardown destroys T before
   removing V from the view registry.
2. A feasible next local implementation boundary is an owned, call-site-local
   lifecycle event/publication adapter: invalidate before `0x491E80`
   creation/navigation, `0x493AC0` teardown, and `0x491240` reset; distinguish
   both close consumers, copied owner identity, and callback caller/context.
   Record/cancel without retaining or dereferencing old V/T/C. Existing
   close/reset capture is useful evidence but is not complete ownership.
3. Before allowing the setter, classify relevant `0x43B240` callers (including
   dynamic names), direct lifecycle calls and view-registry changes against
   an actual common UI owner/serialization contract. A bounded runtime thread
   identity observation can refute a same-thread premise, but absence of a
   conflict in one capture cannot establish universal safety. The fill-worker
   publication/lock-order and complete gesture gates remain independent.

This pass produces static contract tests and a narrower, actionable ownership
gate. It does not authorize holding an extra controller lock across refresh,
replacing stock close semantics, or enabling live autoscroll.

### Intra-refresh follow-up (2026-10-13)

Using current borrowed V/C at `499CB4` avoids a timer lookup and retained
pointer, but does not make every invocation a suitable action boundary.
The eight direct refresh calls include `490920` in callback `4908A0`, installed
via `4928B8..C4 -> 459520` and invoked through resource+154 at `438300`.
That puts this refresh route within rendering. The existing setter writes
the offset and invalidates the parent; simply storing C+18 and resuming
refresh is not established as equivalent. The added twelfth contract test
pins the callback and caller inventory. The
[intermediate firmware guard](folderfollow-reveal-guard-stage.md) changes
neither refresh nor setter, and does not claim that this boundary is closed.
