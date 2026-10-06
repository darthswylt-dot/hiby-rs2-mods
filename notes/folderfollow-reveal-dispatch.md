# Reveal integration: UI dispatch and gesture follow-up

2026-10-06, bounded read-only inspection of reference `02fd1dd1...`
(full hash pinned by `test_folderfollow_reveal_static_contract.py`). This
narrows the [ownership audit](folderfollow-reveal-ownership.md); it does not
declare the timer a universally safe object owner. No device access or new
diagnostic deployment. The separate geometry component is described in
[the MIPS core note](folderfollow-reveal-mips-core.md).

## Timer pump and the positive activity chain

Timer pump 0x473560 synchronously calls the registered function at 0x47362C
with (timer ID, context). On return it reloads count at 0x473634 and restarts
iteration if the timer registry changed. Its own complete body has only two
linking calls: time helper 0x466960 at 0x47358C and the indirect callback. It
does not acquire a mutex itself. This says nothing about a caller-held lock
or locks inside registered callbacks.

Registration 0x4738A0 and removal 0x473A00 mutate the global timer array
0xB89B78/count 0xB89B74. Removal is not an established callback-completion
barrier. The two direct pump call sites found are 0x43C9E4 and 0x43CA9C in
different outer loops. Within each inspected loop, queued dispatch and timer
dispatch are sequential; two call sites alone do not prove one unique thread.

There is a concrete positive route toward UI ownership:

- 0x47569C calls 0x474800, which calls 0x43CFE0 at 0x474814.
- 0x43CFE0 synchronously invokes current controller+0x260 at 0x43D064.
  Only after it returns does the ordinary transition update current controller
  0xAEF208 from next-controller 0xAEF20C (0x43D06C..080).
- Music construction 0x4E3E40 binds +0x260 to 0x4E3DE0 and +0x25C to
  0x4E4AC0. 0x4E3DE0 calls init(+0x254), loop(+0x25C), then teardown(+0x258)
  serially. Its loop proceeds through 0x43C980 to the timer pump.
- The second controller at 0x51A2E0 similarly binds +0x260=0x51A280 and
  +0x25C=0x51A4E0, which uses the other loop 0x43CA60.

This establishes ordering in the inspected invocation, not uniqueness of all
possible callers or serialization of every view/list destruction path.
Controller registry callbacks are +0x2A4=0x4E4A60 and +0x2A8=0x4E4A20;
their mutex is U+0x290 and counter U+0x294. Active-view resolution does not
leave the bracket held, and registry locking does not retain the worker
through the earlier-established teardown ordering.

## List reset scope is now narrower

Six direct call sites to 0x491240 were found:

| Call site | Established local context |
| --- | --- |
| 0x45259C | Enumeration excluding Bluetooth/Wi-Fi views; can include Files |
| 0x4A2D18 | Exact Bluetooth view branch |
| 0x4A5ED4 | Exact Wi-Fi view branch |
| 0x4ACE0C / 0x4ACE20 | Path-special branches inside 0x4ACBC0; scope not fully closed |
| 0x532AC4 | Exact record-operation view |

String verification matters: 0x926674 is `vg_listview_bt`, 0x926684 is
`vg_listview_wifi`, and 0x9265BC is `vg_listview_record_operation`. Do not
mislabel these as All/Favorites or infer Files coverage from the address alone.
No direct T+0x10 lock was found in those containing functions. The general
route is now connected to the ordinary music loop: table 0x926B94 contains
event **0x11A** at 0x926C4C, paired with callback 0x452400 at 0x926C50.
Queued dispatcher 0x454200 reads a message through 0x450600, searches that
table and synchronously calls the matched handler at 0x4542A0. Before reading
the queue it checks 0x8B1F60 and returns while that animation state is zero.
The music loop calls this dispatcher at **0x43C9A4**, before pumping timers
at **0x43C9E4**. Thus this specific queued-reset route and timer callbacks
are sequential in that invocation; it is no longer an unknown independent
worker path. This does not close every indirect invocation, the two
path-special reset callers, or the already-known background fill worker.

An additional raw-descriptor path at 0x499E30/48/50 fetches an element and
copies a path/terminator directly, bypassing list-method mutation hooks. Its
applicability to Files was not established in the completed pass; do not yet
claim it is a Files mutation, and do not claim global mutator-hook completeness.

## Gesture bindings: beginning is not completion

The Files callback table starts at 0xA98B34. Binding 0x43C020 (called at
0x492900) maps its slots to resource callbacks; dispatcher 0x43BB40 selects
those callbacks by event code:

| Event | Table slot | Resource slot | Handler |
| --- | --- | --- | --- |
| 4: initial object hit/selection | +0x4C | +0x164 | 0x49B460 |
| 9: movement, including synthetic kinetic movement | +0x40 | +0x158 | 0x49B000 |
| 10: release/velocity/settle processing | +0x44 | +0x15C | 0x49B1A0 |
| 7: row activation | +0x48 | +0x160 | 0x49E560 |
| 100: animation completion | +0x54 | +0x16C | 0x49E7E0 -> 0x49B980 -> 0x49B5C0 |
| 5 / 6 / 8 | +0x58 / +0x5C / +0x50 | +0x170 / +0x174 / +0x168 | NULL |

0x49B460 is **not** a universal end-of-gesture callback. It is invoked for
event 4 at 0x43BBFC..0C. The dispatcher then resets U+0xD8/+0xDC/+0xF0 at
0x43BC1C..28. Cancelling a pending reveal only on later offset setters misses
stationary initial contact.

Movement handler 0x49B000 cancels timer 20 before movement. Release handler
0x49B1A0 can initiate return animation via 0x8B1CC0 at 0x49B308, or inertia
via 0x8B1DA0 at 0x49B3C8. Its return is not proof that movement has stopped.
Row activation 0x49E560 can navigate via 0x491E80 (0x49E710..738), so it is
another cancellation lead, not complete coverage of all exits from Files.

## Animation state is only part of manual-active state

With H=*(U+0x28), A=*(H+0x10), K=*(A+0x10), helper 0x8B1F60(H) returns
K+0x40 through 0x8B2FA0. Return/inertia startup set K+0x40=0; completion or
forced completion sets it to 1. A+0x0C indicates animation servicing and
A+0x08 holds the object. On completion the pump clears those two fields
at 0x8B1B48..50 before sending event 100 at 0x8B1B54..80. During movement
it can send synthetic event 9 at 0x8B1C68..90.

0x8B1EE0 may abort and clear the animation fields; this route alone does not
prove delivery of event 100. K+0x40 alone is insufficient when completion
delivery is still pending. A+0x0C is useful animation evidence but not proof
that a finger is or is not held down. All these pointer lifetimes remain an
adapter prerequisite, not permission to sample them from an arbitrary timer.

Do not reuse V+0x7C/+0x80/+0x84 or U+0xD8/+0xF0 as a generic active flag:
they describe direction/movement branches and can be cleared before the full
interaction ends. The host model's explicit `manual_active` input remains
abstract. Full physical release/cancel ordering, no-animation completion,
captured-object destruction and all navigation cancellation still need proof.

## Next precise integration gates

1. Complete outer ownership of the two path-special reset callers and scope
   rebinding, using the now-established queued 0x11A reset route as one UI
   serialization anchor. Do not discard the background refill worker or
   extrapolate the single invocation's ordering into a global lifetime proof.
2. Resolve the physical release/cancel source below events 4/5/6/10, including
   a touch that never starts animation. An event-100-only latch could stick.
3. Only after ownership/completion/cancellation are established, attach the
   existing one-shot policy and the now-tested arithmetic core. No guessed
   field, added global lock, active-cache scan or live setter is introduced by
   this pass. Static anchors and a safe scalar component are the result.
