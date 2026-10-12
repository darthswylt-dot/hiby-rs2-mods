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
| 0x4ACE0C / 0x4ACE20 | Prefix `recent` / `music_search_`; see the October 7 scope follow-up below |
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
worker path. This does not close every indirect invocation or the background
fill worker. The two path-special callers were subsequently narrowed in the
October 7 follow-up linked below.

An additional raw-descriptor path at 0x499E30/48/50 fetches an element and
copies a path/terminator directly, bypassing list-method mutation hooks.
The [2026-10-07 scope follow-up](folderfollow-reveal-scope.md) resolves its
string guards: they are substring searches, not a type-based exclusion of
Files. Ordinary paths without the search markers bypass it, but even a local
folder name containing a marker can match. Do not claim global mutator-hook
completeness from the list-method hooks alone. The follow-up also resolves
the two path-special reset branches and their dialog-completion route.

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
abstract. The [2026-10-07 contact follow-up](folderfollow-reveal-contact.md)
now resolves normal no-animation release, including long-press release with
no event 10 or 100. It identifies a separate software-recognized contact
state, not an instantaneous physical sensor reading. Lost/orphan input,
owner lifetime and navigation cancellation remain distinct prerequisites.

## Playback reader bracket: concrete but not universal

2026-10-07 inspection also resolves the getter's +0x48/+0x4C callbacks.
Player base is B=0xADD368. Constructor 0x42BACC..AE8 installs
+0x48=0x428B00 and +0x4C=0x428BE0. These lock/unlock *(B+0x44), the
mutex at global 0xADD3AC, through 0x466DA0/0x466DC0. This is a real mutex,
not an unspecified callback pair.

Next/Previous wrappers bracket their synchronous call to 0x42CAC0 at
0x42E004..024 and 0x42E188..1A8, respectively. That is positive evidence
for the same-file commit path at 0x42CBDC in those invocations. It does not
extend across the asynchronous enqueue into the separate event-9 handler.

In the event-9 route, the staged-item mutex B+0xBB4 has already been released
at 0x42E40C..410 before the call to 0x42CC60 at 0x42E42C. The latter copies
the stack-staged item into 0xADD468 at 0x42CD5C. The worker's outer completion
mutex is B+0x0C (0x42E220..224), not the getter's B+0x44. These exact anchors
do not establish common locking for the general copy and property getter.
Consequently, repeated equal property-24 samples still cannot be promoted
from a stability filter to an atomic path/cue snapshot proof.

The previously measured [commit-hook staging route](playback-commit-safe-diag.md)
remains a more suitable source to investigate for owned copies. A future
publication mechanism must cover public-setter/clear paths as well as both
direct commits, and define cross-thread publication and invalidation; the
existing passive logger by itself is not that adapter.

## Next precise integration gates

1. Use the now-mapped queued/dialog reset routes and worker post-fill route
   to define a retained UI-owner/generation boundary, including explicit
   close-by-name and scope changes. The [publication follow-up](folderfollow-reveal-publication.md)
   shows that P+0x1BC rebinding also runs on the fill worker under T+0x10;
   a callback after fill is not by itself a successful complete-row certificate.
   The host-only `RowPublication` protocol now validates copied producer events;
   the [October 8 passive bridge](folderfollow-reveal-bridge.md) now captures
   selected producer/playback/contact events in an offline-verified ELF.
   It does not provide the retained owner, generation or complete invalidation
   coverage required to feed that protocol as authoritative live inputs.
2. Combine recognized contact and animation servicing at an owned UI boundary,
   with cancellation on owner replacement/input uncertainty. Normal release
   no longer needs to be inferred from event 100. Do not retain raw G/A/K
   pointers between callbacks or treat capture-object destruction as release.
3. Publish coherent copied playback and row identities, including all relevant
   invalidation paths, before attaching the existing one-shot policy and MIPS
   arithmetic core. No guessed field, new global lock, active-cache scan or
   live setter is introduced by these audits. No installable adapter yet.

At the original audit boundary the passive bridge had not been installed or
hardware-tested. Its separate RX load and private BSS required a new bounded
launch/recovery review; existing diagnostic launchers were not approval for
the new hash/size. The subsequent [October 8 smoke](folderfollow-reveal-smoke-20261008.md)
and [October 12 interactive runs](folderfollow-reveal-interactive-20261012.md)
now provide bounded loader/capture/recovery evidence with the separately
reviewed launcher. They do not close the active-autoscroll gates above.
