# Reveal integration: bounded worker and lifetime audit

2026-10-05. Read-only inspection of `artifacts/import-20261001/hiby_player_02fd.bin`,
SHA-256 `02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87`.
This supplements the [host-only reveal model](folderfollow-reveal-model.md).
No firmware patch or device action. Addresses below are static evidence,
not a claim that all runtime interleavings or callback ownership are known.

## Mutation coverage cannot be reduced to a cache pointer

List constructor 0x456C40 installs the following methods:

| Slot | Implementation | Effect |
| --- | --- | --- |
| +0x18 | 0x455DA0 | Append, tail-call insert |
| +0x1C | 0x455BC0 | Insert and shift elements |
| +0x20 | 0x455860 | Delete and shift elements |
| +0x24 | 0x4557C0 | Clear count, retaining allocation |
| +0x28 | 0x455AE0 | Set/replace, potentially grow count/allocation |
| +0x2C | 0x4557E0 | Raw, unpinned element pointer |
| +0x30 | 0x455DC0 | Count |
| +0x34 | 0x455E00 | Recursive in-place sort, comparator callbacks |

External destructor is 0x456E80. Grow 0x455980 has two found direct callers,
inside insert and set. Entry invalidation of clear/delete/set/insert/sort/free
would cover these API mutations before their effects, without dereferencing
the old list token. It would not cover writes through raw getter pointers or
changes to the active scope/binding. These hooks have NOT been implemented.

For example, 0x4A0EE0 stores its new list argument into P+0x1BC at 0x4A0F2C.
0x4906E0 binds V+0x64 from P+0x1BC at 0x490770..77C. Neither is a mutation of
the old list. Folder/sort changes can invalidate a map before any clear.
The full set of those pre-change scope paths remains unaudited.

## Files fill really has a separate worker

The callback table at 0x941664 pairs `vg_listview_explorer` (0x922704) with
0x48D280, which tail-jumps to the in-place refill routine 0x48D080. Resolver
0x48E980 places that callback into job+0x2C0 at 0x48EA34. Worker 0x48EA80
(`lg_list_thread`) locks T+0x10 at 0x48EC34, calls job+0x2C0 at 0x48EC54,
and unlocks T+0x10 at 0x48EC84.

Files constructor calls 0x48F360 at 0x492A30 with &V+0x3B84: the private
worker is T=*(V+0x3B84). Creation at 0x48F4C8 uses 0x466BA0 and callback
0x48EA80. Import relocation identifies 0xA5B9B0 as pthread_create; wrappers
0x466DA0/0x466DC0 resolve to pthread_mutex_lock/unlock. Initialization through
0x466D60 uses pthread_mutex_init with null attributes, not evidence of a
recursive mutex. Therefore "all cache mutations happen on the UI thread"
is not a valid integration premise.

Enqueue 0x48F180 itself locks T+0x10 at 0x48F198. The 0x4906E0 callback is
installed into +0x148 via 0x459540 at 0x4928D0; its private-worker enqueue
branch calls 0x48F180 at 0x49080C. Holding that mutex through an arbitrary
redraw/refill path could reenter enqueue. A complete transitive refresh path
and lock order are not established by this inspection; do not assume it is
safe to hold T+0x10 across refresh, or that releasing it makes the whole
lookup/setter/refresh transaction valid.

## A registry lock does not retain the worker

View destruction 0x493AC0 sets V+0x44=1 at 0x493B10. For the private-worker
branch, selected when (V+0xD0)+0x74 is zero, 0x493BF4 calls 0x48F520(T).

That routine sets T+4 stop at 0x48F540 and wakes T+0x14. Lock/unlock of
T+0x0C at 0x48F554/55C is a completion barrier: the worker holds that mutex
from 0x48EAC4 to 0x48ECD4. This is NOT a literal pthread_join. It subsequently
destroys mutex T+0x10 at 0x48F598 and frees T at 0x48F5B8.

Only later does teardown remove V from the controller registry through
0x4E54A0 (call sites 0x493C70/0x493F70 on later branches). The final common
cleanup frees V+0x68 at 0x493FA8, V+0x64 at 0x493FBC, P at 0x493FD0, and V
at 0x493FDC. The worker can therefore already be gone while V is still
registered. The active-view resolver also releases its registry bracket before
returning. Neither a successful resolution nor a one-time V+0x44 check is a
retention primitive. Do not simply acquire the mutex through that raw T.

The alternate teardown branch uses shared worker controller+0x30 and calls
0x48EE20 at 0x493CCC. Under T+0x10, this disables matching job callbacks
+0x2C0/+0x2BC and removes/clears queue records, then unlocks at 0x48EF34.
The later delay at 0x493CDC is not a private-worker join. Both ownership modes
need separate gates; a private-worker-only design cannot silently accept both.

Independently, refresh/reset 0x491240 frees V+0x64 and V+0x68 at 0x49126C/280
without acquiring T+0x10 or stopping T inside that routine. Its outer callers'
complete serialization is not yet established. Worker locking alone is not
a demonstrated universal guard for the list.

## Narrow setter result

For the observed content-y mode 0x20002 and flags=2, setter 0x8B43C0 writes
C+0x18 at 0x8B462C and calls invalidation 0x8B06E0 via 0x8B45B8. The inspected
invalidation body 0x8B06E0..0744 only calls rectangle helpers 0x8B3220 and
0x8B3140; those are arithmetic leaf routines, not callback dispatchers. This
narrows the local setter reentrancy concern. It does not prove lifetime of C
or its parent, renderer synchronization, playback atomicity, or the full
transaction with the later refresh.

## Result and next implementation gate

No safe live adapter has been established. Before converting the model into
a candidate, establish a UI-owner-serialized hook/retention mechanism that
keeps V, T, C and parent alive; identify every relevant list/scope invalidation
under a consistent lock order; and determine how to cancel for the complete
manual gesture lifecycle. An unchanged pointer/count, double generation read,
or a controller registry lock alone does not meet these conditions.

The structural tests in `test_folderfollow_reveal_static_contract.py` pin the
reference hash, metadata/getter/timer anchors and three teardown guards.
They deliberately do not assert runtime concurrency or hardware safety.
