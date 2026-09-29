# Active Folder View rebuild candidate

Prepared, installed and hardware-tested: 2026-09-29. Status: successful
partial folder follow; automatic descent and selection scrolling unresolved.

The successful VDEP v2 run established that the active explorer may be either
`vg_listview_explorer` or `vg_listview_explorer##1`, and that its path may be
deeper than the last matching explorer's path. This candidate replaces the
historical `current == last` gate with the stock 20-byte type-prefix check
(`strncmp` at `0xA5BA40`) on the inline name of the current view returned by
`0x4E5680`. It retains that current pointer for the pre-rebuild `+0x3DD8`
comparison. It performs no last-view lookup.

The original timer runs first. If the active explorer path differs from the
parent wildcard derived from committed property 24, the wrapper invokes the
same property-11/`0x495D40` storage-open transaction tested in `4c43...`.

## Repeat protection

The old post-rebuild last-path check cannot be retained safely with the new
active-path gate: last-path success can coexist with an active root screen.
That combination could otherwise repeat the rebuild every timer tick.

The new mode therefore records the attempted parent wildcard in property 11
after **every** completed stock transaction, regardless of last-view state.
While the property retains that marker, repeated ticks for the same folder
are skipped. A different playback folder allows another attempt. The old view
is never dereferenced after the stock transaction.

Property 11 remains shared stock state, not permanent private storage. Normal
navigation may replace or clear it; the protection is conditional on retaining
the marker. Manual browsing away from playback can trigger a new attempt after
such a clear. This remains a controlled experimental follow behavior, not a
finished policy for respecting manual browsing. No change-triggered staging
or asynchronous navigation completion is added here.

## Artifact and checks

```text
artifacts/hiby_player_1.4_sortfix_fullnav_wake_active_view_rebuild_test
SHA-256 6e872416963504c8a1823442c143cefbf081d197f0e25b711281bc4060058a50
size    7,133,528 bytes
wrapper 0x1D4 bytes at 0x988040
```

The exact verifier found 330 changed bytes relative to golden `c825...`, all
within the two timer-pointer instructions and the RX cave. It checked 22
control transfers, their delay slots, branch ranges, the type-name constant,
and the expected stock call counts.

The previous builder's default mode still reproduces hardware-tested
`4c43e0a4...` exactly. Its new keyword mode is selected only by
`scripts/build_folderfollow_active_view_rebuild.py`.

`scripts/test_folderfollow_active_view_rebuild.py` executes the generated MIPS
instructions against mocked stock calls. Four test groups cover both explorer
names, unrelated screens, null view, empty/no-separator playback paths,
matching active folder, retained attempt marker, ten timer ticks with a root
screen remaining after rebuild, and a subsequent target on another drive.
The mock clobbers caller-saved registers and unmaps the old view during rebuild,
checking preservation of callee-saved registers, stack and original return
value, as well as absence of post-destruction reads. All groups passed.

These tests do not emulate the real stock navigation transaction, threads,
timing or memory lifetimes. Hardware observations are recorded below.

## Hardware sequence when installed

Installation was explicitly requested. The ordinary one-shot launcher was
installed, its syntax and device hash verified, and the device rebooted.
At uptime 25.70 s, PID 123 ran `/data/hiby_player_sortfix`; its live executable
hash matched `6e872416...`, and the one-shot flag was absent.

Use the ordinary one-shot launcher, not a diagnostic FD9 launcher.

1. Start Roots via `Music -> Files -> SD-card1 -> Roots`. Confirm highlight
   and volume.
2. Advance playback to Slayer. Expect the already observed partial result:
   card root with Slayer selected. Open it to the deep track list.
3. Advance within Show No Mercy. Confirm highlight movement, volume, and no
   repeated root-screen rebuild while the playback directory is unchanged.
4. Advance to Sleep while the deep Slayer track list remains visible. The
   decisive expected improvement is an automatic change to the card root with
   Sleep selected, **without** an extra Back action.
5. Open Sleep; confirm Part 1 highlight and volume. End the one-shot test and
   verify return to stock.

Automatic descent to the target's deepest list remains unresolved. This
candidate tests the active-view gate and repeat protection only.

## Completed hardware result

The user confirmed the following sequence:

1. Roots playback in Folder View: playing file highlighted, volume working.
2. Physical Next to Slayer: card root opened automatically with
   `Slayer - Discography` selected; volume working.
3. Opening Slayer to its deep track list: playing track highlighted, volume
   working. Further track changes moved the highlight within the same folder
   without a visible repeated root rebuild.
4. Transition to Sleep directly from the deep Slayer list: card root opened
   with Sleep selected, without an extra Back action; volume working.
5. Opening Sleep: Part 1 highlighted, volume working (final user confirmation:
   "да и да").

This validates the active-view gate in this scenario, including the transition
previously suppressed by the current/last equality gate. It does not establish
universal repeat suppression when stock navigation clears the shared marker.
No spontaneous crash or input loss was observed during the run.

Separate defect observed in Slayer: the highlight advances beyond the visible
rows, but the list does not scroll to keep it on screen. Its origin is not yet
classified: no stock/baseline comparison was performed, so this is not a proven
regression introduced by this candidate. Selection and viewport following must
be traced separately.

After the completed test, PID 123 was intentionally stopped following sync.
The one-shot launcher rebooted the device. `/usr/bin/hiby_player` then ran as
PID 115; SHA-256 of `/proc/115/exe` matched original firmware 1.4:
`0fedb30f91937eafb5baaf3c75422cdbde04a62fe8bac8eca3c7a88bb761da0e`.
The one-shot flag remained absent. This was an intentional return to stock,
not a candidate crash. The ordinary launcher produced no FD9 diagnostic log.
