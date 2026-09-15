# Firmware 1.4 address map

All addresses below refer to the live `hiby_player` from HiBy RS2 firmware 1.4
with SHA-256
`0fedb30f91937eafb5baaf3c75422cdbde04a62fe8bac8eca3c7a88bb761da0e`.
They are virtual addresses in that executable and must not be reused for another
firmware build without re-identification.

## Folder traversal

| Address | Observed role |
| --- | --- |
| `0x4E3000` | Recursive search for a playable entry inside the directory tree. |
| `0x4E3018` | Initializes the directory iterator; the third argument controls forward/reverse traversal. |
| `0x4E321C` | Directory-entry branch in the recursive walker. |
| `0x4E3238` | Original branch skipped directory descent in the reverse/Previous mode. |
| `0x4E32E4-0x4E33E4` | Candidate/current depth and local-`rowid` comparison before recursive descent. |
| `0x4E3318` | Equal-depth branch investigated while locating the sibling-subtree defect. |
| `0x4E33C4` | Decision point replaced by full-path ordering in the successful forward fix. |
| `0x4E3620` | Directory transition/traversal routine used by Next, autoplay, and Previous. |
| `0x4E39A8` | Recursive call within the directory transition routine. |
| `0x46E320` | Directory iterator initialization; supports reverse mode when passed a negative direction. |
| `0x46E220` | Iterator step using the direction flag. |
| `0x4E2D60` | Produces the parent wildcard/path used while comparing candidates. |
| `0x4E2EC0` | Retrieves a local list position and converts SQLite's 1-based `rowid` to zero-based form. |

The important logical finding is that `rowid` values from different
`list_tb_*` tables are local to different parents and cannot be compared as a
global tree order. The working forward patch compares full paths. Reverse
traversal additionally enables directory descent, uses the reverse iterator,
and enters the last child of a subtree.

## Display and Now Playing refresh

| Address | Observed role |
| --- | --- |
| `0x452990` | Actual `BKL_3` screen-on call site used by the tested short-Power path. |
| `0x468BC0` | Backlight on. |
| `0x468C40` | Backlight off. |
| `0x468D40` | Reads backlight/display state. |
| `0x46AA40` | Late-resume function investigated during early wake experiments. |
| `0x469F40` | Resume helper called from the late-resume path. |
| `0x4E90C0` | 100 ms periodic callback for the Now Playing (`playing_plane`) UI. At `0x4E9160-0x4E9198` it compares the current view's media identity with the playing item and dispatches event 5 with value 0 on mismatch. |
| `0x4E93E0` | Main `playing_plane` event handler region. |
| `0x4E949C` | Calls the display-state helper. |
| `0x4E94A4` | Original screen-off branch that bypasses ordinary UI event processing. |
| `0x4E7580` | Stock progress/time refresh; `force=1` is required for the verified wake fix. |
| `0x4E8480` | Actual Now Playing media-item/widget refresh. Its four native callers are collect-button, screen-on, full panel activation, and internal view-group catch-up paths; none is a universal track-change callback. It has no direct Folder View helper calls. |
| `0x4EA500` | Null-guard adapter: loads global controller `0xB8BACC` and tail-calls `0x4E8480(controller, item)`. Its sole direct caller is the successful `vg_listview_add_m3u` collect path, not a general track-change callback. |
| `0x42AC00` / property 24 setter branch | Copies the `0xA88`-byte current media-item record into global buffer `0xADD468`. Its field `+0x4` is the known UTF-16 playback path at `0xADD46C`. |
| `0x42B180` | Stages a selected media item through `0x428B40` and enqueues playback-worker event 9. This is the asynchronous bridge used by the normal Next/autoplay selection path. |
| `0x42CAC0` | Selected-item dispatcher. Uses a synchronous same-backing-file fast path or stages a general transition through `0x42B180`. |
| `0x42CBD4` / copy at `0x42CBDC` | Direct property-24 commit for the same-backing-file/cue-compatible fast path. Followed through `0x42CA00 -> 0x42BDE0 -> 0x42BBE0` by source finalization. |
| `0x42CD54` / copy at `0x42CD5C` | General event-9 property-24 commit. Copies the staged `0xA88`-byte item into `0xADD468` before decoder/open dispatch; primary cross-file/cross-folder diagnostic hook. |
| `0xB8BACC` | Global pointer to the current `playing_plane`; cleared by stock teardown code. |

Power diagnostics on the hardware produced:

```text
BKL_5 = screen off
BKL_3 = screen on
```

Earlier patches targeted another backlight-on path and therefore could not
affect the reproduced short-Power scenario.

## Folder View synchronization

| Address | Observed role |
| --- | --- |
| `0x4E4B80` | Attempts to retrieve the current playback file path. It also performs internal synchronization/finalization and is not a pure field read. |
| `0x4E4640` | Builds Folder View levels from a UTF-16 path. This actively creates explorer views; it is not a quiet state update. |
| `0x4E4B20` | Walks and destroys the existing explorer-view stack. |
| `0x4E5FA0` | Gesture/touch callback registered for the Now Playing root widget. FD9 telemetry found no immediate explorer-state change across this callback. |
| `0x4E5680` | Returns the current explorer view through an output pointer. |
| `0x438BE0` | Counts views matching a view-type string. |
| `0x4E57E0` | Finds the last view matching a view-type string. |
| `0x4C0620` / event 5 | Generic internal-view event dispatcher. Jump-table entry 5 stores its argument directly at internal view `+0x5A4`; stock activation paths pass 1, while one playing-plane mismatch path passes 0. Hardware showed `+0x5A4` remained 1 across Roots -> Slayer despite the disappearing highlight, so it enables the selection-matching path rather than storing the highlighted row. It does not retarget the folder. |
| internal view `+0x5A0` | Current list row/index used by renderer and item access paths. A direct live read after Roots -> Slayer found value 3 while `+0x5A4` remained 1. |
| `0x4E2C40` | Constructs the `vg_main_category_hiby` generic container and installs callbacks `0x4E2A40`, `0x4E2920`, and `0x4E24C0` into generic fields `+0x70/+0x74/+0x78`. |
| `0x4E2920` | Main-category close/cleanup callback. Before releasing private state it runs the stock current-path -> Folder View build -> widget-dispatch sequence. It is not a recurring activation callback. |
| `0x4E24C0` | Third main-category callback installed at generic object `+0x78`. Generic timed dispatch can call this slot, but hardware produced zero invocations throughout the target Roots -> Slayer Files route; it is not the live folder-follow owner. |
| `0x47C620` | Generic timed dispatch: invokes object callback `+0x78` as `(object, object+0x54)` when the configured interval expires. |
| `0x47D0A0` | Configures generic object run mode/timing. Mode 2 stores its third argument at object `+0x34`; `0x4E2D04` supplies 200 for the main-category container. This alone does not prove that the container is scheduled in the target Files route. |
| `0x4916A0` | Performs the current-view preparation used by stock `0x491E80`. |
| `0x4919E0` | Reconciles the depth of an existing explorer stack for ancestor/descendant navigation. It compares `\\` counts and makes no path/list replacement at equal depth, so it cannot handle flat sibling transitions. The `c637...` hardware run did not reach this call because preceding `0x4E4B80` returned `-1`. |
| `0x495A40` | Locked stock explorer-view cleanup. Uses controller virtual callbacks `+0x274/+0x278`, collects matching `vg_listview_explorer` views, and removes them through ordinary view API `0x43B240`. |
| `0x495B80` | Restores an explorer hierarchy from saved UTF-16 property 11. For each backslash in the saved full path it constructs a prefix ending in `*` and calls `0x491E80`; returns 1 after at least one successful level. |
| `0x495D40` | Complete stock storage-open transaction. It removes explorer views through locked `0x495A40`, restores the saved property-11 hierarchy through `0x495B80`, clears property 11, and uses its supplied `a:\\*`/`b:\\*`/`c:\\*` path only as fallback. |
| property 11 | One-shot UTF-16 explorer restoration path (512 code units / 1024 bytes). Stock callback `0x4BD100` saves `selected_item+0x3DD8`; `0x495D40` consumes and clears it. |
| `0xB8BAC8` | `lg_activity_main` registration/status slot. Live path telemetry read value 1; `0x4E5900` uses it as a registration guard, so it is not a live activity-object pointer. |
| `0x4BAA68` | Return site in the common callback dispatcher observed for all three `a2=1,a3=1` diagnostic records. |
| `0xADD360` | Global pointer to a playback/source object sampled by the recovered `02fd...` diagnostic. The object remained stable across the tested folder transitions. |
| source object `+0x28` / property 32 | Inline 260-code-unit UTF-16 playback-path buffer. Normal source finalization copies global path buffer `0xADD46C` here. |
| source object `+0x230` / property 31 | Absolute backing-file playback position in milliseconds, captured during source finalization. It is selected from live `current_time` for reuse/special-source transitions or the media row's cue `begin_time` for a newly selected backing file. It is not a pointer or continuously updated counter. |
| `0xADD368 + 0x20` | Music-player absolute current decoder position in milliseconds; populated by event `0x500`. |
| `0xADD368 + 0x51C` | Selected media/cue start offset in the backing file. Added before seeks and subtracted when reporting cue-relative time. |

Live `0x4E90C0` path telemetry proved the Folder View target-path transform:
copy property-24 file path `0xADD46C`, remove the last filename component, and
append `*`, producing a path ending in `\\*`. The explorer pointer and its
lock/unlock callbacks `+0x274=0x437D20`, `+0x278=0x437DA0` stayed stable across
Roots -> nested Slayer -> flat Sleep.

A single Now Playing -> Folder View swipe was logged as callback arguments
`a2=1, a3=1`. Invoking `0x4E4640` during screen-on without first removing the
old explorer stack produced several overlapping Folder View panels.

The later swipe-triggered `c4dc...` hardware test briefly displayed the correct
current-track folder before returning to the Music root and hanging. This
confirms that `0x4E4B80` path lookup and `0x4E4640` path construction both work.
In that build the original `0x4E5FA0` callback ran before stack destruction and
reconstruction. Candidate `5faa8c07...` reversed the ordering and failed with
unsolicited navigation, overlapping views, loss of input, and a crash/reboot.
Candidate `c637effa...` intended to preserve the stack and use `0x4919E0`, but
later telemetry proved that preceding `0x4E4B80` returned `-1`; its wrapper
therefore skipped the retarget call. It still showed the old folder and
temporarily lost physical-button response, but that result cannot be
attributed to `0x4919E0`.

The later FD9 diagnostic (`6c274509...`) sampled the stable failure without
retargeting or rebuilding views. In all three records, pre-callback `0x4E4B80`
returned `-1` with an empty path. The player context, explorer, current view,
explorer state, list head/tail, and matching Folder View pointer were unchanged
immediately across original `0x4E5FA0`, which returned zero. The matching view
path remained the folder where playback started even after playback had
advanced to Slayer in another folder.

This shows that the target callback does not own the synchronous Folder View
retarget and has no usable playback path before the original callback. The
next investigation must locate the source fields and deferred owner used by
`0x4E4B80`, rather than invoke it again as if it were an observational getter.

The later safe pointer diagnostic (`eba4b0c9...`) confirmed that the explorer,
current view, matching Folder View, state, and list pointers remain unchanged
even while source-object field `+0x230` changes with playback. Original
`0x4E5FA0` still returns zero without a synchronous explorer update.

Static tracing subsequently identified property 31 as
`source_backing_file_position_ms` and property 32 as the neighboring inline
UTF-16 backing-file path. `0x4E4B80` consumes both to resolve a media/cue row;
it remains unsuitable as a passive telemetry getter. See
[source-object-cue-path-static-trace.md](source-object-cue-path-static-trace.md).

## MIPS patching warning

Branch and jump delay slots are semantically part of the control flow. One
discarded experiment replaced the `addiu` in a branch delay slot at `0x4E39E8`
with `nop`, stopped the child index from advancing, and created an infinite
loop at end-of-track. Every patch must be verified by disassembling the final
binary, not merely by checking the bytes written at the nominal address.
