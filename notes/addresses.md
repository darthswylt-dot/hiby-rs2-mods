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
| `0x4E90C0` | 100 ms periodic callback for the Now Playing (`playing_plane`) UI. |
| `0x4E93E0` | Main `playing_plane` event handler region. |
| `0x4E949C` | Calls the display-state helper. |
| `0x4E94A4` | Original screen-off branch that bypasses ordinary UI event processing. |
| `0x4E7580` | Stock progress/time refresh; `force=1` is required for the verified wake fix. |
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
| `0x4E4B80` | Retrieves the current playback file path. |
| `0x4E4640` | Builds Folder View levels from a UTF-16 path. This actively creates explorer views; it is not a quiet state update. |
| `0x4E4B20` | Walks and destroys the existing explorer-view stack. |
| `0x4E5FA0` | Gesture/touch callback registered for the Now Playing root widget. |

A single Now Playing -> Folder View swipe was logged as callback arguments
`a2=1, a3=1`. Invoking `0x4E4640` during screen-on without first removing the
old explorer stack produced several overlapping Folder View panels. The latest
experiment moves the rebuild to this gesture path and invokes `0x4E4B20` first.

## MIPS patching warning

Branch and jump delay slots are semantically part of the control flow. One
discarded experiment replaced the `addiu` in a branch delay slot at `0x4E39E8`
with `nop`, stopped the child index from advancing, and created an infinite
loop at end-of-track. Every patch must be verified by disassembling the final
binary, not merely by checking the bytes written at the nominal address.
