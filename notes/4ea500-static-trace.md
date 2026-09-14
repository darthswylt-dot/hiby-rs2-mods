# Static trace of `0x4EA500`

Addresses refer to firmware 1.4 `hiby_player` SHA-256 `0fedb30f...`.

## Result

`0x4EA500` is a six-instruction null-guard and tail-call adapter for the global
Now Playing controller. It is not a general playback-track-change callback and
does not update Folder View state.

```text
0x4EA500  lui   v0, 0xB9
0x4EA504  lw    v0, -0x4534(v0)    # global controller at 0xB8BACC
0x4EA508  beq   v0, zero, 0x4EA518
0x4EA50C  move  a1, a0             # delay slot: media item -> second argument
0x4EA510  j     0x4E8480
0x4EA514  move  a0, v0             # delay slot: controller -> first argument
0x4EA518  jr    ra
0x4EA51C  nop
```

Equivalent pseudocode:

```c
void *refresh_global_playing_plane(media_item *item) {
    playing_plane *controller = *(playing_plane **)0xB8BACC;
    if (controller == NULL)
        return NULL;
    return refresh_playing_plane_item(controller, item); // 0x4E8480
}
```

The global is assigned the newly constructed Now Playing controller at
`0x4EAEFC` and cleared by its teardown path at `0x4E5E3C`.

## Sole direct caller

The executable contains one direct `jal 0x4EA500`, at `0x4A7A70`. The enclosing
function `0x4A77A0` is a virtual method of `vg_listview_add_m3u`; its function
pointer appears in that class's table at `0xA9A618`.

The relevant successful-add branch is:

```text
0x4A788C  a0 = 11
0x4A7898  a2 = selected media item
0x4A78A4  call 0x6F7020
0x4A78B0  s1 = return value
0x4A78BC  if s1 == 0, branch to 0x4A7A70
...
0x4A7A70  call 0x4EA500(selected media item)
0x4A7A7C  call 0x4A75A0(L"collect")
0x4A7A8C  select the `add_success` UI message
```

The nonzero branch selects `add_repeat`. Nearby identifiers include
`hiby_collect`, `add_m3u`, `add_fail`, and `add_success`. Together with the
class identity, this establishes that the call refreshes Now Playing after an
Add-to-M3U/collect operation. It is not reached merely because Next, Previous,
autoplay, or cue transition selected another track.

No data pointer to `0x4EA500` exists in the executable, so there is no evidence
that it is also registered as an indirect callback.

## Callee `0x4E8480`

`0x4E8480(controller, item)` is the actual Now Playing item/widget refresh.
It:

- returns early when the controller or `controller+0x478` is null;
- reads global properties 8 and 21;
- examines the media-item type at `item+0x4`;
- selects data from a model resolved through `controller+0x3C`;
- updates the widget at `controller+0x478` through its virtual method at
  offset `+0x178` and changes visibility through `0x459780`.

Its direct callees do not include the Folder View helpers `0x4E4B80`,
`0x4E4640`, `0x4919E0`, or the known explorer lookup/count helpers. It has four
ordinary direct callers inside the broader Now Playing event handler, at
`0x4E9590`, `0x4E9680`, `0x4E9830`, and `0x4E9A2C`, in addition to the tail jump
from `0x4EA500`.

## Diagnostic consequence

Do not use `0x4A7A70 -> 0x4EA500` as the next general folder-follow timing
probe: it would normally remain silent during the Roots -> Slayer -> Sleep
transition test and could produce a misleading empty log.

The four native `0x4E8480` call paths were subsequently classified as collect
button, screen-on, full panel activation, and internal view-group catch-up.
None is a universal playback track-change callback. See
[playing-plane-refresh-callers-static-trace.md](playing-plane-refresh-callers-static-trace.md).

Until a genuine Next/autoplay commit point is identified, `0x4EA500` is useful
as documentation of the collect UI path, not as a folder-follow owner
candidate.
