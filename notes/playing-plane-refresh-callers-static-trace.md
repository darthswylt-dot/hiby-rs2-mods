# Static trace of the native `0x4E8480` callers

Addresses refer to firmware 1.4 `hiby_player` SHA-256 `0fedb30f...`.

## Result

None of the four direct `jal 0x4E8480` sites is a universal playback
track-change callback. They belong to four narrower UI paths inside the long
`playing_plane` worker at `0x4E93E0`:

| Call site | Trigger/path | Payload origin | Classification |
| --- | --- | --- | --- |
| `0x4E9590` | action 11 | fresh property-24 copy at `sp+0xAA8` | Collect-button state refresh. |
| `0x4E9680` | worker catch-up loop | fresh property-24 copy at `sp+0x20` | Incremental construction/synchronization of the playing-plane view group. |
| `0x4E9830` | `controller+0x48 == 1` | fresh property-24 copy at `sp+0x20` | Full panel activation/rebind path. |
| `0x4E9A2C` | action 12 | fresh property-24 copy at `sp+0x20` | Screen-on/wake UI refresh. |

All four pass a local snapshot of property 24 rather than an event-owned
media pointer. A diagnostic around one of them would therefore observe UI
refresh timing, not necessarily the moment the playback item changes.

## Action dispatch

`0x4E93E0` dispatches `controller+0x20` through the 15-entry jump table at
`0x94BBD0`. The relevant entries are:

```text
action 11 -> 0x4E94CC -> call 0x4E8480 at 0x4E9590
action 12 -> 0x4E9A14 -> call 0x4E8480 at 0x4E9A2C
```

`0x4EA6A0(controller, action, parameter, ...)` is the synchronized action
setter: it writes action to `controller+0x20` and parameter to
`controller+0x24`.

### Action 11: collect button

The action-11 setter call is at `0x4EB9D0`. Its callback function `0x4EB980`
is stored at `0xAA7694` beside the widget name
`playing_plane_iv_collect`. The action-11 handler also tests property 21
against the UTF-16 string `collect` before refreshing the item widget.

This is consistent with the independently traced `vg_listview_add_m3u`
success path and is not an ordinary track transition.

### Action 12: screen on

The action-12 setter call is `0x452B7C`. It belongs to the already confirmed
`BKL_3` screen-on handling region. The action refreshes property 24, calls
`0x4E8480`, runs `0x4E80C0`, and reattaches the refreshed widgets.

This is the stock wake-refresh path, not a playback-change notification.

## Non-action refreshes

### `0x4E9830`: full activation/rebind

This call is reached from the `controller+0x48 == 1` branch. The flag is set at
construction and by the `a2=0, a3=0` branch of the registered root callback
`0x4E5FA0`, then cleared at `0x4E96E4` before the full refresh sequence. The
sequence reloads properties 24, 6, 13, 14, 4, and 21; rebuilds multiple widgets;
and calls the stock progress refresh `0x4E7580(force=1)`.

This is a panel lifecycle path. It can make the current item visible when the
panel is activated, but its trigger does not prove that a new playback item
has just been selected.

### `0x4E9680`: view-group catch-up

This site is outside the action jump table. It runs when the playing-plane
worker compares the current count/state at `(controller+0x2C)+0x4` with the
target stored at `controller+0x520` and finds more UI work to create. The
latter value is initialized from field `+0x30` of the
`vg_playing_plane_hiby` view group. After `0x4E8480`, the path calls the
neighboring widget-population/layout routines `0x4E8720`, `0x4E6420`,
`0x4E6160`, and `0x4E8940`.

It is an internal lazy-build/catch-up path. There is no distinct playback
event selector associated with this call.

## Property 24

Setter `0x42AB20` dispatches property 24 to `0x42AC00`, which copies exactly
`0xA88` bytes into global buffer `0xADD468`. Thus:

```text
property 24 object base = 0xADD468
property 24 + 0x4      = 0xADD46C
```

`0xADD46C` is the previously identified UTF-16 current backing-file path copied
by the source finalizer into `source+0x28`. Property 24 is therefore the global
current media-item record that contains the current playback path, rather than
an unrelated UI-only object.

There are three statically direct property-24 setter calls:

- `0x4B55E8`, from a list-selection path;
- `0x531170`, which clears property 24 and related playback properties;
- `0x533C68`, a virtual method of `vg_listview_record_operation` that copies
  its selected item before continuing playback/list handling.

These three direct calls do not yet account for automatic Next/autoplay.
Dynamic-property calls to `0x42AB20` or an earlier playback-owner copy must
still be traced.

## Consequence

Do not build the next folder-follow diagnostic around any `0x4E8480` call.
The next static target is the write lifecycle of property 24 / `0xADD468` and
the code that commits a newly selected item during automatic Next/autoplay.
That commit point should be correlated with `source+0x28` and `source+0x230`;
only then is there a defensible passive timing hook for folder-follow state.
