# Folder-follow owner static trace

This trace follows the successful 2026-09-14 safe path telemetry. Addresses
refer to firmware 1.4 `hiby_player` SHA-256 `0fedb30f...`.

## Result

The original assumption that `0x4E5FA0` starts a deferred Folder View
navigation is incorrect. It is a widget gesture-state callback, not the owner
of explorer navigation.

For the observed `a2=1, a3=1` event, `0x4E5FA0`:

1. resolves the widget/controller through `0x459340`;
2. enters and leaves the widget synchronization primitive through `0x466DA0`
   and `0x466DC0`/`0x466DE0`;
3. returns zero.

The only conditional writes in the callback are on other event values:

- `a2=0, a3=0` writes controller fields `+0x48`, `+0x34`, and a child field
  `+0x1B0`;
- `a2=4` writes controller field `+0x53C`.

The `a2=1` path does not enqueue work, call a Folder View helper, or mutate an
explorer field. The UI framework performs the page transition independently
and merely exposes the already-existing, stale Folder View.

## Playback state and UI refresh lifecycle

The source finalizer `0x42BBE0` writes property 32 (`source+0x28`, backing path)
and property 31 (`source+0x230`, backing-file position). Its normal wrappers
`0x42BC80` and `0x42BDE0` then tail-call `0x429F20`.

`0x429F20` serializes a `0x133ED5F` playback-state message. It includes the
global UTF-16 playback path at `0xADE9BC` and source state fields, then sends it
through the stock message transport. Receiver `0x42A020` validates the same
message ID, restores those fields, and finalizes the path with `0x6F76E0`.

The Now Playing controller has an item/widget refresh routine:

```text
0x4E8480  refresh Now Playing item/widgets
0x4EA500  load global controller 0xB8BACC, then tail-call 0x4E8480
```

The only direct call to `0x4EA500`, at `0x4A7A70`, is inside a virtual method of
`vg_listview_add_m3u`. It runs on the successful `collect`/Add-to-M3U branch,
immediately before the `add_success` message. It is not a general playback
metadata-delivery callback and will not reliably run on Next or autoplay.

`0x4E8480` itself has four other direct callers inside the broader Now Playing
worker. They were subsequently classified as collect-button, screen-on, full
panel activation, and internal view-group catch-up paths. None is a universal
track-change callback, and none of `0x4E8480`'s direct callees is a known Folder
View navigation or lookup helper. See [4ea500-static-trace.md](4ea500-static-trace.md)
and [playing-plane-refresh-callers-static-trace.md](playing-plane-refresh-callers-static-trace.md).

## Consequence for the next diagnostic

Do not add another wrapper around `0x4E5FA0`, `0x4A7A70`, or the four native
`0x4E8480` calls as a track-change probe. Trace the write lifecycle of property
24 / global media-item buffer `0xADD468` and locate the commit path used by
ordinary Next/autoplay. A passive diagnostic should target only that proven
path and record `source+0x28`, `source+0x230`, the media item, and inactive
Folder View state.

Only after that timing is confirmed should an inactive-view retarget be
attempted. Stock `0x4919E0` must be called with the same view preparation and
ownership state as its native callers at `0x492B8C` and `0x494038`.
