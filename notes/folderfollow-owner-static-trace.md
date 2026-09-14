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

## Playback metadata lifecycle

The source finalizer `0x42BBE0` writes property 32 (`source+0x28`, backing path)
and property 31 (`source+0x230`, backing-file position). Its normal wrappers
`0x42BC80` and `0x42BDE0` then tail-call `0x429F20`.

`0x429F20` serializes a `0x133ED5F` playback-state message. It includes the
global UTF-16 playback path at `0xADE9BC` and source state fields, then sends it
through the stock message transport. Receiver `0x42A020` validates the same
message ID, restores those fields, and finalizes the path with `0x6F76E0`.

The Now Playing controller has a separate metadata update entry point:

```text
0x4A7A70  jal 0x4EA500
0x4EA500  load global controller 0xB8BACC, then tail-call 0x4E8480
0x4E8480  refresh Now Playing metadata/widgets
```

This is a single direct call site and is a substantially better timing probe
than `0x4E5FA0`: it runs when playback metadata is delivered, while the old
Folder View remains inactive, rather than inside the gesture transition.

## Consequence for the next diagnostic

Do not add another wrapper around `0x4E5FA0`. The next passive candidate should
wrap the single call at `0x4A7A70` and record:

- the event payload passed to `0x4EA500`;
- `source+0x28` and `source+0x230`;
- current/matching Folder View pointers and their stored paths;
- controller/view state before and after original `0x4EA500`.

This will establish whether the metadata callback is the safe point at which
to stage a pending folder-follow path. Only after that timing is confirmed
should an inactive-view retarget be attempted. Stock `0x4919E0` must be called
with the same view preparation and ownership state as its native callers at
`0x492B8C` and `0x494038`; the failed gesture-time experiment does not prove it
unsafe at metadata-delivery time.
