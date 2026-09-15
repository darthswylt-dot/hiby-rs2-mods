# Existing Folder View reuse contract

Static analysis date: 2026-09-15.

This note corrects the interpretation of the discarded preserve-stack
experiment and records the exact limits of the stock helper at `0x4919E0`.

## The preserve-stack experiment did not reach `0x4919E0`

The wrapper in `build_folderfollow_preserve_stack_retarget.py` first called
`0x4E4B80` and branched directly to original `0x4E5FA0` if the return value was
`-1`. Later FD9 telemetry reproduced the same gesture state and showed
`0x4E4B80 == -1` with an empty output path in all three records. Therefore the
hardware run did not execute its preparation, view lookup, or `0x4919E0` call.

The stale Folder View result is still valid, but it is not evidence that
`0x4919E0` itself caused the temporary input disturbance or failed after being
called. The disturbance can instead have come from the stateful `0x4E4B80`
call or from the extra work performed synchronously in the gesture callback.

## Exact `0x4919E0` contract

The arguments are:

```text
a0  explorer/controller
a1  UTF-16 path stored in the existing Folder View at view + 0x3DD8
a2  target UTF-16 path
```

The function counts `\\` separators in both paths and changes the existing
view stack only when their depths differ:

- target shallower: ancestor reconciliation beginning near `0x491AA0`;
- target deeper: descendant reconciliation beginning near `0x491D10`;
- equal depth: branch reaches `0x491E2C` without replacing the path or list.

It is consequently a depth reconciler for an already related navigation path,
not a general Folder View retarget operation. In particular, it cannot update
the required flat sibling transition `01Flat -> 03Flat`. A different-depth
sibling transition is also unsafe because depth alone does not prove that one
path is an ancestor of the other.

## Stock call contexts

`0x491E80` is the generic view creator. It accepts a controller, a view-type
string, and path/data, prepares the current view through `0x4E5680` and
`0x4916A0`, and has 188 direct callers for many view types. Its
`vg_listview_explorer` reuse path at `0x492B58-0x492B90` counts existing
explorer views, finds the last one, and calls `0x4919E0` with that view's
stored path. Parent navigation also calls `0x4919E0` at
`0x494028-0x49403C`.

These callers confirm that `0x4919E0` belongs to navigation-stack depth
maintenance. They do not provide a stock operation that replaces an open
Folder View with an unrelated playback folder.

## Lifecycle trace

`0x4E4640`, the only stock Folder View path builder, has two direct call sites.
Both follow the stateful `0x4E4B80` helper. One lies in `0x4E4CE0`, reached
from `0x4E4DE0` during activity initialization; the other is a related setup
path. `0x4E58A0` is only a tail jump to `0x4E4640`.

Class metadata at `0x94B400` identifies this owner as `lg_activity_main`, has
object size `0x2AC`, registration/status slot `0xB8BAC8`, and initialization
entry `0x4E3E40`. Live telemetry later found value 1 in `0xB8BAC8`, consistent
with the registration guard in `0x4E5900`; it is not a live object pointer.
The initialization entry installs four lifecycle callbacks:

```text
+0x254  0x4E4DE0
+0x258  0x4E3EA0
+0x25C  0x4E4AC0
+0x260  0x4E3DE0
```

`0x4E3DE0` synchronously invokes `+0x254`, `+0x25C`, and `+0x258` in order.
It is an activity initialization lifecycle, not evidence of a queued
navigation event. Calling `0x4E4CE0`, `0x4E4DE0`, or `0x4E3DE0` from the live
100 ms playing-plane timer would replay initialization against a live UI and
is not a safe candidate.

The two direct callers of the explorer-stack destructor `0x4E4B20`
(`0x4EFFD8` and `0x522048`) are teardown callbacks that remove several view
types before destroying explorer views. Neither combines teardown with a safe
live rebuild.

## Consequence for the next diagnostic

Do not build another functional patch around `0x4919E0` or an activity
initializer. The next safe step is passive telemetry in the proven live owner
`0x4E90C0`: compare the committed property-24 playback path at `0xADD46C` with
the last Folder View path and log the activity/controller state. After that,
the mutation path must use a confirmed UI-queue or complete stock navigation
transaction, not a partial lifecycle callback.
