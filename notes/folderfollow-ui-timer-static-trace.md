# Folder-follow UI timer ownership and passive diagnostic

Addresses refer to firmware 1.4 `hiby_player` SHA-256 `0fedb30f...`. The
diagnostic is based on the hardware-validated sorting + full-navigation + wake
image `c825a72e...`.

## Callback table recovered from `0x4E2C40`

`0x4E2C40` constructs the generic `vg_main_category_hiby` container and passes
three function pointers to `0x47D180`:

| Table slot | Generic object field | Function | Recovered role |
| --- | --- | --- | --- |
| `+0x00` | `+0x70` | `0x4E2A40` | setup/show callback |
| `+0x04` | `+0x74` | `0x4E2920` | close/cleanup callback |
| `+0x08` | `+0x78` | `0x4E24C0` | periodic container callback |

The generic loop at `0x47C580` compares its elapsed clock against the interval
stored at object `+0x34`. When due, `0x47C620` loads the function at object
`+0x78` and invokes it as `(object, object+0x54)`. The constructor enables mode
2 with interval 200 through `0x47D0A0(object, 2, 200)` at `0x4E2D04`.

The `+0x74` interpretation is no longer speculative. `0x47C740` calls it while
stopping the container and then releases its associated objects. The separate
destructor at `0x47E0A0` also calls object `+0x74` immediately before freeing
the object. `0x4E2920` itself releases the 12-byte state held at object `+0x58`
before returning.

## Why the stock close path does not solve continuous folder-follow

`0x4E2920` contains the complete stock synchronization sequence:

1. obtain the current path with `0x4E4B80`;
2. build Folder View levels through `0x4E58A0 -> 0x4E4640`;
3. dispatch the target widget callback through `0x4E28A0`;
4. release object `+0x58`.

This happens when the main-category/Now Playing container closes. It can make
the initially returned Folder View match playback at that instant, but it is
not called again when playback later crosses a folder while Folder View is
already open. That matches the hardware symptom: playback advances from Roots
to Slayer while the visible Folder View remains at Roots.

`0x4E24C0` was therefore a candidate recurring owner-context already permitted
to update this UI. Hardware testing was required to determine whether its
container is actually alive and scheduled during the reproduced Files route.

## Passive UI-timer diagnostic

Artifact:
`hiby_player_1.4_sortfix_fullnav_wake_ui_timer_diag_test`

SHA-256:

```text
32c916ee3762568b06fe05279360b8d2b8f7de5e3ae47be37511e1c44baa3e8a
```

The builder changes only the function construction at `0x4E2C5C/0x4E2C64`
from `0x4E24C0` to the wrapper at `0x988040`, plus `0x22c` bytes of previously
zero executable padding. The wrapper calls original `0x4E24C0` first and then
records:

- callback ABI, container fields, and its three-word private state;
- explorer/current-view/list pointers;
- the bounded UTF-16 current property-24 path copied directly from `0xADD46C`;
- the bounded path in the last existing `vg_listview_explorer` view;
- timestamp, matching-view count, and original return value.

It does not call `0x4E4B80`, `0x4E4640`, `0x4E4B20`, or `0x4919E0`, and performs
no navigation-state writes. Records are fixed-size `0x4a0` blocks written to
inherited FD 9 with magic `FTMR`.

Static verification reports 424 changed bytes, all confined to the two pointer
instructions and wrapper cave. All 15 control transfers have verified delay
slots.

## Hardware result: callback absent from the target route

The diagnostic was installed and its running process was verified as
`/data/hiby_player_sortfix`. `/proc/124/fd/9` correctly pointed to
`/mnt/sd_0/rs2_folderfollow_ui_timer_diag.bin` with write/append flags, proving
that the launcher and logging channel were active.

The controlled run then:

1. started the Roots in Russia composition;
2. returned to its Folder View, where the current item was highlighted and the
   volume wheel worked;
3. used physical Next until playback crossed to Slayer;
4. confirmed that Roots remained visible, no item was highlighted, and volume
   still worked.

The process remained alive throughout, but the FD position and file size stayed
exactly zero before and after the cross-folder transition. Empty-log SHA-256:

```text
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

Therefore the patched third callback was never invoked on this UI route.
Although mode 2 at `0x47D0A0` does store the supplied 200 value at generic
object `+0x34`, the particular `vg_main_category_hiby` container/callback is
not an active recurring owner while this Files/Folder View scenario runs.
`0x4E24C0` must not be used as the folder-follow handoff owner. The artifact is
safe but diagnostically negative and should not be promoted to a functional
candidate.

Relevant files:

- `scripts/build_folderfollow_ui_timer_diag.py`
- `scripts/verify_folderfollow_ui_timer_diag.py`
- `scripts/decode_folderfollow_ui_timer_diag.py`
- `scripts/rs2_folderfollow_ui_timer_diag_launcher.sh`
