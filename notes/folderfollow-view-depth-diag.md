# Active Folder View depth diagnostic

Prepared and run: 2026-09-16. Hardware status: **unexpected process exit and
automatic return to stock; do not reinstall this artifact**.

## Why another passive record is needed

The safe partial property-11 test changed Folder View to the card root and
selected `Slayer - Discography`, but did not immediately show the deep playing
folder. After the user opened that selected folder, the hierarchy was fully
accessible. Later, while deep `Show no mercy` was visible, the conservative
`current_view == last vg_listview_explorer` gate prevented a Sleep transition;
one Back action made it eligible.

Static tracing gives a narrower interpretation than the previous test note:

- `0x4E5560` resolves the active/current view from the controller's ordered
  view list. `0x4E5680` is its thin wrapper.
- `0x4E57E0` scans the same list by view-type name and overwrites its output
  for each match. It returns the **last matching** explorer view, which need
  not be the active one.
- The active view and last-matching view returned from the `controller+0x298`
  list have their narrow type name inline at object offset zero. This was
  initially misread as a pointer; see the correction below.
- `0x4BD100`, the sole non-empty property-11 writer, is registered under UI
  element `sub_back_iv_close` in metadata around `0xAA5574`. It saves a path
  on a close action; it is not the ordinary folder-activation callback.
- `0x495D40` clears property 11 immediately after restoration. Therefore the
  user's later folder activation cannot literally have consumed a path
  retained in property 11. The depth completion must be explained by explorer
  state built or selected elsewhere in the stock navigation transaction.
- Each `0x495B80` prefix goes through `0x491E80`; once at least two explorer
  views exist, its explorer reuse branch at `0x492B58` calls depth reconciler
  `0x4919E0` rather than constructing another wholly independent view. This
  is a plausible source of prebuilt deeper state, but not yet a proven account
  of which level becomes active on-screen.

This diagnostic will distinguish the likely cases without navigating or
changing any property: on the proven live `0x4E90C0` timer it records active
view pointer/type, last explorer pointer/type, each applicable `+0x3DD8` path,
`+0x40` view state, and committed property-24 playback path. It only copies
the active view's `+0x3DD8` path when its type name exactly matches
`vg_listview_explorer`. All strings are bounded.

## Artifact and verification

```text
artifacts/hiby_player_1.4_sortfix_fullnav_wake_view_depth_diag_test
SHA-256 d1c3f979dcc78d30d6ba5a76e25c4d11c06a3af3390972ac3a1d2741f20f4adf
size    7,133,528 bytes
```

The builder normalizes recovered `02fd...` exactly to golden `c825...`, then
changes only the timer callback construction at file offsets
`0x0EAEBC/0x0EAECC` and writes a `0x1F8`-byte wrapper in the executable cave
at `0x988040`. The exact-patch verifier found 374 changed bytes and checked
20 control transfers. The wrapper calls stock `0x4E90C0` first and preserves
its return value. It makes no setter, destroy, view-creator, retarget, or
navigation call.

The launcher writes fixed-size `0x6E0`-byte `VDEP` records through inherited
FD 9 to `/mnt/sd_0/rs2_folderfollow_view_depth_diag.bin`. Expect about
17 KiB/s at 100 ms intervals. Do not truncate the log while the patched
process is running.

Build and verify:

```powershell
python .\scripts\build_folderfollow_view_depth_diag.py `
  E:\platform-tools\hiby_player_02fd.bin `
  .\artifacts\hiby_player_1.4_sortfix_fullnav_wake_view_depth_diag_test

python .\scripts\verify_folderfollow_view_depth_diag.py `
  E:\platform-tools\hiby_player_02fd.bin `
  .\artifacts\hiby_player_1.4_sortfix_fullnav_wake_view_depth_diag_test
```

After stopping the process and copying the log, decode it with
`scripts/decode_folderfollow_view_depth_diag.py`.

## Intended hardware sequence

Only on explicit installation request, use
`scripts/rs2_folderfollow_view_depth_diag_launcher.sh` as a one-shot test.
Keep the run short:

1. Start Roots in Russia from `Music -> Files -> SD-card1 -> 01Flat` and show
   its highlighted Folder View.
2. Navigate normally to nested `02Nesteted -> Slayer -> Albums -> Show no mercy`
   while Slayer is playing; leave this deep Folder View visible.
3. Switch to `Sleep - Part 1` while still viewing Show no mercy, then press
   Back once. Confirm volume and normal input.
4. Stop playback, restore stock, and decode the closed log.

The decisive comparison would have been active type/path versus last explorer
type/path before and after Back. The attempted run did not reach those phases.

## Failed hardware run

The one-shot process `/data/hiby_player_sortfix` started and wrote 315 complete
`VDEP` records. The last complete record has monotonic time 53.916982880 s;
all records report a non-null explorer controller but null active and last
views, with empty playback path. Before the user began the intended music
sequence, the player unexpectedly rebooted. The one-shot launcher had already
removed its flag, so the device returned to `/usr/bin/hiby_player`; its live
executable SHA-256 was verified as
`0fedb30f91937eafb5baaf3c75422cdbde04a62fe8bac8eca3c7a88bb761da0e`.

The closed device log was retained locally at
`artifacts/rs2_folderfollow_view_depth_diag_failed_boot.bin` (554,400 bytes,
315 records, SHA-256
`efbb68987801cf57e7bde69f4c5eee2855751f66e6a8ea163ba778b86017b3fc`).
The log contains no completed record with a non-null view, so it cannot prove
whether the first such dereference caused the exit. The kernel's boot message
does not identify a userspace fault. Do not attribute the reboot more precisely
without a staged fault record or crash trace, and do not rerun this build.

## Post-failure audit and lower-risk next measurement

The successful 5,484-record playing-path diagnostic already exercised the same
`0x4E5680` active-view lookup and `0x4E57E0` last-explorer lookup with live
views. At record 725 it found both pointers equal at the card root; at record
736 they were equal again inside Roots in Russia. It also copied the last
explorer's `+0x3DD8` path throughout Roots -> Slayer -> Sleep without a crash.
That run did **not** include manual navigation to the deep Slayer Folder View,
so it cannot settle whether active and last diverge there.

Relative to that proven logger, this failed build added dereferencing the
first word at `view+0` as though it were a pointer to a narrow type name,
then copying/comparing from that fabricated pointer. It also read `view+0x40`
and conditionally copied the active view's `+0x3DD8` path. The initial audit
incorrectly applied the object layout seen in stock `0x43A0C0` to a
**different** controller list. The corrected interpretation below identifies
the invalid type-name dereference as the leading crash explanation.

## Static root-cause correction

`0x4E5560` returns `lw v0,+0x8(node)` from the ordered list at
`controller+0x298`. `0x4E57E0` traverses that same list, loads the same
`node+0x8` value into `s0`, then passes `s0` **directly** as `strncmp`'s first
string argument at `0x4E5840-0x4E5848`. The returned object thus begins with
an inline type-name string. In contrast, `0x43A0C0` traverses the distinct
list at `controller+0x34` and dereferences its entry at `+0` before `strcmp`.
That unrelated layout was the source of the mistaken pointer assumption.

The failed wrapper's `lw s4,0(s2)` at both active- and last-view paths loaded
the first four ASCII bytes of the inline name (for `vg_listview_explorer`,
little-endian `0x6c5f6776`) and treated them as an address for `strncpy` and
`strcmp`. This is an invalid userspace address, so the first non-null view
would fault before a complete record could be written. The 315-record failed
log ends at 53.916982880 s with null views. In the later successful run on
the same route, the first non-null view appeared at 54.184615010 s. The
timing and control flow strongly support this root cause, although no crash
PC was recovered from the failed boot. Keep the failed binary blacklisted.

For the next hardware observation, prefer the *previously successful*
`playing_path_diag` build and its existing decoder. Navigate manually from
Roots to deep Show no mercy while logging, then compare `current_view` and
`last_view` at each level and after Back. This answers the pointer-equality
question without deploying this failed build or adding a new dereference.
It still requires a separate explicit installation request and a short,
one-shot run; do not start it merely to continue static investigation.

## Reuse of the proven playing-path logger: completed

The user explicitly requested installation. On 2026-09-16, the exact-verified
`playing_path_diag` artifact (`599cc5e2...`) ran through the one-shot launcher.
The user started Roots in Russia, navigated to the track list inside the
`1987 USA Discovery Systems...` release under Show No Mercy while Roots still
played, then pressed Back once. The process stayed healthy. It was stopped
deliberately after the measurement, and the device returned to stock
`/usr/bin/hiby_player` (`0fedb30f...`); the one-shot flag is absent.

The closed log is `artifacts/rs2_folderfollow_playing_path_diag_deep_navigation_final.bin`
(2,449,696 bytes, 2,069 complete records, SHA-256
`ec1383753a0862a3fcd7bc0dbdcf93452d19559a5e85718414f24e0bfbaef18b`).
Decisive records, with the Roots playback path unchanged throughout:

| Record | User-visible navigation phase | `current_view` | `last_view` | Last explorer path |
| --- | --- | --- | --- | --- |
| 344 | Roots track list | `0x0122219c` | `0x0122219c` | `a:\\Roots In Russia...\\*` |
| 925 | SD-card root | `0x00ef171c` | `0x00ef171c` | `a:\\*` |
| 965 | Slayer folder | `0x0122219c` | `0x0122219c` | `a:\\Slayer - Discography\\*` |
| 973 | Next nested level | `0x00ef171c` | `0x0122219c` | `a:\\Slayer - Discography\\*` |
| 986 | Show No Mercy folder | `0x0122219c` | `0x0122219c` | `a:\\Slayer - Discography\\Albums\\1983 - Show No Mercy\\*` |
| 998 | Track list in `1987 USA Discovery Systems...` | `0x00ef171c` | `0x0122219c` | Same Show No Mercy path |
| 1554 | After one Back, `1987 USA Discovery Systems...` entry visible | `0x0122219c` | `0x0122219c` | Same Show No Mercy path |

The two explorer view objects alternate as navigation deepens. The last
matching explorer is **not** necessarily the active view. The old
`current_view == last_view` mutation gate is therefore demonstrably false on
the target deep track-list screen and true again after one Back. The last
explorer path can describe the *parent* while the deeper list is visible. This
log does not include the active view's type or its `+0x3DD8` path, so those
fields must not be inferred from the last-view path. In particular, the
address `0x00ef171c` is reused from the earlier SD-card root; the log alone
does not prove that its path still contains `a:\\*` at the deep level.

Next implementation work should classify the active explorer by the stock
view-list/type contract and obtain the active view's path, with lifetime and
reentrancy protected. Do not replace the equality gate with an unguarded
dereference based only on the failed `VDEP` build.

## Corrected candidate: offline preparation

`scripts/build_folderfollow_view_depth_diag_v2.py` preserves the failed
wrapper's control flow and record layout but replaces its two erroneous
`lw s4,0(view)` instructions at `0x988108` and `0x988198` with
`move s4,view`. The existing bounded narrow-string copy/compare then reads the
inline type name from the same address as stock `0x4E57E0`, though its exact
`strcmp` differs from stock's prefix match. It also replaces two
unneeded `view+0x40` reads at `0x988110` and `0x9881A0` with zero values, so
the corrected logger does not dereference that optional field on a non-explorer
active view. No other wrapper instruction changes. The separately generated
artifact is:

```text
artifacts/hiby_player_1.4_sortfix_fullnav_wake_view_depth_diag_v2_test
SHA-256 a943596abe82468142af3a8af00651782a6960e98b62e01b49a18b9c3fb42c42
size    7,133,528 bytes
```

`scripts/verify_folderfollow_view_depth_diag_v2.py` confirms exact source
normalization, byte scope, and precisely those four instruction substitutions.
The 20 verified control transfers are unchanged. At this preparation stage,
that established only a static correction, not hardware safety. The subsequent
explicitly requested hardware run is recorded below.

## Corrected v2 hardware run

The user explicitly requested installation on 2026-09-16. The one-shot v2
launcher was `scripts/rs2_folderfollow_view_depth_diag_v2_launcher.sh`. The
process remained alive while the user left the DAC screen, opened the SD-card
root, started Roots in Russia, and navigated to the track list inside
`1987 USA Discovery Systems...` without changing the playing track. It did not
repeat the first-view crash. The process was stopped deliberately after the
decisive sample; the launcher rebooted to stock `/usr/bin/hiby_player`
(`0fedb30f...`), and the one-shot flag is absent.

Closed log:

```text
artifacts/rs2_folderfollow_view_depth_diag_v2_final.bin
size:    4,558,400 bytes (2,590 complete records)
SHA-256: 842dcb2c4401f01d05bd70358c56164f964f00381dc9cbe38b1278bb10b51986
```

The first active main-explorer view appeared at record 773, and the first
Folder View at record 806. Both type names decoded correctly, directly
confirming the inline-string correction. Important transitions:

| Record | Active view type and path | Last matching explorer type and path |
| --- | --- | --- |
| 806 | `vg_listview_explorer`, `a:\\*` | Same view and path |
| 1629 | `vg_listview_explorer##1`, path not copied | Same view, Roots wildcard path |
| 2200 | `vg_listview_explorer`, `a:\\Slayer - Discography\\Albums\\*` | `vg_listview_explorer##1`, Slayer root wildcard path |
| 2201 | `vg_listview_explorer##1`, path not copied | Same view, Show No Mercy wildcard path |
| 2266 | `vg_listview_explorer`, `a:\\Slayer - Discography\\Albums\\1983 - Show No Mercy\\1987 USA Discovery Systems, Metal Blade 71034-2\\*` | `vg_listview_explorer##1`, `a:\\Slayer - Discography\\Albums\\1983 - Show No Mercy\\*` |

The record 2266 state persisted through the end of the log. With Roots still
playing, the visible deep track-list view is a distinct explorer object whose
own path is one level deeper than the path returned by the last-match helper.
This conclusively invalidates both pointer equality and last-view path as a
general proxy for the active Folder View.

The v2 logger used exact `strcmp` for its optional active-path copy. That
correctly copied the unsuffixed `vg_listview_explorer` objects but did not
copy the path of `vg_listview_explorer##1` objects. Stock `0x4E57E0` uses a
prefix-length `strncmp`, so both names count as explorer. A future active-view
classifier must follow that stock prefix contract; it must not demand exact
name equality. The `state_+40=0` values printed by the shared decoder are
placeholders in v2 because those two optional reads were removed, not observed
state. No new functional patch was installed in this run.
