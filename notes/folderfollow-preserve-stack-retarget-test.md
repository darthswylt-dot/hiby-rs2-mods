# Folder-follow preserve-stack retarget hardware test

This is an unsupported, one-shot hardware test. It is not a release candidate.
The patched binary is intentionally not stored in the repository.

Status: **failed on hardware; discard**.

## Why this candidate is different

The two discarded candidates called `0x4E4B20` and `0x4E4640` to destroy and
recreate explorer views around `0x4E5FA0`. Both orderings corrupted stock UI
ownership and deferred navigation state.

This candidate calls neither function. Static analysis found an existing-view
reuse path in stock `0x491E80`:

```text
0x4E5680  get the current explorer view
0x4916A0  perform stock current-view preparation
0x438BE0  require at least two "vg_listview_explorer" views
0x4E57E0  find the last existing view of that type
0x4919E0  retarget that view from its old UTF-16 path to a new UTF-16 path
```

The stock instructions at `0x492B58-0x492B90` use the last three operations in
exactly this order when the Folder View constructor decides that an existing
view can be reused. Stock parent-folder navigation at `0x494028-0x49403C` also
calls `0x4919E0` to retarget the existing view stack. This is therefore a stock
navigation mechanism, not another lifecycle permutation.

## Artifact identity

Input artifact:
`hiby_player_1.4_sortfix_fullnav_bkl3_force_refresh_test`

Input SHA-256:

```text
c825a72e1078999f74822846d35c99971f9a660addd5f12d42d50a75f0b9b80e
```

Output artifact:
`hiby_player_1.4_sortfix_fullnav_wake_folderfollow_preserve_stack_retarget_test`

Output SHA-256:

```text
c637effab37ff202c172a3f32a75f0d7cfbf309eec13ab8c5ecd1a89de1adfcc
```

Both files are 7,133,528 bytes. Reproduce the output with:

```powershell
python .\scripts\build_folderfollow_preserve_stack_retarget.py `
  C:\platform-tools\hiby_player_1.4_sortfix_fullnav_bkl3_force_refresh_test `
  C:\platform-tools\hiby_player_1.4_sortfix_fullnav_wake_folderfollow_preserve_stack_retarget_test
```

## Exact binary changes

The executable mapping at these locations is
`virtual address = file offset + 0x400000`.

| File offset | Virtual address | Golden bytes | Test bytes | Meaning |
| --- | --- | --- | --- | --- |
| `0x0EADB4` | `0x4EADB4` | `4e00053c` | `9200053c` | callback address high half: `lui a1,0x4e` -> `lui a1,0x92` |
| `0x0EADBC` | `0x4EADBC` | `a05fa524` | `b0faa524` | callback address low half: `0x4E5FA0` -> `0x91FAB0` |
| `0x51FAB0-0x51FBDB` | `0x91FAB0-0x91FBDB` | 300 zero bytes | wrapper emitted by the patcher | executable code cave |

The changed callback registration still has a valid delay slot:

```text
0x4EADB4  lui   a1,0x92
0x4EADB8  jal   0x459580
0x4EADBC  addiu a1,a1,-0x550    # delay slot; forms 0x91FAB0
```

For the target callback event `a2=1,a3=1`, the wrapper does:

```text
0x91FAE8  jal   0x459340        # player context
0x91FAF8  lw    s0,0x3c(v0)     # explorer object
0x91FB20  jal   0x4E4B80        # current playback UTF-16 path
0x91FB40  jal   0x4E5680        # current view
0x91FB4C  jal   0x4916A0        # stock current-view preparation
0x91FB64  jal   0x438BE0        # count vg_listview_explorer views
0x91FB6C  slti  v0,v0,2
0x91FB70  bnez  v0,0x91FBB0     # do nothing unless count >= 2
0x91FB88  jal   0x4E57E0        # find last existing explorer view
0x91FBA0  addiu a1,s1,0x3dd8    # old view path
0x91FBA4  addiu a2,sp,0x40      # current playback path
0x91FBA8  jal   0x4919E0        # stock in-place retarget
0x91FBB0  restore original callback arguments and saved registers
0x91FBD4  j     0x4E5FA0        # original callback
0x91FBD8  nop
```

Every inserted branch, `jal`, and `j` has an explicit `nop` delay slot. The
wrapper preserves `a0-a3`, `s0-s2`, `ra`, and `sp` before tail-calling the
original callback. A full comparison against the golden input found no changed
bytes outside the two callback-pointer words and the code cave. Sorting,
full-navigation, wake-refresh, and all audio-path bytes remain unchanged.

## One-shot deployment

The launcher consumes the flag before starting the test binary. A player exit
or crash therefore returns the next boot to the stock player.

```powershell
Set-Location C:\platform-tools

$artifact = '.\hiby_player_1.4_sortfix_fullnav_wake_folderfollow_preserve_stack_retarget_test'
$expected = 'c637effab37ff202c172a3f32a75f0d7cfbf309eec13ab8c5ecd1a89de1adfcc'
$localHash = (Get-FileHash -Algorithm SHA256 $artifact).Hash.ToLowerInvariant()
if ($localHash -ne $expected) { throw "Local SHA-256 mismatch: $localHash" }

.\adb.exe devices
.\adb.exe push $artifact /data/hiby_player_sortfix
.\adb.exe shell chmod 755 /data/hiby_player_sortfix
$remoteHash = ((.\adb.exe shell sha256sum /data/hiby_player_sortfix) -split '\s+')[0].ToLowerInvariant()
if ($remoteHash -ne $expected) { throw "Remote SHA-256 mismatch: $remoteHash" }

.\adb.exe shell cat /ui_data/player
.\adb.exe shell touch /mnt/sd_0/RS2_SORTFIX_TEST
.\adb.exe shell "sync; reboot"
```

After at least 15 seconds:

```powershell
.\adb.exe devices
.\adb.exe shell "ps | grep hiby"
.\adb.exe shell ls -l /mnt/sd_0/RS2_SORTFIX_TEST
```

The process list should show `/data/hiby_player_sortfix`; the one-shot flag
should already be absent.

## Focused hardware test

1. Start a track from a nested Folder View and enter Now Playing.
2. Let playback advance to a track in a different folder so the old Folder
   View path is stale.
3. Wait 20 seconds without touching the screen. Any spontaneous transition is
   an immediate failure.
4. Swipe once from Now Playing back toward Folder View.
5. Pass the focused step only if the current track's folder appears, remains
   stable for 20 seconds, and responds normally to scrolling and Back.
6. Return to Now Playing, test one Next/autoplay boundary and one Previous
   boundary, then repeat the swipe.
7. Finish with the verified screen-off -> track change -> Pause -> wake case to
   confirm the wake fix still behaves identically.

Immediate failure conditions: Music or Files root appears unexpectedly; an All
list replaces the current folder; panels shift or overlap; navigation state
disagrees with the visible folder; input stalls; the player exits; or the
device reboots.

## Hardware result

Folder View still showed the folder where playback began rather than the
folder containing the current track. For a period, the interface also did not
respond to physical buttons normally.

Result: **failed; discard**. Avoiding `0x4E4B20`/`0x4E4640` prevented the severe
stack-rebuild corruption seen in the two earlier candidates, but calling the
stock `0x4919E0` retarget sequence from this callback did not synchronize the
view and still disturbed input handling. The next step is to identify the
actual owner and timing of the Folder View activation state, not to call
another navigation helper from `0x4E5FA0`.

Do not remove `/etc/init.d/S99adb` until all RS2 tests are complete.
