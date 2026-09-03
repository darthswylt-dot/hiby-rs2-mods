# Folder-follow rebuild-before-callback hardware test

This is an unsupported, one-shot hardware test. It is not a release candidate.
The patched binary is intentionally not stored in this repository.

Status: **failed on hardware; discard**.

## Artifact identity

Input artifact:
`hiby_player_1.4_sortfix_fullnav_bkl3_force_refresh_test`

Required input SHA-256:

```text
c825a72e1078999f74822846d35c99971f9a660addd5f12d42d50a75f0b9b80e
```

Output artifact:
`hiby_player_1.4_sortfix_fullnav_wake_folderfollow_rebuild_before_callback_test`

Output SHA-256:

```text
5faa8c07da3ffaeba0ac1480ae0694319473112862b3b111bd9f4920d4c06eda
```

Both files are 7,133,528 bytes. The output can be reproduced with the strict
hash-checking patcher:

```powershell
python .\scripts\build_folderfollow_rebuild_before_callback.py `
  C:\platform-tools\hiby_player_1.4_sortfix_fullnav_bkl3_force_refresh_test `
  C:\platform-tools\hiby_player_1.4_sortfix_fullnav_wake_folderfollow_rebuild_before_callback_test
```

## Exact binary changes

The ELF executable mapping is `virtual address = file offset + 0x400000` for
these locations.

| File offset | Virtual address | Golden bytes | Test bytes | Meaning |
| --- | --- | --- | --- | --- |
| `0x0EADB4` | `0x4EADB4` | `4e00053c` | `9200053c` | `lui a1,0x4e` -> `lui a1,0x92` |
| `0x0EADBC` | `0x4EADBC` | `a05fa524` | `00fba524` | `addiu a1,a1,0x5fa0` -> `addiu a1,a1,-0x500` |
| `0x51FB00-0x51FBBF` | `0x91FB00-0x91FBBF` | 192 zero bytes | wrapper below | executable code cave |

The two callback-pointer instructions form `0x91FB00`. The lower `addiu` at
`0x4EADBC` remains the delay slot of the unchanged `jal 0x459580` callback
registration call.

The inserted wrapper disassembles as follows (prologue/epilogue stores and
loads are abbreviated here, but are emitted by the patcher and verified in the
final binary):

```text
0x91FB20  addiu v0,zero,1
0x91FB24  bne   a2,v0,0x91FB98
0x91FB28  nop
0x91FB2C  bne   a3,v0,0x91FB98
0x91FB30  nop
0x91FB34  jal   0x459340
0x91FB38  nop
0x91FB3C  beqz  v0,0x91FB98
0x91FB40  nop
0x91FB44  lw    s0,0x3c(v0)
0x91FB48  beqz  s0,0x91FB98
0x91FB4C  nop
0x91FB50  addiu a0,sp,0x40
0x91FB54  move  a1,zero
0x91FB58  addiu a2,zero,0x208
0x91FB5C  jal   0xA5BC60
0x91FB60  nop
0x91FB64  move  a0,s0
0x91FB68  addiu a1,sp,0x40
0x91FB6C  jal   0x4E4B80
0x91FB70  nop
0x91FB74  move  s1,v0
0x91FB78  move  a0,s0
0x91FB7C  jal   0x4E4B20
0x91FB80  nop
0x91FB84  move  a0,s0
0x91FB88  addiu a1,sp,0x40
0x91FB8C  move  a2,s1
0x91FB90  jal   0x4E4640
0x91FB94  nop
0x91FB98  restore original a0-a3, s0-s1, ra, and sp
0x91FBB8  j     0x4E5FA0
0x91FBBC  nop
```

The ordering for the target `a2=1, a3=1` gesture is therefore:

```text
get current path -> destroy old stack -> build new stack -> original callback
```

All other gesture values, a missing player context, or a null explorer pointer
go directly to the original callback. The tail-call preserves the stock return
value. Every inserted MIPS branch or jump has an explicit `nop` delay slot.

A full comparison with the golden input found 139 changed bytes and no changes
outside the two callback-pointer words and the code cave. This proves that the
confirmed sorting, full-navigation, and wake-refresh patches are unchanged.
It also means no audio-path instruction or data byte was modified.

## Exact one-shot ADB deployment

Run these commands in PowerShell from the machine that contains
`C:\platform-tools`. They verify both the local and device-side hashes before
arming the one-shot boot.

```powershell
Set-Location C:\platform-tools

$artifact = '.\hiby_player_1.4_sortfix_fullnav_wake_folderfollow_rebuild_before_callback_test'
$expected = '5faa8c07da3ffaeba0ac1480ae0694319473112862b3b111bd9f4920d4c06eda'
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

If `/ui_data/player` is absent or does not contain the one-shot launcher, install
the tracked launcher before touching the flag:

```powershell
.\adb.exe shell mkdir -p /ui_data
.\adb.exe push .\hiby-rs2-mods\scripts\rs2_sortfix_launcher.sh /ui_data/player
.\adb.exe shell chmod 755 /ui_data/player
.\adb.exe shell cat /ui_data/player
```

After reboot, wait at least 15 seconds, reconnect ADB, and check that the patched
path is running and the one-shot flag has already been consumed:

```powershell
.\adb.exe devices
.\adb.exe shell "ps | grep hiby"
.\adb.exe shell ls -l /mnt/sd_0/RS2_SORTFIX_TEST
```

The process list should contain `/data/hiby_player_sortfix`; `ls` should report
that the flag does not exist.

## Focused hardware check

1. Start a track from Folder View and enter Now Playing.
2. Let playback move to a track in a different folder so the current explorer
   stack is stale.
3. Swipe once from Now Playing back to Folder View.
4. Pass: the current track's folder appears and remains responsive; opening a
   row and returning to Now Playing still works.
5. Fail: Music root appears, panels overlap, input stops responding, the wrong
   folder appears, or the player exits/reboots.
6. After the focused check, repeat one Next/autoplay boundary, one Previous
   boundary, and the already validated screen-off/track-change/Pause/wake case
   to catch regressions.

If the UI hangs but ADB remains available:

```powershell
.\adb.exe shell "ps | grep hiby"
.\adb.exe shell "sync; reboot"
```

## Hardware result

Playback initially continued normally. Without any user gesture, Now Playing
then transitioned through Music and Files to Files root, showing SD-card1,
SD-card2, and USB-storage. Later, returning from
`Slayer - Evil Has No Boundaries` opened a broad All list instead of the
current Slayer folder. Further navigation produced shifted or overlapping
views and an inconsistent hierarchy. Input eventually stopped responding
normally, the screen went dark, and the player exited or crashed before the
device rebooted automatically.

Result: **failed; severe UI/navigation state corruption**. Moving explorer
destruction/rebuild before original `0x4E5FA0` did not solve folder-follow.
Together with the earlier `c4dc...` result, both simple orderings are unsafe.
Do not try more permutations of `0x4E4B20`, `0x4E4B80`, `0x4E4640`, and
`0x4E5FA0`.

The launcher consumes the flag before starting the test binary, so the next
boot falls back to the stock player. Do not remove `/etc/init.d/S99adb` yet;
remove it only after all RS2 testing is complete and the final binary has been
validated.
