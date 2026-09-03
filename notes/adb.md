# ADB and reversible test deployment

The RS2 firmware contains `/etc/init.d/K90adb`. Its `start` action configures
the USB gadget as `18d1:0d02`, selects the `adb` function, and starts
`/sbin/adbserver.sh`. ADB runs as root without the normal Android authorization
dialog, so automatic startup is suitable only for a controlled test device.

## Temporary automatic ADB

Starting ADB too early with an `S90adb` symlink did not persist: `hiby_player`
later reconfigured the USB gadget according to the selected Storage/Audio USB
mode. The development workaround starts it last and waits for the player to
finish configuring USB:

```sh
cat > /etc/init.d/S99adb <<'EOF'
#!/bin/sh
case "$1" in
  start)
    (
      sleep 10
      /etc/init.d/K90adb start
    ) &
    ;;
  stop)
    /etc/init.d/K90adb stop
    ;;
esac
exit 0
EOF

chmod 755 /etc/init.d/S99adb
sync
```

After boot, wait at least 15 seconds and check:

```powershell
adb devices
```

Remove the automatic root interface when testing is finished:

```powershell
adb shell rm -f /etc/init.d/S99adb
adb shell sync
```

## One-shot patched-player launcher

The stock firmware starts `/ui_data/player` when present. The helper in
[`scripts/rs2_sortfix_launcher.sh`](../scripts/rs2_sortfix_launcher.sh) launches
`/data/hiby_player_sortfix` only when all of the following are true:

- `/mnt/sd_0/RS2_SORTFIX_TEST` exists;
- `/data/hiby_player_sortfix` exists and is executable.

The launcher removes the flag before starting the patched player. If that
player exits or crashes, the device reboots, and the next boot falls through to
the stock `/usr/bin/hiby_player.sh`. This makes each test opt-in and one-shot.

Install or update a test binary:

```powershell
adb push .\hiby_player_TEST /data/hiby_player_sortfix
adb shell chmod 755 /data/hiby_player_sortfix
adb shell sha256sum /data/hiby_player_sortfix
```

Install the launcher if `/ui_data/player` is missing or contains only the stock
passthrough:

```powershell
adb shell mkdir -p /ui_data
adb push .\scripts\rs2_sortfix_launcher.sh /ui_data/player
adb shell chmod 755 /ui_data/player
adb shell cat /ui_data/player
```

Arm exactly one patched boot:

```powershell
adb shell touch /mnt/sd_0/RS2_SORTFIX_TEST
adb shell "sync; reboot"
```

After boot, verify the running executable:

```powershell
adb shell "ps | grep hiby"
adb shell ls -l /mnt/sd_0/RS2_SORTFIX_TEST
```

The process list should show `/data/hiby_player_sortfix`, and the flag should
already be absent.

To disable the launcher completely, replace `/ui_data/player` with
[`scripts/rs2_passthrough_player.sh`](../scripts/rs2_passthrough_player.sh), or
remove the one-shot flag before rebooting.

Exact one-shot commands and hardware results are recorded per experiment:

- [rebuild-before-callback test](folderfollow-rebuild-before-callback-test.md)
- [preserve-stack retarget test](folderfollow-preserve-stack-retarget-test.md)
- [dispatcher FD9 diagnostic](folderfollow-dispatch-fd9-diag.md)

The FD9 diagnostic uses
[`scripts/rs2_folderfollow_diag_launcher.sh`](../scripts/rs2_folderfollow_diag_launcher.sh)
instead of the ordinary launcher. It truncates the binary log before launch,
opens it as inherited descriptor 9, and lets the callback append fixed-size
records without invoking a shell. Do not truncate that log while the patched
process still holds FD 9 open; note any USB/DAC-screen prelude records and
classify later Folder View records by index.
