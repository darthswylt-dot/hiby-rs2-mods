#!/bin/sh

FLAG=/mnt/sd_0/RS2_SORTFIX_TEST
PATCH=/data/hiby_player_sortfix
LOG=/mnt/sd_0/rs2_folderfollow_dispatch_diag.bin

if [ -f "$FLAG" ] && [ -x "$PATCH" ]; then
    rm -f "$FLAG"
    sync

    killall hiby_player >/dev/null 2>&1
    killall -9 hiby_player >/dev/null 2>&1

    if [ -f /usr/bin/batd ]; then
        killall batd >/dev/null 2>&1
        killall -9 batd >/dev/null 2>&1
        /usr/bin/batd -v -s -t5 -o /mnt/sd_0/batlog.txt &
    fi

    : > "$LOG"
    exec 9>>"$LOG"
    "$PATCH"
    exec 9>&-
    sync
    sleep 1
    reboot
fi

exec /usr/bin/hiby_player.sh
