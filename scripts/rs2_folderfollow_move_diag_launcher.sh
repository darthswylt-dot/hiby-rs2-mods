#!/bin/sh
# One-shot MOVE v2 telemetry. Installation/arming is a separate operation.
FLAG=/mnt/sd_0/RS2_SORTFIX_TEST
PATCH=/data/hiby_player_sortfix
LOG=/mnt/sd_0/rs2_folderfollow_move_diag.bin

if [ -f "$FLAG" ] && [ -x "$PATCH" ]; then
    rm -f "$FLAG"
    sync
    # Refuse to overwrite or mix generations of an earlier diagnostic log.
    if [ -e "$LOG" ]; then
        exec /usr/bin/hiby_player.sh
    fi
    exec 9>>"$LOG" || exec /usr/bin/hiby_player.sh
    killall hiby_player >/dev/null 2>&1
    killall -9 hiby_player >/dev/null 2>&1
    if [ -f /usr/bin/batd ]; then
        killall batd >/dev/null 2>&1
        killall -9 batd >/dev/null 2>&1
        /usr/bin/batd -v -s -t5 -o /mnt/sd_0/batlog.txt 9>&- &
    fi
    "$PATCH"
    exec 9>&-
    sync
    sleep 1
    reboot
fi
exec /usr/bin/hiby_player.sh
