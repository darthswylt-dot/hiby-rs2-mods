#!/bin/sh
# LOCAL DRAFT. Install/arm separately. Capture only; no automatic retry.
CARD=/mnt/sd_0
FLAG=/mnt/sd_0/RS2_REVEAL_BRIDGE_ONCE
PATCH=/data/hiby_player_reveal_bridge_7cc98a67
STOCK=/usr/bin/hiby_player.sh
PROC=/proc
BASE=/mnt/sd_0/rs2_reveal_bridge_evidence
EXPECTED=7cc98a67a32dabce3b4d22b50b8dc847f5462d99d70d0ee04254a0ec272439a9
EXPECTED_SIZE=7146848
RUN_SECONDS=45
GRACE_SECONDS=5
MIN_FREE_KIB=65536

field() {
    # /proc stat fields after the final comm delimiter start at field 3.
    S=$(cat "$PROC/$1/stat" 5>&- 6>&- 7>&- 8>&- 9>&- 2>/dev/null) || return 1
    case "$S" in "$1 ("*') '*) ;; *) return 1 ;; esac
    S=${S##*) }
    set -- $S
    [ "$#" -ge 20 ] || return 1
    if [ "$FIELD" = parent ]; then printf '%s\n' "$2"; else shift 19; printf '%s\n' "$1"; fi
}
start() { FIELD=start field "$1"; }
digest() {
    H=$(sha256sum "$1" 5>&- 6>&- 7>&- 8>&- 9>&- 2>/dev/null) || return 1
    printf '%s\n' "${H%% *}"
}
same() {
    A=$(start "$1") || return 1
    [ "$A" = "$2" ] || return 1
    H=$(digest "$PROC/$1/exe") || return 1
    [ "$H" = "$3" ] || return 1
    A=$(start "$1") && [ "$A" = "$2" ]
}
fallback() { exec "$STOCK"; }

# ARM GATE: manual invocation must never start stock alongside a player.
command -v pidof >/dev/null 2>&1 || exit 75
[ "$(FIELD=parent field "$$")" = 1 ] || exit 75
if pidof hiby_player hiby_player_sortfix hiby_player_reveal_bridge_7cc98a67 >/dev/null 2>&1; then exit 75;
else R=$?; [ "$R" = 1 ] || exit 75; fi
[ -f "$FLAG" ] || fallback
if ! rm -f "$FLAG" || [ -e "$FLAG" ]; then fallback; fi
sync
# Do not preserve an old diagnostic arm across this recovery boot.
[ ! -e "$CARD/RS2_SORTFIX_TEST" ] || fallback
[ -x "$PATCH" ] && [ ! -L "$PATCH" ] || fallback
awk -v card="$CARD" '$2 == card && $3 == "vfat" && $4 ~ /(^|,)rw(,|$)/ { found=1 } END { exit !found }' "$PROC/mounts" || fallback
AVAILABLE=$(df -Pk "$CARD" 2>/dev/null | awk 'NR == 2 { print $4 }')
case "$AVAILABLE" in ''|*[!0-9]*) fallback ;; esac
[ "$AVAILABLE" -ge "$MIN_FREE_KIB" ] || fallback
[ ! -L "$BASE" ] || fallback
mkdir -p "$BASE" || fallback
STAMP=$(date +%Y%m%dT%H%M%S 2>/dev/null)
case "$STAMP" in ''|*[!0-9T]*) STAMP=unknown ;; esac
N=0
while :; do
    RUN="$BASE/run_${STAMP}_$$_$N"
    if mkdir "$RUN" 2>/dev/null; then break; fi
    N=$((N + 1))
    [ "$N" -lt 8 ] || fallback
done
PARENT=$$
PARENT_START=$(start "$PARENT") || fallback
case "$PARENT_START" in ''|*[!0-9]*) fallback ;; esac
PARENT_HASH=$(digest "$PROC/$PARENT/exe") || fallback

prepare() (
    exec 8>"$RUN/supervisor.txt" || exit 70
    exec 9>"$RUN/bridge.bin" || exit 70
    exec 6>"$RUN/player.stdout" || exit 70
    exec 7>"$RUN/player.stderr" || exit 70
    exec 5>"$RUN/wait.errors" || exit 70
    exec 2>"$RUN/supervisor.errors" || exit 70
    [ -f "$RUN/bridge.bin" ] && [ ! -L "$RUN/bridge.bin" ] || exit 70
    [ "$(digest "$PATCH")" = "$EXPECTED" ] || exit 71
    [ "$(wc -c <"$PATCH" 5>&- 6>&- 7>&- 8>&- 9>&-)" = "$EXPECTED_SIZE" ] || exit 71
    printf 'phase=prepared\ncandidate_sha256=%s\ncandidate_bytes=%s\nlauncher_pid=%s\nlauncher_start=%s\n' "$EXPECTED" "$EXPECTED_SIZE" "$PARENT" "$PARENT_START" >&8 || exit 72
    printf 'deadline_seconds=%s\nterm_grace_seconds=%s\nreboot_grace_seconds=%s\n[boot]\n' "$RUN_SECONDS" "$GRACE_SECONDS" "$GRACE_SECONDS" >&8
    cat "$PROC/sys/kernel/random/boot_id" >&8 5>&- 6>&- 7>&- 8>&- 9>&- || exit 72
    printf '[uptime]\n' >&8
    cat "$PROC/uptime" >&8 5>&- 6>&- 7>&- 8>&- 9>&- || exit 72
    cat "$PROC/meminfo" >"$RUN/before.meminfo" 5>&- 6>&- 7>&- 8>&- 9>&- || exit 72
)
if prepare; then :; else
    R=$?
    printf 'child_not_launched=1\npreparation_status=%s\n' "$R" >"$RUN/preparation.failed"
    sync
    fallback
fi

watchdog() (
    # No player/evidence descriptors or caller pipes survive here. No helper
    # signal is needed for cancellation: an exited launcher revokes authority.
    exec 5>&- 6>&- 7>&- 8>&- 9>&-
    sleep "$RUN_SECONDS"
    same "$PARENT" "$PARENT_START" "$PARENT_HASH" || exit 0
    if same "$CHILD" "$CHILD_START" "$EXPECTED"; then
        kill -TERM "$CHILD"
    fi
    sleep "$GRACE_SECONDS"
    same "$PARENT" "$PARENT_START" "$PARENT_HASH" || exit 0
    if same "$CHILD" "$CHILD_START" "$EXPECTED"; then
        kill -KILL "$CHILD"
    fi
    sleep "$GRACE_SECONDS"
    # Also covers a supervisor stalled after child exit. Do not sync here:
    # card I/O and reboot itself can still block, so this is best effort only.
    same "$PARENT" "$PARENT_START" "$PARENT_HASH" || exit 0
    reboot
)

supervise() (
    # Any failure from here must recover by reboot, never by stock fallback.
    exec 8>>"$RUN/supervisor.txt" || exit 70
    exec 9>"$RUN/bridge.bin" || exit 70
    exec 6>"$RUN/player.stdout" || exit 70
    exec 7>"$RUN/player.stderr" || exit 70
    exec 5>"$RUN/wait.errors" || exit 70
    exec 2>>"$RUN/supervisor.errors" || exit 70
    ulimit -c 0 || exit 72
    printf 'phase=launch_requested\n' >&8 || exit 72
    "$PATCH" 1>&6 2>&7 5>&- 6>&- 7>&- 8>&- &
    CHILD=$!
    # Failure to read this token never authorizes signaling a guessed PID.
    CHILD_START=$(start "$CHILD") || CHILD_START=unavailable
    watchdog </dev/null >/dev/null 2>&1 &
    printf 'phase=child_started\nchild_pid=%s\nchild_start=%s\nwatchdog_pid=%s\n' "$CHILD" "$CHILD_START" "$!" >&8
    if wait "$CHILD" 2>&5; then R=0; else R=$?; fi
    printf 'phase=wait_returned\nchild_pid=%s\nraw_wait_status=%s\n' "$CHILD" "$R" >&8
    printf 'wait_returned=1\nchild_pid=%s\nraw_wait_status=%s\n' "$CHILD" "$R" >"$RUN/child.exit" || exit 73
    exec 9>&-
    exit 0
)
if supervise; then R=0; else R=$?; fi
printf 'supervisor_status=%s\nreboot_requested=1\n' "$R" >"$RUN/recovery.txt"
sync
if reboot; then exit 0; fi
printf 'reboot_command_failed=1\n' >>"$RUN/recovery.txt"
exit 74
