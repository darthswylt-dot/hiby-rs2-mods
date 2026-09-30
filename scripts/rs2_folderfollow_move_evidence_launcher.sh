#!/bin/sh
# LOCAL DRAFT: not installed, not device-validated. MOVE binary is unchanged.
# One shot, persistent evidence, no tmpfs checkpoints and no automatic retry.
CARD=/mnt/sd_0
FLAG=/mnt/sd_0/RS2_SORTFIX_TEST
PATCH=/data/hiby_player_sortfix
STOCK=/usr/bin/hiby_player.sh
BATD=/usr/bin/batd
PROC=/proc
BASE=/mnt/sd_0/rs2_move_evidence
EXPECTED=15cf4457e829692a52482c0b64a8b478f426f014b7cb31099ed6325a496c3f07
MIN_FREE_KIB=65536

fallback() {
    exec "$STOCK"
}

# An unarmed boot does not create files or touch the test binary.
if [ ! -f "$FLAG" ]; then
    fallback
fi
# Consume before all fallbacks: even a preparation failure must not retry.
if ! rm -f "$FLAG" || [ -e "$FLAG" ]; then
    fallback
fi
sync
[ -x "$PATCH" ] || fallback
# Do not write run data into an unmounted card mountpoint on the rootfs.
awk -v card="$CARD" '$2 == card { found=1 } END { exit !found }' "$PROC/mounts" || fallback
AVAILABLE=$(df -Pk "$CARD" 2>/dev/null | awk 'NR == 2 { print $4 }')
case "$AVAILABLE" in ''|*[!0-9]*) fallback ;; esac
[ "$AVAILABLE" -ge "$MIN_FREE_KIB" ] || fallback
mkdir -p "$BASE" || fallback
STAMP=$(date +%Y%m%dT%H%M%S 2>/dev/null)
case "$STAMP" in ''|*[!0-9T]*) STAMP=unknown ;; esac
ATTEMPT=0
while :; do
    RUN="$BASE/run_${STAMP}_$$_$ATTEMPT"
    if mkdir "$RUN" 2>/dev/null; then
        break
    fi
    ATTEMPT=$((ATTEMPT + 1))
    [ "$ATTEMPT" -lt 8 ] || fallback
done

# Separate prelaunch validation. A failure here permits stock fallback because
# no process shutdown or diagnostic launch is possible in this function.
prepare() (
    exec 8>"$RUN/supervisor.txt" || exit 70
    exec 9>"$RUN/move.bin" || exit 70
    exec 6>"$RUN/player.stdout" || exit 70
    exec 7>"$RUN/player.stderr" || exit 70
    exec 5>"$RUN/wait.errors" || exit 70
    exec 2>"$RUN/supervisor.errors" || exit 70
    ACTUAL=$(sha256sum "$PATCH" 5>&- 6>&- 7>&- 8>&- 9>&- 2>/dev/null)
    ACTUAL=${ACTUAL%% *}
    if [ "$ACTUAL" != "$EXPECTED" ]; then
        printf 'phase=refused reason=candidate_hash\n' >&8
        exit 71
    fi
    printf 'phase=prepared\ncandidate_sha256=%s\nrun=%s\n[launcher_sha256]\n' "$ACTUAL" "$RUN" >&8 || exit 72
    sha256sum "$0" 5>&- 6>&- 7>&- 9>&- >&8 || exit 72
)
if prepare; then
    :
else
    PREPARATION_RC=$?
    printf 'preparation_completed=0\nraw_preparation_status=%s\nchild_not_launched=1\n' "$PREPARATION_RC" >"$RUN/preparation.failed"
    sync
    fallback
fi

# This subshell is intentional: a fatal special-builtin redirection does not
# kill the outer recovery shell. After entering it, any failure goes to reboot
# (not a disk-marker-based fallback that could start two players).
supervise() (
    exec 8>>"$RUN/supervisor.txt" || exit 70
    exec 9>"$RUN/move.bin" || exit 70
    exec 6>"$RUN/player.stdout" || exit 70
    exec 7>"$RUN/player.stderr" || exit 70
    exec 5>"$RUN/wait.errors" || exit 70
    exec 2>>"$RUN/supervisor.errors" || exit 70

    # Direct-to-card streams, not guaranteed small/bounded output. The initial
    # free-space check is admission only. Optional probes are best-effort.
    state() (
        PHASE=$1
        CHILD=$2
        exec 5>&- 6>&- 7>&- 8>&- 9>&-
        STATE_RC=0
        {
            printf 'phase=%s\nlauncher_pid=%s\nchild_pid=%s\n' "$PHASE" "$$" "$CHILD"
            printf '\n[uptime]\n'
            cat "$PROC/uptime" || printf 'unavailable\n'
            printf '\n[meminfo]\n'
            cat "$PROC/meminfo" || printf 'unavailable\n'
            printf '\n[stack_limit]\n'
            ulimit -s || printf 'unavailable\n'
            printf '\n[card_space]\n'
            df -Pk "$CARD" || printf 'unavailable\n'
            printf '\n[processes]\n'
            ps || printf 'unavailable\n'
            if [ -n "$CHILD" ]; then
                for ITEM in status statm maps limits; do
                    printf '\n[child_%s]\n' "$ITEM"
                    cat "$PROC/$CHILD/$ITEM" || printf 'unavailable_or_exited\n'
                done
            fi
        } >"$RUN/$PHASE.state" 2>"$RUN/$PHASE.state.errors" || STATE_RC=1
        dmesg >"$RUN/$PHASE.dmesg" 2>"$RUN/$PHASE.dmesg.errors" || STATE_RC=1
        exit "$STATE_RC"
    )

    state before '' || printf 'warning=before_state_incomplete\n' >&8
    # Guard marker before any stock shutdown or possible child launch. Outer
    # recovery must not start stock alongside an uncertain surviving child.
    printf 'launch_requested=1\n' >"$RUN/launch.requested" || exit 72
    sync 5>&- 6>&- 7>&- 8>&- 9>&-
    killall hiby_player 5>&- 6>&- 7>&- 8>&- 9>&- >/dev/null 2>&1
    killall -9 hiby_player 5>&- 6>&- 7>&- 8>&- 9>&- >/dev/null 2>&1
    if [ -f "$BATD" ]; then
        killall batd 5>&- 6>&- 7>&- 8>&- 9>&- >/dev/null 2>&1
        killall -9 batd 5>&- 6>&- 7>&- 8>&- 9>&- >/dev/null 2>&1
        "$BATD" -v -s -t5 -o "$CARD/batlog.txt" 5>&- 6>&- 7>&- 8>&- 9>&- &
    fi

    # No pipeline/tee, no inherited evidence handles except the player's FD9.
    "$PATCH" 1>&6 2>&7 5>&- 6>&- 7>&- 8>&- &
    CHILD_PID=$!
    printf 'phase=child_started\nchild_pid=%s\n' "$CHILD_PID" >&8
    state running "$CHILD_PID" || printf 'warning=running_state_incomplete\n' >&8
    # No signal traps: an interrupted/killed supervisor leaves incomplete
    # evidence. Controlled test shutdown targets the verified child, not us.
    if wait "$CHILD_PID" 2>&5; then
        CHILD_RC=0
    else
        CHILD_RC=$?
    fi
    printf 'phase=wait_returned\nchild_pid=%s\nraw_wait_status=%s\n' "$CHILD_PID" "$CHILD_RC" >&8
    # The marker is raw shell evidence, not a definitive signal/OOM diagnosis.
    printf 'wait_returned=1\nchild_pid=%s\nraw_wait_status=%s\n' "$CHILD_PID" "$CHILD_RC" >"$RUN/child.exit" || exit 73
    exec 9>&-
    # Flush the minimal wait result before optional final reads can block.
    sync 5>&- 6>&- 7>&- 8>&- 9>&-
    state after "$CHILD_PID" || printf 'warning=after_state_incomplete\n' >&8
    printf 'phase=end_capture_attempted\n' >&8
    sync 5>&- 6>&- 7>&- 8>&- 9>&-
    exit 0
)

if supervise; then
    printf 'supervisor_completed=1\nreboot_requested=1\n' >"$RUN/recovery.txt"
else
    SUPERVISOR_RC=$?
    printf 'supervisor_completed=0\nraw_supervisor_status=%s\nchild_exit_unknown=1\n' "$SUPERVISOR_RC" >"$RUN/recovery.txt"
    # Launch may have occurred even if the card/marker becomes inaccessible.
    printf 'reboot_requested=1\n' >>"$RUN/recovery.txt"
fi
sync
sleep 1
if reboot; then
    exit 0
fi
# If reboot fails, do not risk starting stock beside an uncertain child.
printf 'reboot_command_failed=1\n' >>"$RUN/recovery.txt"
sync
exit 74
