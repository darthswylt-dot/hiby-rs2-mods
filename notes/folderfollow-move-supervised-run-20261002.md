# First supervised evidence-launcher MOVE run

Follow-up: the separately authorized [manual-only run](folderfollow-move-manual-control-20261002.md)
obtained the missing positive setter control. The first-run record below
retains the user's original no-swipe observation and its limitations.

2026-10-02. The user explicitly authorized installation and a short one-shot
test after the read-only preflight. **Installation, live collection and
controlled return to stock succeeded. Auto-scroll remains unfixed.**
The user reproduced the stationary list/offscreen highlight with working
volume and explicitly confirmed that no manual swipe was performed.

## Installation and lifecycle

Fresh preinstallation checks passed with stock PID 121/start ticks 405,
boot `aefacb54-48b6-403f-9414-1755bd214fdc`, absent test flag and unchanged
installed candidate/old log. The current 817-byte launcher was backed up
again under `artifacts/move_launcher_preinstall_20261002/`, SHA-256
`522f0b1bf6e064d52ae1965a7b2724ea4723a4c89f5d250ff1f50e52e38edf4b`.

The exact reviewed 6,535-byte launcher was pushed to a previously absent
`/ui_data/player.move-evidence-20261002.new`, hash-checked and syntax-checked,
made executable, then renamed on the same filesystem over the hash-verified
old `/ui_data/player`. Installed SHA-256:

```text
1cdfed5423da735895993ae18755526cf0395b2c88ad82c138d29ba803f24f6e
```

Only after confirming installation and current stock/boot identity was the
one-shot flag created, synced and a boot-path reboot requested. The launcher
was not manually executed over stock. The MOVE executable remained unchanged:
`15cf4457e829692a52482c0b64a8b478f426f014b7cb31099ed6325a496c3f07`.

The new boot was `75b1fc7f-55b3-4229-ad8b-d74bde2815b0`; MOVE PID 141,
start ticks 700, with verified live executable and FD9 at:

```text
/mnt/sd_0/rs2_move_evidence/run_20261002T093105_108_0/move.bin
```

The flag was consumed. The intended three-minute observation window actually
lasted about **200.68 seconds from child start to the controlled stop request**
(uptime 207.68 minus starttime 7.00 s). This is roughly 20.7 seconds beyond the
intended duration, not an enforced watchdog deadline. Future tests should use
a shorter observation window and reserve explicit shutdown time.

Before stopping, boot ID, PID/starttime, live hash, exact FD9 and absent flag
were checked together. Only PID 141 received SIGTERM. The supervisor was not
signalled. It retained `child.exit`, raw wait status **255**, final state and
`supervisor_completed=1` / `reboot_requested=1`. Status 255 is recorded as the
program/shell result, not recast as a signal number or successful exit 0.
`player.stdout` explicitly records SIGTERM, consistent with the guarded
controlled stop, rather than evidence of a new spontaneous crash.

Recovery boot `b2f2484a-ac4d-4e0f-8916-c760a2e9f64d` ran original stock
PID 119/start ticks 418, hash
`0fedb30f91937eafb5baaf3c75422cdbde04a62fe8bac8eca3c7a88bb761da0e`.
The test flag remained absent. The new launcher stays installed but unarmed.
The old persistent log still hashes to `e181b611...`; it was not removed or
overwritten. No spontaneous reboot occurred during the observed run; this
does not establish general MOVE stability or explain the earlier reboot.

## Evidence integrity and collection

The early live capture in `artifacts/move_live_20261002_early/` passed all
source/transport/record gates: 341,248 bytes, 248 snapshots, no events yet,
no loss, unchanged source identities, and an accepted settled prefix. The
read span was uptime 46.49–56.80. It is an exact byte prefix of the final log.
This is the first successful supervised live use of the legacy collector.

After recovery, the closed run was pulled directly to
`artifacts/move_run_20261002_closed/`: **21 files, 2,148,847 bytes**. All 21
SHA-256 hashes match the device; the manifest and verification report are in
`artifacts/move_run_20261002_verification/`. There were no device-side log
copies, `/tmp` checkpoints, automatic retry or rearm.

Final `move.bin`: **2,069,664 bytes**, SHA-256:

```text
0c8bb9a6c04ba3655d3a6c37f4b7266c2ca08c5eac221d76806d63286eb2f62c
```

Strict decode accepts the complete stream: 1,503 snapshots, three setters,
13 refresh events. Final counters are reserved=drained=16, all loss/error
flags zero, final status present. No partial tail was discarded.
There are also 1,503 status records. Some intermediate statuses have a
pending drain that later statuses confirm; only the final stream is claimed
settled, not every individual observation.

## What the run shows

The playing cue progressed 0→1→2→3→4→5 in the Show No Mercy explorer. Cue
transitions were observed at ticks 1010, 1019, 1028, 1049 and 1058, corresponding
to uptime 144.656, 145.780, 146.926, 149.622 and 150.762 seconds. The final
snapshot, tick 1503 at uptime 207.562, still has cue 5 and scroll_y=0.
All 1,503 snapshots have scroll_y=0.

Only three instrumented setters were recorded, before those cue changes:
ticks 777/787/794, caller `0x491df4`, mode `0x20002`, requested_y=old_y=new_y=0.
There is no nonzero relative `0x30002` setter. The last instrumented refresh
is tick 867, caller `0x452fa4`; neither instrumented hook emits an event during
the later observed cue progression. This supports a missing scroll request
on this Next path, not a failed nonzero setter request. It is not proof that
all possible scroll/update mechanisms have been instrumented.

The user's report agrees: Next moved the highlight beyond the screen, the
list did not follow, and volume continued to work. Because the user did
**not** swipe manually, the positive manual-scroll control is still missing.
The absent relative setter does not show that manual scrolling or its probe
is broken. A separate short, explicitly authorized manual-only test is the
remaining measurement before deciding where to add an auto-scroll request.

## Runtime observations and limits

The launcher retained preparation/start/wait/final markers. `after.state`
reports the expected missing `/proc/141/*` files after the child exited;
these are not evidence of a pre-stop failure. `player.stderr` contains DHCP,
mixer, Bluetooth helper and device warnings, without an established causal
link to scrolling. Kernel after-state extends before-state with audio/device
messages, with no new observed OOM/panic/oops/segfault message. The FAT unclean
unmount warning was already in the before-state, not proof of new corruption.

The startup `running.state` was sampled near exec (uptime 7.01, VmRSS 632 KiB)
and is not steady-state MOVE memory. Live collection at uptime 46.49–56.80
records VmRSS 16,056 KiB, MemFree 956/828 KiB, Cached 11,808/11,920 KiB.
These sparse samples do not establish minimum headroom or a continuous memory
history. Output remains uncapped and card/page-cache activity remains relevant.

No firmware patch, auto-scroll fix, commit or push was made. Current state is
stock playback with the installed one-shot launcher unarmed; no second run
was started after the missing manual-control action was clarified.
