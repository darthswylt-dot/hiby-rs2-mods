# MOVE evidence-retention launcher: local draft

Update 2026-10-02: with explicit user authorization, this exact unchanged
launcher was installed and completed its [first supervised run](folderfollow-move-supervised-run-20261002.md).
Live capture, retained exit evidence and controlled return to stock succeeded.
It remains installed but unarmed. This one short run does not establish
general crash/recovery safety or resolve the previous spontaneous reboot.

Update 2026-10-01: [full-source read-only device preflight](folderfollow-move-launcher-preflight.md)
passed, including exact hash/length, syntax-only controls, prerequisites,
selected shell primitives and a verified backup of the installed launcher.
The draft itself remains unchanged, uninstalled and unexecuted; full live
supervision/recovery and the prior reboot cause are still unvalidated.

Later read-only device checks (2026-09-30) found the host collector
incompatible. A small negative sh -n control worked, but the full launcher
syntax request exceeded the legacy command limit; full device syntax/runtime
remain unverified. No launcher installation/execution or rearm occurred.
See [compatibility gates](folderfollow-move-device-compatibility.md).

2026-09-30. Prepared locally after the user's next `continue` command.
**NOT INSTALLED, NOT ARMED, NOT DEVICE-VALIDATED.** No ADB/device call was
made. The MOVE executable is unchanged and remains a failed/held diagnostic,
not a validated firmware fix. This launcher does not resolve the reboot cause.

Script: `scripts/rs2_folderfollow_move_evidence_launcher.sh`

SHA-256:

```text
1cdfed5423da735895993ae18755526cf0395b2c88ad82c138d29ba803f24f6e
```

Candidate hash is pinned to the existing MOVE v2:

```text
15cf4457e829692a52482c0b64a8b478f426f014b7cb31099ed6325a496c3f07
```

## What changed

This is a separate replacement-launcher **draft**, not a modification to the
old installed launcher or the binary. It addresses the observability gaps
documented in [reboot analysis](folderfollow-move-reboot-analysis.md).

- An unarmed boot runs stock without creating run files. On an armed boot it
  consumes the existing one-shot flag, requires a mounted card and at least
  65,536 KiB free, then atomically creates a fresh persistent run directory.
  If flag removal fails, it runs stock without launching/rebooting the test;
  the flag can remain and must be dealt with before another boot.
- Directories are under `/mnt/sd_0/rs2_move_evidence/`, named by date, launcher
  PID and a bounded collision suffix. Existing directories are not reused.
- `prepare()` opens essential evidence files and verifies the exact candidate
  hash without stopping stock. Only failure in this phase can directly fall
  back to stock.
- The subsequent supervisor starts the diagnostic directly, captures `$!`,
  waits without a pipeline and retains the raw wait result. All non-player
  helpers close FD9. The child inherits only its stdout/stderr and diagnostic
  FD9, not the supervisor's auxiliary descriptors.
- Exit evidence is synced **before** optional final probes, followed by a
  final sync and one recovery reboot. A supervisor failure after the launch
  gate also takes the reboot path, even if an SD marker becomes invisible;
  it must not start stock beside an uncertain surviving test child.
- No log checkpoint is copied to `/tmp` or elsewhere by this script. No
  automatic retry, hung-process kill/timeout or periodic sampler is added.

## Retained evidence

| File in fresh run directory | Meaning |
| --- | --- |
| `move.bin` | Fresh MOVE/MSNP/MSTS stream, opened as FD9 |
| `player.stdout`, `player.stderr` | Direct child output; no tee/pipeline |
| `supervisor.txt`, `supervisor.errors` | Phases, candidate/launcher hash, PID, raw wait result, supervisor errors |
| `wait.errors` | Shell diagnostics emitted by wait, if any |
| `before.state`, `running.state`, `after.state` | Uptime, meminfo, stack limit, free card space, processes; attempted child status/statm/maps/limits |
| `before.dmesg`, `running.dmesg`, `after.dmesg` | Kernel-ring snapshots, if supported |
| `*.errors` | Errors from individual state/kernel capture attempts |
| `child.exit` | `wait_returned=1`, child PID and raw numeric wait status |
| `recovery.txt` | Supervisor outcome and requested recovery; failed reboot can be noted |
| `preparation.failed` | Prelaunch refusal/error; no child launched by that phase |
| `launch.requested` | Attempt marker only; it is never used to authorize stock fallback after supervision starts |

`launcher_pid` deliberately means the invoking shell PID: POSIX `$$` in a
subshell does not reliably identify the inner supervisor. The child PID comes
from `$!`. `/proc` reads can occur before exec or after a very fast exit and
are labeled attempts, not live-executable identity proof.

## Local tests and review

Twenty-one new tests execute an isolated script under GNU Bash in POSIX mode.
All production paths are replaced by disposable fixture paths. Reboot,
killall, sync, battery daemon and firmware are mocked; no real RS2 binary is
executed and no device is connected.

Cases cover unarmed/missing candidate/hash mismatch, mounted-card and free-
space checks, flag-removal failure, naming collisions/exhaustion, fatal open
failure and stock fallback, direct stdout/stderr/FD9, closed helper/child
auxiliary descriptors, normal/raw nonzero/126/127/137 exits, an actual mock
child SIGTERM, optional dmesg failure, wait stderr preservation, immediate
exit flush before final probes, missing disk marker after launch, exit-marker
write failure and failed reboot without duplicate stock launch.

Independent review prompted the separated prelaunch/supervisor stages,
accurate PID label, retained wait stderr and immediate exit sync. Final review
found no concrete must-fix within these stated limits. Shell syntax and
`git diff --check` pass; **all 83 repository tests pass**. This is not a
BusyBox/device test or proof of runtime safety.

```text
bash --posix -n scripts/rs2_folderfollow_move_evidence_launcher.sh
python -m unittest discover -s scripts -p test_move_evidence_launcher.py -v
python -m unittest discover -s scripts -p "test*.py"
```

## Limits and next gate

The 64 MiB free-space check is **admission only**, not an output cap. MOVE and
stdout/stderr can grow until the test ends. Use a short supervised run and
check space externally; this draft does not enforce a time/size budget.
`ulimit -f` was not applied because it would also affect FD9 and could itself
kill the child. Card-backed streams still use page cache and block on I/O.

Three memory snapshots do not measure a continuous RSS/free-memory history.
The existing tmpfs-checkpoint issue is not repaired by installing a launcher
alone: the host collection procedure must also stop accumulating RAM copies
and record memory before/after any capture. A subsequent local-only step
prepared the [direct-to-host checkpoint collector](folderfollow-move-checkpoint-collector.md).
The native collector failed device compatibility; a later
[legacy transport](folderfollow-move-legacy-collector.md) passed stock-only
byte controls, not a live MOVE capture. The old copy procedure must not be reused.

Power loss, a kernel reset, supervisor SIGKILL or card/flush failure may leave
incomplete or non-durable evidence. Neither missing EXIT nor raw status 137
proves OOM/SIGKILL; a program can exit 137 itself. Shell signal messages are
optional and may appear in supervisor errors instead of wait errors. There
are no signal traps; controlled shutdown must target the verified diagnostic
child, not the supervisor. Optional reads or sync may block. If recovery
reboot itself fails, the script exits 74 without risking a duplicate stock
launch; that failure needs manual recovery.

Before installation/start: review these limits, verify supported BusyBox
commands and device free space/memory with scoped read-only checks, preserve
the current installed launcher and prior logs, revise the checkpoint
procedure, and separately authorize a short run. No new hardware result,
autoscroll fix, commit or push is claimed here.
