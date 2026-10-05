# MOVE launcher read-only preflight on RS2

Follow-up 2026-10-02: the user separately authorized installation and a
[short supervised run](folderfollow-move-supervised-run-20261002.md), which
completed with retained evidence and controlled recovery to stock. The
read-only results below remain the earlier preinstallation record.

2026-10-01. **Read-only preflight passed. The launcher was neither installed
nor executed, the test flag stayed absent, and MOVE was not started.**
This closes the earlier full-script syntax/command-length blocker, not the
unexplained MOVE reboot or full launcher runtime validation.

Host check: `scripts/check_move_launcher_preflight.py`.
Evidence: `artifacts/move_launcher_preflight_20261001/`, including raw
before/after, prerequisites, syntax controls, runtime controls and report.
The report records `readonly_preflight_passed=true`,
`stock_state_preserved=true`, `launcher_executed=false`, and
`live_move_validated=false`.

## Exact full-source syntax, without execution

The unchanged 6,535-byte evidence launcher is gzip-compressed and transported
as ASCII using the available `uudecode -o -` (stdout) and `gzip -dc` tools.
The device has no base64 applet. A trailing sentinel preserves all final
newlines when holding the decoded text in a shell variable. The exact length
and SHA-256 are checked **before** that variable is piped exclusively to
`sh -n`; there is no eval, source, normal shell execution or output file.

The quoted remote command is 3,769 bytes, below the 4,000-byte host limit.
This avoids the previous oversized literal without changing the launcher:

```text
1cdfed5423da735895993ae18755526cf0395b2c88ad82c138d29ba803f24f6e
```

The device confirmed this hash and length; the full syntax check returned
explicit remote status 0 with no diagnostics. Before it, two controls passed:

- A valid script containing a stdout sentinel and `exit 37` returned syntax
  status 0 and emitted no sentinel, confirming parse-only operation.
- Deliberately invalid `if then` returned explicit status 2 and the expected
  syntax diagnostic, despite the legacy ADB client's zero exit status.

All three transferred texts were independently length/hash-gated. Malformed
or incomplete output, wrong status/hash/length, unexpected output from a
valid parse, timeouts and output overflows are rejected. These controls do
not execute even the unarmed/fallback path of the real launcher.

## Prerequisites and selected shell primitives

The direct vfat card mount matched between the inspection shell and stock
player: mount ID 19, parent 11, device 179:1, source `/dev/mmcblk0p1`,
mountpoint `/mnt/sd_0`, root `/`, read/write. `df` showed **5,928,296 KiB**
available, above the launcher's 65,536-KiB admission threshold.

All required command paths resolved. Destructive/mutating tools (`rm`,
`mkdir`, `sync`, `killall`, `reboot`) were checked for availability only,
never invoked. Permission checks found the card directory writable and the
candidate, stock wrapper and present battery daemon executable. Existing
stock/installed launcher scripts passed `sh -n`. Stack limit was 4,096 KiB;
date formatting, process list, kernel-ring read and child proc-file access
were available. Permission checks are not proof that a future card write
or recovery reboot will succeed.

Read-only transient-shell controls confirmed:

- `$!` plus `wait` preserves a known child exit status 37.
- A failed read-only `exec` open inside a subshell function returns 2 while
  the outer shell continues, exercising the intended recovery isolation.
- A read-only FD9 opened on `/proc/uptime` is inherited by a test shell and
  absent when explicitly closed for another. This descriptor belongs only
  to the probe, not to the running player.

No player was signalled; no test child was killed. These small controls do
not validate the complete supervisor, firmware, card-output or reboot paths.

## Backup and unchanged state

The previously migrated `move_diag_install_backup_20260930/player` is a
different 889-byte launcher (`0151c274...`), not an exact backup of the
currently installed version. It remains preserved. The current 817-byte
`/ui_data/player` was read through a bounded hex stream to:

```text
artifacts/move_launcher_preflight_20261001/installed_launcher.bin
```

Its complete SHA-256 matches the live file and paired before/after checks:

```text
522f0b1bf6e064d52ae1965a7b2724ea4723a4c89f5d250ff1f50e52e38edf4b
```

Stock PID 116, start ticks 349 and boot ID
`d20f9fb3-9038-445a-961b-02f1cd17f03b` were unchanged. The original live
executable remained `0fedb30f...`; `RS2_SORTFIX_TEST` remained absent.
Installed MOVE stayed `15cf4457...`. The old closed log stayed
`e181b611...`, inode 142, 7,973,184 bytes, matching its saved local recovery.
No installed file or persistent log was overwritten.

Paired stock memory: MemTotal 58,308 KiB, MemFree 796/892 KiB,
Cached 17,116/17,016 KiB, Shmem 4 KiB, VmRSS 18,712 KiB. This is current
stock context, not proof of MOVE headroom or an explanation of its prior
reboot. Read-only inspection still has transient CPU/cache/I/O costs.

## Local verification completed 2026-10-02

All **183** repository tests pass without skips, including 22 new preflight
tests. All 64 Python scripts compile, and `git diff --check` passes. Local
tests exercise strict evidence parsing, exact trailing-newline restoration,
nonexecution of a syntax-valid side-effect payload, decoder failure, runtime
primitives, pre-contact refusal and preservation of failure/after evidence.
The local shell fixture substitutes only uudecode (unavailable in Git Bash);
the actual RS2 applet was used in the separate hardware check above.

Final independent read-only review verified the saved raw controls and
817-byte backup hash and found no material blocker within this scope. No
additional device call or deployment was made during this final local pass.

## Remaining decision

The read-only syntax and prerequisite gate has passed. An actual run still
requires separate authorization to replace the installed launcher, arm the
one-shot flag and restart through the intended boot path. Do not manually
execute the launcher during stock playback merely to test a branch.

Use a short supervised run, a fresh card run directory, and the bounded
legacy collector; never accumulate `/tmp` checkpoint copies. Output growth
is not capped by this launcher, and initial free space is admission only.
Card I/O/flushes, memory use, full supervision and recovery behavior remain
unvalidated. A renewed spontaneous reboot remains a known risk. No
auto-scroll fix, successful live MOVE capture, commit or push is claimed.
