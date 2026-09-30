# MOVE host collector: RS2 read-only compatibility check

2026-09-30, following the user's `check` command. **Compatibility failed;
do not deploy/rearm MOVE using the current collector.** No installation,
launcher execution, player signal, reboot, flag write, device-side copy or
device file creation was performed. Reads can still affect cache/I/O and
start small transient shell/helper processes.

## Observed blockers

| Gate | Device observation | Consequence |
| --- | --- | --- |
| `adb exec-out` | Both the collector-style metadata request and a minimal `echo` return host status 1, `error: closed`, no stdout | Current collector transport cannot operate on this device |
| `adb shell -T` | Host status 1, `error: device only supports allocating a pty` | A raw non-PTY shell is not available through this option |
| `stat -c` / `stat -L` | `stat` is not on PATH; `busybox stat` reports `applet not found`; applet inventory also lacks it | Current file device/inode/size checks cannot run |
| Remote exit status | Legacy shell `exit 37` returns host status 0; a failing syntax probe prints remote status 2 while host status is 0 | Host ADB success does not establish remote command success |
| Binary legacy shell | Explicit 10-byte NUL/CR/LF/FF control yields 16 bytes | Do not replace `exec-out` with plain PTY shell or apply text newline cleanup to binary logs |

Client is ADB 1.0.41, package 36.0.0-13206524. Device BusyBox reports
v1.25.0.git (2016-06-12). These observations describe the current combination,
not a universal claim about all ADB/BusyBox versions or the original reboot.

The exact byte control was remote stdout only, with no file writes:

```text
printf '\000\015\012\377A\012B\015\012Z'
expected: 000d0aff410a420d0a5a
received: 000d0d0d0aff410d0d0a420d0d0d0a5a
```

A separate `head -c 1376` read from the closed old card log matched the local
recovered prefix exactly, SHA-256
`f7053afc949c4f38c9b2489ae7c6e21a7053864de1d7f415978d286fe7d33974`.
The same hash was obtained on-device by piping this bounded prefix to
`sha256sum`. That sample has **zero CR and LF bytes**; it cannot establish
arbitrary binary safety and does not contradict the failing byte control.
No active MOVE capture was attempted; stock is not a valid live MOVE source.

## Supported reads and incomplete launcher verification

`head -c`, `readlink`, SHA-256 of `/proc/118/exe`, boot ID, process
stat/status, meminfo, `ps`, `dmesg` without clearing, `date`, and `ulimit -s`
worked through legacy shell. A transient read-only FD9 opened on the closed
old log resolved to the correct path; no player descriptor was changed.
`awk -v card=/mnt/sd_0` mount detection and `df -Pk`/second-row free-space
extraction worked. The card is mounted vfat, with 5,928,296 KiB available.
Stack limit reported 4096 KiB.

For `rm`, `mkdir`, `sync`, `killall`, `reboot` and `sleep`, only command
availability was queried; no mutating commands were invoked.

A small deliberately invalid literal piped to `sh -n` produced syntax
error and explicit remote `__SYNTAX_RC__2`. Its literal SHA-256 matched
the host input. This confirms that small syntax-check method, not the whole
launcher. A full launcher literal plus hash request was rejected by the
client as `error: shell command too long` before device execution. Therefore
**full device syntax and launcher runtime behavior remain unverified**.
Neither launcher was run by this check.

## Preserved state and memory context

Before/after/final probes retain the same boot ID
`1213d924-5f82-4054-9d77-23e5345a848c`, stock PID 118 and process starttime
418 ticks. Uptime advanced normally (8765.37 to 8769.25 seconds in the paired
probe; final confirmation 8969.69 seconds). The live executable remained:

```text
0fedb30f91937eafb5baaf3c75422cdbde04a62fe8bac8eca3c7a88bb761da0e
```

Flag `/mnt/sd_0/RS2_SORTFIX_TEST` remained absent. Installed files and old log
hashes were unchanged:

```text
/ui_data/player                         522f0b1bf6e064d52ae1965a7b2724ea4723a4c89f5d250ff1f50e52e38edf4b
/data/hiby_player_sortfix                15cf4457e829692a52482c0b64a8b478f426f014b7cb31099ed6325a496c3f07
/mnt/sd_0/rs2_folderfollow_move_diag.bin  e181b61124075c46c6b9be3cc6ebe6ad2c48d8639014991de4545fd632a63222
```

The local evidence launcher remains uninstalled, SHA-256
`1cdfed5423da735895993ae18755526cf0395b2c88ad82c138d29ba803f24f6e`.
Local MOVE hash also remains `15cf4457...`.

Paired current-stock memory reads: MemTotal 58,308 KiB, MemFree 896/920 KiB,
Cached 18,396/18,364 KiB, Shmem 4 KiB, no swap; player RSS 15,964 KiB.
Low MemFree alone is not an OOM diagnosis because some cache is reclaimable.
These are **post-reboot stock** values, not old MOVE RAM/headroom evidence;
they cannot prove or exclude the earlier tmpfs-pressure hypothesis. Current
boot dmesg retains the already-known unclean FAT-unmount warning, not a
demonstrated previous-run cause.

## Evidence and next gate

Raw host artifacts, including unsuccessful attempts, are retained:

- `artifacts/move_compatibility_20260930/before.*`: failed exec-out request.
- `artifacts/move_compatibility_20260930_shell/before.*`: rejected `shell -T`.
- `artifacts/move_compatibility_20260930_pty/`: paired probes, bounded old-log
  prefix, exit-status and syntax-control outputs, `report.json`.
- `artifacts/move_pty_bytes_20260930/`: exact control bytes, final stock/hash
  probe and `report.json`.

Two initial host harness attempts stopped after the rejected transport and
missing metadata marker. They did not reach any launcher check or log read.
Those failed outputs were preserved and each subsequent deliberate capability
check used a fresh host directory. This was not a live collector retry.

Next separately authorized work is a transport/metadata redesign for this
legacy environment, with explicit completion/status evidence and a binary
safe bounded stream (for example, reviewed ASCII encoding). Preserve source
identity gates; do not silently drop missing stat checks. Neither ordinary
PTY shell nor unbounded pull of a growing file is a validated replacement.
Do not resume accumulating `/tmp` copies. No firmware fix, collector behavior
change, commit or push was made by this compatibility check.

Local regression suite rerun after the check: all 106 tests passed;
`git diff --check` passed. Those mock/host tests do not remove the observed
device compatibility failures.
