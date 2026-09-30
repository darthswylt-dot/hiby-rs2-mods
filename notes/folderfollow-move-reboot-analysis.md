# MOVE v2 spontaneous reboot: local investigation

2026-09-30. Resumed after the user's explicit `continue` command. Local
analysis only: no ADB connection, device mutation, new firmware build,
installation, rearming, commit or push. The last verified device state is
stock after the interrupted MOVE run; it was not queried again here.

## Main finding

The cause is still **unproven**. There is a substantial collection-side
memory-pressure candidate that the first audit missed: the checkpoint
commands created distinct files in `/tmp`, which the recorded mount table
identifies as tmpfs. They were not removed by this agent during the run.
If all five completed copies were retained, their file contents total
**21,543,680 bytes (20.545654 MiB)**, excluding filesystem metadata and other
memory use. The last copy alone adds 7,973,184 bytes. That copy completed
immediately before the failed transfer and discovery of the reboot.

This is not a measurement of physical RAM, resident pages, free memory or
an OOM kill. No pre-copy `/proc/meminfo`, player RSS, kernel OOM message or
child exit status was saved. Coincidence does not establish causation.
Nevertheless the capture procedure itself must be changed before another
run; passing firmware tests does not make RAM-backed accumulating copies safe.

The one-shot launcher also has a definite observability gap: after
`"$PATCH"` returns, it closes FD9, syncs and reboots without retaining `$?`
or stderr. Thus an ordinary exit, a fault or a memory-pressure kill followed
by launcher recovery cannot be distinguished from the surviving MOVE log.
A kernel/hardware reset could bypass the launcher entirely.

## Reproducible capture checks

`scripts/diagnose_move_diag_reboot.py` is a read-only, hash-gated report for
the five local reference files. All checkpoints are exact **byte prefixes**
of the recovered run, not merely similar decoded records.

| Checkpoint | Bytes | Snapshots/status pairs | Exported events |
| --- | ---: | ---: | ---: |
| Startup | 623,328 | 453 | 0 |
| Roots | 2,513,056 | 1,826 | 5 |
| Slayer entry | 4,429,984 | 3,218 | 21 |
| Slayer Next | 6,004,128 | 4,362 | 21 |
| Offscreen, recovered after reboot | 7,973,184 | 5,793 | 21 |

Final counters are reserved=drained=21 with no exported loss flags. There
are three setter transactions and 18 refresh-input events. The last exported
event is associated with snapshot tick 2,656; the last snapshot is tick
5,793, 401.216096573 seconds after that associated snapshot. Tick association
is not an event timestamp, and settled exported counters do not exclude an
unexported operation or subsequent failure.

The last 468 snapshots have matching cue brackets 4/4 and y=0 over
59.744035839 seconds. The final ten intervals remain approximately 128 ms.
The largest gap, 5.217277215 seconds, is between ticks 47 and 48 at startup,
not near the end. There is no exported late delay ramp, but a stall/reset
after the last record is not excluded. These observations support stationary
viewport behavior within the captured scope; a positive nonzero manual
setter control remains missing.

Reproduction:

```text
python scripts/diagnose_move_diag_reboot.py artifacts
python -m unittest discover -s scripts -p "test*.py"
```

All **62** tests pass: the previous 59 plus three report checks. Firmware,
launcher and their artifact hashes are unchanged. The new tests verify the
recorded evidence, timestamp handling and hash rejection, not device memory
pressure or crash behavior.

## Independent code audit

Two independent local reviews checked the hot probes and the snapshot/drain
and ELF layout. No demonstrated ABI, return-address, stack-overlap or
control-transfer error was found.

- The original setter uses four register arguments, not incoming stack
  arguments. The wrapper's saved record pointer is outside the four-argument
  outgoing area, scratch registers are preserved and original caller RA is
  restored. The source function runs once.
- The refresher's original frame is `0xED8`; caller is saved at `+0xED4`,
  matching the probe. Null guards precede the hook, and displaced reads are
  replayed once.
- Snapshot frame is `0x600`; the drain adds `0x50`. Its status bytes do not
  overlap saved registers. There is no obvious WRITE argument/return defect.
- Source RW load end is `0xBD3CA4`; MOVE end is `0xBEC040`. The memory-size
  increase is 99,228 bytes including alignment, with a 98,368-byte buffer.
  LOAD ranges do not overlap. These static checks do not prove loader/heap
  safety on every runtime path.

Remaining firmware-side risks include object lifetime after the original
setter returns, non-atomic current-view snapshot dereferences, concurrency,
real stack depth and synchronous card writes. External operations and
threading are mocked in tests. The long interval since the last exported
hot-probe event does not rule out deferred corruption or a later unexported
probe. Neither a firmware bug nor memory pressure is cleared or proven.

## Requirements before any new device test

Keep MOVE v2 on hold. Do not silently rearm it or replace it with a functional
autoscroll candidate. Preparing a capture mechanism locally and installing
or starting it are separate decisions.

1. Preserve a unique persistent run directory and refuse reuse. Record
   source/candidate/launcher hashes, boot uptime, free card space and the
   initial memory/process/stack-limit state. Verify FD9 and live PID/hash.
2. Retain child PID, stdout/stderr and the shell wait result **before** the
   existing recovery reboot. Store the raw numeric result; do not turn
   `128+signal` into proof of a particular signal without shell validation.
3. Save kernel messages and memory/process state at startup, before each
   checkpoint, and after child termination if the supervisor survives.
   Use only supported device features; do not assume `dmesg -w`, pstore or
   core dumps exist. An explicit termination marker distinguishes a
   completed supervisor path from incomplete evidence, not all reset causes.
4. Stop making accumulating tmpfs copies. Prefer bounded direct-to-host
   transfer or at most one card-backed checkpoint with a checked free-space
   budget, verified local copy, and exact-path cleanup afterwards. Card-backed
   copying still has page-cache and I/O cost; no zero-memory/zero-latency claim.
   Never truncate the active FD9 log. Preserve any incomplete tail separately
   rather than silently accepting it as a complete capture.
5. Record `/proc/meminfo`, player status/RSS and checkpoint size immediately
   before and after capture. Establish memory headroom; do not infer it from
   battery level, free card space or the small BSS buffer.
6. Validate the revised supervisor locally with mocked normal exit, nonzero
   exit and signal, logging failure, existing-run refusal and the stock
   fallback. Do not claim it captures SIGKILL of the supervisor, power loss or
   a kernel reset. Preserve one-shot recovery without automatic retries.
7. Only after review and separate installation/start authorization, reproduce
   in short stages, first baseline observation and then the minimal diagnostic
   path. Stop on any regression and preserve evidence. Manual scrolling and
   Sleep are pending, not passed.

No evidence-retention launcher or replacement binary was created during the
initial investigation above. After the user's next continuation, a separate
[local evidence-launcher draft](folderfollow-move-evidence-launcher.md) and 21
isolated shell tests were prepared. It is not installed or device-validated;
the executable is unchanged. A later user-approved local step prepared the
[bounded direct-to-host collector](folderfollow-move-checkpoint-collector.md),
with pre/post memory and source checks and preserved raw/partial evidence.
These components remain untested on the device and are not an already
validated hardware procedure.
