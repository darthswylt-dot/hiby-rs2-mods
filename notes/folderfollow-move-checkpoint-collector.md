# MOVE checkpoint collector: direct device-to-host draft

Update 2026-10-01: the separate [legacy-safe protocol](folderfollow-move-legacy-collector.md)
reuses this script's capture/record-validation logic and passed stock-only
byte controls. The default native exec-out/stat protocol described below
still fails on RS2; no live MOVE capture has been validated.

Current result (2026-09-30): **read-only device compatibility FAILED**.
RS2 rejects exec-out and non-PTY shell, has no stat applet, and its legacy
PTY shell alters newline bytes and loses remote exit status. This draft is
not ready for live use. See [device observations and preserved state](folderfollow-move-device-compatibility.md).

2026-09-30. Prepared locally following the user's `go ahead` command.
**NOT DEVICE-VALIDATED; NO ADB CONNECTION OR TEST START IN THIS STEP.**
Firmware and both launcher files are unchanged.

Script: `scripts/capture_move_checkpoint.py`.

## Purpose and scope

This replaces the old collection procedure that left growing copies in the
player's `/tmp`/tmpfs. It reads a bounded prefix of the live MOVE log directly
through `adb exec-out` into a **new host directory**. It creates no device
files and issues no `cp`, `sync`, removal, signal, reboot or rearm command.
It does not change the active FD9 log. Device reads still require page cache,
I/O and small ADB/shell/head/probe processes; this is not a zero-RAM-cost claim.

The collector is restricted to one exact run directory under
`/mnt/sd_0/rs2_move_evidence/` produced by the
[evidence launcher](folderfollow-move-evidence-launcher.md). Serial, PID and
remote path are validated; no arbitrary remote shell command/path is accepted.
No local shell or PowerShell text pipeline processes the binary stream.

## Collection and success conditions

Before reading, it saves memory/process metadata and verifies:

- boot ID, uptime and PID/starttime (including a bracketed stat read);
- live executable SHA-256 equals MOVE `15cf4457...`;
- FD9 points to the requested `move.bin`;
- pathname and FD9 have matching device/inode identities and nondecreasing
  sizes within the probe;
- required memory and player-status evidence is present.

The pathname size from that probe freezes the read length. Empty files or
files exceeding the host budget are refused. Default budget is 32 MiB;
the configurable hard maximum is 128 MiB. `head -c N` reads exactly that
prefix while the original writer can continue appending. Its device stderr
is redirected away from the binary channel; local ADB stderr is retained.
Unsupported head/stat/exec-out behavior results in failure, not a fallback
copy or a retry. BusyBox support remains a preinstallation verification gate.

Both stdout and stderr are bounded **during** host-side reads. Metadata and
stderr each have a 256 KiB budget; raw stdout has the frozen byte budget.
One extra byte detects overflow. Excess output stops the collector's own
ADB client and is marked failed; the saved file is then a capped partial
artifact, not every excess byte. The player PID is never signaled.

After the transfer attempt, the collector tries to save another probe even
if transfer raised or timed out. Parse failure in that probe does not prevent
analysis of already received bytes. Success requires matching pre/post boot,
process starttime, executable, FD9 and inode identities; uptime/size may grow.
These checks do not make view snapshots or the source capture atomic, and
do not rule out a truncate/rewrite restored between probes.

The unchanged strict MOVE decoder validates complete records. An incomplete
last record is retained separately; invalid magic/version/complete records
are rejected without resynchronization. **All** valid complete records are
kept, including an unsettled trailing MOVE event: the collector never trims
back to an older MSTS to manufacture an accepted prefix.

`capture_accepted=true` requires the exact byte count, successful bounded
transport, verified source coherence, no partial record and an accepted
loss-accounted decoded prefix. Otherwise CLI returns nonzero and evidence
is retained where host storage permits. There is no automatic retry.

## Host output

| File | Evidence |
| --- | --- |
| `before.txt`, `after.txt` and corresponding `.stderr` | Raw pre/post probe output, including unavailable/failed portions |
| `raw.bin`, `raw.stderr` | Original received byte stream up to its bound and local ADB diagnostics |
| `complete_prefix.bin` | Strictly validated whole-record bytes, if framing was valid |
| `incomplete_tail.bin` | Incomplete last record only, when present |
| `report.json` | Transport results, sizes/hash, identities, decoder summary, errors and acceptance |

An existing output directory is refused **before** any device call; nothing
in it is overwritten. The host must initially have room for raw plus prefix
and metadata (twice the configured byte budget plus 4 MiB). Other activity
can still exhaust storage after this check; durable evidence cannot be
guaranteed on a failing/full host filesystem.

The raw host SHA-256 is not an independent device-prefix hash. Capture of a
growing source cannot be compared to a later whole-file device hash. Do not
claim such a comparison was done.

## Local verification

Twenty-three new tests use fake device replies and exclusively local
subprocesses. They cover exact binary bytes (including NUL/CR/LF/non-UTF8),
bounded stdout/stderr, own-client timeout/partial output, exact non-block
head length, probe syntax, source growth and identity changes, short/overlong
or failed transfers, transport exceptions, malformed after-probes, incomplete
headers/payloads, corruption, reported losses, unsettled last records,
argument injection and existing-output refusal.

Independent review prompted the separated post-evidence/byte-analysis stages
and bounded metadata channels. Final review found no concrete must-fix in
the stated local-only scope. All **106** repository tests pass, including
these 23; no real ADB, RS2 executable, or device mutation is exercised.

```text
python -m unittest discover -s scripts -p test_move_checkpoint_capture.py -v
python -m unittest discover -s scripts -p "test*.py"
```

Per-command timeout defaults to 30 seconds (allowed 1..60); process/reader
cleanup may add bounded waits. A host I/O hang or a descendant retaining an
open pipe can defeat ordinary reader cleanup. Such a case is an error with
incomplete evidence, not a universal hard-deadline guarantee. Tests cover
ordinary own-child timeout, not every host/ADB daemon failure.

## Future use, not executed

Before any live use, verify supported read-only device commands and preserve
the current files/logs. Installation/arming of the evidence launcher and a
short MOVE run remain separately authorized actions. Use the **observed**
run directory and verified live PID, never the illustrative values below:

```text
python scripts/capture_move_checkpoint.py --adb E:\platform-tools\adb.exe --serial "HiBy RS2" --pid 123 --run /mnt/sd_0/rs2_move_evidence/run_20260930T120000_108_0 --output artifacts/move_checkpoint_NEW
```

If capture is incomplete or unsettled, keep its failed report/raw/tail;
only a deliberate later checkpoint uses a different new host directory.
No absence conclusion is valid merely because an earlier complete prefix
was accepted. Do not resume the old accumulating `/tmp` copy procedure.

This collector targets a **live** verified MOVE process. After a reboot/exit,
it deliberately refuses to call stock a coherent MOVE source. Recover the
closed persistent run directory with a separate read-only direct pull and
verify its files, rather than rearming MOVE or copying it into tmpfs. That
closed-run salvage workflow is not an implicit launch or install request.
