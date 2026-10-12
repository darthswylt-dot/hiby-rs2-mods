# Reveal bridge: launch preparation, not a live run (2026-10-08)

Follow-up: the user subsequently authorized the
[first loader/timer/recovery smoke](folderfollow-reveal-smoke-20261008.md).
Installation, one diagnostic boot and observed return to stock completed.
The new launcher/candidate now remain installed but unarmed. The preparation
record below describes the preceding state, not the current installation.

The user requested preparation of the diagnostic launch. The new launcher,
its isolated tests and a read-only device preflight are ready. **Nothing was
installed, armed or executed on the player.** The bridge ELF remains capture
only, with the new RX segment's hardware behavior still untested.

## Pinned local files and separate device paths

| Item | Local file / identity | Intended device location |
| --- | --- | --- |
| Capture ELF | `artifacts/hiby_player_1.4_sortfix_fullnav_wake_reveal_bridge_capture_20261008.bin`; 7,146,848 bytes; SHA-256 `7cc98a67a32dabce3b4d22b50b8dc847f5462d99d70d0ee04254a0ec272439a9` | `/data/hiby_player_reveal_bridge_7cc98a67` |
| New launcher | `scripts/rs2_reveal_bridge_launcher.sh`; 5,769 bytes; SHA-256 `850691851dbf5cabbd244bae222e958e70885386e35ac6d425bd35f35342e32b` | Future reviewed replacement of `/ui_data/player` |
| One-shot flag | Not created | `/mnt/sd_0/RS2_REVEAL_BRIDGE_ONCE` |
| New evidence | Not created on device | `/mnt/sd_0/rs2_reveal_bridge_evidence/run_<date>_<launcher-pid>_<suffix>/` |
| Existing launcher's verified backup | `artifacts/reveal_bridge_preflight_20261008/installed_launcher.bin`; 6,535 bytes; SHA-256 `1cdfed5423da735895993ae18755526cf0395b2c88ad82c138d29ba803f24f6e` | Original still installed at `/ui_data/player` |

The old `/data/hiby_player_sortfix`, old one-shot flag name, MOVE launchers
and all old evidence are untouched. The new launcher must not be run manually
over stock, and the new ELF must not replace the old MOVE candidate pathname.

## What the prepared launcher does

The boot-only gate requires parent PID 1 and no process matching any of the
three known stock/MOVE/bridge executable names. Missing `pidof` or an error
other than its normal no-match status refuses without running stock or
consuming the flag. This protects against ordinary manual invocation; it is
not a security boundary against an intentionally orphaned shell.

An unarmed accepted boot runs the stock wrapper without creating evidence.
An armed boot consumes the new flag before preflight or execution and syncs
that change. Failure to remove it falls back without launching the candidate;
the still-present flag would need explicit attention before another attempt.
An old MOVE flag causes refusal of the bridge test and is left untouched.

Admission requires the expected mounted read-write FAT card, at least
65,536 KiB free, a non-symlink executable candidate, and a fresh evidence
directory. The preparation phase opens regular diagnostic/output files and
checks the exact candidate SHA-256 and size before any possible child launch.
Only failures before supervision may fall back directly to stock.

The supervisor disables core dumps, starts one direct child and captures its
PID and `/proc` start token. Only stdout/stderr and FD9 are inherited as
evidence streams; auxiliary handles are closed. FD9 is the new `bridge.bin`,
not a pipe or shared old log. The watchdog starts immediately after the
initial child-token read and before further evidence writes or waiting.

The intended schedule is:

- About 45 seconds after watchdog start: verify parent and child identities,
  then send TERM only to that child.
- Five seconds later: repeat the identity checks and send KILL only if the
  same candidate still exists.
- Five more seconds later: request a recovery reboot if the same launcher
  still exists, including if it is stalled after the child has exited.

The timer is device-side and does not require an active host connection.
It performs no SD writes or sync before its recovery actions. Identity checks
compare PID/start token/live executable hash, and recheck start after hashing.
An unavailable child identity never authorizes a guessed-PID signal. Parent
exit or identity change revokes the watchdog; there is no watchdog-kill step.

Normally `wait` returns first; the launcher retains its raw result, closes
FD9, records recovery intent, syncs and requests one reboot. After any
possible launch it **never directly starts stock beside an uncertain child**.
The consumed flag makes the next accepted boot take the stock path. There
is no automatic test retry or rearm. Reboot command failure is reported and
needs manual recovery rather than a second player start.

## Read-only device preflight completed

`scripts/check_reveal_bridge_preflight.py` first verified the pinned local ELF
and launcher, then used bounded legacy-compatible ASCII ADB transport. Full
evidence and JSON report are in `artifacts/reveal_bridge_preflight_20261008/`.
The report has `readonly_preflight_passed=true`, `stock_state_preserved=true`,
`launcher_executed=false`, `device_files_written=false` and
`hardware_validated=false`.

Before and after observations agree:

- Device serial: `HiBy RS2`.
- Boot: `29694ad6-f042-4245-8213-ecc0d3329140`.
- Stock PID 116, start ticks 353, parent PID 105; live executable and on-disk
  stock SHA-256 `0fedb30f91937eafb5baaf3c75422cdbde04a62fe8bac8eca3c7a88bb761da0e`.
- Installed launcher: `1cdfed...`, inode 2640, 6,535 bytes. Its host backup
  matches byte count and hash through the bounded binary-safe transport.
- Existing MOVE candidate: `15cf4457e829692a52482c0b64a8b478f426f014b7cb31099ed6325a496c3f07`.
- Stock wrapper: `fa5a7a3f10f858a6c4909e4424d0b3cec356986edaccab7d1e2ef5b7eb76cbc8`.
- Both one-shot flags absent; new bridge candidate pathname absent.

The card and `/data` mount identities matched the stock process's namespace,
with read-write mount/superblock flags. Observed free space was 5,925,016 KiB
on the card and 19,236 KiB on `/data`; stack limit was 4,096 KiB. All queried
commands were present. These are observations, not guarantees of future
writes or sufficient peak memory.

The complete launcher was reconstructed in a temporary shell variable,
hash/length checked and passed to **`sh -n` only**, not sourced or executed.
The command was 3,381 bytes, within the legacy 4,000-byte limit. Positive
non-execution and negative syntax controls passed. Wait-status preservation,
failed-open isolation and descriptor inheritance/closure controls passed.
Only the exact pinned read-only `field/start` helper definitions were
executed separately, returning start 353 and parent 105 as expected.

Additional read-only shell checks confirmed stock wrapper 105 has parent 1,
multi-name `pidof` finds only stock 116, and `ulimit -c 0` works in an isolated
shell. No signal was sent to any player, and no sync/reboot was requested.

MemTotal was 58,308 KiB; stock RSS was 18,272 KiB. Before/after MemFree was
940/892 KiB and Cached 15,720/16,580 KiB. These snapshots do not measure peak
headroom for the larger ELF/BSS or establish an OOM safety margin. Read-only
hashing and shell probes also consume CPU and page-cache memory.

This command is a **pre-installation** check: it requires the old installed
launcher, absent new candidate path, and `/data` space for staging. It is not
an installed-state verifier and will correctly reject the later installed
bridge. Do not weaken those gates to reuse it after deployment; the
[October 12 installed-state recheck](folderfollow-reveal-interactive-20261012.md)
uses the new installed identities without staging or device writes.

To repeat the pre-installation check, determine the **current** stock PID first and use a new
host output directory. Do not reuse this report as authorization or as a
fresh identity check after a reconnect/reboot:

```powershell
python -X utf8 scripts/check_reveal_bridge_preflight.py --adb C:\platform-tools\adb.exe --serial 'HiBy RS2' --pid 116 --launcher scripts/rs2_reveal_bridge_launcher.sh --source artifacts/import-20261001/hiby_player_02fd.bin --candidate artifacts/hiby_player_1.4_sortfix_fullnav_wake_reveal_bridge_capture_20261008.bin --output artifacts/reveal_bridge_preflight_20261008_repeat01
```

## Local validation

Final full suite: **449 tests pass, no skips**, including 24 new isolated
launcher tests and 31 new preflight tests. All **85 Python files under
`scripts/` compile**; whitespace checks pass. Launcher fixtures mock signals,
reboot, firmware and device paths. They exercise early exit, deadline TERM,
ignored TERM/KILL, missing/reused identities, invalid size/hash, old arm,
manual/duplicate invocation, refused evidence opens, wait status and reboot
failure. The preflight tests cover exact metadata, mount/space checks,
local refusals before device access, backup integrity, syntax controls and
retained after-snapshots on failure. These are not live recovery tests.

## Next authorized execution procedure

Preparation is complete; installing/arming/rebooting for the test is a
separate action. Once the user authorizes the run:

1. Repeat fresh stock/boot/flags/hash/space checks and preserve a fresh
   verified launcher backup. Ensure adequate device power and that the user
   can perform a manual power-cycle if software recovery fails.
2. Stage the exact ELF and launcher into new, previously absent temporary
   paths on their respective filesystems. Verify on-device size/hash and
   launcher syntax; apply executable permissions. Do not overwrite an
   unexpected existing staging or final candidate file.
3. Rename the candidate to its separate final path and replace only the
   hash-verified old `/ui_data/player` with the checked launcher using a
   same-filesystem rename. Preserve the old verified launcher on the host.
4. Recheck the installed identities, current stock boot and both absent
   flags. Create only the new one-shot flag, sync, and request the boot-path
   reboot. Do not execute the candidate/launcher manually over stock.
5. Observe a single short **loader/capture smoke test**, initially without
   user interaction. Confirm the new process, executable hash, consumed flag
   and exact private FD9 destination if time permits. The 45-second deadline
   is not extended while probing or waiting for the user. No automatic retry
   if ADB disappears or the loader exits.
6. After recovery, require a new boot identity, original stock executable,
   absent flags and no diagnostic child. Preserve the closed run directly
   to the host with remote/local hash and size checks before decoding. Do
   not make growing-log copies in `/tmp`, reinterpret missing exit evidence
   as success, or silently trim a torn trace into an accepted run.

The first run is not yet a request to traverse an album or test autoscroll.
Only after loader/recovery/trace evidence passes should a separate interactive
capture be considered. The strict bridge decoder may still reject an initial
run for queue loss, an unconfirmed tail or incomplete windows; retain that
evidence rather than automatically repeating the test.

## Limits that remain explicit

This is a best-effort shell watchdog, **not a guaranteed 45/55-second bound
or guaranteed stock recovery**. Fork/token-read/scheduling/hash/proc costs
add latency. Kernel stalls, uninterruptible I/O, power loss, killing the
launcher/watchdog, or a failed reboot can defeat software recovery. The
PID/start/hash check and subsequent signal are not atomic; prelaunch hash
validation and pathname exec likewise have a check/use window. No concurrent
candidate/launcher replacement is permitted during a run.

Core dumps are disabled, but stdout/stderr are not size-capped. Initial free
space is admission only; trace/status output and page-cache cost remain real.
The new armed path deliberately does not perform the old wrapper's batd
kill/restart sequence or create a new battery log. It is suitable only for
the proposed short loader smoke test, not a claim of equivalent power
management or long-running player operation.

The added RX segment, heap placement, live timing and stock-object lifetimes
still require hardware evidence. All existing active-autoscroll integration
gates remain in [the bridge note](folderfollow-reveal-bridge.md).
