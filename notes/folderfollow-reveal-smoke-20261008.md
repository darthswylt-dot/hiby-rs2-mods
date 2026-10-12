# First reveal bridge loader/timer/recovery smoke (2026-10-08)

The user explicitly authorized installation and one short test after
[launch preparation](folderfollow-reveal-launch-preparation.md).
**One diagnostic run completed and stock recovery was verified.** The ELF
loaded and the timer exported a valid status stream. There were no captured
events, so the hot hooks and active autoscroll are not validated by this run.
No second run, rearm, firmware change, commit or push was performed.

## Installation and lifecycle

Fresh preinstallation checks and a second verified launcher backup are in
`artifacts/reveal_bridge_preinstall_20261008/`. Stock PID 116/start 353 ran in
boot `29694ad6-f042-4245-8213-ecc0d3329140`; both flags and the new candidate
target were absent. Battery reported 100%/Full/Good and USB power online.

The candidate and launcher were transferred to previously absent staging
paths, checked for exact remote size/hash and shell syntax, then renamed
on their respective filesystems. Installed identities:

- `/data/hiby_player_reveal_bridge_7cc98a67`: 7,146,848 bytes, SHA-256
  `7cc98a67a32dabce3b4d22b50b8dc847f5462d99d70d0ee04254a0ec272439a9`.
- `/ui_data/player`: 5,769 bytes, SHA-256
  `850691851dbf5cabbd244bae222e958e70885386e35ac6d425bd35f35342e32b`.
- Preserved old launcher: 6,535 bytes, SHA-256
  `1cdfed5423da735895993ae18755526cf0395b2c88ad82c138d29ba803f24f6e`,
  at `artifacts/reveal_bridge_preinstall_20261008/installed_launcher.bin`.

The original `/usr/bin/hiby_player` and `/usr/bin/hiby_player.sh` were not
modified; the old MOVE candidate was not overwritten. After another identity
check, only `RS2_REVEAL_BRIDGE_ONCE` was created and synced, followed by one
boot-path reboot. Neither the candidate nor launcher was manually executed
over stock. No host signal was sent to a player process.

Test boot: `0753d7d3-2b0f-4490-895b-15cf7daeb675`.
Launcher PID 108/start 414; child PID 143/start 720, parent 142. Preparation
was recorded at uptime 7.19, with child creation just afterward. The watchdog
was configured for 45 seconds plus 5/5-second grace periods. No exact stop
timestamp was retained; these are configured intervals, not a measured
precise run duration.

## Loader and timer evidence

At uptime 18.14, the live observation confirmed the candidate hash through
`/proc/143/exe`, both flags absent, and FD9 pointing to:

```text
/mnt/sd_0/rs2_reveal_bridge_evidence/run_20261008T161713_108_0/bridge.bin
```

That filename uses the device clock, not a synchronized host timestamp.
Observed mappings:

```text
00a6c000-00ade000 rw-p 0065c000 ... candidate
00ade000-00c69000 rw-p 00000000 ... anonymous extended BSS
00c70000-00c71000 r-xp 006d0000 ... candidate
00c71000-012b0000 rw-p 00000000 ... [heap]
```

This confirms target-loader acceptance of the new RX segment, private BSS
coverage and a non-overlapping heap in this boot. The timer trace also proves
execution of the new code, not merely mapping. RSS was 15,256 KiB, MemFree
2,308 KiB and Cached 11,836 KiB. These sparse observations are not peak memory,
timing bounds or evidence of long-running stability.

## Stop and stock recovery

The supervisor retained the complete phase sequence through `wait_returned`
with child PID 143. `child.exit` reports raw wait status **255**. The player
stdout explicitly contains `HiBy Player crashed by signal SIGTERM`, followed
by address `0x716c8c`. This agrees with the intended watchdog TERM stop; the
stock handler's word "crashed" does not by itself indicate a spontaneous
patch crash. Do not infer a signal from 255 alone or relabel it exit 0.

`recovery.txt` has `supervisor_status=0` and `reboot_requested=1`. Actual
recovery was independently observed:

- New boot `c057dbc2-0cd2-4616-a6b0-5267f5862f92`.
- Stock PID 120/start 367, parent 104, live executable SHA-256
  `0fedb30f91937eafb5baaf3c75422cdbde04a62fe8bac8eca3c7a88bb761da0e`.
- No diagnostic child and both one-shot flags absent.

The same recovery identity was rechecked around log collection and afterward.
The new launcher/candidate **remain installed but unarmed**. The old MOVE
candidate still hashes to
`15cf4457e829692a52482c0b64a8b478f426f014b7cb31099ed6325a496c3f07`.

## Closed evidence and strict decode

Evidence root: `artifacts/reveal_bridge_run_20261008/`, including raw bounded
probes, installation/arm records, live/recovery snapshots, closed manifests
and `collection_verified.json`. `closed/` contains all **9 files, 15,391
bytes**. Every remote/local size and SHA-256 matched, and the remote manifest
was unchanged afterward. There were no device-side log copies or growing-file
pulls. The one-off host control script is retained with the evidence.

`bridge.bin`: **9,344 bytes**, SHA-256
`947937251cdf94b620157b4112e71f712bf1832d71592773d02a4e79bf8d19a8`.

`decoded_report.json` records `accepted_prefix=true`, no errors and exactly
**292 RBST statuses**. Each is version 1/capacity 1,024, reserved=drained=0,
with zero overflow/contention/I/O flags. There are **zero RBRG events**, zero
producer windows and zero playback pairs.

This establishes timer/FD9 export and an intact closed stream, **not** correct
execution of Files/playback/touch/reset/close/refresh hooks. A valid empty-
event stream is not a positive event test. The user was asked not to interact;
stdout shows main activity and USB-DAC transitions, without an observed
Files/track test. No list movement, volume or autoscroll result is claimed.

`supervisor.errors` and `wait.errors` are empty. `player.stderr` contains
145 bytes: udhcpc address-family failure, invalid mixer control, missing
`/etc/init.d/bt_done` and an invalid device. Without a corresponding stock
baseline, these are not established new regressions or harmless warnings.
No test-boot kernel log was retained; this is not a kernel/OOM audit.

## Result and next boundary

The narrow loader/timer/recovery smoke passed; independent local review
agreed with this interpretation. Binary and launcher remained the pinned
versions previously covered by **449 passing tests**. The run changed no
firmware-building or policy code.

Next, if separately authorized, is one bounded interactive capture exercising
Files fill, a playback transition and touch. No automatic rearm. The old
preinstallation checker intentionally requires the old launcher and absent
bridge candidate; future checks must explicitly gate on the now-installed
new identities and current stock boot/PID rather than weaken those checks.

Active autoscroll still needs retained ownership/generations, coherent
publication and cancellation as described in [the bridge note](folderfollow-reveal-bridge.md).
One successful recovery does not guarantee future recovery under kernel,
I/O, reboot-command or power failure.
