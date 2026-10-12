# Bridge installation recheck and first interactive events (2026-10-12)

## Required user coordination

For every interactive run: give the instructions, **end the turn**, and wait
for an explicit fresh user readiness confirmation before arming/rebooting.
After the authorized launch, stop and wait for the user's report. Do not
interpret positioning the player in a folder as readiness for a timed run.
The user explicitly corrected the premature first October 12 launch.
No automatic repeat, timeout extension, or rearm is authorized.

## Installation verification and premature run

Read-only installed-state checks passed in
`artifacts/reveal_bridge_interactive_20261012/verification_03/`.
The candidate `7cc98a67...` and launcher `85069185...` have the exact pinned
hashes/sizes from the October 8 preparation. Both are regular executable
files; device shell syntax checking and original stock/wrapper/old MOVE
candidate hashes passed. A fresh hash-verified launcher backup was saved.
The player/card mount namespaces agree, the card is rw with 5,924,968 KiB
available, USB is online, and battery was 89%/charging. Both flags were absent.
No reinstallation or firmware source edit was necessary.

The initial host verification attempts remain preserved: one parser call
incorrectly supplied text instead of bytes; another reused a pre-install
16-MiB `/data` staging requirement. The installed-state verifier explicitly
checks launch prerequisites instead; `/data` has 14,668 KiB free and no new
candidate is staged there. The original pre-install parser is unchanged.

The premature run `run_20261012T095643_108_0` exported 292 intact status
records and zero events. The user confirmed no requested actions occurred
before recovery. This was **not an interactive test**. Its fresh FD9/run/boot
evidence is preserved under `artifacts/reveal_bridge_interactive_20261012/`.
The identical status-only trace hash to October 8 does not imply file reuse:
those status records contain no timestamp/run ID and have identical counters.

## Run after explicit readiness confirmation

After instructions were delivered and the user replied `готов`, a separate
one-shot run was authorized. Fresh prelaunch boot/PID/start and guards were
used, with a new exclusive host evidence directory:
`artifacts/reveal_bridge_interactive_20261012_ready/`.
The launcher/candidate and 45-second recovery schedule were unchanged.
The assistant stopped after requesting the launch, as agreed; there is no
live-process snapshot for this run. The closed supervisor and trace provide
the run evidence instead.

Remote run: `/mnt/sd_0/rs2_reveal_bridge_evidence/run_20261012T100413_108_0`.
Supervisor test boot: `78bef7b4-9f94-4af5-a071-93751591b59e`;
launcher PID 108/start 412, diagnostic child PID 143/start 717.
All preparation/launch/child/wait phases are present. Raw wait status is 255
and stdout reports SIGTERM, consistent with the configured watchdog stop,
not proof of a spontaneous crash. Recovery reports status 0 and reboot
requested. Exact duration was not measured from the log record count.

After the user reported insufficient time for scrolling/volume, read-only
checks verified a distinct recovery boot
`2eda0476-9c57-4fae-a509-255a6e1b13c7`, exactly one original stock player
PID 120/start 368, live hash `0fed...`, and both diagnostic flags absent.
Stock FD9 is an ordinary `socket:[594]`, not the diagnostic evidence file.
All installed/stock/old-candidate hashes remain pinned and the test is unarmed.

All nine closed files (98,586 bytes) were collected with matching remote
before/after manifests and local size/SHA checks. `bridge.bin`: 91,760 bytes,
SHA-256 `e30dc30670034c8be55dbabb5c85d85eb80bb60597be1772bdbf716bbc430e17`.
No device write, signal, reboot or rearm occurred during collection.

## Result and limits

Strict decoding accepts the exported prefix with no errors: **139 events**
and 296 statuses. Final status follows the events, reserved=drained=139,
overflow/contention-loss/I/O-error all zero.

- Five completed observed Files producer windows, including navigation to
  Show No Mercy and 13 CUE entries (indices 0..12) within its FLAC file.
- Three accepted playback-copy pairs for the same FLAC and CUE indices
  **0, 1, 2**, consistent with selecting track 1 and pressing Next twice.
- 82 touch observations, 13 refresh observations, one view-close observation;
  no list-reset observation.

These are capture observations, not retained-object/generation guarantees,
atomic current-playback identities, audible playback proof, or proof of all
folder completion/invalidation cases. The touch observations include
navigation and do **not** establish a manual scrolling test.
All 13 refresh observations have offset 0, and no refresh was observed after
the last two playback-copy pairs. Highlight movement for CUE 1/2 is therefore
not confirmed by this trace; it still needs a user observation. Independent
local re-decoding matched the report and all nine local file hashes matched
the collection manifest.

The user's explicit result: **did not have time to scroll or check volume**.
Those two checks remain open; do not repeat the already observed Next steps
in a short follow-up focused on the remaining checks. Autoscroll is still
disabled and has not been validated. The 145-byte stderr contains the known
device warnings without a matched stock baseline; no broad stability/OOM
claim is made. The firmware/launcher source was not changed, the prior
449-test source baseline was not rerun, and no commit/push was performed.

## Follow-up: manual scrolling, highlight and volume confirmed

After a separate short instruction and another explicit `готов`, one more
unchanged 45-second run was armed for manual scrolling and volume, without
Next. The assistant stopped after requesting reboot and did not collect or
poll until the user reported completion. The user then explicitly confirmed
that down/up scrolling worked, highlight remained, and volume changed normally.
This closes those functional checks for this short diagnostic run; it is not
a test of highlight following Next or of active autoscroll.

Evidence: `artifacts/reveal_bridge_scroll_volume_20261012/`.
Remote run: `/mnt/sd_0/rs2_reveal_bridge_evidence/run_20261012T101148_108_0`.
Supervisor test boot: `4f0fac4e-de91-4d64-a3a8-d9400385dbd4`,
launcher PID 108/start 416, diagnostic child PID 143/start 723.
All supervisor phases completed, raw wait status 255, stdout reports SIGTERM,
and recovery reports status 0/reboot requested. These are consistent with
the configured stop; there was no live snapshot because of the agreed pause.

Nine closed files (175,024 bytes) have matching remote pre/post manifests and
local size/SHA checks. `bridge.bin` is 168,384 bytes, SHA-256
`3c5dc8770226b7e6e6eb82479a84202f0e1a4892c6f8a74d30f6b7df7ef32a19`.
Decode accepts **268 events and 304 statuses**, no errors/unmatched producer
events, with final reserved=drained=268 and all loss/error flags zero.
There are five completed producer windows (including the same 13 CUE entries),
one accepted playback-copy pair for CUE 0, 206 touch observations, 22 refresh
observations, one view-close, and no list-reset observation.

Refresh offsets now change after track selection: among the observations are
0 -> 270 -> 533 -> 328 -> 0 and 0 -> 214 -> 0. This is evidence of observed
list movement during the user's manual scrolling, not an active autoscroll
action. The user's report supplies the visual highlight and volume outcomes;
the capture format does not itself establish visual/audible correctness.

Latest verified recovery: boot `985e1da1-643c-4f86-ab44-1a76edbf537b`,
exactly one original stock player PID 120/start 369/hash `0fed...`, both
diagnostic flags absent, installed candidate/launcher/stock/old MOVE hashes
unchanged. FD9 belongs to stock's `socket:[594]`, not the evidence file.
No device writes occurred during collection. No new run, timer change,
firmware source change, commit or push after the user's report.
Autoscroll remains disabled; the previously documented ownership/generation,
invalidation and coherent playback/reveal gates are not removed by this test.
