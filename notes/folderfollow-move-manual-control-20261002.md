# MOVE manual-scroll positive control

2026-10-02. The user explicitly approved a second short one-shot run, limited
to manual scrolling without a series of Next presses. The user confirmed:
the list moved down/up, and playback was **not started**. The positive
content-y setter control is now observed in Files. No scroll-fix binary was
built or installed in this step.

## Lifecycle and retained evidence

Before arming: original stock PID 119, boot
`b2f2484a-ac4d-4e0f-8916-c760a2e9f64d`, absent flag, installed launcher
`1cdfed54...` and unchanged candidate `15cf4457...`; 5,926,152 KiB free.
The previous run directory was retained. A guarded one-shot flag creation
and reboot used the already installed launcher, with no reinstall or manual
launcher execution.

The new boot was `12c0e046-db0e-4a66-82b5-a64c5bbed8d0`, diagnostic child
PID 142/start ticks 665, live SHA-256 `15cf4457...`, FD9 at:

```text
/mnt/sd_0/rs2_move_evidence/run_20261002T144115_108_0/move.bin
```

The flag was consumed. Host-side `artifacts/move_manual_20261002_live/`
retains a strict identity/mount/memory probe at uptime 76.30; it is metadata,
not a second live binary checkpoint. After the user's completion report,
boot/PID/starttime/hash/FD9/absent flag were rechecked together and only the
child received SIGTERM at uptime 111.14, about **104.49 seconds** after start.

The player stdout records SIGTERM. Supervisor wait returned raw **255** and
retained `supervisor_completed=1` / `reboot_requested=1`. This is controlled
termination, not evidence of a new spontaneous crash. Recovery boot
`118e7aed-5f35-4266-9933-c7f5b175cca3` returned stock PID 115/start ticks 361,
live hash `0fedb30f...`, with the test flag absent. The evidence launcher
remains installed but unarmed, and the candidate is unchanged.

All **21 files, 1,120,370 bytes**, were pulled directly from the closed run
to `artifacts/move_manual_20261002_closed/`. Every file's SHA-256 matches the
device; the manifest/report are in `artifacts/move_manual_20261002_verification/`.
No old logs, firmware or music files were removed, no `/tmp` checkpoints
were made, and no subsequent run was armed.

`move.bin`: **1,045,344 bytes**, SHA-256:

```text
0357a90bf37c37d94bc01473a8f70c0750867c806825cd26fe24155ff9ec8e27
```

Strict decoder: 753 snapshots, 753 statuses, 82 setters, 14 refresh events;
final reserved=drained=96, no loss/overflow/I/O flags, no incomplete tail,
accepted complete stream. Intermediate pending drains are confirmed later;
the final stream, not every individual status, is settled.

## Measured manual path

Of the 82 setters, three are earlier absolute zero-to-zero navigation calls.
The other **79** are relative mode `0x30002`, with nonzero requests and real
movement in every call:

- 78 return addresses `0x4BA67C`, one `0x4BA5FC`.
- Every call satisfies `new_y = old_y + requested_y`; old/new form a
  continuous chain, and all relative deltas sum to zero.
- Event trajectory: **0 → 385 → −28 → 0**. Snapshots independently show
  **0 → 385 → −8 → 0**; the different minima reflect sampling between calls.
- Every setter result is 0 despite real movement, so zero return is not a
  failure or no-movement indicator.

The relative calls span ticks 302–345. Surrounding snapshots identify the
same deep Show No Mercy folder, `vg_listview_explorer`, view `0xF0F134`,
viewport/event object `0x133D660`, pitch 80, viewport height 260, sampled total
folder count 13 (`cache_count` wire field, clarified on 2026-10-05). The
association uses continuous folder/view/context observations, not
an address alone; it remains observational rather than a lifetime proof.

Snapshot tick 302 is at uptime 53.749543465; tick 346, back at zero, is at
59.029566710. These bracket the sampled gesture activity, not exact event
timestamps. Forty-three snapshots (ticks 303–345) have nonzero y; y then
stays zero through tick 753 at 111.125584814 seconds.

Four post-gesture-start refreshes use caller `0x49A200` (timer-20 path):
ticks 308/315/341/347 at y=163/303/41/0. Remaining refreshes belong to folder
navigation. Cue-before/after are 0/0 and playback path is empty in all 753
snapshots. Do not label cue 0 as an actively playing first track in this run.

## Comparison and updated conclusion

| Observation | Earlier Next run | Manual-only control |
| --- | --- | --- |
| Playback | Cue 0→5 in Show No Mercy | Not started |
| Sampled content y | Always 0 | 0→385→−8→0 |
| Nonzero content-y setters | None | 79, all change y |
| Final event accounting | 16/16, no loss | 96/96, no loss |

The [earlier run](folderfollow-move-supervised-run-20261002.md) has no
instrumented setter during its cue progression; its only three setters are
prior absolute zero-to-zero navigation requests. This positive control
demonstrates that the setter can move this Files viewport and that MOVE
records those calls. The comparison supports a **missing reveal request
on the observed Next path**, rather than a rejected nonzero setter request.
It does not prove every scroll path, especially all playback-time behavior,
or identify a safe patch callback by itself.

Important implementation constraint: all 79 relative events have object
flags `0x2`, viewport height 260 and raw content extent 0. Real scrolling
still works and briefly goes negative. Therefore do not rely on this raw
extent or the generic setter to clamp an automatic target safely. The
future target must be based on a validated visible-list row/path/cue match,
with explicit bounds and UI-thread/lifetime rules. Do not equate cue number
or the transient working index with a general row index. Trigger a reveal
on a playback transition, not on every timer tick, so manual browsing is
not continually pulled back.

The next step is local design/build of an auto-reveal change using the
verified route and existing row-mapping evidence. Any new firmware
installation is separate; no further hardware measurement is implied here.
