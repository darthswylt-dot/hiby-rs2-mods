# Safe playback-commit timing diagnostic

This passive diagnostic measures the two direct property-24 commits recovered
in [playback-media-commit-static-trace.md](playback-media-commit-static-trace.md).
It is built on the sorting + full-navigation + wake baseline.

## Artifact

```text
artifacts/hiby_player_1.4_sortfix_fullnav_wake_playback_commit_diag_test
size:    7,133,528 bytes
SHA-256: d78e7805cf630af004f43317be8ee9ce3fcbcc78eb6fd42a0a7d18179653629e
```

The builder accepts the golden `c825a72e...` baseline or recovered
`02fd1dd1...`; the latter is first normalized and required to reproduce the
golden full-file hash.  It redirects only the original `memcpy` calls at
`0x42CBDC` and `0x42CD5C` to a `0x2E8`-byte wrapper in the already-audited
empty cave at `0x988040`.

## Safety boundary

The wrapper makes exactly five calls:

- two `memset` calls for independent before/after records;
- two writes to inherited file descriptor 9;
- the original `memcpy(0xADD468, selected_item, 0xA88)` once.

It performs no Folder View, navigation, media-database, property-setter, or
source-finalizer call.  It never calls the state-consuming `0x4E4B80` helper.
The selected item and destination paths are safe because the original copy is
already about to consume those same objects.  The source object is null
checked; its inline `+0x28` path is copied with a fixed 260-code-unit loop and
`+0x230` is recorded only as a scalar.

Each commit appends a durable `0x680`-byte before record, performs the original
copy, then appends an after record.  If execution stops during the hook, the
first record remains.  The binary verifier checks exact deterministic output,
the two redirections, the complete changed-byte scope, all call targets,
branch delay slots, bounded path loops, cave bounds, and return sequence.

Build and verify:

```powershell
python .\scripts\build_playback_commit_diag.py `
  E:\platform-tools\hiby_player_02fd.bin `
  .\artifacts\hiby_player_1.4_sortfix_fullnav_wake_playback_commit_diag_test

python .\scripts\verify_playback_commit_diag.py `
  E:\platform-tools\hiby_player_02fd.bin `
  .\artifacts\hiby_player_1.4_sortfix_fullnav_wake_playback_commit_diag_test
```

## Record format and expected evidence

`PCMT` records contain the phase, commit site, caller, copy arguments, selected
and global media IDs, source pointer/scalars, and three bounded UTF-16 paths:
selected item, global property 24, and source object.  Decode a pulled log with:

```powershell
python .\scripts\decode_playback_commit_diag.py `
  E:\platform-tools\rs2_playback_commit_diag.bin
```

Site 1 is the same-backing-file/cue path (`0x42CBDC`); site 2 is the general
event-9 path (`0x42CD5C`).  For each valid pair, the selected path must be
unchanged, the global path should move from the old item in phase 1 to the
selected item in phase 2, and the source path may remain on the preceding
decoder source.  A later commit pair can show when source catches up.

## Hardware sequence

After one-shot installation, start playback through
`Music -> Files -> SD-card1 -> 01Flat -> Roots in Russia`.  Exercise both a
normal Next/autoplay transition and the full-navigation path through
`02Nesteted/Slayer/Albums/Show no mercy`, then continue to `03Flat/Sleep`.
Record whether playback, volume, visible folder, and highlighting remain
normal.  Pull `/mnt/sd_0/rs2_playback_commit_diag.bin` before any manual reboot
and decode it locally.

## Hardware result: 2026-09-14

The diagnostic ran without a process exit, reboot, playback failure, or loss
of volume input.  The retained checkpoint contains five complete before/after
pairs:

```text
artifacts/rs2_playback_commit_diag_complete_roots_evil_antichrist_die.bin
size:    16,640 bytes (10 records)
SHA-256: 6cda1e5bcf835854eeee2ea2fcfd85a132fe7ddf4cf3d5b59f5265560cb8a6da
```

Observed transitions:

| Transition | Cause | Commit site | Media ID | `source+0x230` |
| --- | --- | --- | --- | ---: |
| empty -> Roots | manual start | general `0x42CD5C` | `0 -> 0` | `0` |
| Roots -> Evil Has No Boundaries | physical Next/full navigation | general `0x42CD5C` | `0 -> 0` | `0` |
| Evil -> The Antichrist | physical Next | general `0x42CD5C` | `0 -> 1` | `0` |
| The Antichrist -> Die By The Sword | natural autoplay | same-file `0x42CBDC` | `1 -> 2` | `48483` |
| Die By The Sword -> following cue | natural autoplay | same-file `0x42CBDC` | `2 -> 3` | `361626` |

Both general commits proved the expected ordering.  On Roots -> Evil, the
selected path was Show No Mercy while `source+0x28` still contained Roots both
before and immediately after the original copy.  The global property-24 path
was Show No Mercy immediately after the copy.  By the next commit the source
path had caught up.  The general path also clears property 24 before entering
the observed copy.

Physical Next and natural autoplay therefore converge on media selection but
do not necessarily use the same final commit: physical Next used the general
event-9 path even within one cue-backed FLAC, while both naturally completed
cue transitions used the synchronous same-file path.  The same-file records
also confirm that `source+0x230` carries the live absolute backing-file timing
boundary.

During playback the user opened Folder View.  It remained on Roots in Russia,
the currently playing Slayer cue was not highlighted, and one-detent volume
input worked.  The gesture itself produced no playback commit.  This preserves
the prior conclusion that the inactive Folder View is stale and independent
of the playback commit, while confirming that this passive hook is safe enough
for the tested sequence.
