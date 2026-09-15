# HiBy RS2 firmware notes and patches

Reverse-engineering notes for the HiBy RS2 player, focused on defects in the
firmware 1.4 `hiby_player` executable.

## Current state

The following fixes have been confirmed on hardware:

| Area | Result |
| --- | --- |
| Folder sorting | Removed the hard-coded `pinyin` SQLite collation from 32 queries. Mixed numeric, Latin, and Cyrillic folder names sort normally. |
| Folder traversal | `Next`, autoplay, and `Previous` traverse nested sibling directories in the expected order. |
| Wake refresh | After a track changes while the screen is off, waking on Pause shows the current track, time, and progress bar. |

Folder-follow is not fixed yet. Passive hardware telemetry proved that the
live UI timer sees the committed full playback path while Folder View remains
stale. Static tracing then recovered the complete stock nested restoration
contract: property 11 carries a one-shot full path, `0x495B80` rebuilds every
explorer level, and `0x495D40` performs locked cleanup and consumes that path.
A narrowly gated functional candidate is prepared but not yet hardware-run;
see
[notes/folderfollow-saved-path-rebuild-test.md](notes/folderfollow-saved-path-rebuild-test.md).

See [notes/status.md](notes/status.md) for the test matrix and exact artifact
hashes, [notes/addresses.md](notes/addresses.md) for the reverse-engineered
firmware addresses,
[notes/folderfollow-dispatch-fd9-diag.md](notes/folderfollow-dispatch-fd9-diag.md)
for the latest hardware evidence, and [notes/adb.md](notes/adb.md) for the
reversible test launcher and temporary ADB setup.

A later local binary with SHA-256 prefix `02fd` was recovered after these notes
were written. Byte-level archaeology proves that it is the golden `c825...`
sorting/full-navigation/wake build plus a newer passive source-state diagnostic.
See [notes/02fd-archaeology.md](notes/02fd-archaeology.md).
Its crash-resistant two-phase successor is documented in
[notes/folderfollow-safe-pointer-diag.md](notes/folderfollow-safe-pointer-diag.md).
The successor completed a full Roots -> Slayer -> Sleep hardware run and
identified source-object field `+0x230` as changing scalar cue/timing state
while the sampled Folder View and explorer state remained stale.
Static tracing has now identified it precisely as an absolute millisecond
position in the backing audio file and identified the adjacent inline UTF-16
playback path at `source+0x28`. See
[notes/source-object-cue-path-static-trace.md](notes/source-object-cue-path-static-trace.md).
The corresponding bounded, two-phase hardware telemetry candidate is
documented in
[notes/folderfollow-safe-path-diag.md](notes/folderfollow-safe-path-diag.md).

## Repository policy

This repository intentionally contains no HiBy firmware images, original or
modified `hiby_player` binaries, music files, database dumps, or device logs.
Those artifacts may be copyrighted, device-specific, or contain private data.
Only notes and small helper scripts are tracked.

Always compare SHA-256 hashes before installing a test binary. The filenames
used during development were reused several times and one cached download was
observed with unexpected contents.

## Test directory layout

The minimal regression card uses this structure:

```text
01_Flat/
  track.flac
02_Nested/
  Album1/
    track.flac
  Album2/
    track.flac
03_Flat/
  track.flac
```

Expected traversal:

```text
Next/autoplay: 01_Flat -> Album1 -> Album2 -> 03_Flat
Previous:      03_Flat -> Album2 -> Album1 -> 01_Flat
```

## Warning

These notes describe unsupported modification of a MIPS executable running as
root on the player. Keep a known-good firmware image and a recovery path. The
temporary ADB configuration described here exposes an unauthenticated root ADB
interface and must be removed after testing.
