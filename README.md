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

Folder-follow is not fixed yet. Rebuilding the explorer stack on either side of
the stock callback caused navigation corruption, and reusing the stock
existing-view retarget path still left Folder View on the folder where playback
started. A later FD9 telemetry test reproduced the stale-folder state without
corrupting the UI: before the callback, `0x4E4B80` returned no playback path,
and original `0x4E5FA0` did not immediately change the sampled explorer state.
The next step is to identify and observe the underlying state fields rather
than trying another stack-lifetime permutation.

See [notes/status.md](notes/status.md) for the test matrix and exact artifact
hashes, [notes/addresses.md](notes/addresses.md) for the reverse-engineered
firmware addresses,
[notes/folderfollow-dispatch-fd9-diag.md](notes/folderfollow-dispatch-fd9-diag.md)
for the latest hardware evidence, and [notes/adb.md](notes/adb.md) for the
reversible test launcher and temporary ADB setup.

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
