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

The latest context-sensitive **Now Playing -> Folder View** experiment is now
classified as failed: it briefly opened the correct folder, then returned to
the Music root and hung. This still confirms that current-path lookup and the
stock path builder work. The next candidate is to rebuild the explorer stack
before invoking the original gesture callback.

See [notes/status.md](notes/status.md) for the test matrix and exact artifact
hashes, [notes/addresses.md](notes/addresses.md) for the reverse-engineered
firmware addresses, and [notes/adb.md](notes/adb.md) for the reversible test
launcher and temporary ADB setup.

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
