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

Folder-follow and automatic current-track scrolling are not fixed yet.
The latest passive bridge test confirmed manual scrolling, preserved highlight
and normal volume adjustment; autoscroll remained disabled. See the
[October 12 hardware report](notes/folderfollow-reveal-interactive-20261012.md).
The local [publication/cancellation coordinator](notes/folderfollow-reveal-coordinator.md)
is host-only. A separate intermediate
[MIPS mutation-guard build](notes/folderfollow-reveal-guard-stage.md) connects
protection to nine known playback mutation sites. Its local
[grouped successor](notes/folderfollow-reveal-grouped-stage.md) also brackets
the general track-change operation, including preparation and repeated copies.
Both refuse active reveal and have not been tested on the player.
The [October 15 extension](notes/folderfollow-reveal-fast-grouped-stage.md)
also groups the synchronous same-file block, separately from fallback paths.
Live playback coherence, complete invalidation and retained UI ownership are
still required before an active firmware candidate can be produced.

A later [offline queue-identity diagnostic](notes/folderfollow-reveal-queue-transport-stage.md)
now carries an explicit request-birth ID to the native paint callback entry,
not yet to renderer rows. Its separate image widens generic nodes from 16 to
20 bytes, changing memory pressure; it remains hardware UNTESTED and refuses
active reveal. Prior build defaults are unchanged.
Its [renderer successor](notes/folderfollow-reveal-renderer-transport-stage.md)
now associates that exact ID with an existing renderer root and captured row
events through private lineage IDs. This is historical diagnostic evidence,
not current contents or scrolling authority; it is still local and hardware
UNTESTED.
The [host-only request-age report](notes/folderfollow-reveal-request-age.md)
now explains known boundary conflicts without changing firmware. No-conflict
histories remain unproven; this report never authorizes scrolling.
The [playback-to-paint cause boundary](notes/folderfollow-reveal-playback-cause-boundary.md)
now distinguishes queued player events from separately staged selected media.
Local counterexamples show why event order or a later playback ticket cannot
recover a missing original cause; that host-only step changes no firmware.
The separate [passive playback-dispatch stage](notes/folderfollow-reveal-playback-dispatch-stage.md)
now records the actual optional callback target as dispatch intent only.
The general action1 paint route is distinct and occurs earlier; no causal ID
is inferred from the new journal. This local image is hardware UNTESTED and
still cannot scroll or authorize a UI action.
Its [explicit notification-link successor](notes/folderfollow-reveal-action-link-stage.md)
now carries GENERAL action1's original ID through both native queues to the
actual paint BIRTH, then joins existing renderer/row ancestry by explicit IDs.
This is historical invocation evidence, not coherent/current playback or a
retained native record. The separate image widens action and paint elements
to20/36 bytes; it remains offline, hardware UNTESTED and cannot scroll.
The [paint-payload follow-up](notes/folderfollow-reveal-paint-payload-boundary.md)
now isolates post-BIRTH rectangle tearing and current-index removal from
historical ID ancestry. A known purge uses a different mutex; stable bytes,
selected-entry removal and object lifetime need separate protection.
A separate [host paint-queue coordinator](notes/folderfollow-reveal-paint-queue.md)
now implements one retained FIFO claim, exact acknowledgement, owner-generation
revocation and deferred accounting release. Its lock protects host values only;
native cleanup/lifetime integration and active scrolling remain unimplemented.
A separate [offline MIPS handoff prototype](notes/folderfollow-reveal-paint-handoff.md)
now exercises owned queue-byte transfer and exact-head acknowledgement against
the original list methods under148. Its distinct40-byte test format adds a
publication nonce without changing LALI or saved builds. Failed native growth
withdraws terminally; stock purge/lifecycle participation is still required.
Its separate [generation-retirement successor](notes/folderfollow-reveal-paint-retirement.md)
now revokes captured owner tickets before cooperative queue purge, preserves
an active head until acknowledgement and refuses late old-generation work.
The44-byte offline format and local drained check still grant no native-free
or scrolling authority; no firmware builder or player installation changes.
An explicit [checked-mutex variant and admission audit](notes/folderfollow-reveal-paint-admission.md)
now distinguish raw lock errors from the stock wrappers' forced-zero results.
Creation/cleanup hooks remain gated; mutex-error recovery is a caller duty.

See [notes/status.md](notes/status.md) for the test matrix and exact artifact
hashes, [notes/addresses.md](notes/addresses.md) for the reverse-engineered
firmware addresses,
[notes/folderfollow-dispatch-fd9-diag.md](notes/folderfollow-dispatch-fd9-diag.md)
for the earlier folder-restoration investigation, and
[notes/adb.md](notes/adb.md) for the reversible test launcher and temporary ADB
setup.

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
