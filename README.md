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
A [passive registry-lock receipt prototype](notes/folderfollow-reveal-registry-receipt.md)
now records raw acquisition before native status masking and links it to registry
publication. It remains local-only and grants no owner-generation or cleanup authority.
A separate [receipt-bound owner issuance prototype](notes/folderfollow-reveal-registry-owner.md)
now records logical generations under checked distinct registry/paint guards.
It is historical accounting only: no producer transport, native lease or installation.
A separate [explicit captured-carrier publication adapter](notes/folderfollow-reveal-owner-carrier.md)
now checks a creation-time pair before checked queue publication on the local
instruction fixture. All nine native producer call paths remain unwired; no
latest-by-pointer generation lookup, native lifetime or player installation.
An [emitted per-invocation creation capture](notes/folderfollow-reveal-creation-capture.md)
now retains the issuer event in an explicit owned output instead of a Python
observer. Its flag is historical/release-unobserved; native explorer fanout
still loses generation across name relookup and remains unwired.
A separate opt-in [raw registry-release witness](notes/folderfollow-reveal-registry-release.md)
now gates captured output on the actual same-invocation unlock result before
native status masking. Default bytes stay unchanged; native queue/lifetime
integration remains gated.
A separate [owned deferred envelope prototype](notes/folderfollow-reveal-deferred-envelope.md)
now copies checked capture and payload values through a typed native FIFO on
the caller-exclusive fixture, consuming each owned work buffer before publication.
It does not connect the original action queue, provide concurrency arbitration
or grant native lifetime/UI authority.
A separate [checked transport guard](notes/folderfollow-reveal-deferred-queue.md)
now serializes cooperating accesses to that explicit typed FIFO with a distinct
raw mutex, releases it before publication and fails closed on checked local
postcondition faults. Native worker integration and whole-instance error
isolation/lifetime remain separate gates.
A separate [first-constructor capture](notes/folderfollow-reveal-constructor-capture.md)
now preserves the genuine creation handoff and exact registration status from
an explicit native-constructor fixture. Its unchanged native post-registration
UI/error continuation is diagnostic only, not safe admission or a native lease.
A separate [cooperative operation ledger](notes/folderfollow-reveal-retained-operations.md)
now keeps extracted requests outstanding until exact paint acknowledgement,
using a distinct token-bearing FIFO72. Closing admission and emptying the FIFO
alone cannot prove quiescence. This local accounting still requires an externally
retained engine/resource/callback bundle and grants no native-free or UI authority.
An optional [one-shot cleanup intent](notes/folderfollow-reveal-cleanup-intent.md)
now records that exact captured bundle only after closed admission and checked
quiescence. It calls no native teardown: the original deletion re-resolves by
name, and explorer teardown mutates objects before reaching the delete calls.
A [read-only registry comparison](notes/folderfollow-reveal-registry-identity.md)
now checks the exact historical binding against the current guarded native ring.
Reused node/engine addresses can still match an older capture; this observation
does not authorize unlinking, freeing or reassigning a generation.
A separate [independent birth history](notes/folderfollow-reveal-registry-birth.md)
now records the actual publication before old receipt/binding/owner quota gates.
Its tokens identify historical events, not live allocations: missing raw-result
coverage and all four known unlink paths still block native cleanup integration.
A separate [retirement-observation branch](notes/folderfollow-reveal-registry-lifecycle.md)
now marks the four known frontiers under fresh checked R, before native unlink
or conservatively before outer unlock. Selected retirement is not completed
deletion; missed raw-error events can still miscorrelate reused addresses.
A separate [owned birth-token capture](notes/folderfollow-reveal-birth-capture.md)
now transfers the just-committed token to its exact registration invocation,
exporting BCAP48 after checked R release. It performs no latest-by-address
lookup and grants no native lifetime, owner/paint health or cleanup authority.
A separate [typed birth-token FIFO](notes/folderfollow-reveal-birth-queue.md)
now carries that exact token with an owned payload snapshot. Its BQ84 format
does not change any stock queue or older diagnostic record. Extraction exports
an owned copy after checked transport release; it does not dispatch paint or
prove that native objects remain alive.
A separate [historical queue consumer](notes/folderfollow-reveal-birth-consumer.md)
now compares that exact queued token and birth event with the recorded history,
after releasing T and acquiring fresh checked R. It exports an owned snapshot
of either recorded retirement-observation state, never native-use or UI approval.
A separate opt-in [raw-acquisition gate](notes/folderfollow-reveal-registry-acquire-gate.md)
now refuses registration before allocation and name-selected deletion before
their first ring read when a fresh raw-zero witness is missing. It does not
isolate ignored caller failures or cover other shutdown/teardown routes; no
native lifetime, cleanup or active scrolling authority is inferred.
A separate opt-in [constructor continuation gate](notes/folderfollow-reveal-constructor-continuation-gate.md)
now skips local UI/name work after a genuinely executed registration returns
nonzero in either native constructor. It preserves the engine-pointer return
convention; higher callers, skipped-registration paths and masked release
errors remain outside this status-only stop.
A separate opt-in [explorer failure gate](notes/folderfollow-reveal-explorer-failure-gate.md)
now sends that specific explorer invocation to its stock NULL-return exit
after a classified registration failure, before storing or enabling the engine.
Earlier allocations, resource aliases and mutations remain; this is not cleanup,
rollback or isolation of other callers.
A separate opt-in [constructor release gate](notes/folderfollow-reveal-registry-release-gate.md)
now carries the actual registry-unlock result past native forced-zero returns.
Its same-invocation private witness feeds the existing constructor/explorer
stops; publication already happened, so this is not rollback, cleanup or a
global release/lifetime certificate.
A separate opt-in [destructor continuation gate](notes/folderfollow-reveal-destructor-continuation-gate.md)
now skips the remaining explorer resource/view cleanup after an explicit
name-delete failure. This is a late local stop: earlier destructive effects,
masked delete-release errors and outer caller behavior remain unresolved.
A separate opt-in [destructor delete-release gate](notes/folderfollow-reveal-delete-release-gate.md)
now carries the actual unlock result from that one name-delete invocation into
the existing destructor stop. Its fresh private witness prevents a native
forced-zero result from hiding the observed release error. Earlier unlink/free
effects, other callers and whole-instance ownership remain unresolved.
A separate opt-in [refresh failure gate](notes/folderfollow-reveal-refresh-failure-gate.md)
now skips local view recreation and offset restoration after that refresh
invocation's destructor returns an explicit error. It preserves the error
through the native refresh exit; higher callback handling and earlier cleanup
still require their own coordination.
A separate opt-in [refresh wrapper gate](notes/folderfollow-reveal-refresh-wrapper-gate.md)
now carries that classified failure past one wrapper's remaining view work.
It uses the existing failure decision and native frame exits, preserving the
exact result without a shared error flag. Higher callbacks remain separate.

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
