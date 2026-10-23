# Playback-to-paint cause: selected record is not queued-event identity

2026-10-22. Offline original-instruction contracts and host counterexamples
only. No new firmware stage, image, hook, allocation, BSS layout, live read,
device connection or UI action. Autoscroll stays disabled; hardware is
UNTESTED. Existing diagnostic images remain unchanged. Changes are local and
uncommitted. The request-age decoder adds one explanatory limitation, not a
new positive gate, input, algorithm or format.

Reference: `artifacts/import-20261001/hiby_player_02fd.bin`, 7,133,528 bytes,
SHA-256
`02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87`.
`scripts/test_reveal_playback_cause_contract.py` requires this exact input;
missing or different source fails rather than skipping a test.

## Two separate native channels before general playback commit

The player queue sender `42B140` copies **eight bytes** through `4504E0`:
`[event, parameter]`. Worker `42E280` receives eight bytes through `450600`,
then copies them to its own local message at `SP+AA0` with `42E294`.
Event 9 selects `42E3A8` via table `921334[9]`. Its sender at `42B1EC..1F8`
posts `[9,0]`, not a pointer or ID for the selected media record. The message
does not carry an owned media identity or extra immutable invocation ID.

The selected media travels through a different staged list at player B+BB0,
protected by B+BB4. Constructor `42BA38..50` requests 16 elements of **A90**
bytes using `456E60`. That wrapper sets chunk size ten and calls `456C40`:
the initial capacity rounds up to twenty, not a fixed sixteen-entry queue.
Its method bindings are:

| List slot | Native implementation | Bounded role |
| --- | --- | --- |
| +18 | `455DA0 -> 455BC0` | Append at the current count |
| +2C | `4557E0` | Return the indexed element |
| +30 | `455DC0` | Return count at object+C |
| +24 | `4557C0` | Clear the entire count at object+C |

Producer `428B40` copies A88 bytes of media into its local SP+18 at
`428B88/8C`, writes a transition word at SP+AA0 (= record+A88), then appends
at `428B9C`. The A90-byte list copy also includes record+A8C, which this
body does not explicitly initialize. That observation **does not establish a
spare field**, zero value, valid ID or permission to extend/reuse the record.
`42B180` does not check the staging call's return before its event-9 send.
Receiving event 9 alone therefore does not certify a successful new append.

## Latest-item selection, whole-batch clear and the unlock gap

The event-9 worker locks B+BB4, reads the count at `42E3D0`, then requests
**count-1** at `42E7EC/7F0`. It copies that last element's A88-byte media to
SP+18 at `42E804/808` and reads its transition word into FP at `42E810`.
It does not choose index zero or reconstruct the record from the event word.

The following ordering is concrete:

1. Copy the selected last media record and transition while holding B+BB4.
2. Unlock at `42E3E4/3E8`.
3. Reload B+BB0 at `42E3EC`, then lock again at `42E3F0/3F4`.
4. Clear the **whole staged count** at `42E404`, then unlock at `42E40C`.
5. Subject to its native gate, call general commit `42CC60` at `42E42C`
   with the earlier SP+18 media copy and FP transition.

Two staged selections A and B with two pending event-9 messages need not be
delivered as A then B. The first event can select B and clear both entries.
More subtly, producer C may append between steps 2 and 4 and be cleared
without ever being selected.
These are source-permitted histories, not evidence that the physical player
actually took either schedule during prior tests. This work preserves native
coalescing, empty, failure and discard behavior; it does not fix that policy.

`scripts/test_reveal_playback_staging_native.py` executes these original
constructor, staged-list, player-queue, selection and call-boundary instructions.
It substitutes the final general callee `42CC60`. Repeated dequeues with an
empty staged list are tested **under that explicit substitution**: actual
general commit also flushes the player event queue through `450720` at
`42CD6C`, so the test does not assert that those pending messages survive the
real callee or that multiple opaque calls are actual playback completions.
Allocator/free, copying/zeroing, mutex, naming, readiness and string helpers
are bounded fixture substitutes; no OS scheduler or hardware race is proved.

The worker's SP+18+A88 is SP+AA0, its current event/parameter message. It
copies only A88 bytes and holds the transition separately in FP: simply
enlarging that copy to A90 would overwrite live message locals. The staged
producer and worker do not share an interchangeable extended stack layout.

A future exact selected-operation ID must be copied with the **selected
record before the first unlock**. The event-9 order, later B+BB0 count, a reused
element address or a current publication ticket cannot recover that ID.
Discarded/coalesced entries require explicit superseded/unknown handling.

## No established universal playback-to-Files notification

Both inspected commit paths may call the unresolved callback B+BA0:
fast at `42CC0C`, general at `42D6A0`, with context B+B98 and the mutable
global descriptor D=`ADD468`. The actual callback target and its propagation
are not established. D is not an immutable request cause or retained snapshot.
The order also differs: fast calls `42CA00` before this callback; general
calls it afterwards.

Fast then sends **player event 11** at `42CC18`, using the eight-byte player
queue above. `921334[11]=42E32C`, not Files/UI event 140. General's worker
call at `42E42C` returns to the worker loop; it is not a proved common event-11
route. Neither observation establishes a universal Next/autoplay notification
to Files. The [resource-completion audit](folderfollow-reveal-nonrender-boundary.md)
already shows why the known UI 140 PNG route is not that proof.

UI sender `474380` instead zeroes and fills a **20-byte** record:
`[0,event,parameter1,parameter2,clock]`. Its original call `4743E8` copies
that record to the UI queue. No extra immutable playback invocation ID is
present in this layout. A pointer-valued parameter does not retain its target.
Dispatcher `454200` receives twenty bytes, matches message+4 and synchronously
calls its table handler with the local stack copy. Dequeue `450600` copies
the requested bytes at `450670`, then frees the original heap message at
`450694` before the handler runs. A later heap-address registry would thus
be ABA-unsafe. No inspection here proves all indirect producers or lifetimes.

## Executable ambiguity, not a fabricated native source edge

`scripts/test_reveal_playback_cause_ambiguity.py` uses two explicitly modeled
notification histories with different frozen playback parents, 1 versus 2.
Both later hold the same coherent **host-model** publication B/revision 2.
Both have the same UI-message-shaped bytes and execute the same existing
native renderer fixture, producing byte-identical owned diagnostic snapshots
and identical public request-age assessments.

The shaped message is deliberately **unlinked**: it is neither delivered to
nor consumed by that renderer fixture. Its modeled producer is not a claimed
native playback -> UI 140 edge. The fixture executes the previously bounded
native paint/callback/renderer path with its documented resource/geometry/SQL
substitutions, not an entire player or scheduler. The counterexample shows
information absent from these observations cannot be recovered by a late
current-ticket stamp. It does not establish a new native event route.

Playback publications can differ while UI revision/scope samples are equal.
Consequently an explicit BIRTH -> callback -> renderer -> row association and
no extra UI-counter conflict still do not identify the original playback
parent. The request-age report continues to say **unproven / deny**, with all
five authority flags false. Equal IDs in different namespaces are not a join.
The separate older playback guard is not composed or sampled by this image;
no implication is proved that Next/autoplay/path/cue changes advance UI clocks.

## Next implementation boundary

Do not connect the host publication model as a native authority by sampling
the latest guard, descriptor, path, clock or callback address at paint time.
Even a coherent later publication cannot reveal an earlier message's parent.

The next causal adapter needs independently identified selected-record,
playback invocation, notification and delivery receipts. IDs must be frozen
before the corresponding asynchronous publication, follow the exact selected
record despite coalescence/discard, and travel through every proved queue
copy/dequeue boundary into the actual `8B4280` invocation. Unknown BA0 targets,
unclassified producers, absent carriers and exhausted journals remain unknown,
not repaired from ambient current state. Field/allocation/ABI/lifetime audits
are prerequisites, not permissions supplied by this protocol sketch.

This requirement is additional to coherent owned identities, complete native
writer/cancellation coverage, retained UI ownership and the final guarded UI
transaction. None of the existing refusal or lifetime gates is waived.

## Verification

All **38 focused checks pass** (1.534 s): 16 pinned original-source contracts,
12 original-instruction staged-selection/queue fixtures, and 10 explicitly
unlinked host-model causality counterexamples with public raw decoding.
Independent source/ABI/interpreter reviews found no remaining actionable issue.
The opaque-callee queue-flush boundary and both transition/tail offsets are
explicitly distinguished; no original test, refusal or native behavior was
weakened. Full regression: **1,603 tests pass, no skips** (249.450 s). All
198 Python scripts compile; tracked/new text files pass whitespace checks.
The existing saved renderer-stage image remains exactly verified with its
unchanged `f42fac...` SHA-256. No new firmware image was generated. Full
saved-image details are recorded in [status](status.md).

## Separate playback-dispatch follow-up (2026-10-23)

The [passive dispatch stage](folderfollow-reveal-playback-dispatch-stage.md)
follows player event11 through the action queue: actions0/5 are ignored by
explorer callback490980. General commit separately queues action1 at42D614,
which the explorer can turn into a paint request. This is a conditional native
edge, not a transported playback/paint parent or a universal Next/autoplay path.
The new LPDI journal captures only the already-loaded optional BA0 target and
arguments. General action1 precedes that observation, so it cannot be parented
to LPDI by late stamping. No currentness, lifetime or UI gate is relaxed.
