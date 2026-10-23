# Queued birth to existing renderer and captured rows

Local offline diagnostic stage, 2026-10-22. Hardware **UNTESTED**. No device
connection, install, launch, rearm, signal or reboot. Active reveal remains
refused. Changes are local/uncommitted; no commit or push was requested.

This separate successor to the [queue callback transport stage](folderfollow-reveal-queue-transport-stage.md)
extends explicit identity through the native outer call to the **actual existing
renderer lineage root**. A copied snapshot can now associate that root's captured
row events with the original queued birth, only through immutable private IDs.
It does not establish the original playback/UI cause, native ownership,
capture coherence, current contents or authorization to scroll.

## Preserve the existing root and native calls

Two new linear source hooks are added:

| Boundary | Observation and preserved behavior |
| --- | --- |
| `438248/24C` | Replay native `s4=a2; s1=a3`, clear outer SP+14, gate exact callback frames/arguments and capture OUTER from its already-published CALLBACK ID. |
| `49076C/770` | After the old `490758` root observer and original native `490764/768` call/delay, bind an existing root ID to the exact OUTER; restore actual native result/HI/LO, then replay original cache store/P+1BC load. |

The original callback-to-outer `439F90/94`, outer-to-child `438740/744`, native
P-to-V getter `459340` and `strcpy` call `490764/768` retain their callsites,
arguments, delay instructions and return PCs. No native lookup or callback
call is added. All preceding builder defaults stay byte-identical.

Renderer native SP+10 already holds its original-entry revision; SP+14 already
holds its lineage root ID. Neither is overwritten or repurposed. The new
association lives in a separate private journal, not a native renderer field
or a mutation of the old lineage receipt. The outer uses only its separately
audited SP+14. Low-slot ABI/native-buffer assumptions are still bounded, not
universal ownership proofs. See the [source/frame contract](folderfollow-reveal-renderer-transport-boundary.md).

The preceding generic node extension (16 -> 20 bytes for six inspected list
uses) is inherited unchanged. This stage adds no further native allocation-size
change; the new journal and additional stack/code still consume memory and
time. Previous allocation outcomes and hardware safety remain unproved.

## Explicit journal and ordered native gates

Private LQRD has a 16-byte header and default 1024 non-reusing 96-byte records:
`magic, kind, parent, origin, seq, transport, lineage, engine, widget, view,
panel, frame, upstream, descriptor, input, controller, job, revision, scope,
cache, site, reserved0, reserved1, reserved2`. Origin is the original private
BIRTH ID, transport is the exact private CALLBACK ID, lineage is the existing
LNRG root ID. Different namespaces are never interchangeable. Magic publishes
last, reserved fields stay zero, bounded LL/SC allocation never resets/reuses,
and loss/invalid ancestry/exhaustion faults permanently.

OUTER kind1 has external parent LQTR.CALLBACK. Let outer native SP be O and
callback SP B=O+200. Before callback carrier B+14 is read, the wrapper checks
own saved RA O+1FC==439F98, callback saved RA O+234==8B40EC, coordinates a2==B+18,
and C/W/input/controller against the saved incoming callback registers. The
private parent must bind exact B and C; coordinates/input must be B+18/B+90.
The new OUTER ID goes into O+14, or zero on unsupported paths. An OUTER receipt
publishes before that subsequent carrier store and alone does not prove it.

RENDER kind2 has an earlier LQRD.OUTER parent. At native renderer SP R, first
gate R+2C==438748, then outer saved RA R+22C==439F98, then callback saved RA
R+264==8B40EC. Only afterward may the outer carrier R+44 be consumed. C/s3
must match own saved outer C R+18; cache/s1 must match outer local R+1E0.
Private OUTER binding checks C, W/fp, coordinate pointer from R+28, original
paint input from R+1C and controller from R+24. These are existing native
scalar values, not fresh native object reads or a current-name join.

At this later site **s0 is V**, **fp is W**, and **live s4 is no longer the
coordinate pointer**: the original call delay loaded V+DC into it. The wrapper
uses saved R+28 for coordinates. Actual v0 is the `strcpy` result until the
original P+1BC load is replayed; all intermediate state is preserved exactly.

The actual existing root ID from R+14 must validate as LNRG.RENDER, self-origin,
parent0, STACK=R, VIEW=V/s0, PANEL=P/s2, JOB=V+38A4 and SITE=490758. An INITIAL
or foreign-frame root is not admitted. No new root, birth epoch or hidden
argument is minted to replace missing provenance. Multiple child invocations
can share one OUTER but must have distinct actual lineage roots.

The new MIPS core uses only owned 13-word scalar metadata, private headers and
records, and its own stack. Native-looking values are never dereferenced by
the core. Its only external callees are existing **private** LQTR/LNRG
validators; it adds no external native call. 96-byte indexing is 64+32 without
MUL/HI/LO changes. Parent0 is ignored before metadata access; private fault
never suppresses native rendering, the original cache store or queue cleanup.

## Strict decoding and captured-row association

`decode_reveal_renderer_transport.py` requires owned LQRD bytes and canonical
prior LQTR, LQBR and lineage results. It reconstructs and rechecks canonical
events/receipts, including known original-entry and producer-revision
extensions, rather than trusting mutable summary claims. Malformed sites,
frame/scalar bindings, reserved/tails/magic, impossible counter chronology,
future scope-issued/revision samples and faults are rejected. Repeated use of
the same explicit lineage root is rejected, even if all native addresses are
identical; different actual roots under one OUTER are allowed.

Consumer/root observation can precede producer RETURN. Separate journal
sequence numbers are not one clock. Missing/duplicate/mismatching producer
RETURN stays incomplete and is not repaired by a complete renderer ancestry.
The original-entry revision remains unchanged; renderer entry itself advances
the known counter, so literal all-sample equality is deliberately conservative
and normally false even for an uninterrupted path. No self-bump exemption or
request-freshness admission is introduced.

The combined `lineage-rows-renderer-transport-v1` format appends LQRD after the
exact previous layout. `renderer_transport_observation.associations` reports
the explicit birth/CALLBACK/OUTER/RENDER/root IDs. A separate
`renderer_row_associations` list names producer IDs, row-event sequences,
window indices and operation borrow IDs **only by the already validated
lineage origin ID**. It does not mutate prior receipts, rows, windows,
operations, their completeness flags or their rejection reasons. V/P/job,
frame, cache, metadata and current names never locate or merge receipts.

`renderer_identity_associated` means an actual explicit historical root
association was observed, not that a current native owner exists. A root
without captured rows does not imply row coverage. Every current-owner,
contents-current, coherent-capture, request-freshness and UI-authority flag
remains false, including per-row-association output. Old frontier/scope/window
refusals remain intact even when the upstream birth is now known.

## Native-instruction fixture boundaries

The new integration executes the actual `439EC0` body, with resource/name
helpers explicitly mocked; the original `439F90` call enters actual `438200`
prologue/guards/new observer. The outer geometry/cache middle is explicitly a
fixture; its original `438740` W+148 load/call/delay still executes. The actual
`4906E0` entry and selected native list-method calls then run through `490778`,
including the native `459340` P+7C getter, existing root observer, original
`strcpy` call with hostile return-register/HI/LO behavior, new root binding and
original native store/load. Actual renderer/outer/callback epilogues run.

The renderer suffix and worker/job/query/SQL sequence remain the earlier
composed fixtures using that exact already-created root, not an execution of
every UI/SQL routine. A two-callback test captures first-root rows before the
second entry advances the frontier: only the first root gets those rows,
despite equal V/P/job/cache/frame values. An earlier fixture attempted that
capture after the second entry and correctly hit the unchanged row guard;
the fixture ordering was corrected, with no production gate weakened.

Other checks cover each pre-carrier gate/ABI/HI/LO path, duplicate-root refusal,
new-birth ABA reuse, old/reset requests, RETURN arriving after native renderer,
journal fault/exhaustion and native cleanup continuation. Interleaving fixtures
use a separate stack and retain freed mapped fixture storage; no concurrent
native lifetime or full UI/hardware safety is inferred.

## Saved offline intermediate and remaining gates

Saved and deterministically verified ignored local intermediate:
`artifacts/hiby_player_1.4_sortfix_fullnav_wake_renderer_transport_stage_v1_20261022.bin`,
7,166,664 bytes, SHA-256
`f42fac46890dc2eadbeba88f90ce5b82857d3045752b974b15d04bef263d2244`.
Private BSS: 999552 bytes from `BD4000`; new LQRD is 98320 bytes at `CB0070`.
Separate RX: 23240 bytes at `CD0000`. 35 hook pairs plus declared stride/
allocation/ELF edits change 259 original bytes. No RWX or new native call.
Firmware intermediates and raw snapshots remain excluded from Git.

This closes the bounded explicit queued-birth-to-renderer/row-identity gap,
not the original playback/UI-cause or freshness gap. Still required before an
active candidate: complete native writer/cancellation and lifetime coverage,
retained owner, coherent owned handoff, explicit playback/request-generation
association, final guarded UI transaction, and separate hardware validation of
new reads, layouts, memory pressure and timing. Scrolling remains disabled.

All **112 new focused tests pass** (50.181 s): 13 pinned source contracts, 27
MIPS-core tests, 33 standalone parser tests, 24 combined parser tests and 15
native-boundary integration tests. All 191 Python scripts compile. Independent
source/ABI, private-core and decoder review found no actionable defect. The
saved default image is exactly deterministic and verified; the preceding
queue-transport default retains its pinned hash. Existing native/UI-authority
tests and old row/frontier rejections were not weakened.

Full repository regression: **1506 tests pass, no skips** (244.049 s). This
includes all 112 renderer-association checks plus the preceding 1394 checks.
Tracked and new text files pass whitespace checks; the existing LF/CRLF notices
were not bulk-normalized. The saved default artifact remains exactly verified
and ignored. HEAD remains the prior checkpoint: no commit, push, device or
network action was performed.
