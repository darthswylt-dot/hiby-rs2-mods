# Explicit queue birth transport to native callback entry

Local offline diagnostic stage, 2026-10-22. Hardware **UNTESTED**. Active
reveal is refused; no device connection, install, launch, signal, reboot or
rearm is part of this work. Changes remain local and uncommitted.

The [prepublication birth journal](folderfollow-reveal-queue-birth-stage.md)
now has a separate successor that explicitly transports its immutable ID to
the inspected native paint callback entry `439EC0`. It does **not** connect
that ID to outer `438200`, child renderer `4906E0`, row receipts or an original
UI/playback cause. Current owner, contents-current, capture coherence, request
freshness and autoscroll authority all remain false.

## Native change and bounded premise

`build_reveal_queue_transport_stage.py` builds on the preceding birth stage.
The generic list constructor `8B3CC0` now allocates **20 instead of 16 bytes**,
through its unchanged original allocator call. This affects all six inspected
list uses, not just paint requests. The new `node+10` word is zeroed after a
successful allocation, before either native link publication. A failed
allocation restores the original RA delay and takes its original null route,
without a node access. The native node prefix, rectangle allocation (16 bytes),
metadata, original append call/delay/RA, callback calls and frees stay intact.

The four-byte increase is a real native memory-pressure/timing change and can
change allocation success. Preserving failure control flow does not preserve
allocation outcomes. This separate offline image is not deployment approval.
All previous builder defaults remain byte-identical.

The sole new node-tail read occurs in the classified `C+34` queue loop, under
the pinned closed-producer/type/live-borrow premise: C starts zeroed and its
inspected producer appends through the widened constructor. Neither direct-call
census nor pointer equality proves all computed aliases, corruption, imported
nodes or concurrent frees impossible. There is **no retained native lease**.
See the exact [source/frame boundary](folderfollow-reveal-queue-transport-boundary.md).

## Explicit receipts and invocation carriers

New private journal LQTR: 16-byte header plus 1024 non-reusing 64-byte records
by default. Fields are `magic, kind, parent, origin, seq, engine, node, copy,
metadata, frame, site, upstream, revision, scope, reserved0, reserved1`.
Magic publishes last; both reserved words stay zero. Loss, invalid ancestry,
capacity/retry exhaustion and malformed bindings permanently fault the journal.
No private fault suppresses native append, paint callbacks or cleanup.
INSTALL publishes before the wrapper stores the returned ID in the native
tail; an interrupted/orphan receipt alone confirms neither that store nor
successful native append. A later exact consumer chain is separate evidence.

| Receipt | Exact boundary and parent |
| --- | --- |
| INSTALL | `8B3CE8`, before node publication. Exact saved original RA `8B42F0` gates producer SP+14; private ENQUEUE_BEGIN must bind producer frame, C, copied payload and unchanged metadata. Its new ID goes to node+10. Other generic callers leave zero. |
| BORROW | `8B4754`, after replaying original payload/metadata loads. Read current node+10 once; validate its exact INSTALL and save a fresh BORROW in native parent SP+14. Original `475C/4760` call/delay and RA `4764` stay unchanged. |
| HELPER | `8B3FA0`, after original B8 prologue. Original RA `4764` and C/incoming parent s5 gate ancestor carrier access; validate exact parent frame/node/payload/metadata and store a fresh ID in helper SP+14. |
| CALLBACK | `439EC0`, after original 38 prologue. Original RA `40EC`, descriptor at callbackSP+90, C==helper s6 and saved helper RA `4764` gate helper SP+14. Exact private HELPER ancestry produces a fresh callback SP+14 receipt. |

Every wrapper preserves original arguments/volatile registers, callee-saved
registers, HI/LO, native SP and RA except the relocated native prologue itself.
Incoming a3 remains untouched; it is forwarded by native geometry code and is
not a hidden token argument. Full callback RA `4998`, synthetic geometry and
unknown routes carry zero and do not read a node/rectangle tail or unvalidated
ancestor carrier. Multiple split callbacks receive different IDs with the
same exact HELPER parent. The full path's later native `49B8/49BC` queue
branch still enters the instrumented loop for real queued nodes.

The MIPS core reads only owned scalar metadata, private records/headers and
its own stack. Its sole external callee is the existing **private** birth
validator. Native-looking values are numeric bindings, never dereferenced by
that core or used as registry keys. Runtime domain/ancestry checks do not
claim capture coherence or writer coverage. Strict copied-snapshot decoding
additionally rejects impossible revision/scope chronology and wrapping native
extents; that conservatism is not a native lease or freshness admission rule.

## Decoding and partial histories

`decode_reveal_queue_transport.py` accepts owned LQTR bytes and the strictly
decoded LQBR result. It rechecks canonical birth events rather than trusting
mutable request summaries. Each CALLBACK follows exact IDs through HELPER,
BORROW, INSTALL and ENQUEUE_BEGIN to BIRTH. Engine/node/copy/metadata/frame
values cannot discover, merge or repair ancestry.

The native consumer can run before the producer RETURN observer. Separate
journal counters are not one clock: RETURN is joined only by explicit
ENQUEUE_BEGIN parent, with no consumer-vs-RETURN sequence requirement. Missing
or duplicated producer events stay incomplete; a unique mismatching raw return
is incomplete too. INSTALL precedes its producer RETURN; parent-chain revision
and issued-scope counters cannot regress. Active scope count is not monotonic.
Optional final counters reject impossible future samples. Quiet/equal samples
remain historical diagnostics, not request-freshness evidence.

The combined `lineage-rows-queue-transport-v1` decoder appends LQTR after the
exact preceding birth layout and preserves prior row/frontier/scope refusals.
It never attaches these new events to rows. The top-level
`birth_identity_transported=True` denotes this format's implemented transport
target (`439EC0-entry-only`), not complete request coverage; actual evidence is
reported separately as `observed_birth_to_callback_chain` and
`observation_complete`. Empty journals and partial installs cannot imply
coverage. All currentness/ownership/coherence/UI authority flags remain false.

## Executable checks and artifact

130 focused checks pass: pinned native source, private MIPS core, standalone
and combined parsers, and instruction-level queue/entry integration. Fixtures
execute actual producer, generic list, queue loop, geometry-helper body,
callback entry hooks and ordinary cleanup. Allocator/cache/SQL/geometry helpers
remain explicit stubs; callback **body after `439EC8` is mocked**. An optional
earlier row/job fixture is independent and never joined by address. This is not
a full native widget/SQL execution or a hardware run.

Regression cases include both allocation failures, original call/delay/RA and
HI/LO preservation, prepublication initialization, synthetic/full/unknown gates,
active/reset age observations, split callback IDs, journal faults/exhaustion,
and consumer-before-RETURN ordering. Reusing all engine/node/copy/frame
addresses with a new enqueue still yields a different explicit birth chain;
reuse by another generic caller zeroes the tail. The interleaving fixture uses
a separate stack and keeps freed fixture storage mapped; it proves private
causality only, not concurrent native memory safety.

Saved and deterministically verified ignored local intermediate:
`artifacts/hiby_player_1.4_sortfix_fullnav_wake_queue_transport_stage_v1_20261022.bin`,
7,162,704 bytes, SHA-256
`754ea4f3b1a6351b4409f1229a84ac380d18365fa32ce91062489b08b2bedba6`.
Private BSS: 901232 bytes from `BD4000`; LQTR begins at `CA0060` and occupies
65552 bytes. Separate RX code: 19280 bytes at `CC0000`. 33 hook pairs plus
declared allocation/stride/ELF edits change 242 original bytes. There is no RWX
segment or new external native call. The firmware artifact is ignored and
must not enter Git.

Next boundary: explicit callback-to-outer-to-child renderer transport without
overwriting occupied renderer slots or reconstructing identity by current-name
lookup. Complete writer/lifetime coverage, original UI/playback association,
coherent handoff, cancellation and final UI action remain separate gates.

Full repository regression: **1394 tests pass, no skips** (212.286 s), including
all 130 new checks. All 181 Python scripts compile. Tracked and new text files
pass whitespace checks; existing LF/CRLF notices were not bulk-normalized.
Independent source/ABI and decoder review found no actionable defect. The
saved default artifact is deterministic and exactly verified; the previous
birth-stage default retains its pinned hash. No existing test or native
currentness/UI-authority assertion was weakened. No player or network action
was taken, and no commit/push was performed.

A separate later [renderer successor](folderfollow-reveal-renderer-transport-stage.md)
now carries this explicit identity to the actual existing renderer root and
its captured row-event ancestry. This preceding callback-only builder/default
image remains unchanged; the successor still grants no currentness, native
lease or active UI authority.
