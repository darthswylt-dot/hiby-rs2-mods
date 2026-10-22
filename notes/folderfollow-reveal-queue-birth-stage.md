# Prepublication queued-request birth observation

Offline diagnostic stage, 2026-10-21. Hardware is **UNTESTED**. No player access,
installation, launch, signal, rearm or reboot; autoscroll remains disabled.
This stage implements **birth observation**, not transport of that identity
through the queue to its eventual renderer, and not a request-to-row join.

## Purpose and exact boundary

The [request-age counterexample](folderfollow-reveal-request-engine-boundary.md)
shows that old queued paint geometry can survive a reset and later receive
fresh renderer/producer tickets. The next safe increment is to observe the
original native producer invocation before allocation/queue publication,
without changing the 16-byte native rectangles/nodes or reusing metadata.

`build_reveal_queue_birth_stage.py` composes the prior native-scope stage and
adds three exact hook pairs. The [source contract](folderfollow-reveal-queue-birth-boundary.md)
pins their instructions, inbound targets, SP+14 premise and append semantics.

| Event | Original hook | Evidence, not authority |
| --- | --- | --- |
| BIRTH | `8B428C` | Nonnull input, numeric engine/input/metadata/native frame, sampled private revision/scope before allocation |
| ENQUEUE_BEGIN | `8B42E0` | Exact private BIRTH parent and numeric allocated-copy identity, before native append |
| RETURN | `8B42F0` | Exact private ENQUEUE_BEGIN parent and actual generic-append v0 |

The original C+44 guard occurs before the first hook: its early-return route
is unobserved. Null-rectangle/full-redraw calls clear the local carrier to zero
and continue unobserved; they cannot obtain a fabricated trusted birth. An
empty journal therefore proves neither request coverage nor freshness.

The revision is sampled inside the entry observer before native allocation;
it is not an atomic first-instruction timestamp or proof of the UI cause before
`8B4280` was called. Scope/revision sampling and publication do not lock writers.

## Private immutable receipts

`reveal_queue_birth_mips.py` emits a bounded append-only LQBR journal. Its
16-byte header is an issued counter plus three reserved zero words. There are
1024 default 64-byte slots, never reused. IDs are one-based private slot indices,
not native owner generations. Exhaustion, invalid bindings, loss or eight
failed LL/SC attempts cause permanent `FFFFFFFF` fault, overriding all records.
Magic is published last. There is no reset, ready state, recovery or exporter.

| Offset | u32 field |
| --- | --- |
| 0 | `LQBR` magic |
| 4 | BIRTH 1 / ENQUEUE_BEGIN 2 / RETURN 3 |
| 8, 12, 16 | Parent ID, original BIRTH ID, own sequence/ID |
| 20, 24, 28 | Numeric engine, original input, allocated-copy identities |
| 32, 36, 40 | Original metadata, exact native frame, original source site |
| 44 | Actual append v0 only for RETURN; otherwise zero |
| 48, 52 | Historical private revision and packed native-scope samples |
| 56, 60 | Reserved zero |

The core validates ancestry, exact expected parent kinds and inherited numeric
engine/input/metadata/frame/copy bindings in **private published records**.
Equal native addresses in unrelated births never group them. Metadata comes
from an observer-owned seven-word block; native-looking values are never
dereferenced by the core. Only private state, the owned block and the core's
own stack are accessed. ABI saved/reserved registers, SP/RA and HI/LO survive.

Valid revision changes/active scopes are recorded, not hidden or re-stamped.
These are diagnostic observations, not additional runtime row-admission gates.
Parent-zero descendants are ignored; they cannot guess a parent by pointers.

## Native behavior is preserved

The entry observer replays the native SP-0x40 / saved-s0 pair first, then uses
its own 0xA0 frame. Original RA is preserved until its later native save at
`8B4294`. The native locally-unused SP+14 carries BIRTH ID, then ENQUEUE_BEGIN
ID, within this exact invocation. This depends on the bounded O32/callee/alias
premises, not a universal native-stack ownership proof.

The observer at `8B42E0` first replays its displaced store/move. Crucially the
last rectangle word is still pending in v0: the original `JAL 8B3CC0` at
`8B42E8` and `SW v0,+C(s1)` delay at `8B42EC` remain **byte-identical**. The
private helper preserves that v0 and original arguments/SP; the native append
runs once with original return PC `8B42F0`. ENQUEUE_BEGIN is not a completed
four-word copy or successful publication, and no geometry words are captured.

RETURN records the actual node/zero scalar before stock code overwrites v0,
then replays the original two loads once. A nonzero return is not a retained
queue node or owner lease. Initial copy-allocation failure produces only BIRTH
and native -1; generic node-allocation failure produces all three observations,
raw return zero and the original outer zero result. No cleanup/failure behavior
is repaired. Stock enqueue and cleanup continue even after diagnostic fault.

No allocation-size change, queue-tail read, metadata replacement, native pointer
registry, additional native query/callback or UI operation is introduced. The
default native-scope and preceding builds remain byte-identical.

## Owned snapshot decoding

`decode_reveal_queue_birth.py` strictly decodes the private journal. It groups
events only by immutable BIRTH ancestry and retains missing/duplicated sequences
as incomplete. Unpublished issued records, malformed domains/reserved/tails,
bad bindings/sites and faults are refused. Monotonic revision/scope-issued
chronology is checked within parent chains, not across independent reservation
order. Optional current revision narrows unchanged-boundary observations and
rejects impossible future stamps.

The combined `lineage-rows-queue-birth-v1` decoder appends this journal to the
exact prior native-scope layout and validates both. A sampled scope-issued value
beyond the final scope header is refused; a previously active count that later
closed is allowed as historical evidence. Active count is not monotonic.
Independent review found this cross-journal check missing initially; it was
fixed with a concrete regression test.

Neither decoder attaches a birth to row/renderer receipts by engine, metadata,
node, rectangle or frame equality. Existing row/frontier/scope refusals remain
unchanged. All request-freshness/current-owner/current-contents/coherence/UI
authority flags stay false. Equal-sized capacity repartitions of empty tails
remain an out-of-band-format limitation; copied bytes do not prove coherent
acquisition.

## Executable result and remaining work

The native queue/reset fixture now distinguishes the earlier counterexample:
the complete prior private prefix remains byte-identical for old/new queued
causes, but the new suffix records birth revision 0 versus 2 for the marked
input. The native callbacks, allocations, metadata, links and cleanup remain
unchanged. Resource/cache/SQL/geometry helpers and the optional widget-to-job
chain are still explicitly bounded stubs; this is not a real UI/hardware run.

This establishes the first immutable observation before enqueue, not a safe
consumer lookup. Still required: justified identity transport through the
native queue and every relevant callback/split, unknown handling for full /
synthetic / unclassified routes, complete writer/lifetime coverage, original
UI/playback association, retained owner, coherent handoff and final UI action.
The [queue safety requirements](folderfollow-reveal-request-queue-safety.md)
are not waived by having a private birth journal.

Saved and deterministically verified ignored local intermediate:
`artifacts/hiby_player_1.4_sortfix_fullnav_wake_queue_birth_stage_v1_20261021.bin`,
7,159,132 bytes, SHA-256
`3f4d975087af7d31e2b60b6a0d6c5762585acd02658ed36cefb2152a78b79c7d`.
Private BSS: 835680 bytes from `BD4000`; the new 65552-byte journal begins
at `C90050`. Separate RX code: 15708 bytes at `CB0000`. Total source hooks:
29 pairs; exact original-image changes: 215 bytes, confined to declared hooks,
strides and ELF layout. No RWX segment or new external native call is added.
Changes remain local/uncommitted; this file is not deployment approval.

All 106 new focused checks pass, including the future-scope-issued regression.
The first unrestricted full run completed 1264 tests in 180.129 s with one
failure in the unchanged 25-ms mocked launcher watchdog fixture
`test_normal_exit_preserves_fd_and_status_no_delayed_signal`. The other 1263
checks passed. A separate rerun of all 24 launcher tests passed (16.316 s).
Neither launcher nor tests were changed to hide this intermittent failure;
all fixture signal/reboot calls remain mocked, without a real device.

The second unrestricted full run passed **1264 tests, no skips** (183.884 s).
All 171 Python scripts compile and tracked/new text files pass whitespace
checks. The saved default image remains deterministic and verified. No new
test weakens existing native, scope, row/frontier or UI-authority assertions.
