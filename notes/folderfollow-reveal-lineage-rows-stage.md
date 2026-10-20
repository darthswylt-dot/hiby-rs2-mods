# Provenance-bound native row journal (2026-10-19)

Separate **offline diagnostic intermediate** following the
[native lineage stage](folderfollow-reveal-lineage-stage.md). No device access,
installation, launch, export, UI action or automatic reveal was enabled. The
previous lineage-only emitter and its saved output remain unchanged.

## What is captured

`build_reveal_lineage_rows_stage.py` composes the unchanged original-invocation
transport with a private bounded journal. Every admitted event references the
immutable PRODUCER receipt, which in turn references its QUERY, borrowed job
and original renderer/initial enqueue invocation. It does not recover ancestry
from a current view name, list address or reused native frame.

Three additional source-hash-gated hook pairs capture four event kinds:

- `0x6ED6E8`: ROW after the original indirect append runs exactly once, before
  the native row ordinal increments. Its original delay slot still forms the
  descriptor pointer at the original producer stack.
- `0x6ED704`: TERMINAL records the actual SQL-step result before the original
  statement reset overwrites it. The wrapper calls reset `0x5C31C0` once and
  records its actual return in a separate RESET event.
- `0x6ED7D4`: END records the actual producer return, then replays the displaced
  saved-fp/s7 loads. The hook is nonlinking because native RA is already restored.

`0x5C31C0` is **reset, not finalization**. The distinct statement-finalize
`0x5C30E0` occurs later in the query wrapper and is not captured. Native reset
return 19 follows the same stock branch as zero, but this decoder conservatively
rejects 19. All actual native results, registers and HI/LO are preserved; journal
failure does not change the native append, reset or producer result.

The source contracts pin normal END reachability through receipt initialization.
Early NULL-argument guards use a separate epilogue; bind failures can reach END
without TERMINAL/RESET. Those failures cannot acquire an invented SQL success.

## Admission, bounds and publication

`reveal_lineage_rows_mips.py` rejects unsupported nonzero modes before reading
producer-frame, list-count or descriptor payload. Mode zero with an unbound ID
is ignored. A nonzero ID must validate as a published private PRODUCER with the
exact frame, statement, destination and original offset. Existing lineage
validation retains the original invocation rather than consulting live V/P.

Only after those checks does capture read native list count at `dest+0xC`.
ROW additionally copies raw signed-cue bits from producer `sp+0x444` and a
bounded UTF-16LE path from `sp+0x24`. At most 260 code units are inspected;
at most 259 are copied. A nonzero 260th unit marks truncation without reading
the adjacent field. The decoder rejects truncation and malformed UTF-16.
No native object is written or retained by these capture routines.

The journal has a 16-byte header and 1,024 non-reused 592-byte slots by default.
Reservation uses at most eight LL/SC attempts. Exhaustion, association mismatch
or allocation/retry loss sets a permanent fault; there is no wrapping, slot reuse
or fallback. Missing, duplicate or misordered captured events are separately
rejected by the decoder; omitted native hooks are not independently detected.
All payload precedes `sync` and magic-last publication. Both lineage and journal
fault state invalidate previously published diagnostic history. This ordering
does not itself establish coherent external acquisition or native ownership.

Each slot contains sixteen u32 words: magic, kind, producer ID, sequence,
frame, statement, destination, mode, offset, ordinal, actual result, cue,
truncated flag, list count, origin ID and a reserved zero word. A 260-unit path
area starts at byte 64; unused path/tail bytes remain zero. Numeric event kinds
are ROW=1, TERMINAL=2, RESET=3, END=4.

## Strict offline interpretation

`decode_reveal_lineage_rows.py` accepts only an already-owned byte string in
`lineage-rows-bss-v1` format: the complete private lineage buffer immediately
followed by the complete journal. Capacities are explicit, not guessed from
native pointers or magic. There is no device reader or telemetry exporter.

Structural checks reject faulted headers, holes/unpublished allocated slots,
nonzero unused space, invalid kinds, wrong source sites, broken ancestry,
incorrect inherited origin/V/P, query/borrow job and stack mismatch,
producer/query job/window/destination and stack mismatch, event association
mismatch, unknown modes, truncation and noncanonical string/padding bytes.

Events are grouped by exact producer ID, never frame/list/path equality. Every
producer receipt appears, including one with no events. An observed complete
window requires all of the following in order:

1. Zero or more ROW events with ordinals 0..n-1, append results equal to their
   ordinals and counts 1..n; nonempty, unique exact `(path, cue)` identities.
2. Exactly one TERMINAL with SQL result 101 and ordinal/count n.
3. Exactly one RESET with result zero and ordinal/count n.
4. Exactly one END with actual return n and ordinal/count n.

Negative or excessive window bounds, n exceeding the requested limit, failed
append/reset/SQL, missing/duplicate/reordered events or anything after END
leave the window incomplete. Empty successful windows are valid observations.
Semantic failure does not silently retry under the same producer.

Even a complete window is explicitly `observed_window_only`, not a whole
folder or current ready-row publication. Initial list count, query scope,
row-parent relationship, folder total, later wrapper finalization, capture
coherence and mutations after capture are not certified. Raw native addresses
remain diagnostic scalars, not lifetime leases. The decoder always reports
`autoscroll_authorized=False`; it never constructs host `CompletedRows`.

## Saved candidate and local checks

Git-ignored local artifact, **not installed**:
`artifacts/hiby_player_1.4_sortfix_fullnav_wake_lineage_rows_stage_v1_20261019.bin`.

- Size 7,149,012 bytes; SHA-256
  `408163fd6c2d529df2e04976b89e1b9c39f36dbba679dc5fb9520365bc133a81`.
- Appended RX code 5,588 bytes at `0xC80000`, file offset `0x6D0000`.
- Private BSS 671,776 bytes at `0xBD4000`: lineage 65,552 bytes, then journal
  606,224 bytes at `0xBE4010`. This larger layout is not hardware-validated.
- Saved-file deterministic verification passed: 69 changed original-file bytes,
  confined to nine hook pairs, two stride words and declared ELF-header spans.
  The 708-byte prefix copies remain unchanged; internal element stride is 712.
- Verifier inventories only the original query/reset direct calls, original
  indirect append once, and declared native continuations. No added SQL, view
  lookup, list getter, timer, refresh, UI setter, I/O or installer.

All 68 new focused checks pass: 23 journal-core, six hash-gated source,
17 decoder, 17 emitted-hook integration and five image-verifier tests.
Integration runs actual emitted lineage/capture instructions and decodes their
bytes; query/append/reset bodies are hostile-ABI stubs with explicit fixtures,
not a real SQL engine. Core cases cover full capacity, LL/SC interference,
fault injection, native-read gates, signed cue, path bounds and ABI preservation.
Image tests also pin the previous lineage-only output's exact SHA-256
`f31239aa544c55959e9f75686a421489c8ea6d91e1ef6d30b01955d8c75ec139`.
Independent read-only review found no further actionable defect.

Full repository regression: **874 tests pass, no skips** (169.922 s), including
all 68 new checks. It ran with local temporary-file access, without changing
legacy tests or using a real device transport. All 126 Python scripts compile;
tracked and new text files pass whitespace checks. These remain bounded
emulator/source/model checks, not target CPU, scheduler, cache or live ownership
certification.

## Remaining gates

This diagnostic path does not yet feed the host staged-row API. Native retained
view/list lifetime, complete prefix-writer/cancellation coverage, contents-phase
and playback-generation binding, coherent cross-thread acquisition/delivery,
recognized input and the final owned UI setter plus refresh remain open. The
first synchronous Files fill is still outside worker-lineage admission. The
new native reads, extended layout and timing require separate hardware review.

No launch instructions or device transport are added here. A future physical
trial still requires an ended instruction turn, fresh user readiness, one
authorized launch and waiting for the user's report. Automatic reveal remains
disabled, independently of whether a local journal window is complete.

## Known-boundary follow-up (2026-10-20)

The separate [contents-revision filter](folderfollow-reveal-contents-revision-stage.md)
now observes eight known pre-mutation entry/attempt boundaries and freezes a
producer-start revision. Later known entries reject its historical evidence;
equal revisions still prove neither settled contents nor native ownership.
Normal postfill/bind also conservatively invalidates the window. Both earlier
default image outputs remain byte-identical; neither new nor old candidate was
installed or launched during this follow-up.
