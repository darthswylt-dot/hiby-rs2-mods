# Known contents-boundary revision filter (2026-10-20)

Separate **offline diagnostic intermediate**, following the
[provenance-bound row journal](folderfollow-reveal-lineage-rows-stage.md).
This adds negative evidence: a later instrumented entry invalidates older
producer observations. It does **not** establish a settled contents generation,
associate the exact original job with a contents phase, publish host ready rows
or authorize the UI. No device access, installation or launch occurred.

## Eight bounded source hooks

`build_reveal_contents_revision_stage.py` composes the earlier lineage/row
capture with a private monotonic revision counter. Each hook bumps it before
replaying the original pair and continuing stock code. It performs no native
object lookup, read, retention or list write to produce this notification.

| Source pair | Entry/attempt observed before native effects |
| --- | --- |
| `0x4906F8` | Guarded renderer prologue, before template changes/rebinding |
| `0x48D080` | Files worker callback, before auxiliary/main list clears and refill |
| `0x491240` | Reset entry, before old-list reads/frees |
| `0x4919E0` | Depth reconciliation, before scope writes/common reset |
| `0x494A00` | Named reset entry, before resolution and old-list frees |
| `0x493B0C` | Nonnull close/navigation attempt, before closing-marker store |
| `0x48F880` | Post-fill callback entry, before resolving and binding again |
| `0x4A0EE0` | Panel-list binding entry, before the binding store |

These are **known entry notifications**, not successful mutation or completed
destruction. The close attempt can navigate to a parent and return without
destroying the view. Known ordinary nesting exists, including named reset,
close/navigation and depth reconciliation. Therefore every nested entry
increments independently; a strict nonnested BEGIN/finish guard is not used.
NULL/no-op/failed paths and other owners can conservatively invalidate history.
No return path clears, rearms or declares the counter READY.

The worker's optional auxiliary clear at `0x48D120`, auxiliary append through
`0x48D040 -> 0x48CC80 -> 0x48CD34`, and main clear `0x48D170` all precede the
query at `0x48D1B8`. A query-start stamp alone is not a pre-mutation epoch.
One renderer can enqueue multiple jobs, and master/work copying can repeat an
origin. Neither original-render identity nor native Files return means one
complete contents transaction. Postfill resolves V by name again and binds
through P+0x410; that is still outside a retained-owner proof.

## Private counter and immutable producer samples

`reveal_contents_revision_mips.py` owns sixteen initially zero BSS bytes:
one revision word and three reserved zero words. `bump()` issues 1 through
`0x7FFFFFFF` via bounded LL/SC. Zero is the initial observation, not readiness.
Malformed state, exhaustion or eight unsuccessful reservation attempts make
`0xFFFFFFFF` a permanent fault. `invalidate()` also faults permanently.
No ordinary store can roll the counter back or erase a fault. The leaf core
preserves O32 callee-saved registers, SP, RA and HI/LO and has no stack access,
native pointer, allocation, external call, timer or I/O.

The optional producer extension freezes the private revision at native
`0x6ED624`, in immutable PRODUCER receipt byte 56, before its existing magic-last
publication. It is a **producer-start sample**, not a transported original
renderer epoch. An old job beginning after reset can sample the new revision;
that limitation is deliberately not hidden by renaming it a content handle.

The corresponding optional capture core checks that immutable sample against
the current counter after private producer/frame validation, before additional
offset/count/descriptor payload reads, again before count, and before event
publication. A mismatch or fault permanently faults row capture, without
suppressing any stock append/reset call or changing its actual result.
Event byte 60 mirrors its producer's frozen sample; callbacks never replace
it with a newer revision. The optional leaf frame is 0x50 bytes, keeping the
sample at +0x40 outside argument homes, native memory and saved state.

A known entry after the final check can still precede magic publication.
This is not a lease: a final coherent owned snapshot's newer counter makes
that historical window unacceptable at decoding. The collector cannot undo
native reads that have already happened; it does not claim pointer lifetime.
An event fault suppresses publication, not the original native mutation.

## Distinct strict snapshot format

`decode_reveal_contents_revision.py` accepts exactly
`lineage-rows-content-revision-v1`: complete lineage BSS, complete row journal,
then the sixteen-byte revision state. Capacities are explicit. It validates
the final counter/reserved words, producer-only extension, sample bounds and
every exact producer/event mirror. In an owned temporary copy only those two
versioned fields are cleared before delegating to the earlier strict decoder.
No unrelated reserved field, unallocated slot, ancestry, event ordering,
SQL/reset result, count, string or padding check is bypassed. Input bytes are
not modified; the legacy decoder still rejects nonzero extension fields.

Each producer reports its original `observed_window_complete` separately from
`known_boundary_unchanged`. `complete` becomes false with reason
`known-contents-boundary` if a later known entry exists. Both top-level and
per-window `contents_current` and `coherent_capture` remain false, and
`autoscroll_authorized` is always false, including when revisions agree.

**Ordinary successful Files flow also enters postfill and panel binding after
producer END. Those entries intentionally invalidate this diagnostic window.**
This stage is consequently not a usable ready-row publication gate, even on
an otherwise quiet normal path. It does not silently exempt postfill as a
trusted completion; exact invocation/owner/phase association is still needed.

Equal samples exclude only an additional *observed* entry between samples.
They do not exclude an earlier writer still running, a stale job starting
later, missed/indirect aliases, mixed-owner histories or mutation after capture.
There is no operation completion, writer-coverage, current-list or lifetime
certificate, and no connection to host `ContentChangeHandle`/`CompletedRows`.

## Saved local intermediate and verification

Ignored local file, **not installed or hardware validated**:
`artifacts/hiby_player_1.4_sortfix_fullnav_wake_contents_revision_stage_v1_20261020.bin`.

- Size 7,151,032 bytes; SHA-256
  `f4284cb5adf77111d9c114c4c8889c7cb95eefec5e50c757a21544e8568603ac`.
- Appended RX code 7,608 bytes at `0xC80000`, file offset `0x6D0000`.
- Private BSS 671,792 bytes at `0xBD4000`: lineage 65,552 bytes, journal
  606,224 bytes at `0xBE4010`, revision sixteen bytes at `0xC78020`.
- Saved-file verification reconstructs exact bytes and checks seventeen hook
  pairs, two stride words, declared ELF changes, permissions and full extents.
  There are 126 changed original-file bytes. Prefix copies remain 708 bytes.
- External transfers remain only the original query/reset, indirect append
  once and declared native continuations; no new SQL, view lookup, UI action,
  synchronization repair, exporter or installer.

All 58 new checks pass: eighteen revision-core tests, eight source contracts,
fifteen decoder tests and seventeen emitted-stage/image tests. They cover
nested entries, LL/SC interference/fault injection, exhaustion, unchanged native
ABI/results/replay even on fault, before/during/after-capture invalidation,
ordinary postfill rejection, stale-start limitations, full storage overlap
rejection and strict image/format corruption. Actual emitted capture/lineage
instructions run, while SQL/append/reset bodies use explicit hostile-ABI stubs.

Independent review caught full-sixteen-byte interval and native MIPS jump-region
checks missing from the public composition helper; both were fixed and
regression-tested. The normal planned layout and saved candidate were
unaffected. Both preceding default outputs remain byte-identical: row journal
`408163fd...c133a81` and lineage
`f31239aa...c75ec139`. No historical artifact was overwritten.

Full repository regression: **932 tests pass, no skips** (170.376 s), including
the 58 new checks. That full run preceded the last helper-only jump-region
argument rejection; the final 58 focused tests were rerun afterward and passed
(6.077 s). The final saved image is byte-identical and reverified. All 134
Python scripts compile and tracked/new text files pass whitespace checks.
Tests used local temporary-file access, not a real player transport. These
checks do not prove target CPU, cache, scheduler, source coherence or lifetime.

## Next integration gate

The filter is a cancellation prerequisite, not the full contents binding
promised by a host phase. The next positive protocol needs an exact original
borrow-bound mutation invocation, pre-mutation revocation, matching completion,
recognized nesting/overlap and the same proven owner through postfill binding.
It cannot stamp current revision onto an old queued job or exempt a binding
because its folder/address happens to match. Playback generation, full-row
scope, coherent delivery and a retained UI setter/refresh transaction remain
separate gates. Automatic reveal stays off; no physical test is requested.
