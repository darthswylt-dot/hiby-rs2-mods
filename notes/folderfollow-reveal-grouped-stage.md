# Grouped playback guard: offline firmware stage

Follow-up, 2026-10-15: a separate [fast-grouped successor](folderfollow-reveal-fast-grouped-stage.md)
adds the synchronous same-file descriptor block and explicit scope-kind checks.
This artifact remains unchanged; neither version enables active reveal.

2026-10-14. The general track-change entry and common exit now bracket its
preparation clear and repeated descriptor copies in emitted MIPS code. This
is a successor to the [single-mutation guard](folderfollow-reveal-guard-stage.md),
not a complete autoscroll implementation. It publishes completion history only,
not a copied current-track identity or permission to modify a live list.
Active reveal is explicitly refused. No player access, installation, arming,
launch, reboot, commit or push occurred in this step.

## Exact local artifact

`artifacts/hiby_player_1.4_reveal_grouped_guard_stage_20261014.bin`

- Size: 7,146,352 bytes.
- SHA-256: `cce0d3ddb5fbee1284f1e47ed6976421b78a9f7b882caea8f363b9a9998a4e57`.
- Appended code: 2,928 bytes at `0xBE0000`, file offset `0x6D0000`.
- Private state: 20 zero-initialized bytes at `0xBD4000`, plus segment alignment
  padding. Separate RW and RX segments; no RWX load.
- 65 original-file bytes changed within eleven declared hook pairs and two
  required ELF header fields, relative to normalized golden sort/fullnav/wake.
- Default builder mode still reproduces the October 13 `c8b6d954...` artifact
  byte-for-byte. Both artifacts remain separate and ignored by Git.
- Hardware loader, timing and memory-ordering behavior: **UNTESTED**.

Offline build and verification (the builder refuses to overwrite output):

```powershell
python -X utf8 scripts/build_reveal_guard_stage.py artifacts/import-20261001/hiby_player_02fd.bin artifacts/hiby_player_1.4_reveal_grouped_guard_stage_20261014.bin --grouped
python -X utf8 scripts/verify_reveal_guard_stage.py artifacts/import-20261001/hiby_player_02fd.bin artifacts/hiby_player_1.4_reveal_grouped_guard_stage_20261014.bin --grouped
```

The preserved source has SHA-256
`02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87`.
This does not stack with the installed passive bridge or match its launcher
hash. There is no installer or diagnostic I/O in this stage.

## Exact operation boundary and ownership checks

The [complete bounded function audit](folderfollow-reveal-logical-boundary.md)
found entry `42CC60`, fixed stock frame G of `0x1DD0` bytes, and common
epilogue `42D6E4` on every normal return. Results are exactly 0 or -1.
The new entry/exit hooks replay their displaced instructions once and preserve
the stock stack frame, saved return address, return value, registers and HI/LO.
No extra frame or changed return address survives for the whole stock call.

The 20-byte state holds raw-mutation guard, logical-scope guard, owner G,
non-reused owner ticket, and outcome (-2 pending, 0 success, -1 failure).
Both guards use the bounded, sticky-fault LL/SC implementation. An overlapping
entry cannot replace the earlier owner. Abnormal/nonreturning invocation never
completes merely because a timer expires; there is no recovery/reset here.

Every known raw writer acquires its raw guard BEFORE scope classification.
The entry acquires its scope guard BEFORE checking raw state. This ordering
avoids admitting both sides from pre-acquisition observations of EMPTY.
Classification happens before the instrumented stock identity mutation:

- General copies require writer kind COPY, original return PC `42CD64`,
  `42CF8C` or `42D3A0`, exact original SP=G and matching active scope ticket.
- Preparation requires kind PREPARATION, current helper SP+`0x20`=G and its
  live saved incoming RA at helper SP+`0x1C`=`42CD40`. The live RA register
  is not sufficient, because an intervening call has changed it.
- Other known writers invalidate an active scope before their identity write.
  Stock work still runs once even after any instrumentation fault.

The owner G is compared only as a scalar, never used as a retained pointer.
The one added stock read is from the currently executing preparation helper's
owned stack frame. There are no new descriptor/source/UI object reads.
This bounded dynamic-frame evidence assumes conventional disjoint stacks,
normal ABI and no nonlocal unwind/interior entry; it is not a universal
thread identity or lifetime proof.

A regression test caught a shared-return-whitelist bug: preparation could
mistakenly accept a copy return PC. Explicit writer-kind discrimination now
separates these classes. Tests also reject inverse copy/zero confusion,
wrong frames, missing entry and unrelated preparation callers.

At exit, the current frame, scope ticket/state, raw state and stock result
are checked. Only exact 0/-1 results are recorded, before matching completion.
Unknown outcome or mismatch faults the scope without altering stock behavior.
A failure may leave a nonempty descriptor: completion does not imply playback
success or an automatic rollback.

## Completion history is deliberately not currentness

Scope READY is historical. A foreign raw writer may begin after the exit's
raw-state check, then reach scope classification after the scope finishes.
It sees READY rather than an active scope and leaves that historical ticket
intact. An emitted-code interleaving test demonstrates scope READY coexisting
with the later raw WRITER and then later raw READY. This is not a lock, reader
lease, coherent snapshot or no-overlap-at-BEGIN certificate.

No consumer is attached to these state words. A future identity protocol must
cover every relevant writer and atomically relate its copied value to ordering,
outcome and cancellation; checking these two guard words once is insufficient.
The host [deferred publication API](folderfollow-reveal-coordinator.md) models
that already-owned final value, but does not obtain it from the stock player.

## Static follow-up and remaining gates

The [pointer-consumer audit](folderfollow-reveal-pointer-consumers.md) separates
concrete readers and source copies from writers. It does not establish complete
alias coverage: the player callback target at B+`BA0` remains unresolved,
and interior metadata pointers still escape to indirect UI methods.

The [non-render refresh audit](folderfollow-reveal-nonrender-boundary.md) finds
a queued refresh at `452F9C`, but its view lookup releases the registry before
use. The apparent playback-adjacent producer is PNG-resource completion, not
an established event for every Next/autoplay. No lifetime-safe UI transaction
or exhaustive scheduling trigger has been proven. No new timer, forced refresh,
raw offset store, UI setter or worker lock was added.

Next work remains coherent final identity with complete relevant-writer
coverage, logical boundaries for other playback routes, complete row/lifecycle
publication and a retained non-render UI transaction with complete cancellation.
This intermediate artifact is not proposed for a hardware test. Any later
authorized test still requires instructions, an ended turn, fresh explicit
readiness, one launch, then waiting for the user's report without automatic
rearming or extending the watchdog.

## Validation

Full repository validation: **622 tests pass, no skips** (82.943 s); all
**100 Python scripts compile**. Tracked and new source files pass whitespace
checks. Independent read-only review found no concrete ABI/grouping defect;
its historical-completion interleaving concern is retained as a test above.

The saved artifact passes the standalone deterministic verifier, including
instruction/transfer inventory, exact hook bytes, private-memory extent,
separate load permissions and undeclared-change rejection. Sixteen grouped
emitted-code tests cover entry/exit ABI, intermediate clear and three copies,
failure outcomes, reused frames with new tickets, wrong provenance, overlap,
foreign mutations, sticky invalidation, bounded contention and the historical
completion race above. The nine original wrapper tests remain unchanged in
their expectations; the earlier image hash is pinned.

Thirty-one new static tests pin the logical boundary (11), pointer consumers
(10) and non-render refresh routes (10). Seventeen new host tests cover the
deferred final-publication/outcome protocol. These checks do not establish
target CPU memory ordering, hardware loader behavior or whole-program safety.
