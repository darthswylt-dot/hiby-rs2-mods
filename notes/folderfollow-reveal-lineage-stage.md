# Native job-lineage transport (2026-10-19)

Implemented as a **separate offline intermediate MIPS ELF**, not another host
registry or an installable autoscroll fix. No device access, installation,
launch, signal, rearm or reboot. It does not enable the host coordinator or
combine the earlier playback mutation/grouping stage with this job stage.
The [provenance audit](folderfollow-reveal-provenance.md) supplies its anchors.
Native object lifetime and complete writer coverage remain open.

## Extended copies, unchanged stock fields

The V-resident template and its prefix copies remain exactly `0x2C4` (708)
bytes. Four more source bytes would read `V+0x3B68`, the actual P field, not
spare template storage. The builder never widens these source reads.

Only master/work list element-size arguments `0x48F3BC/3CC` become `0x2C8`
(712). The final word at offset `0x2C4` is a private origin ID. Both local
enqueue records explicitly initialize it, including zero for unsupported
origins/failures; it fits before saved registers. Stock offsets are unchanged.
Generic native list operations use their element size and carry the tail with
the record, including insertion, master-to-work copying and record movement.
There is no pointer-keyed sidecar registry that could relabel a reused address.

Zero means unsupported, not current/default owner. Unknown Files routes,
including shared creation `0x4936DC` and `0x49B730`, never acquire a renderer
ID from a matching name/pointer. Their zero tail cannot support a later Files
query. Stride stays 712 after ledger failure; reverting it would corrupt the
already allocated lists.

## Private non-reused receipts

The leaf MIPS core uses a 16-byte header and 1,024 immutable 64-byte records
(65,552 private BSS bytes). One-based IDs never repeat. Allocation has at most
eight LL/SC attempts. Invalid ancestry, unissued/unpublished IDs, exhaustion or
contention loss permanently fault it. No reset, runtime allocation, external
call, native dereference or stock mutex is added by the core. Allocator stores
cannot erase fault. Wrappers fill payload, execute `sync`, publish `LNRG` magic
once; readers check published ancestry and global fault state.

| Kind | Captured association | Parent |
| --- | --- | --- |
| Render origin | Original numeric V/P before template mutation | none |
| Initial origin | Known private initial enqueue's copied V/P before append | none |
| Borrow | Exact returned work-record address and worker frame | origin ID |
| Query | Original borrow and actual query destination/window | borrow ID |
| Producer | Original query and actual statement/list/window | query ID |

Descendants inherit original V/P and origin ID from private parents, not name
lookup. Renderer invocation can fan out to shared/private enqueue and a master
can be recopied for later windows. Origin is NOT a unique work-copy/SQL-fill ID;
borrow/query/producer each get a new ID. Numeric V/P are not native owner epochs,
retained objects, coherent template bytes or contents generations. Matching
tail cannot detect prefix-only mutation; validation is not a UI lease.

## Six native wrappers

- `0x490758`: mint before the first template copy; save ID in unused native
  renderer `sp+0x14`, outside O32 homes/before saved registers.
- `0x48F1D0`: zero local tail after unchanged prefix copy/resolver. Only return
  PCs `0x490814/880` and matching original frame/template/copied V/P carry its
  origin. Original RA is enqueue `sp+0x2EC`; renderer scratch is `sp+0x304`.
- `0x48F40C`: zero local tail. Only constructor return `0x492A38`, Files
  callback and consistent source mint INITIAL. This enqueue origin is later
  than, and does not certify, the first synchronous Files fill.
- `0x48EB40`: capture at nonnull work borrow, publish BORROW and save ID in
  worker `sp+0xAA0`, after its exact descriptor/before saved registers. Later
  callbacks use that receipt, never current job-address/name lookup.
- `0x48D1B8`: require callback return `0x48EC5C` before reading worker receipt;
  check exact job address/frame, original tail and numeric V/P against actual
  stock call. Fault on mismatch. Keep QUERY in our wrapper, rehome fifth
  argument at our `sp+0x10`, call real `0x6F7CA0` once, preserve actual result
  registers and HI/LO, return to original continuation even on lineage failure.
- `0x6ED624`: admit physical-query return PCs `0x6F8BF4/E0C`. Require query's
  saved return to equal our emitted `query_native_return` before reading our
  private frame. Check marker/query ID/original frame/list/offset/limit/mode0;
  publish PRODUCER and save ID in unused producer `sp+0x18`.

Displaced instructions/delay slots remain exact. There is no extra query, view
lookup, list getter, UI setter, refresh, timer, export or I/O. Failures suppress
lineage only; stock continues. Host staged-row API is not invoked and no ready
rows are published. Extended stamps do not implement cancellation or revoke
completed host proposals.

The new tail read at stock borrow is itself a native read. In bounded source,
storage has patched size, known cancellation clears count without freeing bytes,
and the inspected work appender is this worker. This is not global alias/lifetime
proof: previous startup/teardown/wake-object limits remain. Hardware safety of
reads/timing and retained UI ownership are still deployment gates. Source tests
pin direct frame uses, not arbitrary callees or every indirect entry.

## Offline verification and remaining gates

Builder accepts exact `02fd...` reference or normalized golden via the existing
hash gate; refuses active reveal/output overwrite. Verifier reconstructs exact
output, checks six hook pairs/two stride words/ELF-header patch scope, unchanged
708-byte prefix-copy lengths, separate RX/RW extents and external transfers.
Only emitted external call is the original query; other hooks resume native PCs.

This is not hardware, loader, concurrency, UI lifetime or autoscroll validation.
No launcher/install command is provided or armed. Active integration still needs
contents/playback generation binding, complete invalidation, loss-free rows,
recognized input and owned setter plus refresh. Future device trials require
instructions in an ended turn, fresh explicit readiness, one launch, then waiting
for the user's report.

## Saved local candidate and checks

Git-ignored, **offline intermediate only**:
`artifacts/hiby_player_1.4_sortfix_fullnav_wake_lineage_stage_v1_20261019.bin`.

- Size 7,147,220 bytes; SHA-256
  `f31239aa544c55959e9f75686a421489c8ea6d91e1ef6d30b01955d8c75ec139`.
- Appended RX code 3,796 bytes at `0xBF0000`, file offset `0x6D0000`.
- Private BSS 65,552 bytes at `0xBD4000`; 56 changed original-file bytes,
  all within declared hook/stride/ELF-header spans.
- Saved-file deterministic verification passed; no deployment.

An earlier local build preceding exact-job/frame consistency checks is retained
as `artifacts/hiby_player_1.4_sortfix_fullnav_wake_lineage_stage_obsolete_20261019.bin.disabled`,
not the current candidate. No historical firmware artifact was overwritten.

All 48 focused checks pass: 21 emitted-core/LL-SC tests, seven hash-gated
source/frame contracts, 16 emitted-image/native-list integration tests and
four saved-image verifier tests. Integration executes actual native list
constructor/append/index/growth bodies for 21 records, with copied tails across
segmented growth and master/work transfer, then exercises the full stamped
origin-to-producer chain. It also checks both SQL return sites, private initial
origin, unknown ingress, same-origin/different-job and frame mismatches, reused
job addresses, orphan/failed allocation, hostile O32 home-word/volatile/HI-LO
clobbers, original query once, fifth argument and actual query result.

Independent review found a missing exact borrowed-job comparison; it was added
alongside original-frame checks and regression tests before the saved candidate.
Review of the corrected wrappers found no further actionable defect. All 117
Python scripts compile and whitespace checks pass. These checks remain bounded
instruction/source tests, not target CPU/scheduler/cache or object-lifetime proof.

Full repository regression: **806 tests pass, no skips** (134.251 s), including
the 48 new checks. The first sandboxed run failed on legacy tests' temporary
file/cleanup permissions, including fixtures beneath `artifacts/`; the repeat
with local test filesystem access passed. No test used a real player transport.
No source was changed to suppress those failures or skip tests.
