# Firmware-connected mutation guard: intermediate build

Follow-up, 2026-10-14: a separate [grouped guard build](folderfollow-reveal-grouped-stage.md)
adds the general entry/common-exit boundary. The original artifact and checks
below are preserved; neither build enables autoscroll.

2026-10-13. A first protection component is now connected to stock MIPS
instructions in a real ELF. **This is not complete autoscroll integration**:
the reveal coordinator, copied identity/row publication and UI action are not
enabled. The builder explicitly refuses active reveal. No device access,
installation, arming, launch, reboot, commit or push occurred in this step.

## Exact offline artifact

`artifacts/hiby_player_1.4_reveal_guard_stage_20261013.bin`

- 7,145,148 bytes; SHA-256
  `c8b6d9544bfccf98375efb871029e5fbb6d292e17f3a198f2eaa06578b12749d`.
- 1,724 bytes of appended code at `0xBE0000`, file offset `0x6D0000`.
- Four private zero-initialized bytes at `0xBD4000`; RW growth also includes
  alignment padding, so this is not a four-byte total process-memory claim.
- 49 original-file byte changes, all within nine declared hook pairs and
  the two required ELF program-header fields.
- Base: normalized golden sorting/full-navigation/wake. The old code cave,
  timer callback and UI code are unchanged. This does not stack with the
  installed passive bridge, export its telemetry, or match its launcher hash.
- Hardware/loader/timing behavior of this specific layout is **untested**.
  The earlier bridge's successful loader test does not validate this image.

Build and verify without deployment (the builder refuses output overwrite):

```powershell
python -X utf8 scripts/build_reveal_guard_stage.py artifacts/import-20261001/hiby_player_02fd.bin artifacts/hiby_player_1.4_reveal_guard_stage_20261013.bin
python -X utf8 scripts/verify_reveal_guard_stage.py artifacts/import-20261001/hiby_player_02fd.bin artifacts/hiby_player_1.4_reveal_guard_stage_20261013.bin
```

## Connected operations

| Stock site | Operation | Preservation |
| --- | --- | --- |
| `42AC0C`, `42CBDC`, `42CD5C`, `42CF84`, `42D398` | Five known descriptor copies | Original memcpy once, arguments and post-call result preserved |
| `42DECC` | Full descriptor clear | Original memset once; original unrelated delay-slot store retained |
| `42B9DC` | Player initialization | Original memset once; original stack save occurs before wrapper frame |
| `429EF8` | Preparation path clear | Both displaced halfword stores once after BEGIN, resume `429F00` |
| `42AC68` | Potential scalar cue setter | Relocated store after BEGIN, original branch destination `42AB98` |

This is a known-site inventory, not complete mutation coverage. All original
operations still run on their original threads even if the guard faults.
There is no blocking stock lock, retry of stock operations or suppression of
playback. The guard accesses only its private state; wrappers save registers
on their own stack and do not add borrowed descriptor or UI pointer reads.

## Atomic guard contract

`folderfollow_reveal_guard_mips.py` emits 280 bytes of MIPS. One aligned
atomic word encodes EMPTY=0, READY=positive ticket, WRITER=high bit plus
positive ticket, and terminal FAULT=`0x80000000`. BEGIN atomically withdraws
readiness and returns a non-reused positive ticket. FINISH must match that
writer and atomically publish it. LL/SC retries are bounded to eight; overlap,
invalid completion, exhaustion or persistent contention faults permanently.
Initialization of the stock player does not reset the private counter.

SYNC surrounds transitions. Competing invalidation breaks the pending
reservation, preventing a later SC from restoring readiness. The terminal
encoding discards the old revision; unlike the host model it does not keep
incrementing after a fault. There is no recovery in this component.

READY means only **that instrumented mutation finished**. It is not a coherent
copied identity, a current-track certificate, a reader lease, a retained UI
object or permission to scroll. Another event can invalidate it before a
successful caller returns. This is why no setter is connected to READY.

## New findings that prevent premature activation

The previous capture instrumented only three descriptor copies. Further
inspection found `42CF84` after a source-processing call at `42CF68`, and
`42D398` on the general path's mode-3 branch. Both copy into the same current
descriptor. They are now guarded, with their distinct delay slots preserved.

The public property-24 getter also exposes the descriptor address through
its pointer-out argument (`42B068..074`), and indirect callbacks receive that
same address at `42CC0C` and `42D6A0`. These are definite pointer escapes, not
proof that a consumer writes through them. Their consumers must be classified
before this bounded inventory could be treated as all-relevant-writer coverage.

Preparation clears the path before a normal general commit, which may then
recopy it. Treating each operation as a completed stop/new-track event would
erase the policy baseline and suppress legitimate following. This guard
deliberately counts mutations, not logical track transitions; grouping and
coherent publication remain separate work.

For UI integration, using V/C only inside current refresh is narrower than
retaining a pointer from a timer. However, refresh `499C20` has eight direct
callers, including renderer callback `4908A0` via resource slot `+154`.
Changing the offset halfway through that drawing invocation is not yet an
established safe apply point. The stock setter also invalidates the parent;
replacing it with a raw C+18 store would omit that operation. No raw store,
recursive refresh or new timer lookup was introduced.

These playback and render anchors are retained in the hash-gated static
contract suites. The live gate therefore remains closed for concrete reasons,
not because a stable pointer/count or a single successful run is missing.

## Validation and remaining work

Full repository validation: **558 tests pass, no skips** (85.920 s); all
**96 Python scripts compile**. Whitespace checks pass. The saved artifact
passed the standalone verifier against the preserved source after building.

Seventeen emitted-guard tests cover LL/SC interleavings, invalidation at every
instruction boundary, sticky faults, non-wrapping tickets, ABI and private
memory-only access. Nine ELF/wrapper tests execute the bytes of the built
image, including all nine hook sites, original delay slots, hostile callee
clobbers, original calls after failure, inline stores and result preservation.
The verifier checks exact reproducibility, hook scope, separate RX/RW loads,
all emitted instruction/control-flow targets, and absence of extra stock reads
or UI calls. Independent read-only review found no concrete wrapper defect.
These checks are not hardware timing, cache ordering or whole-stock concurrency
proofs.

Next: classify escaped-pointer consumers and logical general-commit boundaries;
publish a coherent copied identity, then connect complete row generations and
cancellation to a specifically owned non-render UI transaction. The full
[host coordinator](folderfollow-reveal-coordinator.md) is not yet ported or
admitted into an active firmware path. This artifact is not proposed for a
player test. Any future test still requires instructions, a stopped turn,
fresh explicit readiness, one launch, and a stop until the user's report.
