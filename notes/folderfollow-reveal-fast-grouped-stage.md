# General and synchronous same-file grouping: offline stage

2026-10-15. Extended the [general grouped guard](folderfollow-reveal-grouped-stage.md)
with a separate same-file descriptor-block boundary. This remains an intermediate
guard-only ELF. No coherent final identity, full-row publication, UI setter or
active autoscroll is connected. No device access, install, arm, launch, reboot,
commit or push occurred during this step.

## Exact local artifact

`artifacts/hiby_player_1.4_reveal_fast_grouped_guard_stage_20261015.bin`

- Size: 7,147,040 bytes.
- SHA-256: `0c587656d2bd169b6763bebf8ddf0f1103f65275b46e1f43f6604718e7f23d72`.
- Appended code: 3,616 bytes at `0xBE0000`, file offset `0x6D0000`.
- Private state: 24 bytes at `0xBD4000`, plus segment alignment padding.
- 80 original-file byte changes relative to normalized golden sort/fullnav/wake,
  inside thirteen declared hook pairs and the required ELF header fields.
- Separate RW and RX loads; no RWX segment. No diagnostic I/O or installer.
- The October 13 default and October 14 general-grouped modes still reproduce
  their respective `c8b6d954...` and `cce0d3dd...` files byte-for-byte.
- This specific image is **UNTESTED on hardware**, and does not match the
  installed passive bridge launcher hash. Do not substitute it into that launcher.

Reproduce locally; output overwrite is refused:

```powershell
python -X utf8 scripts/build_reveal_guard_stage.py artifacts/import-20261001/hiby_player_02fd.bin artifacts/hiby_player_1.4_reveal_fast_grouped_guard_stage_20261015.bin --fast-grouped
python -X utf8 scripts/verify_reveal_guard_stage.py artifacts/import-20261001/hiby_player_02fd.bin artifacts/hiby_player_1.4_reveal_fast_grouped_guard_stage_20261015.bin --fast-grouped
```

`--fast-grouped` includes general grouping. The Python API requires both
`grouped=True` and `fast_grouped=True`; unsupported/non-boolean combinations
and active reveal are rejected. Old command lines retain their old output.

## Why the narrow same-file block is different

The [same-file audit](folderfollow-reveal-fast-boundary.md) establishes that
function `42CAC0` has two unframed early-return paths and framed asynchronous
fallbacks that return zero without executing the fast copy. Instrumenting its
literal entry/shared return as a fixed-frame successful commit would be wrong.
Two worker callers explicitly select fallback with mode `0x10002`; this build
does not label those invocations as synchronous commits.

The new entry at `42CBD4` is after the existing frame and compatibility checks.
It restores the two displaced argument-setup instructions, then reaches the
already-guarded copy at `42CBDC`. Entry does not allocate another stock frame.
The new exit at `42CC20` follows source processing, the optional descriptor
callback and event posting. It replays the old branch delay-slot effect once,
then resumes `42CB68`. The trailing bounded backing-path copy is disjoint from
the current descriptor. All bounded normal routes through this narrow block
reach that exit; indirect entries and nonlocal/nonreturning calls remain limits.

The scope owner now includes a kind at private offset 20:

| Kind | Entry/frame token | Admitted inner identity writes | Outcome meaning |
| --- | --- | --- | --- |
| 1, general | `42CC60`, entry SP minus `0x1DD0` | Three general copies and exact nested preparation helper | Original result 0/-1 at `42D6E4` |
| 2, synchronous block | `42CBD4`, unchanged current SP | COPY with return `42CBE4` and this exact SP | Synthetic zero means only block completion |

Each still needs its own matching non-reused scope ticket. Equal SP alone,
or a known return PC in the wrong kind, cannot adopt another invocation.
Preparation is not admitted as a same-file child. Recursive or competing
entries permanently fault without replacing the original owner; original
stock calls/stores still run once. Every exit checks the kind as well as frame,
ticket and raw mutation state. No extra stock pointer read or lock was added.

At the fast exit, stock v0 is the event helper's result, **not** a checked
playback result. It is preserved byte-for-byte even if nonzero/negative.
Private synthetic zero must not be mapped blindly to the host coordinator's
`succeeded=True`: it neither proves audible playback nor authorizes reveal.
Outcome and scope kind must be interpreted together; neither is a copied
identity, a stable reader snapshot or a UI permission.

Scope READY retains the previous historical-completion contract. It can
coexist with later raw WRITER/READY state; it is not a reader lease or currentness
certificate. No consumer of these state words is introduced in this stage.

## Final-identity audit: no shortcut through the stock getter

The [player-lock audit](folderfollow-reveal-player-lock.md) resolves the stock
mutex and actual ELF imports. Public getter/setter and all four direct
same-file callers use B+`0x44`. Initialization supplies null mutex attributes;
wrappers discard lock/unlock results. Adding the getter inside an already-locked
setter/same-file hook could reacquire the same non-established-recursive mutex.
That is a deadlock risk, not a coherent-copy solution.

The general commit has no established bracket using this mutex, full clear
occurs after its helper unlocks, and initialization clears the descriptor before
creating the mutex. Therefore the getter's lock cannot certify all relevant
writers. Narrow post-copy/pre-unlock sites are recorded for future work, but
none is a universal authoritative final sample. No new getter or lock call
was inserted into the firmware.

A further bounded search did not resolve the B+`BA0` descriptor callback target.
No additional callback-binding file was created because absence of a direct
slot store is not proof that the callback stays null. The escaped-pointer gate
from the earlier audit remains open, independently of these known hook sites.

## Validation and next boundary

Full repository validation: **658 tests pass, no skips** (99.516 s), including
36 added tests. All **103 Python scripts compile**. Tracked and new source
files pass whitespace checks.

The saved artifact passed the deterministic standalone verifier. Seventeen
new emitted-code tests exercise stock ABI/HI/LO and delay-slot preservation,
arbitrary fast-exit v0, general clear/recopies, alternating kinds/tickets,
wrong kind/frame/entry, overlap, foreign writers, raw busy/fault, sticky finish
invalidation, bounded contention, malformed modes and artifact tampering.
Independent read-only review found no actionable preservation/grouping defect.

Nine new exact-reference tests cover the complete same-file body and narrower
block, its direct caller/entry inventory, early returns/fallbacks, disjoint
trailing copy and unchecked exit result. Ten further tests cover actual mutex
imports, initialization/results, concrete caller brackets and incomplete writer
coverage. These are bounded offline checks, not whole-program alias analysis,
target memory-ordering, hardware timing or retained-object proof.

Next: establish a separately validated final-copy protocol against all relevant
writers and lifecycle events, then connect complete rows/cancellation inside a
retained non-render UI transaction. The fast path's block-completion result must
not be promoted to success eligibility without its own contract. No player test
is requested now. Any future test still follows instructions, an ended turn,
fresh explicit readiness, one launch, then waiting for the user's report.
