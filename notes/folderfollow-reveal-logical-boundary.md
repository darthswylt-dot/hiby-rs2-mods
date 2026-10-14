# General playback commit: bounded outer grouping boundary

2026-10-14. Static audit of the complete original function `0x42CC60` through
`0x42DCA4` in `artifacts/import-20261001/hiby_player_02fd.bin`: 7,133,528 bytes,
SHA-256 `02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87`.
No device operation or binary change was performed by this audit. This extends
the [writer/provenance audit](folderfollow-reveal-playback-boundary.md) and
the [mutation guard stage](folderfollow-reveal-guard-stage.md).

## Result and scope

There is a concrete entry/normal-completion pair that encloses preparation,
all three known general-path copies, source processing and the descriptor
callback. Its original stack frame need not be moved or kept alive after
return. This is a **grouping boundary**, not proof of a coherent identity,
complete writer coverage, serialized threads or safe UI access.

The 1,042 instructions in `[0x42CC60,0x42DCA8)` are all reachable in a
conservative intraprocedural graph which treats calls as returning. There
are 141 direct calls, one indirect call at `0x42D6A0`, and exactly one
normal return at `0x42D70C`. There is no direct tail exit, branch-likely or
COP branch in this body. Every normal route to that return passes through
the shared epilogue at `0x42D6E4`. The graph says nothing about a called
function failing to return, nonlocal unwinding, signals or thread termination.

The incoming direct-edge scan uses the ELF's **SHF_EXECINSTR sections**:
`.init`, `.text`, `.MIPS.stubs`, `.fini` and `.plt`. It does not decode the
whole RX load as instructions; that load also contains strings that produce
false branch-like words. Within this explicit scope, the only external
direct edges into the body are `0x42E42C` and `0x42E598`, both to its entry.
There are no found direct entries to the interior or epilogue. Patching just
those two callers covers the observed direct callers, but is not proof of
all indirect entries. An entry hook also covers ordinary indirect entry at
`0x42CC60`; it does not establish that interior entry is impossible.

## Entry, frame and common epilogue

| Site | Original instruction pair | Grouping implication |
| --- | --- | --- |
| `42CC60` | `27BDE230`: `addiu sp,sp,-0x1DD0`; `AFB01DA8`: `sw s0,+0x1DA8(sp)` | Original general frame G is entry SP minus `0x1DD0` (7,632 bytes). Replay both once. |
| `42D6E4` | `8FBF1DCC`: `lw ra,+0x1DCC(sp)`; `8FBE1DC8`: `lw fp,+0x1DC8(sp)` | Common completion hook before register restoration; replay both and resume `42D6EC`. |
| `42D70C` | `03E00008`: `jr ra`; `27BD1DD0`: `addiu sp,sp,+0x1DD0` | The sole return restores the original caller SP in its delay slot. |

The function captures incoming a0 in fp (`42CC80`), a1 in s1 (`42CC84`),
a2 in s3 (`42CC90`), and ra at G+`0x1DCC` (`42CC98`). Its own instructions
change SP only at entry and the sole return. Callees must obey their stock
ABI and return with their caller's SP. The epilogue contains only restoration
loads and the return/pop; no descriptor mutation remains after `42D6E4` on
these normal routes.

An adapter can therefore leave the stock frame and saved return address
unchanged: use a temporary instrumentation frame, restore it completely,
replay the original entry/epilogue pair, and resume the original function.
Do not substitute ra, keep an extra wrapper frame for the whole invocation,
or change the caller's stack-item address. Preserve the original result
registers, HI/LO and all displaced effects through any instrumentation calls.

## Completion outcome is exactly zero or minus one

Success reaches `42D6DC` (clear B+`0xE0`) and `42D6E0` (set v0=0), then
falls into the epilogue. Four error edges instead set v0=-1 in their branch
delay slots before the same epilogue:

| Error edge / value assignment | Concrete path |
| --- | --- |
| `42DAFC` / `42DB00` | Source/service handling failure; B+`0xBA8` is cleared at `42DAF8`. |
| `42DB10` / `42DB14` | Null source after preparation; sets B+`0xD8`=3 and B+`0x18`=0. |
| `42DC64` / `42DC68` | Backend-open failure handling, including stop/retry/event routes. |
| `42DC6C` / `42DC70` | Mode-4 helper `442EC0` returned zero. |

The -12 constant at `42CC78` is not another function return. It initializes
the error-out local G+`0x1D8C` at `42CCB8`; that address is passed as a3 to
`431EE0` at `42D5F8`, `42D890` and `42DB2C`. Later direct loads at
`42DBB4` and `42DBD0` feed reporting. All normal returns overwrite v0 with
the explicit zero/-1 values above.

A non-null failure can leave the descriptor from the first copy present.
It is not an established playing-track transition merely because the copied
path is nonempty. Conversely, null-source failure occurs **after** the
preparation call at `42CD38`, so it may follow an actual path clear. A caller
must preserve the stock return value and distinguish failed completion from
successful publication. There is no audited rollback restoring the previous
identity. Treating every failed return as the previous track is unjustified.

## Inner operations and the original-frame discriminator

The first full descriptor copy is at `42CD5C`; additional copies are at
`42CF84` after source handling and at `42D398` on the mode-3 branch. Each
executes with the same original general frame G. The first two delay slots
set a2=`0xA88`; the mode-3 slot stores v0 at B+`0xBA8` and must retain that
separate stock side effect. The first copy is not the final logical boundary.

Preparation `429E80` has its own `0x20`-byte frame P and saves its original
incoming ra at P+`0x1C`. Its path clear at `429EF8` is conditional on
B+`0x18` being nonzero. It is nested in this specific general invocation
only when **both** of these exact conditions hold:

- P+`0x20` equals the active original general frame G.
- The saved word at P+`0x1C` equals `0x42CD40`, the return from `42CD38`.

The live ra register is not that evidence: the nested call at `429EE0`
has overwritten it before the clear. The other direct preparation callers
are `42C2B4` and `42E7D8`, with saved return addresses `42C2BC` and
`42E7E0`. Their clears must not be silently absorbed into a general commit.
Instrumentation must reconstruct **original** P/G after subtracting its own
temporary frame; it must not compare the instrumentation SP to G.

G is only a live dynamic-frame discriminator under conventional disjoint
thread-stack and ABI behavior. It is not a globally unique lifetime ID, a
thread ID, an ownership lock or proof against reused stack addresses. Bind it
to a non-reused active scope ticket; reject mismatches and overlap, and do
not overwrite the owner of a still-active invocation. A recursive general
call has a different G and must not be mistaken for a permissible nested
copy. An unrelated mutation must not be accepted simply because it uses a
known hook PC. Atomic coordination with unrelated writers still needs its
own instruction/interleaving tests; a load of scope readiness is not a lease.

## What grouping does not establish

At `42E42C`, a1 is a caller stack item; at `42E598`, a1 is the global
descriptor `0xADD468` itself. Both converge on s1 and the same copy sites.
Grouping does not make either source independently owned or coherent.

The function's indirect callback at `42D6A0` receives the global descriptor
in a1; it runs before completion and needs separate consumer classification.
Direct callees also process s1 (for example `52E7E0`, `4B16E0`, `433000`
and `432E20`). The graph does not model their aliasing, writes, callbacks or
retained pointers. Other known public copies, cue changes, initialization and
full clear remain outside this particular outer grouping boundary.

Failure handling can call a 2,000-ms delay at `42DC74` and the retry route
`42B200` at `42DC7C`. Helper `466E20` multiplies its argument by 1,000 and
calls PLT `A5B530` (the `usleep` relocation through GOT `A6F94C`). This is
not a short section in which a UI mutex may
be held. A stopped or nonreturning invocation must never restore readiness
merely because time passed. The current work does not add a live identity
reader, permit UI mutation or authorize a player test.

## Reproducible checks

`scripts/test_folderfollow_reveal_logical_contract.py` pins the full source
hash, explicit executable sections, direct entry inventory, complete bounded
intraprocedural reachability, sole normal exit, fixed frame, common epilogue,
all return assignments, error-out local, preparation nesting evidence,
three copies and the indirect callback. Missing/mismatched reference is an
error, not a skip. These are static anchor and grouping checks, not a
whole-program, hardware memory-ordering, all-writers or live lifetime proof.
