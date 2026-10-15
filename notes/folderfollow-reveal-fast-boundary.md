# Same-file playback: bounded synchronous descriptor block

2026-10-15. Static inspection of `0x42CAC0..0x42CC54` (exclusive) in
`artifacts/import-20261001/hiby_player_02fd.bin`, 7,133,528 bytes, SHA-256
`02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87`.
No device operation or binary change was performed by this audit. This extends
the [general grouping boundary](folderfollow-reveal-logical-boundary.md) and
the [writer/provenance audit](folderfollow-reveal-playback-boundary.md).

## Result: use the descriptor block, not the whole function's return value

The same-file copy at `42CBDC` belongs to function `42CAC0`. That function
does not have a single fixed-frame entry/exit contract like `42CC60`:

- Null a1 returns -1 at `42CC40/44`, without creating a frame.
- A zero halfword at source+`0x20C` returns 0 at `42CB94/98`, also without
  creating a frame. The zero is assigned in the `42CACC` branch delay slot.
- Other paths allocate a `0x30`-byte frame at `42CAD4`. All their normal
  returns restore registers at `42CB74`, force v0=0 at `42CB8C`, pop the
  frame at `42CB90`, then use the same `42CB94/98` return.
- Two framed paths call `42B180`, which ultimately posts event 9 through
  `42B140`. They can return zero without executing the same-file copy.

Therefore zero from the whole function does not prove that the synchronous
descriptor copy occurred, much less successful playback. Entry `42CAD4`
and epilogue `42CB74` could delimit a framed invocation, but would include
those fallback paths and require another discriminator. Do not treat the
unframed entry and shared return as if every path had a `0x30` frame.

There is a narrower normal-returning block that starts immediately before
the descriptor-copy argument setup and finishes after its callback/event
posting, without absorbing the fallback paths:

| Site | Original pair | Required continuation |
| --- | --- | --- |
| `42CBD4` | `2684D468`: `addiu a0,s4,-11160`; `02002821`: `addu a1,s0,zero` | Replay both once, resume `42CBDC`. s4 has already been set to `0x00AE0000` at `42CBD0`. |
| `42CC20` | `1000FFD1`: unconditional branch to `42CB68`; `2664DFB4`: `addiu a0,s3,-8268` | Preserve the delay-slot effect, then resume `42CB68`; the old branch encoding cannot be copied to a new PC unchanged. |

The block's 15 instruction nodes and seven delay slots all reach `42CC20`
in a bounded intraprocedural graph that treats calls as returning. Its
alternative `42CC48/4C/50` path rejoins at `42CBF4`. There is no direct
tail exit, return or fallback edge from this block. The SHF_EXECINSTR scan
finds no direct entry from outside the block to any of its instruction or
delay-slot addresses. The ordinary entry is fallthrough from `42CBD0`.
This is not an exclusion of indirect interior entry, nonlocal exits,
nonreturning callees or asynchronous callbacks.

At `42CC20`, **v0 is not a checked success result**: the latest direct call
was the event-posting helper at `42CC18`. Instrumentation must preserve that
stock register value. A private outcome of zero may mean only that this
synchronous block completed; it must not be described as a proved successful
track start or a coherent/current identity. The later whole-function zero
assignment is also unconditional for all framed paths, including fallback.

## Exact scope and nesting evidence

The original active frame F is the current SP at `42CBD4`; allocation already
happened at `42CAD4`. It is unchanged through this block under the ordinary
callee ABI. Saved ra is at F+`0x2C`; s0..s4 are at F+`0x18..0x28`.
An adapter must not subtract `0x30` again at this interior entry. Temporary
instrumentation frames must be completely removed before stock resumes.

The known inner copy has this exact provenance:

- `42CBDC`: `jal 0xA5B440`, delay slot `addiu a2,zero,0xA88`.
- Original caller SP equals the active F, and original return PC is
  `42CBE4`. Arguments are a0=D=`0xADD468`, a1=s0 (the function's saved
  source argument), a2=`0xA88`.
- No preparation-helper nesting is part of this block. Neither
  `42CD40` nor any general-copy return PC is an admissible same-file child.

Bind this evidence to a non-reused active ticket **and an explicit scope
kind**, not just SP. The general and same-file paths can later reuse the
same numerical stack address. A recursive/overlapping scope must not replace
the active owner. Other known mutation hooks reached from an indirect
callback must not silently inherit same-file ownership. The raw mutation
guard and scope guard still require their own atomic/interleaving proof.

The optional callback at `42CC0C` uses t9 loaded from B+`0xBA0` and receives
D in a1. It is inside the proposed block but its target, alias writes,
retained pointers and later asynchronous effects remain unproved. The direct
call at `42CBF4` passes the original source to `42CA00`; source ownership and
callee aliasing are also not established by this graph. See the
[pointer-consumer audit](folderfollow-reveal-pointer-consumers.md).

## Remaining stock path copy is outside the current descriptor

After `42CC20`, stock sets a1=s2 (original source+4) at `42CB68` and calls
`41FB80` at `42CB6C` with a2=260. Its destination, set in the branch delay
slot, is `0xADDFB4` = B+`0xC4C`, not current descriptor path D+4.
Helper `41FB80` copies at most 260 UTF-16 units and writes a terminator;
its destination extent is `[0xADDFB4,0xADE1BE)`. The current descriptor's
extent is `[0xADD468,0xADDEF0)`, so these concrete destinations do not overlap.
The block also stores B+`0xE8`, outside D. Thus these directly decoded stores
are not another current-D path/cue write. This does not prove absence of
alias writes by the callback, other callees, another thread or retained
pointers, and the trailing copy still reads a borrowed source.

## Incoming callers and bounded checks

The executable-section direct-edge inventory finds exactly four incoming
calls to `42CAC0`: `42E014`, `42E198`, `42E4E8`, `42E780`, and no direct
interior entry to the function. All four load source pointers from caller
stack slots (`+0xAA4` for the first two, `+0xAB0` for the last two); a stack
slot containing a pointer is not an owned stack descriptor. The last two
pass mode `0x10002`, whose low-byte 2 selects the fallback path at
`42CB10/42CC28`, not the synchronous copy. The first two pass s2 as mode.
Calls through B+`0x48` and B+`0x4C` surround these four calls, but this audit
does not establish that they form an ownership lock or serialize all writers.

The full function has 101 instructions, eight direct calls, one indirect
call and two return instructions. `scripts/test_folderfollow_reveal_fast_contract.py`
pins the exact source, executable-section incoming edges, body/fast-block
graphs, frame, both early returns, fallback routes, narrow hook pairs,
descriptor copy, callback, event and disjoint trailing path copy. Missing
or mismatched reference is an error, not a skip. These checks establish
bounded static grouping evidence only; they do not authorize identity reads,
UI mutation, a live test or an all-writers/coherence/lifetime claim.
