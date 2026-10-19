# Original Files fill provenance (2026-10-16; completed 2026-10-19)

Bounded inspection of `artifacts/import-20261001/hiby_player_02fd.bin`,
SHA-256 `02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87`,
7,133,528 bytes. No native hook, firmware build, device access or UI action.
This supplies concrete association leads for [staged rows](folderfollow-reveal-coordinator.md),
not a live ownership implementation.

## The first synchronous Files fill is a distinct route

Ordinary explorer config record 2 is `0xA98A28`. Its initial loader at `+0x104`
is `0x49E360`; lookup copies that slot at `0x4A06CC..6D8`, and construction
stores it in `V+0x4218` at `0x492400..40C`. Do not confuse it with record
`+0x16C = 0x49CC80` (a separate widget callback) or NULL prefill `+0x174`.
`0x49CC80` calls `0x4957A0` and `0x49BA00`, not the initial loader below.

Construction invokes the callback stored at `V+0x4218` at `0x4927AC`, with
`P=*(V+0x3B68)`, output slot `V+0x64`, requested count derived from the layout,
and total-count output slot `V+0x6C`. Reset `0x491240` invokes the same loader at `0x49129C` after
freeing/clearing the old lists. These invocations must retain their own outer
operation association; the loader's code address alone does not identify it.

In `0x49E360`, saved registers retain these original arguments:

| Value | Carrier before query | Source |
| --- | --- | --- |
| P | `s0` | original `a0`, `0x49E38C` |
| newly allocated list | `s2` | `0x456C40` result, `0x49E3C4` |
| requested count | `s4` | original `a2`, `0x49E398` |
| total-count output slot | `s3` | original `a3`, `0x49E3B4` |
| V | `s1` | `0x459340(P)` result, `0x49E3C8` |
| scope | `s5 = V+0x3DD8` | `0x49E3DC` |

The original output-slot pointer is initially `s1`. `0x49E3B8` writes the
new list through it **before** resolving V, enumeration `0x6FC0A0`, and row
fill. That pointer store is not completion. The query call at `0x49E430`
passes `(list=s2, offset=0, requested=s4, mode=0, scope=s5)` to `0x6F7CA0`.
The alternative preparation branch `0x49E4C0` changes control state through
`0x490B00/0x490CC0`, then rejoins `0x49E418` at `0x49E4F0`; it does not skip
the common enumeration/query. The contract pins normal preparation and the
common arguments, not every effect of those alternative helpers.
Scope remains borrowed stock memory; assigning it to a saved register does
not make an immutable string copy or establish its lifetime.

After query return, the loader publishes total from `V+0x3B74`, updates P's
window metadata, and may allocate/update the auxiliary list through `0x494FE0`.
Its final return also loads `V+0x3B74` at `0x49E49C`, not the producer's return.
Thus an outer loader return cannot seal a staged map without the original
append/terminal/end facts and all subsequent relevant mutation coverage.

## Renderer jobs carry pointers, not retained owner generations

`0x459320(P,V)` installs P's associated V at `P+0x7C` (constructor call
`0x49274C`). Getter `0x459340` returns that field. Renderer `0x4906E0` obtains
the last child P, then calls this getter at `0x490750`. At `0x490758`, `v0`
therefore carries the original associated V before template changes begin.
This is an association lead, not acquisition of ownership or a non-reused epoch.

The V-resident template begins at `J=V+0x38A4`. Known fields include:

| Job field | Native source |
| --- | --- |
| `+0x48` view name | constructor / renderer copies |
| `+0x88` UTF-16 query scope | renderer copies `V+0x3DD8`, `0x4907B8..7C4` |
| `+0x2AC` request pointer | renderer `0x49076C` |
| `+0x2B0` P pointer | constructor `0x4929A8`, renderer `0x490774` |
| `+0x2B4` V pointer | constructor `0x4929B8` |
| `+0x2B8` prefill callback | ordinary Files NULL |
| `+0x2BC` post-fill callback | `0x48F880` |
| `+0x2C0` fill callback | resolved through `0x48E980`, Files `0x48D280` |

None of these pointer fields is established as free space for a private token.
In particular, the request/P/V fields cannot be overwritten merely because
the Files fill branch does not consume all of them. Whole-record copying does
not add ownership to the pointers it transports.

There are separate constructor and later-render enqueue paths. A future
association scheme must cover both, including the constructor's initial
record; hooking only `0x48F180` misses that ingress. The shared/private
selection and cancellation limits in the [worker audit](folderfollow-reveal-worker-lifecycle-boundary.md)
remain unchanged.

The inspected record transport is:

1. Initial private-worker construction `0x48F360` copies the template to its
   local `sp+0x18` at `0x48F3F4`, resolves its callback, and appends it to the
   master list at `0x48F414`. Later renderer enqueue `0x48F180` instead copies
   to its own `sp+0x18` at `0x48F1BC`, resolves the callback, clears the master
   count, and appends at `0x48F1E8`. Both copy `0x2C4` bytes.
2. The worker selects the last master record at `0x48ED6C`, then appends a
   distinct copy to the work list at `0x48ED7C`. That association must be
   preserved too; master and work pointers are not interchangeable.
3. Work-list getter `0x48EB30` returns the record retained in `s1` before the
   short mutex acquisition at `0x48EB48`. Later `0x48EC54` invokes its fill
   callback with `(T, work-record)`; post-fill receives the same arguments at
   `0x48EC74`. Neither dispatch creates an original owner generation.

The decisive split is inside Files callback `0x48D080`: V is resolved anew
using controller `*(T+0x138)` and name `job+0x48` at `0x48D0DC`, and
`P=*(V+0x3B68)` comes from **that** V at `0x48D0F0`.
At query `0x48D1B8`, destination is the newly resolved `*(V+0x64)`,
but scope is the **original copied job+0x88**. Post-fill `0x48F880` resolves
the name again and binds the then-current list. If a stale job reaches this
dispatch and its name resolves to a replacement, this path combines old scope
with the newly resolved destination; it does not verify original ownership.
This conditional source path is not an observed hardware failure or proof of
such a schedule in the private-worker observation.

No direct loads/stores of job `+0x2B0/+0x2B4` occur in the bounded inspected
worker/Files/post-fill bodies. That syntactic absence does not prove unused
fields globally or exclude indirect/computed access. Merely comparing those
original raw pointers with a callback-time lookup would still admit same-address
reuse and would not retain either object. Association and lifetime need
independent, non-reused ownership; T's existing mutex alone does not supply it.

## Query-to-producer arguments can be followed directly

`0x6F7CA0` captures its original list/offset/request/mode as `s5/s4/s6/s2`
and its fifth argument (scope) as `s0`. The physical-folder branches prepare
a statement in stack slot `+0xBA8`, then call `0x6ED5C0` at `0x6F8BEC` or
`0x6F8E04`. Both pass the same original destination, offset, requested count,
mode and scope, together with the selected statement. They are not an
independent view-name lookup.

Scope is not the wrapper's entire query input: selection also reads current
global context `*(0xBAD7B0)`, including fields `+0x4FC` at `0x6F8B7C` or
`+0x538` at `0x6F8D94`. Copying a job's scope therefore does not freeze the
query-selection/order state at enqueue time. The accepted row map must follow
the actual validated producer order, and relevant later changes still revoke
it; the source anchors do not establish complete selector-writer coverage.

At the producer, destination becomes `s6`; offset is saved at frame `+0xAD8`,
requested count initially becomes `s1`, and mode is loaded from the caller's
fifth argument into `s7`. Its later row ordinal reuses `s1`, so that register
must not be mistaken for the original limit after binding. Statement is `s0`.
The known post-append/terminal/end observation sites retain the original
producer invocation, not a view generation inferred from the list address.
Scope is also passed as the producer's sixth argument (`new sp+0xAE4`), but
the bounded explicit load of it at `0x6ED76C` is on the mode-1 branch.
Mode zero builds its descriptor from the statement through `0x6E8D80`.
Passing scope therefore does not itself validate every row's parent folder;
the staging validator's independent exact-parent check is still required.

The wrapper discards producer status on the ordinary branch and can do further
work on the date-order branch after producer return. Its return is not a SQL
completion certificate. These argument chains provide bounded diagnostic
provenance, not proof of coherent source memory, successful SQL prepare/bind,
complete fill, serialized threads or retained UI objects.

## Adapter consequence

An operation-bound handle must originate before the relevant mutation and
travel with the exact admitted invocation and every proved job copy. It must
not be recreated from a callback-time V/P/name/scope match. Original raw
pointer equality is only a consistency check: close/reopen can reuse it.
Before an actual bridge can submit staged events, its native sidecar storage,
copy association, cancellation, bounded reuse/exhaustion, thread handoff and
nested-operation admission still need implementation and review.

An additional host receipt registry is deliberately not added here: without
the native association it would move the same external-trust assumption to
another object rather than close it. Active reveal stays disabled. The
hash-gated provenance contracts pin inspected argument/slot relationships;
they do not assert complete writer coverage or runtime lifetime safety.

## Validation completed 2026-10-19

Eight query/synchronous-loader and six renderer/job provenance contracts pass
against the exact reference hash and size. The 388-test reveal-focused run
passed before the six new job checks and final global-selector check were
added; those seven checks passed separately (395 distinct tests in total).
The 165-test structural-contract run is a subset of that first run, not an
additional count. Independent review checked the synchronous/query chain and
notes; the job-chain tests were cross-checked separately. Compilation and
whitespace checks passed. These are local source/model checks, not hardware,
native hook, concurrency or automatic-scroll validation.

## Implemented native transport follow-up (2026-10-19)

The subsequent [native lineage stage](folderfollow-reveal-lineage-stage.md)
implements original invocation IDs in an added tail of the internally copied
master/work records, while keeping the 708-byte source template unchanged.
Separate borrowed-job/query/producer receipts retain original ancestry instead
of recovering it by callback-time name or pointer lookup. Unknown origins stay
unbound. This advances the native copy-transport obligation described above;
it does not implement native owner lifetime, complete prefix mutation/cancellation,
contents-change epochs, host row publication or the final UI action.
