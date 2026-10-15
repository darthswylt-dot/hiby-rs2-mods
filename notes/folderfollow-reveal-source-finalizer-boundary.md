# Source-finalizer timing boundary

2026-10-15. Static trace of the shared source-finalization call reached by the
known fast and general playback commits. Reference image:
`artifacts/import-20261001/hiby_player_02fd.bin`, SHA-256
`02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87`.
No firmware or device changes were made for this audit.

## Shared boundary

The only direct calls to `0x42CA00` are:

| Call site | Route | Ordering |
| --- | --- | --- |
| `0x42CBF4` | Same-file/CUE fast path | Copies selected `0xA88`-byte record to `0xADD468`, then calls `0x42CA00`; its optional player callback and event post follow. |
| `0x42D6A8` | General cross-file path | Runs the optional player callback first, then calls `0x42CA00` in the normal-success epilogue before the `0x42D6E4` return. |

At entry, `0x42CA00` calls wrapper `0x42BDE0`. That wrapper calls source
finalizer `0x42BBE0`, then tail-calls state serializer `0x429F20`. The finalizer
gets the current source object from global `0xAED360`, writes its property 32
from the current descriptor path at `0xADD46C`, and writes property 31 from the
player time (`B+0x20`) when source mode is 2 or source field `+0x730` is set;
otherwise it uses player start offset (`B+0x51C`). The following serializer
emits message `0x133ED5F` and includes the separate global playback path at
`0xADE9BC`.

## Source-object lifetime

The singleton source pointer at `0xAED360` is allocated by `0x423FE0` and
published at `0x424018`; its direct caller is controller setup `0x47553C`.
Controller teardown calls `0x422B40` at `0x47539C`. Teardown marks the object,
destroys it through `0x466A80`, and only then clears the global pointer at
`0x422B6C`. The bounded constructor/destructor path shows no source-specific
lock shared with `0x42BBE0`/`0x422BA0`. This does not prove a runtime race, but
does mean a new reader cannot assume the pointer remains live merely because
it was loaded once; nor does a second getter call prove both properties came
from the same object generation.

## Existing playback-state message is not a retained source snapshot

`0x429F20` builds a fixed `0x250`-byte message and sends it via `0x46DE60`.
The bounded sender copies the global path at `0xADE9BC` and player scalars
`B+0x34`, `B+0x3C`, and `B+0x40`. Receiver `0x42A020` reads that message and
restores those scalars plus the global path; it does not read or set source
properties 31/32. Its three direct call sites are `0x4E4BB4`, `0x4E4C08`, and
`0x4E508C`; this is not a direct universal callback from the serializer. The
only direct property-31 getter call is at `0x4E4C30`, inside the mutating
recovery route. The serialized message therefore is not an existing
lifetime-safe copy of the source path **and** absolute backing-file position
needed to resolve cue identity. Do not call the recovery path merely to consume
it as telemetry.

The bounded direct-property audit also finds that property 31 has only the two
writer call sites inside `0x42BBE0` (`0x42BC30` and `0x42BC50`, selected by its
mode/offset branch). Property 32 has the finalizer call at `0x42BBFC` plus a
second direct writer at `0x5191AC`, which passes a constant pointer rather
than `0xADD46C`. Its meaning is not established here, so a future private
path/position capture must treat this writer as an invalidation/reset event,
not assume every path update is a track commit. This is a direct-call inventory,
not proof against indirect calls into the setter.

For the general route, `0x42D6A8` is on the common successful epilogue; the
bounded failure branches return `-1` through other epilogues. This makes the
source-finalizer call a useful post-open lifecycle boundary for that route,
not just the earlier descriptor-copy point. It is still not proof of audible
output or of a complete row identity.

For the fast route, the finalizer follows the descriptor copy, but its return
is followed by the player callback at `0x42CBFC` and event posting. Fast block
completion still means only that the synchronous block completed. It cannot be
promoted to the general route's success contract.

## Callback slot remains unresolved

The callback at player `B+0xBA0` is invoked after `0x42CA00` on the fast route
and immediately before it on the general route. A separate code path around
`0x6CBEF0` stores `0x6C35A0` into offset `+0xBA0`, but the store targets an
object reached through a distinct `s2+0x3A0` media-pipeline context. The
`0x6C35A0` function is a no-op stub. This is not evidence that the global
player's callback slot is that stub: the object identity is different and no
direct player-slot store has been established. Preserve the unresolved-gate
classification; do not infer null or no-op from zero initialization or this
lookalike field.

## Setter-input capture is not yet an authoritative snapshot

`0x422BA0` loads `0xAED360` into `s0` at entry and returns early if it is null.
For property 31 it stores the incoming `a1` at source `+0x230`; for property 32
it copies 260 UTF-16 units from `a1` into source `+0x28` (with a separate
`a1==0` branch). This makes copying the setter arguments into private storage
safer than retaining or later dereferencing the source pointer, but does not
certify that the stock setter accepted either value: the setter has no result
that reports whether a source object was present, and there is no source lock
covering these calls and teardown.

The finalizer's path call at `0x42BBFC` and its selected position call at
`0x42BC30` or `0x42BC50` are sequential calls, not one atomic pair. They can be
correlated as inputs from one finalizer invocation, but current evidence does
not prove that both calls observed the same source-object generation or a
stable descriptor generation. The second direct property-32 writer at
`0x5191AC` is one known invalidation route; it is not a complete inventory of
indirect calls, aliases, or descriptor writers. The separate player-lock audit
also finds no common `B+0x44` bracket around the general descriptor writer.

Disposition: private copies of these inputs may be useful as a **diagnostic
probe only**. They are not safe authority for selecting/revealing a Folder View
row until setter applicability, source teardown/replacement, and all path and
descriptor writers are covered by a coherent generation protocol. Do not
enable active reveal based on this candidate.

## Integration consequence

Both routes now have a shared source-finalizer point suitable for a future
**passive timing probe**. It could correlate the post-open source path/position
against descriptor path/CUE state without calling the getter or recursively
acquiring the player's mutex. Such samples would remain observations only:
source-object lifetime/replacement, external descriptor aliases, a complete
row mapping, Folder View ownership, and a retained UI transaction are not
certified here. No UI action or active reveal is enabled by this boundary.

The next safety gate is a coherent generation protocol covering setter
applicability, source teardown/replacement, descriptor/path writers and aliases.
Owned setter-input copies alone do not meet it; until the missing coverage is
proved, such copies are diagnostic observations only. Any later player trial
requires its own build verification, user instructions in an ended turn, fresh
explicit readiness, one launch, and then waiting for the user's report.
