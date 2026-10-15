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
gets the current source object from global `0xADD360`, writes its property 32
from the current descriptor path at `0xADD46C`, and writes property 31 from the
player time (`B+0x20`) when source mode is 2 or source field `+0x730` is set;
otherwise it uses player start offset (`B+0x51C`). The following serializer
emits message `0x133ED5F` and includes the separate global playback path at
`0xADE9BC`.

## Source-object lifetime

The singleton source pointer at `0xADD360` is allocated by `0x423FE0` and
published at `0x424018`; its direct caller is controller setup `0x47553C`.
Controller teardown calls `0x422B40` at `0x47539C`. Teardown marks the object,
destroys it through `0x466A80`, and only then clears the global pointer at
`0x422B6C`. The bounded constructor/destructor path shows no source-specific
lock shared with `0x42BBE0`/`0x422BA0`. This does not prove a runtime race, but
does mean a new reader cannot assume the pointer remains live merely because
it was loaded once; nor does a second getter call prove both properties came
from the same object generation.

The address arithmetic is `0xAE0000 + sign_extend(0xD360) = 0xADD360`;
`0xAED360` is not this slot. The accessor at `0x422B20` returns the word loaded
from `0xADD360`, the setter `0x422BA0` loads the same slot at entry, constructor
`0x423FE0` publishes its allocation at `0x424018`, and teardown clears it at
`0x422B6C`. An exact-address scan finds 27 statically resolved references to
`0xADD360` (two stores: constructor publication and teardown clear) and none
to `0xAED360`. This is a bounded instruction-reference inventory, not an
alias or indirect-access proof.

Teardown's clear is too late to be a pre-destruction invalidation point: it
calls `0x466A80` with the source pointer before writing zero to `0xADD360`.
A private lifetime epoch could be advanced on entry to teardown and on each
successful publication, but that would only let our own sample reject overlap;
it would not make an in-flight stock setter/finalizer safe against destruction,
and would not close descriptor/path aliases.

## Player path/cue writer recheck

On this exact image, the bounded property-call scan resolves two direct
property-31 setter calls (`0x42BC30`, `0x42BC50`) and two direct property-32
calls (`0x42BBFC`, `0x5191AC`). The player property-24 setter has three direct
callers (`0x4B55E8`, `0x531170`, `0x533C68`); no direct call to its property-17
cue-setter branch is resolved. The property-17 store at `0x42AC6C` remains real
code and indirect/interior invocation is not excluded.

Address-resolution finds 11 direct constructions/references to D=`0xADD468`
and three to its path `D+4`. Classified direct mutations remain the known
whole-record setter/fast/general copies, preparation path clear, full clear,
player initialization, cue setter, and source property writers recorded in the
[playback boundary](folderfollow-reveal-playback-boundary.md). Several other
D references are reads or escaped arguments: the property-24 getter can hand D
out through its pointer-out parameter, and the `B+0xBA0` callback receives D on
both playback routes. Their retention/write behavior is unresolved.

An immediate-offset sweep is deliberately not treated as a writer inventory:
the executable has 501 memory operands with `+0x104` and 57 with `+0x524`.
Within the nearby `0x42xxxx..0x43xxxx` code, path-offset stores include the
known preparation clear at `0x429EF8` and two stores at `0x43B570`/`0x43B698`.
The latter use `s0 = *(a0+0x50)` in the containing handler; its object identity
is not statically tied to B, but neither is an alias to B disproved. The cue
offset store in that range is the property-17 branch at `0x42AC6C`.
Elsewhere, `0x6E5500` stores to `+0x524` through a method object initialized
from its incoming `a0`; its direct caller passes a saved incoming pointer, not
a fixed B address. That is an offset collision, not proof that it writes B's
cue field, and it is not a proof of non-aliasing either. These ambiguous bases
remain outside any closed-world claim.

The source/global and descriptor sweeps are finite syntactic evidence only.
They do not analyze escaped pointer lifetimes, indirect callback targets,
nonlocal aliases, or concurrency. Thus neither a private source epoch nor an
optimistic descriptor revision can currently be certified as complete writer
coverage. The new hash-gated source-finalizer contract pins the corrected
`0xADD360` slot, constructor/teardown order, bounded property-call inventories,
and the empty-path reset input at `0x5191AC`; it does not promote those
inventories into a complete alias proof.

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
than `0xADD46C`. It passes `0x920AB4` (formed in the call delay slot); the first
UTF-16 code unit there is NUL, so the effective source path is empty. The
following data begins with UTF-16 `#EXTINF`, consistent with this pointer
selecting an empty prefix before adjacent metadata, not a backing-file path.
This is therefore a confirmed path-clear invalidation route, not evidence of a
track commit. The call is in the method block beginning at `0x519140`, whose
entry appears as a function-pointer word at `0xAAE660`; the bounded scan finds
no direct `jal` or branch reference to the entry, so its dynamic owner and
invocation circumstances remain unresolved. This remains a direct-call
inventory, not proof against indirect calls into the setter or other aliases.

A second bounded pass over the ELF tables found no `.symtab`, `.reginfo`, or
`DT_MIPS_GP_VALUE`; the dynamic relocations do not describe `0xAAE660`, and the
GOT contains no copy of this method pointer. The pointer sits in `.data` among
nearby UI-label strings `pull_down_menu_iv_mseb`, `pull_down_menu_iv_lineout`,
and `pull_down_menu_iv_balance`, with other method pointers at `0xAAE658`,
`0xAAE6B8`, and `0xAAE718`. This makes a UI-control metadata association
plausible, but the stripped image does not establish which control/event owns
`0x519140` or when it is invoked. Treating this as an output-menu callback
would still be an inference, not a resolved caller.

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
and immediately before it on the general route. A binary-wide immediate scan
finds seven `+0xBA0` memory operands: the two player callback loads at
`0x42CBFC`/`0x42D690`, stack save/restore at `0x4A66F4`/`0x4A69D0`, a media-
pipeline callback load at `0x6C7328`, a store at `0x6CBEF8`, and one
data-like `swc1` word at `0x97D03C` inside an executable segment. At
`0x6CBEF8`, the base is loaded from `s2+0x3A0` in the preceding delay slot and
the stored callback is `0x6C35A0`; the nearby `0x6C7328` use is likewise on a
pipeline object whose `+0x518..+0x528` members are being released. These are
not statically bound to global player B. Exact static references to the
player's computed slot `0xADDF08` are absent, but that is not an alias/bulk-copy
proof. No direct player-slot store has been established. Preserve the
unresolved-gate classification; do not infer null or no-op from
zero-initialization or these lookalike fields.

## Setter-input capture is not yet an authoritative snapshot

`0x422BA0` loads `0xADD360` into `s0` at entry and returns early if it is null.
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
