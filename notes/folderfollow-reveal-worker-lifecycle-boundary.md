# Reveal integration: worker start, cancellation and wake lifetime

2026-10-16, bounded static inspection of reference
`artifacts/import-20261001/hiby_player_02fd.bin`, SHA-256
`02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87`
(7,133,528 bytes). Supplements [ownership](folderfollow-reveal-ownership.md)
and [publication](folderfollow-reveal-publication.md). No firmware change,
device operation or observed runtime race. The sequences below disprove
unconditional safety assumptions; they do not diagnose the Show No Mercy test.

## First distinguish the ownership modes

`V+0xD0` is runtime resource state, not the config-record prefill field.
Constructor `0x492460` calls `0x485DE0`; the named-view branch obtains
resource-node `+0xD0` at `0x485FD8`, and the constructor stores the returned
resource in `V+0xD0` at `0x492474`. Constructor `0x492A18` and render enqueue
`0x4907E4` select shared mode when resource `+0x74 == 1`. Destruction
`0x493BEC` instead selects shared cancellation for **any nonzero** value.
Do not silently normalize those predicates. Setter `0x459820` can write this
field directly. The follow-up below establishes the fresh resource's zero
default, not the value of an already resolved/reused explorer resource or
complete mutation coverage. Neither live ownership mode may be assumed.

Ordinary explorer's initial prefill **is** resolved: config record 2 starts
at `0xA98A28`; its `+0x174` word at `0xA98B9C` is zero. Lookup
`0x4A06F4..6FC` copies it to output `+0x174`, then `0x49242C/430` stores
it at `V+0x4228`; `0x492988/9B4` copies it to template `V+0x3B5C`,
which is `job+0x2B8`. The adjacent `0x49CC80` at record `+0x16C` is
a separate widget callback, not this prefill or the initial Files loader.
The initial loader is record `+0x104 = 0x49E360`, copied into `V+0x4218`;
see the [provenance audit](folderfollow-reveal-provenance.md). Known worker callbacks
remain Files fill `0x48D280 -> 0x48D080` and post-fill `0x48F880`.

## Follow-up: fresh viewgroup defaults to private mode

The `lg_viewgroup` prototype at `0x927F6C` declares type 5, allocation size
`0x178`, and constructor `0x459E00`. Registration `0x45A6AC` supplies this
prototype to `0x43D2C0`. Factory `0x43D400` clears the **whole allocation**
at `0x43D438`, then copies only the first `0x20` prototype bytes at
`0x43D448`. The mode word at `+0x74` is outside that copied header, so
it starts zero rather than coming from external layout bytes.

Constructor `0x459E00..E78` installs methods, creates child list `+0xFC`,
and calls `0x4597C0(W,1)`. That helper writes `W+0x114`, not `W+0x74`.
The constructor leaves mode zero. Parser `0x488EE4` creates a type-5
`lg_viewgroup` and stores W in manager `+0xAC80` at `0x488EF4`.
That is node base manager `+0xABB0`, field `+0xD0`. Node registration
`0x48909C -> 0x480680` copies `0x1328` bytes at `0x48096C`, preserving
the pointer; it does not copy external bytes over W's mode word.
Later view lookup returns that node's `+0xD0` as described above.

Inspected viewgroup attribute helpers set image binding (`0x459420`),
colors (`0x4593A0/3E0`), geometry (`0x4596E0/660/620`) and visibility
(`0x459780`), at fields distinct from `+0x74`. This supplies a concrete
**zero/default-private** source at factory/constructor completion, with no
mode override in those inspected attribute helpers. It is not a certificate
of every parser operation or malformed layout, nor an immutable live mode:
lookup may return an existing resource, and all subsequent aliases, reuse
paths and bulk writers have not been fenced.

In particular, name copy `0x488F08` uses `strcpy` from node `+0xE4` into
W `+0x20`, without an explicit length. The inferred `0x40`-byte source-name
field does not itself prove termination within that field. A valid terminated
name fitting that field is required before carrying the default through this
step; absent layout/input evidence, factory zero is not a full parsed-resource
certificate. This is an input-proof limit, not an observed corruption.

All five found direct mode-setter calls belong to other registered initial
loaders, not ordinary explorer:

| Config index / internal name | Initial loader | Setter call |
| --- | --- | --- |
| 22 / `vg_listview_tidal_item` | `0x4B1E20` | `0x4B1EF4` |
| 56 / `vg_listview_recent_add` | `0x4B5BC0` | `0x4B5C14` |
| 53 / `vg_listview_tidal_play_info` | `0x515760` | `0x5157DC` |
| 61 / `vg_listview_qobuz_item` | `0x530440` | `0x530538` |
| 68 / `vg_listview_sony_item` | `0x539020` | `0x5390C4` |

Each registration is a loader pointer in record `+0x104`, with the internal
name at `+0x10C`; these names need not match the layout filename. All calls
pass mode 1 through `V+0xD0`. Ordinary explorer record 2 instead registers
`0x49E360` at `0xA98B2C`; its bounded body `0x49E360..E510` has no direct
mode-setter call or `+0x74` store. This separates known loader routes, not
all possible indirect invocations or future rebinding.

Existing FFRS/VDEP/safe-pointer diagnostic formats do not capture `V+0xD0`
or resource `+0x74`. The older standalone heap/data dumps have no preserved
base address/capture map and cannot supply a defensible value by guessing a
base. Maps from another run must not be reused. Actual current mode therefore
still requires separately attributable read-only evidence; even a one-time
mode read would not retain the resource or stabilize it through teardown.

### First read-only device probe: no explorer registered

2026-10-16, after the user reported the player connected. ADB found serial
`HiBy RS2`; the live process was original `/usr/bin/hiby_player`, PID 124,
start ticks 425, SHA-256
`0fedb30f91937eafb5baaf3c75422cdbde04a62fe8bac8eca3c7a88bb761da0e`.
Boot ID `777e7205-c433-40ab-8e3d-4bc2582cf7ec` and the complete maps were
checked around the reads. Host evidence is preserved locally in ignored
`artifacts/worker_mode_readonly_20261016_all.json`.

Direct `od -j` on process memory failed, but aligned `dd` seek followed by
remote `od` successfully returned exact bounded bytes without process stop.
Both `*(0xADF208)` and `*(*(0xB8BACC)+0x3C)` resolved U=`0xD4D5DC`.
Its circular view-list sentinel `0xD4D874` had exactly one node,
`0xF3879C`, whose V=`0x125ABFC` has inline name `vg_listview_all`,
closing marker 0 and owner U. No `vg_listview_explorer` member was present;
its worker mode therefore was **not read and remains unknown**.

Root, sentinel, node and full `0xD8`-byte view header matched on reread;
boot/PID/start/hash/maps remained unchanged. This is bounded sequential
diagnostic evidence, not an atomic snapshot, active-view selection or lifetime
lease. No player function, signal, ptrace attach, device file write, install,
test-build launch or reboot was used. Open Folder View only after a separate
user action, then acquire fresh identity/maps/roots rather than reusing these
addresses for the next probe.

### Confirmed observation after opening Show No Mercy

After the user opened Folder View and confirmed readiness, a fresh acquisition
rechecked stock PID 124/start ticks 425, the same boot/hash, and current maps
before following any object pointer. The heap mapping had grown since the
All-only probe; its old bounds were not reused. Both controller roots again
resolved U=`0xD4D5DC`.

Two registered explorer members were observed, both with resource `+0x74=0`:

| Registered name / scope | V | Resource R | Private T |
| --- | --- | --- | --- |
| `vg_listview_explorer`, Show No Mercy / USA edition | `0x12ACB64` | `0x127363C` | `0x12B5F6C` |
| `vg_listview_explorer##1`, Show No Mercy album directory | `0x122E754` | `0x12185C4` | `0x1226BB4` |

Both resource inline names matched their corresponding view names, both
types were `hgl_view`, closing markers were zero, and `V+0xD4` equalled U.
`V+0x3B84` supplied each private T; both `T+0x138` owners matched U and
both `T+0xBDC` markers were `0x48E960`. These corroborate the private-worker
layout, not actual pthread startup, running state or retained lifetime.

All 18 bounded object-memory reads (1,796 bytes per pass), including roots,
ring links, full view/resource headers, terminated scope strings, T slots,
owners and markers, matched on a second pass. Unique PID/start, boot ID,
executable hash and full maps also remained unchanged. Raw reads and exact
scope paths are preserved locally in ignored
`artifacts/worker_mode_readonly_20261016_show_no_mercy.json`.

This resolves the **observed Show No Mercy mode**: if evaluated with the
captured zero, constructor/enqueue and destruction select private branches,
without the nonzero predicate mismatch. It does not retrospectively establish
mode at original construction. It is not a permanent mode invariant,
an atomic snapshot, a reproduction of stock sorted active-view selection,
or a safety certificate for the private stop/wake-object ordering below.
No mutex/semaphore pointer was dereferenced and no player function, signal,
attach, device write, installation, test launch or reboot was performed.

## Shared cancellation does not revoke a borrowed work copy

`0x48F3B4..3D0` creates separate master (`T+0x130`) and work (`T+0x134`)
lists of `0x2C4`-byte records. `0x48ED64..D80` appends a **copy** of a
master record into the work list. Append `0x455DA0` tail-calls insert
`0x455BC0`, whose `0x455CE8` copies the record bytes.

The worker obtains a raw work-record pointer into `s1` at
`0x48EB28..B3C`, before acquiring `T+0x10`. Its first short lock bracket
only copies `T+0x140`'s player descriptor to the stack. It neither pins nor
recopies the job. Cancellation `0x48EE20` locks `T+0x10`, compares master
`job+0x88` against the destructor's scope, zeros matching master callbacks
`+0x2C0/+0x2BC` at `0x48EEFC/EF00`, and deletes those master records.
It then clears the work list through its `+0x24` method at `0x48EF2C`.
That method `0x4557C0` only zeros list `+0x0C` count; it does not wipe or
free the borrowed record's bytes.

This permits the following interleaving, assuming a valid, eligible work copy:

1. Worker borrows work record with `job+4 == 0` and live callbacks.
2. Cancellation locks, disables/removes the master, clears the work count,
   unlocks and returns. The borrowed copy still has its callbacks.
3. Worker locks at `0x48EC34`, checks only the borrowed `job+4`, and calls
   fill at `0x48EC54`, then post-fill at `0x48EC74` if fill does not return
   -1. It does not recheck membership,
   view-closing state or generation before these calls.

`T+0x128` does not close the window: nonzero branches straight to
`0x48EC34`; zero sets it to one, and NULL `job+0x2B8` also branches there.
Cancellation never changes `T+0x128`. Thus the NULL Files prefill does not
invalidate this conditional shared-mode counterexample.

Cancellation does wait for a fill/post-fill pair already holding `T+0x10`.
It is not a barrier against a later pair from a borrowed copy. Nonnull prefill
at `0x48EBBC` and the renderer signal at `0x48EC90` are outside that bracket.
Cancellation also neither sets worker stop `T+4`, waits on completion
`T+0x0C`, nor drains messages already posted through `0x474380`.

## Private start has a conditional handshake, not a success certificate

The constructor locks startup `T+8` at `0x48F4AC`, creates the worker at
`0x48F4C8`, then locks `T+8` again at `0x48F4D4`. Worker entry first locks
completion `T+0x0C` at `0x48EAC4`, then unlocks startup `T+8` at
`0x48EAD8`. If that handshake operates as intended and the normal constructor
path returns, completion has already been acquired by the worker. This
narrows the earlier startup concern: do not invent a normal-path gap before
its first completion lock.

The constructor and worker are different threads for the startup lock/unlock;
mutex initialization uses NULL attributes and wrappers discard lock statuses.
The sequence alone is not a portable synchronization proof. Moreover, `T`
is published through `*out` at `0x48F3D8` before startup. Null startup or
completion pointers select `0x48F46C..4A0`, returning zero **without creating
the worker**. This is a syntactic failure path, not proof of recoverable
allocation failure: initialization itself does not check its allocation.
The Files caller does not inspect the result before registration at
`0x492A3C`. The thread-create wrapper also discards the actual create status
and returns stack `+0x3C`; zero alone is not evidence of a completed handshake.

## Private completion does not preserve the wake object until last use

Stop `0x48F520` sets `T+4=1`, posts wake `T+0x14`, destroys/frees that wake
object at `0x48F54C`, and **only then** waits on completion `T+0x0C` at
`0x48F554`. Wrapper `0x466D20` calls `sem_destroy`, then `free` at
`0x466D3C`. ELF relocations, not call shape, identify the semaphore imports.

Even without prefill or progression, a private worker can read stop=0 at
`0x48EAE0/E4`, be delayed while stop frees the wake object, and then load
the unchanged `T+0x14` at `0x48EAEC` and call `sem_wait` at `0x48EAF0`.
Its second stop check `0x48EAF8` is after this operation. The completion
wait does not prevent that check/use interleaving: the worker still holds
completion while making the late wake-object call.

There is also a conditional progression path: when `job+0x2A8 != 0` and
`job+0x290 + job+0x2A4 < job+0x2A8`, `0x48ECC0` posts the same wake object
before checking stop at `0x48ECC8`. Do not label this particular path an
ordinary Files failure: the view is initially zeroed, and no writer to the
template's progression fields was established on the bounded Files paths.
The simpler stop-check/`sem_wait` window does not require those fields.

Completion release at `0x48ECD4` is followed only by stack/register restore
and return; the examined worker has no subsequent `T` access. Subject to
working synchronization, completion still bounds worker accesses before
later T/list frees. It does not retrospectively protect the earlier wake free.

## Live-adapter gate

A raw registry result, `V+0x44`, queue clear, constructor zero return, fixed
delay or `T+0x10` acquisition is not a lifetime lease. A live bridge needs
verified, stable ownership mode; revocation before close/rebind; accounting
for already-borrowed jobs and outstanding notifications; and a completion
boundary **after every last use** of retained synchronization objects.
Job identity must include a non-reused generation, not only a view name.
This note does not authorize replacing the stock worker or modifying its
teardown. Active reveal remains disabled; no live adapter is emitted.

`scripts/test_folderfollow_reveal_worker_lifecycle_contract.py` pins the
reference hash, record-copy/cancel distinction, start paths, wake last-use
ordering, imports, default initialization, attribute-helper stores and
Files/setter scope. These are structural checks, not
scheduled thread execution or hardware safety certification.
