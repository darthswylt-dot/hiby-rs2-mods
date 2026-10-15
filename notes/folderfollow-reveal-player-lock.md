# Playback identity: stock mutex coverage and final-sample limits

2026-10-15. Read-only follow-up of the exact `02fd` reference, SHA-256
`02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87`,
7,133,528 bytes. B=`0xADD368`, D=`0xADD468` (current descriptor, size
`0xA88`). No firmware/device operation or new lock acquisition is introduced.

## Result

The stock property getter has a real mutex, but it is **not established as a
common lock for all identity writers**. Its copy-out is therefore not an
authoritative final-identity sample merely because it locks. Adding a call to
the getter inside every writer hook would additionally attempt to reacquire
the same mutex on already-locked routes. There is no recursive-mutex contract.

The useful narrow sites are different for different routes:

- Public property-24 completion at `42AC14` is after its whole copy and before
  the setter's unlock tail. Property-17 cue completion reaches `42AB98` after
  the store at `42AC6C`. A direct bounded copy at those sites would not require
  taking an additional stock lock, but still needs admission against other
  writers, source aliases, and lifecycle changes.
- `42B060` is immediately after an existing property-24 copy into a caller's
  buffer, still before getter unlock. It is a consumer observation, not a
  particular logical commit's completion; the destination's ownership and
  aliasing are not universally known.
- `42D6E4` remains the general commit's common completion boundary. Unlike the
  public setter, that function has no established B+`0x44` bracket. A sample
  there needs a separate fail-closed coherence protocol; calling the getter
  would not make the general writer participate in the getter's mutex.

None of these is currently a universal safe publication/apply site. A local
copy must remain unavailable as active authority until the missing writer,
alias and lifecycle gates are met. UI owner/row/apply gates are independent.

## Concrete lock identity, initialization, and failure handling

Initialization `42B9C0` first zeroes the whole player, including the current
descriptor, at `42B9DC`. Only later does `42BA28` create a synchronization
object through `466D60`; its result is stored to B+`0x44` at `42BA34`.
At `42BACC..42BAE8`, a nonzero object permits binding B+`0x48=428B00` and
B+`0x4C=428BE0`.

The two callbacks load the pointer from absolute `0xADD3AC` (B+`0x44`) and
call `466DA0` / `466DC0`. The ELF `.rel.plt` entries identify:

| Wrapper | PLT target | GOT slot | Imported symbol |
| --- | --- | --- | --- |
| `466D60` initialization | `A5B8A0` | `A6FA28` | `pthread_mutex_init` |
| `466DA0` lock | `A5B960` | `A6FA58` | `pthread_mutex_lock` |
| `466DC0` unlock | `A5B830` | `A6FA0C` | `pthread_mutex_unlock` |

`466D60` allocates 24 bytes and passes **null attributes** at `466D78`.
This does not establish recursive behavior. It returns the saved allocation
pointer, not the initialization status. Lock/unlock wrappers discard the
imported result and explicitly return zero at `466DB4` / `466DD4`. Thus the
caller does not receive a checked successful-lock certificate. This audit
does not assert that an observed lock failure occurred.

## Writer coverage

Public setter `42AB20` loads B+`0x48` at `42AB30`, calls it at `42AB4C`, then
dispatches the property table. The return tail loads B+`0x4C` at `42ABA8` and
tail-calls it at `42ABB0`. Both the copy at `42AC0C` and cue store at `42AC6C`
are inside that local bracket. Public getter `42AD60` similarly calls the lock
at `42AD90` before dispatch and tail-calls unlock at `42ADBC`. If the lock
callback is null, its early branch instead returns without performing the
requested copy; that return must not be treated as initialized output.

The same-file routine `42CAC0` has **four** statically direct callers. All four
are locally bracketed by B+`0x48` / B+`0x4C`:

| Lock call | Same-file call | Unlock call |
| --- | --- | --- |
| `42E008` | `42E014` | `42E020` |
| `42E18C` | `42E198` | `42E1A4` |
| `42E4D8` | `42E4E8` | `42E4F4` |
| `42E770` | `42E780` | `42E78C` |

The first two are the previously recorded Next/Previous routes. The latter
two are worker-loop calls and pass `a0=0x10002`, whose low byte selects the
`42CC28` branch rather than the optimized same-file copy. The function body
does not acquire the mutex itself; indirect/interior-entry coverage is not
proved. Its descriptor callback `42CC0C`, if invoked, executes before the
outer bracket is released and can receive D.

The general routine `42CC60..42DCA8` contains no direct calls to `428B00`,
`428BE0`, `466DA0`, or `466DC0`, and no s0-based loads/stores of B+`0x44`,
B+`0x48`, or B+`0x4C`. This bounded syntactic fact does not prove absence of
locks inside all callees. Both direct callers (`42E42C`, `42E598`) belong to
the player worker loop. Its outer B+`0x0C` completion mutex is distinct from
B+`0x44`; the staged-item B+`0xBB4` mutex is also distinct and released before
`42E42C`. No common B+`0x44` bracket has been established for the general copy.
The unresolved B+`0xBA0` callback at `42D6A0` precedes the common completion.

Preparation `429E80` has three direct calls: `42C2B4`, `42CD38`, `42E7D8`.
Only the first has a local B+`0x44` bracket in `42C280`: lock `42C298`, helper
`42C2B4`, unlock tail `42C2DC`. The general and worker calls do not inherit
that particular bracket. The helper itself performs its path-clear store at
`429EF8`; it has no own call to the player lock callbacks.

Full clear `42DEA0` calls `42C280` at `42DEA8`, but that helper **unlocks before
returning**. It next calls `42BBE0` and only then clears D at `42DECC`.
Consequently, the local helper lock is not a bracket around the full clear.
The zeroing at player initialization likewise precedes mutex creation.
Neither route can be included in an all-writer mutex claim.

## Deadlock and ownership consequences

Calling `42AD60(24, buffer, NULL)` inside the public-setter copy hook or inside
the synchronous same-file copy hook would call B+`0x48` again while the same
invocation already holds that lock. The stock null-attribute initialization
does not justify that recursive acquisition; it must not be added as a
supposedly safe shortcut. Holding an extra player lock across the general
commit's callbacks, backend calls or UI work also lacks a checked lock order.

An owned private destination avoids retaining the borrowed D pointer, but
does not itself serialize source reads. An optimistic raw-revision bracket
could detect covered writers while copying; it still cannot certify unknown
alias/callback writes or reinitialization outside its lifecycle contract.
Similarly, sampling before unlock is useful local ordering, not a proof of
complete writer exclusion. Getter pointer-out and B+`0xBA0` callback escapes
remain as described in [the pointer audit](folderfollow-reveal-pointer-consumers.md).

## Checks and limits

`test_folderfollow_reveal_player_lock_contract.py` pins the initialization,
ELF import bindings, wrapper result handling, public brackets, all four direct
same-file caller brackets, preparation/full-clear separation, and the bounded
absence of direct player-lock operations in the general body. Its exact-source
hash is mandatory. It is not a whole-program alias analysis, proof of lock
success, recursive behavior, all-writer exclusion, live hardware behavior, or
permission to enable autoscroll.
