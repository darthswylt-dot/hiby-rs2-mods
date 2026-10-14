# Reveal playback publication: clear routes and source provenance

2026-10-13. Bounded local inspection of reference
`artifacts/import-20261001/hiby_player_02fd.bin`, 7,133,528 bytes, SHA-256
`02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87`.
This supplements the [commit trace](playback-media-commit-static-trace.md)
and [dispatch audit](folderfollow-reveal-dispatch.md). No firmware generation,
device operation, new hook or live playback mailbox is introduced here.

## Result

Later on 2026-10-13, [firmware guard integration](folderfollow-reveal-guard-stage.md)
found two additional copies (`42CF84`, `42D398`) and descriptor pointer escapes
through property 24 and indirect callbacks. Five known full-copy sites are now
pinned by the contract tests. The three hooks discussed below remain the
unchanged **old passive bridge** coverage, not an all-copy inventory.

The passive bridge's three whole-record copy hooks are insufficient as a
complete playback publication boundary. Two concrete clear mechanisms bypass
them, initialization can overwrite the whole player, and a separate public
cue setter exists. Also, the general commit does not always receive an
independently owned source: one direct caller passes the current global record
itself. A successful before/after log pair is not proof of coherent current
playback authority or common writer serialization.

Let B=`0xADD368` be the player base and D=`0xADD468` its current `0xA88`-byte
descriptor. The established identity fields are path D+4 and cue D+`0x424`.
These coincide with B+`0x104` and B+`0x524`, respectively.

## Concrete mutation boundaries

| Boundary | Original instruction evidence | Publication consequence |
| --- | --- | --- |
| Public property 24 copy | Table `0x92123C+24*4` selects `0x42AC00`; `0x42AC0C` calls `memcpy(D,source,0xA88)` | Already captured by the passive bridge. The copied value can be empty. |
| Same-file and general commits | `0x42CBDC` and `0x42CD5C` call the same full-size copy | Both sites matter; one is not a substitute for the other. |
| Preparation path clear | `0x429EF8`: `sh zero,+0x104(s0)` with s0=B | Invalidates the path without either commit-copy hook. |
| Full descriptor clear | `0x42DECC`: `memset(D,0,0xA88)` | Independent clear writer, not a property-24 setter call. |
| Public cue setter | Property 17 selects `0x42AC68`; its branch delay slot at `0x42AC6C` stores s2 to B+`0x524` | Potential identity mutation without a whole-descriptor copy; direct invocation evidence is qualified below. |
| Player initialization | `0x42B9DC`: `memset(B,0,0x1E68)` | Contains D and its identity fields. Reinitialization, if possible during an adapter lifetime, needs lifecycle invalidation. |

Preparation `0x429E80` tests B+`0x18` at `0x429EC0..C4`; zero skips the
path-clearing block. After the intervening calls, `0x429EF8` clears only the
first UTF-16 path unit, not the whole descriptor. The direct calls to this
helper are `0x42C2B4`, `0x42CD38`, and `0x42E7D8`. The general commit calls it
at `0x42CD38`, then calls `0x428DE0`, tests its item pointer, and only later
copies at `0x42CD5C`. Hence a clear can precede the existing observed copy;
it must not be silently replaced by an assumption of unchanged playback.

The full-clear function `0x42DEA0` has twelve statically direct calls:
`0x423284`, `0x42DFE0`, `0x42E164`, `0x4521FC`, `0x4522EC`, `0x4F9550`,
`0x5026A0`, `0x503044`, `0x5055F0`, `0x5098B8`, `0x532DE4`, `0x538588`.
This is a direct-instruction inventory, not proof that every caller runs in
the tested UI sequence or that there are no indirect entries.

There is also a clear routed through the public setter: `0x531150` zeroes a
stack descriptor at sp+`0x18`, and `0x531170` passes it as property 24. This
route already reaches the bridge's `0x42AC0C` hook. Its empty identity must
be classified as a clear, not accepted as a usable path/cue identity.

## Potential cue setter is not an observed transition

The branch/store for property 17 is definite original code. The bounded
direct-call argument audit, however, finds no property-17 argument among the
69 direct calls to `0x42AB20`. The local straight-line helper resolves 66;
the three remaining setups are pinned separately:

- `0x42E564` branches to the setup for `0x42E7C0`, assigning property 19 in
  the branch delay slot at `0x42E568`.
- `0x42E898` branches to the setup for `0x42E928`, assigning property 19 in
  the branch delay slot at `0x42E89C`.
- `0x445180` assigns property 23 before the branch at `0x445188` to the
  setter call at `0x4451D4`.

The three direct property-24 calls remain `0x4B55E8`, `0x531170`, and
`0x533C68`. This supports a narrow distinction: property 17 is a potential
setter boundary, not an established user-action path or measured event.
Neither the bounded argument scan nor this note proves absence of indirect,
interior-entry, alias-based or bulk identity writes.

## General commit source can alias its destination

There are two statically direct calls to `0x42CC60`:

- `0x42E42C` passes a1=sp+`0x18`, the event-9 staged stack item discussed in
  the earlier dispatch audit.
- `0x42E598` passes a1=`0xADD468`, the current global descriptor itself.

`0x42CC84` saves the argument in s1; `0x42CD58` supplies s1 to the original
copy at `0x42CD5C`. Both caller classes therefore converge on the same inner
hook and return address `0x42CD64`. That return address alone cannot establish
source provenance, independent ownership, or exclusion of another writer.
The conditional earlier path clear also applies to this general function;
this note does not assert which branch the alias-source invocation takes.

The passive bridge copies source identity before stock's copy, then emits a
completion referring to the earlier record without rereading the source.
That avoids a later borrowed-source read, but does not convert arbitrary
concurrent source access into a coherent snapshot. Its reservation order is
also not a linearization order for stock mutations.

## Consequences for the host protocol and future adapter

The host-only `PlaybackPublication` protocol models correctly serialized,
coherent copied inputs. It withdraws the published value at mutation begin,
uses a non-reused revision/ticket, and publishes only after the matching end.
A ready `None` represents a completed clear; not-ready `None` represents an
in-flight or faulted publication. Overlap, invalid input, mismatched completion
or loss disables that instance. These are executable protocol rules, not
implemented MIPS memory ordering, source ownership, or hook coverage.

A reveal proposal must bind playback revision as well as identity. Otherwise
A -> B -> A, a same-value write, or clear/restore between proposal and apply
can evade identity equality. Transient publication withdrawal must cancel
authority without accidentally turning every ordinary commit into a fresh
policy baseline; actual clear/uncertainty has separate policy consequences.

An eventual live adapter still needs before-mutation coverage for relevant
writers, source admission, cross-thread publication ordering, and UI/list
ownership through the final setter/refresh. The stock refresh invocation at
`0x499CB4` supplies borrowed current V/C values, not a retained owner or a
generation certificate. No arbitrary timer read of the global descriptor or
saved UI pointer is authorized by these findings.

## Checks

`scripts/test_folderfollow_reveal_playback_contract.py` contains eleven
hash-gated tests for exact original words and their decoded instructions,
the bounded direct-call inventories, the public-setter branch table and
nonlocal argument setups, the two clear mechanisms, initialization extent,
and the two general-commit source classes. The preserved source is required;
a missing or mismatched reference is an error, not a skipped test.

These tests are deliberately not an all-writers, whole-CFG, thread-safety,
input-coherence, object-lifetime or hardware-behavior proof.
