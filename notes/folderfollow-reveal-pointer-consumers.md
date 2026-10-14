# Current-descriptor pointer consumers: bounded classification

2026-10-14. Offline inspection of the required `02fd` reference:
`artifacts/import-20261001/hiby_player_02fd.bin`, 7,133,528 bytes, SHA-256
`02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87`.
No player access or binary changes. This follows the pointer escapes identified
by the [guard stage](folderfollow-reveal-guard-stage.md).

## Result

Several concrete escaped-pointer consumers can now be distinguished from
writers. None of the inspected routes adds a definite path/cue writer to the
existing inventory. **That is not a complete no-writers result.** In particular,
the `B+0xBA0` callback target remains unresolved, and metadata interior pointers
are passed to indirect UI methods. Neither route is admitted as a coherent
playback-publication boundary.

Here B=`0xADD368`, D=`0xADD468`, descriptor size=`0xA88`, identity path=D+4,
cue=D+`0x424`. The getter at `0x42AD60` takes property in a0, an optional
copy destination in a1, and an optional pointer-out address in a2. Property 24
selects `0x42B048` in table `0x9212B8`. It can copy D into caller storage at
`0x42B058`, then publish D itself through the pointer-out at `0x42B074`.
The return tail invokes the player's `+0x4C` unlock at `0x42ADBC`.
Consequently, a returned pointer is not a retained read lease.

## Direct getter inventory and concrete uses

The bounded direct-JAL scan finds 216 getter calls. Its local argument resolver
identifies 34 property-24 calls. One further property-24 call at `0x4ED678`
receives a0=24 from the branch delay slot at `0x4ED638`. The two other locally
unresolved calls, `0x446A6C` and `0x446AA0`, instead receive property 28 from
`0x446A04` and `0x4469F0`. These are static direct calls, not all possible
indirect/interior entries or evidence of runtime execution.

Among those 35 property-24 sites, 13 provide nonzero pointer-out storage:

| Getter call(s) | Bounded consumer classification |
| --- | --- |
| `41BD54` | Reads metadata D+`52C` and D+`20C` as sources for copies/appends into stack strings. The alternate `442EC0` call does not consume its apparent a1 descriptor argument: that function uses incoming a0, not incoming a1. |
| `444628` | Compares D+4 with another path (`44465C`) and loads D+`424` (`44466C`). The UTF-16 comparison routine `41FC80` reads its arguments. Subsequent playback requests are separate stock operations, not stores through this borrowed D. |
| `475938` | Loads metadata D+`A58` at `475970`. The other pointer read by this routine comes from property 28, not from D. |
| `4977D8` | Reads the first path unit at `4977F8` and D+0 at `497848`, then selects a UI/playback branch. No identity store was identified in this bounded path. |
| `4B4794` | Reads D+`414` at `4B47BC` and D+`A80` at `4B4A7C`/`4B4AF4` for UI selection. These are not stores into D. |
| `4E8EE8` | Saves D in a stack slot, then copies path D+4 and title D+`20C` into stack strings. The apparent terminator write `4E8FE8` targets the result of searching the **stack copy**, not D. |
| `4E9C64`, `4E9EE8` | Put D in shared local slot sp+`1B00` before UI visibility updates. That large looping function reuses the same slot for other output values; this audit does not treat a local absence of immediate dereference as proof that its whole lifetime is inert. |
| `4ED4D0`, `4ED83C`, `4ED87C` | Forward D as a1 to command 9 of `424F60` at `4ED4DC`, `4ED848`, `4ED888`; see the copy-direction analysis below. |
| `4EDA00` | Loads scalar metadata and copies/appends metadata strings into stack display buffers. Representative sources are D+`42C` (`4EDA54`), D+`62C` (`4EDCE4`), and D+`A5C` (`4EDB60`). |
| `522BAC` | Compares/copies metadata strings from D+`20C` and D+`52C`; also passes those interior pointers to indirect UI method `+190` at `5230C4` and `522FFC`. This remains an indirect interior-pointer escape, not a proven write or a proven non-retaining reader. |

The other 22 identified direct property-24 calls provide a2=0 and use the
copy-out interface. Their destinations and all subsequent consumers are not
an all-alias proof. The table above deliberately separates concrete first-hop
operations from claims about complete transitive behavior.

## Command 9 is a source copy, not an observed store through D

The three forwarding calls pass the pointer obtained from the getter unchanged
as a1 and command number 9 as a0. `424F60` saves incoming a1 at sp+`844`, takes
a context mutex, and dispatches through `0x920834`. Entry 9 selects `425128`:

- `42512C` loads the saved argument into a1;
- `42513C` loads the destination into a0 from context+`2C`;
- `425140` calls `memcpy(a0,a1,0xA88)`.

Thus D is the source operand of this copy; there is no direct store to D in
this command's block. The destination comes from context storage, not a literal
D address. This does **not** establish the context destination's allocation,
non-aliasing, source coherence, or a common lock with every writer to D.
Forwarding D does not itself make the copy coherent. Calling this command
"another descriptor commit" on the basis of its size alone would be wrong.

## The two player callbacks remain a gate

`42CBFC..42CC10` and `42D690..42D6A4` load the callback from B+`BA0`, context
from B+`B98`, and call it with a1=D. The bounded player-text scan
`428B00..42EAA0` finds just those two memory operands with immediate `BA0`,
both loads. No binding of a concrete callback target was established.

The initialization memset at `42B9DC` spans B..B+`1E68`, including both slots.
Zero-initialization and absence of a matching direct store are **not** proof
that the callback stays null: aliases, table/bulk copies, and other code remain
possible. The similarly numbered fields in unrelated objects around `6C...`
are not evidence of a player callback binding. This audit therefore leaves
both indirect callbacks unclassified and does not remove their safety gate.

## Integration consequence and checks

Do not instrument the source-only consumers as new mutations merely because
they receive D. Conversely, do not certify the known nine mutation hooks as
complete merely because no additional writer appeared here. A coherent
publication still needs writer coverage, source ownership, ordering, and
logical operation completion; UI lifetime/transaction admission is separate.

`scripts/test_folderfollow_reveal_pointer_contract.py` pins these bounded
inventories, nonlocal argument setups, representative consumer directions,
the command-9 block, getter unlock, and unresolved callback anchors. It requires
the exact preserved source and fails rather than skipping when it is absent or
mismatched. Static anchors are not a whole-CFG, alias, concurrency, callback
binding, or hardware-behavior proof.
