# Exact-source boundary for a diagnostic queue-birth receipt

2026-10-21. Local source audit for a diagnostic observer, not a scrolling
implementation or native queue-ownership proof. Pinned reference:
`artifacts/import-20261001/hiby_player_02fd.bin`, 7,133,528 bytes, SHA-256
`02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87`.
The source premises are checked by
`scripts/test_reveal_queue_birth_contract.py`.

## Observe birth before the native allocation

`8B4280` first reads C+44. A null value returns zero at `8B43B8/BC`
without allocating its native frame. The proposed observer does not cover
that rejected route and must not invent a receipt for it.

The first replaceable linear pair after that guard is:

| Site | Original words | Resume |
| --- | --- | --- |
| `8B428C` | `27BDFFC0` / `AFB00030`: allocate 40-byte frame, save s0 | `8B4294` |
| `8B42E0` | `AE230008` / `02202821`: store third rectangle word, set append payload | `8B42E8` |
| `8B42F0` | `8E280000` / `8E240004`: load first two copied rectangle words | `8B42F8` |

The entry wrapper can replay its pair, preserve all live registers and
HI/LO, then sample only private diagnostic state before the native
allocation or publication. The live inputs there are C in a0, the original
rectangle pointer in a1, and untouched metadata in a2. No extra input-pointer
dereference is justified by this entry site alone. A nonnull-rectangle BIRTH
record may store these as numeric scalar values together with its native
frame identity and frozen private samples.

For a null rectangle, the native branch at `8B42A0` ORs `40000000` into
C+3C at `8B4398`, then invalidates parent geometry. It has no queue-copy
allocation or individual queued request. The diagnostic carrier should be
zero on this route, without changing the native full-redraw bit, arguments
or return. A missing receipt here is intentional unknown coverage, not a
fresh full-redraw identity.

## The middle event is prepared, not already published

The first native allocation remains **16 bytes** at `8B42B0`. The second
allocation, inside generic append `8B3CC0`, also remains **16 bytes**.
Neither payload nor node has spare storage, and this design does not grow
them, read a tail, reuse metadata, or install a native-pointer registry.

Immediately before `8B42E0`, the four native rectangle words have already
been loaded into **a3, a1, v1, v0**. Their allocated copy pointer is s1,
C is s0, and original metadata is a2 (also saved at native SP+28).
An ENQUEUE_BEGIN observer could copy those scalar values without adding a
native rectangle read. The implemented observer instead records only seven
numeric identity fields (engine, original input address, allocated-copy
address, metadata, frame, site, result), not the rectangle coordinates. It
replays `sw v1,+8(s1)` and `move a1,s1` before its private save/capture, then
restores the pending fourth-word value in v0 for the original delay store.

There is **no** native linear pair after all four stores but before append:
the fourth store, `sw v0,+C(s1)`, is the original JAL delay instruction at
`8B42EC`. The native `jal 8B3CC0` at `8B42E8` and that delay instruction
must remain byte-identical. ENQUEUE_BEGIN therefore means that allocation
exists and the four scalar values are prepared. It must not be described
as a fully stored or successfully linked request.

The original JAL produces return address **8B42F0**. An ENQUEUE_RETURN
observer at that exact pair can preserve actual v0 before native `8B42F8`
overwrites it. The generic helper returns the raw newly allocated node
pointer on its two linked paths, or zero when node allocation fails before
linking. This is not a normalized success code. The outer function later
returns zero even after a generic append failure; its final zero must not
be substituted for the exact append result. Initial rectangle allocation
failure is separate and returns -1 without reaching either middle hook.

## One local carrier, not a queue-consumer identity

The bounded native `8B4280..8B43C0` body uses SP-relative offsets
18/1C/20/24/28/30/34/38/3C and only forms a local SP+18 address. It neither
directly accesses SP+14 nor forms that address. Its four encoded calls are
allocator `8B0D00`, generic append `8B3CC0`, geometry helper `8B3220` and
parent invalidation `8B06E0`; there is no encoded indirect call or locally
formed outgoing stack argument. This supports a local SP+14 scalar carrier,
subject to the callees' normal ABI and absence of unrelated alias writes.
It is not a proof against all possible callees or concurrent native memory
corruption.

The carrier may hold the invocation's BIRTH ID, then be replaced by its
linked ENQUEUE_BEGIN ID. ENQUEUE_RETURN reads that scalar before replaying
the original native loads. Every diagnostic association must validate the
private published record, kind, exact native frame and numeric original
inputs. No association follows from a reused C, rectangle or node address.

All native frame behavior remains: entry saves s0 at +30, later saves
RA/s2/s1 at +3C/+38/+34, and the epilogue restores those values and pops
exactly 0x40 (64) bytes at `8B4368`. The wrappers need their own disjoint frames;
native SP+14 is not storage for the wrappers' saved register sets.

The executable-section scan finds no encoded direct J/JAL or conditional
branch target at any of the six hook words. There is also no aligned
file-backed word equal to those six addresses. Those are bounded source
facts, not proof that computed/indirect entries or aliases are impossible.

## What the receipt does not establish

This stage is only historical evidence that one exact native invocation
prepared a queued rectangle before a known private revision boundary.
Private revision/scope samples do not constitute a native owner lease or
an atomic view of all writers. A receipt without all linked events remains
incomplete; an entry event alone cannot distinguish a suspended allocator
from an allocation failure. Faulted, lost, duplicate, reordered or mismatched
events must not be repaired with new callback-time identities.

No queue-consumer association or callback-frame transport is implemented
by this source audit. Raw address equality must not be used later as an
implicit registry. Full/coalesced/synthetic requests, native lifetime,
current folder/playback cause, complete writer coverage, coherent acquisition,
the retained UI transaction and active scrolling remain independent gates.
These contracts do not authorize hardware installation or a player operation.
