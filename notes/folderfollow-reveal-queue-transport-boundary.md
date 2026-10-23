# Explicit generic-node queue transport source boundary

Offline source contract, 2026-10-22. No device access, installation, launch,
reboot or active scrolling is authorized. The native allocation extension
described here belongs only to a separate explicit diagnostic stage; preceding
builders and their default images must remain unchanged. Hardware is UNTESTED.

Reference: `artifacts/import-20261001/hiby_player_02fd.bin`, 7,133,528 bytes,
SHA-256 `02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87`.
`scripts/test_reveal_queue_transport_contract.py` checks the exact source
premises below. It fails, rather than skipping, on a missing or different
reference. Addresses and offsets are hexadecimal.

## Widen the generic node, not the rectangle

The original generic append `8B3CC0` allocates a 16-byte node through its sole
allocator call at `8B3CE0`. The allocation-size instruction at `8B3CCC` is
`24040010`. The explicit transport stage changes this one instruction to
`24040014`, making every allocation through this helper 20 bytes.
The six encoded direct callers are `8B083C`, `8B0E30`, `8B0EA4`, `8B0FB4`,
`8B1060` and paint enqueue `8B42E8`. The change is therefore not paint-only.
Unknown computed/indirect entry is not excluded by this direct-call inventory.

The node prefix remains payload at 0, metadata at 4, previous at 8 and next at
C. The new word is **node+10**, not rectangle+10. The paint rectangle copy
still allocates its original 16 bytes at `8B42A8/42B0`. Its four coordinates
and the last store in the original append-call delay `8B42EC` stay unchanged.
Native metadata is not a token slot and must remain untouched.

The larger allocation is a real native behavior change. It increases memory
consumption for all six classified callers and can change allocation-success
outcomes or timing. Preserving the allocator call, result and native failure
branches does not make memory pressure or successful outcomes identical.
This source contract is not deployment approval for that tradeoff.

## Initialize before either publication path

The exact post-allocation pair is:

| Site | Original words | Required relocation |
| --- | --- | --- |
| `8B3CE8/3CEC` | `10400010 / 8FBF0024` | Branch on actual v0; restore original RA on both routes |

The native delay instruction `lw ra,+24(sp)` runs whether allocation failed or
succeeded. On v0=0, the interceptor must restore RA and continue at `8B3D2C`
without accessing node+10, inventing a node, retrying or changing the actual
result. On nonnull v0, it may initialize the newly allocated word to zero,
perform the private identity check and resume at `8B3CF0` with original live
registers and HI/LO restored. The allocator call at `3CE0` and its metadata
delay `move s1,a2` at `3CE4` remain original.

Stock code writes only the old prefix. Empty-list publication is the store to
the list head at `8B3D4C`; nonempty publication is the store to previous tail's
next at `8B3D24`. Zero initialization and any valid ID installation must finish
before either. All other generic callers retain zero in the new word. A
private journal fault must not stop stock append or manufacture a trusted ID.

The generic native frame is 0x28 bytes, saved RA at +24. At this point s0 is the
target-list address, s2 the payload, s1 the unmodified metadata and v0 the new
node. Only restored original RA `8B42F0` admits the paint-producer ancestor.
Before reading that ancestor's carrier, validate this exact call route; producer
SP is genericSP+28 and its SP+14 carrier is genericSP+3C. A private published
ENQUEUE_BEGIN must bind that frame, engine/list, copied payload and metadata.
It cannot be reconstructed by matching raw node, rectangle or engine addresses.

An INSTALL receipt records the private binding before the wrapper's subsequent
tail store. Alone, it confirms neither that store nor the following native
append/publication. Existing RETURN receipts preserve the actual append result
and still have a separate role; an orphan INSTALL stays incomplete.

## Conditional node type at the queued consumer

The classified C constructor allocates and zeroes its 84-byte object, so C+34
starts empty. The classified paint producer passes C+34 to the widened generic
append. Ordinary cleanup and buffer-allocation failure delete the queue through
`8B3F00(...,1)` then clear C+34. This supports a **bounded closed-producer/type
premise** for this explicit diagnostic image: nodes reached on that classified
queue were allocated by its widened helper.

It does not prove that all possible alias writers, imported/preexisting nodes,
runtime callback replacements, corruption or concurrent frees are impossible.
Numeric node equality is not an allocation-size certificate or retained lease.
The consumer's new node+10 read is conditional on this stated native type and
lifetime premise, not on a private record lookup making an arbitrary pointer
safe. No callback later in the chain should read that tail again.

The queued-loop hook pair `8B4754/4758` is `lw a1,0(fp); lw a2,4(fp)`. It must
replay both original payload/metadata reads, read the widened current node+10
once under that premise, then create a private BORROW bound to exact parent
loop SP, C in s5, current node in fp and those loaded payload/metadata scalars.
The parent native SP+14 receives that BORROW ID, or zero for unsupported input.
Neither private lookup nor a newly sampled current generation repairs an
invalid or missing node receipt.

The original `jal 8B3FA0` at `8B475C` and its a0=s5 delay at `8B4760` must remain
byte-identical: original helper RA is `8B4764`. There are known inbound branches
to the hook's first word from `8B4768` (next node) and `8B49BC` (after full
redraw). There is no encoded target into its second word or the original call
and delay. A full callback at `8B4990` remains unknown even when the same
native pass subsequently reaches real queued nodes through `8B49BC`.

## Helper and callback invocation carriers

| Boundary | Native frame | Local carrier | Source condition before ancestor carrier read |
| --- | --- | --- | --- |
| `8B3FA0/3FA4` | B8 | SP+14 | Original live RA `8B4764`, exact private BORROW frame/C/fp/payload/metadata binding |
| `439EC0/9EC4` | 38 | SP+14 | Original RA `8B40EC`, expected descriptor/C and helper saved RA `8B4764`, exact private HELPER binding |

The helper entry pair is `27BDFF48 / AFB600B0`: allocate B8 and save old s6.
Its later original RA save is `8B3FB0` at SP+B4. Replay the pair first, clear
its own carrier and preserve original RA until the native later save. Before
reading parentSP+14 (helperSP+CC), gate RA `8B4764`; then validate the private
BORROW against parentSP=helperSP+B8, C/a0 matching incoming parent s5, current
fp/node, payload a1 and metadata a2. A valid result creates a separate private
HELPER receipt and is carried in helper SP+14. The legitimate nonqueued calls
at `8B4A14` and `8B4AF8` must remain zero without an ancestor or rectangle-tail
read. Their rectangles are native buffer/stack data, not widened queue nodes.

Do not substitute a hidden a3 argument. Although `8B3FA0` itself explicitly
loads a3 only later, it forwards incoming a3 to native helper `8B3220` at
`8B3FD8` before that load; local absence of an a3 use proves no callee contract.

The helper preserves C in s6, metadata in s5 and original queued rectangle in
s3. Its split loop can invoke C+48 multiple times at `8B40E4`, with descriptor
at helperSP+58. Original return PC is `8B40EC`; the delay at `8B40E8` stores
unchanged metadata into descriptor+10. One helper receipt therefore may parent
several distinct callback receipts; neither collapse nor a global current-ID
slot is justified.

Callback entry `439EC0/9EC4` is `27BDFFC8 / AFBF0034`. Let its native SP be B,
helper SP Q=B+38. After replay, clear callback SP+14. First gate original RA
`8B40EC`, a1==B+90 (Q+58) and a0==incoming helper s6. Then gate saved helper RA
at B+EC (Q+B4) equal to `8B4764` before reading helper carrier B+4C (Q+14).
The private HELPER must bind Q, C, fp/node, original rectangle in incoming s3
and metadata in incoming s5. A separate CALLBACK receipt goes into B+14.
Full callback RA `8B4998` and all unclassified routes remain zero without these
ancestor reads. The callback adds no native queue-tail or rectangle-tail read.

The complete bounded stack inventories of parent `8B4660..8B4BC8`, helper
`8B3FA0..8B4120` and callback `439EC0..43A044` contain no direct SP+14 access or
formed SP+14 address. Outgoing argument homes, callee writes, aliasing and native
geometry-buffer bounds remain ABI/native-behavior premises, not universal
stack ownership guarantees.

## Cleanup, census and remaining gates

Generic delete `8B3E00` reads only node prefix 0/4/8/C and frees the node through
`8B0D20` at `8B3E80` with the node pointer in a0, without a size argument. Paint
mode-one cleanup invokes `8B3100`, which frees the separate payload pointer.
This source behavior does not require shrinking a widened node or freeing the
receipt ID, and it is not proof about allocator internals or memory pressure.

The executable direct-target census includes J/JAL, ordinary/likely, REGIMM
and COP branch encodings. It finds no target at `3CE8/3CEC`, `439EC0/9EC4`,
or helper entry+4. Helper entry itself has precisely the three direct callers
listed above; queue-loop first word has the two known branches. No aligned
file-backed pointer literal equals any word of those four hook pairs. These
bounded facts exclude neither computed entries nor opaque aliases/unwind.

This source audit does not implement the stage or transport into outer
`438200`/child renderer, join births to row receipts, classify every producer
or writer, freeze an original UI/playback cause, retain native C/W/V/job data,
prove coherent capture or authorize an offset setter. The existing
[callback/outer boundary](folderfollow-reveal-request-callback-boundary.md)
and [queue safety requirements](folderfollow-reveal-request-queue-safety.md)
remain separate gates. All active reveal/current-owner/UI-authority claims
must remain false.
