# Request callback and outer-render source boundary

Source-only audit, 2026-10-21. This note implements no callback carrier, does
not enable active reveal, and requests no player launch or physical test.

Pinned reference: `artifacts/import-20261001/hiby_player_02fd.bin`, 7,133,528
bytes, SHA-256
`02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87`.
Addresses and stack offsets below are hexadecimal original ELF values.
`scripts/test_reveal_request_callback_contract.py` requires this exact source;
it does not skip when the reference is absent.

## Earlier than the fresh cache canvas, but not the original UI request

The inspected path is persistent render object **C+48 -> 439EC0 -> 438200 ->
W+148=4906E0**. The callback begins earlier than the cache-miss allocation at
`438724 -> 47A920`; that allocation supplies the renderer's third argument.
That argument is a service/cache-canvas descriptor, not immutable original
playback/UI-request provenance. Its `+50/+60` fields are the coordinate/height
used at `49078C/490790`.

An ID freshly minted at `439EC0` would close only the narrower case of an
already-started callback crossing a known boundary. It would **not** distinguish
a newly invoked old C after that boundary. No fresh UI-cause stamp, retained
request, playback association, or permission to mutate the UI is established.
Any later transport through these frames must carry a separately justified,
already-frozen upstream invocation ID; an unsupported source stays unsupported,
not a newly minted trusted request.

## Persistent C and the bounded registered callback chain

Two bounded split-immediate constructions name `439EC0`: `43AE50/54` and
`43AFF0/F4`. Both write the callback at caller `SP+44`, descriptor `D+2C`
because D begins at `SP+18`. Calls at `43AE64` and `43B00C` pass that descriptor
to `8B4120`. The constructor allocates a persistent `54`-byte C, then copies
`D+2C` into `C+48` at `8B418C/90`. C+4C is a distinct event callback.
This bounded construction census is not a proof against runtime callback
replacement or arbitrary computed pointer constructions.

The two inspected native engine dispatches are:

| Call site | C argument | Render descriptor argument | Original continuation |
| --- | --- | --- | --- |
| `8B40E4` | `a0=s6` | `a1=engineSP+58` | `8B40EC` |
| `8B4990` | `a0=s5` | `a1=engineSP+18` | `8B4998` |

Each loads its indirect target from C+48 and builds a rectangle-pair descriptor
in its own invocation stack. Those descriptors are not stable immutable queued
requests. This audit does not assert that these are all possible indirect calls
to a C+48 target, nor does it prove UI-owner serialization or C lifetime.

## Callback lookup is current-name resolution, not a retained UI epoch

`439EC0` has native frame `38`, saved RA at `+34`. It checks a0/C and a1/render
descriptor, loads controller `s3=C+50` at `439EE8`, and checks global
`A90F94`. The global-disabled path returns zero; invalid inputs/error lookups
return minus one through their logging paths. A successful callback ultimately
forces zero; neither value is a native lifetime or settled-list certificate.

The successful path preserves C in s0 and the input rectangle descriptor in
s2, then does the following:

1. `439F34 -> 485DE0(controller+24, current C+0 name, "viewgroup")`.
   The viewgroup branch of `485DE0` calls `485420` at `485FC4` and returns
   selected resource `+D0` at `485FD8`.
2. `439F48 -> 439E20(result, result+20)` supplies W in s1. The helper compares
   names and can traverse native `+F8` links or use `437E00`; it is not a retain.
3. `439F5C -> 485420(controller+24, current C+0 name, "viewgroup")` performs
   another resource lookup. Its `+18` and optional `+CC->0` values are copied
   into callback locals `SP+18/+1C`.
4. `439F90 -> 438200(C, W, callbackSP+18, original rectangle descriptor)`.
   The delay slot forwards a3=s2. Original return address is `439F98`.

For the viewgroup registry branch, `485420` invokes manager `+193E8`, traverses
manager `+D378`, compares node `+E4` names, then invokes manager `+193EC` at
`485A00` **before returning the selected node** via `485A08/0C` and the common
epilogue. The actual callback locking/retention semantics remain opaque. There
is no source-proven retained lease across either lookup, `439E20`, or the later
render. Re-reading a matching current name is not an immutable UI epoch or an
atomic C/W transaction. No additional native lookup is proposed by this note.

## Native frames and candidate carrier space

| Native function | Frame | Saved RA | Normal JR RA / native pop |
| --- | --- | --- | --- |
| Callback `439EC0..43A044` | `38` | `34` | `439F0C/10`, `439FB4/B8` |
| Outer `438200..4388B8` | `200` | `1FC` | `438330/334`, `438694/698` |
| Child renderer `4906E0` | `30` after guards | `2C` | Existing renderer contract |

Callback direct native memory offsets are exactly `18,1C,24,28,2C,30,34`.
Its only locally derived SP address is `SP+18`; all inspected calls use at most
four register arguments, with no fifth/sixth argument write. Native callback
`SP+14` has no direct memory access or locally derived address in this body.

The outer render has native fifth arguments at `SP+10` (`438438`, `438464`,
`4384D4`), local buffers beginning at `SP+20`, and derived SP addresses
`20,140,180,190,1A0,1B0`. Native `SP+14` is absent from its complete pinned
direct-memory/address inventory. The apparently unused upper `SP+1B4` is not
an alternative safety premise: unbounded `sprintf("canvas_%s", name)` begins
at `SP+140`, so upper locals depend on name length. The low-slot claim also
assumes bounded native buffer behavior and valid O32 actual callees; absence
of a direct access is not an arbitrary alias/callee-write proof. SP+14 is
outside the four argument homes but would be a sixth outgoing argument.

The outer linear pair `438248/24C` is `s4=a2; s1=a3`, after the C/a3/controller
guards and before the first geometry/helper call. W/a1 is not separately
NULL-guarded here. A future interceptor must preserve native behavior even on
unsupported routes, replay each displaced word exactly once, and use its own
private save frame without corrupting native stack arguments or saved state.

## Candidate exact invocation gates, not an implemented transport

Let **O** be outer native SP and **B=O+200** callback native SP. At `438248`,
a bounded transport candidate can check, in this order:

- Outer saved RA `[O+1FC] == 439F98` before accessing callback ancestors.
- Callback saved RA `[O+234]` is an audited engine continuation
  (`8B40EC` or `8B4998`) before reading a candidate `[O+214]` callback carrier.
- `a2 == O+218`, C/a0 matches saved callback s0 at `[O+1D8]`, W/a1 matches
  saved callback s1 at `[O+1DC]`, a3 matches saved callback s2 at `[O+1E0]`,
  and current controller s3 matches saved callback s3 at `[O+1E4]`.
- Validate the upstream ID against its separate private provenance, without
  native pointer dereferences or a raw pointer-address registry, then copy the
  already-frozen ID into outer `SP+14`. No new current-clock stamp substitutes.

Let **R** be child renderer native SP, allocated at `4906F8`. Then O=R+30,
B=R+230. The call at `438740` passes `a0=W`, `a1=C`, and cache descriptor a2;
its delay slot passes C and its continuation is `438748`. The renderer's own
saved RA `[R+2C]` must match that continuation before ancestor reads. Outer
saved RA is `[R+22C]`, callback saved RA `[R+264]`, outer carrier `[R+44]`,
and callback carrier `[R+244]`. Original W/C/descriptor scalars can be compared
with the preserved s-register/frame values; these are numeric invocation
bindings, not new native lifetime guarantees.

The current diagnostic child renderer already uses native `SP+10` for its
original entry-revision ticket and `SP+14` for its lineage root ID; saved native
state begins at `SP+18`. **Neither word is available for an additional ID.**
A future implementation must use a distinct private frame/record extension or
a correctly gated ancestor-carrier read, not overwrite the existing carriers.

## Direct control-flow census and remaining limits

A global aligned executable-word scan includes J/JAL, ordinary/likely branches,
REGIMM and COP branch encodings. It finds no encoded external direct edge into
the callback body, and only `439F90 -> 438200` into the outer body. No encoded
direct edge enters either word of `438248/24C` or the listed callback/outer
return pairs, or entry+4. A word that happens to be executable data can overcount;
absence still excludes only encoded direct targets, never unknown indirect
calls, computed entries, exceptions or unwind. The bounded normal paths return
through the listed native epilogues; observing one would not mean SQL success,
completed destruction or UI ownership.

These contracts identify a possible invocation transport route earlier than
cache-canvas creation. They do not yet provide a pre-existing queued carrier,
cover every writer/request source, prove fresh UI cause, retain C/W/V/native
job bytes, establish coherent snapshot acquisition, or authorize the final
offset setter. Existing negative filters and always-false UI-currentness/
ownership claims must remain in force.
