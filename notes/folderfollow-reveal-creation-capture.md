# Offline emitted per-invocation creation capture

2026-10-26. Successor to [explicit carrier publication](folderfollow-reveal-owner-carrier.md).
The previous fixture observed issuer registers in Python. This step instead
emits an explicit registration wrapper and a commit sink: the retained output
comes from MIPS instructions executed for that exact registration invocation.
No native explorer call site, worker queue, object layout or firmware image is
changed. This is a local prototype, not deployment or native lifetime authority.

## An owned output from the exact creation invocation

The new explicit interface is `register(U, descriptor20, out32)`. It snapshots
all five descriptor words in its private frame, arms a fresh capture slot and
calls actual native4389E0 once with that owned descriptor. An optional issuer
commit callback receives `(U, owned_request36, binding_sequence, owner)` only
after a positive checked owner and binding publication. The callback is absent
by default; old issuance/receipt/carrier compositions remain unchanged.

The sink preserves all registers and HI/LO. Before any request read it pins
A1 to the actual issuer snapshot at sink-entrySP+0x90, without wrapping; an
identical copied request at another address is not admitted. It validates the request's exact
wrapper continuation and derives its invocation's wrapper frame from the
native40-byte frame. It also requires nativeSP to equal the actual sink-entry
SP plus the known192-byte receipt and192-byte issuer frames, without wrapping;
another live armed frame with the same U/engine cannot be substituted. It then
checks that private frame's armed state and copied
controller/engine before writing the pair once. No global output pointer, TLS,
latest count, historical row search or engine/node/name lookup selects a sink.
Genuine coherent call scope and retained private mapped frames remain premises;
saved return PCs do not authenticate hostile forged stacks. In particular the
all-register-preserving sink saves its frame before validation, like the earlier
receipt/issuer callbacks. Its initial stack validity/nonaliasing is not proved.

After native return, only a fresh captured pair and native result0 permit
export into independently owned write-once output. The output must be entirely
zero both before registration and before export; no caller output is reset or
reused by this API. Body words precede magic publication. There is no reminting
or retry if callback/capture is missing, denied, stale, consumed or malformed.
Export denial can follow an already published native node, owner or binding;
it is not rollback or absence of side effects. The wrapper returns nativeV0
and either the output address or zero inV1; preflight refusal returnsFFFFFFFF/0
without entering registration. This is an explicit new ABI, not a native patch.

The32-byte output consists of magic, flags, U, opaque engine scalar, binding
sequence, owner, receipt sequence and native result. The flag is explicitly
`HISTORICAL_RELEASE_UNOBSERVED`. Even native0 plus a fresh positive pair does
NOT certify successful raw13C release, safe use/free or current UI ownership.
Native437DA0/466DC0 still discard that result, and registration438A68 forces
zero. A raw13C release error may therefore export the same historical record.
All raw errors still require full-instance external isolation; no retry, guessed
unlock, cleanup, retire/close, shared quarantine write after uncertain release
or reacquisition-to-infer-release is introduced. A native allocation failure
still skips registry unlock. These original defects are preserved, not fixed.

Capture happens after issuer binding commit but before the receipt observer's
later journal commit and before native unlock. Thus the record is specifically
an issuer event, not a receipt-prefix/release certificate. Tests may consume a
pair with the explicit producer only under separate fixture trust in raw-zero
service behavior, never because the historical flag confers admission.

## Bounds, ABI and composition

Wrapper preflight excludes its own frame, full descriptor and output extents
from each other, complete receipt/binding/owner state, controller, both mutexes,
pinned native RX and the exact complete generated RX. It denies before frame
save or source/output access when those bounds fail. Arbitrary mapping, source
coherence, private output ownership and full nested native/library stack remain
caller premises, not consequences of arithmetic bounds. The sink's all-register
save has the stronger prior stack premise described above.

The new composer orders checked/pinned kernel, capture wrapper/sink, callback-
enabled issuer, receipt and explicit producer adapter. A fixed-width second
pass gives the capture wrapper the exact complete RX extent without changing
layout. Static checks include whole component extents, not just entrypoints.
Old composers/builders remain untouched. CallbackNone preserves old issuer
bytes and labels; optional descriptor validation cannot prove arbitrary callee
semantics. The composition binds the actual generated callback/kernel entries.
Four coherent receipt redirects remain required; arbitrary partial activation
is unsupported. This stage adds no lifetime/free or complete lock-order proof.

The wrapper uses160 bytes; receipt, issuer and sink each use192. At capture
that is736 helper bytes plus the40-byte native registration frame (776 total),
before any additional native/library costs. The distinct kernel path instead
adds its160-byte frame, totaling744 helper/native registration bytes. Sink and
kernel are not simultaneously nested; adding both would overstate this bounded
stack sum. Neither sum proves actual available stack or scheduling safety.

## Why the native explorer path is still unwired

The source audit now identifies an earlier generation-loss boundary than the
paint producer. Worker4BA99C..4BAA04 walks the registry inside its native13C
callback bracket, copying only resource names into an8192-byte stack area with
64-byte stride. The copy is native strcpy, not a checked64-byte copy; neither
name length nor fanout count is proved bounded by this source observation.

After registry unlock,4BAA20 calls43A0C0(U,name) and4BAA34 re-resolves resource
through485DE0. The callback receives the newly found engine, not a retained
creation pair. Equal names or a field read at callback entry can therefore
adopt a replacement. The name lookup itself reads node+8 after its unlock,
which is not a retained native engine lease. The existing callback's fifth
argument already contains selected-action data; it is not a spare owner word.

A future native transport needs an owned owner-scoped context before deferral,
or exact per-target capture under a genuinely checked registry bracket carried
with that selected slot. It also needs bounded snapshot growth, real raw unlock
observation, copy/queue/callback/free participation and retained controller/
engine/resource storage. This explicit creation output is one prerequisite,
not any of that coverage. No real explorer callback or worker consumes it yet.

## Verification scope

The fixture executes original registration/wrapper instructions and emitted
receipt, issuer, sink, wrapper and checked owner code. Its output is read only
from emitted stores; the previous Python pair-capture observer is bypassed.
Raw pthread and allocator services remain bounded hostile-ABI substitutes, not
a concurrent scheduler, real loader/imports or lifetime simulation. Pinned
source contracts bound the newly observed name-rebinding and release gaps.
Exact counts, sizes and byte identity checks are recorded in [status](status.md).

Default composition is22,676 code bytes:12,248 checked/pinned kernel,4,232
capture wrapper/sink,1,708 callback-enabled issuer,2,288 receipt and2,200
explicit producer adapter. At the preceding fixture addresses, SHA-256 is
`90be0fdb56fa349782d7a5b89009661ca26484ad1beed25fb8628ddfc2383da5`.
Private shared state stays656 receipt+784 bindings+328 owner bytes; each
independently retained caller-owned output needs32 more bytes. The old18,416-
byte explicit-carrier composition remainsSHA-256
`b085c15d00bff87ebb8211a574b5921a12f20030de42e7c7e7bbe426dae74394`.

Serial focused verification: **346 tests pass, no skips** (24.788 s):56 new
checks (18 basic/emitted output/ABI,27 adversarial/configuration,11 pinned
native-source contracts), plus290 prior carrier/issuance/receipt/retirement/
admission checks. Every positive capture comes from the emitted output stores,
not Python issuer observation or later binding-table recovery. Tests include
write-once output, hostile input/output changes, distinct equal-engine owners,
consumed capture, foreign valid armed frames and identical foreign requests,
whole generated RX/state/adjacent bounds, raw errors and partial effects,
ALL-GPR/HI/LO preservation, and unchanged old golden modes.

Fresh serial full regression: **2,399 tests pass, no skips** (374.412 s).
All255 Python sources compile;10 changed/new text paths pass whitespace checks.
Old18,416-byte carrier and new22,676-byte capture compositions have the exact
hashes above. Saved action-link, playback-dispatch and renderer-transport images
are exactly reverified against02fd with unchangedd4306357...,a9a6f02f...,
f42fac46... hashes, scrollingFalse/hardwareUNTESTED. Existing firmware builders/
decoders,40-byte core, launcher/timers/assertions are unchanged fromf371c83.
No firmware image was built or modified, no assertion or timer was weakened.

No device/network action, installation, commit or push in this step. Active
scrolling stays disabled and hardware is UNTESTED; changes remain local.

The opt-in [raw registry-release successor](folderfollow-reveal-registry-release.md)
adds three coherent observers and a distinct flag only for actual same-invocation
raw-zero release. This historical/default mode remains byte-identical; neither
mode grants native lifetime, retry, cleanup or explorer transport authority.
