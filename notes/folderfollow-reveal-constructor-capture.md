# Offline first-constructor creation capture

2026-10-27. Successor to the [checked transport queue](folderfollow-reveal-deferred-queue.md).
This removes a creation-handoff gap on an explicit local path: actual43AD00
constructs an engine and calls actual4389E0, but normally returns only the raw
engine while discarding registration status and the creation pair. This wrapper
captures that same invocation, not a later name/pointer/current-table lookup.
It does not replace the explorer call at492918, install hooks or retain objects.

## Explicit request and result, not an accidental fifth argument

The new `construct(U, request12, out48)` request owns three words: the native
A1 descriptor pointer, A2 callback and A3 callback context. First constructor
43AD00 already uses all four native argument registers. The second constructor
is43AF00, not43AEC0 (which is inside the first epilogue); it is not intercepted.

The mutable native descriptor is at least104 bytes, not the inner20-byte registry
request. Native code reads through+64, writes+5C and scans its string prefix with
strlen. The explicit wrapper first guards request/output/frame extents, checks
all12 output words zero, reads and guards the descriptor pointer, and rejects
unless the first64 bytes contain NUL. The pointer is retained after this guard,
not reread from mutable request+0 into an unchecked argument. Descriptor/request
coherence, exclusive access and valid mapping for the complete call remain
caller premises; the native descriptor is not snapshotted or made immutable.

No native constructor action or output write precedes these checks. Actual
43AD00 then executes once with the three native values. The result is exported
only if the constructor actually returns and out48 is still entirely zero.
Preflight denial returns(FFFFFFFF,0); a returning constructor always preserves
its actual engineV0. V1 is the exported out48 pointer, or0 if the second output
check refuses export. Neither a nonnull engine nor an output pointer alone
means successful registration, isolation, safe retry, safe use or safe free.

The result layout is:

| Offset | Meaning |
| --- | --- |
| 00..1F | Exact checked GCAP32 only on a matching positive capture; otherwise CNFL magic followed by zero words |
| 20 | Actual returned native engine scalar |
| 24 | Actual checked-register entry return V0 |
| 28 | Actual checked-register entry return V1 |
| 2C | Witness flags:0 missing;1 observed;3 observed and matching positive capture |

REG_SEEN distinguishes missing interception from an actual zero result. The
registration V1 may be an exact error or a historical private-stack pointer;
it is a diagnostic scalar only, never a retained dereferenceable output handle.
These are the composed checked-register wrapper's actual return words, not a
reconstruction of every raw pthread result. Observed(0,0) remains ambiguous:
quota/export denial or masked native acquisition failure can produce it. No
already-erased raw acquisition status is recovered and no cause is inferred
from a later table lookup. Zero does not prove that native insertion was absent.
GCAP positivity additionally requires observed raw-release flag2, native result0,
the exact private capture pointer, pinnedU, bounded sequence/owner values and
capturedENGINE equal to the actual constructor return. CNFL cannot enter the
existing envelope packer as GCAP. Body words and witness fields precede magic
publication. No call, table lookup or native-object read follows native return.

## One genuine constructor invocation

Only the local instruction-fetch override at43AE8C changes: JAL to the bridge
retains the original delay-slot `A1=constructorSP+50` and return43AE94. The
native136-byte frame stores its outer return at+84. The bridge checks actual
RA, U, descriptor pointer and complete native-frame arithmetic/exclusions, then
that saved return equals this emitted wrapper's native_return, BEFORE any read
of its candidate outer frame. Unmatched legacy calls tail-forward to original
4389E0 with unchanged SP/RA/A0..A3 and without allocating the bridge's160 frame.

Only a bound retained outer256 frame with pinnedU and fresh ARMED tag enters
the checked capture wrapper. Tag progresses ARMED->ENTERED->RETURNED. Exact
register V0/V1 are saved before native43AE94 overwrites them. Duplicate/reentrant
bound entry invalidates positive export rather than reusing the first capture.
The actual checked register supplies private GCAP through the existing coherent
receipt/issuer/sink/release route; Python never reconstructs a pair from a table
or observed issuer registers. Missing/old/partial hooks do not authorize capture.
Scalar saved-return/tag tests are not authentication against forged stacks.

This adds one coherent local override to the preceding seven receipt/release
overrides. Source census finds13 encoded direct43AD00 callers and two4389E0
callers (43AE8C,43B030), not complete indirect-call coverage. Existing explorer
and all other native callers still do not invoke the new outer API by themselves.
No constructor/node/object layout, callback ABI or native allocation is widened.

## Native error continuation is deliberately NOT isolated

The constructor ignores registration V0/V1 and continues through519FA0, then
dereferences the engine/name before returning its saved engine.519FA0 can call
widget setter8B43C0 and name resolver43A0C0. A checked registration raw error
or denied capture does NOT stop that native continuation. The diagnostic
wrapper records this fact; it does not turn the constructor into an admitted
transaction or claim external quarantine was performed soon enough.
If an uncertain release retained nonrecursive R, that continuation can also
reenter/block on registry lookup. The returning test substitute does not prove
termination of the real native continuation or that an error can be reported
before unsafe work starts. No output is promised if native execution never returns.

The first constructor's missing-resource/failed-validation branches reach this
same continuation with a NULL saved engine. Engine allocation failure likewise
reaches a NULL name load. These native paths can fault before any out48 export;
tests must preserve that fault rather than manufacture a graceful NULL return.
Registration allocation failure still omits unlock. Native unchecked lock and
unlock facades still mask their real results. No guessed unlock, early epilogue,
rollback, repair, retry, destructor, rescan or UI suppression is introduced.

Even a positive exact GCAP does not retain engine, resource, controller or
callback context.4395A0 can unlink and destroy the engine/name/node under13C;
explorer493F44 then493F50 separately deletes resource metadata. The worker later
re-resolves both engine and resource by name and its callback dereferences their
graphs. A generation scalar is not an engine/resource allocation lease. Full
pre-mutation teardown participation, retained contexts, bounded fanout and safe
deferred continuations remain gates before any native worker/UI connection.

## Composition and verification premises

The full queue/capture/envelope prefix is composed with the new fragment in two
passes. Actual checked register entry and coherent hook targets are bound; outer
source-taking RX guards extend over the exact new tail. Zero-default queue
following_code_bytes preserves the preceding34,200-byte composition. Q56/T24/
fault4 are extra constructor exclusions, distinct from all old fixed storage.
Standalone protected_code=None only knows its own fragment and register entry
word; the rest of the callee RX remains an explicit caller separation premise.

Guards cover the named dynamic extents, outer256 frame, bound native136 frame
and bridge160 frame. Complete deeper native/import stacks, heap/table/chunk
mapping, initialization, coherent services and actual retained objects are not
proved. The bounded capture path is256 outer+136 constructor+160 bridge+776
checked creation=1,328 bytes before additional native/library costs.519FA0's
separate320-byte frame and transitive lookup/UI paths are not all nested with
that capture path and have no complete stack or scheduling proof here.

Verification executes actual constructor/engine/registration instructions with
explicit bounded import/resource/UI-continuation substitutes. Substituting the
UI continuation does not prove it harmless; pinned source and error tests show
that it is still reached. Exact identities, test boundaries and fresh regression
results are recorded in [status](status.md). No image, device/network operation,
installation, commit or push; active scrolling disabled, hardware UNTESTED.

Serial focused verification passes577 tests without skips (106.247 s), including
62 new checks:16 actualconstructor/ABI/path,31 adverse/boundary/config and15
pinned source. Fresh serial full regression passes2,630 tests without skips
(396.598 s). All273 Python sources compile without writing files;10 changed/new
text paths pass whitespace checks. No existing assertion/timer was weakened.

The fragment is5,876 bytes after the34,200-byte queue prefix, for40,076 bytes.
Canonical fixture addresses are receipt01F50000,binding01F80000,owner01F70000,
U01800000,R01F20300,P01F20200,CODE01E80000,Q01FF0000,T01F20400,fault01FE0000,
with16 receipt/binding/owner slots,40 transport slots and64 paint capacity.
The exactly reverified SHA-256 is
`3bf7a75351ea9c91d2ff629d1a24f6deb478a918b2fa2696217f8c250c000693`.
All preceding18,416/22,676/25,716/30,224/34,200-byte compositions retain their
documented hashes. The three saved action-link/playback-dispatch/renderer-
transport images retain d4306357...,a9a6f02f...,f42fac46... and unchanged exact
verification against02fd with autoscrollFalse/hardwareUNTESTED. Existing firmware
builders/decoders,40-byte core and launcher/timers remain unchanged fromf02b5fe.
No firmware image was built or modified; all changes remain local/uncommitted.
