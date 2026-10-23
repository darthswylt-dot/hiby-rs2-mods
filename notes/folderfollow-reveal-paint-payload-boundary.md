# Paint payload, removal ownership and different native mutexes

2026-10-23. Local source audit and executable counterexamples following the
[explicit notification-to-BIRTH stage](folderfollow-reveal-action-link-stage.md).
No firmware code, builder, image, native allocation, stack frame, hook or
snapshot layout changes. No player connection, install, launch, rearm, signal,
reboot, timer or UI action. Hardware remains UNTESTED and scrolling disabled.
The only host-decoder change explains these limitations more precisely; every
existing algorithm, association, refusal and authority flag is retained.

## Result: three different obligations

The explicit historical notification ID is valid without proving that native
paint bytes remain stable or that later removal still targets that selected
entry. There is also a known purge using a **different controller mutex**.
Consequently neither the historical ID nor merely copying under the paint
mutex is a complete native ownership/coherence solution.

| Obligation | What is needed | What the current ID observes |
| --- | --- | --- |
| Copied bytes | A completed, stable payload copy protected against every relevant writer during acquisition | Selected invocation ancestry, not rectangle values |
| Exact selected-entry claim/removal | A serialized claim/removal protocol, not a later deletion of whichever record is now index0 | The original selected ID, not ownership of the current FIFO head |
| Engine/controller lifetime | A retained lifetime and cancellation contract across actual use | Borrowed numeric addresses only |

This step does not assert that the controlled interleavings below occur on
the user's player or explain its observed folder-follow defect. It establishes
why a passing historical receipt is insufficient to authorize a native action.

The pinned reference remains7,133,528 bytes, SHA-256
`02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87`.
New source contracts use that exact local input; missing/mismatched source is
an error, not a skipped check.

## Actual native borrow and delayed reads

The paint record has native words0/4, engine at+8, four inline rectangle words
at+C/+10/+14/+18 and metadata at+1C. The separate diagnostic image adds its
explicit ID at+20, for36 bytes in total. Common producer43C860 initializes0/4
to zero and copies the rectangle before439900 appends under the paint mutex.

Getter4399C0 locks through controller+284, selects index0 via list+2C, then
unlocks through controller+288 at4399F0. Its delay stores the selected pointer
in its own SP+18; its epilogue returns that same pointer. This is a borrowed
element address, not a retained allocation or an owned payload copy.

Consumer43C900 reads all of the following **after** that unlock:

| Source instruction | Use |
| --- | --- |
| 43C920 | Load selected element+8 to choose the zero-engine branch |
| 43C960 | Load element+8 again as the actual redraw engine |
| 43C964 | Load element+1C as native metadata |
| 43C968/96C | Call459840 with element+C as the rectangle address |

459840 can then call8B4280 at459874 with the same borrowed rectangle address.
The existing BIRTH observer at8B428C captures this **address**, not the rectangle
values. Native allocation at8B42B0 occurs before the four separate loads:

| Instruction | Register | Rectangle word |
| --- | --- | --- |
| 8B42C4 | a3 | 0 |
| 8B42C8 | a1 | 1 |
| 8B42CC | v1 | 2 |
| 8B42D0 | v0 | 3 |

The values are subsequently stored into the allocated16-byte copy. The last
store remains the delay slot8B42EC of original enqueue JAL8B42E8, with native
returnPC8B42F0. Nothing in the current historical journal compares those four
loaded words with values at the selected-delivery boundary.

For an initial rectangle `(1,16,8,8)`, a controlled replacement with
`(101,202,303,404)` before8B42C8 yields `(1,202,303,404)`: the first word has
already been loaded. The explicit SOURCE -> actual BIRTH link can still be
structurally valid, because engine, input address, metadata, frame and IDs
match. Its coherence/lifetime/currentness flags correctly remain false.

## Removal is by current index, not by the retained historical ID

Consumer43C900 does not mark or write the selected native body. A nonnull
selection follows439960(U,0) after zero engine, a false global predicate, or
return from459840. The removal target is **current index0**, not the selected
address, its ID or a conditional compare against the selected element.

In a controlled interleaving, another actual native removal can move B over A's
head address after A was selected. A's frozen diagnostic parent remains A;
the native reads can now observe B, and the original consumer's later removal
can remove B too. Equal rectangle/engine/metadata values do not cure this
selected-entry ownership gap. A private copy alone would stabilize its bytes
but would not make the later current-index0 removal refer to A.

There are **two encoded direct callers** of43C900:43C9AC in loop43C980 and
43CA8C in loop43CA60. The source census does not establish simultaneous
execution, mutual exclusion, a unique OS thread, all computed aliases or
complete lifecycle serialization. Tests do not infer a scheduler from these
two call sites.

## Known purge is outside the paint mutex protocol

The controller constructor binds distinct callback pairs and mutex fields:

| Controller callbacks | Native functions | Mutex field | Inspected use |
| --- | --- | --- | --- |
| +274/+278 | 437D20/437DA0 | +13C | Resource registry and439780 purge caller |
| +284/+288 | 437CE0/437D60 | +148 | Paint append, getter, normal index removal and destruction |

439780 acquires the **registry** bracket at4397B8 and calls4396C0 at4397F8.
4396C0 traverses the paint list at controller+128, reads each element's engine
and name, and calls the list's removal method+20 at439760 for a matching name.
It does not acquire the paint+148 bracket. Its caller tail-dispatches registry
unlock through+278 at43982C after its own other native work.

Thus paint+148 alone is not a demonstrated exclusion boundary against every
known paint-list mutation. A future copy/claim design must include this purge
and destructor/cancellation paths, or establish an applicable caller/lifecycle
exclusion. Merely adding another pointer check or holding+148 longer does not
provide that proof. Combining mutexes also requires an explicit lock-order
audit; neither a new nested order nor callback-under-lock behavior is admitted
by this note.

The new bounded native fixture also executes439780,4396C0, the actual registry
lock callbacks and dynamic-width list removal. One interleaving invokes purge
after getter unlock; another invokes it at4399F0 while paint+148 remains held
and the selected delivery ID has already been published. Registry+13C can be
acquired/released without acquiring+148 in this model. With one live element,
the native removal shifts a zero following element into the old head; the
consumer observes engine0, attempts its original later removal (which returns
FFFFFFFE for an empty list), and does not call BIRTH. The frozen historical
delivery stays incomplete, not repaired by matching addresses.

String comparison and registry cleanup8B0760 are explicit bounded services in
that fixture, not a resource destructor or lifetime model. The interleaving
demonstrates the distinct lock protocol, not actual simultaneous-thread
reachability, native mutex scheduling, or a hardware reproduction.

## The predicate does not validate an object

468D40 consists of four instructions: load globalB896D0 and return whether it
is zero. It ignores a0 entirely. Its positive result cannot establish that
the passed controller/engine is live, owned, current or even a valid pointer.
The existing instruction fixture's receiver assertions are argument-domain
checks for its substitute, not native object-validity tests. That comment is
now explicit; no fixture predicate, assertion or production behavior changed.

## Constraints for the next implementation

A real payload handoff needs stable acquisition, selected-entry ownership and
engine/controller lifetime considered separately. A stack-owned copy must
live in the **consumer** frame until all native loads finish, not in a popped
observer/getter frame. The current40-byte consumer frame has savedS0 at+1C,
S1 at+20, RA at+24 and the diagnostic ID at+18; it has no spare36-byte region.
An examined, but **not implemented**,80-byte frame could reserve+28..4B for
36 bytes and+4C for completion, leaving old saved-register offsets intact.

Routing native input to such a copy would change actual BIRTH.INPUT from
native element+C to consumerSP+34. It requires a clearly versioned owned-copy
binding. The original selected record cannot silently be relabelled as its
copy, and old pointer equality must not be relaxed to keep an apparent link.
Diagnostic exhaustion/unknown ancestry must not suppress ordinary native
work; it also cannot turn a borrowed fallback into an owned receipt.

Removing the selected element under a common bracket before rendering and
skipping later removal would change native ordering/visibility. Keeping later
removal requires a claim/check that cannot delete a different head after
purge or relocation. Neither policy is selected here without the shared
writer/cancellation and lock-order contract. Engine retention, complete
playback coverage and a final admitted UI transaction remain unproved.

## Local verification

All **45 new focused checks pass** (4.859 s):18 pinned-source contracts and27
native-interleaving cases. They execute changes after getter unlock, after
BIRTH, before each of the four native rectangle loads and after the registers
are loaded; change/restore remains unproven. Actual native FIFO removal between
loads shifts B over A and yields each of the three mixed old/new prefixes,
without corrupting the suspended native register state. Full/fault/retry-loss,
engine/metadata mismatch, zero parent, no head, identical/different next
payloads, null engine and current-index removal paths remain deny-only.

The preceding146 action-link checks also pass (33.365 s). Independent source,
fixture, decoder and documentation review found no remaining actionable issue.
The new exact-source census includes direct J/JAL, integer and coprocessor
branch forms, but not computed targets or runtime writes. No existing test,
native behavior, format, refusal or authority algorithm was weakened.

Full repository regression: **1,895 tests pass, no skips** (313.633 s).
All221 Python scripts compile; tracked/new text files pass whitespace checks.
No legacy launcher, test timer, existing assertion or refusal was changed.

All three saved ignored diagnostic images are exactly reverified with
unchanged SHA-256:

- Action link: `d4306357ec6b70153b15e98202dad1a7ad0615d02ea6bd9e0d53857844ab37a8`.
- Optional playback dispatch: `a9a6f02fd48a3b57e27e3bb19c9e8c2b8329b6602cc12988091dfbb98c2abe2c`.
- Renderer transport: `f42fac46890dc2eadbeba88f90ce5b82857d3045752b974b15d04bef263d2244`.

No new firmware artifact, player/network operation, commit or push occurred.
These changes remain local/uncommitted. No new payload read or capture policy
is enabled on the player; active reveal remains disabled and hardware UNTESTED.

The next [host-only paint-queue implementation](folderfollow-reveal-paint-queue.md)
implements a retained exact claim and cancellation before owner-accounting
release. It does not install a native mutex/lifetime adapter or change the
borrowed-input bindings examined here.
