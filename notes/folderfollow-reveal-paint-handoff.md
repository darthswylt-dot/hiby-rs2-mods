# Offline MIPS paint handoff: owned queue bytes and exact-head acknowledgement

2026-10-23. Follow-up to the [host paint queue](folderfollow-reveal-paint-queue.md).
This is an executable MIPS prototype exercised locally against original native
list methods. It is not wired into a firmware builder, installed on the player,
or a complete owner-lifetime adapter. No player/device access or UI action.

## Separate queue format

The prototype uses a separately versioned **40-byte element**: the previous
36 bytes remain unchanged, followed by its own non-reused publication nonce at
offset0x24. The existing LALI ID at0x20 is not reused as an entry nonce: it is
zero for unclassified producers and identifies invocation ancestry, not all
queue publications. Existing LALI/BIRTH bindings, decoders, builders and saved
images remain unchanged. In particular no owned-copy address is relabelled as
an original-record BIRTH input.

Publication, selection and acknowledgement participate in the same native
paint-mutex148 protocol. The helper bypasses the stock getter's borrowed
post-unlock return and the stock append facade's hidden failure result. It
uses the actual native list append, get and remove implementations. A separate
logical pending limit is checked: the constructor's64 is an initial capacity
request rounded to70 with ten-element segments; the native list can grow.
Neither64 nor70 is a proved maximum pending count.

The one active head remains in the native list until a matching acknowledgement.
Its 36-byte copy lives in private storage and is valid only until completion;
a later claim can reuse that buffer. Acknowledgement reselects the current
head under148 and compares its publication nonce and list binding before
removal. Equal pointers or payload words cannot substitute for that nonce.
The nonce is a private cooperative protocol identifier, not an unforgeable
host capability or proof that a particular native consumer has finished.

Cancellation marks the active claim without removing it. Close rejects new
publication/selection and cancels the active claim. Neither operation frees
an engine, removes unclaimed owners or drains the entire list. Mismatch and
native-method/service failures must not be converted into successful cleanup.
Exhaustion is nonwrapping; old exact claims can still acknowledge after new
work has been withdrawn, provided the native list remains structurally valid.

The original grow routine can store a null reallocation result into list+0
at455A08 before returning failure, despite an unchanged pending count. A raw
append failure is therefore terminal here, not a benign retryable admission
failure. A nonce may be burned but is never reused. Header/storage checks must
refuse a later acknowledgement before the native getter if that table has
been lost; the active claim remains outstanding rather than reporting false
cleanup. No queue repair, allocator rollback or forced release is invented.

An injected nonzero callback result returns denial without reading queue/private
state or attempting unlock. An injected unlock-callback failure also denies
success and writes a terminal fault in this bounded fixture. These tests replace
the466DA0/DC0 wrapper result: they do not demonstrate detection of actual
pthread failures. The original wrappers force zero regardless of the lower
result, as already recorded in the [player-lock audit](folderfollow-reveal-player-lock.md).
The40-byte helper therefore requires a genuinely held, valid guard as a caller
premise; its callback zero is not an acquisition certificate. Its post-unlock
fault store is not a general synchronized failure-recovery protocol. Denial is
not rollback or permission to retry an effect. The separate44-byte successor
has an explicit [checked raw-service mode](folderfollow-reveal-paint-admission.md).

## What the guard does not establish

All native queue mutators would need to participate before this protocol could
be installed. Stock purge439780 ->4396C0 uses13C, not148; stock439960 removes
the current index0; queue destruction4398A0 is another bypass. They are not
rewritten here. A mismatch after a bypass can be refused, but a mismatch check
does not make arbitrary bypass writes safe or restore a destroyed list.

The caller must retain the controller, list and mutex objects through each
operation. A fixed controller address is a binding, not a lifetime lease.
The caller also supplies a mapped, separate writable stack through all nested
native/libc/mutex calls. Rejecting overlap with the helper's128-byte frame is
not a bound on those callees' stack depth or proof of safe borrowed stack data.
Source publication inputs must already be coherent, owned36-byte values:
the original producer reads rectangle words at43C880..43C88C **before**148 is
acquired. Copying a queue element under148 does not repair that producer gap.

Object retirement also needs a checked continuation protocol:

- Resource deletion4395A0 must be fenced before the first registry unlink at
  439610. The name is freed at43962C and engine queue destroyed at43963C,
  before the engine free at439644. Intercepting only that last free is late.
- Detach8B0760 must be fenced before link mutation, not merely the later
  engine+40 clear or attachment free.
- Controller teardown43CB20 must be fenced before worker shutdown, not merely
  before paint-queue or mutex destruction. This inner fence is insufficient for
  its outer callers: both can unlink/free registry nodes before43CB20. The
  [admission/cleanup audit](folderfollow-reveal-paint-admission.md) records these
  earlier mutation paths; whole-controller admission must close earlier still.

An outstanding-use counter reaching zero would establish only local accounting
quiescence until all native users and mutation paths are covered. Returning
early from an existing destructor would not preserve its callers' behavior:
they have no deferred-removal result protocol. No destructor is blocked,
deferred, resumed or replaced by this prototype.

Coherent source playback, current contents, parent membership, retained native
ownership, complete invalidation coverage and an owned UI transaction remain
independent gates. Active folder-follow and scrolling remain disabled.

## Verification

All **63 focused checks pass** (4.943 s):25 basic instruction/ABI checks,
21 adversarial checks and17 pinned original-source contracts. Actual native
append/get/remove and mutex callback bodies execute; only this fixture's
in-memory constructor width changes to40. Existing builders are untouched.

Coverage includes identical/unclassified payloads with distinct nonces, raw
head removal that shifts B onto A's former address, changed list binding,
duplicate/wrong/stale acknowledgement, retained cancelled capacity, close and
nonwrapping exhaustion. Growth beyond the original70 slots preserves FIFO.
Two genuine allocation-failure paths distinguish a lost table from intact old
storage; a held claim cannot falsely acknowledge the lost-table case. Malformed
headers/private state, aliased/unaligned/wrapping selected pointers and invalid
input/frame extents are refused. Twelve deterministic60-operation sequences
match an independent retained-head oracle. Raw engine/geometry scalars are not
dereferenced and no render/destructor/UI function is invoked.

Independent source/protocol and implementation review found no remaining
actionable issue after correcting the destructive failed-grow path.
Full repository regression: **2,053 tests pass, no skips** (321.134 s).
All229 Python scripts compile; tracked/new text files pass whitespace checks.
The emitted standalone helper is4,640 code bytes with64 private state bytes
and a128-byte helper frame, excluding nested native/service frames and native
list allocations. These are prototype sizes, not a firmware loader/stack or
resource-lifetime approval.

Saved action-link, playback-dispatch and renderer-transport images are exactly
reverified against the pinned source with unchanged SHA-256 hashes
`d4306357ec6b70153b15e98202dad1a7ad0615d02ea6bd9e0d53857844ab37a8`,
`a9a6f02fd48a3b57e27e3bb19c9e8c2b8329b6602cc12988091dfbb98c2abe2c`
and `f42fac46890dc2eadbeba88f90ce5b82857d3045752b974b15d04bef263d2244`.
No existing launcher/test timer, assertion or refusal was changed or weakened.
The instruction fixture substitutes bounded memory, heap and mutex services;
it is not a target cache, scheduler, native concurrency or hardware test.
No new installable firmware image is produced by this step. Changes remain
local/uncommitted; no device/network operation, commit or push. Hardware
UNTESTED; active folder-follow and scrolling remain disabled.

The next [separate44-byte retirement prototype](folderfollow-reveal-paint-retirement.md)
adds captured owner generations, revocation before cooperative purge and a
local drained query. It leaves this40-byte implementation and all saved
images unchanged; native cleanup/lifetime integration is still required.
