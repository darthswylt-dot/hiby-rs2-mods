# Tidal queue transport and refusal review

Date: 2026-11-12. Source: `artifacts/import-20261001/hiby_player_02fd.bin`,
SHA-256 `02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87`.
The diagnostic baseline is `scripts/reveal_tidal_job_snapshot_mips.py`
with 44 coherent redirects. The first sections record its native boundaries.
The later local operation and close-seal composers described below have 47
redirects. No firmware image or player operation is introduced here.

## What the serial transport establishes

`454B40` places command and argument in its private stack frame and calls
`4504E0` with a fixed size of eight bytes. The ring writer allocates a separate
packet, copies those eight bytes before returning, and publishes its pointer.
Thus the selected serial path does not retain the POST caller's stack pointer.
The local command-zero generation is copied by value; no session pointer is
embedded in this packet. The selected QR descriptor's lifetime is separate.

Native `450600` copies eight bytes into the worker frame, releases the packet,
clears the slot and advances the read index before returning success. The
worker copies the two scalar fields again from SP+828 to SP+820. Under serial,
successful, live-object conditions this preserves the captured generation.
The native writer's zero/-1 result reaches POST's caller without masking.

The ring is created with capacity 50 in `4554E0`, published at `45559C` in
`B89250`, and consumed by the identified worker `454380` at `454410`. Its
stop/drain/destroy route is `4556E0`; the queue is passed to `4507E0` at
`455754`. That call releases queued packets and the ring itself.

## Reproduced boundaries

The new tests run actual pinned instructions with bounded allocation/copy/free
services. Scheduling cuts are explicit and reproducible. These are conditional
counterexamples, not observations of a player crash or proof that native caller
threads execute those schedules.

| Boundary | Native evidence and fixture result |
| --- | --- |
| Admission is not atomic | The ring's +C field is tested and incremented with ordinary loads/stores. Two POST producers can both pass the zero test, compute the same next index, then both return zero while one allocated packet lies outside the logical read/write interval. The session generation mutex is already released before ring admission. |
| Allocation refusal is unchecked | After `4669E0` returns NULL, `45056C..45057C` supplies that NULL to memcpy with size eight. No refusal branch intervenes. The fixture rejects this service input; it does not execute libc or claim a particular hardware exception. The ring's +C remains one at that cut. |
| Packet lifetime needs reader serialization | Two conditional consumers can capture the same slot pointer before one copies, frees and clears it. The other then attempts a copy from retired packet storage. Only one Tidal worker consumer is currently identified; the test does not establish a second native Tidal consumer. |
| A generation capture does not pin the queue | A command-zero POST can finish its session admission with WRITER/BORROWS both zero. The stamped close gate can enter CLOSING, and the selected native queue-destroy suffix can then free the ring. Resuming the earlier admitted POST reads the retired ring because it has no queue receipt or recheck. This isolates the suffix under the worker-stop premise rather than emulating a successful native join. |
| Native queue refusal leaves earlier pending state | A full or absent ring returns -1 but does not undo the earlier status arm. Caller tests separately distinguish local generation-gate refusal from a native queue refusal after admission. |

The two-producer case requires concurrent producers; a complete native producer
thread/binding census is not established. The two-reader case requires a second
consumer; it is a generic ring boundary, not a claim about normal Tidal worker
topology. Physical memory ordering, allocator behavior and actual scheduling
remain outside the fixture. The schedules already expose problems under the
fixture's sequentially consistent shared-memory execution.

## Startup and shutdown are still premises

Source startup zeros the 352-byte context, allocates/publishes the ring and
constructs separate handshake/lifetime mutexes. The wrappers around native
operations hide important results:

- `466D60` calls raw mutex initialization even if its allocation returned NULL,
  and returns the saved pointer rather than the initialization status.
- `466DA0` and `466DC0` replace raw lock/unlock results with zero.
- `466BA0` calls thread creation but returns its stack output word after
  attribute destruction, without checking creation success or first initializing
  that output. A creation failure can leave the expected worker absent while
  startup waits on the handshake mutex it already acquired.

The successful handshake uses the worker to unlock the startup mutex. This
review does not establish that protocol's ownership/progress contract for all
runtime mutex bindings. Shutdown sets the stop flag, waits through the masked
lifetime mutex, then destroys worker state and the ring. It does not close POST
admission or clear `B89250` after ring free. The current session close gate stops
later command-zero admissions, but it does not drain POSTs already admitted;
nonzero commands also deliberately bypass that generation gate.

These findings do not establish successful worker termination, safe queue
reclamation, or safe initialization failure. Making the ring pointer NULL only
after free would not protect a producer that already loaded it.

## Refusal scope and next implementation boundary

Command-zero producers perform mutable-input/status/UI work before their POST.
Their continuation must be considered separately from the packet's ownership.
In particular, QR's local generation-gate refusal skips construction, whereas
native queue failure after successful admission can still be followed by the
native constructor. A shared pending status is not evidence of a queued request.
The native producer continuations differ:

- `478260` ignores command-zero refusal and keeps command-zero status at
  pending=1.
  With the selected later credential branch it can still post command six,
  whose native behavior deliberately bypasses the command-zero generation
  gate, even while that gate is CLOSING or FAILED. Later configuration/UI
  services still run and the caller ultimately returns zero.
- The login callers at `5077A8` and `50872C` copy new strings into shared input
  storage before POST. They ignore refusal, read status and may arm pending=1
  afterward, then continue their UI update. Neither gets input rollback from
  the generation gate.
- QR at `5082A8` distinguishes local gate refusal, which skips construction,
  from native ring-full refusal after successful admission, which is ignored
  before constructing the stamped payload. Earlier bounded file/status effects
  remain even on local policy refusal.

The exact producer tests and instruction evidence are recorded in the response
access manifest. Real configuration/UI/file/network services are substituted
in these tests, so their effects and progress are not established.

Worker rejection jumps to `4544EC`, past the ordinary busy-clear notification
at `4544E4`. The native suffix still sleeps, checks stop and either loops or
releases its independently owned worker mutex before returning. A stale BEGIN
refusal occurs before busy-set. A raw lock failure at END after busy-set retains
the existing pending status and WRITER pin; skipping the current command does
not itself complete or recover that request. The regression takes the native
stop suffix under a valid worker-mutex ownership premise and bounded sleep,
without claiming an actual successful detached-worker shutdown.

Before image integration, queue admission must be closed and admitted producers
drained before destroy; ordinary queue operations need a proven serialization
contract; allocation refusal must return without copying to NULL; and callers
need an explicit completion/refusal policy for their earlier effects. Extending
the existing session mutex over the unbounded native queue wait is not a proven
solution: it would introduce new lock-order, callback and progress obligations.

The review's passing diagnostic tests assert the present deficiencies. They do
not mean the queue is ready for firmware activation. Test counts and commands
are recorded in [project status](status.md).

## Local operation protection

`reveal_tidal_queue_operations_mips.py` composes the 44-hook baseline with three
redirects. A common ring WRITE check at `45056C` branches on allocation NULL
before memcpy. Refusal balances native +C once, publishes no slot/index and
takes the native 48-byte epilogue with V0=-1 and V1=12 (ENOMEM). Non-NULL
execution replays the displaced A0/A1 moves. Other queues receive this refusal
check but acquire no new gate.

Tidal callsites `454B5C` and `454410` use a separate retained four-byte gate.
Bounded LL/SC admits one whole native WRITE or READ, with at most four failed
reservation attempts. Contention returns -1/16 without touching the ring or
releasing another operation's gate. Admission refuses a null pointer or nonzero
legacy counter before the native sleep loop. The session mutex is not held
while the native operation runs.

The gate stays held through full native return, including READ's index store
at `4506D4` after native +C was cleared at `4506CC`. Reentry through guarded
callsites refuses instead of waiting. Release is ordered after native effects
with SYNC. Wrappers return native V0/V1 and restore other saved registers and
HI/LO, replaying the native delay effect and JAL link address. Exact native
caller-clobber effects are not claimed; these callers do not consume them.

Fifteen tests cover competing LL reservations, invalidation after a 0→1→0 gate
ABA, bounded failure/final-attempt success, producer refusal/retry, reader
serialization, publication/index ordering, reentry, legacy state and allocation
NULL. The reservation epoch is shared between modeled CPUs. Direct native ring
calls remain outside this selected-callsite protocol. Bounded native services
and ordinary return assumptions remain in force.

## One-lifetime early close seal

`reveal_tidal_queue_close_seal_mips.py` retains 47 redirects and enables the
optional seal in both existing session close gates. Under the checked session
mutex, after identity/token and zero WRITER/BORROWS validation, bounded LL/SC
changes an idle gate from 0 to SEALED=2. This precedes CLOSING and the first
native teardown call. A busy operation causes EBUSY through the pure outer
epilogue, leaving the session and operation untouched. An operation winning
between close's LL and SC also prevents retirement. The session mutex is
released before native teardown.

Selected operation wrappers reject SEALED before reading ring storage. Thus an
earlier generation-admitted POST, or a READ with an already loaded pointer,
refuses even after native ring destruction. Nonzero commands through the same
POST callsite also refuse. An unlock error after sealing retains SEALED and
CLOSING with FAILED, without guessed unseal or native teardown.

The seal is permanent in this fixture. Finish, session re-publication and
later errors never reset it. Reopening a Tidal queue is unsupported until a
separate queue-generation protocol exists. This one-lifetime limit prevents
stale pointer captures from entering a newly opened gate. Activation starts
coherently with an exclusive retained zeroed gate and a valid first ring.

Eleven tests follow both close routes, active-operation refusal/retry, both
outcomes of an LL/SC race, stale POST/READ pointer captures, raw errors,
reservation exhaustion and closure after finish/re-publication. The STOP
substitute executes only `455748..45575B`'s queue-destroy suffix under the
worker-stop premise. Earlier opaque cleanup, worker completion and startup
are not proved by this fixture.
The first native teardown callback is also checked for an already sealed gate
and a released session mutex.

The optional address passes through 12 session-to-job composers, with overlap
checks against every complete appended extent. With the option absent, all
12 emitted byte strings and patch dictionaries match their pre-change versions.
A lower close-only composition is not a queue protocol without cooperating
operation wrappers using the same gate.

All 199 targeted Tidal tests pass: 173 preceding tests, 15 operation tests and
11 close-seal tests. Caller pending recovery, fairness/retries, native creation/
stop success, opaque teardown progress, unconnected aliases and concurrent
native initialization/CLEAR/DESTROY remain outside the guarantee. No builder
or hardware test activates these composers.
