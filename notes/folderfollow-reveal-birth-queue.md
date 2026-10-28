# Typed transport of an exact historical birth token

2026-10-28. This separate offline branch transports the exact token exported by
[owned birth capture](folderfollow-reveal-birth-capture.md). It does not recover
a token by looking up a latest node, engine, name or history row. The transport
is diagnostic: neither a token nor successful FIFO extraction proves that a
native object is still alive. Missing lifecycle events and unchecked native
continuation remain unresolved. No image is built, no hooks are installed and
no player operation is provided.

## Separate BQ84 format

The new FIFO stores its own 84-byte type; no BCAP48, GCAP32, READY68,
retained-operation72 or stock worker record is extended or reinterpreted.

| Offset | Meaning |
| --- | --- |
| 00 | `BQ84` typed transport magic |
| 04 | Exact captured lifecycle birth token |
| 08,0C | Captured controller and pinned registry mutex |
| 10,14 | Historical node and engine scalars |
| 18,1C | Historical native registration frame SP and caller |
| 20,24 | Publication site 438A5C and actual acquisition status zero |
| 28,2C | Native registration result and observed raw release status, both zero |
| 30..50 | Owned 36-byte payload; its engine word at +08 equals the captured engine |

Offsets 04..2F copy the BCAP body without replacing its token. The node, engine
and native frame words are opaque historical scalars. They are not followed,
looked up, required to remain allocated or turned into live pointer handles.
Arithmetic, fixed-field and engine-equality checks do not authenticate fabricated
captures, source ownership or provenance outside the coherent capture route.

## Enqueue is one attempt per owned source

`enqueue(U, exclusive_BCAP48, owned_payload36)` checks complete arithmetic and
known fixed/native/generated RX exclusions for both inputs and the outer frame
before reading either source or saving the frame. The inputs and frame must be
pairwise disjoint. It snapshots all 48+36 bytes into its private frame, validates
BCAP, a token in 1..configured lifecycle capacity, pinned U/R, the checked
capture's exact native-return caller, site 438A5C, three zero result/status words
and matching payload engine scalar. Only then does it change the exclusive
source magic to `BCNS`, before the first raw transport-mutex call.

Consumption is not conditional on append success: full, an already faulted
queue, header refusal, native append anomaly or uncertain raw error still uses
that source's one attempt. Invalid input/schema refuses without consuming it.
Copying a capture beforehand creates independently consumable inputs; there
is no global replay-prevention table and no native-birth rollback or retry.

The dedicated preallocated native FIFO has a 56-byte header, width 84, chunk 10
and a pinned positive allocated capacity that is a multiple of 10 in 10..10240.
All accesses use a separate correctly initialized, retained ordinary mutex T,
not the stock worker's mutex and not registry R or paint P. Full capacity is
refused before native APPEND can enter its nontransactional growth path. On
success, the actual native returned index and incremented count must agree;
the result is `(native_index+1, 0)`. Ordinary refusal returns `(0, 0)`.

## Pop exports an owned copy after checked release

`pop(U, zero_out84)` checks all 21 output words are zero after complete known
extent/alias guards and before saving its outer frame. Under T it validates
the pinned header and calls the actual native GET. The returned head is
borrowed: its complete 84-byte extent must exclude known fixed/generated/native
RX, this invocation's frame and the complete caller output. It is copied into
private storage before schema validation and before native REMOVE can reuse
or shift its storage. Actual REMOVE zero and the exact decremented count must
both agree.

After raw release returns zero, the entire 21-word output is checked a second
time. The body is copied from the private snapshot and `BQ84` magic committed
last. Success returns `(out84, 0)`; empty or ordinary refusal returns `(0, 0)`.
An output dirtied during the operation is refused after extraction, without
putting the record back. This is not transactional delivery or completion.

There is no dispatcher, callback, paint publication, GCAP conversion, R/P
acquisition, native engine/resource access, cleanup call or destructor. Removing
an item acknowledges only transport extraction, not rendering, operation
completion, safe native use, object retention, native incarnation or permission
to unlink/free. Multiple drainers can consume FIFO heads but finish later work
in another order; no stronger scheduling guarantee is inferred.

## Faults, raw errors and storage premises

One initially zero retained fault word latches permanently under T:
header 1, head 2, append 3, remove 4. A faulted instance refuses further queue work;
there is no automatic clear/reset, rollback or recovery. Actual nonzero raw
acquire/release returns `(0, exact_status)` immediately. After that raw error,
the wrapper accesses only its retained private frame: no late source/output,
queue/header/fault read or write, guessed unlock, retry or extra service call.
The caller must arrange synchronous coordinated isolation of the WHOLE
instance after uncertain raw ownership; absence of a late fault write is not
evidence that an error did not occur.

Every queue user, including future clear/destroy/rebind/bypass routes, must
cooperate with T. The native table and all allocated complete chunks must be
mapped, retained and nonaliasing, as must all exclusive inputs/output and the
complete nested native/service stack. Native REMOVE can move spare slots:
count 1/chunk 10/width 84 still shifts 756 spare bytes. Guarded pointer arithmetic
does not prove mapping, allocation ownership, native retention or separation
from unknown heap/table/chunk graphs. The borrowed-head/output comparison
handles that known immediate alias, not every possible indirect alias. Native
header +04 is deliberately not checked for zero: the pinned factory does not
initialize it.

## Composition and verification boundary

`reveal_birth_queue_stage.assemble` takes the seven canonical
receipt/binding/owner/U/R/P/code arguments followed by lifecycle history, Q, T
and the retained fault word. It composes checked birth capture and appends only
the diagnostic enqueue/pop fragment. The existing 16 coherent fixture hooks are
preserved; no stock producer/worker route is redirected. Q/T/fault exclusions
propagate through the parent's outer guards, and the exact complete generated
RX extent protects both prefixes and the new tail. Strict default-empty
following-RX and extra-data options preserve the preceding twelve default
composition hashes. These outer guards are not universal certification of all
internal entries, native heap graphs or transitive stack storage.

At the preceding canonical receipt/binding/owner/U/R/P/CODE addresses,
lifecycle 01F3A000, Q 01FF2000, T 01F20700, fault 01F20800 and 40 allocated slots,
the prefix is 74,724 bytes and the new transport core 6,620 bytes: 81,344 total,
SHA-256
`95ced6cf23eeda0a1db56f0461d5a5dd331bdc0fa6bfd4b431e937fb799b80d9`.
The default BCAP-only stage remains 65,796 bytes with SHA-256
`76a95966f8e35f8053408b9a7cd0c472cabd0fed53ea9f1234af261a07331cb7`.
The larger guarded prefix reflects the Q/T/fault exclusions, not a change to
the defaults of preceding compositions.

The emitted/native fixtures execute the actual FIFO APPEND/GET/REMOVE and the
new wrappers, with bounded raw mutex, heap/libc and scheduling substitutes.
They do not prove hardware mutex behaviour, OS scheduling, complete lifecycle
coverage or native allocation lifetime. No current-LIVE query, constructor or
explorer integration, firmware image change, installer, player/network action,
commit or push is implied. Active scrolling remains disabled; hardware is
UNTESTED. Current serial verification totals are recorded in [status](status.md).

The subsequent [historical consumer](folderfollow-reveal-birth-consumer.md)
drains this FIFO into its own private storage, then acquires R separately to
compare the exact token and birth fields with the complete validated history.
It exports the recorded retirement-observation metadata as BOBS100 only after
checked R release. This does not add a dispatcher or authenticate current native
lifetime. Its zero-default following-RX option protects the consumer tail while
preserving the default BQ84 composition's bytes and labels.
