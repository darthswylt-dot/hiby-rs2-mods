# Read-only comparison of a queued birth with its recorded history

2026-10-28. This separate offline branch consumes the exact historical token
and owned payload from [the typed birth FIFO](folderfollow-reveal-birth-queue.md)
and compares that birth with its recorded lifecycle row. It does not replace a
token with the latest matching node, engine or name. A successful comparison
means that two observations agree, not that a native object is still alive.
No native pointer is followed, no paint is published and no player operation
or firmware image is provided.

## Separate BOBS100 output

`take(U, zero_out100)` returns an owned diagnostic snapshot, not an extended
stock queue record, BCAP48, BQ84, GCAP32 or rendering request.

| Offset | Meaning |
| --- | --- |
| 00 | `BOBS` output magic |
| 04..50 | Exact queued BQ84 body, including its original birth token and owned payload |
| 54 | Observed BRLC state: 1 no retirement observed, or 2 retirement selected |
| 58,5C,60 | Observed retirement site, frame SP and caller |

The 80 bytes at offsets 04..53 are copied from that extracted BQ84 without
rewriting the token or adopting another row. State 1 is
`NO_RETIREMENT_OBSERVED`, never LIVE. State 2 is `RETIREMENT_SELECTED`, not
DEAD, completed deletion or proof of free. Both states can be exported as
observed metadata. An unknown state, inconsistent retirement fields or an
unrecognized selected-retirement site refuses the comparison.

## Extract first, then take a fresh history observation

The consumer checks the complete 100-byte output, combined known outer/pop
frame extents and all fixed/native/generated RX exclusions before output reads
or saving its outer frame. All 25 output words must initially be zero. It
then calls the existing checked `pop` exactly once into a zeroed private
84-byte area. That wrapper copies the borrowed queue head before native
REMOVE, releases the separate ordinary T and only then commits its owned
BQ84 output. There is no T/R nesting and no reacquisition of T for a failed
comparison.

Only successful extraction permits a fresh actual raw acquisition of the
pinned ordinary R. Under R, the consumer checks the controller's pinned
R/lock/unlock bindings and reads the bounded BRLC history. It validates the
whole occupied prefix, row tokens and fixed birth fields, both allowed states
and their retirement schemas, uniqueness of all outstanding node scalars,
and every unused tail word. It selects only the queued token and compares
all its birth words at offsets 04..27 with that exact BRLC row. It never
chooses a row by a latest-by-address search.

History is read-only here: a faulted, malformed or nonmatching history is
refused without latching a new history fault, repairing storage, marking
retirement or modifying a row. Body comparison is not authentication of
fabricated queue/history data. Node, engine and historical SP/caller words
remain opaque scalars; none is dereferenced as a native allocation.

The matching state and retirement metadata are copied privately while R is
genuinely held. After actual raw release returns zero, the complete 25-word
output is checked again. The owned body and observation words are written
first and `BOBS` magic committed last. Success returns `(out100, 0)`;
empty extraction and ordinary refusal return `(0, 0)`. No shared/history or
native/service access follows the successful release before export.

## Extraction is not delivery or native authority

The FIFO record has already been removed when a normal history refusal,
missing token, birth mismatch or later dirty output prevents export. There is
no requeue, retry, rollback, paint acknowledgement or completion guarantee.
Concurrent drainers can complete their later comparisons/exports in a
different order from FIFO extraction.

Actual nonzero raw T or R acquisition/release status returns
`(0, exact_status)` immediately. After the error, only retained private-frame
storage is accessed: no later caller output, history, queue or fault access,
no guessed unlock, extra service call or retry. A T error never starts R work.
Uncertain ownership requires synchronous coordinated isolation of the WHOLE
combined instance, including all queue and history users. No late shared
fault write is used to pretend that isolation has happened.

The exported metadata is a snapshot at the R-held comparison, not a lease
covering export or future use. Retirement can be selected immediately after
release. More fundamentally, missed native raw-error deletion and unobserved
same-address birth can leave an apparently healthy history correlated with
the wrong native incarnation. Exact token/body comparison does not close
those missing-event gaps. No current-LIVE query, retention certificate,
safe native continuation, pointer-use permission or cleanup/free authority
is supplied.

## Storage and composition boundary

All preceding BQ84 premises remain: correctly initialized retained ordinary
T and R, coherent participation by every user, retained mapped native header,
table and complete allocated chunks, exclusive output and independent
nonaliasing frame/storage ownership. Native REMOVE may copy spare slots, not
only live bytes. Bounds and the known combined 416-byte outer/pop guard do
not establish allocation mapping, unknown heap/table/chunk aliases, history
coverage or sufficient transitive native/service stack. The initial
architectural-save/storage prerequisites of inherited internal callbacks are
unchanged.
Neither ordinary T nor R may already be held on entry. Immediate known-frame
guards do not replace the independent nonaliasing premise for the complete
native table/chunk graph and every caller/native/service stack allocation.

`reveal_birth_consumer_stage.assemble` takes the same arguments and bounded
options as the BQ84 stage. It appends the consumer fragment and extends the
exact protected generated RX extent through every preceding prefix and queue
guard. The BQ84 stage's opt-in following-RX reservation does not append bytes;
its default zero reservation preserves the preceding thirteen composition
hashes. The existing 16 coherent fixture hook pairs remain the same source
sites. No additional stock producer/worker hook, shared allocation, installer,
firmware image, player/network action, commit or push is implied.

At the preceding canonical receipt/binding/owner/U/R/P/CODE addresses,
lifecycle 01F3A000, Q 01FF2000, T 01F20700 and fault 01F20800 with 40 native
allocated slots, this composition is 85,044 bytes: the guarded 81,344-byte
queue prefix plus a 3,700-byte consumer. SHA-256:
`765759c2a2ee7a29a2f6d7f0b9af90496d4ef0510a5d1fe809c6bb6fbd9db71f`.
The default BQ84 stage remains 81,344 bytes and SHA-256
`95ced6cf23eeda0a1db56f0461d5a5dd331bdc0fa6bfd4b431e937fb799b80d9`.

Pinned-source contracts and emitted-code fixtures are local evidence, with
bounded raw mutex, heap/libc and scheduling substitutes. They do not prove
hardware pthread behavior, complete lifecycle coverage, object lifetime or
OS scheduling. Active scrolling remains disabled; hardware is UNTESTED.
Current serial verification totals are recorded in [status](status.md).

A subsequent opt-in [acquisition gate](folderfollow-reveal-registry-acquire-gate.md)
adds two pre-mutation refusals to a separate composition. It blocks the observed
raw-error registration/name-delete bodies, not ignored caller continuation or
every other writer. The default BOBS consumer, its historical-only interpretation
and all remaining lifecycle/retention/isolation gates are unchanged.
