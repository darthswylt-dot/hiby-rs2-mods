# Passive GENERAL notification to actual paint BIRTH

2026-10-23. Local offline diagnostic successor to the
[optional playback-dispatch stage](folderfollow-reveal-playback-dispatch-stage.md).
No player connection, installation, launch, rearm, signal, reboot, UI setter,
timer or queue injection. Hardware is UNTESTED; active reveal remains disabled.
Changes are local/uncommitted. No commit, push or network action occurred.

## The explicit historical chain

The new stage connects GENERAL's earlier `4BAC80(1,B+38,0)` notification to
the actual LQBR BIRTH returned by the existing paint observer. It does not use
the later optional BA0 call, current playback, an address registry, a queue
count or coincident sequence numbers as an invented parent.

```text
GENERAL call42D614
  -> SOURCE at4BACBC, fresh ID in action record+10
  -> actual FIFO selection under worker+10 mutex, DELIVERY at4BA96C
  -> actual explorer callback490980, EXPLORER at4909A4
  -> native43C860, PAINT at43C868, fresh ID in paint record+20
  -> actual FIFO selection before getter unlock, PAINT_DELIVERY at4399E8
  -> actual8B4280, BIRTH_LINK at8B428C -> explicit existing LQBR BIRTH ID
  -> existing queue transport -> renderer root -> captured row lineage IDs
```

This is selected-invocation/control-flow ancestry. It does not establish an
immutable media selection, coherent native paint data, live resource ownership,
current playback or complete notification coverage. Fast event11 yields
actions0/5, which this explorer ignores; those are not classified as GENERAL
action1. Other producers always initialize the added tail to zero. A matching
native address or payload cannot repair an unknown/missing parent.

## Native carrier and lifetime boundary

Two narrowly scoped element-width instructions change: action records
**16 -> 20 bytes** at4BAAF4 and paint records **32 -> 36 bytes** at439844.
Their capacity requests remain16 and64 respectively (the allocator rounds in
chunks). The earlier generic-node16 ->20 extension is inherited unchanged.
These are real allocation/memory-pressure and pre-call timing changes, not
claims of behavior-neutral instrumentation.

All 17 known direct action producers use common sender4BAC80. Its native
SP+28 is free before savedS0 at+2C; the source hook initializes that word on
every append path. Only savedRA42D61C, saved incomingS0=ADD368, action1 and
parameter2=0 admit SOURCE. Native payload words, last-word delay store, append,
unlock and wake calls remain unchanged. Native segmented append/index/remove
use the dynamic element width, so the ID moves with the record during FIFO
relocation. A reused address never becomes its identity.

The worker reads the selected action tail once under its existing mutex,
after nonnull indexed selection and a20-byte-width check. Each iteration
clears/replaces its private SP+1C delivery carrier. The exact resource callback
returnPC4BAA68 admits the explorer carrier at its free SP+30; the two exact
paint returnPCs490A10/490A60 admit the producer's free SP+38 tail. Every other
common43C860 call initializes that tail to zero. Both known direct439900
appends use this common producer.

The paint getter4399C0 returns a **borrowed record after unlocking**. Therefore
the new observer freezes its selected tail at4399E8, *before* native unlock,
after a36-byte-width check. Only savedRA43C918 permits writing the exact
consumer's free SP+18 invocation carrier. Null selections clear it as well.
No diagnostic code rereads the native tail after unlocking or looks it up by
address when the later BIRTH occurs.

Native code still reads the borrowed engine/metadata/rectangle after unlock.
This diagnostic does **not** retain/copy that whole native record or repair its
coherence. A later engine/metadata mismatch refuses the diagnostic link while
the original native call continues. Same-pointer/same-fields ABA cannot prove
coherence either, even if the selected historical control-flow ID survives.
`native_record_lease_proven` and `native_payload_coherence_proven` remain false.

At the existing BIRTH wrapper, only its one private recorder JAL is redirected
to a private post-capture helper. The helper calls the old recorder exactly
once and preserves its actual result/state. It requires incoming native
RA45987C and intermediary savedRA43C970 before reading the deeper consumer
carrier, then records the actual returned LQBR ID. The existing native
JAL/JALR instructions, delay stores, native return addresses, R10/R14 carriers,
old BIRTH-return store, and callback dispatch remain unchanged. Failure/full/
fault cannot veto a native enqueue, callback or paint call.

Direct-call and inbound inventories are bounded pinned-source audits. They do
not exclude runtime writes, computed aliases or unknown consumers. Exact
frame gates and initialization are not a proof of universal native coverage.

## Private journal and host decoding

`reveal_action_link_mips.py` emits a separate16-byte header and96-byte LALI
records. Six kinds carry immutable parent/origin IDs and seventeen owned
scalars. Capture and validation check the whole bounded kind/site/frame/
payload ancestry and the external private LQBR BIRTH binding. Eight bounded
LL/SC reservation attempts never reuse/wrap IDs; magic is published last and
fault is terminal. The core reads only private journals, wrapper-owned metadata
and its own stack. Native-looking scalar values are not dereferenced by it.

The standalone decoder accepts exact already-owned raw LALI and LQBR buffers,
not predecoded mutable dictionaries. It rejects bad extents/header/schema,
reserved words, dirty unused slots, unpublished/invalid ancestors, wrong
foreign BIRTH bindings and duplicate BIRTH associations. Partial valid chains
remain incomplete historical observations, never proof of complete coverage.

The combined decoder preserves all previous row/window/operation/request-age
evidence and refusals. A SOURCE-to-BIRTH link survives without a later
renderer. Renderer/row joining uses only the actual validated LQBR ID and the
existing explicit renderer/root/lineage IDs. A different BIRTH with identical
native fields cannot attach itself to an earlier renderer. Independent LPDI
CALL_INTENT records remain unjoined. All decisions deny; all five existing
authority flags and all lifetime/coherence/currentness proof flags stay false.

## Verification and artifact

All **146 focused checks pass** (28.566 s):27 emitted-core checks,45 strict
standalone decoder checks,23 combined-decoder checks,22 pinned-source contracts,
21 actual native-path integration checks and8 exact-build/tamper checks.
Independent source/ABI/builder and decoder/fixture reviews found no remaining
actionable issue. Review found and fixed a core/decoder extent asymmetry before
this run: both capture and ancestor validation now reject overflowing frames/
records, while an extent ending exactly at2^32 remains valid. Regression cases
execute both former counterexamples and accepted top-u32 boundaries.

The instruction fixture executes the actual GENERAL call, native constructors,
20/36-byte segmented append/index/remove, action worker/fanout, explorer,
paint producer/getter/consumer, redraw wrapper and previous BIRTH/transport
observers. The full owned snapshot passes the combined decoder and associates
SOURCE1 -> actual BIRTH1 -> renderer2 -> lineage1 -> producer4/row-event1.
All earlier renderer/row structures and the existing known-boundary refusal
remain unchanged. Distinct identical notifications retain distinct source IDs
through both FIFO head-address reuse and full-width native relocation.

Tests also cover unknown producer/caller/zero-ID refusal, missing registry or
callback, explorer returning without paint, one selected-tail read under lock,
post-unlock tail mutation without restamping, native engine/metadata mutation
with diagnostic fault but continued native BIRTH, actual action-list growth
allocation failure with original unlock/wake, and copy-allocation failure that
observes BIRTH without claiming successful enqueue. Full/fault/eight-failed-SC
diagnostics do not suppress native work. Hook GPR/HI/LO/SP, original native
RAs/delays, BIRTH prologue and the old BIRTH-return carrier are checked.

Registry/name resolution, scheduling, mutex services, allocation predicates
and some existing renderer geometry/resource/SQL/row jobs remain explicit
fixture substitutions. The worker runs one bounded native drain and its actual
exit epilogue, not an operating-system scheduler. These checks do not prove
whole-player concurrency, hardware cache behavior, post-unlock native lifetime
or successful UI scrolling. Manually duplicated BIRTH-link calls or corrupted
reserved headers are rejected by host decoding; the emitted core does not
pretend to make arbitrary private-memory corruption a valid history.

Full repository regression: **1,850 tests pass, no skips** (297.274 s), including
all146 new checks. All219 Python scripts compile; tracked and new text files
pass whitespace checks. No previous assertion, refusal, legacy launcher or
test timer was weakened or changed.

Saved ignored local artifact:
`artifacts/hiby_player_1.4_sortfix_fullnav_wake_action_link_stage_v1_20261023.bin`,
7,176,916 bytes, SHA-256
`d4306357ec6b70153b15e98202dad1a7ad0615d02ea6bd9e0d53857844ab37a8`.
It is exactly and deterministically verified against the pinned7,133,528-byte
reference `02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87`.
There are42 hook pairs and310 changed normalized-original bytes, only in
declared hook/stride/ELF spans. Original native calls/delays/return PCs and
capacity requests remain intact. Shared verification retains every old native
continuation, external-call and indirect-dispatch restriction.

Default LALI adds98,320 private BSS bytes. The complete stage has1,163,424
private bytes atBD4000, LALI atCD8090 and33,492 separate RX bytes atD00000;
there is no RWX segment. The new wrapper/core/validator frames total at most
464 bytes (D0+B0+50); at BIRTH the inheritedA0 observer frame brings this
to624 bytes below its native frame. Native/renderer/exception frames are
additional; this is not a whole-player stack/lifetime budget.

The saved LPDI predecessor is exactly reverified with unchanged SHA-256
`a9a6f02fd48a3b57e27e3bb19c9e8c2b8329b6602cc12988091dfbb98c2abe2c`;
the saved renderer predecessor is exactly reverified with unchanged SHA-256
`f42fac46890dc2eadbeba88f90ce5b82857d3045752b974b15d04bef263d2244`.
Previous builders/default images remain unchanged. No installer, launcher or
runtime export policy is introduced here. No device/network action, commit or
push occurred; the changes and new ignored artifact remain local.

## Remaining prerequisites

This closes the observed GENERAL notification-to-paint invocation-ID gap for
the audited route. It does not connect every Next/autoplay branch or establish
coherent playback/row publication. Complete invalidation/cancellation coverage,
native retained ownership and an admitted UI transaction are still required
before enabling automatic folder-follow or scrolling. No deployment or
physical-test instruction is introduced by this stage.

The following [paint-payload and removal audit](folderfollow-reveal-paint-payload-boundary.md)
executes the remaining post-BIRTH four-word copy and a known purge outside
the paint mutex protocol. It separates stable bytes, exact selected-entry
removal and object lifetime without changing this diagnostic image or format.
