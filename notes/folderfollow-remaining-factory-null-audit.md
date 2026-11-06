# Remaining dialog factories: NULL-refusal audit

Offline source audit, 2026-11-05, after published `aa91550` and the local
[secondary admission gate](folderfollow-reveal-secondary-factory-admission-gate.md).
The three factories below remain unguarded. Returning NULL from a new admission
gate is not safe for every known caller of `47D180` or `47D960`; concrete native
continuations dereference that result. No such dereference was found for
`47DCE0`, but its computed callback routes still prevent a universal claim.

## Scope and inventory

The pinned input is `artifacts/import-20261001/hiby_player_02fd.bin`,
7,133,528 bytes, SHA-256
`02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87`.
Every encoded direct J/JAL to these three addresses in its executable ranges
is listed. An encoded census is not proof that all listed instructions execute,
or that computed calls, imports and foreign callers have been enumerated.

| Factory | Encoded callers | NULL dereference | Result discarded | Result propagated | NULL handled locally | Unresolved locally |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `47D180` | 51 | 18 | 10 | 23 | 0 | 0 |
| `47D960` | 157 | 2 | 95 | 27 | 5 | 28 |
| `47DCE0` | 21 | 0 | 17 | 4 | 0 | 0 |
| Total | 229 | 20 | 122 | 54 | 5 | 28 |

Each classification describes the documented native continuation, with its
stated conditions. A NULL dereference is a conditional source consequence of
refusing the factory, not a crash observed on the player. Discarded means the
returned value becomes dead before use; it does not prove that suppressing the
factory's other effects is operationally safe. Propagated leaves the upper
return/field/global consumer open. NULL handled locally (`null_guarded`) means
an existing native branch handles the empty result on the checked continuation;
it is distinct from a value discarded without use. Unresolved retains a concrete
external-body or computed-target obligation; absence of an immediate V0 use is
not treated as proof. No classification establishes whole-factory refusal safety.

Machine-readable instruction evidence and per-caller conditions are in:

- [47D180 manifest](folderfollow-factory-d180-null-audit.json).
- [47D960 manifest](folderfollow-factory-d960-null-audit.json).
- [47DCE0 manifest](folderfollow-factory-dce0-null-audit.json).

## Confirmed refusal hazards

For `47D180`, 18 call sites have a documented unchecked NULL access. Examples:

- `45336C` leads to `453384` storing through H+50 in the configurator call's
  delay slot, before the configurator can reject NULL.
- `4A4F1C` leads to an unchecked H+5C store at `4A4F2C`.
- `4AF958`, `4AFC74` and `4CF1F4` lead to H+58 reads before a later context check.
- `5270A0` saves H across an independent allocation. The H+58 store at
  `5270B8` is in the allocation check's branch delay slot, so allocation failure
  does not protect the NULL H.

Six other `47D180` hazard paths require a successful subsequent allocation:
`4CFF38`, `4D1ADC`, `4D2B44`, `4D3724`, `509A2C` and `515218`.
Their conditions remain explicit in the manifest.

For `47D960`, calls at `5091A8` and `50BAB4` save H, then allocate an independent
payload. On allocation success, `5091E0` or `50BAD8` writes that payload through
H+58 without a factory NULL check. On allocation failure the write is skipped;
testing only that failure route would conceal the hazard.

## Extended return-value review

Twelve initially opaque `47D960` continuations were followed one callee or branch
further, with a separate source review:

- Eight discard the result. `451EB0` reaches `4476C0`'s immediate V0 overwrite;
  `453E80` and `453F38` either overwrite V0 at `453EB0` or take a non-NULL free
  path that overwrites it at `466A90`; `478728`, `49D468`, `49D4E4` and `49D54C`
  reach `466F84`'s fresh stack-derived V0; `4A1470` reaches `47438C`'s fresh load.
- Four propagate it on a documented condition. For `435168` and `4351DC`, an
  old context field S0+58 equal to zero selects the actual `466A80` free(NULL)
  leaf. That leaf preserves V0, and the caller returns it at `43518C`.
  For `4AEB74` and `4AEBD4`, the same old-field condition skips free and preserves
  V0 through the return at `4AEB18`. This old context is not the returned H.

The next pass follows all 37 initially remaining `47D960` records as detailed
below. There are now 28 with concrete unresolved indirect frontiers.
Ordinary caller-saved ABI rules alone do not prove that a callee overwrites V0.
The 23 `47D180` and 27 `47D960` propagated records still require their downstream
consumers to be checked before a broader refusal policy can be justified.

## Follow-up of the 37 remaining continuations

Four more discard the result before use. `4937A8`, `4937E8` and `493868` reach
`48F800` with old S0 as A0. A NULL old context returns -1 in the JR delay at
`48F874`; a zero old +1988 field returns 0 at `48F864`; a nonzero field reaches
the real free header load at `466A90`, overwriting V0 before imported free.
The old context/allocation must remain valid independently of the factory H.
`49E794` reaches `49CFA0` and `490B40`; that native leaf overwrites V0 at
`490B4C` for a non-NULL old A0 or in the JR delay at `490B64` for NULL old A0.

Five have an existing local NULL continuation, now separately classified
`null_guarded` rather than discarded:

- `453A0C` branches on NULL to the pure return-0 suffix at `453AD4`.
- `50049C` branches to `500534` and returns 1. Its delay copies NULL to S3,
  but the epilogue restores S3 before further use and skips the H+5C store.
  The remaining clear targets old global `B8BB2C`; earlier `500444` sets the
  old S0 global base to `B90000`.
- `52B320` skips its H+5C store on NULL, then passes fresh arguments to the
  native setter `477600`, whose `477608` overwrites V0 before use; it returns 0.
- `4A33D8` enters cleanup at `4A32B0` on NULL. Fresh arguments reach the same
  setter and overwrite, with old S1 supplied independently of H.
- `4A33A8` enters cleanup at `4A3344` on NULL. A nonzero old S2 selects `469240`;
  otherwise `4691E0` runs with old S1. Both reach `466F84`'s fresh stack-derived
  V0 before an incoming-value use. Other cleanup effects and progress are open.

These are existing branches, not new firmware guards. The full admitted
non-NULL body, old-object lifetimes and safety of suppressing factory effects
are outside this local NULL classification.

All 28 unresolved continuations now name an actual indirect instruction and
its delay slot, with the full checked local prefix up to that frontier:

| Frontier | Callers | Missing evidence |
| --- | ---: | --- |
| `A5BC68`, JR T9 through the memset PLT | 8 | Actual linked library body/resolver behavior |
| `A5B968`, JR T9 through the configurator's import | 10 | Actual linked library body/resolver behavior |
| `4E535C`, JALR through old object+2A4 | 6 | Actual callback binding and body |
| `43B150`, JALR through old object+274 | 1 | Actual callback binding and body |
| `4A6E70`, JALR through old list+24 | 2 | Actual method binding and body |
| `4E5590`, JALR through old object+2A4 | 1 | Actual callback binding and body |

The 18 import and 10 computed-callback records do not expose a known incoming
V0 alias before the boundary, but they do not prove the incoming value dead.
The local PLT words do not overwrite it. Later forced native return constants
occur after the external call and cannot establish what happened inside it.

Some records have useful conditional facts without changing classification.
The configurator has a native V0=-1 exit for a NULL old object, but its non-NULL
route reaches the import. For `505674`, a constructor installs method `4E4A60`,
whose `4E4A6C` would overwrite V0; actual target identity/stability at the call
is unproved. A plausible list method has the same binding limitation. The
manifest retains these distinctions rather than assuming a constructor or
symbol name authenticates a runtime target.

## Selected callback assignments and readiness

The [callback-binding manifest](folderfollow-factory-callback-binding-audit.json)
now covers all ten computed consumers at their four local frontiers. It records
four selected direct constant assignments and their conditional behavior:

| Slot | Assignment fragment | Selected target | Behavior with that actual binding |
| --- | --- | --- | --- |
| `+24` | `456CD4..456CDC` | `4557C0` | Replaces V0 in either native return delay; clears a live list's +C field |
| `+274` | `439A64..439A6C` | `437D20` | Reaches `466DA0` and external `A5B960` before replacing incoming V0 |
| `+274` | `45B6B0..45B6CC` | `45B100` | JR-delay `45B104` loads V0 from the old object's +1B0 field |
| `+2A4` | `4E4E34..4E4E3C` | `4E4A60` | `4E4A6C` replaces V0 from the old object's +294 field before any call |

The assignment fragments are actual LUI/ADDIU/SW sequences, including the
transparent intervening stores for `45B6CC`. These selected candidates are
not a closed set of runtime targets. Matching offsets in unrelated structures
do not establish the type or identity of the object passed at these consumers.

The manifest also pins a syntactic inventory of aligned encoded store-word
matches in file-backed PF_X ranges, with PC/word digests:

| Literal slot | SW matches | SW with base other than SP | SB/SH/SWL/SWR matches | Partial matches with base other than SP |
| --- | ---: | ---: | ---: | ---: |
| `+24` | 7,275 | 733 | 300 | 135 |
| `+274` | 57 | 18 | 4 | 4 |
| `+2A4` | 48 | 12 | 4 | 3 |

For the partial column, the encoded immediate must be within `[slot,slot+4)`.
This deliberately simple rule omits earlier-starting overlaps, SC/SWC1,
shifted-base stores, copying/memset, imported writes and runtime reachability.
PF_X includes data and earlier possible code caves; a matching word is not
automatically a reachable instruction. Likewise, a base register other than
SP may still address a stack alias or a different object. Concrete same-offset
partial stores and runtime copies prevent treating a single known constant
assignment as proof that the callback cannot change.

There is a more direct readiness boundary for five consumers that obtain U
from accessor `43D200`. The generic dispatcher copies pending U into active
global `ADF208` at `43D028`, before invoking U+260 at `43D064`. For descriptor
`94B400`, constructor `4E3E40` installs +260=`4E3DE0`, which invokes initializer
+254=`4E4DE0`. The +2A4 assignment at `4E4E3C` occurs only inside that later
initializer, after earlier external work. The accessor simply returns the
active global, without a ready/type check. The lifecycle also calls the +258
destructor, including mutex destruction at `4E3F6C`, before returning to the
generic dispatcher. Publication therefore does not itself certify initialization
completion, an unchanged callback or a retained live object/mutex.

Native fixtures execute the publication prefix and accessor with a supplied
pending object, then select a reentry point before the callback assignment.
They read U while its +2A4 field is still zero and reach the unresolved target.
This disproves an inference from publication alone within that bounded model;
it does not prove that this reentry is reachable on hardware or that a device
race/crash has occurred. Actual execution ordering still needs evidence.

Other fixtures execute all four selected assignment fragments and their native
consumer loads/JALRs. They contrast an actual list clear with a deliberately
changed slot, a field-loading +274 method with the stock +274 import route,
and the bound +2A4 method's first definite V0 replacement at both consumers.
The list slot mutation is a supplied counterexample to constructor-only target
inference, not a claimed native writer. The +2A4 body stops after its first
replacement, and the +274 import route stops at external entry; neither invents
successful completion of the remaining body. One SWC1 stores supplied raw FP0
bits in an assignment fragment, without FP arithmetic/FCSR claims.

The verifier checks source words, literal-store counts/digests, constant
materialization and complete coverage of the ten existing computed consumers.
It rejects promotion of `runtime_binding_proven`, `closed_write_set_proven`,
`universal_refusal_safety_proven` or `classification_promoted`, and does not
promote a source publication ordering into proven scheduling/reentry behavior.
The initial binding audit contributed 320 PC/word records, in addition to the preceding
2,808 factory records. All ten consumers retain their unresolved classification;
the table's totals and guarded factory set are unchanged.

## Own-loop ordering and resource release

For descriptor `94B400`, the known driver `4E3DE0` synchronously calls the
initializer, own-loop adapter and destructor at `4E3DF0`, `4E3DFC` and `4E3E08`.
The driver proceeds after each return and ignores the initializer and loop
results. The initializer has a straight native prefix through the +2A4 store
at `4E4E3C`. Two imported clears, property query 4 and mutex creation precede
that store. Both native initializer return suffixes follow it. The encoded
error branch tests `439A20` for -1. The pinned base initializer forces zero on
its normal return. The own-loop adapter `4E4AC0` enters `43C980` only when its
U+2C window field is nonzero.

The selected own-loop invocation reaches the known input and queued routes
after initializer return. The input route passes through widget+4C and resource
+138/+160. The template slots at `A9A618` and `A9AA30` hold the two list handlers.
Their input dialogs store the getter wrappers in state+10 and invoke them
through `50A13C`. The queued route sends event `112` to `4520C0` through
`4542A0`, with the old U supplied by the loop. This establishes the local
ordering for the demonstrated registrations. Actual resource selection,
callback replacement and entry from outside this invocation remain open.

On the worker-start branch, base initializer `439A20` passes U to `48F360`
after +2A4 assignment and before initializer return. `48F428` stores U in the
worker context at +138. The initial task input is zero on this route and skips
the initial enqueue block. The `pthread_create` call at `466BFC` passes entry
`48EA80` and the worker context. Its checked initial path waits, then uses
queued task slots +2B8/+2C0/+2BC. Connecting those task callbacks to the audited
UI consumers still requires a producer and actual target binding. The known
worker launch occurs after the handler assignment. Earlier external calls and
other entry routes leave pre-assignment reentry unresolved.

At teardown, `4E3F6C` passes U+290 to `466DE0`. That wrapper calls raw mutex
destroy and then calls free for a nonzero pointer regardless of destroy status.
The checked suffix proceeds to base cleanup while the active global `ADF208`
and U+290 still contain their old values. Base cleanup also has computed
callback frontiers. At `43D080`, normal dispatch replaces the active pointer
with pending U or zero. The exit-flag branch at `43D074` bypasses this store
and reaches logger/exit services. In the separate shutdown path, `43D158`
clears the active pointer before the registry loop can reach the generic
object free at `43D4F4`. This ordering concerns the checked release paths.
Other release callers, retained aliases and resource lifetime remain open.

Three bounded tests execute the actual driver and initializer prefix/return,
the window gate and getter at the loop call, the mutex destroy wrapper and
dispatcher return branches, and shutdown with one registry object. The
initializer middle, event loop, destructor entry in the driver test, base
cleanup and imported services use supplied outcomes. The nonzero initializer
status is injected to exercise the driver's ignored result. The allocator
fixture records free arguments and the active pointer at each free boundary.
Actual concurrent reentry and hardware execution remain unverified. The
follow-up adds 365 source-word records to the binding manifest.

## The `47DCE0` frontier

Seventeen immediate continuations discard the result. The other four return it
through wrappers containing calls at `49A6D8`, `4A7080`, `4A8278` and `5188CC`.

The `49A2E0` wrapper has ten encoded direct upper callers; all ten discard the
result. In particular, `4B231C` and `5308C4` ultimately reach explicit V0=1
instructions at `4B234C` and `5308F4`.

Wrappers `4A6F60` and `4A80E0` are passed to `509F20`, stored at object+10 by
`50A018`, and called through `50A13C`. That known dispatcher overwrites the
callback result with V0=1 at `50A148`. Wrapper `518780` is published at slot+284
by `518378`; identified widget dispatches at `45C238`, `45C514`, `45C850` and
`45CD8C` ignore the result.

These known chains expose no NULL dereference. Complete callback target
binding, aliases, imports and other computed callers remain unproved; the
four records stay propagated at the direct-call frontier. The manifest keeps
both the checked upper chains and those explicit limits.

## Validation and limits

`scripts/factory_null_audit.py` checks the source size/hash, exact 229-site
census, unique caller records, known classes, nonempty textual notes and distinct
instruction evidence including each call and its delay slot. `null_guarded`
also requires explicit local closure, an actual V0/zero BEQ or BNE, and its
correct NULL continuation with delay evidence. An unresolved record requires
its concrete JR/JALR T9 frontier and delay. Every recorded PC/word pair,
including nested upper-chain and callee evidence, must match the source.
Classifications are manual analysis;
the verifier does not establish whole-program dataflow or semantic safety.

`scripts/test_factory_null_audit.py` supplies source-evidence mutation checks
and bounded native execution. Actual caller JALs, delay slots, conditional
branches and return suffixes execute. Factory, allocator, copy, configurator
and callback outcomes are explicit bounded substitutes. In the new local-NULL
cases the short native `477600` setter also executes; other UI/query/copy
services are bounded. Caller frames and live
old-context memory are supplied. The actual free(NULL) leaf executes without
substituting an invented return value. Non-NULL free and allocation internals,
earlier function bodies, hardware scheduling and object lifetimes are outside
this fixture. One wrapper's LDC1 restore is modeled as a load, without floating
point arithmetic, FCSR or hardware pipeline claims.

The execution cases include NULL faults with non-NULL controls, allocation
success/failure distinctions, the unconditional branch-delay fault, four DCE0
return suffixes and the known controller's result overwrite. New cases cover
all five local NULL guards, non-NULL controls, both old-S2 cleanup branches,
the actual global clear and native setter table writes. Execution state
and service outcomes are not cached; no assembler is invoked by this audit.
Exact final test results and local preflight are recorded in
[project status](status.md).

This audit adds evidence and tests, with no new admission guard, firmware image,
installer or device operation. The local guarded set remains `(47D720,47D4A0)`.
All-dialog protection, universal refusal safety, native lifetime/free authority
and progress remain unproved. Active scrolling stays disabled and hardware
remains UNTESTED. The next work is to close the unresolved continuations and
downstream consumers, then design refusal handling where required before
extending the guarded set.
