# Field-correlated retirement observations, not live object identity

2026-10-28. This separate local branch observes the four known controller-ring
retirement frontiers and correlates their node/engine fields with directly
observed births. It follows the [independent birth history](folderfollow-reveal-registry-birth.md)
without changing that format or its default composition. It does not install
firmware hooks, provide a live-object query, retain allocations or authorize
cleanup. No player operation or firmware image is produced.

## Exact observed events and conservative terminal state

The new all-register/HI/LO-preserving callbacks are
`observe_birth(U,owned32_event)` and `observe_retirement(U,owned32_event)`.
Both receive the actual controller, pinned R, current selected node, engine
scalar, native frame SP, native caller, source site and actual acquisition
status zero. Genuine fresh raw-zero ownership of a retained initialized
ordinary R remains a caller premise, not authenticated by a schema or tag.
The core never dereferences these historical pointer-looking fields.

Birth occurs after native438A58's final coherent link store, before old
receipt/binding/owner quota checks. It appends a new token, never adopting a
latest historical row by address. Retirement requires one outstanding row
with matching node/engine fields; a missing row, mismatched engine or collision
permanently faults the history rather than guessing/reviving an old record.
An earlier terminal row at the same address does not become outstanding again.

This is **field correlation**, not an authenticated incarnation match.
State1 means `NO_RETIREMENT_OBSERVED`, not LIVE. State2 means
`RETIREMENT_SELECTED`, not DEAD or successful deletion. The outer shutdown
paths can select retirement and then call an opaque callback which leaves the
node linked. Repeated selection may conservatively fault; neither a fault nor
a refusal vetoes the original native operation or makes its continuation safe.

The initially zero table has a16-byte count/fault/reserved/reserved header and
64-byte records:

| Offset | Meaning |
| --- | --- |
| 00,04 | `BRLC` magic and nonreused token, row index plus one |
| 08,0C | Pinned controller and registry mutex |
| 10,14 | Observed node and engine scalar fields |
| 18,1C,20,24 | Birth frame, caller, site438A5C, raw acquisition zero |
| 28 | State1 no retirement observed, or2 retirement selected |
| 2C,30,34 | Retirement site, frame and caller |
| 38,3C | Zero reserved words |

Both callbacks validate the entire occupied prefix, uniqueness of outstanding
node fields and every unused tail word before a successful change. State1
requires all retirement words zero; state2 requires a known retirement site.
Partial retirement-body writes with state1 therefore permanently fault on the
next admitted operation, rather than becoming an automatic retry. The bounded
uniqueness scan is quadratic; no runtime latency/scheduling guarantee is made.

Birth writes its body/state, then synchronized magic and count. Retirement
writes site/frame/caller, then synchronized state2 last. No row/token is reset
or recycled. Capacity is a strict integer1..1024, default16. Full birth storage
faults permanently; a full healthy table can still mark an existing retirement.
There is no positive return record, token export, query or change to GCAP32,
CINT48, RIAU64 or deferred queue records.

## Four frontiers under an actual checked native R scope

The separate passive bridges preserve displaced instructions, every GPR and
HI/LO, native raw-service arguments and native return PCs. They only observe:

| Native route | Observation site | What still follows |
| --- | --- | --- |
| Name-selected4395A0 delete |439618, before first link store | Native unlink, name/paint/engine cleanup and node free |
|43CB20 registry loop |43CBB0, before first link store | Each selected node's unlink/free; later controller cleanup is outside the bounded fixture |
| Outer shutdown A |4E3F18, before its unlock call | Unlock, opaque callback or unlocked unlink4E3F48/free |
| Outer shutdown B |51A3B8, before its unlock call | Unlock, opaque callback or unlocked unlink51A3E8/free |

The outer observations intentionally occur before release, not at the later
unlocked first stores. Empty sentinel branches skip their retirement callbacks.
This avoids treating an earlier acquisition receipt as current ownership after
unlock, but it cannot establish that the eventual callback/deletion completed.

Each native scope uses only previously unused non-home locals10/14 for a fresh
ARMED/ENTERED/CAPTURED tag and exact raw status. The actual callback selection,
pinned raw A0 and saved callback/native return chain are classified before
status masking. A nonzero/missing/wrong witness produces no lifecycle access,
even though unchanged native code may still unlink/free. The43CB20 witness
survives all node iterations under the same acquisition and is cleared before
the real release. Other frontiers consume their per-scope witness once.

The two global raw-acquire hooks dispatch the four retirement scopes, otherwise
restore all registers and tail-chain the preceding receipt bridges exactly once.
They do not duplicate raw calls or forced-zero native return effects. All
eleven retirement redirects, existing receipt redirects and three checked
registration-release redirects must be coherent. The composer exports the
complete16-pair `coherent_hooks` map; partial activation is not fail-closed.
These are local instruction-fetch overrides, not an installation procedure.

Known fixed/native/generated RX, input, current-node28 and native/save-frame
arithmetic exclusions precede observer loads. The raw N=W+40 chain explicitly
rejects unsigned wrap before following native locals. As in prior callbacks,
initial architectural-save stores occur before validation: independent retained,
writable and nonaliasing save frames remain a prerequisite. Guards establish
neither mapping, native retention, unknown heap/stack aliases nor authenticity.

## Remaining counterexample and integration gates

The executable fixture demonstrates an important limit. A failed native raw
acquisition can delete A without a safely writable retirement observation.
Another failed acquisition can publish B with A's node/engine field values
without a birth observation. The fixture reuses the28-byte node; engine graph
cleanup stays opaque, not a proved engine free/reallocation. A later raw-zero
retirement then correlates B's fields
with A's still-outstanding historical record. The header can remain healthy.
This is deliberately recorded as a counterexample, never as a recovered
incarnation certificate. Covering the four encoded frontiers does not repair
those missing events or establish a continuous allocation lease.

All other native escaped aliases, computed writers/callbacks, sentinel
reinitialization, complete resource/engine graph lifetime, safe caller
continuation and synchronous whole-instance error isolation remain independent
gates. A future usable birth-token transport must originate at the exact owned
birth event, not a latest-by-address table lookup. No LIVE query, native unlink
entry, cleanup retry, guessed unlock or free authority is supplied here.

## Composition and local verification

`reveal_registry_lifecycle_stage.assemble` takes the seven preceding canonical
receipt/binding/owner/U/R/P/code arguments plus `lifecycle_address`. Its separate
registration-capture branch does not replace constructor/retained/cleanup-intent
or read-only-identity branches. Exact full RX is resolved in two passes for the
capture, lifecycle core and retirement bridges; additional fixed state is
excluded by their outer guards. Other inherited internal-entry/native allocation
and transitive-stack premises are not universally extended.

Actual native registration and name-selected unlink execute in the fixture.
Separate native registry-teardown and outer-loop sections execute with explicit
entry/stop boundaries; this does not run their entire shutdown object graphs.
Raw pthread, allocation/free, strcmp, log, paint/engine destructor and callback
imports are bounded substitutes. Controlled28-byte node reuse checks terminal
old/new token separation after an observed unlink; it does not prove the engine
graph was destroyed. Source contracts, ABI/bounds checks and the deliberately
unresolved counterexample are recorded in [status](status.md) after serial
verification. Active scrolling remains disabled; hardware is UNTESTED.

A later opt-in [owned birth-token capture](folderfollow-reveal-birth-capture.md)
adds a private post-commit callback and separate BCAP48 output. It carries this
actual birth's token, not a latest matching row. The preceding default BRLC64
composition and all its limitations remain unchanged; it is not a LIVE query
or proof that retirement/deletion completed.
