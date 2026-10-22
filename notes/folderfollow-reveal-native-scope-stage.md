# Known in-flight native scope exclusion

Offline diagnostic stage, 2026-10-21. No player access, installation, launch,
signal, rearm or reboot. Autoscroll remains disabled; hardware is **UNTESTED**.
This does not stop a stale stock callback or make native objects safe to retain.

## Scope of the change

The original renderer-entry frontier detects intervening known beginnings, but
an earlier writer can still be running when that entry receives a new ticket.
This stage adds exact entry/normal-return bindings for reset `491240` and
reconcile `4919E0`. The [source audit](folderfollow-reveal-native-scope-boundary.md)
pins the reference hash, all three ordinary epilogues, direct inbound targets,
native carrier and ABI premises. Other routines/aliases and abnormal exits are
not covered by these two scopes.

The renderer's apparent request is a newly allocated cache-canvas descriptor,
not an immutable UI request. Stamping that descriptor cannot establish freshness
of its outer cause. This stage addresses known overlap only, not that separate
request/playback provenance gap.

## Private guard, not a native lock

`reveal_native_scope_mips.py` emits leaf `begin`, `end` and terminal `invalidate`
helpers. They read/write only permanent private BSS; raw native argument/frame
values are copied as scalars, never followed. No native calls, runtime allocation,
export or I/O are added. SP/RA, O32 saved/reserved registers and HI/LO survive.
The wrappers additionally preserve every native volatile register and actual v0.

The 16-byte header contains one packed word plus three reserved zero words:

- Bits 0..15: issued, non-reused ticket count, bounded by capacity (default 1024,
  maximum 65535).
- Bits 16..30: active count, at most 32767.
- High bit: invalid; `FFFFFFFF` is a permanent fault overriding every slot.

One successful bounded LL/SC increments issued and active together **before**
any slot publication or remaining stock effects. A paused, unpublished entry
therefore cannot disappear from the active guard. Eight failed attempts,
exhaustion, invalid bindings/state or duplicate close permanently fault it.
There is no reset, recovery, ready state or ticket reuse.

Each 32-byte slot has these u32 fields:

| Offset | Field |
| --- | --- |
| 0 | `LSCP` magic, published last |
| 4 | Kind: reset 1 / reconcile 2 |
| 8 | Own ticket, one-based slot number |
| 12 | Exact native frame scalar |
| 16, 20 | Raw entry arguments 0 / 1 |
| 24 | OPEN 1 / CLOSING 2 / CLOSED 3 |
| 28 | Actual native result |

Identity is immutable after publication; status/result are one-shot closure
fields, so this table is **not** an append-only event log. End validates exact
ticket/kind/frame, atomically claims OPEN→CLOSING, stores actual result and
CLOSED, then decrements only the packed active count. The claim prevents two
ends releasing the same invocation twice. A missing end remains active; a wrong
end faults. Return is not a successful SQL operation, destruction or settlement.
The runtime helper validates packed state and used identity/status fields; the
offline decoder additionally checks reserved words and every unused tail.

## Native integration and admission order

`build_reveal_native_scope_stage.py` composes the previous lineage, row,
revision, operation and original-entry stages with the new optional exclusion.
Defaults of all previous builders remain byte-identical.

1. Reset/reconcile entry replays the native prologue first, saves its own frame,
   begins a private scope, writes its actual returned ticket to native `SP+14`,
   then bumps the existing revision once and resumes at original entry+8.
2. Renderer entry bumps its own revision as before. If the packed scope state
   has an active/high-bit state, its original-entry carrier becomes zero and
   remains unadmitted after that scope closes. The root is never re-stamped.
3. Row capture retains all provenance/frontier/revision gates. Active scopes
   before allocation suppress additional row payload reads; fault states fault
   the journal. Activity detected after allocation or before magic publication
   faults permanently rather than leaving a healthy allocator with a gap.
4. Each normal native return preserves actual v0 and restored RA. It bumps the
   revision **before** releasing the active scope, closes the exact invocation,
   restores registers and pops the native frame exactly once.

The native callbacks/append/SQL reset still run once even if diagnostic capture
is skipped or faults. These checks are not a lifetime lease: a new writer can
start between a check and a native read. A later check can reject publication,
not undo an earlier read or an existing stock mutation.

Three additional source hook pairs are the reset return `4913F0` and reconcile
returns `491D08` / `491E68`. The two entry hooks replace, rather than chain,
their prior wrappers. Total: 26 source hook pairs; old unused private entry
wrappers and their audited tails remain in the emitted image. Original fill /
postfill JALRs, return PCs, native saves and job/list strides remain unchanged.

## Offline decoding and limitations

The `lineage-rows-native-scope-v1` snapshot appends the scope guard to the exact
previous frontier layout. At default capacity the extra private BSS is 32784
bytes. Format/capacities are explicit out-of-band arguments, not a self-identifying
native header; equal-size capacity repartitions of empty tails need not be
distinguishable. A raw snapshot does not prove its own coherent acquisition.

`decode_reveal_native_scope_stage.py` strictly decodes both sections. Unpublished
entries, CLOSING, any open scope or count disagreement are non-quiet. CLOSED
before decrement is a conservative incomplete snapshot, not success. Fault,
malformed identities, reserved words and nonzero unused tails are refused.

Annotation only narrows existing operation completeness/window `complete` and
preserves earlier refusals and historical row observations. Quiet means no open
**observed** scope in these copied bytes. It never repairs a rejected frontier
or yields current contents, retained owner, coherent capture or UI permission.

Still required before an actual reveal transaction: fresh UI/playback request
identity, complete native writer/lifetime coverage, retained owner, final host
row publication/coherent handoff, and safe UI-context setter/invalidation.
Normal postfill/bind revocation remains enabled.

## Verification

Source contracts, MIPS instruction tests, strict decoder tests and composed
entry/exit/capture tests cover ticket uniqueness, overlapping/out-of-order
completion, unpublished entries, duplicate/foreign ends, permanent faults,
bounded retries, ABI, exact source pairs, ordinary and partial-publication races,
native callback continuity, deterministic image footprint and prior hashes.
Instruction interleavings are bounded harness evidence, not target CPU/cache,
scheduler, indirect control-flow or native lifetime certification.

Saved and deterministically verified ignored local intermediate:
`artifacts/hiby_player_1.4_sortfix_fullnav_wake_native_scope_stage_v1_20261021.bin`,
7,156,404 bytes, SHA-256
`404827620fc6addba436c1911eb89b72b633562d84331de9e0097ede9469b0d5`.
Private BSS is 770128 bytes starting at `BD4000`; the scope table starts at
`C88040` and occupies 32784 bytes. Separate RX code starts at `CA0000`, 12980
bytes. Exact original-image changes: 193 bytes, confined to declared hooks,
strides and ELF layout fields. No RWX segment or additional external native
call is introduced; all native external call/return anchors remain pinned.

All 90 new checks pass. The first unrestricted full run completed 1122 tests
with one failure in the unchanged launcher fixture
`test_normal_exit_preserves_fd_and_status_no_delayed_signal`. Its mocked
watchdog sleeps only 25 ms; the failure observed an unexpected mocked signal
during nominal exit. A separate rerun of all 24 launcher tests passed (16.574 s).
Neither that launcher nor its tests were changed to hide the failure. No
fixture signal/reboot function in these tests addresses a real device.

A second unrestricted full run, without parallel focused tests, passed all
**1122 tests, no skips** (168.446 s). All 158 Python scripts compile, and
tracked/new text files pass whitespace checks. The first restricted attempt
was not a valid regression result because legacy temporary-file fixtures
received Windows permission errors; tests were rerun with local temp access,
not weakened or skipped. Changes remain local and uncommitted.

The subsequent [request-origin audit](folderfollow-reveal-request-engine-boundary.md)
provides an executable counterexample for the expressly remaining freshness
gap: old queued paint geometry can survive the executed native reset, then
receive fresh renderer/producer tickets after the known scope closes. Two
different queue-birth histories produce identical diagnostic capture bytes in
the bounded fixture. This is not a failure of the stage's negative overlap
claim, and no existing rejection is relaxed or UI authority granted.
