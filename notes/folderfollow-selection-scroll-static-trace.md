# Selection versus scrolling: initial static trace

Date: 2026-09-29. This is static research following the successful partial
`6e872416...` hardware run. No new binary was built or installed, and no device
state was changed during this investigation.

## Observation and corrected field interpretation

Within Slayer, playback changes move the visible highlight until it leaves the
screen, but the list does not follow it. Whether stock/golden behaves the same
way remains untested; this is not yet a proven regression of folder follow.

The earlier description of internal-list `+0x5A0` as a current row/index was too
easy to interpret as the selected playback row. It is demonstrably also a
working enumeration index:

- `0x4BF1EC-0x4BF23C` enumerates entries via list method `+0x2C`; at
  `0x4BF228` it stores the loop counter into `internal+0x5A0` before processing
  the entry. The loop continues to subsequent entries.
- `0x4C04C8` initializes it to zero; `0x4C0554` writes the next loop index,
  before another entry lookup at `0x4C056C` and callback at `0x4C052C`.
- `0x490260` consumes that index to update row data. Its row-slot arithmetic
  at `0x490404-0x490420` uses stride 788 bytes and pointer field `view+0xE8`.

Consequently, the earlier sampled value 3 is not proof of a selected track at
index 3. Do not use a timer snapshot of this field as a scroll target.

## Event dispatch is not a scroll command

The table at `0x9489A4` maps events of `0x4C0620` as follows:

| Event | Target | Effect relevant here |
| --- | --- | --- |
| 1 | `0x4C070C` | Store argument at internal `+0x5A8` |
| 2 | `0x4C06FC` | Store argument at internal `+0x5AC` |
| 3 | `0x4C06EC` | Store argument at internal `+0x5B0` |
| 4 | `0x4C0664` | Unlock/return |
| 5 | `0x4C06DC` | Store argument at internal `+0x5A4` |
| 6 | `0x4C06CC` | Store argument at internal `+0xF14` |

Event 0 populates a list and saves the supplied count at `+0xF08`; event 7
copies a string. These stores are under the internal object's lock. The table
does not expose a direct ensure-visible operation.

The local straight-line argument scan found event-3/value-1 calls at
`0x499F9C` and `0x49A110`, both inside `0x499C20`, after event 5/value 1.
This is a limited direct-call scan, not proof that all possible indirect or
dynamically supplied event calls have been identified. `+0x5B0` affects several
processing branches; setting it globally is not justified as a scroll fix.

## Redraw rectangle versus content offset

In `0x490260`, let `V` be the resolved explorer view and `C = *(V+0xCC)`.
The paths around `0x490308` and `0x4905B4` read:

- `C+0x18`, an offset used in the vertical coordinate calculation;
- `V+0x4C`, the divisor/multiplier used as row pitch;
- `internal+0x5A0`, the current processing index;
- `internal+0x5B0`, choosing a per-row versus broader update rectangle.

The common calculation rounds the offset down to a pitch boundary and clamps
negative results to zero. With `+0x5B0 == 1`, `0x4905F4-0x490624` adds
`index * pitch` and uses one pitch as the rectangle height. It writes the
rectangle at `V+0x2A0C..+0x2A18` and corresponding render-object fields
`+0xD4..+0xE0`. This is not a write to `C+0x18`.

At `0x49062C-0x490638`, `0x43C860` receives the rectangle. That helper copies
four words into a message and calls `0x439900`. Separately, `0x452DC0` copies
the saved rectangle to the render object and invokes `0x459840`, which reaches
`0x8B4280` when rendering is available.

`0x8B4280` copies the supplied rectangle, transforms its coordinates using
the object's `+0x14/+0x18` offsets and `+0x4/+0x8` position, then propagates an
update to the parent. The inspected path reads these offsets; it does not
change them to reveal a selected row. This supports interpreting the rectangle
as redraw/invalidation state, not an automatic-scroll request.

The viewport-refresh routine `0x499C20` also divides the supplied object's
`+0x10` and `+0x18` by `V+0x4C` at `0x499CB4-0x499CE8`, then fills row slots
(with an eight-slot bound). These are useful leads for a later viewport trace,
not a complete proof of every field's UI semantics.

## Follow-up: stock offset setter and playback-location path

Further static tracing on 2026-09-29 found a concrete stock alternative to
writing an offset or using the transient `+0x5A0` index.

### Generic content-offset setter: `0x8B43C0`

The entry requires a non-null parent at `object+0x40`. Flag `a3 & 0x20000`
selects content-offset handling rather than object-position/size handling.
Within that mode, bit 1 selects the vertical component from `*(a1+4)`, bit 0
selects horizontal, and `0x10000` makes the supplied values relative.
Thus the stock calls with `a3=0x20002` request absolute vertical offset only;
`a2=0` is used by the browser callers inspected here.

The path reads existing offsets `+0x14/+0x18`, applies object flags at `+0x3C`,
and writes the new offsets at `0x8B45AC/0x8B45B0` (or conditional single-axis
stores at `0x8B462C/0x8B4640`). With object flag bits `0x4` and `0x8` set,
it applies a lower bound of zero and then an upper bound computed as content
extent `+0x1C/+0x20` minus viewport extent `+0x0C/+0x10`. Do not simplify this
to an unconditional safe clamp: behavior depends on flags, and a negative
extent difference can still produce a negative upper-bound result.
Changed offsets trigger `0x8B06E0` on the parent. No lock acquisition was
identified in this setter; its existence is not permission to call it from
the playback worker or an arbitrary callback.

### Higher-level playback-location helper: `0x490E20`

This routine accepts the controller and an exact view-type name. A pointer to
the view is usable as that second argument only because its name is inline;
stock itself uses this convention after `0x4E5680` at `0x4BD514-0x4BD528`.
`0x4E5320` resolves the exact name using `strcmp` under controller list locking.
That lock is released before the subsequent lookup and scrolling work.

Observed flow:

1. Require a nonzero `0x42C060` result and a nonzero `0x8B1F60(controller+0x28)`
   result. Their full state semantics remain to be established.
2. Resolve the named view. The matching-name branch normally reads property
   24 into a media descriptor (not merely a path string); type 9 uses property
   21 instead. It requires a nonempty UTF-16 path at descriptor `+4`.
3. For the normal branch, call `0x6EFAA0(view+0x3824, descriptor)` to obtain a
   position. Type 19 uses another property-based branch; type 8 reverses the
   index using the list count. These special cases must not be generalized to
   the explorer without checking its actual type.
4. Multiply the position by `view+0x4C` (row pitch). Adjust near the end using
   `(view+0x3B68)->+0x1B8->+0x9C` and viewport height `(view+0xCC)->+0x10`.
5. At `0x490F48`, call `0x8B43C0(view+0xCC, coordinate_pair, 0, 0x20002)`.
6. At `0x490F54`, call `0x490D00(controller, exact_name)` to request redraw
   and, when view flag `+0x70 & 1` is set, invoke `0x499C20` to refill rows.

This is a playback-location/reposition path, not yet a proven minimal
ensure-visible operation: it computes a playback-based offset even if the row
is already visible. Calling it repeatedly could fight manual scrolling.

The position helper performs database work. One SQL format at `0x99CB28` is:

```sql
SELECT count(id) FROM %s WHERE rowid < (SELECT rowid FROM %s WHERE path like ? and cue_id = %d)
```

Another branch at `0x99CAD4` locates by `media_id`. The inspected helper uses
descriptor `+0x424` in the path/cue query and returns a scalar result; failure
paths can return zero as well. Consequently zero alone does not prove a match
at the first row. The presence of a cue-aware branch is promising for Sleep,
but the branch selected by the actual explorer/table still needs validation.

Direct callers of `0x490E20` found in the executable are `0x4BD528`,
`0x4ED404`, and `0x4F05F4`. The latter two use either a current-view name or
`vg_listview_cur_songlist`. Their enclosing UI event contracts have not yet
been completely identified. This does not prove that manual dragging invokes
the playback-location helper.

### Row refill callback registration

`0x4928C0` registers `0x4908A0` through `0x459520`, which stores it in a UI
object's `+0x154` slot. The callback resolves its owner through `0x459340`,
checks view flag `+0x70 & 1`, internal-list existence, and `view+0x8C`, then
conditionally calls `0x499C20` and clears `+0x8C`. The generic dispatcher reads
the `+0x154` callback at `0x4382F4`. This identifies another gated row-refill
path, not a guarantee that a raw offset write would refill the list.

No candidate has been built from these findings. A safe next diagnostic should
first observe the selected view/table, descriptor identity, location-helper
entry/exit, and offsets during a stock action. Do not add a database query to
every 100 ms timer tick. A future change-triggered call must also respect
manual scrolling and confirm that the current folder matches playback.

Additional reproduction ranges:

```text
dump 0x8B43C0 0x8B4654
dump 0x490D00 0x49106C
jal-xrefs 0x490E20 --context 7
dump 0x4E5320 0x4E53D8
dump 0x6EFAA0 0x6EFDD0
cstr 0x99CB28
cstr 0x99CAD4
dump 0x4908A0 0x490930
dump 0x459520 0x45953C
address-xrefs 0x4908A0 --context 8
```

## Explorer-specific checks: applicability is not established

The next static/read-only pass found a reason **not** to install a direct
`0x490E20` timer call yet.

The constructor copies configuration records from `0x942410`, stride `0x34`.
The explorer name field at `0x942674` points to `vg_listview_explorer`; its
following type value is 2 and its lookup-key string is empty. At
`0x49218C-0x4921A4`, these values initialize `view+0x40` and `view+0x3824`.
The explorer-specific branch at `0x492C2C` returns to the same initialization.
The constructor's prefix comparison accepts suffixed explorer names too.

`0x6EFAA0` recognizes the keys `all`, `collect`, `history`, `artist`, `album`,
`album_artist`, `genre`, and `playlist`. An empty key matches none of them.
The inspected nonmatching path reaches preparation with the initially zeroed
SQL buffer, not the path/cue query. Thus the constructor state alone does not
support using this helper to locate a file-browser row. A later mutation of
the key or some other live contract has not been ruled out by exhaustive
dataflow analysis. Do not claim that the runtime helper was tested or always
returns zero in Files; its applicability remains unproven.

The entry gates can now be stated mechanically:

- `0x42C060` acquires callbacks at `0xADD368+0x48/+0x4C`; if global field
  `+0x18` is zero it returns zero. Otherwise `0x42BFE0` returns 1 when
  `0x4320C0` returns 1, or returns whether global `+0xFC` is zero.
  `0x4320C0` obtains a result via command `0x209` to `0x64ADBC`.
  These are not yet fully named playback-state semantics.
- `0x8B1F60` returns 1 for a null input. Otherwise it follows two `+0x10`
  pointers and uses `0x8B2FA0` to read the next object's `+0x40`; that helper
  also returns 1 for a null input. This is not evidence of an active-explorer
  type check or a lock protecting view lifetime.

### Saved database experiment

Read-only snapshot `E:\\platform-tools\\usrlocal_media_test.db`, SHA-256
`a037154e3659d33d355c88fdc9b9089150ac2474c7947d3bbe3929d402cac89c`, contains:

- `list_tb_5`: 13 Slayer tracks sharing one FLAC path, with cue IDs 0 through
  12. Their SQL row positions are 0 through 12.
- `list_tb_6`: a `covers` directory at position 0, followed by Sleep cue IDs
  0 through 5. Part I (cue ID 0) is therefore at list position 1, not 0.

Replaying the stock path/cue count query against these tables gives the correct
position for every saved entry. An absent path also returns 0: the scalar
subquery becomes NULL and the outer count is zero. This proves the ambiguity
of that query, independently of SQL preparation failures. A successful match
must be established separately before interpreting zero as the first row.

This experiment does **not** prove that the live explorer uses these snapshot
table names, that `0x490E20` selects this query in Files, or that a playback
descriptor remains consistent during a timer callback. The directory entry in
Sleep also rules out using cue ID directly as the absolute browser index.

Reproduce with the read-only checker:

```text
python scripts/check_folderfollow_scroll_lookup.py E:\platform-tools\hiby_player_02fd.bin E:\platform-tools\usrlocal_media_test.db
```

Next priority: identify the active explorer's actual table/list mapping and
match `(path, cue_id)` there; observe `view+0x3824` at runtime if necessary.
Only then combine a verified absolute list position with the stock offset and
refresh transaction. No new binary or player installation was made.

## File-browser row source and manager mapping

The next pass followed the actual Files row reader rather than the unrelated
empty `view+0x3824` lookup key.

At `0x499D18`, `0x499C20` calculates the requested absolute row as visible slot
plus the offset-derived starting row. For explorer type 2 it follows the normal
branch at `0x499D3C-0x499D48`, calling
`0x4327C0(view+0x3DD8, absolute_index, output_descriptor)`.

`0x4327C0` first obtains the controller and calls `0x4E53E0`. This resolver
compares the supplied UTF-16 folder wildcard with each view's `+0x3DD8`, under
controller list locking. Unlike `0x4E5320`, it resolves by path, not type name.
The selected view then feeds `0x4994E0`:

- Let `P=*(view+0x3B68)`. When `index % P[+0x1D4] + P[+0x1DC] == index`,
  the reader tries list object `view+0x64`, method `+0x2C`, at the modulo index.
- Otherwise (or if that lookup fails), it calls `0x48CFA0(view+0x68, index)`.
- Found descriptors are copied with size `0xA88`. Missing entries return -1;
  another branch can return 0 without copying when a descriptor's UTF-16 field
  at `+0x20C` is empty. Therefore a zero return is not alone proof of a valid
  populated descriptor.
- `0x4327C0` may fall back to `0x6F7CA0(out, index, 1, 1, folder_path)`;
  this wrapper itself does not faithfully propagate every fallback error.

The fallback takes database callbacks at database-context `+0x560/+0x564`.
Its folder-table branch calls `0x6F2D20(folder_path)` at `0x6F8B08`, rejects a
negative result, and uses the returned number to format a `list_tb_` query.
`0x6F2D20` binds the UTF-16 path to the prepared statement at database-context
`+0x4AC`, reads column zero on a row result, resets the statement, and returns
-1 on missing statement/no result. It does not acquire a lock itself.

The binary contains `SELECT id FROM MANAGER_TABLE WHERE path = ?` at
`0x9A7300` (referenced by statement tables at `0x99B150` and `0x99B238`).
The complete initializer-to-`+0x4AC` assignment has not yet been traced, so the
statement identity is supported by the matching behavior and database schema,
not asserted as a fully proved initializer chain.

### Concrete saved mapping

The read-only snapshot gives an exact path-to-table mapping:

| Manager ID | Folder suffix | Row table | Entries |
| --- | --- | --- | --- |
| 3 | `Slayer - Discography\\Albums\\*` | `list_tb_3` | 1 |
| 4 | `Albums\\1983 - Show No Mercy\\*` | `list_tb_4` | 1 |
| 5 | `1983 - Show No Mercy\\1987 USA Discovery Systems, Metal Blade 71034-2\\*` | `list_tb_5` | 13 |
| 6 | `Sleep - 1998 - Jerusalem\\*` | `list_tb_6` | 7 |

These IDs are snapshot values, not persistent constants to embed in a patch.
The checker now resolves `MANAGER_TABLE` by folder path, verifies counts,
requires a unique exact `(path, cue_id)` match, and only then counts preceding
rowids. All 20 saved Slayer/Sleep entries passed. Missing folder, file and cue
tests return `None` rather than conflating absence with index zero. This is an
offline experiment, not player-side code or a proven live read contract.

### Sort order caveat

For drive-letter paths (`a:` through `c:`), `0x6F8D90` checks database-context
`+0x538`. Modes 3/4/5/6 select SQL with `has_child_file desc` followed by
ctime ascending/descending or mtime ascending/descending. Other modes use
`SELECT * FROM %s%d limit ? offset ?` (`0x9A15C8`, no explicit ORDER BY).
The ordering templates are at `0x9A16F4`, `0x9A1740`, `0x9A165C`, `0x9A16A8`.
The snapshot rowid experiment must not be generalized to those date-sort modes,
nor assumed to resolve tie ordering. A runtime target should use the same
ordering as the active list and require a verified descriptor match.

Additional reproduction:

```text
dump 0x499D00 0x499D60
dump 0x4327C0 0x4328A0
dump 0x4E53E0 0x4E5498
dump 0x4994E0 0x4995C8
dump 0x6F2D20 0x6F2DB0
dump 0x6F8AFC 0x6F8C08
dump 0x6F8D90 0x6F8EB0
cstr 0x9A7300
```

Next measurement can now target the active wildcard, cache window
`P+0x1D4/+0x1DC/+0x1E0`, playback path/cue, and sort mode. No live list getter,
database helper, or offset setter was called in this pass; no firmware was
built or installed.

## Post-hardware audit (2026-09-29)

Final SCRL log: 2,868 complete records. Deep Slayer cues 0..4 occur only at
offset 0; cue 5 occurs at 0 and then manual offsets 33..330. Pitch is 80,
viewport height 260. The lookup key is empty throughout these samples,
confirming the obstacle to using the generic key-based locator for Files.
No cue-before/after mismatch was sampled; that does not prove atomic reads.

### Actual extent used by stock bottom adjustment

Let V be the explorer, P=*(V+0x3B68), Q=*(P+0x1B8), C=*(V+0xCC).
The locator at `0x490F08..0x490F38` reads **Q+0x9C**, not C+0x20, for its
bottom adjustment. For requested offset Y it computes:

`if extent - Y < viewport_height: Y = max(0, extent - viewport_height)`.

Saved-position restoration at `0x48FA80..0x48FACC` independently uses the same
Q+0x9C field, limits saved Y to extent minus viewport height, and handles a
negative result separately. Two stock consumers corroborate this field; its
runtime value and safety of calling these routines from a timer remain unproved.

SCRL v1's `content_height` is only raw C+0x20, zero even during manual scrolling.
The generic setter uses it only in its flag-dependent bounds branch
(C+0x3C bits 4/8). Other branches can write offsets without these bounds.
We did not record flags, so the live viewport's branch is not established.
Next telemetry should record C+0x3C, Q and Q+0x9C separately. Do not reinterpret
old records or use their zero field as a valid scroll limit.

### Sort: address chain confirmed, value still unexplained

At `0x6F8B34` the drive-letter branch's delay slot `0x6F8B38` loads
*(0xBAD7B0) into v0; `0x6F8D94` then reads v0+0x538. This matches the probe,
and these instructions are unchanged in the tested ELF. There is no evidence
yet to replace the diagnostic's base pointer.

The sampled raw value is consistently `0x00BDA6C9`, not 3..6. If this value
reaches the fallback at lookup time, the comparisons select default SQL.
This does not establish active cache ordering or explain initialization.
Do not label it a validated user-selected sort mode. Direct stores using
offset 0x538 elsewhere may be unrelated: `0x4EA420`, for example, uses the
global at 0xB8BACC rather than the database global.

Read-only reproduction (ten instruction anchors plus complete log decoding):

```text
python scripts/check_scroll_diag_findings.py artifacts/hiby_player_1.4_sortfix_fullnav_wake_scroll_diag_test artifacts/scroll_diag_final_20260929.bin
```

Checks pass. No new firmware was built or installed; the device remains stock.

## Cache descriptor identity and absolute index (2026-09-29)

`0x4994E0` reads a primary descriptor from list V+0x64 at slot
`i % capacity` only if `slot + P[0x1DC] == i` (capacity=P[0x1D4]).
Thus a snapshot slot j maps to start+j only when the modulo condition also
holds; do not blindly interpret an arbitrary ring-buffer slot as an index.
This function does not itself null-check P or guard zero capacity before div.
It is not a safe generic timer getter just because it returns -1 on some errors.

The additional list V+0x68 is searched by `0x48CFA0`:
method +0x30 returns count; method +0x2C returns each descriptor; its trailing
word **descriptor+0xA88** is compared with the requested absolute index at
`0x48CFF4..0x48CFF8`. Producer `0x48CC80` corroborates this layout: it copies
0xA88 descriptor bytes to sp+0x18, then stores the index at sp+0xAA0
(exactly +0xA88 after the descriptor start), before appending via method +0x18
at `0x48CD30..0x48CD38`. The normal 0xA88-byte copy returned by `0x4994E0`
does NOT include that trailing index. It is unsafe to read it from that copy.

The playing-match predicate `0x4961E0` also establishes descriptor identity:
the Files type-2 jump-table entry at `0x944578` routes to `0x496294`.
After path-specific checks it compares property-24 path against descriptor+4
and compares property-24 cue (sp+0x43C, descriptor origin sp+0x18) against
descriptor+0x424 at `0x4962B4..0x4962C4`. This path uses bounded UTF-16
comparison by descriptor path length; special paths have other branches.
A proposed cache search should conservatively require exact full path and cue,
not inherit prefix-only acceptance. The helper's other gates and branches
mean it should not yet be called directly from the diagnostic timer.

Offline conservative index model: `scripts/test_scroll_cache_index_model.py`.
Four tests cover synthetic Slayer/Sleep layouts, nonzero windows, trailing
absolute indices, no match, wrong cue, prefix collisions, duplicate identities,
conflicting copies and invalid window geometry. These are model tests, NOT
captured live descriptor data or proof of safe concurrent cache access.

Next unresolved prerequisite: identify list getter implementations and their
lifetime/locking contract, and observe a consistent active-cache snapshot.
No scanning getters or new firmware were run on the device in this pass.

## Cache lifetime audit (2026-09-29)

The list constructor `0x456C40` installs method +0x2C = `0x4557E0`,
+0x30 = `0x455DC0`, and +0x18 = `0x455DA0` (append). The Files setup at
`0x49512C` creates a primary list with element size 0xA88. At `0x4951CC`,
`0x495240..0x495250` it creates the additional list with element size 0xA90,
consistent with the trailing absolute index at +0xA88. Do not treat these
as contiguous arrays of pointers to independently retained descriptors.

For a non-null list, count getter `0x455DC0` simply returns list+0x0C.
Getter `0x4557E0` checks index against count, then computes a raw pointer:

`blocks[index / block_size] + (index % block_size) * element_size`

where blocks is list+0, block_size list+0x14 and element_size list+0x10.
It neither copies nor pins the result. Its complete leaf body contains no
calls, LL/SC or SYNC; no internal lock protects the pointer after return.
It also assumes valid block metadata after the initial count check.

Append `0x455DA0` tail-calls insertion `0x455BC0`; insertion copies/moves
element bytes, grows through `0x455980` when necessary, and updates list count
at `0x455CF8`. Thus even a retained address is not a stable row identity in
the presence of mutation. Destructor `0x456E80` releases backing blocks,
the block table and the list object.

A concrete UI refresh path at `0x491240` destroys V+0x64 (`0x49126C`) and
V+0x68 (`0x491280`), clears those fields, and calls V+0x4218 to refill them.
No lock acquisition appears between entry and these destruction calls.
This does NOT exclude a lock held by the caller or UI-thread serialization.
It DOES rule out relying on getter-internal protection or a null check alone.
The primary list can also alias P+0x1BC (`0x490770..0x49077C`), so an owner
pointer must not be assumed to give an independent retained copy.

Conclusion: an arbitrary timer-side cache scan is not yet justified. The next
proof must cover outer serialization/lifetime across all relevant mutation
paths, or use an existing callback where each descriptor and its index are
already valid. Sampling unchanged pointers/count twice does not prevent a
free/reuse between samples (ABA). No new locking calls, scanning getters or
firmware changes were executed on the device.

The read-only `check_scroll_diag_findings.py` additionally checks constructor,
getter and destruction anchors and the getter's leaf/non-atomic instruction
shape. These static checks are not a concurrency test.

## Candidate observation point inside stock row processing (2026-09-29)

Preferred next diagnostic candidate is **0x499D4C**, immediately after the
ordinary Files row lookup returns to `0x499C20`. At that point:

- s0 is the owning view, s2 the visible slot, s7 the offset-derived starting
  row, and s3=s2+s7 is the absolute requested row (`0x499D18`).
- sp+0x18 holds the 0xA88-byte descriptor buffer. It is cleared at
  `0x499D00..0x499D0C` before each row, then passed as the output argument
  to `0x4327C0` at `0x499D44`, with the argument in the delay slot.
- The local copy's path is sp+0x1C and cue is sp+0x43C. This avoids retaining
  a cache pointer after stock has completed its own read. It does not establish
  atomicity of that original read or validity of an unpopulated descriptor.

Important restrictions: type-filter to Files, check nonempty/terminated path,
and treat return zero as insufficient evidence because `0x4327C0` suppresses
some lookup failures. Do not read +0xA88 from the copy (outside the descriptor).
Capture before s3 is reused later in the function. Any eventual trampoline
must replay the overwritten instruction and preserve the caller's live state.
Only copy values for observation; do not scroll or reenter navigation there.

Coverage is limited: row refill iterates visible slots derived from viewport
height/pitch and caps at eight (`0x499ED4..0x499EE8`). This is **not** a scan
of all cached tracks and cannot discover an arbitrary offscreen match alone.
For this test's height 260/pitch 80, the refill loop normally visits four slots.

Alternative identified: draw callback `0x496C60` receives an index as its fifth
argument (original sp+0x10 = new sp+0xDB8). Its primary/additional cache lookup
uses that same index (`0x49722C..0x497264`). It invokes playing-match predicate
`0x4961E0` at `0x497050` and `0x497F0C`; at the latter, a match stores the
index in view+0x90 (`0x497F1C..0x497F2C`). This is a conditional write, not
proof that view+0x90 always tracks playback. Descriptor sp+0xD54 may still be
a raw cache pointer, so this is less attractive than the row-local copy for
initial observation. No new getter should be called from a hook.

The worker callback at `0x4C052C` was also examined: it supplies a different
processed-row structure (e.g. path at +0x114), not the 0xA88 media descriptor.
Its enumeration index must not be relabeled an absolute browser index without
an additional mapping proof. It is not selected as the observation point.

This pass identifies a bounded-lifetime local-data observation point, **not**
a proven safe deployment or completed autoscroll design. The unresolved next
question is how the offscreen target becomes known without scanning mutable
cache memory. No firmware changes or device calls were made.

## Offscreen mapping: observe list production, not draw state (2026-09-29)

The scoped scan of direct loads/stores at offset 0x90 in 0x490000..0x550000
did not identify another proven writer of the explorer playing-row field.
Many hits refer to unrelated objects. The timer helper `0x4E6420`, for example,
reads +0x90 from a widget returned by `0x485420`; that is not evidence for an
explorer index update. `view+0x90` remains an unproven offscreen source; the
known write at `0x497F2C` depends on processing a matching draw row. This scan
is not exhaustive for computed addresses or out-of-range code.

A stronger candidate is the existing SQL-to-list producer `0x6ED5C0`:

- The Files list setup calls `0x6F7CA0` with the newly created descriptor list,
  offset zero, requested count, mode zero and folder wildcard at
  `0x49518C..0x4951A0`.
- In the folder SQL branch, `0x6F8BD8..0x6F8BF0` passes the prepared statement,
  output list, offset, limit, mode and folder through to `0x6ED5C0`.
- That producer preserves offset at sp+0xAD8, binds limit as parameter 1 and
  offset as parameter 2, then resets its row ordinal s1 to zero at `0x6ED6A8`.
- In mode zero, `0x6ED6D8` populates a local 0xA88 descriptor at sp+0x20 using
  `0x6E8D80`; **0x6ED6E0** is immediately after that returns and before append.
  Destination list is s6, ordinal s1, path sp+0x24, cue sp+0x444. For the
  verified LIMIT/OFFSET folder query, requested absolute row = saved offset+s1.
- The append call is at `0x6ED6E8`; ordinal increments at `0x6ED6F0` without
  testing append success. An observation before append proves a SQL row was
  produced, NOT that it was successfully committed to the live cache.

Unlike viewport refill, this producer handles the requested cache range, so
it can observe rows beyond the screen. It follows the SQL order actually
chosen by stock rather than inferring order from rowid or cue. It is not
automatically a complete-folder enumeration: count/offset still limit it.

Possible next passive experiment: capture bounded copies of folder, destination
list identity, offset/ordinal, path/cue and append outcome during this existing
flow. No database query or list getter should be added. Guard mode zero and
the proven folder-query caller; the producer has other modes and callers.
Correlate list ownership with the view only after the stock setup publishes it.
Do not retain stack pointers or treat a reused list address as a generation ID.
Any durable map must be invalidated on folder/sort changes, list recreation,
failed/incomplete loads and identity ambiguity. Its playback lookup must
require exact path+cue and a unique current-generation match.

This identifies a potential offscreen observation source, not a firmware patch.
No new binary was built, installed or invoked on the device in this pass.

## Append result and generation audit (2026-09-29)

For the proven standard list, append `0x455DA0` forwards the old count as the
insertion index to `0x455BC0`. The insertion copies the element, increments
count at `0x455CF8`, and returns the insertion index at `0x455D00`. Failure
sets that return to -1 at `0x455D98`. Therefore index **zero is success**;
a Boolean/nonzero success check would discard the first row and accept -1.
This contract applies only after verifying the actual append implementation.

At producer return site `0x6ED6F0`, v0 still contains append result, s1 is the
pre-increment SQL ordinal and the local descriptor remains at sp+0x20.
This is more useful than pre-append observation for distinguishing attempted
and committed records. The displaced instruction increments s1; a future
probe must observe the old value and then preserve that increment. Stock does
not branch on append failure. Consequently producer row count can exceed
actual list count; offset+ordinal remains a SQL row number, not necessarily
the cache slot after a skipped insertion. Reject a map for the entire affected
load rather than silently shifting subsequent indices.

Correction to the earlier publication proposal: `0x495144` writes the new
list to the caller-provided output slot BEFORE `0x49519C` fills it. Publication
is NOT a completion event. At `0x4951A4` stock reads actual list count; this
does not by itself verify all SQL or append outcomes. An observer needs a
separate load generation and explicit validated completion, not pointer equality.

Invalidation evidence:

- `0x491240` frees both lists and clears/rebuilds their fields (previous audit).
- `0x493FA8` / `0x493FBC` free additional/primary lists; the owning object and
  view are subsequently released in the displayed teardown path.
- Method +0x24 is `0x4557C0`: clearing only writes count=0 and keeps the list
  address. Destruction-only invalidation would therefore be insufficient.
  All relevant callers of clear and in-place mutation are not yet mapped.

Design requirement for any later map: begin generation in loading state,
copy only validated mode-zero folder records, require append index consistency,
mark any failed/missing event invalid, and expose lookup only after validated
completion. Invalidate before reset, replacement, in-place reorder or scope
change. Pointer/count checks cannot substitute for generation ownership.
Full coverage of those lifecycle events is still unproved, so this audit does
not authorize using a persistent map for scrolling yet. No firmware changes
or device access occurred.

## In-place refill confirmed; bounded diagnostic scope (2026-09-29)

`0x48D080` resolves a view and its cache owner P, then on the examined branch:
clears V+0x68 through method +0x24 at `0x48D120`, preserves selected old
descriptors through `0x48D040`, clears P+0x1BC at `0x48D170`, calculates a
new offset, and refills V+0x64 via `0x6F7CA0` at `0x48D1B8`. The cache-owner
metadata callbacks +0x404/+0x408 execute **after** refill at `0x48D1C8` and
`0x48D1D8`. Another branch clears/refills at `0x48D5C0` / `0x48D608` with
the same post-fill callback ordering. Both show that a stable list address
does not imply stable contents or window metadata.

Therefore future row telemetry must use the query's saved offset, not a
cache-owner offset sampled midway through filling. A persistent on-device map
still needs lifecycle coverage, but initial observation can avoid that scope:
record a bounded fill session and validate it offline without driving scrolling.

Proposed session events (not implemented in firmware): begin with generation,
folder/query identity, list identity, offset, requested count, mode and initial
list count; per-row record ordinal, copied path/cue and append return; end with
producer outcome, observed rows, actual list count and event-drop/error status.
Use only the verified initially-empty, mode-zero folder-list case. Treat SQL
completion/error separately from append count; a matching count alone is not
proof of completion. Nonzero offsets and empty results are legal, while row
zero must not be confused with failed lookup. Missing, interleaved, dropped,
failed or inconsistent events must not yield a usable mapping.

`test_scroll_fill_session_model.py` adds five offline protocol-model tests:
successful append index zero, failed insertion despite advancing producer
ordinal, missing/reordered/duplicate events, incomplete/published-only list,
and a fresh session after clear at the same address. These tests do not prove
runtime event coverage, SQL completion, concurrency or logging reliability.
Existing SCRL v1 logs lack these fields and cannot reconstruct the full map.
No new firmware was built or installed in this pass.

## Completion diagnostic: counters can conceal partial reads (2026-09-29)

The first step result is compared with 100 at `0x6ED6C0`; subsequent step
results are compared at `0x6ED6FC`. Both non-row paths arrive at **0x6ED704**
with terminal step result still in v0. That instruction calls `0x5C31C0` and
overwrites it. The callee changes statement state (including +0x28/+0x48 and
other fields); it must not be treated as a read-only getter of the original
terminal result. For diagnostic purposes capture v0 BEFORE this call and
preserve the original call/delay slot unchanged.

Afterwards, zero and 19 branch to the normal epilogue; other results are logged
but still reach the epilogue returning s1, the processed-row counter
(`0x6ED70C..0x6ED730`, `0x6ED7D0`). Thus a nonnegative producer return alone
does not establish a fully completed query. Bind-error paths differ and must
be recorded separately, not inferred from absence of row events.

The outer folder-query branch discards the producer return during statement
cleanup and explicitly sets s0=0 at `0x6F8BFC`; the common epilogue returns
s0 at `0x6F7F6C`. Its zero return is therefore not an independent completion
certificate. Equal observed-row/list counts can coexist with early query exit.

Required passive evidence is now three stages: begin (scope and offset),
post-append `0x6ED6F0` (row and actual append result), pre-cleanup `0x6ED704`
(terminal step result), plus explicit bind/early-return/error coverage. Do not
add synchronous file writes inside a database-held callback without evaluating
blocking/reentrancy; buffering and loss indication need design before a build.

Existing SCRL v1 has viewport/cache summary and playback identity only. Its
2,868 final records prove the manual-vs-automatic offset behavior but cannot
show row insertion results, SQL termination or a complete path/cue index map.
No such runtime diagnostics can be reconstructed from this log. A new passive
instrumentation build and separately authorized hardware run are required for
that measurement; neither occurred in this diagnostic pass.

## Next safe investigation

1. Identify the writers of the actual active view's `C+0x18`, starting from
   ordinary manual scroll and activation paths. Trace their bounds and locking.
2. Find the playback-match row independently of `internal+0x5A0`; separate
   absolute media index, visible row-slot index, and cue-track identity.
3. If hardware observation is needed, use passive telemetry of the active
   explorer, playback identity, pitch, content offset and redraw rectangle.
   Compare physical Next and manual scrolling; do not write these fields.
4. Only after that identify an ordinary ensure-visible operation and a
   change-triggered policy that does not fight manual browsing.

Automatic descent after root-folder selection remains a separate open task.

## Reproduction

Use `scripts/mips_static_trace.py` on the recovered `hiby_player_02fd.bin`
(`02fd1dd1...`) for these unmodified stock-code regions:

```text
mem-imm-xrefs 0x5A0 --context 3
dump 0x4BF180 0x4BF340
dump 0x4C04A0 0x4C0620
table 0x9489A4 8
dump 0x4C0620 0x4C0794
dump 0x490260 0x4906C8
dump 0x499C20 0x49A140
dump 0x43C860 0x43C8F0
dump 0x452DC0 0x452E70
dump 0x459840 0x459894
dump 0x8B4280 0x8B43A0
```

The helper does not decode every MIPS instruction. In particular,
`0x70A23002` at `0x4905FC` is MIPS32 `mul a2,a1,v0`, and `0x0005200B`
at `0x4905E4` is `movn a0,zero,a1`; these were decoded manually above.
