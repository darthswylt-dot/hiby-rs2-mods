# Offline MIPS owner-generation retirement and cooperative queue purge

2026-10-23. Follow-up to the [40-byte handoff prototype](folderfollow-reveal-paint-handoff.md),
committed in faf635f. This is a separate executable MIPS prototype, not a
firmware stage, installed queue replacement or native object-lifetime lease.
No player/device/network operation, native destructor or UI action.

## Generation and publication are separate identities

The new record is **44 bytes**: the prior36-byte body remains unchanged,
publication nonce is at36, and the captured owner-generation ticket is at40.
Neither tail replaces LALI at32. The old40-byte module, existing builders,
decoders, LALI/BIRTH input bindings and saved images are not changed.

One persistent nonwrapping serial issues both owner and publication tickets.
A bounded append-only private owner table stores ticket, raw engine word,
retired flag and reserved zero. Registration must occur at an independently
admitted lifecycle boundary. A producer supplies the generation it captured
there; it must not register a fresh owner or look up the latest generation to
repair a refused late publication. Repeated/equal engine words do not merge
generations and are never dereferenced by this helper.

Publication checks the issued owner, its live status and agreement between
the owned payload's engine word and the registered scalar before appending.
Retired, unknown or mismatched generations cannot create queued work. Owner
slots are never reused, even after retirement/drain: a full table rejects new
registration without consuming a serial or evicting another owner. This is a
bounded prototype, not a fully reclaiming long-running lifecycle allocator.

## Retirement under the same native paint guard

The default emission uses the pinned native148 callback protocol, with a
genuinely acquired guard as an external premise: the native wrappers discard
pthread status. An explicit `checked_mutex=True` variant instead checks raw
service results; see the [checked mode and admission audit](folderfollow-reveal-paint-admission.md).
In either valid-guard execution, `retire` first
sets the generation's tombstone permanently, then cancels its active claim,
before inspecting/removing queued records. It validates an existing active
head's list binding, nonce and generation before any purge removal. That
active head stays present with its private copy until exact acknowledgement.

The bounded scan validates each visited row's nonce, owner and raw engine
binding. It removes only unclaimed rows of the target generation using the
actual raw native remove method. Kept rows advance the index; removed rows
recheck the same index after compaction. Other generations preserve their
relative order, including across native ten-element segment boundaries.
Raw remove must return0 and reduce count by exactly one.

A later invalid row, raw list failure or unexpected count does not undo earlier
removals or revoke the tombstone. While the guard is held, it sets terminal
fault and suppresses positive `drained`. The older callback-failure tests inject
errors at466DA0/DC0, above the native status masking; they are not raw pthread
failure tests. In checked mode, a nonzero raw lock result prevents private/queue
access and does not guess an unlock. A nonzero raw unlock result denies this
call's success without a post-unlock shared fault store. The caller must
quarantine further use externally; neither mode promises rollback or a general
mutex-failure recovery/lifetime protocol.

`close` only withdraws new registration/publication/claims and cancels the
active one. It does not implicitly retire every owner or remove the tail.
Explicit retire/drained operations remain available after close; exact old
acknowledgements can finish cancellation while storage remains valid.

`drained` is a guarded observation requiring a retired owner, no queued or
active entry for that generation, and no terminal fault. A live empty owner is
not drained: it can still publish. Terminal fault suppresses positive drain
even if later acknowledgement empties the visible list. No owner row is freed
or recycled and no native continuation is executed from this result.

## Remaining native integration gates

This protocol establishes only cooperative local queue/accounting behavior.
It does not install hooks into stock purge4396C0, current-index remove439960,
queue destroy4398A0, resource deletion4395A0, detach8B0760 or controller
shutdown43CB20 or its earlier outer-caller registry cleanup. It never calls the facade439780, which performs parent detach
after its queue purge. The original13C-only purge remains a separate bypass.

The caller must retain the controller, mutex, native list and its complete
allocated segments, including spare slots. Raw removal shifts spare segment
bytes as well as logical entries; a valid selected pointer alone cannot prove
all its copy accesses safe. Bounds/schema checks do not prove heap lifetime.
Native mutex/libc/list stack depth and cache/scheduler behavior are likewise
outside this instruction fixture.

Coherent owned publication inputs remain a prerequisite; the original producer
reads its borrowed rectangle before148. A copied engine word or fresh logical
generation does not retain the actual allocation or parent membership.
Even a positive local drained result grants **no permission to free native
objects**. Actual deletion/detach/shutdown needs complete user coverage and a
checked deferred-continuation protocol before the previously audited first
mutations, not just a hook at the final free. Current playback, request
freshness, contents, UI ownership and automatic scrolling remain unproved.

## Verification

All **65 focused checks pass** (5.796 s):23 basic instruction/ABI checks,
24 adversarial checks and18 hash-pinned original-source contracts. Coverage
includes captured-generation rejection after equal-engine reopen, exact old
acknowledgement, revocation/cancellation before the first actual remove,
repeated retire/drain, a full non-reclaiming owner table and shared-ticket
exhaustion. Close leaves the tail until explicit owner retirement.

Tests exercise75-entry queues across9/10,19/20 and69/70 boundaries, adjacent
matches and stable unmatched FIFO. Bad active-list bindings are refused before
foreign-header reads. Later-row corruption after an earlier removal, genuine
native growth failures, injected raw remove/count failures and substituted
mutex-wrapper failures cannot claim rollback or positive drain. Malformed owner schemas,
duplicate owner tickets, nonces not following their owner, full-state aliasing
and incompatible record/method layouts are refused. Ten deterministic70-event
sequences match an independent generation/retained-head oracle. Raw engine
words do not cause native object, name, destructor or UI access.

Independent source and implementation/test/documentation review found no
remaining actionable issue after moving list-binding checks ahead of foreign
header access and enforcing owner-ticket-before-nonce ordering. The prototype
emits10,824 code bytes,328 state bytes at the default16 owner slots, and a
160-byte helper frame; state is72+16*owner_capacity bytes (1..1024 slots).
Native/service frames, full list allocation and guard hold time remain separate
costs and are not approved by these numbers.

The first full run executed2,118 tests in322.292 s and had one failure in the
unchanged `test_reveal_bridge_launcher` normal-exit fixture's no-late-signal
assertion. Its mocked watchdog sleeps25 ms. All new checks passed. The entire
unchanged launcher module then passed separately:24 tests in16.642 s. No
launcher timer, assertion or production code was modified. On2026-10-26 a
fresh serial full rerun completed: **2,118 tests pass, no skips** (308.557 s).
The earlier interrupted retry had no retrievable result and is not counted as
a successful run.

All233 Python scripts compile; tracked/new text files pass whitespace checks.
The old40-byte handoff, launcher and launcher tests are unchanged from faf635f.
Saved action-link, playback-dispatch and renderer-transport images are exactly
reverified against the pinned source with unchanged SHA-256 hashes
`d4306357ec6b70153b15e98202dad1a7ad0615d02ea6bd9e0d53857844ab37a8`,
`a9a6f02fd48a3b57e27e3bb19c9e8c2b8329b6602cc12988091dfbb98c2abe2c`
and `f42fac46890dc2eadbeba88f90ce5b82857d3045752b974b15d04bef263d2244`.

The default test fixture executes emitted instructions and original list/mutex callback
bodies with bounded memory, heap/libc/mutex services and explicit fault
injections. It is not a hardware concurrency or resource-lifetime test. No
installable image is produced. This verification preceded publication: no
device/network operation, commit or push was part of it. The later user request
authorizes committing/pushing these text-only prototypes and reports, not
installing firmware. Hardware UNTESTED; active folder-follow/scrolling stays disabled.

The later [registry-bound issuance prototype](folderfollow-reveal-registry-owner.md)
adds an optional expected_mutex_address pin to checked mode: a changed U+148
snapshot is denied before raw acquisition. Omitting the pin preserves both
earlier instruction variants exactly. The new caller nests148 under captured
13C and records historical logical issuance only, not native ownership/free
or current producer authority.
