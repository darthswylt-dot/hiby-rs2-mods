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

For these six sites, the model executes the native allocation branch and
its delay. A successful allocation reaches the unchecked H+58 store with
both a zero and a live H. A failed allocation skips the store and returns
the saved H through the native epilogue, restoring the frame. The success
fixtures end at the store, with bounded allocator, clear, time and copy
services where needed.

| Factory call | Allocation-failure exit | Sole encoded direct wrapper caller | Upper return |
| --- | --- | --- | --- |
| `4CFF38` | `4CFFC8` | `4CB100` | 1 at `4CB118` |
| `4D1ADC` | `4D1BD4` | `4CB0A4` | 1 at `4CB0BC` |
| `4D2B44` | `4D2C24` | `4C9124` | 1 at `4C82FC` |
| `4D3724` | `4D3760` | `4C8C20` | 1 at `4C82FC` |
| `509A2C` | `509A5C` | `509368` | 1 at `509394` after configuring the old object |
| `515218` | `515250` | `4C1A2C` | 1 at `4C1A38` |

The upper fixtures supply both wrapper results and execute the actual
continuations. The notice path at `509368` passes the previous S1 and
selector 1 to `47D0A0`. With a live old object, the native configurator
passes that object's mutex to lock and unlock and stores 1 in old object+4.
A zero old object takes the configurator's own return-minus-one path.
Both then reach the upper return-one suffix. The fixture bounds the mutex
services. Runtime mutex ownership and computed wrapper callers remain open.

The D180 emitter adds redirects at `4CFF44`, `4D1AE8`, `4D2B50`,
`4D3730` and `515224`, where the upper continuation returns 1 directly.
Each keeps the handle-save delay. With a zero H, it takes the original
allocation-failure exit and replays that branch's delay. With a live H,
the allocator receives the original register state and return address.
The emitted-code fixtures check the full failure returns and the success
paths through the H+58 store.

For the notice wrapper `5099C0`, the redirect at `509A38` keeps S1=H.
The zero-H route replays S0=0 and takes the original exit at `509A5C`.
The fixture starts at `509360` and runs the actual upper call, lower wrapper
and mode-1 configurator. It compares early exit with stock allocation failure
after a zero factory result. The two executions deliberately supply
different volatile A2/A3 values at the configurator. Both pass the same
old S1 and selector 1, touch the same old mutex and store the same old-object
flag. Both return 1 to the upper caller. The known event route supplies a
live old object, and a zero old object is also covered as a local control.
The model bounds the factory, allocator and imported mutex operations.
With a live factory result, the fixture also compares both allocation
outcomes from the native wrapper entry through its return, including the
bounded string copy and the H+58 store.

For the `527040` wrapper, the emitter redirects the allocator call at
`5270AC` and preserves the delay that saves H in S1. A zero H jumps
straight to `5270F0`, bypassing both allocation and the hazardous branch
delay. The earlier clear of `B8BE04` at `5270A4` still executes.
With a live H, the helper enters the allocator with the original arguments
and link `5270B4`. The native delay stores the allocation result in H+58
for both outcomes. On success, four native lookups fill the payload.

The bounded fixture executes the emitted helper, the native wrapper and
its lookup paths for both allocation outcomes. The zero-H test returns
zero through the original epilogue. The sole encoded caller at `4C1A3C`
then returns one through `4C1860`, which the fixture also executes.
The checked scope is this wrapper and its encoded caller. The model
supplies factory and allocator results, a mapped resource and valid frames.

For `47D960`, calls at `5091A8` and `50BAB4` save H, then allocate an independent
payload. On allocation success, `5091E0` or `50BAD8` writes that payload through
H+58 without a factory NULL check. On allocation failure the write is skipped;
testing only that failure route would conceal the hazard.

The two existing allocation-failure suffixes can return NULL directly
from the supplied post-factory state. `5091E4` takes zero in S1, and
`50BAEC` takes zero in S0. With the genuine caller frames, each suffix
returns zero, restores SP, RA and the saved registers, and performs no
write or service call. The fixture compares that supplied transition
with the original path where both the factory and subsequent allocator
return zero. This validates the local exit contract.

The exact encoded census finds three callers of the `5090E0` wrapper and
two of `50BA60`. All five known continuations discard the wrapper result.
`5081D8` reaches `50817C`, which returns the preexisting S0. `508758` and
`50B348` set V0 to 1 at `508778` and `50B360`. The calls at `5077D4` and
`50A8AC` return the value through `507440` and `50A600`. Under their known
input-dialog registration, `506340` then overwrites it at `506378`.

The fixtures execute the five upper continuations with supplied zero and
nonzero results. They cover the three immediate replacements and both
registered dialog routes. They assume the original frames and the known
callback state. This establishes the result handling for the demonstrated
routes. Runtime redirection and additional computed callers remain separate
verification work.

### Queued context at `45336C`

The `data_dealing` wrapper at `453320` handles event `0x138` through table
pair `926D2C/926D30` and the JALR at `4542A0`. Its epilogue at
`453388` returns 0 and the dispatcher forwards that value. The factory
delay saves the completion address `450D60` in the descriptor. On
success, the configurator call delay at `453384` copies message+8 to the
new dialog's +50, and mode 4 writes 1 to the dialog's +5C.

One producer reads the operation from the old dialog's +58 at `4AECB4`.
It posts the same pointer at `4AEF10`; `4743E4` writes it into message+8.
After posting, `4AEF24` uses operation+50 as the source of a 2,696-byte
copy into the worker's storage. The producer returns through `4AECDC`
with the old +58 still populated. On successful dialog completion,
`47C7C4` passes new dialog+50 to `450D60`, which reaches the free call
at `450DA4`.

The bounded fixture executes the producer tail, the post record stores,
the worker copy path, the table-driven dispatcher and the completion
call. It supplies the view/path selection, queue handoff and dialog
allocation, and bounds mutex, notification and free services. With a
supplied zero factory result and transition to `453388`, the dispatcher
still returns 0. The checked completion no longer receives the operation
and the old dialog still holds its pointer. An early-exit design must
account for the producer's post-enqueue copy, the old alias and the
release authority for the queued context. The fixture establishes the
loss of this completion route, with other teardown and aliases open.

The old-dialog teardown fixture also runs the normal poll at `47CC20` and
close-by-name at `47CF80` with one live list record. Both invoke `47C740`,
which runs the selected producer branch before destroying the old mutexes.
The bound list method `455860` removes the record. At the final free call
(`47CCC8` or `47D02C`), the argument is the old dialog and its +58 still
holds the operation pointer. The checked poll uses the zero +7C state of
a newly cleared dialog. Reused dialogs and a changed optional +7C binding
are separate cases. Registry/resource services and the raw free body are
bounded in this fixture.

The normal music loop calls the dispatcher at `43C9A4` before dialog
completion at `43C9CC`. In the checked continuing iteration, the next
dispatch boundary sees the published record only after the worker copy and
old-dialog free calls. This order belongs to that serial loop invocation.
The queue publishes the record before the worker lock and copy, so an
independent dispatch route needs its own ordering proof.

With a full ring, the actual queue writer returns -1 via `4505C8` before
allocating or publishing a record. The producer still copies from the
operation and the old dialog still reaches its free call. This path leaves
the checked completion without an event even when the dialog factory has
yet to run. The queued-context lifetime therefore also depends on the
producer's handling of enqueue failure.

With an absent queue, `47438C` loads zero and `47439C` returns that zero
without calling the queue writer. The fixture takes this path through
the worker copy and old-dialog retirement. The post wrapper's zero
result alone cannot certify a published record.

The application startup calls `450460` with capacity 128 at `4747AC`,
stores the returned ring in `B89C68` at `4747BC` and copies the same
pointer to application+14 at `4747CC`. The startup fixture executes the
ring constructor and both stores with a supplied allocation and
application object. The producer loads the global and both UI dispatchers
obtain the ring through `475320` and the application's +14. For the
same posted record, both dispatchers reach
`450600`, which copies 20 bytes, frees the record at `450694`, clears
the slot and advances the read index. The music dispatcher finds
`0x138` and transfers the operation to the new dialog. With that dialog
live, the completion fixture reaches a separate free of the operation.
The other dispatcher at `4542C0` scans all 128 entries from `926F94`
and returns after the search. Its table has no `0x138` handler.

The remaining two encoded direct reads of `450600` occur at `42E280`
and `454410`. They load separate worker queue globals at `ADD368`
and `B89250` and request eight bytes. Their startup paths create
separate rings of capacity 50 at `42BAE4` and `455590`. The worker
fixture executes both native reader prefixes and verifies that each
consumes its own eight-byte record while the application ring retains
the posted `0x138` record. The fixture supplies distinct initialized
queue storage and bounds the thread setup and lock services.

On shutdown, `474880` drains the queue through `4507E0`. Its free at
`450830` takes the record address and the free at `45085C` takes the
queue address. The fixture observes no load from inside the record during
the drain. The global queue pointer is cleared at `474898`. The alternate
dispatch and shutdown fixtures both reach the queue cleanup with the
operation still outside the observed free arguments. These results cover
the checked record and shutdown slice with bounded free and earlier
application teardown.

#### Music teardown and the charge controller

The normal music poll at `43C9CC` is the sole encoded direct call to
`47CC20`. A dialog can also complete after the music loop returns.
The music driver calls its +258 teardown at `4E3E08`. The teardown
walks controller records at `4E3EA0` and calls record+18 with
record+14 at `4E3EE8`. For the dialog created at `4AF274`,
`47D320` supplies the close callback `47D060`. Its call at
`47D07C` reaches the close-by-name path, which can invoke the
`4AEC60` producer and retire the old dialog after the post and copy.

The application calls `474800` at `47569C`. The selected controller's
driver returns before that call returns. The application can then read
property 11 as nonzero and select `lg_activity_charge` at `47567C`.
It calls `474800` again with the same application and ring. The charge
driver runs `43CA60` and dispatches through `4542C0`.

The fixture starts with a live remove-song record awaiting teardown
and takes that application branch with supplied exit requests, power
results and UI bindings. Music dispatch sees an empty ring. Music
teardown posts `0x138`, copies the request bytes and retires the old
dialog before the charge controller starts. Charge then frees the
20-byte record after an unsuccessful handler search. Neither the
dialog factory nor the request deallocator is called on that route.
The model bounds registry removal and the final controller cleanup.
This route requires the supplied live record and charge transition.
It establishes a sequential disposal path without assuming that the
two loops run concurrently.

The checked completion `450D60` needs a live dialog. With a nonzero
operation it reads dialog+58 at `450D74` before choosing its continuation.
The source and fixture still leave release authority open across
independent dispatch, failed publication and shutdown.

#### Same-name dialog reuse

The five encoded sends that load event `0x138` directly into A0
reach `474380` at the following call sites.

| Send | Message+8 | Work after the send |
| --- | --- | --- |
| `4AEF10` | Operation from old dialog+58 | Worker copy from operation+50 in mode 2 |
| `4ABFA4` | Zero | `4A8A60` selects and copies separate worker input in mode 1 |
| `4B213C` | Zero | `4327C0` supplies stack data for the mode-1 copy at `4B2160` |
| `4B67B0` | Zero | Mode-1 worker copy at `4B67C4` uses the selected view's data |
| `53076C` | Zero | `4327C0` supplies stack data for the mode-1 copy at `530790` |

For a live `data_dealing` dialog, the native lookup `47CA40` compares
the registered dialog name and returns the existing handle through
`47D1D8` and `47D1E0`. That route bypasses allocation and descriptor
setup. The caller still writes message+8 to H+50 in the delay at
`453384`, before the configurator locks the dialog and sets H+5C.
The original owner, completion callback and timing fields stay in
place. The completion reads the current H+50 once at `47C7C4`.

The fixture dispatches the owned request, supplies the registered
live dialog for reuse and executes the native lookup for a second
queued event. It covers all four native zero-payload send slices and
a second distinct owned operation. In both cases the first request
loses its completion route. With a zero second payload, completion
has no request to release. With a distinct second payload, the
checked H+58=0 completion releases only that second operation.
The fixture supplies the two dispatches before dialog retirement,
with queue allocation and name comparison bounded.

#### Copy before publication

The stock mode-2 handoff at `48F220` copies the descriptor under the
worker mutex at `48F290`, unlocks it at `48F260`, then signals the
worker at `48F268`. After the worker wakes, `48EB58` copies the
descriptor and `48EB80` invokes the mode-2 operation. That operation
can post events `0x139` or `0x13A`, for example at `4A94C0` or
`4A952C`. Moving `0x138` past the stock handoff would allow those
events to enter the same application queue first. Both handlers
look up `data_dealing` by name and request completion when they find
it. Their ordering affects which live dialog receives the request.

The producer-local helper copies 2,696 bytes from operation+50 to the
stack at F+20 before publication. The range ends at F+AA8, where the
path buffer begins. The callback uses that descriptor-sized local
for the property-24 copy at `4AEDB4` on the other path. The selected
post tail leaves that range available. The worker call at
`4AEF24` receives the snapshot in A3 and keeps the original worker,
mode and F+AA8 argument. The worker helper still copies and signals
under its original lock ordering. The producer performs its last
descriptor read from the operation before it publishes the record.

#### Producer transfer and refusal

The producer checks that the old dialog still holds the selected
operation in +58 and that its optional +7C callback is zero. On that
path it clears +58 after the snapshot and before publication. The
ordinary completion code after `4AEC60` uses the saved owner, name
and mutex. The poll's optional +7C call is absent for the checked
freshly initialized `remove_song` binding, and close-by-name has no
such call. A different alias or nonzero +7C takes the native post
with the snapshot still supplied to the worker.

The checked transfer loads the application queue once. With a live
queue it constructs the five-word record in a separate frame as
`(ownership tag, 0x138, operation, 0, ticks)` and calls `4504E0`. A zero
return transfers the request to the published record. An absent
queue or a writer refusal leaves release with the producer. The
producer calls `466A80` once and continues to the original worker
handoff with the snapshot.

The shared queue writer now checks the allocation at `45056C`.
A zero result takes its existing refusal epilogue at `4505C8`,
which restores the writer count and returns -1 before the slot and
write index change. The live route replays both native copy-argument
instructions.

The fixture executes poll and close-by-name with available, full and
absent queues. It verifies unchanged worker data, path and lock order,
native record bytes, alias clearing before publication and one release
on refusal. Separate cases cover allocation failure and the two
conditions that retain the native post. The candidate assumes a live
ring through the writer call in the checked application invocation.

#### Disposal by the charge controller and application shutdown

The marked producer writes `OD38` into message+0. The stock posts
at `474380` and `474420` clear that word. The other four encoded
20-byte writes into the application ring at `44F804`, `44F8C8`,
`44F914` and `44FC98` use the alias at `B890D8` and clear it too.
The known dispatchers
select the handler using message+4. Handler `453320` uses message+8
as its request. The ring copy keeps all five words.

After a successful charge dequeue, the redirect at `45431C` checks
the tag, event `0x138` and a nonzero payload in the local record.
It releases that payload after the native queue reader has freed
the record allocation. The helper replays the table setup and keeps
the native scan and return. Other records take the original scan.

The redirect at `450830` checks the drain's saved link for
`474888`, the continuation of the application shutdown call. It
releases a matching payload before freeing that record and
resumes the native drain. Other callers, including eight-byte
worker queues, reach the native record free without inspecting
message fields. The checked application shutdown retains the stock
premise that the ring is quiescent during destruction.

The fixtures exercise the emitted redirects through the music-to-charge
transition and a mixed application drain. They verify one release of
the marked request, preservation of ordinary records and continued
support for an eight-byte worker drain.

#### Transfer to the music dialog

The redirect at `453374` checks the factory result before the H+50
store. With H zero, it releases a marked request and returns through
`453388`. An unmarked record takes the same return with its existing
ownership unchanged.

A live dialog accepting a marked request stores a private adapter
in H+74 and the request in H+50. A dialog with an unmarked incoming
record and its original callback continues through the native
configurator. For an owned update, the helper uses the raw mutex
imports with H+10 and checks the result. The native wrappers mask
those results. The helper sets H+5C under the mutex, matching the
mode-4 configurator.

On reuse, a different marked request replaces the old one. The
previously marked pointer is released after successful unlock. An
unmarked replacement restores the native completion callback, and
the same pointer retains its existing ownership. A foreign callback
keeps its request and callback and declines a distinct marked input.
When the native close calls the adapter with its current request,
the adapter clears the owned slot, restores `450D60` and passes the
original arguments to it, including the native success refresh.

The fixtures run marked and ordinary records through factory
refusal, live completion, same-name reuse, an unfamiliar callback
and unsuccessful mutex calls. The checked scope assumes a live
dialog through the ordinary serial dispatch. The helper leaves
release unresolved if it cannot confirm lock or unlock. A mutex
call alone does not establish a retained dialog or serialize
independent teardown routes.

### Wi-Fi scan at `4A4F1C`

The `4A49C0` wrapper creates `wifi_scan` on this branch. Its table entry
at `A9A40C` points to the `4A6120` tail trampoline. The branch builds
the descriptor at F+20, and the factory delay at `4A4F20` saves that
pointer in F+10. After the unchecked H+5C write, the normal path registers
callback `4A48E0` in slot 12, marks operation 2 and requests a scan on
`wlan0`. The registration and request belong to the same scan.

The local emitter redirects `4A4F24` and keeps V1=1 in the delay. With a
live dialog it restores the A0 high half and jumps to the original
`4A4F2C` store. With a zero factory result it enters `4A4A14`, restores
the native frame and returns 1. This exit leaves the existing callback
and request state intact.

The bounded fixture executes the descriptor preparation, emitted guard,
native setter and request marking. It checks that the zero result skips
the store and the request, and compares registers and writes with stock
on the live route. The factory, clock and final transport are supplied
services. Callback execution and actual scan results remain outside
the fixture.

### Context reads at `4AF958`, `4AFC74` and `4CF1F4`

The `remove_song` wrapper `4AF8C0` saves the factory result in S2 and
then reads H+58. The local guard keeps the save and sends a zero result
to the existing validation exit at `4AFB54`. This exit returns 0 before
the context allocation and UI updates. The sole encoded caller at
`4B9884` returns 1 through its own epilogue.

The `settings_color` wrapper `4CF180` saves H in S0 before the same
read. With a zero H, the local guard takes `4CF20C` with S0=0, and the
sole encoded caller at `4C84B0` returns 1 through `4C82FC`. The live
route preserves the cached-context branch and the allocation branch,
including the H+58 store in its delay at `4CF24C`.

The emitted-code fixtures execute the two upper calls and both native
wrapper epilogues for zero results. For live results they compare
registers and writes through the empty and populated context branches.
The color cases also cover allocator failure through return and success
through publication. The model supplies the factory, view lookup and
allocation outcomes. Later UI updates and computed callers are outside
this check.

The `loading` wrapper `4AFBE0` has a local return-zero exit at
`4AFCAC`. Its live path may copy caller-owned data into a new context
before returning. Callers at `4A7328` and `4A79AC` then free their
original temporary buffers. The latter returns 1 explicitly; the former
can propagate V0 through the free(NULL) leaf when its temporary is zero.
The `4AFDD8` route originates in the completion of an existing
`remove_song` operation and subsequently uses its own saved view and
old context. It asks the saved view for its list count, then looks for
a record whose +4 field equals 1. On a match it frees the current old
H+58 and clears the field. An empty list or a scan without a match
retains the source pointer.

The local guard at `4AFC7C` keeps the save of H in S1. With a live H it
replays the H+58 load and resumes at `4AFC84`; with a zero H it takes
the native exit at `4AFCAC`. The fixture executes the emitted transition
through all three known caller continuations and compares it with live
creation and the native second-lookup miss.
The old completion has the same release decision in all three cases.
With a newly created loading dialog, the wrapper copies the source fields,
UTF-16 path and view name to a distinct context before publishing it.
It also registers `4AEA80` and `4ADBE0`. A reused live dialog returns H
with its existing context and callbacks intact. Both zero-return cases leave
the loading continuation absent. The two temporary-buffer callers
likewise execute their native free calls for either wrapper result.
The fixtures supply the resolved view, factory, allocator and raw services.
The pending operation's later execution and any retry remain separate.

### Update-check dialog at `4D5010`

The `4D4FA0` wrapper calls `454BA0(4, 1)` before the factory.
That call writes pending status to `B8927C`. The initializer
`4D4CC0` registers `4D4D00` as a 200-ms timer. The registration
stores its function and context for later dispatch. The timer reads
the pending status through `454B80(4)`. The live wrapper clears
the progress counter at `B8BAA4`, posts an eight-byte worker record
`(4, mode)` on the `B89250` ring and clears owner+208.

The local guard moves the arm call past the factory result. It keeps
the descriptor clear at `4D4FF4` and the handle save at `4D5018`.
With H zero it takes the native return at `4D5048`, preserving the
prior status, progress counter and owner field. With H live it arms
status and rejoins `4D5020` before the counter clear and worker post.
The three encoded upper callers at `453CF8`, `4CBEEC` and
`4D732C` return 0, 1 and 1 respectively, regardless of H.

The fixture supplies the factory result and runs the native initializer,
timer registration and queue write for both live modes. It compares the
timer record, worker message and final state with stock. The refusal
cases start with idle, pending and terminal status values and keep them.
The check covers the selected UI invocation. Independent worker writes,
later timer execution and recovery from a rejected live worker post
remain outside this fixture.

### Volume dialog at `50506C`

The `505000` wrapper clears the owner's +208 before calling the factory
for `volume`. Its post-factory pair at `505074` saves H in S1 and reads
H+58. The local guard retains the save and takes the native return-zero
exit at `5050A8` for H=0. The earlier +208 clear still executes, and
the later +170 activation store is skipped.

The dispatcher `43C360` checks zero at `43C3A4` before using the dialog
on one branch and forwards the wrapper result on the other branch.
The known direct dispatcher callers both replace that value.
`43C530` loads the old state and `4E106C` sets 1. The fixture executes
both dispatcher branches through both upper continuations.

For a live dialog, the cached-context path returns H and sets owner+170
as before. The empty-context case executes the native 12-byte
allocation path, reads properties 17 and 4 and publishes the new
context at `5050F8`. The fixture compares registers and writes with
stock through publication. It supplies the factory, lookup and allocator
outcomes, and ends the fresh-context comparison before the later UI
updates.

### Text reader progress dialog at `5276B0`

The `527620` wrapper allocates a four-byte progress value before the
`book_percent` factory call. The original call delay puts the pointer
in descriptor +0C. The factory can copy it to the provisional dialog's
+4C before loading resources. Its checked failure exits precede
registration at `47D388` and the initializer at `47D3A0`. The resource
failure path destroys the lock and releases the provisional dialog.
The missing-widget branch passes the provisional dialog to the raw
deallocator. These branches do not call the descriptor destructor or
release the separate progress allocation.

The local redirect at `5276B8` preserves the return-address load.
With a live dialog, the original store hands the progress pointer to
H+58. The destructor at `527120` later reads that field and releases it
if nonzero. With a zero dialog result, the guard skips the store,
releases a nonzero progress pointer through the paired deallocator at
`466A80` and rejoins the native epilogue with V0 zero. The sole encoded
caller at `4C1B78` replaces either wrapper result with 1. Its handler
checks that the active widget is `vg_listview_book`, which belongs to
the text reader.

The fixture executes the complete wrapper, the native allocator and
deallocator wrappers, the sole encoded caller and the normal destructor.
It covers all four combinations of progress allocation and dialog result.
One case executes the native factory through a supplied resource-load
failure and observes separate releases for the provisional dialog and
progress value. The model supplies raw heap, resource and lock services
and treats the progress value as raw floating-point bits.

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
The 23 `47D180` propagated records still require downstream review. The
`47D960` follow-up below traces known consumers for its 27 propagated records
and records the remaining dynamic obligations.

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

## Library provenance and consumers above the D960 wrappers

The pinned ELF relocations and symbol versions identify the two import
frontiers. `A5BC68` dispatches `memset@GLIBC_2.0` from `libc.so.6` for eight
direct continuation records. `A5B968` dispatches
`pthread_mutex_lock@GLIBC_2.0` from `libpthread.so.0` for ten. The two
file-backed GOT entries point to the resolver at `A5B0C0`. The relocation,
version and provider establish the linked interface. The resolved library
body and its incoming V0 handling require the corresponding MIPS binaries.

The initial local check covered the preserved 1.4 import, the nearby 1.3 dump and
the pre-update backup. The 1.3 dump contains player executables, data and
init scripts. The local `boot.img` ramdisk contains Android AArch64 libc
files and `dtbo.img` has an Android DT table header. A matching RS2 1.4
library body was absent from the inspected material.

Six propagated sites in `5066C0`, `507440`, `50A600` and `50C760` have a
concrete input-dialog consumer. Their registrations supply a callback at
descriptor+310 to `5061E0`, which copies it to dialog state+D8. The resource
table contains `506340`. With that registration, `506368` calls the selected
wrapper and `506378` overwrites its return with 1. The outer frame is restored
without reading the callback result. The bounded fixture executes the actual
getter, dispatcher and six native factory-call/return tails with both result
values. It supplies the wrapper frame and already-bound widget state.

Six more sites in `4D4D00` and `4D5260` reach a timer consumer. `4738A0`
stores the registered function and context. The pump calls it at `47362C`.
On continued iteration the pump overwrites V0 at `473604` before another
callback. If the value survives the pump return, its two encoded direct
callers load V0 from old U+134 at `43C9EC` and `43CAA4`. This closes result
use along the demonstrated timer route, with computed aliases outside it.

The remaining ten sites have identified confirmation, input-dialog and
direct-return consumers. `51CCC0` and `5322E0` are registered at dialog
state+10. Their handlers overwrite the callback result at `50C1C4` and
`535664`. Both encoded callers of `5257A0` replace V0 at `525EA0` or `525D60`.
`52BEC0` has two encoded callers. One overwrites V0 at `52C7A0`. The other
returns through `52BF20`, whose registered input-dialog consumer overwrites
the result at `506378`. Two additional factory tails in `52BF20` reach
the same consumer.

Five sites in `4350E0`, `4AEA80` and `4AEC60` reach a completion consumer.
Their descriptor registrations reach H+74 through `47D180`. The known
completion handler calls H+74 at `47C7C8`, then `47AA20` reaches imported
`memset` before a definite V0 overwrite. The completion handler sets zero
later at `47C810`. The resolved binding checked below supplies the missing
library prefix for this known route.

For the four conditional sites `435168`, `4351DC`, `4AEB74` and `4AEBD4`,
the wrapper entry checks for a nonzero old H+58 before reaching the factory.
The propagation case requires a later reload of zero. A native nonzero
reload reaches `466A90`, overwriting V0 through the old allocation header.
The checked wrapper instructions have no explicit H+58 clear before these
factory calls. A refusal that skips the factory body requires a separate
explanation for the changed field. Earlier bounded tests supply the zero
post-call state and establish what happens from there.

The follow-up covers all 27 propagated sites. The known continuations
overwrite the result for 22 sites, and five retain it at the import frontier.
Their direct classification stays `propagated` because their own wrappers
return the factory value. The higher-level evidence concerns the identified
registrations and continuations. Runtime binding and all possible consumers
still require separate evidence.

## Observed RS2 1.4 import bindings

The running stock 1.4 executable had the expected SHA-256 prefix `0fedb30f`.
Its process mappings identified `/lib/libc-2.16.so` and
`/lib/libpthread-2.16.so`. The two copies in
`artifacts/rs2_14_import_libraries_20261106` match the device SHA-256 hashes
recorded in the D960 manifest. Two four-byte reads captured the live GOT
targets. Both addresses match the corresponding `GLIBC_2.0` exports in the
copied MIPS ELF32 files.

| Import | Direct sites | Live GOT target | First overwrite in library |
| --- | ---: | --- | --- |
| `memset` | 8 | `770E81F0` | `871F8`, `ADDU V0,A0,zero` |
| `pthread_mutex_lock` | 10 | `771E0F50` | `9F74`, `LW V0,+12(A0)` |

`memset` starts at `871F0`. Its `BNE` at `871F4` uses the ordinary delay slot
at `871F8` for both branch outcomes. Each caller supplies an independent
buffer, fill byte zero and fixed length. The factory value dies before the
first buffer write.

`pthread_mutex_lock` starts at `9F50`. Its straight prefix computes GP from
T9 and saves registers. The first V0 operation loads the old mutex field
at `9F74`, before any branch or call. The player supplies the old context's
mutex from +10. Its separate null-old-context path overwrites V0 locally.
The library prefix assumes a mapped frame and readable mutex storage.
Mutex initialization, lifetime and lock progress remain separate premises.

All 18 direct import continuations discard the factory value under the
observed resolved bindings. In that view, D960 has 113 discarded sites and
10 unresolved computed sites. The source-only table retains the original
import frontiers for readers without the captures. The five known upper
completion continuations also lose the value in the resolved `memset`.
Their direct wrapper records remain `propagated`, with the earlier field
conditions intact. The observation concerns the sampled stock process and
the resolved targets. Lazy resolution and other runtime bindings remain open.

### Selected lock callback at `43B150`

With the `439A6C` assignment of `437D20` to the old object's +274 slot,
factory call `45211C` reaches that method through `43B240` and `43B120`.
The method passes the old object's +13C mutex to `466DA0`. The native PLT
loads the sampled lock target from `A6FA58` and enters the captured library
with the factory result still in V0. At `9F74` the library loads V0 from
the mutex's +C field.

The bounded test executes the assignment, the native caller chain and PLT,
and the captured library prefix through that load with factory results zero
and nonzero. Both reach the same overwrite from the independently supplied
mutex. This conditional result requires the selected callback, the resolved
import and readable mutex storage. The actual callback at a live call and
the remainder of the mutex operation are outside this check.

Run the optional capture check from the repository root.

```powershell
python -B scripts/factory_null_audit.py --resolved-imports
```

The optional check matches both library hashes, the RX mapping arithmetic,
dynamic symbol entries and prefix words. It checks coverage of all 18 direct
sites and five known upper paths. The ordinary source report works with the
pinned player image and source manifests. The two library copies are local
artifacts excluded by Git.

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
