# Reveal integration: special reset and raw-path scope

2026-10-07. Bounded local inspection of reference `02fd1dd1...`, with the
full source hash and size checked by `test_folderfollow_reveal_scope_contract.py`.
No device access, binary patch, or production hook. This narrows the
[dispatch](folderfollow-reveal-dispatch.md) and [ownership](folderfollow-reveal-ownership.md)
notes; it does not establish universal UI ownership.

## The two special reset sites are selected by path, not view type

In `0x4ACBC0(V)`, `s0=V`, `s1=V+0x3DD8` (UTF-16 scope string), and
`s2=*(V+0xD4)` (controller). Neither of these reset branches tests V+0x40:

| Reset call | Required path condition | Immediate predecessor |
| --- | --- | --- |
| `0x4ACE20` | No `tidal` substring; prefix `music_search_` | `0x4ACD5C` bounded comparison, zero branch at `0x4ACD64` |
| `0x4ACE0C` | No `tidal` substring; not the preceding search prefix; prefix `recent` | `0x4ACD7C` bounded comparison, zero branch at `0x4ACD84`; `0x4B8D60(*(V+0x3B9C))` at `0x4ACE00` |

Both call `0x491240(controller,V)`, then return zero. The literals are
`0x921230 = L"tidal"`, `0x921194 = L"music_search_"` (13 code units),
and `0x941654 = L"recent"` (6 code units). `0x41FE00` supplies the literal
length; `0x41FCE0` is a case-sensitive UTF-16 bounded comparison. These are
prefix tests, not exact equality or a path-component comparison.

The earlier `tidal` test calls `0x41FEC0` at `0x4ACC54` for a populated
primary list or `0x4ACD0C` for a null/empty list. This helper is a UTF-16
substring search, returning a match pointer or zero (`0x41FEC0..0x41FF40`).
A match uses a different update/destruction branch. A missing or empty list
does NOT prevent either special reset when the path prefix matches.

Consequently these sites are not ordinary physical-folder resets when the
scope begins with its mount prefix, rather than either pseudo-scope prefix.
They cannot be excluded merely by `type==2`: the function has no such gate.
For a non-special, non-Tidal scope, the same function instead calls
`0x493AC0(V)` at `0x4ACD8C`; when the original list was nonempty it recreates
the view through `0x491E80` at `0x4ACDA4`, and later restores bounded offset
via `0x8B43C0` at `0x4ACDF0`. Thus excluding the two reset sites does not
exclude the containing operation from Files lifetime/scope changes.

## Concrete callers and completion dispatch

The found direct entry routes to `0x4ACBC0` are:

1. `0x4AD880(V,descriptor,mode)` calls it at `0x4AD8D8`, after
   `0x4AD1E0` and `0x4ACA40`. Its two direct callers are `0x450D9C` and
   `0x4AEEE0`.
2. `0x4AD860` tail-jumps to it. The direct caller at `0x4AEC1C` belongs
   to `0x4AEA80` and resolves the view by the operation's stored name.

All three outer callbacks are supplied in callback-vector slot +4 to
`0x47D180`, which stores that slot into dialog D+0x74 at `0x47D24C..250`:

| Callback | Registration | View passed to the operation |
| --- | --- | --- |
| `0x450D60` | `0x45334C..370`, `data_dealing` dialog | Active view resolved by `0x4E5680` at `0x450D84` |
| `0x4AEC60` | `0x4AF1F4..234`, creation at `0x4AF274`, `remove_song` dialog | Active view resolved at `0x4AECFC`; ordinary branch calls `0x4AD880` at `0x4AEEE0` |
| `0x4AEA80` | `0x4AFBF4..BF8`, creation at `0x4AFC74`, `loading` dialog | For operation+8==4 (`0x4AEAD8..DC`), exact stored name resolved at `0x4AEBEC`, then `0x4AEC1C` |

The first dialog's creation handler `0x453320` is queued event **0x138**:
table pair `0x926D2C=0x138`, `0x926D30=0x453320`. The callback runs later,
not inline at registration.

The normal completion route is concrete and serial in one music-loop
invocation:

`0x43C9CC -> 0x47CC20 -> D+0x6C (0x47C740) -> D+0x74`, then the loop
reaches timer pump `0x43C9E4 -> 0x473560`.

`0x47CC20` checks D+0x1C at `0x47CC78..7C` and calls D+0x6C at
`0x47CC88..90`. Construction installs `0x47C740` in D+0x6C at
`0x47D380..38C`. In `0x47C740`, the D+0x0C lock/unlock/destroy at
`0x47C77C..790` waits for the dialog worker; then D+0x10 is acquired at
`0x47C794..798`, D+0x74 is called at `0x47C7B8..7CC`, and D+0x10 is
released at `0x47C800..804`. **This is the dialog's mutex, not Files worker
T+0x10.** No direct T+0x10 acquisition occurs in the inspected operation
wrappers or `0x4ACBC0`.

The dialog really has a separate worker: `0x47C8C0` creates it with
entry `0x47C580`. That worker calls D+0x78 at `0x47C62C`, not D+0x74;
on exit it marks D+0x1C at `0x47C6D4`. Do not misattribute the three
completion callbacks to that worker.

There is also a synchronous close-by-name route:
`0x47D060 -> 0x47CF80` at `0x47D07C`, then D+0x6C at `0x47D004`.
`0x47D180` passes `0x47D060` to `0x43AF00` at `0x47D310..324`;
that registration copies it through the +0x10 callback field into the
controller object-list record (+0x18) at `0x438A30..34`. This pass does not
audit every consumer of that callback record. The normal completion route
is therefore a positive UI ordering anchor, not proof that every possible
close/reset invocation is uniquely owned by that loop.

## Raw descriptor rewrite: path-specific, but type 2 is not excluded

At `0x499D4C..58`, the code computes unsigned `(V.type-3)<42`. For
Files type 2 this is false, so the branch goes directly to `0x499DB0`,
not around the string guards. Those guards call `0x41FEC0` with:

- `0x942220 = L"music_search_albums"`; nonzero at `0x499DBC` enters rewrite.
- `0x942248 = L"music_search_artists"`; zero at `0x499DD4` skips rewrite.

On a match it copies the scope, calls `0x6F44C0` at `0x499E1C`, fetches
`V+0x64` row `(absolute_index % P+0x1D4)` through +0x2C at `0x499E30`,
and, if nonnull, copies the local descriptor path into raw row+4 at
`0x499E48` and terminates raw row+0x20A at `0x499E50`.

Without either substring, `0x49A0C0..E4` can change the stack-local
descriptor before joining `0x499E54`, but does not reach that raw getter
or raw path write. Normal physical Files scopes without the two markers
therefore avoid this particular cache mutation. However a Files path such
as `/mnt/sdcard/music_search_albums/Album/*` contains the marker and is
not excluded by the type guard. This is a control-flow edge, not a claim
that this unusual path was observed on hardware. Calling the raw rewrite
"non-Files only" would be stronger than the source supports.

## Narrow result

The special reset conditions and the ordinary dialog-completion ownership
route are now anchored. Remaining scope work is specifically the consumer
of the registered close callback (+0x18 in the controller object list),
plus previously known rebinding/worker/teardown contracts. These findings
neither retain V/T/C nor certify a filled cache; in particular count==total
still does not prove SQL terminal 101. The companion tests preserve static
strings, branches and callback ordering only.
