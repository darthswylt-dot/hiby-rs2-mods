# Reveal cancellation: recognized contact and no-animation release

2026-10-07. Bounded static audit of reference `02fd1dd1...`; full hash and
size are required by `test_folderfollow_reveal_contact_contract.py`. No
device access or firmware change. This narrows the [dispatch audit](folderfollow-reveal-dispatch.md).

## Contact is separate from capture and animation

With H=*(U+0x28), G=*(H+0x08) is the input converter; A=*(H+0x10) is
capture/animation state. 0x8B1AA0 calls 0x8B4CC0(G,input,0x8B16A0,H)
at 0x8B1AF4. G+0 is software-recognized contact, not a view direction flag.

| Input in a normal stream | Contact state | Output |
| --- | --- | --- |
| First raw 2, G+0=0 | Set to 1 at 0x8B4E38 | Event 4 |
| Raw 2, changed coordinates | Remains 1 | Event 6, then recognizer may emit 9 |
| Raw 2, unchanged coordinates | Remains 1 | No new event, 0x8B4E94..B0 |
| Raw 3, G+0 nonzero | Cleared at 0x8B4E84 **before callbacks** | Event 5, then recognizer result |

The release source is input type 1/code 0x14A/value 0 in parser 0x4725A0
(checks 0x472778..78C, raw 3 publication 0x4727AC..B4). UI loop 0x43CA2C
passes input to 0x8B1AA0. These statements concern the inspected normal
software path, not every physical sensor or malformed-input condition.

After the converter sends event 5, recognizer 0x8B5480 can produce a short
tap/event 7 (0x8B5510..44), a movement release/event 10 (0x8B599C..59CC),
or **no new event** after an already-recognized long press. The last path
branches at 0x8B5508, clears recognizer+0x44 at 0x8B56DC and returns zero
at 0x8B5700. G+0 was already cleared in every normal variant. Waiting for
event 100 to clear a contact latch would therefore leave it stuck.

## What does not establish release

A+0 is the captured object, set at 0x8B1924; ordinary release does not clear
it. Object destruction sends event 101 at 0x8B07E4. The corresponding
0x8B1B94..1C0C path clears A+0/A+4 and conditionally A+8, **not G+0**.
Animation abort 0x8B1EE0 clears animation fields, again not contact. H
destruction frees G via 0x8B4C60 at 0x8B11BC without a proven prior contact
cancel callback. Neither capture nor animation-object presence substitutes
for contact, and G cannot be retained across H destruction/replacement.

## Remaining limits

- Parser ignores BTN_TOUCH-down with nonzero value. Raw 2 is emitted after
  coordinate updates/sync (0x4726D4..710). G is not an instantaneous physical
  contact reading, and cannot cover the interval before accepted input.
- Orphan raw 3 while G+0=0 takes the shared first-contact branch **before**
  checking for raw 3, setting G+0=1/event 4. No recovery from lost or malformed
  input was established. Do not silently convert uncertainty into idle.
- For an owned, coherent, normally dispatched state, contact G+0, animation
  servicing A+0x0C and kinetic completion K+0x40 (K=*(A+0x10)) are separate
  inputs. Nonzero contact/servicing or unfinished kinetics must suppress reveal.
  Sampling these pointers safely still requires owner lifetime/serialization.
- Navigation, owner replacement and uncertain input must cancel pending work;
  these anchors do not establish coverage of every external abort/reset path.

Normal stationary release is now understood. No generic live `manual_active`
reader, input repair, latch hook or setter has been installed.
