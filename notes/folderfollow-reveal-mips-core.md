# Uninstalled MIPS geometry core

2026-10-06. Implemented `scripts/folderfollow_reveal_mips.py`, a scalar-only
MIPS32/O32 leaf function for the arithmetic in the reveal model. This is a
component, **not a firmware patch or deployable image**. No ELF bytes, hooks,
device files, launcher or test flags were changed; no hardware test occurred.

`build_geometry()` returns 216 bytes (54 little-endian instruction words):

```text
31707143564916f3f192ba656d8a522cd5e86cc3b013d3c741478bb7b14f287b
```

The emitter returns bytes in memory. It has no installer or file-writing CLI.
It reuses the existing assembler for label resolution but emits only relative
branches, so the assembler's bookkeeping base does not bind the result to an
address. No cave placement or space reservation is asserted.

## Calling contract

| Input/output | Meaning |
| --- | --- |
| a0 | Absolute row index, not cue number |
| a1 | Verified complete folder count, 1..512 |
| a2 | Positive row pitch |
| a3 | Viewport height, at least one row pitch |
| word at entry sp+16 | Current signed content y |
| v0 | Nonnegative target y, or -1 for invalid/unsupported geometry |

Unchanged target y means already fully visible and must not trigger a setter.
The function preserves a0..a3, s0..s7, fp, gp, sp and ra. It clobbers v0,
t0..t5 and HI/LO (volatile under this function's O32 call contract). Any future
inline hook still needs its own live-register/HI/LO preservation contract;
these bytes must not simply be spliced into arbitrary stock instructions.

Only memory access is `lw t0,16(sp)`. There are no writes, external calls,
object-pointer dereferences, global/BSS references or absolute jumps.
Every branch and return delay slot is a nop.

## Bounds and arithmetic

Reject count outside 1..512, invalid row, nonpositive pitch, height smaller
than pitch and negative y. Use unsigned 64-bit multiplication of positive
count/pitch: reject nonzero HI and a signed-negative LO before using extent.
Then require y in `0..max(0,extent-height)`, and a representable y+height.

Checked extent and row<count make row*pitch and (row+1)*pitch safe. If the row
is above the viewport, target its top; if below, target bottom-height;
otherwise return the current y. The prior checks mathematically keep either
changed target within the bounds, so no final saturation instruction is
needed. This is equivalent to the model's explicit clamp, not reliance on
the stock setter's flags or raw extent.

The component does not decide whether a track changed, resolve a cue to a
row, verify fill completion, inspect active gesture state or retain any view.
Those remain caller prerequisites. Passing total count alone from telemetry
does not meet them.

## Verification

`test_folderfollow_reveal_mips.py` independently interprets the emitted bytes
and compares results with `minimal_reveal` from the host model. Seven test
methods cover 16,074 exhaustive small-geometry cases, 2,000 deterministic
larger valid/boundary cases, 2,000 arbitrary signed-word cases, concrete
13-row examples, overflow/overscroll boundaries, ABI preservation and four
relocation bases. The structural test allows only the actual instruction
classes used by this component, excluding even unexecuted unknown stores,
calls, coprocessors and absolute jumps.

Independent review found no arithmetic, opcode, delay-slot or ABI defect in
the current component. Its suggestion to replace a partial instruction deny
list with a strict allowlist was implemented. The interpreter does not model
processor timing/interlocks, stock callers, threads, hardware exceptions or
object lifetime; this is not evidence of device safety or a completed fix.

Final full repository validation for this continuation: 261 tests pass with
no skips, including 7 geometry-core, 56 reveal-model and 15 static-contract
tests. All 69 Python scripts compile; whitespace checks pass.

See [ownership constraints](folderfollow-reveal-ownership.md) and the
[UI/gesture dispatch follow-up](folderfollow-reveal-dispatch.md) before any
attempt to write a live adapter.
