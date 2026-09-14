# Source-object cue/path static trace

This note applies to the firmware 1.4 `hiby_player` with SHA-256
`0fedb30f91937eafb5baaf3c75422cdbde04a62fe8bac8eca3c7a88bb761da0e`.
All addresses are virtual addresses in that executable.

## Result

The source object at global pointer `0xADD360` contains:

| Offset | Property | Meaning |
| --- | ---: | --- |
| `+0x24` | 30 | Small source/mode selector, constrained to values below 3 by its setter. |
| `+0x28` | 32 | Inline UTF-16 playback-path buffer, 260 code units / `0x208` bytes. |
| `+0x230` | 31 | Absolute playback position in the backing audio file, in milliseconds, captured when the source descriptor is finalized. |

`+0x230` is therefore neither a pointer nor a continuously updated elapsed-time
counter. It is a position seed/snapshot used together with the backing-file
path to resolve the current media/cue row.

## Property dispatcher proof

The setter at `0x422BA0` dispatches property IDs through the 114-entry jump
table at `0x92042C`. The corresponding getter at `0x423980` uses the table at
`0x9205F4`.

The relevant consecutive cases are:

```text
property 30 setter -> 0x422F7C -> source+0x24
property 31 setter -> 0x422F90 -> source+0x230
property 32 setter -> 0x422F98 -> UTF-16 copy to source+0x28, 260 units

property 30 getter -> 0x423AB8 -> load source+0x24
property 31 getter -> 0x423AC0 -> load source+0x230
property 32 getter -> 0x423AC8 -> return source+0x28
```

Initialization at `0x423E1C-0x423E28` zeros the mode, first UTF-16 path code
unit, position, and following scalar:

```text
sw zero, 0x24(source)
sh zero, 0x28(source)
sw zero, 0x230(source)
sw zero, 0x234(source)
```

This also proves that the old `02fd...` diagnostic crossed a field boundary:
the path occupies `+0x28..+0x22F`, and `+0x230` is the next 32-bit scalar.

## The only normal writer of property 31

There are only two direct calls that set property 31, at `0x42BC30` and
`0x42BC50`. Both belong to the source-finalization helper at `0x42BBE0`.
That helper first copies global UTF-16 buffer `0xADD46C` into property 32 and
then selects the position value as follows:

```text
source.path = UTF16[0xADD46C]

if source.mode == 2 or source.field_730 != 0:
    value = music_player.current_time       # music_player+0x20
    if value > 0:
        source.position = value
        return

source.position = music_player.start_offset # music_player+0x51C
```

The music-player object is the global object at `0xADD368`; `0x42C460`
returns its address directly.

## Timing-field semantics and units

The field at `music_player+0x20` (`0xADD388`) is written from argument `a2` of
event `0x500` in the player event callback at `0x42B2C0`. A nearby stock log at
`0x42C114` labels the value `cur_time = %d`. It is the absolute current decoder
position in the backing file.

The fallback field at `music_player+0x51C` is the backing-file start offset of
the selected media/cue row:

- it is initialized to `-1` at `0x4EAAC8`;
- media parsing writes it at `0x67AD90`;
- `0x444260` returns `current_time - start_offset`;
- `0x4450E0` adds `start_offset` before seeking;
- `0x447A24` subtracts it before converting/reporting relative time.

The media database confirms millisecond units. Hardware values correlate as
follows:

| Playback observation | `source+0x230` | Database correlation |
| --- | ---: | --- |
| Roots in Russia | `0` | Ordinary file/start at zero. |
| Evil Has No Boundaries | `191332` (`0x2EB64`) | 132 ms after its `end_time=191200`; a same-backing-file transition selected live `current_time`. |
| Later Show No Mercy cue | `375360` (`0x5BA40`) | 13,867 ms after Die By The Sword `begin_time=361493`; again a live absolute position. |
| Sleep Part I | `426` (`0x1AA`) | Exactly its `begin_time=426`; opening a new backing file selected `start_offset`. |

The exact stable name for `+0x230` is therefore
`source_backing_file_position_ms`. For cue tracks it is an absolute offset in
the shared image/FLAC, not cue-relative elapsed time. Its value may be a live
position just after a boundary or the selected row's `begin_time`, depending
on the source-mode/reuse branch.

## Playback-path field and consumers

The actual neighboring backing-file path is the inline UTF-16 buffer at
`source+0x28`, exposed as property 32. The normal finalization path fills it
from global buffer `0xADD46C` immediately before writing property 31.

Direct property-32 readers occur at `0x476948`, `0x4E4C24`, and `0x4E5084`.
The path-recovery routine `0x4E4B80` is the sole direct reader of property 31:

```text
0x4E4C24: path = get_property(32)      # source+0x28
0x4E4C30: position = get_property(31)  # source+0x230
0x4E4C50: call 0x4328C0(media_id, position, 0x40000)
```

`0x4328C0` uses the path/media state and absolute position to select or rebuild
the current media/cue row. It is not a passive lookup. This explains both why
`0x4E4B80` can recover the correct folder in some transition states and why it
can return `-1` or consume/synchronize state when called as telemetry.

For the next safe diagnostic, copy `source+0x28` directly as a bounded
260-code-unit UTF-16 string. Record `source+0x230` only as a `uint32_t` position
and do not call `0x4E4B80` merely to observe the path.

## Reproduction helper

`scripts/mips_static_trace.py` is a dependency-free ELF32/MIPS inspection
helper used to dump these routines, decode both property jump tables, locate
direct property calls, and enumerate immediate/address references. It does not
modify the firmware binary.
