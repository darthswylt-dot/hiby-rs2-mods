#!/usr/bin/env python3
"""Decode FFRS records emitted by the recovered 02fd raw-state wrapper."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path


MAGIC = b"FFRS"
RECORD_SIZE = 0x1200

STAGE_BITS = {
    0x0001: "target_event",
    0x0002: "fixed_path_before_copied",
    0x0004: "source_object_before_present",
    0x0008: "source_pointer_path_before_present",
    0x0010: "player_context_present",
    0x0020: "explorer_present",
    0x0040: "current_view_before_present",
    0x0080: "folder_view_before_present",
    0x0100: "original_callback_returned",
    0x0200: "fixed_path_after_copied",
    0x0400: "source_object_after_present",
    0x0800: "source_pointer_path_after_present",
    0x1000: "current_view_after_present",
    0x2000: "folder_view_after_present",
}


def u32(record: bytes, offset: int) -> int:
    return struct.unpack_from("<I", record, offset)[0]


def signed32(value: int) -> int:
    return value - 0x1_0000_0000 if value & 0x8000_0000 else value


def ptr(value: int) -> str:
    return "NULL" if value == 0 else f"0x{value:08x}"


def utf16(record: bytes, offset: int, size: int = 0x208) -> str:
    raw = record[offset:offset + size]
    end = next(
        (index for index in range(0, len(raw) - 1, 2) if raw[index:index + 2] == b"\0\0"),
        len(raw),
    )
    return raw[:end].decode("utf-16le", "replace")


def stage_names(bits: int) -> str:
    names = [name for bit, name in STAGE_BITS.items() if bits & bit]
    unknown = bits & ~sum(STAGE_BITS)
    if unknown:
        names.append(f"unknown_{unknown:#x}")
    return ", ".join(names)


def print_source_fields(record: bytes, suffix: str, base: int) -> None:
    print(
        f"  source_fields_{suffix}="
        f"+24:{ptr(u32(record, base))} "
        f"+230:{ptr(u32(record, base + 4))} "
        f"+414:{ptr(u32(record, base + 8))} "
        f"+730:{ptr(u32(record, base + 12))}"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("log", type=Path)
    args = parser.parse_args()

    data = args.log.read_bytes()
    if len(data) % RECORD_SIZE:
        raise SystemExit(
            f"truncated log: {len(data)} bytes is not a multiple of {RECORD_SIZE}"
        )

    print(f"records={len(data) // RECORD_SIZE} bytes={len(data)}")
    for index in range(len(data) // RECORD_SIZE):
        record = data[index * RECORD_SIZE:(index + 1) * RECORD_SIZE]
        if record[:4] != MAGIC:
            raise SystemExit(f"bad magic in record {index}: {record[:4]!r}")
        if u32(record, 0x08) != RECORD_SIZE:
            raise SystemExit(
                f"bad size in record {index}: {u32(record, 0x08):#x}"
            )

        stages = u32(record, 0x0C)
        print(f"record={index}")
        print(
            f"  version={u32(record, 0x04)} size={u32(record, 0x08):#x} "
            f"stage_bits={stages:#06x}"
        )
        print(f"  stages={stage_names(stages)}")
        print(f"  entry_time={u32(record, 0x10)}.{u32(record, 0x14):09d}")
        print(f"  exit_time={u32(record, 0x18)}.{u32(record, 0x1C):09d}")
        print(
            f"  caller_ra={ptr(u32(record, 0x20))} "
            f"original_sp={ptr(u32(record, 0x24))}"
        )
        print(
            "  args="
            + ", ".join(
                f"a{arg}={ptr(u32(record, 0x28 + arg * 4))}" for arg in range(4)
            )
        )
        print(
            f"  source_object_before={ptr(u32(record, 0x38))} "
            f"fixed_source={ptr(u32(record, 0x3C))} "
            f"context={ptr(u32(record, 0x40))} "
            f"explorer={ptr(u32(record, 0x44))}"
        )
        print(
            f"  views_before=current:{ptr(u32(record, 0x48))} "
            f"folder:{ptr(u32(record, 0x4C))} count:{signed32(u32(record, 0x50))}"
        )
        print(
            f"  explorer_before=state:{ptr(u32(record, 0x54))} "
            f"head:{ptr(u32(record, 0x58))} tail:{ptr(u32(record, 0x5C))}"
        )
        print_source_fields(record, "before", 0x60)
        print(f"  original_return={signed32(u32(record, 0x70))}")
        print(
            f"  views_after=current:{ptr(u32(record, 0x74))} "
            f"folder:{ptr(u32(record, 0x78))} count:{signed32(u32(record, 0x7C))}"
        )
        print(
            f"  explorer_after=state:{ptr(u32(record, 0x80))} "
            f"head:{ptr(u32(record, 0x84))} tail:{ptr(u32(record, 0x88))}"
        )
        print_source_fields(record, "after", 0x8C)
        print(
            f"  source_object_after={ptr(u32(record, 0x9C))} "
            f"global_value_before={ptr(u32(record, 0xA0))} "
            f"global_value_after={ptr(u32(record, 0xA4))}"
        )
        for label, offset in (
            ("fixed_path_before", 0x100),
            ("source_inline_path_before", 0x308),
            ("source_pointer_path_before", 0x510),
            ("folder_view_path_before", 0x718),
            ("fixed_path_after", 0x920),
            ("source_inline_path_after", 0xB28),
            ("source_pointer_path_after", 0xD30),
            ("folder_view_path_after", 0xF38),
        ):
            print(f"  {label}={utf16(record, offset)!r}")


if __name__ == "__main__":
    main()
