#!/usr/bin/env python3
"""Decode FFSP records from the crash-resistant pointer diagnostic."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path


MAGIC = b"FFSP"
RECORD_SIZE = 0x100

STAGES = {
    0x0001: "target",
    0x0002: "source_before",
    0x0004: "context_before",
    0x0008: "explorer_before",
    0x0010: "current_view_before",
    0x0020: "folder_view_before",
    0x0040: "pre_complete",
    0x0080: "pre_write_full",
    0x0100: "callback_returned",
    0x0200: "source_after",
    0x0400: "context_after",
    0x0800: "explorer_after",
    0x1000: "current_view_after",
    0x2000: "folder_view_after",
    0x4000: "post_complete",
}


def u32(record: bytes, offset: int) -> int:
    return struct.unpack_from("<I", record, offset)[0]


def signed32(value: int) -> int:
    return value - 0x1_0000_0000 if value & 0x8000_0000 else value


def ptr(value: int) -> str:
    return "NULL" if value == 0 else f"0x{value:08x}"


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
        phase = u32(record, 0x0C)
        bits = u32(record, 0x10)
        names = ",".join(name for bit, name in STAGES.items() if bits & bit)
        print(f"record={index} phase={phase} stages={bits:#06x} [{names}]")
        print(
            f"  entry={u32(record, 0x18)}.{u32(record, 0x1C):09d} "
            f"exit={u32(record, 0x20)}.{u32(record, 0x24):09d}"
        )
        print(
            f"  caller={ptr(u32(record, 0x28))} sp={ptr(u32(record, 0x2C))} "
            + " ".join(
                f"a{arg}={ptr(u32(record, 0x30 + arg * 4))}" for arg in range(4)
            )
        )
        print(
            f"  source_before={ptr(u32(record, 0x40))} "
            f"+24={ptr(u32(record, 0x44))} +230={ptr(u32(record, 0x48))} "
            f"+414={ptr(u32(record, 0x4C))} +730={ptr(u32(record, 0x50))} "
            f"global={ptr(u32(record, 0x54))}"
        )
        print(
            f"  before=context:{ptr(u32(record, 0x58))} "
            f"explorer:{ptr(u32(record, 0x5C))} current:{ptr(u32(record, 0x60))} "
            f"folder:{ptr(u32(record, 0x64))} count:{signed32(u32(record, 0x68))} "
            f"state:{ptr(u32(record, 0x6C))} head:{ptr(u32(record, 0x70))} "
            f"tail:{ptr(u32(record, 0x74))}"
        )
        print(
            f"  callback_return={signed32(u32(record, 0x78))} "
            f"pre_write_return={signed32(u32(record, 0xAC))}"
        )
        print(
            f"  source_after={ptr(u32(record, 0x7C))} "
            f"+24={ptr(u32(record, 0x80))} +230={ptr(u32(record, 0x84))} "
            f"+414={ptr(u32(record, 0x88))} +730={ptr(u32(record, 0x8C))} "
            f"global={ptr(u32(record, 0x90))}"
        )
        print(
            f"  after=context:{ptr(u32(record, 0xB0))} "
            f"explorer:{ptr(u32(record, 0xB4))} current:{ptr(u32(record, 0x94))} "
            f"folder:{ptr(u32(record, 0x98))} count:{signed32(u32(record, 0x9C))} "
            f"state:{ptr(u32(record, 0xA0))} head:{ptr(u32(record, 0xA4))} "
            f"tail:{ptr(u32(record, 0xA8))}"
        )


if __name__ == "__main__":
    main()
