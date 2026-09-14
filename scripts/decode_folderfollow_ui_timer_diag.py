#!/usr/bin/env python3
"""Decode passive Folder View UI-timer diagnostic records."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path


MAGIC = b"FTMR"
RECORD_SIZE = 0x4A0


def u32(record: bytes, offset: int) -> int:
    return struct.unpack_from("<I", record, offset)[0]


def signed32(value: int) -> int:
    return value - 0x1_0000_0000 if value & 0x8000_0000 else value


def ptr(value: int) -> str:
    return "NULL" if value == 0 else f"0x{value:08x}"


def utf16(record: bytes, offset: int, size: int = 0x208) -> str:
    raw = record[offset:offset + size]
    end = next((i for i in range(0, len(raw) - 1, 2) if raw[i:i + 2] == b"\0\0"), len(raw))
    return raw[:end].decode("utf-16le", "replace")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("log", type=Path)
    args = parser.parse_args()
    data = args.log.read_bytes()
    if len(data) % RECORD_SIZE:
        raise SystemExit(f"truncated log: {len(data)} bytes is not a multiple of {RECORD_SIZE}")

    for index in range(len(data) // RECORD_SIZE):
        record = data[index * RECORD_SIZE:(index + 1) * RECORD_SIZE]
        if record[:4] != MAGIC:
            raise SystemExit(f"bad magic in record {index}: {record[:4]!r}")
        print(f"record={index}")
        print(f"  version={u32(record, 4)} size={u32(record, 8)} stage_bits=0x{u32(record, 0x0c):02x}")
        print(f"  time={u32(record, 0x10)}.{u32(record, 0x14):09d}")
        print(f"  caller_ra={ptr(u32(record, 0x18))} original_sp={ptr(u32(record, 0x1c))}")
        print(f"  object={ptr(u32(record, 0x20))} timer_arg={ptr(u32(record, 0x24))} original_return={signed32(u32(record, 0x28))}")
        print("  object_fields=" + ", ".join(
            f"+{field:02x}:{ptr(u32(record, record_offset))}"
            for field, record_offset in ((0x20,0x2c),(0x3c,0x30),(0x40,0x34),(0x48,0x38),(0x50,0x3c),(0x54,0x40),(0x58,0x44),(0x5c,0x48))
        ))
        print(f"  explorer_fields=+150:{ptr(u32(record,0x4c))}, +298:{ptr(u32(record,0x50))}, +29c:{ptr(u32(record,0x54))}")
        print(f"  state_words={signed32(u32(record,0x58))}, {signed32(u32(record,0x5c))}, {signed32(u32(record,0x60))}")
        print(f"  property24_path_source={ptr(u32(record,0x64))} current_view={ptr(u32(record,0x68))}")
        print(f"  explorer_view_count={signed32(u32(record,0x6c))} found_view={ptr(u32(record,0x70))}")
        print(f"  property24_path={utf16(record, PLAYBACK_PATH_OFFSET)!r}")
        print(f"  folder_view_path={utf16(record, FOLDER_PATH_OFFSET)!r}")


PLAYBACK_PATH_OFFSET = 0x80
FOLDER_PATH_OFFSET = 0x288


if __name__ == "__main__":
    main()
