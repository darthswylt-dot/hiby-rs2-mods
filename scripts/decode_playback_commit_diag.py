#!/usr/bin/env python3
"""Decode PCMT records written by the playback media-item commit diagnostic."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path


MAGIC = b"PCMT"
RECORD_SIZE = 0x680
PATH_BYTES = 0x208
PATHS = (
    ("selected", 0x040),
    ("global", 0x248),
    ("source", 0x450),
)


def u32(record: bytes, offset: int) -> int:
    return struct.unpack_from("<I", record, offset)[0]


def pointer(value: int) -> str:
    return "NULL" if value == 0 else f"0x{value:08x}"


def utf16(record: bytes, offset: int) -> str:
    raw = record[offset:offset + PATH_BYTES]
    end = next(
        (i for i in range(0, len(raw), 2) if raw[i:i + 2] == b"\0\0"),
        len(raw),
    )
    return raw[:end].decode("utf-16le", errors="replace")


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
        if u32(record, 0x04) != 1 or u32(record, 0x08) != RECORD_SIZE:
            raise SystemExit(f"unsupported record header at index {index}")
        site = {1: "same-file", 2: "general"}.get(
            u32(record, 0x10), f"unknown-{u32(record, 0x10)}"
        )
        phase = {1: "before", 2: "after"}.get(
            u32(record, 0x0C), f"unknown-{u32(record, 0x0C)}"
        )
        print(
            f"record={index} site={site} phase={phase} "
            f"caller={pointer(u32(record, 0x14))} size={u32(record, 0x20):#x}"
        )
        print(
            f"  dest={pointer(u32(record, 0x18))} "
            f"selected={pointer(u32(record, 0x1C))} "
            f"source={pointer(u32(record, 0x24))} "
            f"mode={u32(record, 0x28)} position_ms={u32(record, 0x2C)} "
            f"field_414={u32(record, 0x30):#x} field_730={u32(record, 0x34):#x}"
        )
        print(
            f"  selected_id={u32(record, 0x38):#x} "
            f"global_id={u32(record, 0x3C):#x}"
        )
        for name, offset in PATHS:
            print(f"  {name}_path={utf16(record, offset)!r}")


if __name__ == "__main__":
    main()
