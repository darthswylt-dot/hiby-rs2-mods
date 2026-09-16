#!/usr/bin/env python3
"""Decode passive VDEP records, emitting only changed view/path states."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

from build_folderfollow_view_depth_diag import (
    CURRENT_NAME_OFFSET, CURRENT_PATH_OFFSET, LAST_NAME_OFFSET,
    LAST_PATH_OFFSET, PLAYBACK_PATH_OFFSET, RECORD_SIZE,
)


def u32(record: bytes, offset: int) -> int:
    return struct.unpack_from("<I", record, offset)[0]


def ptr(value: int) -> str:
    return "NULL" if not value else f"0x{value:08x}"


def cstr(record: bytes, offset: int) -> str:
    return record[offset:offset + 0x40].split(b"\0", 1)[0].decode("ascii", "replace")


def u16str(record: bytes, offset: int) -> str:
    raw = record[offset:offset + 0x208]
    end = next((i for i in range(0, len(raw) - 1, 2) if raw[i:i + 2] == b"\0\0"), len(raw))
    return raw[:end].decode("utf-16le", "replace")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("log", type=Path)
    parser.add_argument("--all", action="store_true")
    args = parser.parse_args()
    data = args.log.read_bytes()
    if len(data) % RECORD_SIZE:
        raise SystemExit(f"truncated log: {len(data)} bytes")
    total = len(data) // RECORD_SIZE
    previous: tuple[object, ...] | None = None
    emitted = 0
    for index in range(total):
        record = data[index * RECORD_SIZE:(index + 1) * RECORD_SIZE]
        if record[:4] != b"VDEP" or u32(record, 0x08) != RECORD_SIZE:
            raise SystemExit(f"invalid VDEP record at index {index}")
        current_name = cstr(record, CURRENT_NAME_OFFSET)
        last_name = cstr(record, LAST_NAME_OFFSET)
        current_path = u16str(record, CURRENT_PATH_OFFSET)
        last_path = u16str(record, LAST_PATH_OFFSET)
        playback = u16str(record, PLAYBACK_PATH_OFFSET)
        state = (
            u32(record, 0x20), u32(record, 0x24), u32(record, 0x28),
            u32(record, 0x34), u32(record, 0x38),
            current_name, last_name, current_path, last_path, playback,
        )
        if not args.all and state == previous:
            continue
        previous = state
        emitted += 1
        print(f"record={index}/{total - 1} time={u32(record,0x10)}.{u32(record,0x14):09d}")
        print(f"  explorer={ptr(u32(record,0x20))}")
        print(f"  current={ptr(u32(record,0x24))} name={current_name!r} state_+40={u32(record,0x34):#x}")
        print(f"  last={ptr(u32(record,0x28))} name={last_name!r} state_+40={u32(record,0x38):#x}")
        print(f"  current_path={current_path!r}")
        print(f"  last_path={last_path!r}")
        print(f"  playback_path={playback!r}")
    print(f"records_total={total} records_emitted={emitted}")


if __name__ == "__main__":
    main()
