#!/usr/bin/env python3
"""Decode passive playing-plane path diagnostic records."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path


MAGIC = b"PPTH"
RECORD_SIZE = 0x4A0
PLAYBACK_PATH_OFFSET = 0x80
FOLDER_PATH_OFFSET = 0x288


def u32(record: bytes, offset: int) -> int:
    return struct.unpack_from("<I", record, offset)[0]


def ptr(value: int) -> str:
    return "NULL" if value == 0 else f"0x{value:08x}"


def utf16(record: bytes, offset: int, size: int = 0x208) -> str:
    raw = record[offset:offset + size]
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
    previous: tuple[object, ...] | None = None
    emitted = 0
    total = len(data) // RECORD_SIZE
    for index in range(total):
        record = data[index * RECORD_SIZE:(index + 1) * RECORD_SIZE]
        if record[:4] != MAGIC:
            raise SystemExit(f"bad magic in record {index}: {record[:4]!r}")
        playback = utf16(record, PLAYBACK_PATH_OFFSET)
        folder = utf16(record, FOLDER_PATH_OFFSET)
        state = tuple(u32(record, off) for off in range(0x20, 0x70, 4)) + (playback, folder)
        if not args.all and state == previous:
            continue
        previous = state
        emitted += 1
        print(f"record={index}/{total - 1} time={u32(record,0x10)}.{u32(record,0x14):09d} flags=0x{u32(record,0x0c):02x}")
        print(f"  callback_a0={ptr(u32(record,0x20))} context={ptr(u32(record,0x24))} return={u32(record,0x28):#x}")
        print(f"  playing_item={ptr(u32(record,0x2c))} explorer={ptr(u32(record,0x30))} context_+30={u32(record,0x34):#x} context_+254={ptr(u32(record,0x38))}")
        print(f"  controller=+34:{ptr(u32(record,0x3c))}, +150:{ptr(u32(record,0x40))}, +274:{ptr(u32(record,0x44))}, +278:{ptr(u32(record,0x48))}")
        print(f"  current_view={ptr(u32(record,0x4c))} current_view_+d4={ptr(u32(record,0x50))}")
        print(f"  explorer_count={u32(record,0x54)} last_view={ptr(u32(record,0x58))} last_view_+3dcc={u32(record,0x5c)}")
        print(f"  global_playing_plane={ptr(u32(record,0x60))} activity_main={ptr(u32(record,0x64))} property24_word0={u32(record,0x68):#x}")
        print(f"  property24_path={playback!r}")
        print(f"  folder_view_path={folder!r}")
    print(f"records_total={total} records_emitted={emitted}")


if __name__ == "__main__":
    main()
