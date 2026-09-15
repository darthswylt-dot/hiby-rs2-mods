#!/usr/bin/env python3
"""Summarize compact records from the playing_plane timer diagnostic."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path


MAGIC = b"PTMR"
RECORD_SIZE = 0x100


def u32(record: bytes, offset: int) -> int:
    return struct.unpack_from("<I", record, offset)[0]


def signed32(value: int) -> int:
    return value - 0x1_0000_0000 if value & 0x8000_0000 else value


def ptr(value: int) -> str:
    return "NULL" if value == 0 else f"0x{value:08x}"


def snapshot(record: bytes) -> tuple[int, ...]:
    return tuple(u32(record, offset) for offset in (0x24, 0x30, 0x34, 0x38, 0x40, 0x44, 0x48, 0x4C, 0x50, 0x54, 0x60, 0x64, 0x68, 0x6C, 0x70))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("log", type=Path)
    parser.add_argument("--all", action="store_true", help="print every 100 ms record")
    args = parser.parse_args()
    data = args.log.read_bytes()
    if len(data) % RECORD_SIZE:
        raise SystemExit(f"truncated log: {len(data)} bytes is not a multiple of {RECORD_SIZE}")

    previous: tuple[int, ...] | None = None
    emitted = 0
    total = len(data) // RECORD_SIZE
    for index in range(total):
        record = data[index * RECORD_SIZE:(index + 1) * RECORD_SIZE]
        if record[:4] != MAGIC:
            raise SystemExit(f"bad magic in record {index}: {record[:4]!r}")
        current = snapshot(record)
        if not args.all and current == previous:
            continue
        previous = current
        emitted += 1
        playing_identity = u32(record, 0x30)
        view_identity = u32(record, 0x40)
        print(f"record={index}/{total - 1} time={u32(record,0x10)}.{u32(record,0x14):09d} flags=0x{u32(record,0x0c):02x}")
        print(f"  context={ptr(u32(record,0x24))} global_playing_plane={ptr(u32(record,0x60))} original_return={signed32(u32(record,0x28))}")
        print(f"  playing_item={ptr(u32(record,0x2c))} identity={ptr(playing_identity)}")
        print(f"  explorer={ptr(u32(record,0x34))} current_view={ptr(u32(record,0x38))} view_item={ptr(u32(record,0x3c))} identity={ptr(view_identity)}")
        print(f"  identity_match={playing_identity == view_identity}")
        print(f"  view_internal={ptr(u32(record,0x44))} +5a4={signed32(u32(record,0x48))} +5a8={signed32(u32(record,0x4c))} +5ac={signed32(u32(record,0x50))} +5b0={signed32(u32(record,0x54))}")
        print(f"  playing_plane_+30={signed32(u32(record,0x58))} +254={ptr(u32(record,0x5c))} current_view_+d4={ptr(u32(record,0x70))}")
        print(f"  source={ptr(u32(record,0x64))} music_player={ptr(u32(record,0x68))} property24_word0={ptr(u32(record,0x6c))}")
    print(f"records_total={total} records_emitted={emitted}")


if __name__ == "__main__":
    main()
