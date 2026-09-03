#!/usr/bin/env python3
"""Decode rs2_folderfollow_dispatch_diag.bin records."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path


MAGIC = b"FFDG"
RECORD_SIZE = 0x4A0


def u32(record: bytes, offset: int) -> int:
    return struct.unpack_from("<I", record, offset)[0]


def signed32(value: int) -> int:
    return value - 0x1_0000_0000 if value & 0x8000_0000 else value


def utf16(record: bytes, offset: int, size: int = 0x208) -> str:
    raw = record[offset:offset + size]
    end = next((i for i in range(0, len(raw) - 1, 2) if raw[i:i + 2] == b"\0\0"), len(raw))
    return raw[:end].decode("utf-16le", "replace")


def ptr(value: int) -> str:
    return "NULL" if value == 0 else f"0x{value:08x}"


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
        print(f"  version={u32(record, 0x04)} size={u32(record, 0x08)} stage_bits=0x{u32(record, 0x0c):02x}")
        print(f"  entry_time={u32(record, 0x10)}.{u32(record, 0x14):09d}")
        print(f"  exit_time={u32(record, 0x68)}.{u32(record, 0x6c):09d}")
        print(f"  caller_ra={ptr(u32(record, 0x18))} original_sp={ptr(u32(record, 0x1c))}")
        print("  args=" + ", ".join(f"a{i}={ptr(u32(record, 0x20 + i * 4))}" for i in range(4)))
        print(f"  context={ptr(u32(record, 0x30))} explorer={ptr(u32(record, 0x34))}")
        print(f"  get_path_rc={signed32(u32(record, 0x38))}")
        print(f"  current_view_before={ptr(u32(record, 0x3c))}")
        print(f"  explorer_state_before={ptr(u32(record, 0x40))}")
        print(f"  list_before=head:{ptr(u32(record, 0x44))} tail:{ptr(u32(record, 0x48))}")
        print(f"  explorer_view_count={signed32(u32(record, 0x4c))}")
        print(f"  found_view={ptr(u32(record, 0x50))}")
        print(f"  original_return={signed32(u32(record, 0x54))}")
        print(f"  current_view_after={ptr(u32(record, 0x58))}")
        print(f"  explorer_state_after={ptr(u32(record, 0x5c))}")
        print(f"  list_after=head:{ptr(u32(record, 0x60))} tail:{ptr(u32(record, 0x64))}")
        print(f"  playback_path={utf16(record, 0x80)!r}")
        print(f"  found_view_path={utf16(record, 0x288)!r}")


if __name__ == "__main__":
    main()
