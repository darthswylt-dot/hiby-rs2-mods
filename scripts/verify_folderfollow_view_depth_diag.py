#!/usr/bin/env python3
"""Verify exact patch scope and jump delay slots for the passive view diagnostic."""

from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

from build_folderfollow_view_depth_diag import (
    CALLBACK_HI_OFFSET, CALLBACK_LO_OFFSET, CAVE_OFFSET, CAVE_VADDR,
    CLOCK_GETTIME_PLT, EXPECTED_SIZE, EXPLORER_VIEW_TYPE,
    FIND_LAST_VIEW_BY_TYPE, GET_CURRENT_VIEW, MEMSET_PLT,
    ORIGINAL_CALLBACK, RECORD_SIZE, STRCMP_PLT, STRNCPY_PLT,
    WIDE_COPY, WRITE_PLT, build_wrapper, normalize_source,
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("artifact", type=Path)
    args = parser.parse_args()
    source = args.source.read_bytes()
    artifact = args.artifact.read_bytes()
    if len(source) != EXPECTED_SIZE or len(artifact) != EXPECTED_SIZE:
        raise SystemExit("input size differs from validated ELF size")
    golden, _ = normalize_source(source)
    wrapper = build_wrapper()
    expected = bytearray(golden)
    expected[CALLBACK_HI_OFFSET:CALLBACK_HI_OFFSET + 4] = bytes.fromhex("9900063c")
    expected[CALLBACK_LO_OFFSET:CALLBACK_LO_OFFSET + 4] = bytes.fromhex("4080c624")
    expected[CAVE_OFFSET:CAVE_OFFSET + len(wrapper)] = wrapper
    if artifact != expected:
        raise SystemExit("artifact differs outside the exact intended patch")

    words = struct.unpack(f"<{len(wrapper) // 4}I", wrapper)
    controls = []
    calls = []
    for i, word in enumerate(words):
        op = word >> 26
        funct = word & 0x3F
        if op in (2, 3, 4, 5) or (op == 0 and funct in (8, 9)):
            if i + 1 >= len(words):
                raise SystemExit(f"missing delay slot at {CAVE_VADDR + i * 4:#x}")
            if words[i + 1] != 0 and not (op == 0 and funct == 8 and i + 1 == len(words) - 1):
                raise SystemExit(f"unexpected non-NOP delay slot at {CAVE_VADDR + i * 4:#x}")
            controls.append(CAVE_VADDR + i * 4)
        if op == 3:
            calls.append(((CAVE_VADDR + i * 4 + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2))
        if op in (4, 5):
            imm = word & 0xFFFF
            if imm & 0x8000:
                imm -= 0x10000
            target = CAVE_VADDR + (i + 1 + imm) * 4
            if not CAVE_VADDR <= target < CAVE_VADDR + len(wrapper):
                raise SystemExit(f"branch outside wrapper at {CAVE_VADDR + i * 4:#x}")
    allowed_calls = {
        ORIGINAL_CALLBACK, MEMSET_PLT, CLOCK_GETTIME_PLT,
        GET_CURRENT_VIEW, FIND_LAST_VIEW_BY_TYPE, STRNCPY_PLT,
        STRCMP_PLT, WIDE_COPY, WRITE_PLT,
    }
    if set(calls) != allowed_calls:
        raise SystemExit(f"unexpected call set: {[hex(x) for x in calls]}")
    if EXPLORER_VIEW_TYPE != 0x922704:
        raise SystemExit("unexpected explorer type address")
    changed = sum(a != b for a, b in zip(golden, artifact))
    print(f"artifact_sha256={sha256(artifact)}")
    print(f"wrapper_size={len(wrapper):#x}")
    print(f"record_size={RECORD_SIZE:#x}")
    print(f"changed_bytes={changed}")
    print(f"control_transfers={len(controls)}")
    print("exact_patch=yes")


if __name__ == "__main__":
    main()
