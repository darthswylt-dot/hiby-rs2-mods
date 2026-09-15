#!/usr/bin/env python3
"""Verify the gated property-11 Folder View rebuild artifact."""

from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

from build_folderfollow_saved_path_rebuild import (
    CALLBACK_HI_OFFSET, CALLBACK_LO_OFFSET, CAVE_OFFSET, CAVE_VADDR,
    EXPECTED_SIZE, SOURCE_SHA256, build_wrapper, normalize_source,
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
    if len(source) != EXPECTED_SIZE:
        raise SystemExit("source size is invalid")
    golden, _ = normalize_source(source)
    if len(artifact) != EXPECTED_SIZE:
        raise SystemExit("artifact size differs from source")
    wrapper = build_wrapper()
    expected = bytearray(golden)
    expected[CALLBACK_HI_OFFSET:CALLBACK_HI_OFFSET + 4] = bytes.fromhex("9900063c")
    expected[CALLBACK_LO_OFFSET:CALLBACK_LO_OFFSET + 4] = bytes.fromhex("4080c624")
    expected[CAVE_OFFSET:CAVE_OFFSET + len(wrapper)] = wrapper
    if artifact != expected:
        raise SystemExit("artifact contains changes outside the exact patch")

    words = struct.unpack(f"<{len(wrapper) // 4}I", wrapper)
    control = []
    for index, word in enumerate(words):
        op = word >> 26
        funct = word & 0x3F
        if op in (2, 3, 4, 5) or (op == 0 and funct in (8, 9)):
            if index + 1 >= len(words):
                raise SystemExit(f"control transfer without delay slot at {index}")
            control.append(CAVE_VADDR + index * 4)

    changed = [i for i, (a, b) in enumerate(zip(golden, artifact)) if a != b]
    print(f"artifact_sha256={sha256(artifact)}")
    print(f"wrapper_size={len(wrapper):#x}")
    print(f"changed_bytes={len(changed)}")
    print(f"control_transfers={len(control)}")
    print("exact_patch=yes")


if __name__ == "__main__":
    main()
