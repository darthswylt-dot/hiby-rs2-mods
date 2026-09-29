#!/usr/bin/env python3
"""Build a gated property-11 rebuild using the active explorer view path."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

import build_folderfollow_saved_path_rebuild as previous


def build(source: bytes) -> tuple[bytes, str]:
    if len(source) != previous.EXPECTED_SIZE:
        raise ValueError("source size differs from validated ELF")
    golden, input_hash = previous.normalize_source(source)
    if any(golden[previous.CAVE_OFFSET:previous.CAVE_OFFSET + previous.CAVE_CAPACITY]):
        raise ValueError("selected executable cave is not empty")
    wrapper = previous.build_wrapper(active_type_gate=True)
    patched = bytearray(golden)
    patched[previous.CALLBACK_HI_OFFSET:previous.CALLBACK_HI_OFFSET + 4] = bytes.fromhex("9900063c")
    patched[previous.CALLBACK_LO_OFFSET:previous.CALLBACK_LO_OFFSET + 4] = bytes.fromhex("4080c624")
    patched[previous.CAVE_OFFSET:previous.CAVE_OFFSET + len(wrapper)] = wrapper
    return bytes(patched), input_hash


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    patched, input_hash = build(args.source.read_bytes())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(patched)
    print(f"input_sha256={input_hash}")
    print(f"output_sha256={hashlib.sha256(patched).hexdigest()}")
    print(f"output_size={len(patched)}")
    print(f"wrapper_size={len(previous.build_wrapper(active_type_gate=True)):#x}")
    print("hardware_status=partial_follow_verified_2026_09_29")


if __name__ == "__main__":
    main()
