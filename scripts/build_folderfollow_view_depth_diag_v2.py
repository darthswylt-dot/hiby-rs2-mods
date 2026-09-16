#!/usr/bin/env python3
"""Build corrected inline-type view telemetry; see hardware result in notes."""

from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

import build_folderfollow_view_depth_diag as failed


TYPE_LOADS = ((50, failed.S2), (86, failed.S3))
OPTIONAL_STATE_LOADS = ((52, failed.S2), (88, failed.S3))


def build_wrapper() -> bytes:
    wrapper = bytearray(failed.build_wrapper())
    for index, source_register in TYPE_LOADS:
        old = failed.lw(failed.S4, 0, source_register)
        actual = struct.unpack_from("<I", wrapper, index * 4)[0]
        if actual != old:
            raise AssertionError(f"historical wrapper changed at word {index}")
        # The controller+0x298 list stores views with an inline type string.
        # Pass the view address itself to strncpy/strcmp, not *(view+0).
        struct.pack_into("<I", wrapper, index * 4, failed.move(failed.S4, source_register))
    for index, source_register in OPTIONAL_STATE_LOADS:
        old = failed.lw(failed.V0, 0x40, source_register)
        actual = struct.unpack_from("<I", wrapper, index * 4)[0]
        if actual != old:
            raise AssertionError(f"historical state read changed at word {index}")
        # This field is not needed for type/path identity. Avoid dereferencing
        # it on an arbitrary active non-explorer view.
        struct.pack_into("<I", wrapper, index * 4, failed.move(failed.V0, failed.ZERO))
    return bytes(wrapper)


def build(source: bytes) -> tuple[bytes, str]:
    if len(source) != failed.EXPECTED_SIZE:
        raise ValueError("source size differs from validated ELF")
    golden, source_hash = failed.normalize_source(source)
    if any(golden[failed.CAVE_OFFSET:failed.CAVE_OFFSET + failed.CAVE_CAPACITY]):
        raise ValueError("selected cave is not empty")
    patched = bytearray(golden)
    patched[failed.CALLBACK_HI_OFFSET:failed.CALLBACK_HI_OFFSET + 4] = bytes.fromhex("9900063c")
    patched[failed.CALLBACK_LO_OFFSET:failed.CALLBACK_LO_OFFSET + 4] = bytes.fromhex("4080c624")
    wrapper = build_wrapper()
    patched[failed.CAVE_OFFSET:failed.CAVE_OFFSET + len(wrapper)] = wrapper
    return bytes(patched), source_hash


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    patched, source_hash = build(args.source.read_bytes())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(patched)
    print(f"input_sha256={source_hash}")
    print(f"output_sha256={hashlib.sha256(patched).hexdigest()}")
    print(f"output_size={len(patched)}")
    print(f"wrapper_size={len(build_wrapper()):#x}")
    print("hardware_status=successful_passive_run_documented")


if __name__ == "__main__":
    main()
