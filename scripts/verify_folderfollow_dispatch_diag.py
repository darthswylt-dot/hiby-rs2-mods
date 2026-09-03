#!/usr/bin/env python3
"""Verify byte scope and MIPS delay slots of the Folder View diagnostic."""

from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path


SOURCE_SHA256 = "c825a72e1078999f74822846d35c99971f9a660addd5f12d42d50a75f0b9b80e"
OUTPUT_SHA256 = "6c274509946c57a642a5ae7f7a42910e6bc8abe28fba8155c973bb6a56c08912"
CALLBACK_HI = 0x0EADB4
CALLBACK_LO = 0x0EADBC
CAVE_OFFSET = 0x588040
WRAPPER_SIZE = 0x280


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("golden", type=Path)
    parser.add_argument("patched", type=Path)
    args = parser.parse_args()

    golden = args.golden.read_bytes()
    patched = args.patched.read_bytes()
    if len(golden) != len(patched):
        raise SystemExit("size changed")
    if sha256(golden) != SOURCE_SHA256:
        raise SystemExit("golden hash mismatch")
    if sha256(patched) != OUTPUT_SHA256:
        raise SystemExit("patched hash mismatch")

    allowed = set(range(CALLBACK_HI, CALLBACK_HI + 4))
    allowed.update(range(CALLBACK_LO, CALLBACK_LO + 4))
    allowed.update(range(CAVE_OFFSET, CAVE_OFFSET + WRAPPER_SIZE))
    changed = [index for index, pair in enumerate(zip(golden, patched)) if pair[0] != pair[1]]
    outside = [index for index in changed if index not in allowed]
    if outside:
        raise SystemExit(f"unexpected changed offsets: {outside[:16]}")
    if not any(CALLBACK_HI <= index < CALLBACK_HI + 4 for index in changed):
        raise SystemExit("callback high instruction was not changed")
    if not any(CALLBACK_LO <= index < CALLBACK_LO + 4 for index in changed):
        raise SystemExit("callback low instruction was not changed")
    if not any(CAVE_OFFSET <= index < CAVE_OFFSET + WRAPPER_SIZE for index in changed):
        raise SystemExit("wrapper was not installed")

    if patched[CALLBACK_HI:CALLBACK_HI + 4] != bytes.fromhex("9900053c"):
        raise SystemExit("wrong callback LUI")
    if patched[CALLBACK_LO:CALLBACK_LO + 4] != bytes.fromhex("4080a524"):
        raise SystemExit("wrong callback ADDIU delay slot")

    words = list(struct.unpack_from(f"<{WRAPPER_SIZE // 4}I", patched, CAVE_OFFSET))
    control_count = 0
    for index, word in enumerate(words[:-1]):
        opcode = word >> 26
        is_branch = opcode in {0x04, 0x05}
        is_jal = opcode == 0x03
        is_jr = opcode == 0 and (word & 0x3F) == 0x08
        if not (is_branch or is_jal or is_jr):
            continue
        control_count += 1
        delay = words[index + 1]
        if is_jr:
            expected_return_move = 0x00601021  # addu v0,v1,zero
            if delay != expected_return_move:
                raise SystemExit(f"unsafe jr delay slot at wrapper word {index:#x}")
        elif delay != 0:
            raise SystemExit(f"non-NOP branch/call delay slot at wrapper word {index:#x}")

    if control_count != 22:
        raise SystemExit(f"unexpected control-transfer count: {control_count}")

    print(f"golden_sha256={sha256(golden)}")
    print(f"patched_sha256={sha256(patched)}")
    print(f"changed_bytes={len(changed)}")
    print("changed_scope=callback LUI + callback delay-slot ADDIU + RX padding wrapper only")
    print(f"checked_control_transfers={control_count}")
    print("delay_slots=verified")


if __name__ == "__main__":
    main()
