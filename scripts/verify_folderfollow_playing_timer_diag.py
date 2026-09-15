#!/usr/bin/env python3
"""Verify byte scope and delay slots of the playing-plane timer diagnostic."""

from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path


GOLDEN_SHA256 = "c825a72e1078999f74822846d35c99971f9a660addd5f12d42d50a75f0b9b80e"
OLD_UI_TIMER_SHA256 = "32c916ee3762568b06fe05279360b8d2b8f7de5e3ae47be37511e1c44baa3e8a"
OUTPUT_SHA256 = "4927297b4ceebe3b7f8d4bb8854c632e2083d5212aa9f02c9182c9f213acf3fe"
CALLBACK_HI = 0x0EAEBC
CALLBACK_LO = 0x0EAECC
OLD_CALLBACK_HI = 0x0E2C5C
OLD_CALLBACK_LO = 0x0E2C64
CAVE_OFFSET = 0x588040
CAVE_CAPACITY = 0x780
WRAPPER_SIZE = 0x1D8


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize(data: bytes) -> bytes:
    digest = sha256(data)
    if digest == GOLDEN_SHA256:
        return data
    if digest != OLD_UI_TIMER_SHA256:
        raise SystemExit("input is neither golden nor the previous UI-timer diagnostic")
    golden = bytearray(data)
    golden[OLD_CALLBACK_HI:OLD_CALLBACK_HI + 4] = bytes.fromhex("4e00023c")
    golden[OLD_CALLBACK_LO:OLD_CALLBACK_LO + 4] = bytes.fromhex("c0244224")
    golden[CAVE_OFFSET:CAVE_OFFSET + CAVE_CAPACITY] = b"\0" * CAVE_CAPACITY
    if sha256(golden) != GOLDEN_SHA256:
        raise SystemExit("normalization did not reproduce golden")
    return bytes(golden)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("patched", type=Path)
    args = parser.parse_args()

    golden = normalize(args.source.read_bytes())
    patched = args.patched.read_bytes()
    if len(golden) != len(patched):
        raise SystemExit("size changed")
    if sha256(patched) != OUTPUT_SHA256:
        raise SystemExit("patched hash mismatch")

    allowed = set(range(CALLBACK_HI, CALLBACK_HI + 4))
    allowed.update(range(CALLBACK_LO, CALLBACK_LO + 4))
    allowed.update(range(CAVE_OFFSET, CAVE_OFFSET + WRAPPER_SIZE))
    changed = [i for i, pair in enumerate(zip(golden, patched)) if pair[0] != pair[1]]
    outside = [i for i in changed if i not in allowed]
    if outside:
        raise SystemExit(f"unexpected changed offsets: {outside[:16]}")
    if patched[CALLBACK_HI:CALLBACK_HI + 4] != bytes.fromhex("9900063c"):
        raise SystemExit("wrong callback LUI")
    if patched[CALLBACK_LO:CALLBACK_LO + 4] != bytes.fromhex("4080c624"):
        raise SystemExit("wrong callback ADDIU")

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
            if delay != 0x00601021:  # addu v0,v1,zero
                raise SystemExit(f"unsafe jr delay slot at wrapper word {index:#x}")
        elif delay != 0:
            raise SystemExit(f"non-NOP branch/call delay slot at wrapper word {index:#x}")

    if control_count != 12:
        raise SystemExit(f"unexpected control-transfer count: {control_count}")
    print(f"golden_sha256={sha256(golden)}")
    print(f"patched_sha256={sha256(patched)}")
    print(f"changed_bytes={len(changed)}")
    print("changed_scope=playing timer LUI/ADDIU + RX padding wrapper only")
    print(f"checked_control_transfers={control_count}")
    print("delay_slots=verified")


if __name__ == "__main__":
    main()
