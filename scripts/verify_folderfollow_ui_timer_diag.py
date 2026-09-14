#!/usr/bin/env python3
"""Verify byte scope and control-transfer delay slots of the UI-timer diagnostic."""

from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path


GOLDEN_SHA256 = "c825a72e1078999f74822846d35c99971f9a660addd5f12d42d50a75f0b9b80e"
RECOVERED_02FD_SHA256 = "02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87"
OUTPUT_SHA256 = "32c916ee3762568b06fe05279360b8d2b8f7de5e3ae47be37511e1c44baa3e8a"
CALLBACK_HI = 0x0E2C5C
CALLBACK_LO = 0x0E2C64
CAVE_OFFSET = 0x588040
WRAPPER_SIZE = 0x22C


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize(data: bytes) -> bytes:
    digest = sha256(data)
    if digest == GOLDEN_SHA256:
        return data
    if digest != RECOVERED_02FD_SHA256:
        raise SystemExit("input is neither golden nor recovered 02fd")
    golden = bytearray(data)
    golden[0x0EADB4:0x0EADB8] = bytes.fromhex("4e00053c")
    golden[0x0EADBC:0x0EADC0] = bytes.fromhex("a05fa524")
    golden[CAVE_OFFSET:CAVE_OFFSET + 0x780] = b"\0" * 0x780
    if sha256(golden) != GOLDEN_SHA256:
        raise SystemExit("02fd normalization did not reproduce golden")
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
    if sha256(golden) != GOLDEN_SHA256:
        raise SystemExit("golden hash mismatch")
    if sha256(patched) != OUTPUT_SHA256:
        raise SystemExit("patched hash mismatch")

    allowed = set(range(CALLBACK_HI, CALLBACK_HI + 4))
    allowed.update(range(CALLBACK_LO, CALLBACK_LO + 4))
    allowed.update(range(CAVE_OFFSET, CAVE_OFFSET + WRAPPER_SIZE))
    changed = [i for i, pair in enumerate(zip(golden, patched)) if pair[0] != pair[1]]
    outside = [i for i in changed if i not in allowed]
    if outside:
        raise SystemExit(f"unexpected changed offsets: {outside[:16]}")
    if patched[CALLBACK_HI:CALLBACK_HI + 4] != bytes.fromhex("9900023c"):
        raise SystemExit("wrong callback LUI")
    if patched[CALLBACK_LO:CALLBACK_LO + 4] != bytes.fromhex("40804224"):
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

    if control_count != 15:
        raise SystemExit(f"unexpected control-transfer count: {control_count}")
    print(f"golden_sha256={sha256(golden)}")
    print(f"patched_sha256={sha256(patched)}")
    print(f"changed_bytes={len(changed)}")
    print("changed_scope=third callback LUI/ADDIU + RX padding wrapper only")
    print(f"checked_control_transfers={control_count}")
    print("delay_slots=verified")


if __name__ == "__main__":
    main()
