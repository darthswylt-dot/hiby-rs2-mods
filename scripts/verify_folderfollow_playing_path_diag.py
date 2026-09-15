#!/usr/bin/env python3
"""Verify byte scope and delay slots of the playing-path diagnostic."""

from __future__ import annotations

import argparse
import hashlib
import struct
from collections import Counter
from pathlib import Path

from build_folderfollow_playing_path_diag import build_wrapper


GOLDEN_SHA256 = "c825a72e1078999f74822846d35c99971f9a660addd5f12d42d50a75f0b9b80e"
OLD_PLAYING_TIMER_SHA256 = "4927297b4ceebe3b7f8d4bb8854c632e2083d5212aa9f02c9182c9f213acf3fe"
OUTPUT_SHA256 = "599cc5e2143aae7633da967f3ea819d0683d2b9d5b184fd799930e07d1c9dc01"
CALLBACK_HI = 0x0EAEBC
CALLBACK_LO = 0x0EAECC
CAVE_OFFSET = 0x588040
CAVE_CAPACITY = 0x780
WRAPPER_SIZE = 0x214
EXPECTED_JAL_COUNTS = Counter({
    0x4E90C0: 1,
    0x4E5680: 1,
    0x438BE0: 1,
    0x4E57E0: 1,
    0x41FB80: 2,
    0xA5B380: 1,
    0xA5B4A0: 1,
    0xA5BC60: 1,
})
FORBIDDEN_TARGETS = {
    0x4E4B80, 0x4E4B20, 0x4E4640, 0x4919E0, 0x491E80,
    0x495A40, 0x495D40, 0x4E3DE0, 0x4E4CE0, 0x4E4DE0,
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize(data: bytes) -> bytes:
    digest = sha256(data)
    if digest == GOLDEN_SHA256:
        return data
    if digest != OLD_PLAYING_TIMER_SHA256:
        raise SystemExit("input is neither golden nor the prior playing-timer diagnostic")
    golden = bytearray(data)
    golden[CALLBACK_HI:CALLBACK_HI + 4] = bytes.fromhex("4f00063c")
    golden[CALLBACK_LO:CALLBACK_LO + 4] = bytes.fromhex("c090c624")
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

    expected_wrapper = build_wrapper()
    if len(expected_wrapper) != WRAPPER_SIZE:
        raise SystemExit("builder wrapper size changed")
    if patched[CAVE_OFFSET:CAVE_OFFSET + WRAPPER_SIZE] != expected_wrapper:
        raise SystemExit("embedded wrapper differs from builder output")
    if any(patched[CAVE_OFFSET + WRAPPER_SIZE:CAVE_OFFSET + CAVE_CAPACITY]):
        raise SystemExit("nonzero bytes follow wrapper in reserved cave")

    words = list(struct.unpack_from(f"<{WRAPPER_SIZE // 4}I", patched, CAVE_OFFSET))
    control_count = 0
    jal_counts: Counter[int] = Counter()
    for index, word in enumerate(words[:-1]):
        opcode = word >> 26
        is_branch = opcode in {0x04, 0x05}
        is_jal = opcode == 0x03
        is_jr = opcode == 0 and (word & 0x3F) == 0x08
        if not (is_branch or is_jal or is_jr):
            continue
        control_count += 1
        if is_jal:
            pc = 0x988040 + index * 4
            target = ((pc + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)
            jal_counts[target] += 1
        delay = words[index + 1]
        if is_jr:
            if delay != 0x00601021:
                raise SystemExit(f"unsafe jr delay slot at wrapper word {index:#x}")
        elif delay != 0:
            raise SystemExit(f"non-NOP branch/call delay slot at wrapper word {index:#x}")
    if control_count != 14:
        raise SystemExit(f"unexpected control-transfer count: {control_count}")
    if jal_counts != EXPECTED_JAL_COUNTS:
        raise SystemExit(f"unexpected jal targets: {jal_counts}")
    forbidden = set(jal_counts) & FORBIDDEN_TARGETS
    if forbidden:
        raise SystemExit(f"forbidden calls present: {sorted(forbidden)}")
    print(f"golden_sha256={sha256(golden)}")
    print(f"patched_sha256={sha256(patched)}")
    print(f"changed_bytes={len(changed)}")
    print("changed_scope=playing timer callback pointer + RX padding wrapper only")
    print(f"checked_control_transfers={control_count}")
    print("delay_slots=verified")


if __name__ == "__main__":
    main()
