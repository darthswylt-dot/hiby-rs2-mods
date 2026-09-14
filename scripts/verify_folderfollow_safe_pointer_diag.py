#!/usr/bin/env python3
"""Verify the byte scope and control transfers of the safe FFSP diagnostic."""

from __future__ import annotations

import argparse
import hashlib
import struct
from collections import Counter
from pathlib import Path

from build_folderfollow_safe_pointer_diag import (
    CALLBACK_POINTER_HI_OFFSET,
    CALLBACK_POINTER_LO_OFFSET,
    CODE_CAVE_CAPACITY,
    CODE_CAVE_OFFSET,
    CODE_CAVE_VADDR,
    GOLDEN_SHA256,
    build_wrapper,
    normalize_source,
)


EXPECTED_OUTPUT_SHA256 = "eba4b0c99ae0f0436a038d9db242b62176c9120bc79d64b6da40564288cf3a01"

EXPECTED_JAL_COUNTS = Counter(
    {
        0xA5BC60: 1,  # memset
        0xA5B380: 2,  # clock_gettime
        0x459340: 2,  # player context, pre/post
        0x4E5680: 2,  # current view, pre/post
        0x438BE0: 2,  # Folder View count, pre/post
        0x4E57E0: 2,  # last Folder View, pre/post
        0xA5B4A0: 2,  # durable pre/post writes
        0x4E5FA0: 1,  # original callback
    }
)

FORBIDDEN_TARGETS = {
    0x41FB80,  # UTF-16 copy
    0x4E4B80,  # state-consuming current-path helper
    0x4E4B20,  # destroy explorer stack
    0x4E4640,  # build Folder View
    0x4919E0,  # retarget existing view
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def words(data: bytes) -> list[int]:
    if len(data) % 4:
        raise AssertionError("wrapper is not word-aligned")
    return list(struct.unpack(f"<{len(data) // 4}I", data))


def jump_target(pc: int, word: int) -> int:
    return ((pc + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("candidate", type=Path)
    args = parser.parse_args()

    source = args.source.read_bytes()
    candidate = args.candidate.read_bytes()
    golden, _ = normalize_source(source)
    if sha256(golden) != GOLDEN_SHA256:
        raise AssertionError("normalized source is not golden")
    if sha256(candidate) != EXPECTED_OUTPUT_SHA256:
        raise AssertionError(f"unexpected output SHA-256: {sha256(candidate)}")
    if len(candidate) != len(golden):
        raise AssertionError("candidate size differs from golden")

    wrapper = build_wrapper()
    allowed = set(range(CALLBACK_POINTER_HI_OFFSET, CALLBACK_POINTER_HI_OFFSET + 4))
    allowed.update(
        range(CALLBACK_POINTER_LO_OFFSET, CALLBACK_POINTER_LO_OFFSET + 4)
    )
    allowed.update(range(CODE_CAVE_OFFSET, CODE_CAVE_OFFSET + len(wrapper)))
    changed = {index for index, pair in enumerate(zip(golden, candidate)) if pair[0] != pair[1]}
    if not changed <= allowed:
        extras = sorted(changed - allowed)
        raise AssertionError(f"changes outside callback/cave: {extras[:8]}")
    if candidate[CODE_CAVE_OFFSET:CODE_CAVE_OFFSET + len(wrapper)] != wrapper:
        raise AssertionError("embedded wrapper differs from builder output")
    if any(
        candidate[
            CODE_CAVE_OFFSET + len(wrapper):CODE_CAVE_OFFSET + CODE_CAVE_CAPACITY
        ]
    ):
        raise AssertionError("nonzero data follows wrapper in reserved cave")

    wrapper_words = words(wrapper)
    jal_counts: Counter[int] = Counter()
    control_count = 0
    for index, word in enumerate(wrapper_words):
        opcode = word >> 26
        pc = CODE_CAVE_VADDR + index * 4
        if opcode == 0x03:
            jal_counts[jump_target(pc, word)] += 1
        if opcode in {0x02, 0x03, 0x04, 0x05, 0x06, 0x07}:
            control_count += 1
            if index + 1 >= len(wrapper_words) or wrapper_words[index + 1] != 0:
                raise AssertionError(f"non-nop delay slot after {pc:#x}")

    if jal_counts != EXPECTED_JAL_COUNTS:
        raise AssertionError(f"unexpected jal targets: {jal_counts}")
    forbidden_found = set(jal_counts) & FORBIDDEN_TARGETS
    if forbidden_found:
        raise AssertionError(f"forbidden calls present: {forbidden_found}")

    # Final return is `jr ra` with `move v0,v1` in its intentional delay slot.
    if wrapper_words[-2:] != [0x03E00008, 0x00601021]:
        raise AssertionError("unexpected return sequence")

    print(f"candidate_sha256={sha256(candidate)}")
    print(f"wrapper_size={len(wrapper):#x}")
    print(f"changed_bytes={len(changed)}")
    print(f"control_transfers_with_nop_slots={control_count}")
    print("forbidden_calls=none")
    print("verification=ok")


if __name__ == "__main__":
    main()
