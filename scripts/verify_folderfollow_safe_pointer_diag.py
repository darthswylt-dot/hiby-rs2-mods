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
    PATH_RECORD_SIZE,
    POINTER_RECORD_SIZE,
    build_wrapper,
    normalize_source,
)


EXPECTED_OUTPUT_SHA256 = "eba4b0c99ae0f0436a038d9db242b62176c9120bc79d64b6da40564288cf3a01"
EXPECTED_PATH_OUTPUT_SHA256 = "dfa618c017b35505fa654742c0193a155fac11c3eaf6c2b301e6bbb2163f52df"

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
    parser.add_argument("--capture-path", action="store_true")
    args = parser.parse_args()

    source = args.source.read_bytes()
    candidate = args.candidate.read_bytes()
    golden, _ = normalize_source(source)
    if sha256(golden) != GOLDEN_SHA256:
        raise AssertionError("normalized source is not golden")
    expected_hash = (
        EXPECTED_PATH_OUTPUT_SHA256 if args.capture_path else EXPECTED_OUTPUT_SHA256
    )
    if sha256(candidate) != expected_hash:
        raise AssertionError(f"unexpected output SHA-256: {sha256(candidate)}")
    if len(candidate) != len(golden):
        raise AssertionError("candidate size differs from golden")

    wrapper = build_wrapper(args.capture_path)
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
    if wrapper_words[20] != 0x24020001:
        raise AssertionError("target callback filter is not a2=1,a3=1")
    expected_version_word = 0x24020002 if args.capture_path else 0x24020001
    if wrapper_words[35] != expected_version_word:
        raise AssertionError("unexpected FFSP record-version instruction")
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

    expected_jal_counts = EXPECTED_JAL_COUNTS.copy()
    if args.capture_path:
        expected_jal_counts[0xA5BC60] = 2  # clear full record, then post path
    if jal_counts != expected_jal_counts:
        raise AssertionError(f"unexpected jal targets: {jal_counts}")
    forbidden_found = set(jal_counts) & FORBIDDEN_TARGETS
    if forbidden_found:
        raise AssertionError(f"forbidden calls present: {forbidden_found}")

    # Final return is `jr ra` with `move v0,v1` in its intentional delay slot.
    if wrapper_words[-2:] != [0x03E00008, 0x00601021]:
        raise AssertionError("unexpected return sequence")

    record_size = PATH_RECORD_SIZE if args.capture_path else POINTER_RECORD_SIZE
    size_words = [word for word in wrapper_words if word == 0x24060000 | record_size]
    if len(size_words) != 3:
        raise AssertionError("record size is not used by clear and both durable writes")
    if args.capture_path:
        lhu_count = sum(word >> 26 == 0x25 for word in wrapper_words)
        sh_count = sum(word >> 26 == 0x29 for word in wrapper_words)
        if (lhu_count, sh_count) != (2, 2):
            raise AssertionError(
                f"unexpected bounded path-copy bodies: lhu={lhu_count} sh={sh_count}"
            )
        copy_loop = [
            0x94480000,  # lhu t0,0(v0)
            0xA4680000,  # sh t0,0(v1)
            0x24420002,  # source += 2
            0x24630002,  # destination += 2
            0x26D6FFFF,  # 260-code-unit counter -= 1
            0x16C0FFFA,  # loop back exactly six instructions
            0x00000000,  # branch delay slot
        ]
        copies = sum(
            wrapper_words[index:index + len(copy_loop)] == copy_loop
            for index in range(len(wrapper_words) - len(copy_loop) + 1)
        )
        if copies != 2:
            raise AssertionError(f"expected two exact bounded copy loops, found {copies}")
        if wrapper_words.count(0x24060208) != 1:
            raise AssertionError("post-callback path clear is not exactly 0x208 bytes")

    print(f"candidate_sha256={sha256(candidate)}")
    print(f"wrapper_size={len(wrapper):#x}")
    print(f"record_size={record_size:#x}")
    print(f"changed_bytes={len(changed)}")
    print(f"control_transfers_with_nop_slots={control_count}")
    print("forbidden_calls=none")
    print("verification=ok")


if __name__ == "__main__":
    main()
