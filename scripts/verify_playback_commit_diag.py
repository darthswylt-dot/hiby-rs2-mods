#!/usr/bin/env python3
"""Verify byte scope and calls in the passive playback-commit diagnostic."""

from __future__ import annotations

import argparse
import hashlib
import struct
from collections import Counter
from pathlib import Path

from build_folderfollow_safe_pointer_diag import (
    CODE_CAVE_CAPACITY,
    CODE_CAVE_OFFSET,
    CODE_CAVE_VADDR,
    jal,
    normalize_source,
)
from build_playback_commit_diag import (
    FAST_COPY_OFFSET,
    GENERAL_COPY_OFFSET,
    MEMCPY_PLT,
    MEMSET_PLT,
    RECORD_SIZE,
    WRITE_PLT,
    build_candidate,
    build_wrapper,
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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
    expected, wrapper, _ = build_candidate(source)
    if candidate != expected:
        raise AssertionError("candidate does not exactly match deterministic builder output")
    if len(candidate) != len(golden):
        raise AssertionError("candidate size differs from golden")

    patched_call = struct.pack("<I", jal(CODE_CAVE_VADDR))
    for offset in (FAST_COPY_OFFSET, GENERAL_COPY_OFFSET):
        if candidate[offset:offset + 4] != patched_call:
            raise AssertionError(f"commit call not redirected at {offset:#x}")

    allowed = set(range(FAST_COPY_OFFSET, FAST_COPY_OFFSET + 4))
    allowed.update(range(GENERAL_COPY_OFFSET, GENERAL_COPY_OFFSET + 4))
    allowed.update(range(CODE_CAVE_OFFSET, CODE_CAVE_OFFSET + len(wrapper)))
    changed = {i for i, pair in enumerate(zip(golden, candidate)) if pair[0] != pair[1]}
    if not changed <= allowed:
        raise AssertionError(f"changes outside two calls/cave: {sorted(changed - allowed)[:8]}")
    if any(candidate[CODE_CAVE_OFFSET + len(wrapper):CODE_CAVE_OFFSET + CODE_CAVE_CAPACITY]):
        raise AssertionError("nonzero bytes follow wrapper in reserved cave")

    wrapper_words = list(struct.unpack(f"<{len(wrapper) // 4}I", wrapper))
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
    expected_calls = Counter({MEMSET_PLT: 2, WRITE_PLT: 2, MEMCPY_PLT: 1})
    if jal_counts != expected_calls:
        raise AssertionError(f"unexpected wrapper calls: {jal_counts}")
    if wrapper_words[-2:] != [0x03E00008, 0x00601021]:
        raise AssertionError("unexpected return sequence")
    if wrapper_words.count(0x24060680) != 4:
        raise AssertionError("record size is not used by two clears and two writes")
    if sum(word >> 26 == 0x25 for word in wrapper_words) != 6:
        raise AssertionError("expected six bounded UTF-16 read loops")
    if sum(word >> 26 == 0x29 for word in wrapper_words) != 6:
        raise AssertionError("expected six bounded UTF-16 write loops")

    print(f"candidate_sha256={sha256(candidate)}")
    print(f"wrapper_size={len(wrapper):#x}")
    print(f"record_size={RECORD_SIZE:#x}")
    print(f"changed_bytes={len(changed)}")
    print(f"control_transfers_with_nop_slots={control_count}")
    print("calls=2x_memset,2x_write,1x_original_memcpy")
    print("ui_or_navigation_calls=none")
    print("verification=ok")


if __name__ == "__main__":
    main()
