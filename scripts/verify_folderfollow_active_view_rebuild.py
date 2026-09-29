#!/usr/bin/env python3
"""Verify exact byte scope and stock-call contract of active-view rebuild."""

from __future__ import annotations

import argparse
import hashlib
import struct
from collections import Counter
from pathlib import Path

import build_folderfollow_active_view_rebuild as candidate
import build_folderfollow_saved_path_rebuild as previous


EXPECTED_CALLS = Counter({
    previous.ORIGINAL_CALLBACK: 1,
    previous.GET_CURRENT_VIEW: 1,
    previous.STRNCMP_PLT: 1,
    previous.WIDE_COPY: 1,
    previous.PROPERTY_GET: 1,
    previous.WIDE_COMPARE: 2,
    previous.PROPERTY_SET: 2,
    previous.STOCK_STORAGE_OPEN: 1,
})


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("artifact", type=Path)
    args = parser.parse_args()
    source = args.source.read_bytes()
    artifact = args.artifact.read_bytes()
    expected, _ = candidate.build(source)
    if artifact != expected:
        raise SystemExit("artifact differs from exact intended patch")
    golden, _ = previous.normalize_source(source)
    wrapper = previous.build_wrapper(active_type_gate=True)
    if len(wrapper) != 0x1D4:
        raise SystemExit(f"unexpected wrapper size: {len(wrapper):#x}")

    # The stock function's input string is 20 bytes. Matching exactly this
    # prefix includes vg_listview_explorer##1, as seen in hardware telemetry.
    type_name = b"vg_listview_explorer\0"
    type_offset = previous.EXPLORER_VIEW_TYPE - previous.IMAGE_BASE
    if golden[type_offset:type_offset + len(type_name)] != type_name:
        raise SystemExit("explorer type name changed")

    changed = [i for i, (a, b) in enumerate(zip(golden, artifact)) if a != b]
    allowed = set(range(previous.CALLBACK_HI_OFFSET, previous.CALLBACK_HI_OFFSET + 4))
    allowed.update(range(previous.CALLBACK_LO_OFFSET, previous.CALLBACK_LO_OFFSET + 4))
    allowed.update(range(previous.CAVE_OFFSET, previous.CAVE_OFFSET + len(wrapper)))
    if any(i not in allowed for i in changed):
        raise SystemExit("bytes changed outside timer callback and RX cave")

    words = struct.unpack(f"<{len(wrapper) // 4}I", wrapper)
    calls: list[tuple[int, int]] = []
    controls = 0
    for index, word in enumerate(words):
        opcode = word >> 26
        funct = word & 0x3F
        branch = opcode in (4, 5)
        jump = opcode in (2, 3)
        jr = opcode == 0 and funct == 8
        if not (branch or jump or jr):
            continue
        if index + 1 >= len(words):
            raise SystemExit("control transfer lacks delay slot")
        controls += 1
        delay = words[index + 1]
        if jr:
            if delay != previous.move(previous.V0, previous.V1):
                raise SystemExit("unexpected return delay slot")
        elif delay:
            raise SystemExit(f"non-NOP branch/call delay slot at word {index}")
        if branch:
            immediate = word & 0xFFFF
            if immediate & 0x8000:
                immediate -= 0x10000
            target = index + 1 + immediate
            if not 0 <= target < len(words):
                raise SystemExit(f"branch leaves wrapper at word {index}")
        if opcode == 3:
            pc = previous.CAVE_VADDR + index * 4
            target = ((pc + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)
            calls.append((index, target))
    if Counter(target for _, target in calls) != EXPECTED_CALLS:
        raise SystemExit(f"unexpected call set: {[hex(x) for _, x in calls]}")
    call_targets = [target for _, target in calls]
    if previous.FIND_LAST_VIEW_BY_TYPE in call_targets:
        raise SystemExit("active-view rebuild must not depend on last-view lookup")

    print(f"artifact_sha256={hashlib.sha256(artifact).hexdigest()}")
    print(f"wrapper_size={len(wrapper):#x}")
    print(f"changed_bytes={len(changed)}")
    print(f"control_transfers={controls}")
    print("active_view_prefix_gate=yes")
    print("exact_patch=yes")
    print("hardware_status=partial_follow_verified_2026_09_29")


if __name__ == "__main__":
    main()
