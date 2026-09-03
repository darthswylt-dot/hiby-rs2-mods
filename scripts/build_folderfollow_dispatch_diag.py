#!/usr/bin/env python3
"""Build a passive RS2 Folder View dispatcher diagnostic.

The wrapper records state for callback event a2=1,a3=1, calls the original
0x4E5FA0 callback, records the immediate post-callback state, and writes one
fixed-size binary record to inherited file descriptor 9. It never calls the
view mutators used by the failed folder-follow experiments.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path


SOURCE_SHA256 = "c825a72e1078999f74822846d35c99971f9a660addd5f12d42d50a75f0b9b80e"
EXPECTED_SIZE = 7_133_528

IMAGE_BASE = 0x400000
CALLBACK_POINTER_HI_OFFSET = 0x0EADB4
CALLBACK_POINTER_LO_OFFSET = 0x0EADBC
CODE_CAVE_VADDR = 0x988040
CODE_CAVE_OFFSET = CODE_CAVE_VADDR - IMAGE_BASE
CODE_CAVE_CAPACITY = 0x780

ORIGINAL_CALLBACK = 0x4E5FA0
GET_PLAYER_CONTEXT = 0x459340
GET_CURRENT_PATH = 0x4E4B80
GET_CURRENT_VIEW = 0x4E5680
COUNT_VIEWS_BY_TYPE = 0x438BE0
FIND_LAST_VIEW_BY_TYPE = 0x4E57E0
WIDE_COPY = 0x41FB80
CLOCK_GETTIME_PLT = 0xA5B380
WRITE_PLT = 0xA5B4A0
MEMSET_PLT = 0xA5BC60
EXPLORER_VIEW_TYPE = 0x922704  # "vg_listview_explorer"

FRAME_SIZE = 0x600
RECORD_OFFSET = 0x40
RECORD_SIZE = 0x4A0
PLAYBACK_PATH_OFFSET = 0x80
FOUND_VIEW_PATH_OFFSET = 0x288

# MIPS o32 registers.
ZERO, V0, V1, A0, A1, A2, A3 = 0, 2, 3, 4, 5, 6, 7
S0, S1, S2, S3, S4, S5, SP, RA = 16, 17, 18, 19, 20, 21, 29, 31


def r_type(rs: int, rt: int, rd: int, funct: int) -> int:
    return (rs << 21) | (rt << 16) | (rd << 11) | funct


def i_type(op: int, rs: int, rt: int, immediate: int) -> int:
    return (op << 26) | (rs << 21) | (rt << 16) | (immediate & 0xFFFF)


def j_type(op: int, target: int) -> int:
    if target & 3:
        raise ValueError(f"unaligned jump target: {target:#x}")
    return (op << 26) | ((target >> 2) & 0x03FFFFFF)


def addiu(rt: int, rs: int, immediate: int) -> int:
    return i_type(0x09, rs, rt, immediate)


def ori(rt: int, rs: int, immediate: int) -> int:
    return i_type(0x0D, rs, rt, immediate)


def lui(rt: int, immediate: int) -> int:
    return i_type(0x0F, ZERO, rt, immediate)


def lw(rt: int, offset: int, base: int) -> int:
    return i_type(0x23, base, rt, offset)


def sw(rt: int, offset: int, base: int) -> int:
    return i_type(0x2B, base, rt, offset)


def move(rd: int, rs: int) -> int:
    return r_type(rs, ZERO, rd, 0x21)


def jal(target: int) -> int:
    return j_type(0x03, target)


def build_wrapper() -> bytes:
    words: list[int] = []
    labels: dict[str, int] = {}
    fixups: list[tuple[int, str, int, int, int]] = []

    def emit(word: int) -> None:
        words.append(word)

    def label(name: str) -> None:
        if name in labels:
            raise ValueError(f"duplicate label: {name}")
        labels[name] = len(words)

    def branch(op: int, rs: int, rt: int, target: str) -> None:
        fixups.append((len(words), target, op, rs, rt))
        emit(0)

    # Private stack frame: one 0x4a0-byte record, helper output pointers, and
    # preserved callback ABI/callee-saved state.
    emit(addiu(SP, SP, -FRAME_SIZE))
    emit(sw(RA, 0x5FC, SP))
    emit(sw(S0, 0x5F8, SP))
    emit(sw(S1, 0x5F4, SP))
    emit(sw(S2, 0x5F0, SP))
    emit(sw(S3, 0x5EC, SP))
    emit(sw(S4, 0x5E8, SP))
    emit(sw(S5, 0x5E4, SP))
    emit(sw(A0, 0x5E0, SP))
    emit(sw(A1, 0x5DC, SP))
    emit(sw(A2, 0x5D8, SP))
    emit(sw(A3, 0x5D4, SP))
    # Keep the early-exit paths safe: a missing player context or explorer
    # reaches the post-callback logger without ever assigning these registers.
    emit(move(S0, ZERO))
    emit(move(S4, ZERO))
    emit(move(S5, ZERO))

    # Non-target callback events pass through without logging or helper calls.
    emit(addiu(V0, ZERO, 1))
    branch(0x05, A2, V0, "call_original")
    emit(0)
    branch(0x05, A3, V0, "call_original")
    emit(0)

    emit(addiu(S5, ZERO, 1))  # stage bit 0: target event
    emit(addiu(S1, SP, RECORD_OFFSET))
    emit(move(A0, S1))
    emit(move(A1, ZERO))
    emit(addiu(A2, ZERO, RECORD_SIZE))
    emit(jal(MEMSET_PLT))
    emit(0)

    # Header: magic "FFDG", format version, record size, stage flags.
    emit(lui(V0, 0x4744))
    emit(ori(V0, V0, 0x4646))
    emit(sw(V0, 0x00, S1))
    emit(addiu(V0, ZERO, 1))
    emit(sw(V0, 0x04, S1))
    emit(addiu(V0, ZERO, RECORD_SIZE))
    emit(sw(V0, 0x08, S1))
    emit(sw(S5, 0x0C, S1))

    # Entry time and caller/ABI snapshot.
    emit(addiu(A0, ZERO, 1))  # CLOCK_MONOTONIC
    emit(addiu(A1, S1, 0x10))
    emit(jal(CLOCK_GETTIME_PLT))
    emit(0)
    emit(lw(V0, 0x5FC, SP))
    emit(sw(V0, 0x18, S1))  # callback caller return address
    emit(addiu(V0, SP, FRAME_SIZE))
    emit(sw(V0, 0x1C, S1))  # original stack pointer
    for saved_offset, record_offset in (
        (0x5E0, 0x20), (0x5DC, 0x24), (0x5D8, 0x28), (0x5D4, 0x2C)
    ):
        emit(lw(V0, saved_offset, SP))
        emit(sw(V0, record_offset, S1))

    # Player and explorer objects.
    emit(lw(A0, 0x5E0, SP))
    emit(jal(GET_PLAYER_CONTEXT))
    emit(0)
    emit(move(S4, V0))
    emit(sw(S4, 0x30, S1))
    branch(0x04, S4, ZERO, "call_original")
    emit(0)
    emit(ori(S5, S5, 0x02))

    emit(lw(S0, 0x3C, S4))
    emit(sw(S0, 0x34, S1))
    branch(0x04, S0, ZERO, "call_original")
    emit(0)
    emit(ori(S5, S5, 0x04))
    emit(lw(V0, 0x150, S0))
    emit(sw(V0, 0x40, S1))
    emit(lw(V0, 0x298, S0))
    emit(sw(V0, 0x44, S1))
    emit(lw(V0, 0x29C, S0))
    emit(sw(V0, 0x48, S1))

    # Current playback path. 0x4E4B80 writes at most 0x208 bytes.
    emit(move(A0, S0))
    emit(addiu(A1, S1, PLAYBACK_PATH_OFFSET))
    emit(jal(GET_CURRENT_PATH))
    emit(0)
    emit(sw(V0, 0x38, S1))
    emit(addiu(V1, ZERO, -1))
    branch(0x04, V0, V1, "after_path")
    emit(0)
    emit(ori(S5, S5, 0x08))
    label("after_path")

    # Read-only current-view, view-count, and last matching Folder View probes.
    emit(sw(ZERO, 0x20, SP))
    emit(move(A0, S0))
    emit(addiu(A1, SP, 0x20))
    emit(jal(GET_CURRENT_VIEW))
    emit(0)
    emit(lw(V0, 0x20, SP))
    emit(sw(V0, 0x3C, S1))
    branch(0x04, V0, ZERO, "after_current_view")
    emit(0)
    emit(ori(S5, S5, 0x10))
    label("after_current_view")

    emit(lui(S2, EXPLORER_VIEW_TYPE >> 16))
    emit(addiu(S2, S2, EXPLORER_VIEW_TYPE & 0xFFFF))
    emit(move(A0, S0))
    emit(move(A1, S2))
    emit(jal(COUNT_VIEWS_BY_TYPE))
    emit(0)
    emit(sw(V0, 0x4C, S1))
    emit(ori(S5, S5, 0x20))

    emit(sw(ZERO, 0x24, SP))
    emit(move(A0, S0))
    emit(move(A1, S2))
    emit(addiu(A2, SP, 0x24))
    emit(jal(FIND_LAST_VIEW_BY_TYPE))
    emit(0)
    emit(lw(V0, 0x24, SP))
    emit(sw(V0, 0x50, S1))
    branch(0x04, V0, ZERO, "call_original")
    emit(0)
    emit(ori(S5, S5, 0x40))

    emit(addiu(A0, S1, FOUND_VIEW_PATH_OFFSET))
    emit(addiu(A1, V0, 0x3DD8))
    emit(addiu(A2, ZERO, 0x103))
    emit(jal(WIDE_COPY))
    emit(0)

    # The diagnostic never changes navigation state. It invokes stock code with
    # the original callback arguments and records its result.
    label("call_original")
    emit(lw(A0, 0x5E0, SP))
    emit(lw(A1, 0x5DC, SP))
    emit(lw(A2, 0x5D8, SP))
    emit(lw(A3, 0x5D4, SP))
    emit(jal(ORIGINAL_CALLBACK))
    emit(0)
    emit(move(S3, V0))
    branch(0x04, S5, ZERO, "return_original")
    emit(0)

    emit(sw(S3, 0x54, S1))
    emit(ori(S5, S5, 0x80))
    branch(0x04, S0, ZERO, "after_post_snapshot")
    emit(0)
    emit(sw(ZERO, 0x28, SP))
    emit(move(A0, S0))
    emit(addiu(A1, SP, 0x28))
    emit(jal(GET_CURRENT_VIEW))
    emit(0)
    emit(lw(V0, 0x28, SP))
    emit(sw(V0, 0x58, S1))
    emit(lw(V0, 0x150, S0))
    emit(sw(V0, 0x5C, S1))
    emit(lw(V0, 0x298, S0))
    emit(sw(V0, 0x60, S1))
    emit(lw(V0, 0x29C, S0))
    emit(sw(V0, 0x64, S1))
    label("after_post_snapshot")

    emit(addiu(A0, ZERO, 1))
    emit(addiu(A1, S1, 0x68))
    emit(jal(CLOCK_GETTIME_PLT))
    emit(0)
    emit(sw(S5, 0x0C, S1))

    # FD 9 is opened once by the one-shot launcher. One binary write replaces
    # the old snprintf + system("echo ...") diagnostic path.
    emit(addiu(A0, ZERO, 9))
    emit(move(A1, S1))
    emit(addiu(A2, ZERO, RECORD_SIZE))
    emit(jal(WRITE_PLT))
    emit(0)

    label("return_original")
    emit(move(V1, S3))
    emit(lw(S5, 0x5E4, SP))
    emit(lw(S4, 0x5E8, SP))
    emit(lw(S3, 0x5EC, SP))
    emit(lw(S2, 0x5F0, SP))
    emit(lw(S1, 0x5F4, SP))
    emit(lw(S0, 0x5F8, SP))
    emit(lw(RA, 0x5FC, SP))
    emit(addiu(SP, SP, FRAME_SIZE))
    emit(r_type(RA, ZERO, ZERO, 0x08))  # jr ra
    emit(move(V0, V1))

    for index, target, op, rs, rt in fixups:
        if target not in labels:
            raise ValueError(f"undefined label: {target}")
        relative = labels[target] - (index + 1)
        if not -0x8000 <= relative <= 0x7FFF:
            raise ValueError(f"branch out of range: {target}")
        words[index] = i_type(op, rs, rt, relative)

    wrapper = b"".join(struct.pack("<I", word) for word in words)
    if len(wrapper) > CODE_CAVE_CAPACITY:
        raise AssertionError(f"wrapper is too large: {len(wrapper):#x}")
    return wrapper


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    source = args.source.read_bytes()
    source_hash = sha256(source)
    if len(source) != EXPECTED_SIZE:
        raise SystemExit(f"refusing input size {len(source)}; expected {EXPECTED_SIZE}")
    if source_hash != SOURCE_SHA256:
        raise SystemExit(f"refusing input SHA-256 {source_hash}; expected {SOURCE_SHA256}")

    if source[CALLBACK_POINTER_HI_OFFSET:CALLBACK_POINTER_HI_OFFSET + 4] != bytes.fromhex("4e00053c"):
        raise SystemExit("unexpected callback high instruction")
    if source[CALLBACK_POINTER_LO_OFFSET:CALLBACK_POINTER_LO_OFFSET + 4] != bytes.fromhex("a05fa524"):
        raise SystemExit("unexpected callback low instruction")

    wrapper = build_wrapper()
    cave = source[CODE_CAVE_OFFSET:CODE_CAVE_OFFSET + CODE_CAVE_CAPACITY]
    if any(cave):
        raise SystemExit("selected executable padding is not all zero in the golden input")

    patched = bytearray(source)
    # 0x99000000 + sign-extended 0x8040 = 0x988040.
    patched[CALLBACK_POINTER_HI_OFFSET:CALLBACK_POINTER_HI_OFFSET + 4] = bytes.fromhex("9900053c")
    patched[CALLBACK_POINTER_LO_OFFSET:CALLBACK_POINTER_LO_OFFSET + 4] = bytes.fromhex("4080a524")
    patched[CODE_CAVE_OFFSET:CODE_CAVE_OFFSET + len(wrapper)] = wrapper

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(patched)
    print(f"source_sha256={source_hash}")
    print(f"output_sha256={sha256(patched)}")
    print(f"output_size={len(patched)}")
    print(f"wrapper_vaddr={CODE_CAVE_VADDR:#x}")
    print(f"wrapper_size={len(wrapper):#x}")
    print(f"record_size={RECORD_SIZE:#x}")


if __name__ == "__main__":
    main()
