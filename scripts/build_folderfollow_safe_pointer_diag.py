#!/usr/bin/env python3
"""Build the crash-resistant RS2 folder-follow pointer diagnostic.

The wrapper appends a durable pointer-only record before the original callback
and a second copy after it. It never dereferences the candidate +0x230 path
pointer and performs no explorer/view mutation.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path


GOLDEN_SHA256 = "c825a72e1078999f74822846d35c99971f9a660addd5f12d42d50a75f0b9b80e"
RECOVERED_02FD_SHA256 = "02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87"
EXPECTED_SIZE = 7_133_528

IMAGE_BASE = 0x400000
CALLBACK_POINTER_HI_OFFSET = 0x0EADB4
CALLBACK_POINTER_LO_OFFSET = 0x0EADBC
CODE_CAVE_VADDR = 0x988040
CODE_CAVE_OFFSET = CODE_CAVE_VADDR - IMAGE_BASE
CODE_CAVE_CAPACITY = 0x780

ORIGINAL_CALLBACK = 0x4E5FA0
GET_PLAYER_CONTEXT = 0x459340
GET_CURRENT_VIEW = 0x4E5680
COUNT_VIEWS_BY_TYPE = 0x438BE0
FIND_LAST_VIEW_BY_TYPE = 0x4E57E0
CLOCK_GETTIME_PLT = 0xA5B380
WRITE_PLT = 0xA5B4A0
MEMSET_PLT = 0xA5BC60
EXPLORER_VIEW_TYPE = 0x922704

FRAME_SIZE = 0x180
RECORD_OFFSET = 0x40
RECORD_SIZE = 0x100

# MIPS o32 registers.
ZERO, V0, V1, A0, A1, A2, A3 = 0, 2, 3, 4, 5, 6, 7
S0, S1, S2, S3, S4, S5, S6, SP, RA = 16, 17, 18, 19, 20, 21, 22, 29, 31


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

    # Private frame with ABI saves, two helper output slots, and one record.
    emit(addiu(SP, SP, -FRAME_SIZE))
    for register, offset in (
        (RA, 0x17C), (S0, 0x178), (S1, 0x174), (S2, 0x170),
        (S3, 0x16C), (S4, 0x168), (S5, 0x164), (S6, 0x160),
        (A0, 0x15C), (A1, 0x158), (A2, 0x154), (A3, 0x150),
    ):
        emit(sw(register, offset, SP))
    for register in (S0, S1, S2, S3, S4, S5, S6):
        emit(move(register, ZERO))

    # Non-target events remain a transparent pass-through.
    emit(addiu(V0, ZERO, 1))
    branch(0x05, A2, V0, "call_original")
    emit(0)
    branch(0x05, A3, V0, "call_original")
    emit(0)

    emit(addiu(S5, ZERO, 0x0001))
    emit(addiu(S1, SP, RECORD_OFFSET))
    emit(move(A0, S1))
    emit(move(A1, ZERO))
    emit(addiu(A2, ZERO, RECORD_SIZE))
    emit(jal(MEMSET_PLT))
    emit(0)

    # Header: FFSP, version, size, phase=1, stage bits.
    emit(lui(V0, 0x5053))
    emit(ori(V0, V0, 0x4646))
    emit(sw(V0, 0x00, S1))
    emit(addiu(V0, ZERO, 1))
    emit(sw(V0, 0x04, S1))
    emit(addiu(V0, ZERO, RECORD_SIZE))
    emit(sw(V0, 0x08, S1))
    emit(addiu(V0, ZERO, 1))
    emit(sw(V0, 0x0C, S1))

    emit(addiu(A0, ZERO, 1))
    emit(addiu(A1, S1, 0x18))
    emit(jal(CLOCK_GETTIME_PLT))
    emit(0)
    emit(lw(V0, 0x17C, SP))
    emit(sw(V0, 0x28, S1))
    emit(addiu(V0, SP, FRAME_SIZE))
    emit(sw(V0, 0x2C, S1))
    for saved_offset, record_offset in (
        (0x15C, 0x30), (0x158, 0x34), (0x154, 0x38), (0x150, 0x3C)
    ):
        emit(lw(V0, saved_offset, SP))
        emit(sw(V0, record_offset, S1))

    # Raw candidate source fields. +0x230 is recorded but never dereferenced.
    emit(lui(V0, 0x00AE))
    emit(lw(S0, -0x2CA0, V0))  # *(0xADD360)
    emit(sw(S0, 0x40, S1))
    branch(0x04, S0, ZERO, "after_source_before")
    emit(0)
    emit(ori(S5, S5, 0x0002))
    for source_offset, record_offset in (
        (0x24, 0x44), (0x230, 0x48), (0x414, 0x4C), (0x730, 0x50)
    ):
        emit(lw(V0, source_offset, S0))
        emit(sw(V0, record_offset, S1))
    label("after_source_before")
    emit(lui(V1, 0x00A9))
    emit(lw(V0, 0x2744, V1))
    emit(sw(V0, 0x54, S1))

    # Proven read-only explorer probes, before callback.
    emit(lw(A0, 0x15C, SP))
    emit(jal(GET_PLAYER_CONTEXT))
    emit(0)
    emit(move(S4, V0))
    emit(sw(S4, 0x58, S1))
    branch(0x04, S4, ZERO, "write_pre")
    emit(0)
    emit(ori(S5, S5, 0x0004))
    emit(lw(S2, 0x3C, S4))
    emit(sw(S2, 0x5C, S1))
    branch(0x04, S2, ZERO, "write_pre")
    emit(0)
    emit(ori(S5, S5, 0x0008))
    for explorer_offset, record_offset in (
        (0x150, 0x6C), (0x298, 0x70), (0x29C, 0x74)
    ):
        emit(lw(V0, explorer_offset, S2))
        emit(sw(V0, record_offset, S1))

    emit(sw(ZERO, 0x20, SP))
    emit(move(A0, S2))
    emit(addiu(A1, SP, 0x20))
    emit(jal(GET_CURRENT_VIEW))
    emit(0)
    emit(lw(V0, 0x20, SP))
    emit(sw(V0, 0x60, S1))
    branch(0x04, V0, ZERO, "after_current_before")
    emit(0)
    emit(ori(S5, S5, 0x0010))
    label("after_current_before")

    emit(lui(S6, EXPLORER_VIEW_TYPE >> 16))
    emit(addiu(S6, S6, EXPLORER_VIEW_TYPE & 0xFFFF))
    emit(move(A0, S2))
    emit(move(A1, S6))
    emit(jal(COUNT_VIEWS_BY_TYPE))
    emit(0)
    emit(sw(V0, 0x68, S1))
    emit(sw(ZERO, 0x24, SP))
    emit(move(A0, S2))
    emit(move(A1, S6))
    emit(addiu(A2, SP, 0x24))
    emit(jal(FIND_LAST_VIEW_BY_TYPE))
    emit(0)
    emit(lw(V0, 0x24, SP))
    emit(sw(V0, 0x64, S1))
    branch(0x04, V0, ZERO, "write_pre")
    emit(0)
    emit(ori(S5, S5, 0x0020))

    label("write_pre")
    emit(ori(S5, S5, 0x0040))
    emit(sw(S5, 0x10, S1))
    emit(addiu(A0, ZERO, 9))
    emit(move(A1, S1))
    emit(addiu(A2, ZERO, RECORD_SIZE))
    emit(jal(WRITE_PLT))
    emit(0)
    emit(sw(V0, 0xAC, S1))
    emit(addiu(V1, ZERO, RECORD_SIZE))
    branch(0x05, V0, V1, "call_original")
    emit(0)
    emit(ori(S5, S5, 0x0080))

    label("call_original")
    emit(lw(A0, 0x15C, SP))
    emit(lw(A1, 0x158, SP))
    emit(lw(A2, 0x154, SP))
    emit(lw(A3, 0x150, SP))
    emit(jal(ORIGINAL_CALLBACK))
    emit(0)
    emit(move(S3, V0))
    branch(0x04, S5, ZERO, "return_original")
    emit(0)
    emit(sw(S3, 0x78, S1))
    emit(ori(S5, S5, 0x0100))

    # Post-callback raw fields. Again, +0x230 is a value only.
    emit(lui(V0, 0x00AE))
    emit(lw(S0, -0x2CA0, V0))
    emit(sw(S0, 0x7C, S1))
    branch(0x04, S0, ZERO, "after_source_after")
    emit(0)
    emit(ori(S5, S5, 0x0200))
    for source_offset, record_offset in (
        (0x24, 0x80), (0x230, 0x84), (0x414, 0x88), (0x730, 0x8C)
    ):
        emit(lw(V0, source_offset, S0))
        emit(sw(V0, record_offset, S1))
    label("after_source_after")
    emit(lui(V1, 0x00A9))
    emit(lw(V0, 0x2744, V1))
    emit(sw(V0, 0x90, S1))

    emit(lw(A0, 0x15C, SP))
    emit(jal(GET_PLAYER_CONTEXT))
    emit(0)
    emit(move(S4, V0))
    emit(sw(S4, 0xB0, S1))
    branch(0x04, S4, ZERO, "write_post")
    emit(0)
    emit(ori(S5, S5, 0x0400))
    emit(lw(S2, 0x3C, S4))
    emit(sw(S2, 0xB4, S1))
    branch(0x04, S2, ZERO, "write_post")
    emit(0)
    emit(ori(S5, S5, 0x0800))
    for explorer_offset, record_offset in (
        (0x150, 0xA0), (0x298, 0xA4), (0x29C, 0xA8)
    ):
        emit(lw(V0, explorer_offset, S2))
        emit(sw(V0, record_offset, S1))

    emit(sw(ZERO, 0x20, SP))
    emit(move(A0, S2))
    emit(addiu(A1, SP, 0x20))
    emit(jal(GET_CURRENT_VIEW))
    emit(0)
    emit(lw(V0, 0x20, SP))
    emit(sw(V0, 0x94, S1))
    branch(0x04, V0, ZERO, "after_current_after")
    emit(0)
    emit(ori(S5, S5, 0x1000))
    label("after_current_after")

    emit(lui(S6, EXPLORER_VIEW_TYPE >> 16))
    emit(addiu(S6, S6, EXPLORER_VIEW_TYPE & 0xFFFF))
    emit(move(A0, S2))
    emit(move(A1, S6))
    emit(jal(COUNT_VIEWS_BY_TYPE))
    emit(0)
    emit(sw(V0, 0x9C, S1))
    emit(sw(ZERO, 0x24, SP))
    emit(move(A0, S2))
    emit(move(A1, S6))
    emit(addiu(A2, SP, 0x24))
    emit(jal(FIND_LAST_VIEW_BY_TYPE))
    emit(0)
    emit(lw(V0, 0x24, SP))
    emit(sw(V0, 0x98, S1))
    branch(0x04, V0, ZERO, "write_post")
    emit(0)
    emit(ori(S5, S5, 0x2000))

    label("write_post")
    emit(ori(S5, S5, 0x4000))
    emit(addiu(A0, ZERO, 1))
    emit(addiu(A1, S1, 0x20))
    emit(jal(CLOCK_GETTIME_PLT))
    emit(0)
    emit(addiu(V0, ZERO, 2))
    emit(sw(V0, 0x0C, S1))
    emit(sw(S5, 0x10, S1))
    emit(addiu(A0, ZERO, 9))
    emit(move(A1, S1))
    emit(addiu(A2, ZERO, RECORD_SIZE))
    emit(jal(WRITE_PLT))
    emit(0)

    label("return_original")
    emit(move(V1, S3))
    for register, offset in (
        (S6, 0x160), (S5, 0x164), (S4, 0x168), (S3, 0x16C),
        (S2, 0x170), (S1, 0x174), (S0, 0x178), (RA, 0x17C),
    ):
        emit(lw(register, offset, SP))
    emit(addiu(SP, SP, FRAME_SIZE))
    emit(r_type(RA, ZERO, ZERO, 0x08))
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


def normalize_source(source: bytes) -> tuple[bytes, str]:
    source_hash = sha256(source)
    if source_hash == GOLDEN_SHA256:
        return source, source_hash
    if source_hash != RECOVERED_02FD_SHA256:
        raise SystemExit(f"refusing input SHA-256 {source_hash}")

    golden = bytearray(source)
    golden[CALLBACK_POINTER_HI_OFFSET:CALLBACK_POINTER_HI_OFFSET + 4] = bytes.fromhex(
        "4e00053c"
    )
    golden[CALLBACK_POINTER_LO_OFFSET:CALLBACK_POINTER_LO_OFFSET + 4] = bytes.fromhex(
        "a05fa524"
    )
    golden[CODE_CAVE_OFFSET:CODE_CAVE_OFFSET + CODE_CAVE_CAPACITY] = (
        b"\0" * CODE_CAVE_CAPACITY
    )
    normalized = bytes(golden)
    if sha256(normalized) != GOLDEN_SHA256:
        raise SystemExit("02fd normalization did not reproduce the golden binary")
    return normalized, source_hash


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    source = args.source.read_bytes()
    if len(source) != EXPECTED_SIZE:
        raise SystemExit(f"refusing input size {len(source)}; expected {EXPECTED_SIZE}")
    golden, source_hash = normalize_source(source)
    if any(golden[CODE_CAVE_OFFSET:CODE_CAVE_OFFSET + CODE_CAVE_CAPACITY]):
        raise SystemExit("selected cave is not empty in normalized golden input")

    wrapper = build_wrapper()
    patched = bytearray(golden)
    patched[CALLBACK_POINTER_HI_OFFSET:CALLBACK_POINTER_HI_OFFSET + 4] = bytes.fromhex(
        "9900053c"
    )
    patched[CALLBACK_POINTER_LO_OFFSET:CALLBACK_POINTER_LO_OFFSET + 4] = bytes.fromhex(
        "4080a524"
    )
    patched[CODE_CAVE_OFFSET:CODE_CAVE_OFFSET + len(wrapper)] = wrapper

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(patched)
    print(f"input_sha256={source_hash}")
    print(f"golden_sha256={sha256(golden)}")
    print(f"output_sha256={sha256(patched)}")
    print(f"output_size={len(patched)}")
    print(f"wrapper_vaddr={CODE_CAVE_VADDR:#x}")
    print(f"wrapper_size={len(wrapper):#x}")
    print(f"record_size={RECORD_SIZE:#x}")


if __name__ == "__main__":
    main()
