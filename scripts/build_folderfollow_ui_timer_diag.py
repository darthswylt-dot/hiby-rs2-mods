#!/usr/bin/env python3
"""Build a passive Folder View UI-timer diagnostic for the HiBy RS2.

The wrapper replaces only the third callback pointer installed by 0x4E2C40.
It calls the original 0x4E24C0 UI-timer callback first, then records read-only
navigation state and bounded UTF-16 property-24/Folder View paths to inherited
file descriptor 9.  It never calls 0x4E4B80, a view builder, or a navigation
mutator.
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
CALLBACK_POINTER_HI_OFFSET = 0x0E2C5C
CALLBACK_POINTER_LO_OFFSET = 0x0E2C64
CODE_CAVE_VADDR = 0x988040
CODE_CAVE_OFFSET = CODE_CAVE_VADDR - IMAGE_BASE
CODE_CAVE_CAPACITY = 0x780

ORIGINAL_CALLBACK = 0x4E24C0
GET_CURRENT_VIEW = 0x4E5680
COUNT_VIEWS_BY_TYPE = 0x438BE0
FIND_LAST_VIEW_BY_TYPE = 0x4E57E0
WIDE_COPY = 0x41FB80
CLOCK_GETTIME_PLT = 0xA5B380
WRITE_PLT = 0xA5B4A0
MEMSET_PLT = 0xA5BC60
EXPLORER_VIEW_TYPE = 0x922704
PROPERTY24_PATH = 0xADD46C

FRAME_SIZE = 0x600
RECORD_OFFSET = 0x40
RECORD_SIZE = 0x4A0
PLAYBACK_PATH_OFFSET = 0x80
FOLDER_PATH_OFFSET = 0x288

# MIPS o32 registers.
ZERO, V0, V1, A0, A1, A2 = 0, 2, 3, 4, 5, 6
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

    emit(addiu(SP, SP, -FRAME_SIZE))
    for register, offset in (
        (RA, 0x5FC), (S0, 0x5F8), (S1, 0x5F4), (S2, 0x5F0),
        (S3, 0x5EC), (S4, 0x5E8), (S5, 0x5E4),
    ):
        emit(sw(register, offset, SP))
    emit(sw(A0, 0x5E0, SP))
    emit(sw(A1, 0x5DC, SP))

    # Preserve stock timing and behavior: run the original callback first.
    emit(jal(ORIGINAL_CALLBACK))
    emit(0)
    emit(move(S3, V0))

    emit(addiu(S1, SP, RECORD_OFFSET))
    emit(move(A0, S1))
    emit(move(A1, ZERO))
    emit(addiu(A2, ZERO, RECORD_SIZE))
    emit(jal(MEMSET_PLT))
    emit(0)

    # Header: "FTMR", version 1, fixed record size, stage flags.
    emit(lui(V0, 0x524D))
    emit(ori(V0, V0, 0x5446))
    emit(sw(V0, 0x00, S1))
    emit(addiu(V0, ZERO, 1))
    emit(sw(V0, 0x04, S1))
    emit(addiu(V0, ZERO, RECORD_SIZE))
    emit(sw(V0, 0x08, S1))
    emit(move(S5, ZERO))

    emit(addiu(A0, ZERO, 1))
    emit(addiu(A1, S1, 0x10))
    emit(jal(CLOCK_GETTIME_PLT))
    emit(0)

    # Callback ABI and generic container fields after the stock timer callback.
    emit(lw(V0, 0x5FC, SP))
    emit(sw(V0, 0x18, S1))
    emit(addiu(V0, SP, FRAME_SIZE))
    emit(sw(V0, 0x1C, S1))
    emit(lw(S0, 0x5E0, SP))
    emit(lw(S4, 0x5DC, SP))
    emit(sw(S0, 0x20, S1))
    emit(sw(S4, 0x24, S1))
    emit(sw(S3, 0x28, S1))
    branch(0x04, S0, ZERO, "write_record")
    emit(0)
    emit(ori(S5, S5, 0x01))
    for object_offset, record_offset in (
        (0x20, 0x2C), (0x3C, 0x30), (0x40, 0x34), (0x48, 0x38),
        (0x50, 0x3C), (0x54, 0x40), (0x58, 0x44), (0x5C, 0x48),
    ):
        emit(lw(V0, object_offset, S0))
        emit(sw(V0, record_offset, S1))

    # The constructor and 0x4E2920 establish object+0x48 as the explorer owner.
    emit(lw(S2, 0x48, S0))
    branch(0x04, S2, ZERO, "write_record")
    emit(0)
    emit(ori(S5, S5, 0x02))
    for explorer_offset, record_offset in (
        (0x150, 0x4C), (0x298, 0x50), (0x29C, 0x54),
    ):
        emit(lw(V0, explorer_offset, S2))
        emit(sw(V0, record_offset, S1))

    # Optional 12-byte state allocated by 0x4E2C40 and stored at object+0x58.
    emit(lw(S4, 0x58, S0))
    branch(0x04, S4, ZERO, "after_state")
    emit(0)
    emit(ori(S5, S5, 0x04))
    for state_offset, record_offset in ((0, 0x58), (4, 0x5C), (8, 0x60)):
        emit(lw(V0, state_offset, S4))
        emit(sw(V0, record_offset, S1))
    label("after_state")

    # Copy the proven current property-24 path directly. Unlike 0x4E4B80 this
    # has no synchronization/finalization side effects.
    emit(lui(S4, 0xAE))
    emit(addiu(S4, S4, -0x2B94))  # 0xADD46C
    emit(addiu(A0, S1, PLAYBACK_PATH_OFFSET))
    emit(move(A1, S4))
    emit(addiu(A2, ZERO, 0x103))
    emit(jal(WIDE_COPY))
    emit(0)
    emit(sw(S4, 0x64, S1))
    emit(ori(S5, S5, 0x08))

    emit(sw(ZERO, 0x20, SP))
    emit(move(A0, S2))
    emit(addiu(A1, SP, 0x20))
    emit(jal(GET_CURRENT_VIEW))
    emit(0)
    emit(lw(V0, 0x20, SP))
    emit(sw(V0, 0x68, S1))
    branch(0x04, V0, ZERO, "after_current_view")
    emit(0)
    emit(ori(S5, S5, 0x10))
    label("after_current_view")

    emit(lui(S4, EXPLORER_VIEW_TYPE >> 16))
    emit(addiu(S4, S4, EXPLORER_VIEW_TYPE & 0xFFFF))
    emit(move(A0, S2))
    emit(move(A1, S4))
    emit(jal(COUNT_VIEWS_BY_TYPE))
    emit(0)
    emit(sw(V0, 0x6C, S1))
    emit(ori(S5, S5, 0x20))

    emit(sw(ZERO, 0x24, SP))
    emit(move(A0, S2))
    emit(move(A1, S4))
    emit(addiu(A2, SP, 0x24))
    emit(jal(FIND_LAST_VIEW_BY_TYPE))
    emit(0)
    emit(lw(V0, 0x24, SP))
    emit(sw(V0, 0x70, S1))
    branch(0x04, V0, ZERO, "write_record")
    emit(0)
    emit(ori(S5, S5, 0x40))
    emit(addiu(A0, S1, FOLDER_PATH_OFFSET))
    emit(addiu(A1, V0, 0x3DD8))
    emit(addiu(A2, ZERO, 0x103))
    emit(jal(WIDE_COPY))
    emit(0)

    label("write_record")
    emit(sw(S5, 0x0C, S1))
    emit(addiu(A0, ZERO, 9))
    emit(move(A1, S1))
    emit(addiu(A2, ZERO, RECORD_SIZE))
    emit(jal(WRITE_PLT))
    emit(0)

    emit(move(V1, S3))
    for register, offset in (
        (S5, 0x5E4), (S4, 0x5E8), (S3, 0x5EC), (S2, 0x5F0),
        (S1, 0x5F4), (S0, 0x5F8), (RA, 0x5FC),
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
    # Remove only the recovered 02fd diagnostic hook and its private cave.
    golden[0x0EADB4:0x0EADB8] = bytes.fromhex("4e00053c")
    golden[0x0EADBC:0x0EADC0] = bytes.fromhex("a05fa524")
    golden[CODE_CAVE_OFFSET:CODE_CAVE_OFFSET + CODE_CAVE_CAPACITY] = b"\0" * CODE_CAVE_CAPACITY
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
    if golden[CALLBACK_POINTER_HI_OFFSET:CALLBACK_POINTER_HI_OFFSET + 4] != bytes.fromhex("4e00023c"):
        raise SystemExit("unexpected third-callback LUI")
    if golden[CALLBACK_POINTER_LO_OFFSET:CALLBACK_POINTER_LO_OFFSET + 4] != bytes.fromhex("c0244224"):
        raise SystemExit("unexpected third-callback ADDIU")
    if any(golden[CODE_CAVE_OFFSET:CODE_CAVE_OFFSET + CODE_CAVE_CAPACITY]):
        raise SystemExit("selected cave is not empty in normalized golden input")

    wrapper = build_wrapper()
    patched = bytearray(golden)
    patched[CALLBACK_POINTER_HI_OFFSET:CALLBACK_POINTER_HI_OFFSET + 4] = bytes.fromhex("9900023c")
    patched[CALLBACK_POINTER_LO_OFFSET:CALLBACK_POINTER_LO_OFFSET + 4] = bytes.fromhex("40804224")
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
