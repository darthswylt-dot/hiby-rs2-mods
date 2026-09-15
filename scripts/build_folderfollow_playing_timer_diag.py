#!/usr/bin/env python3
"""Build a passive diagnostic around the live playing_plane 100 ms timer.

The wrapper calls the original 0x4E90C0 callback first, then records a compact
snapshot of its playing-item/current-view identity comparison and the current
view's list state.  It performs no Folder View or navigation mutation.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path


GOLDEN_SHA256 = "c825a72e1078999f74822846d35c99971f9a660addd5f12d42d50a75f0b9b80e"
RECOVERED_02FD_SHA256 = "02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87"
OLD_UI_TIMER_SHA256 = "32c916ee3762568b06fe05279360b8d2b8f7de5e3ae47be37511e1c44baa3e8a"
EXPECTED_SIZE = 7_133_528

IMAGE_BASE = 0x400000
CALLBACK_POINTER_HI_OFFSET = 0x0EAEBC
CALLBACK_POINTER_LO_OFFSET = 0x0EAECC
OLD_CALLBACK_HI_OFFSET = 0x0E2C5C
OLD_CALLBACK_LO_OFFSET = 0x0E2C64
CODE_CAVE_VADDR = 0x988040
CODE_CAVE_OFFSET = CODE_CAVE_VADDR - IMAGE_BASE
CODE_CAVE_CAPACITY = 0x780

ORIGINAL_CALLBACK = 0x4E90C0
GET_CURRENT_VIEW = 0x4E5680
CLOCK_GETTIME_PLT = 0xA5B380
WRITE_PLT = 0xA5B4A0
MEMSET_PLT = 0xA5BC60

FRAME_SIZE = 0x180
RECORD_OFFSET = 0x20
RECORD_SIZE = 0x100

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
        labels[name] = len(words)

    def beq(rs: int, rt: int, target: str) -> None:
        fixups.append((len(words), target, 0x04, rs, rt))
        emit(0)

    emit(addiu(SP, SP, -FRAME_SIZE))
    for register, offset in (
        (RA, 0x17C), (S0, 0x178), (S1, 0x174), (S2, 0x170),
        (S3, 0x16C), (S4, 0x168), (S5, 0x164),
    ):
        emit(sw(register, offset, SP))
    emit(sw(A0, 0x160, SP))
    emit(sw(A1, 0x15C, SP))

    # Preserve stock behavior and timing priority.
    emit(jal(ORIGINAL_CALLBACK))
    emit(0)
    emit(move(S3, V0))

    emit(addiu(S1, SP, RECORD_OFFSET))
    emit(move(A0, S1))
    emit(move(A1, ZERO))
    emit(addiu(A2, ZERO, RECORD_SIZE))
    emit(jal(MEMSET_PLT))
    emit(0)

    # Header: "PTMR", version 1, fixed record size, stage flags.
    emit(lui(V0, 0x524D))
    emit(ori(V0, V0, 0x5450))
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

    emit(lw(V0, 0x17C, SP))
    emit(sw(V0, 0x18, S1))
    emit(addiu(V0, SP, FRAME_SIZE))
    emit(sw(V0, 0x1C, S1))
    emit(lw(V0, 0x160, SP))
    emit(sw(V0, 0x20, S1))
    emit(lw(S0, 0x15C, SP))
    emit(sw(S0, 0x24, S1))
    emit(sw(S3, 0x28, S1))
    beq(S0, ZERO, "globals")
    emit(0)
    emit(ori(S5, S5, 0x01))

    # playing_plane fields used by 0x4E90C0.
    emit(lw(V0, 0x2C, S0))
    emit(sw(V0, 0x2C, S1))
    beq(V0, ZERO, "after_playing_item")
    emit(0)
    emit(lw(V1, 0x04, V0))
    emit(sw(V1, 0x30, S1))
    emit(ori(S5, S5, 0x02))
    label("after_playing_item")
    emit(lw(V0, 0x30, S0))
    emit(sw(V0, 0x58, S1))
    emit(lw(S2, 0x3C, S0))
    emit(sw(S2, 0x34, S1))
    emit(lw(V0, 0x254, S0))
    emit(sw(V0, 0x5C, S1))
    beq(S2, ZERO, "globals")
    emit(0)
    emit(ori(S5, S5, 0x04))

    # Read the same current view that the stock callback just inspected.
    emit(sw(ZERO, 0x18, SP))
    emit(move(A0, S2))
    emit(addiu(A1, SP, 0x18))
    emit(jal(GET_CURRENT_VIEW))
    emit(0)
    emit(lw(S4, 0x18, SP))
    emit(sw(S4, 0x38, S1))
    beq(S4, ZERO, "globals")
    emit(0)
    emit(ori(S5, S5, 0x08))

    emit(lw(V0, 0xCC, S4))
    emit(sw(V0, 0x3C, S1))
    beq(V0, ZERO, "after_view_item")
    emit(0)
    emit(lw(V1, 0x04, V0))
    emit(sw(V1, 0x40, S1))
    emit(ori(S5, S5, 0x10))
    label("after_view_item")
    emit(lw(V0, 0xD4, S4))
    emit(sw(V0, 0x70, S1))
    emit(lw(V0, 0x78, S4))
    emit(sw(V0, 0x44, S1))
    beq(V0, ZERO, "globals")
    emit(0)
    emit(ori(S5, S5, 0x20))
    for field_offset, record_offset in (
        (0x5A4, 0x48), (0x5A8, 0x4C), (0x5AC, 0x50), (0x5B0, 0x54),
    ):
        emit(lw(V1, field_offset, V0))
        emit(sw(V1, record_offset, S1))

    label("globals")
    emit(lui(V1, 0xB9))
    emit(lw(V0, -0x4534, V1))  # 0xB8BACC
    emit(sw(V0, 0x60, S1))
    emit(lui(V1, 0xAE))
    emit(lw(V0, -0x2CA0, V1))  # 0xADD360
    emit(sw(V0, 0x64, S1))
    emit(lw(V0, -0x2C98, V1))  # 0xADD368
    emit(sw(V0, 0x68, S1))
    emit(lw(V0, -0x2B98, V1))  # first word of property 24 at 0xADD468
    emit(sw(V0, 0x6C, S1))

    emit(sw(S5, 0x0C, S1))
    emit(addiu(A0, ZERO, 9))
    emit(move(A1, S1))
    emit(addiu(A2, ZERO, RECORD_SIZE))
    emit(jal(WRITE_PLT))
    emit(0)

    emit(move(V1, S3))
    for register, offset in (
        (S5, 0x164), (S4, 0x168), (S3, 0x16C), (S2, 0x170),
        (S1, 0x174), (S0, 0x178), (RA, 0x17C),
    ):
        emit(lw(register, offset, SP))
    emit(addiu(SP, SP, FRAME_SIZE))
    emit(r_type(RA, ZERO, ZERO, 0x08))
    emit(move(V0, V1))

    for index, target, op, rs, rt in fixups:
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
    golden = bytearray(source)
    if source_hash == RECOVERED_02FD_SHA256:
        golden[0x0EADB4:0x0EADB8] = bytes.fromhex("4e00053c")
        golden[0x0EADBC:0x0EADC0] = bytes.fromhex("a05fa524")
    elif source_hash == OLD_UI_TIMER_SHA256:
        golden[OLD_CALLBACK_HI_OFFSET:OLD_CALLBACK_HI_OFFSET + 4] = bytes.fromhex("4e00023c")
        golden[OLD_CALLBACK_LO_OFFSET:OLD_CALLBACK_LO_OFFSET + 4] = bytes.fromhex("c0244224")
    else:
        raise SystemExit(f"refusing input SHA-256 {source_hash}")
    golden[CODE_CAVE_OFFSET:CODE_CAVE_OFFSET + CODE_CAVE_CAPACITY] = b"\0" * CODE_CAVE_CAPACITY
    if sha256(golden) != GOLDEN_SHA256:
        raise SystemExit("normalization did not reproduce the golden binary")
    return bytes(golden), source_hash


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    source = args.source.read_bytes()
    if len(source) != EXPECTED_SIZE:
        raise SystemExit(f"refusing input size {len(source)}; expected {EXPECTED_SIZE}")
    golden, source_hash = normalize_source(source)
    if golden[CALLBACK_POINTER_HI_OFFSET:CALLBACK_POINTER_HI_OFFSET + 4] != bytes.fromhex("4f00063c"):
        raise SystemExit("unexpected playing timer callback LUI")
    if golden[CALLBACK_POINTER_LO_OFFSET:CALLBACK_POINTER_LO_OFFSET + 4] != bytes.fromhex("c090c624"):
        raise SystemExit("unexpected playing timer callback ADDIU")
    if any(golden[CODE_CAVE_OFFSET:CODE_CAVE_OFFSET + CODE_CAVE_CAPACITY]):
        raise SystemExit("selected cave is not empty in normalized golden input")

    wrapper = build_wrapper()
    patched = bytearray(golden)
    patched[CALLBACK_POINTER_HI_OFFSET:CALLBACK_POINTER_HI_OFFSET + 4] = bytes.fromhex("9900063c")
    patched[CALLBACK_POINTER_LO_OFFSET:CALLBACK_POINTER_LO_OFFSET + 4] = bytes.fromhex("4080c624")
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
