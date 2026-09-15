#!/usr/bin/env python3
"""Build passive path telemetry around the live 0x4E90C0 UI timer."""

from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path


GOLDEN_SHA256 = "c825a72e1078999f74822846d35c99971f9a660addd5f12d42d50a75f0b9b80e"
OLD_PLAYING_TIMER_SHA256 = "4927297b4ceebe3b7f8d4bb8854c632e2083d5212aa9f02c9182c9f213acf3fe"
EXPECTED_SIZE = 7_133_528

IMAGE_BASE = 0x400000
CALLBACK_HI_OFFSET = 0x0EAEBC
CALLBACK_LO_OFFSET = 0x0EAECC
CAVE_VADDR = 0x988040
CAVE_OFFSET = CAVE_VADDR - IMAGE_BASE
CAVE_CAPACITY = 0x780

ORIGINAL_CALLBACK = 0x4E90C0
GET_CURRENT_VIEW = 0x4E5680
COUNT_VIEWS_BY_TYPE = 0x438BE0
FIND_LAST_VIEW_BY_TYPE = 0x4E57E0
WIDE_COPY = 0x41FB80
CLOCK_GETTIME_PLT = 0xA5B380
WRITE_PLT = 0xA5B4A0
MEMSET_PLT = 0xA5BC60
EXPLORER_VIEW_TYPE = 0x922704

FRAME_SIZE = 0x600
RECORD_OFFSET = 0x40
RECORD_SIZE = 0x4A0
PLAYBACK_PATH_OFFSET = 0x80
FOLDER_PATH_OFFSET = 0x288

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
        (RA, 0x5FC), (S0, 0x5F8), (S1, 0x5F4), (S2, 0x5F0),
        (S3, 0x5EC), (S4, 0x5E8), (S5, 0x5E4),
    ):
        emit(sw(register, offset, SP))
    emit(sw(A0, 0x5E0, SP))
    emit(sw(A1, 0x5DC, SP))

    # Stock behavior always runs first.
    emit(jal(ORIGINAL_CALLBACK))
    emit(0)
    emit(move(S3, V0))

    emit(addiu(S1, SP, RECORD_OFFSET))
    emit(move(A0, S1))
    emit(move(A1, ZERO))
    emit(addiu(A2, ZERO, RECORD_SIZE))
    emit(jal(MEMSET_PLT))
    emit(0)

    # "PPTH", version 1, record size, stage flags.
    emit(lui(V0, 0x4854))
    emit(ori(V0, V0, 0x5050))
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

    emit(lw(V0, 0x5FC, SP))
    emit(sw(V0, 0x18, S1))
    emit(addiu(V0, SP, FRAME_SIZE))
    emit(sw(V0, 0x1C, S1))
    emit(lw(V0, 0x5E0, SP))
    emit(sw(V0, 0x20, S1))
    emit(lw(S0, 0x5DC, SP))
    emit(sw(S0, 0x24, S1))
    emit(sw(S3, 0x28, S1))
    beq(S0, ZERO, "globals")
    emit(0)
    emit(ori(S5, S5, 0x01))

    emit(lw(V0, 0x2C, S0))
    emit(sw(V0, 0x2C, S1))
    emit(lw(S2, 0x3C, S0))
    emit(sw(S2, 0x30, S1))
    emit(lw(V0, 0x30, S0))
    emit(sw(V0, 0x34, S1))
    emit(lw(V0, 0x254, S0))
    emit(sw(V0, 0x38, S1))
    beq(S2, ZERO, "globals")
    emit(0)
    emit(ori(S5, S5, 0x02))

    # Read-only controller fields used by the stock locked cleanup path.
    for controller_offset, record_offset in (
        (0x34, 0x3C), (0x150, 0x40), (0x274, 0x44), (0x278, 0x48),
    ):
        emit(lw(V0, controller_offset, S2))
        emit(sw(V0, record_offset, S1))

    emit(sw(ZERO, 0x20, SP))
    emit(move(A0, S2))
    emit(addiu(A1, SP, 0x20))
    emit(jal(GET_CURRENT_VIEW))
    emit(0)
    emit(lw(S4, 0x20, SP))
    emit(sw(S4, 0x4C, S1))
    beq(S4, ZERO, "after_current")
    emit(0)
    emit(ori(S5, S5, 0x04))
    emit(lw(V0, 0xD4, S4))
    emit(sw(V0, 0x50, S1))
    label("after_current")

    emit(lui(S4, EXPLORER_VIEW_TYPE >> 16))
    emit(addiu(S4, S4, EXPLORER_VIEW_TYPE & 0xFFFF))
    emit(move(A0, S2))
    emit(move(A1, S4))
    emit(jal(COUNT_VIEWS_BY_TYPE))
    emit(0)
    emit(sw(V0, 0x54, S1))
    emit(ori(S5, S5, 0x08))

    emit(sw(ZERO, 0x24, SP))
    emit(move(A0, S2))
    emit(move(A1, S4))
    emit(addiu(A2, SP, 0x24))
    emit(jal(FIND_LAST_VIEW_BY_TYPE))
    emit(0)
    emit(lw(S4, 0x24, SP))
    emit(sw(S4, 0x58, S1))
    beq(S4, ZERO, "globals")
    emit(0)
    emit(ori(S5, S5, 0x10))
    emit(lw(V0, 0x3DCC, S4))
    emit(sw(V0, 0x5C, S1))
    emit(addiu(A0, S1, FOLDER_PATH_OFFSET))
    emit(addiu(A1, S4, 0x3DD8))
    emit(addiu(A2, ZERO, 0x103))
    emit(jal(WIDE_COPY))
    emit(0)

    label("globals")
    emit(lui(V1, 0xB9))
    emit(lw(V0, -0x4534, V1))  # 0xB8BACC playing_plane
    emit(sw(V0, 0x60, S1))
    emit(lw(V0, -0x4538, V1))  # 0xB8BAC8 lg_activity_main
    emit(sw(V0, 0x64, S1))
    emit(lui(V1, 0xAE))
    emit(lw(V0, -0x2B98, V1))  # property 24 word 0 at 0xADD468
    emit(sw(V0, 0x68, S1))
    emit(addiu(S4, V1, -0x2B94))  # property 24 path at 0xADD46C
    emit(sw(S4, 0x6C, S1))
    emit(addiu(A0, S1, PLAYBACK_PATH_OFFSET))
    emit(move(A1, S4))
    emit(addiu(A2, ZERO, 0x103))
    emit(jal(WIDE_COPY))
    emit(0)
    emit(ori(S5, S5, 0x20))

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
        relative = labels[target] - (index + 1)
        if not -0x8000 <= relative <= 0x7FFF:
            raise ValueError(f"branch out of range: {target}")
        words[index] = i_type(op, rs, rt, relative)

    wrapper = b"".join(struct.pack("<I", word) for word in words)
    if len(wrapper) > CAVE_CAPACITY:
        raise AssertionError(f"wrapper is too large: {len(wrapper):#x}")
    return wrapper


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize_source(source: bytes) -> tuple[bytes, str]:
    digest = sha256(source)
    if digest == GOLDEN_SHA256:
        return source, digest
    if digest != OLD_PLAYING_TIMER_SHA256:
        raise SystemExit(f"refusing input SHA-256 {digest}")
    golden = bytearray(source)
    golden[CALLBACK_HI_OFFSET:CALLBACK_HI_OFFSET + 4] = bytes.fromhex("4f00063c")
    golden[CALLBACK_LO_OFFSET:CALLBACK_LO_OFFSET + 4] = bytes.fromhex("c090c624")
    golden[CAVE_OFFSET:CAVE_OFFSET + CAVE_CAPACITY] = b"\0" * CAVE_CAPACITY
    if sha256(golden) != GOLDEN_SHA256:
        raise SystemExit("normalization did not reproduce golden")
    return bytes(golden), digest


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    source = args.source.read_bytes()
    if len(source) != EXPECTED_SIZE:
        raise SystemExit(f"refusing input size {len(source)}")
    golden, source_hash = normalize_source(source)
    wrapper = build_wrapper()
    patched = bytearray(golden)
    patched[CALLBACK_HI_OFFSET:CALLBACK_HI_OFFSET + 4] = bytes.fromhex("9900063c")
    patched[CALLBACK_LO_OFFSET:CALLBACK_LO_OFFSET + 4] = bytes.fromhex("4080c624")
    patched[CAVE_OFFSET:CAVE_OFFSET + len(wrapper)] = wrapper
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(patched)
    print(f"input_sha256={source_hash}")
    print(f"golden_sha256={sha256(golden)}")
    print(f"output_sha256={sha256(patched)}")
    print(f"output_size={len(patched)}")
    print(f"wrapper_vaddr={CAVE_VADDR:#x}")
    print(f"wrapper_size={len(wrapper):#x}")
    print(f"record_size={RECORD_SIZE:#x}")


if __name__ == "__main__":
    main()
