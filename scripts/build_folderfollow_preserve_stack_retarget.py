#!/usr/bin/env python3
"""Build the RS2 non-destructive folder-follow retarget test.

The input must be the hardware-validated firmware 1.4 sort/fullnav/wake binary.
Only the Now Playing gesture callback pointer and an unused executable code cave
are changed. The wrapper follows the stock existing-view reuse path and never
destroys or constructs explorer views. No proprietary binary is stored here.
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
CODE_CAVE_VADDR = 0x91FAB0
CODE_CAVE_OFFSET = CODE_CAVE_VADDR - IMAGE_BASE

ORIGINAL_CALLBACK = 0x4E5FA0
GET_PLAYER_CONTEXT = 0x459340
GET_CURRENT_PATH = 0x4E4B80
GET_CURRENT_VIEW = 0x4E5680
PREPARE_CURRENT_VIEW = 0x4916A0
COUNT_VIEWS_BY_TYPE = 0x438BE0
FIND_LAST_VIEW_BY_TYPE = 0x4E57E0
RETARGET_EXISTING_VIEW = 0x4919E0
MEMSET_PLT = 0xA5BC60
EXPLORER_VIEW_TYPE = 0x922704  # "vg_listview_explorer"

ZERO, V0, A0, A1, A2, A3, S0, S1, S2, SP, RA = 0, 2, 4, 5, 6, 7, 16, 17, 18, 29, 31


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


def lui(rt: int, immediate: int) -> int:
    return i_type(0x0F, ZERO, rt, immediate)


def lw(rt: int, offset: int, base: int) -> int:
    return i_type(0x23, base, rt, offset)


def sw(rt: int, offset: int, base: int) -> int:
    return i_type(0x2B, base, rt, offset)


def move(rd: int, rs: int) -> int:
    return r_type(rs, ZERO, rd, 0x21)


def slti(rt: int, rs: int, immediate: int) -> int:
    return i_type(0x0A, rs, rt, immediate)


def jal(target: int) -> int:
    return j_type(0x03, target)


def jump(target: int) -> int:
    return j_type(0x02, target)


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

    # Keep the callback ABI intact. The 0x208-byte path and view output live in
    # this private frame and are gone before the stock callback is tail-called.
    emit(addiu(SP, SP, -0x360))
    emit(sw(RA, 0x35C, SP))
    emit(sw(S0, 0x358, SP))
    emit(sw(S1, 0x354, SP))
    emit(sw(S2, 0x350, SP))
    emit(sw(A0, 0x34C, SP))
    emit(sw(A1, 0x348, SP))
    emit(sw(A2, 0x344, SP))
    emit(sw(A3, 0x340, SP))

    # Only the Folder View return gesture is eligible. Everything else is a
    # byte-for-byte-equivalent pass-through to the original callback.
    emit(addiu(V0, ZERO, 1))
    branch(0x05, A2, V0, "call_original")
    emit(0)
    branch(0x05, A3, V0, "call_original")
    emit(0)

    emit(jal(GET_PLAYER_CONTEXT))
    emit(0)
    branch(0x04, V0, ZERO, "call_original")
    emit(0)
    emit(lw(S0, 0x3C, V0))
    branch(0x04, S0, ZERO, "call_original")
    emit(0)

    emit(addiu(A0, SP, 0x40))
    emit(move(A1, ZERO))
    emit(addiu(A2, ZERO, 0x208))
    emit(jal(MEMSET_PLT))
    emit(0)

    emit(move(A0, S0))
    emit(addiu(A1, SP, 0x40))
    emit(jal(GET_CURRENT_PATH))
    emit(0)
    emit(addiu(S1, ZERO, -1))
    branch(0x04, V0, S1, "call_original")
    emit(0)

    # Match the preparation performed at the start of stock 0x491E80.
    emit(sw(ZERO, 0x30, SP))
    emit(move(A0, S0))
    emit(addiu(A1, SP, 0x30))
    emit(jal(GET_CURRENT_VIEW))
    emit(0)
    emit(lw(A0, 0x30, SP))
    emit(jal(PREPARE_CURRENT_VIEW))
    emit(0)

    # Mirror stock 0x492B58-0x492B90 exactly: the existing-view retarget path
    # is used only when at least two explorer views exist.
    emit(lui(S2, EXPLORER_VIEW_TYPE >> 16))
    emit(addiu(S2, S2, EXPLORER_VIEW_TYPE & 0xFFFF))
    emit(move(A0, S0))
    emit(move(A1, S2))
    emit(jal(COUNT_VIEWS_BY_TYPE))
    emit(0)
    emit(slti(V0, V0, 2))
    branch(0x05, V0, ZERO, "call_original")
    emit(0)

    emit(sw(ZERO, 0x30, SP))
    emit(move(A0, S0))
    emit(move(A1, S2))
    emit(addiu(A2, SP, 0x30))
    emit(jal(FIND_LAST_VIEW_BY_TYPE))
    emit(0)
    emit(lw(S1, 0x30, SP))
    branch(0x04, S1, ZERO, "call_original")
    emit(0)

    emit(move(A0, S0))
    emit(addiu(A1, S1, 0x3DD8))
    emit(addiu(A2, SP, 0x40))
    emit(jal(RETARGET_EXISTING_VIEW))
    emit(0)

    label("call_original")
    emit(lw(A0, 0x34C, SP))
    emit(lw(A1, 0x348, SP))
    emit(lw(A2, 0x344, SP))
    emit(lw(A3, 0x340, SP))
    emit(lw(S2, 0x350, SP))
    emit(lw(S1, 0x354, SP))
    emit(lw(S0, 0x358, SP))
    emit(lw(RA, 0x35C, SP))
    emit(addiu(SP, SP, 0x360))
    emit(jump(ORIGINAL_CALLBACK))
    emit(0)

    for index, target, op, rs, rt in fixups:
        relative = labels[target] - (index + 1)
        words[index] = i_type(op, rs, rt, relative)

    return b"".join(struct.pack("<I", word) for word in words)


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

    expected_hi = bytes.fromhex("4e00053c")
    expected_lo = bytes.fromhex("a05fa524")
    if source[CALLBACK_POINTER_HI_OFFSET:CALLBACK_POINTER_HI_OFFSET + 4] != expected_hi:
        raise SystemExit("unexpected callback high instruction")
    if source[CALLBACK_POINTER_LO_OFFSET:CALLBACK_POINTER_LO_OFFSET + 4] != expected_lo:
        raise SystemExit("unexpected callback low instruction")

    wrapper = build_wrapper()
    if any(source[CODE_CAVE_OFFSET:CODE_CAVE_OFFSET + len(wrapper)]):
        raise SystemExit("selected code cave is not empty in the golden input")

    patched = bytearray(source)
    patched[CALLBACK_POINTER_HI_OFFSET:CALLBACK_POINTER_HI_OFFSET + 4] = bytes.fromhex("9200053c")
    patched[CALLBACK_POINTER_LO_OFFSET:CALLBACK_POINTER_LO_OFFSET + 4] = bytes.fromhex("b0faa524")
    patched[CODE_CAVE_OFFSET:CODE_CAVE_OFFSET + len(wrapper)] = wrapper

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(patched)
    print(f"source_sha256={source_hash}")
    print(f"output_sha256={sha256(patched)}")
    print(f"output_size={len(patched)}")
    print(f"wrapper_vaddr={CODE_CAVE_VADDR:#x}")
    print(f"wrapper_size={len(wrapper):#x}")


if __name__ == "__main__":
    main()
