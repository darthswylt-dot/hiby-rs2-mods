#!/usr/bin/env python3
"""Build the RS2 folder-follow pre-callback hardware-test artifact.

The input must be the hardware-validated firmware 1.4 sort/fullnav/wake binary.
Only the Now Playing gesture callback pointer and an unused executable code cave
are changed. No proprietary binary is stored in the repository.
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
CODE_CAVE_VADDR = 0x91FB00
CODE_CAVE_OFFSET = CODE_CAVE_VADDR - IMAGE_BASE

ORIGINAL_CALLBACK = 0x4E5FA0
GET_PLAYER_CONTEXT = 0x459340
DESTROY_EXPLORER_STACK = 0x4E4B20
GET_CURRENT_PATH = 0x4E4B80
BUILD_FOLDER_VIEW = 0x4E4640
MEMSET_PLT = 0xA5BC60

ZERO, V0, A0, A1, A2, A3, S0, S1, SP, RA = 0, 2, 4, 5, 6, 7, 16, 17, 29, 31


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


def lw(rt: int, offset: int, base: int) -> int:
    return i_type(0x23, base, rt, offset)


def sw(rt: int, offset: int, base: int) -> int:
    return i_type(0x2B, base, rt, offset)


def move(rd: int, rs: int) -> int:
    return r_type(rs, ZERO, rd, 0x21)


def beq(rs: int, rt: int, immediate: int) -> int:
    return i_type(0x04, rs, rt, immediate)


def bne(rs: int, rt: int, immediate: int) -> int:
    return i_type(0x05, rs, rt, immediate)


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

    # Preserve the callback ABI and enough callee-saved state for the reordered
    # path lookup -> destroy -> build sequence.
    emit(addiu(SP, SP, -0x320))
    emit(sw(RA, 0x31C, SP))
    emit(sw(S0, 0x318, SP))
    emit(sw(S1, 0x314, SP))
    emit(sw(A0, 0x310, SP))
    emit(sw(A1, 0x30C, SP))
    emit(sw(A2, 0x308, SP))
    emit(sw(A3, 0x304, SP))

    # All non-target gestures pass straight through to the stock callback.
    emit(addiu(V0, ZERO, 1))
    branch(0x05, A2, V0, "call_original")
    emit(0)  # bne delay slot
    branch(0x05, A3, V0, "call_original")
    emit(0)  # bne delay slot

    emit(jal(GET_PLAYER_CONTEXT))
    emit(0)  # jal delay slot; original a0 is still live here
    branch(0x04, V0, ZERO, "call_original")
    emit(0)  # beq delay slot
    emit(lw(S0, 0x3C, V0))
    branch(0x04, S0, ZERO, "call_original")
    emit(0)  # beq delay slot

    # Clear the same 0x208-byte UTF-16 path buffer used by the failed test.
    emit(addiu(A0, SP, 0x40))
    emit(move(A1, ZERO))
    emit(addiu(A2, ZERO, 0x208))
    emit(jal(MEMSET_PLT))
    emit(0)  # jal delay slot

    # New ordering: resolve the playback path while the old stack is intact,
    # retain the returned builder argument in s1, then replace the stack.
    emit(move(A0, S0))
    emit(addiu(A1, SP, 0x40))
    emit(jal(GET_CURRENT_PATH))
    emit(0)  # jal delay slot
    emit(move(S1, V0))

    emit(move(A0, S0))
    emit(jal(DESTROY_EXPLORER_STACK))
    emit(0)  # jal delay slot

    emit(move(A0, S0))
    emit(addiu(A1, SP, 0x40))
    emit(move(A2, S1))
    emit(jal(BUILD_FOLDER_VIEW))
    emit(0)  # jal delay slot

    # Tail-call stock code last. Its return value is returned directly to the
    # callback dispatcher, exactly as in the unmodified binary.
    label("call_original")
    emit(lw(A0, 0x310, SP))
    emit(lw(A1, 0x30C, SP))
    emit(lw(A2, 0x308, SP))
    emit(lw(A3, 0x304, SP))
    emit(lw(S1, 0x314, SP))
    emit(lw(S0, 0x318, SP))
    emit(lw(RA, 0x31C, SP))
    emit(addiu(SP, SP, 0x320))
    emit(jump(ORIGINAL_CALLBACK))
    emit(0)  # j delay slot

    for index, target, op, rs, rt in fixups:
        if target not in labels:
            raise ValueError(f"undefined label: {target}")
        relative = labels[target] - (index + 1)
        words[index] = i_type(op, rs, rt, relative)

    wrapper = b"".join(struct.pack("<I", word) for word in words)
    if len(wrapper) != 0xC0:
        raise AssertionError(f"unexpected wrapper size: {len(wrapper):#x}")
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

    expected_hi = bytes.fromhex("4e00053c")  # lui a1,0x4e
    expected_lo = bytes.fromhex("a05fa524")  # addiu a1,a1,0x5fa0
    if source[CALLBACK_POINTER_HI_OFFSET:CALLBACK_POINTER_HI_OFFSET + 4] != expected_hi:
        raise SystemExit("unexpected callback high instruction")
    if source[CALLBACK_POINTER_LO_OFFSET:CALLBACK_POINTER_LO_OFFSET + 4] != expected_lo:
        raise SystemExit("unexpected callback low instruction")

    wrapper = build_wrapper()
    if any(source[CODE_CAVE_OFFSET:CODE_CAVE_OFFSET + len(wrapper)]):
        raise SystemExit("selected code cave is not empty in the golden input")

    patched = bytearray(source)
    patched[CALLBACK_POINTER_HI_OFFSET:CALLBACK_POINTER_HI_OFFSET + 4] = bytes.fromhex("9200053c")
    patched[CALLBACK_POINTER_LO_OFFSET:CALLBACK_POINTER_LO_OFFSET + 4] = bytes.fromhex("00fba524")
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
