#!/usr/bin/env python3
"""Historical view-depth diagnostic; hardware exited unexpectedly. Do not deploy."""

from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

from build_folderfollow_playing_path_diag import (
    CAVE_CAPACITY, CAVE_OFFSET, CAVE_VADDR, CALLBACK_HI_OFFSET,
    CALLBACK_LO_OFFSET, EXPECTED_SIZE, EXPLORER_VIEW_TYPE,
    FIND_LAST_VIEW_BY_TYPE, GET_CURRENT_VIEW, MEMSET_PLT,
    ORIGINAL_CALLBACK,
    WIDE_COPY, WRITE_PLT, CLOCK_GETTIME_PLT, addiu, i_type, jal,
    lui, lw, move, ori, r_type, sw,
)
from build_folderfollow_safe_pointer_diag import normalize_source


STRNCPY_PLT = 0xA5B6E0
STRCMP_PLT = 0xA5B600
FRAME_SIZE = 0x800
RECORD_OFFSET = 0x40
RECORD_SIZE = 0x6E0
CURRENT_NAME_OFFSET = 0x40
LAST_NAME_OFFSET = 0x80
CURRENT_PATH_OFFSET = 0xC0
LAST_PATH_OFFSET = 0x2C8
PLAYBACK_PATH_OFFSET = 0x4D0
PLAYBACK_PATH = 0xADD46C

ZERO, V0, V1, A0, A1, A2 = 0, 2, 3, 4, 5, 6
S0, S1, S2, S3, S4, S5, S6, SP, RA = 16, 17, 18, 19, 20, 21, 22, 29, 31


def build_wrapper() -> bytes:
    words: list[int] = []
    labels: dict[str, int] = {}
    fixups: list[tuple[int, str, int, int, int]] = []

    def emit(word: int) -> None:
        words.append(word)

    def label(name: str) -> None:
        labels[name] = len(words)

    def branch(op: int, rs: int, rt: int, target: str) -> None:
        fixups.append((len(words), target, op, rs, rt))
        emit(0)

    emit(addiu(SP, SP, -FRAME_SIZE))
    for reg, off in (
        (RA, 0x7FC), (S0, 0x7F8), (S1, 0x7F4), (S2, 0x7F0),
        (S3, 0x7EC), (S4, 0x7E8), (S5, 0x7E4), (S6, 0x7E0),
    ):
        emit(sw(reg, off, SP))
    emit(sw(A0, 0x7DC, SP))
    emit(sw(A1, 0x7D8, SP))

    emit(jal(ORIGINAL_CALLBACK))
    emit(0)
    emit(move(S6, V0))

    emit(addiu(S1, SP, RECORD_OFFSET))
    emit(move(A0, S1))
    emit(move(A1, ZERO))
    emit(addiu(A2, ZERO, RECORD_SIZE))
    emit(jal(MEMSET_PLT))
    emit(0)
    emit(lui(V0, 0x5045))  # "VDEP" little endian
    emit(ori(V0, V0, 0x4456))
    emit(sw(V0, 0x00, S1))
    emit(addiu(V0, ZERO, 1))
    emit(sw(V0, 0x04, S1))
    emit(addiu(V0, ZERO, RECORD_SIZE))
    emit(sw(V0, 0x08, S1))
    emit(addiu(A0, ZERO, 1))
    emit(addiu(A1, S1, 0x10))
    emit(jal(CLOCK_GETTIME_PLT))
    emit(0)

    emit(lw(V0, 0x7DC, SP))
    emit(sw(V0, 0x18, S1))
    emit(lw(S0, 0x7D8, SP))
    emit(sw(S0, 0x1C, S1))
    branch(0x04, S0, ZERO, "playback")
    emit(0)
    emit(lw(S0, 0x3C, S0))
    emit(sw(S0, 0x20, S1))
    branch(0x04, S0, ZERO, "playback")
    emit(0)

    emit(sw(ZERO, 0x24, SP))
    emit(move(A0, S0))
    emit(addiu(A1, SP, 0x24))
    emit(jal(GET_CURRENT_VIEW))
    emit(0)
    emit(lw(S2, 0x24, SP))
    emit(sw(S2, 0x24, S1))
    branch(0x04, S2, ZERO, "last_view")
    emit(0)
    emit(lw(S4, 0x00, S2))
    emit(sw(S4, 0x2C, S1))
    emit(lw(V0, 0x40, S2))
    emit(sw(V0, 0x34, S1))
    branch(0x04, S4, ZERO, "last_view")
    emit(0)
    emit(addiu(A0, S1, CURRENT_NAME_OFFSET))
    emit(move(A1, S4))
    emit(addiu(A2, ZERO, 0x3F))
    emit(jal(STRNCPY_PLT))
    emit(0)
    emit(move(A0, S4))
    emit(lui(S5, EXPLORER_VIEW_TYPE >> 16))
    emit(addiu(S5, S5, EXPLORER_VIEW_TYPE & 0xFFFF))
    emit(move(A1, S5))
    emit(jal(STRCMP_PLT))
    emit(0)
    branch(0x05, V0, ZERO, "last_view")
    emit(0)
    emit(addiu(A0, S1, CURRENT_PATH_OFFSET))
    emit(addiu(A1, S2, 0x3DD8))
    emit(addiu(A2, ZERO, 0x103))
    emit(jal(WIDE_COPY))
    emit(0)

    label("last_view")
    emit(sw(ZERO, 0x28, SP))
    emit(lui(S5, EXPLORER_VIEW_TYPE >> 16))
    emit(addiu(S5, S5, EXPLORER_VIEW_TYPE & 0xFFFF))
    emit(move(A0, S0))
    emit(move(A1, S5))
    emit(addiu(A2, SP, 0x28))
    emit(jal(FIND_LAST_VIEW_BY_TYPE))
    emit(0)
    emit(lw(S3, 0x28, SP))
    emit(sw(S3, 0x28, S1))
    branch(0x04, S3, ZERO, "playback")
    emit(0)
    emit(lw(S4, 0x00, S3))
    emit(sw(S4, 0x30, S1))
    emit(lw(V0, 0x40, S3))
    emit(sw(V0, 0x38, S1))
    branch(0x04, S4, ZERO, "last_path")
    emit(0)
    emit(addiu(A0, S1, LAST_NAME_OFFSET))
    emit(move(A1, S4))
    emit(addiu(A2, ZERO, 0x3F))
    emit(jal(STRNCPY_PLT))
    emit(0)
    label("last_path")
    emit(addiu(A0, S1, LAST_PATH_OFFSET))
    emit(addiu(A1, S3, 0x3DD8))
    emit(addiu(A2, ZERO, 0x103))
    emit(jal(WIDE_COPY))
    emit(0)

    label("playback")
    emit(lui(S4, (PLAYBACK_PATH + 0x8000) >> 16))
    emit(addiu(S4, S4, PLAYBACK_PATH & 0xFFFF))
    emit(addiu(A0, S1, PLAYBACK_PATH_OFFSET))
    emit(move(A1, S4))
    emit(addiu(A2, ZERO, 0x103))
    emit(jal(WIDE_COPY))
    emit(0)
    emit(addiu(A0, ZERO, 9))
    emit(move(A1, S1))
    emit(addiu(A2, ZERO, RECORD_SIZE))
    emit(jal(WRITE_PLT))
    emit(0)

    emit(move(V1, S6))
    for reg, off in (
        (S6, 0x7E0), (S5, 0x7E4), (S4, 0x7E8), (S3, 0x7EC),
        (S2, 0x7F0), (S1, 0x7F4), (S0, 0x7F8), (RA, 0x7FC),
    ):
        emit(lw(reg, off, SP))
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
        raise AssertionError(f"wrapper too large: {len(wrapper):#x}")
    return wrapper


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    source = args.source.read_bytes()
    if len(source) != EXPECTED_SIZE:
        raise SystemExit(f"refusing input size {len(source)}")
    golden, input_hash = normalize_source(source)
    wrapper = build_wrapper()
    if any(golden[CAVE_OFFSET:CAVE_OFFSET + CAVE_CAPACITY]):
        raise SystemExit("selected cave is not empty")
    patched = bytearray(golden)
    patched[CALLBACK_HI_OFFSET:CALLBACK_HI_OFFSET + 4] = bytes.fromhex("9900063c")
    patched[CALLBACK_LO_OFFSET:CALLBACK_LO_OFFSET + 4] = bytes.fromhex("4080c624")
    patched[CAVE_OFFSET:CAVE_OFFSET + len(wrapper)] = wrapper
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(patched)
    print(f"input_sha256={input_hash}")
    print(f"golden_sha256={sha256(golden)}")
    print(f"output_sha256={sha256(patched)}")
    print(f"output_size={len(patched)}")
    print(f"wrapper_vaddr={CAVE_VADDR:#x}")
    print(f"wrapper_size={len(wrapper):#x}")
    print(f"record_size={RECORD_SIZE:#x}")


if __name__ == "__main__":
    main()
