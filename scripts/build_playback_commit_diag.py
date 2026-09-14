#!/usr/bin/env python3
"""Build a passive diagnostic around the two playback media-item commits."""

from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

from build_folderfollow_safe_pointer_diag import (
    CODE_CAVE_CAPACITY,
    CODE_CAVE_OFFSET,
    CODE_CAVE_VADDR,
    EXPECTED_SIZE,
    addiu,
    i_type,
    jal,
    lui,
    lhu,
    lw,
    move,
    normalize_source,
    ori,
    r_type,
    sh,
    sw,
)


IMAGE_BASE = 0x400000
FAST_COPY_VADDR = 0x42CBDC
GENERAL_COPY_VADDR = 0x42CD5C
FAST_COPY_OFFSET = FAST_COPY_VADDR - IMAGE_BASE
GENERAL_COPY_OFFSET = GENERAL_COPY_VADDR - IMAGE_BASE
ORIGINAL_COPY_WORD = 0x0C296D10

MEMCPY_PLT = 0xA5B440
WRITE_PLT = 0xA5B4A0
MEMSET_PLT = 0xA5BC60

RECORD_SIZE = 0x680
FRAME_SIZE = 0x740
RECORD_OFFSET = 0x20
PATH_BYTES = 0x208
PATH_CODE_UNITS = PATH_BYTES // 2
SELECTED_PATH_OFFSET = 0x040
GLOBAL_PATH_OFFSET = 0x248
SOURCE_PATH_OFFSET = 0x450

ZERO, V0, V1, A0, A1, A2 = 0, 2, 3, 4, 5, 6
T0 = 8
S0, S1, S2, S3, S4, S5, S6, SP, RA = 16, 17, 18, 19, 20, 21, 22, 29, 31


def build_wrapper() -> bytes:
    save_offsets = {
        RA: 0x73C,
        S0: 0x738,
        S1: 0x734,
        S2: 0x730,
        S3: 0x72C,
        S4: 0x728,
        S5: 0x724,
        S6: 0x720,
        A0: 0x71C,
        A1: 0x718,
        A2: 0x714,
    }
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

    def load_u32(register: int, value: int) -> None:
        emit(lui(register, value >> 16))
        emit(ori(register, register, value & 0xFFFF))

    def copy_path(
        source: int, source_offset: int, destination_offset: int, loop_name: str
    ) -> None:
        emit(addiu(V0, source, source_offset))
        emit(addiu(V1, S1, destination_offset))
        emit(addiu(S6, ZERO, PATH_CODE_UNITS))
        label(loop_name)
        emit(lhu(T0, 0, V0))
        emit(sh(T0, 0, V1))
        emit(addiu(V0, V0, 2))
        emit(addiu(V1, V1, 2))
        emit(addiu(S6, S6, -1))
        branch(0x05, S6, ZERO, loop_name)
        emit(0)

    def emit_record(phase: int, suffix: str) -> None:
        emit(move(A0, S1))
        emit(move(A1, ZERO))
        emit(addiu(A2, ZERO, RECORD_SIZE))
        emit(jal(MEMSET_PLT))
        emit(0)

        load_u32(V0, 0x544D4350)  # "PCMT" in little-endian bytes.
        emit(sw(V0, 0x00, S1))
        emit(addiu(V0, ZERO, 1))
        emit(sw(V0, 0x04, S1))
        emit(addiu(V0, ZERO, RECORD_SIZE))
        emit(sw(V0, 0x08, S1))
        emit(addiu(V0, ZERO, phase))
        emit(sw(V0, 0x0C, S1))
        emit(sw(S4, 0x10, S1))
        emit(lw(V0, save_offsets[RA], SP))
        emit(sw(V0, 0x14, S1))
        emit(sw(S0, 0x18, S1))
        emit(sw(S2, 0x1C, S1))
        emit(lw(V0, save_offsets[A2], SP))
        emit(sw(V0, 0x20, S1))
        emit(lw(V0, 0x00, S2))
        emit(sw(V0, 0x38, S1))
        emit(lw(V0, 0x00, S0))
        emit(sw(V0, 0x3C, S1))

        emit(lui(V0, 0x00AE))
        emit(lw(S5, -0x2CA0, V0))  # *(0xADD360)
        emit(sw(S5, 0x24, S1))
        branch(0x04, S5, ZERO, f"source_done_{suffix}")
        emit(0)
        for source_offset, record_offset in (
            (0x24, 0x28),
            (0x230, 0x2C),
            (0x414, 0x30),
            (0x730, 0x34),
        ):
            emit(lw(V0, source_offset, S5))
            emit(sw(V0, record_offset, S1))
        copy_path(S5, 0x28, SOURCE_PATH_OFFSET, f"copy_source_{suffix}")
        label(f"source_done_{suffix}")

        copy_path(S2, 0x04, SELECTED_PATH_OFFSET, f"copy_selected_{suffix}")
        copy_path(S0, 0x04, GLOBAL_PATH_OFFSET, f"copy_global_{suffix}")
        emit(addiu(A0, ZERO, 9))
        emit(move(A1, S1))
        emit(addiu(A2, ZERO, RECORD_SIZE))
        emit(jal(WRITE_PLT))
        emit(0)

    emit(addiu(SP, SP, -FRAME_SIZE))
    for register in (RA, S0, S1, S2, S3, S4, S5, S6, A0, A1, A2):
        emit(sw(register, save_offsets[register], SP))
    emit(move(S0, A0))
    emit(move(S2, A1))
    emit(addiu(S1, SP, RECORD_OFFSET))

    # site=1 for return address 0x42CBE4, otherwise site=2 (0x42CD64).
    emit(addiu(S4, ZERO, 1))
    load_u32(V0, FAST_COPY_VADDR + 8)
    emit(lw(V1, save_offsets[RA], SP))
    branch(0x04, V1, V0, "site_ready")
    emit(0)
    emit(addiu(S4, ZERO, 2))
    label("site_ready")

    emit_record(1, "pre")
    emit(lw(A0, save_offsets[A0], SP))
    emit(lw(A1, save_offsets[A1], SP))
    emit(lw(A2, save_offsets[A2], SP))
    emit(jal(MEMCPY_PLT))
    emit(0)
    emit(move(S3, V0))
    emit_record(2, "post")

    emit(move(V1, S3))
    for register in (S6, S5, S4, S3, S2, S1, S0, RA):
        emit(lw(register, save_offsets[register], SP))
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


def build_candidate(source: bytes) -> tuple[bytes, bytes, str]:
    golden, source_hash = normalize_source(source)
    for offset in (FAST_COPY_OFFSET, GENERAL_COPY_OFFSET):
        word = struct.unpack_from("<I", golden, offset)[0]
        if word != ORIGINAL_COPY_WORD:
            raise SystemExit(f"unexpected instruction {word:#010x} at file offset {offset:#x}")
    if any(golden[CODE_CAVE_OFFSET:CODE_CAVE_OFFSET + CODE_CAVE_CAPACITY]):
        raise SystemExit("selected cave is not empty in normalized golden input")

    wrapper = build_wrapper()
    candidate = bytearray(golden)
    patched_call = struct.pack("<I", jal(CODE_CAVE_VADDR))
    for offset in (FAST_COPY_OFFSET, GENERAL_COPY_OFFSET):
        candidate[offset:offset + 4] = patched_call
    candidate[CODE_CAVE_OFFSET:CODE_CAVE_OFFSET + len(wrapper)] = wrapper
    return bytes(candidate), wrapper, source_hash


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    source = args.source.read_bytes()
    if len(source) != EXPECTED_SIZE:
        raise SystemExit(f"refusing input size {len(source)}; expected {EXPECTED_SIZE}")
    candidate, wrapper, source_hash = build_candidate(source)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(candidate)
    print(f"input_sha256={source_hash}")
    print(f"output_sha256={sha256(candidate)}")
    print(f"output_size={len(candidate)}")
    print(f"wrapper_vaddr={CODE_CAVE_VADDR:#x}")
    print(f"wrapper_size={len(wrapper):#x}")
    print(f"record_size={RECORD_SIZE:#x}")


if __name__ == "__main__":
    main()
