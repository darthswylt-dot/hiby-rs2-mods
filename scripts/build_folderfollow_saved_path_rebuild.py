#!/usr/bin/env python3
"""Build a gated Folder View rebuild through stock property 11 + 0x495D40."""

from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path


SOURCE_SHA256 = "c825a72e1078999f74822846d35c99971f9a660addd5f12d42d50a75f0b9b80e"
RECOVERED_02FD_SHA256 = "02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87"
EXPECTED_SIZE = 7_133_528

IMAGE_BASE = 0x400000
CALLBACK_HI_OFFSET = 0x0EAEBC
CALLBACK_LO_OFFSET = 0x0EAECC
CAVE_VADDR = 0x988040
CAVE_OFFSET = CAVE_VADDR - IMAGE_BASE
CAVE_CAPACITY = 0x780
GESTURE_HI_OFFSET = 0x0EADB4
GESTURE_LO_OFFSET = 0x0EADBC

ORIGINAL_CALLBACK = 0x4E90C0
GET_CURRENT_VIEW = 0x4E5680
FIND_LAST_VIEW_BY_TYPE = 0x4E57E0
WIDE_COPY = 0x41FB80
WIDE_COMPARE = 0x41FC80
PROPERTY_SET = 0x424F60
PROPERTY_GET = 0x425360
STOCK_STORAGE_OPEN = 0x495D40
PLAYBACK_PATH = 0xADD46C
EXPLORER_VIEW_TYPE = 0x922704

FRAME_SIZE = 0x800
TARGET_OFFSET = 0x40
ROOT_OFFSET = 0x250
MARKER_OFFSET = 0x280

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


def lhu(rt: int, offset: int, base: int) -> int:
    return i_type(0x25, base, rt, offset)


def sh(rt: int, offset: int, base: int) -> int:
    return i_type(0x29, base, rt, offset)


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

    def branch(op: int, rs: int, rt: int, target: str) -> None:
        fixups.append((len(words), target, op, rs, rt))
        emit(0)

    emit(addiu(SP, SP, -FRAME_SIZE))
    for register, offset in (
        (RA, 0x7FC), (S0, 0x7F8), (S1, 0x7F4), (S2, 0x7F0),
        (S3, 0x7EC), (S4, 0x7E8), (S5, 0x7E4),
    ):
        emit(sw(register, offset, SP))
    emit(sw(A0, 0x7E0, SP))
    emit(sw(A1, 0x7DC, SP))

    # Preserve the exact stock timer behavior and return value.
    emit(jal(ORIGINAL_CALLBACK))
    emit(0)
    emit(move(S5, V0))

    # The validated timer owner stores the explorer/controller at +0x3c.
    emit(lw(V0, 0x7DC, SP))
    branch(0x04, V0, ZERO, "done")
    emit(0)
    emit(lw(S0, 0x3C, V0))
    branch(0x04, S0, ZERO, "done")
    emit(0)

    # Mutate only while the active view is also the last Folder View.
    emit(sw(ZERO, 0x20, SP))
    emit(move(A0, S0))
    emit(addiu(A1, SP, 0x20))
    emit(jal(GET_CURRENT_VIEW))
    emit(0)
    emit(lw(S1, 0x20, SP))
    branch(0x04, S1, ZERO, "done")
    emit(0)

    emit(sw(ZERO, 0x24, SP))
    emit(lui(S2, EXPLORER_VIEW_TYPE >> 16))
    emit(addiu(S2, S2, EXPLORER_VIEW_TYPE & 0xFFFF))
    emit(move(A0, S0))
    emit(move(A1, S2))
    emit(addiu(A2, SP, 0x24))
    emit(jal(FIND_LAST_VIEW_BY_TYPE))
    emit(0)
    emit(lw(S2, 0x24, SP))
    branch(0x04, S2, ZERO, "done")
    emit(0)
    branch(0x05, S1, S2, "done")
    emit(0)

    # Copy committed property 24 and derive its parent wildcard path.
    # addiu sign-extends the low half, so bias the high half when bit 15 is set.
    emit(lui(S3, (PLAYBACK_PATH + 0x8000) >> 16))
    emit(addiu(S3, S3, PLAYBACK_PATH & 0xFFFF))
    emit(lhu(V0, 0, S3))
    branch(0x04, V0, ZERO, "done")
    emit(0)
    emit(addiu(S1, SP, TARGET_OFFSET))
    emit(move(A0, S1))
    emit(move(A1, S3))
    emit(addiu(A2, ZERO, 0x103))
    emit(jal(WIDE_COPY))
    emit(0)

    emit(move(V1, S1))
    emit(move(S4, ZERO))
    label("scan")
    emit(lhu(V0, 0, V1))
    branch(0x04, V0, ZERO, "scan_done")
    emit(0)
    emit(addiu(A0, ZERO, 0x5C))
    branch(0x05, V0, A0, "scan_next")
    emit(0)
    emit(move(S4, V1))
    label("scan_next")
    emit(addiu(V1, V1, 2))
    branch(0x04, ZERO, ZERO, "scan")
    emit(0)
    label("scan_done")
    branch(0x04, S4, ZERO, "done")
    emit(0)
    emit(addiu(V0, ZERO, 0x2A))
    emit(sh(V0, 2, S4))
    emit(sh(ZERO, 4, S4))

    # A retained target in property 11 is the failure marker. It prevents a
    # failed stock transaction from repeating every 100 ms; a new target
    # naturally differs and is allowed one attempt.
    emit(addiu(S4, SP, MARKER_OFFSET))
    emit(sh(ZERO, 0, S4))
    emit(addiu(A0, ZERO, 11))
    emit(move(A1, S4))
    emit(addiu(A2, ZERO, 512))
    emit(jal(PROPERTY_GET))
    emit(0)
    emit(move(A0, S4))
    emit(move(A1, S1))
    emit(jal(WIDE_COMPARE))
    emit(0)
    branch(0x04, V0, ZERO, "done")
    emit(0)

    # No-op while the Folder View already matches the playing folder.
    emit(addiu(A0, S2, 0x3DD8))
    emit(move(A1, S1))
    emit(jal(WIDE_COMPARE))
    emit(0)
    branch(0x04, V0, ZERO, "done")
    emit(0)

    # Property 11 takes the full file path. 0x495B80 consumes its separators
    # to rebuild every explorer level and 0x495D40 clears it afterwards.
    emit(addiu(A0, ZERO, 11))
    emit(move(A1, S3))
    emit(jal(PROPERTY_SET))
    emit(0)

    # Construct the matching drive root (for example b:\\*) as fallback.
    emit(addiu(S1, SP, ROOT_OFFSET))
    emit(lhu(V0, 0, S3))
    emit(sh(V0, 0, S1))
    emit(addiu(V0, ZERO, 0x3A))
    emit(sh(V0, 2, S1))
    emit(addiu(V0, ZERO, 0x5C))
    emit(sh(V0, 4, S1))
    emit(addiu(V0, ZERO, 0x2A))
    emit(sh(V0, 6, S1))
    emit(sh(ZERO, 8, S1))
    emit(move(A0, S0))
    emit(move(A1, S1))
    emit(jal(STOCK_STORAGE_OPEN))
    emit(0)

    # Never dereference the old view pointer after 0x495D40. Resolve the new
    # last explorer and retain TARGET as property 11 only if rebuild failed.
    emit(sw(ZERO, 0x24, SP))
    emit(lui(S2, EXPLORER_VIEW_TYPE >> 16))
    emit(addiu(S2, S2, EXPLORER_VIEW_TYPE & 0xFFFF))
    emit(move(A0, S0))
    emit(move(A1, S2))
    emit(addiu(A2, SP, 0x24))
    emit(jal(FIND_LAST_VIEW_BY_TYPE))
    emit(0)
    emit(lw(S2, 0x24, SP))
    branch(0x04, S2, ZERO, "mark_failed")
    emit(0)
    emit(addiu(A0, S2, 0x3DD8))
    emit(addiu(A1, SP, TARGET_OFFSET))
    emit(jal(WIDE_COMPARE))
    emit(0)
    branch(0x04, V0, ZERO, "done")
    emit(0)
    label("mark_failed")
    emit(addiu(A0, ZERO, 11))
    emit(addiu(A1, SP, TARGET_OFFSET))
    emit(jal(PROPERTY_SET))
    emit(0)

    label("done")
    emit(move(V1, S5))
    for register, offset in (
        (S5, 0x7E4), (S4, 0x7E8), (S3, 0x7EC), (S2, 0x7F0),
        (S1, 0x7F4), (S0, 0x7F8), (RA, 0x7FC),
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
        raise AssertionError(f"wrapper too large: {len(wrapper):#x}")
    return wrapper


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize_source(source: bytes) -> tuple[bytes, str]:
    digest = sha256(source)
    if digest == SOURCE_SHA256:
        return source, digest
    if digest != RECOVERED_02FD_SHA256:
        raise SystemExit(f"refusing input SHA-256 {digest}")
    golden = bytearray(source)
    golden[GESTURE_HI_OFFSET:GESTURE_HI_OFFSET + 4] = bytes.fromhex("4e00053c")
    golden[GESTURE_LO_OFFSET:GESTURE_LO_OFFSET + 4] = bytes.fromhex("a05fa524")
    golden[CAVE_OFFSET:CAVE_OFFSET + CAVE_CAPACITY] = b"\0" * CAVE_CAPACITY
    if sha256(golden) != SOURCE_SHA256:
        raise SystemExit("02fd normalization did not reproduce golden")
    return bytes(golden), digest


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    source = args.source.read_bytes()
    if len(source) != EXPECTED_SIZE:
        raise SystemExit(f"refusing input size {len(source)}")
    golden, digest = normalize_source(source)
    wrapper = build_wrapper()
    if any(golden[CAVE_OFFSET:CAVE_OFFSET + CAVE_CAPACITY]):
        raise SystemExit("selected cave is not empty")
    patched = bytearray(golden)
    patched[CALLBACK_HI_OFFSET:CALLBACK_HI_OFFSET + 4] = bytes.fromhex("9900063c")
    patched[CALLBACK_LO_OFFSET:CALLBACK_LO_OFFSET + 4] = bytes.fromhex("4080c624")
    patched[CAVE_OFFSET:CAVE_OFFSET + len(wrapper)] = wrapper
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(patched)
    print(f"input_sha256={digest}")
    print(f"golden_sha256={sha256(golden)}")
    print(f"output_sha256={sha256(patched)}")
    print(f"output_size={len(patched)}")
    print(f"wrapper_vaddr={CAVE_VADDR:#x}")
    print(f"wrapper_size={len(wrapper):#x}")


if __name__ == "__main__":
    main()
