#!/usr/bin/env python3
"""Offline, hash-gated ELF layout for the passive reveal integration bridge.

Call ``normalize_source`` from build_folderfollow_saved_path_rebuild first.
Only the resulting exact golden bytes are accepted here. This module neither
normalizes hook sites nor writes a file, runs firmware, or accesses a device.

The existing RW load gets zero-filled private BSS, and the unused final PHDR
becomes a separate, file-backed RX load. Existing segment permissions and all
other original bytes remain unchanged. This is a structural layout guarantee,
not a claim that an untested target loader will accept the added segment.
"""

from __future__ import annotations

import hashlib
import struct

from build_folderfollow_saved_path_rebuild import EXPECTED_SIZE, SOURCE_SHA256


PAGE_ALIGNMENT = 0x1000
LOAD_ALIGNMENT = 0x10000
J_REGION_END = 0x10000000
MAX_MEMORY_BYTES = 16 * 1024 * 1024
MAX_CODE_BYTES = 1024 * 1024
PHOFF = 52
PHENTSIZE = 32
PHNUM = 10
RW_INDEX = 3
CODE_INDEX = 9
RW_HEADER = (1, 0x65C000, 0xA6C000, 0xA6C000,
             0x7120C, 0x167CA4, 6, LOAD_ALIGNMENT)
EMPTY_HEADER = (0, 0, 0, 0, 0, 0, 0, 4)


def _align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) & -alignment


def _size(value: int, name: str, maximum: int) -> None:
    if type(value) is not int or not 0 < value <= maximum:
        raise ValueError(f'{name} must be an integer in 1..{maximum}')


def _headers(golden: bytes) -> list[tuple[int, ...]]:
    if not isinstance(golden, bytes):
        raise ValueError('golden must be immutable bytes')
    if len(golden) != EXPECTED_SIZE:
        raise ValueError(f'unexpected golden size: {len(golden)}')
    if hashlib.sha256(golden).hexdigest() != SOURCE_SHA256:
        raise ValueError('expected exact normalized golden SHA-256')
    if (golden[:7] != b'\x7fELF\x01\x01\x01'
            or struct.unpack_from('<HH', golden, 16) != (2, 8)
            or struct.unpack_from('<I', golden, 28)[0] != PHOFF
            or struct.unpack_from('<HHH', golden, 40)
            != (52, PHENTSIZE, PHNUM)):
        raise ValueError('unexpected ELF32 little-endian MIPS header')
    headers = [struct.unpack_from('<8I', golden, PHOFF + i * PHENTSIZE)
               for i in range(PHNUM)]
    if headers[RW_INDEX] != RW_HEADER or headers[CODE_INDEX] != EMPTY_HEADER:
        raise ValueError('unexpected RW load or occupied final PHDR')
    loads = [header for header in headers if header[0] == 1]
    previous_end = 0
    for _, offset, address, _, filesz, memsz, flags, alignment in loads:
        if (filesz > memsz or offset + filesz > len(golden)
                or address < previous_end or address + memsz >= J_REGION_END
                or alignment != LOAD_ALIGNMENT
                or offset % alignment != address % alignment
                or flags & 3 == 3):
            raise ValueError('unexpected original load geometry/permissions')
        previous_end = address + memsz
    if not loads or loads[-1] != RW_HEADER:
        raise ValueError('RW load must be the final original load')
    return headers


def plan_layout(golden: bytes, memory_bytes: int) -> dict[str, int]:
    """Plan a private buffer and RX segment without modifying ``golden``.

    ``memory_bytes`` is the exact positive number of private zero-filled bytes
    requested, not a rounded page count. The buffer starts on a 4 KiB boundary;
    code starts at the next 64 KiB boundary at or above the extended RW end.
    The explicit size limits keep accidental requests bounded.
    """
    _size(memory_bytes, 'memory_bytes', MAX_MEMORY_BYTES)
    _headers(golden)
    rw_address, rw_memsz = RW_HEADER[2], RW_HEADER[5]
    buffer = _align_up(rw_address + rw_memsz, PAGE_ALIGNMENT)
    memory_end = buffer + memory_bytes
    code_base = _align_up(memory_end, LOAD_ALIGNMENT)
    if not rw_address + rw_memsz <= buffer < memory_end <= code_base:
        raise ValueError('private buffer or code overlaps original memory')
    if code_base >= J_REGION_END:
        raise ValueError('code base leaves the original MIPS J region')
    return {
        'buffer': buffer,
        'memsize_offset': PHOFF + RW_INDEX * PHENTSIZE + 20,
        'memsize': memory_end - rw_address,
        'code_base': code_base,
        'code_offset': _align_up(len(golden), LOAD_ALIGNMENT),
        'phdr_offset': PHOFF + CODE_INDEX * PHENTSIZE,
    }


def install_layout(golden: bytes, code: bytes,
                   memory_bytes: int) -> tuple[bytes, dict[str, int]]:
    """Return a laid-out image plus metadata; no hook sites are modified.

    The caller must assemble for ``plan_layout(...)[\"code_base\"]`` and patch
    its independently verified hooks separately. This helper does not inspect
    code semantics. Only the RW ``p_memsz`` and final 32-byte PHDR may differ
    within the original file; appended alignment padding is always zero.
    """
    if not isinstance(code, bytes):
        raise ValueError('code must be immutable bytes')
    _size(len(code), 'code size', MAX_CODE_BYTES)
    if len(code) % 4:
        raise ValueError('MIPS code size must be a multiple of four bytes')
    layout = plan_layout(golden, memory_bytes)
    code_end = layout['code_base'] + len(code)
    if code_end >= J_REGION_END:
        raise ValueError('code leaves the original MIPS J region')
    output_size = layout['code_offset'] + len(code)
    if output_size > 0xFFFFFFFF:
        raise ValueError('file size overflows ELF32')
    output = bytearray(golden)
    struct.pack_into('<I', output, layout['memsize_offset'], layout['memsize'])
    struct.pack_into('<8I', output, layout['phdr_offset'],
                     1, layout['code_offset'], layout['code_base'],
                     layout['code_base'], len(code), len(code),
                     5, LOAD_ALIGNMENT)
    output.extend(b'\0' * (layout['code_offset'] - len(output)))
    output.extend(code)
    return bytes(output), dict(layout, code_bytes=len(code),
                               output_size=output_size)
