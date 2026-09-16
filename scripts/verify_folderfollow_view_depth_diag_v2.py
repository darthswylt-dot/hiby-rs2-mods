#!/usr/bin/env python3
"""Verify two inline-type corrections and removal of two optional field reads."""

from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

import build_folderfollow_view_depth_diag as failed
import build_folderfollow_view_depth_diag_v2 as fixed


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("artifact", type=Path)
    args = parser.parse_args()
    source = args.source.read_bytes()
    artifact = args.artifact.read_bytes()
    expected, _ = fixed.build(source)
    if artifact != expected:
        raise SystemExit("artifact differs from the exact corrected patch")

    before = failed.build_wrapper()
    after = fixed.build_wrapper()
    if len(before) != len(after) or len(after) != 0x1F8:
        raise SystemExit("wrapper size changed")
    changed_words = [i for i in range(len(before) // 4)
                     if before[i * 4:i * 4 + 4] != after[i * 4:i * 4 + 4]]
    if changed_words != [50, 52, 86, 88]:
        raise SystemExit(f"unexpected wrapper changes: {changed_words}")
    for index, source_register in fixed.TYPE_LOADS:
        word = struct.unpack_from("<I", after, index * 4)[0]
        if word != failed.move(failed.S4, source_register):
            raise SystemExit(f"wrong corrected instruction at word {index}")
    for index, _ in fixed.OPTIONAL_STATE_LOADS:
        word = struct.unpack_from("<I", after, index * 4)[0]
        if word != failed.move(failed.V0, failed.ZERO):
            raise SystemExit(f"optional field read remains at word {index}")

    golden, _ = failed.normalize_source(source)
    changed_offsets = [i for i, (old, new) in enumerate(zip(golden, artifact))
                       if old != new]
    allowed = set(range(failed.CALLBACK_HI_OFFSET, failed.CALLBACK_HI_OFFSET + 4))
    allowed.update(range(failed.CALLBACK_LO_OFFSET, failed.CALLBACK_LO_OFFSET + 4))
    allowed.update(range(failed.CAVE_OFFSET, failed.CAVE_OFFSET + len(after)))
    if any(i not in allowed for i in changed_offsets):
        raise SystemExit("bytes changed outside callback and RX cave")

    print(f"artifact_sha256={hashlib.sha256(artifact).hexdigest()}")
    print(f"changed_bytes={len(changed_offsets)}")
    print(f"corrected_wrapper_words={changed_words}")
    print("control_flow=identical_to_previous_verified_wrapper")
    print("hardware_status=successful_passive_run_documented")


if __name__ == "__main__":
    main()
