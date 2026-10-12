#!/usr/bin/env python3
"""Strict passive RBRG/RBST v1 decoder; never certifies a live list or identity."""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import struct


RECORD = 0x250
CAPACITY = 1024
VERSION = 1
FIELDS = (
    "magic", "version", "event", "seq", "frame", "statement", "list", "mode",
    "offset", "ordinal", "result", "caller", "cue", "truncated", "list_count",
    "reserved",
)
STATUS_FIELDS = (
    "magic", "version", "reserved", "drained", "overflow", "contention_loss",
    "io_error", "capacity",
)
KINDS = {
    1: "begin", 2: "row", 3: "terminal", 4: "end", 5: "playback_begin",
    6: "playback_end", 7: "touch", 8: "view_close", 9: "list_reset", 10: "refresh",
}
PRODUCER_CALLERS = (0x6F8BF4, 0x6F8E0C)
PLAYBACK_CALLERS = (0x42AC14, 0x42CBE4, 0x42CD64)
LOSS_FIELDS = ("overflow", "contention_loss", "io_error")
LIMITATIONS = (
    "Only the exported, finally confirmed prefix is checked; future records and I/O are unknown.",
    "Reservation order is not a global execution or playback-commit linearization order.",
    "A playback pair captures source identity before memcpy and its return, not an atomic current identity.",
    "Completed producer windows do not certify folder total, generation, lifetime, or later list contents.",
    "Pointer values are raw tokens, not retained objects or non-reused generations.",
    "Reset and close probes cover only their selected entry points, not every invalidation.",
    "Touch and refresh records are observations, not a complete gesture state or safe-autoscroll proof.",
)


def signed(value):
    return value - (1 << 32) if value & 0x80000000 else value


def _path(raw, truncated, allow_empty_truncated=False):
    end = next((i for i in range(0, len(raw), 2) if raw[i:i + 2] == b"\0\0"), None)
    if end is None:
        raise ValueError("unterminated path")
    if any(raw[end:]):
        raise ValueError("nonzero path padding")
    if truncated and end != 259 * 2 and not (allow_empty_truncated and end == 0):
        raise ValueError("invalid truncated path length")
    try:
        return raw[:end].decode("utf-16le", errors="strict")
    except UnicodeDecodeError as error:
        raise ValueError("invalid UTF-16 path") from error


def _zero(row, fields):
    if any(row[field] for field in fields):
        raise ValueError("nonzero unused event fields")


def decode(data):
    """Yield structurally valid records, rejecting corruption instead of resyncing."""
    position = 0
    while position < len(data):
        magic = data[position:position + 4]
        size = {b"RBRG": RECORD, b"RBST": 32}.get(magic)
        if size is None or position + size > len(data):
            raise ValueError(f"bad/truncated record at {position:#x}")
        raw = data[position:position + size]
        if struct.unpack_from("<I", raw, 4)[0] != VERSION:
            raise ValueError(f"unsupported version at {position:#x}")
        if magic == b"RBST":
            row = dict(zip(STATUS_FIELDS, struct.unpack("<8I", raw)))
            if row["capacity"] != CAPACITY or not 0 <= row["drained"] <= row["reserved"] <= CAPACITY:
                raise ValueError("invalid buffer counters")
            if any(row[key] not in (0, 1) for key in LOSS_FIELDS):
                raise ValueError("invalid loss flags")
            row["kind"] = "status"
        else:
            row = dict(zip(FIELDS, struct.unpack_from("<16I", raw)))
            event = row["event"]
            if event not in KINDS:
                raise ValueError("unknown event")
            if row["seq"] >= CAPACITY or row["truncated"] not in (0, 1) or row["reserved"]:
                raise ValueError("invalid event metadata")
            if any(raw[0x248:]):
                raise ValueError("nonzero record padding")
            row["kind"] = KINDS[event]
            # Playback also uses flag 1 + empty path when its source alignment
            # precludes capture. Preserve that observation, but reject its pair.
            row["path"] = _path(raw[0x40:0x248], row["truncated"], event == 5)
            if event in (3, 4, 6, 7, 8, 9):
                if row["path"]:
                    raise ValueError("unexpected event path")
                _zero(row, ("cue", "truncated"))
            if event <= 4:
                if event == 1:
                    _zero(row, ("cue",))
                if row["list_count"] & 0x80000000:
                    raise ValueError("negative list count")
                for key in ("offset", "ordinal", "result", "cue", "list_count"):
                    row[key] = signed(row[key])
            elif event == 5:
                _zero(row, ("statement", "list", "mode", "offset", "ordinal", "list_count"))
                row["cue"] = signed(row["cue"])
            elif event == 6:
                _zero(row, ("list", "mode", "offset", "ordinal", "list_count"))
            elif event == 7:
                _zero(row, ("list_count",))
                if row["mode"] not in (2, 3):
                    raise ValueError("invalid raw touch mode")
                row["ordinal"], row["result"] = signed(row["ordinal"]), signed(row["result"])
            elif event in (8, 9):
                _zero(row, ("mode", "offset", "ordinal", "result", "list_count"))
                if event == 8:
                    _zero(row, ("statement",))
            else:
                _zero(row, ("cue", "list_count"))
                for key in ("offset", "ordinal", "result"):
                    row[key] = signed(row[key])
        del row["magic"]
        yield row
        position += size


def _integrity(records):
    expected, previous = 0, None
    errors = []
    counts = Counter({kind: 0 for kind in KINDS.values()})
    for row in records:
        if row["kind"] == "status":
            if previous and any(row[key] < previous[key] for key in ("reserved", "drained", *LOSS_FIELDS)):
                errors.append("counter reversal or mixed runs")
            if row["drained"] != expected:
                errors.append("drain/export mismatch")
            if any(row[key] for key in LOSS_FIELDS):
                errors.append("reported loss")
            previous = row
        else:
            counts[row["kind"]] += 1
            if row["seq"] != expected:
                errors.append("sequence gap, duplicate, or mixed runs")
            expected += 1
    if not records or records[-1]["kind"] != "status":
        errors.append("no final status after last event")
    if not previous or previous["reserved"] != previous["drained"] or previous["drained"] != expected:
        errors.append("unsettled or unconfirmed tail")
    return dict(accepted_prefix=not errors, errors=sorted(set(errors)), event_count=expected, counts=dict(counts))


def _producer_windows(records, integrity_ok):
    active, finished, unmatched = {}, [], []
    for row in records:
        if row["kind"] not in ("begin", "row", "terminal", "end"):
            continue
        key = (row["frame"], row["statement"], row["list"])
        if row["kind"] == "begin":
            window = dict(begin=row, rows=[], terminal=None, end=None, errors=[])
            for other in active.values():
                if row["list"] == other["begin"]["list"] or row["frame"] == other["begin"]["frame"]:
                    other["errors"].append("overlapping list or reused producer frame")
                    window["errors"].append("overlapping list or reused producer frame")
            if key in active:
                old = active.pop(key)
                old["errors"].append("reused session before end")
                finished.append(old)
            active[key] = window
            continue
        if key not in active:
            unmatched.append(dict(seq=row["seq"], kind=row["kind"], error="no matching producer begin"))
            for other in active.values():
                if row["list"] == other["begin"]["list"] or row["frame"] == other["begin"]["frame"]:
                    other["errors"].append("unmatched event overlaps active producer scope")
            for other in reversed(finished):
                if key == tuple(other["begin"][field] for field in ("frame", "statement", "list")):
                    other["errors"].append("producer event after end or reused scope without begin")
                    break
            continue
        window = active[key]
        begin = window["begin"]
        if any(row[field] != begin[field] for field in ("offset", "mode", "caller")):
            window["errors"].append("producer scope changed")
        if row["kind"] == "row":
            count = len(window["rows"])
            if (window["terminal"] is not None or row["ordinal"] != count or row["result"] != count
                    or row["list_count"] != count + 1 or row["truncated"] or not row["path"]):
                window["errors"].append("row or append mismatch")
            window["rows"].append(row)
        elif row["kind"] == "terminal":
            if window["terminal"] is not None:
                window["errors"].append("duplicate terminal")
            window["terminal"] = row
        else:
            window["end"] = row
            finished.append(active.pop(key))
    finished.extend(active.values())
    results = []
    for window in finished:
        begin, terminal, end = (window[key] for key in ("begin", "terminal", "end"))
        errors, count = window["errors"], len(window["rows"])
        if not integrity_ok:
            errors.append("trace integrity not confirmed")
        if (begin["mode"] != 0 or begin["caller"] not in PRODUCER_CALLERS
                or not all(begin[key] for key in ("frame", "statement", "list"))
                or begin["ordinal"] != 0 or begin["list_count"] != 0 or begin["offset"] < 0
                or begin["result"] < 0 or begin["truncated"] or not begin["path"]):
            errors.append("invalid begin")
        if not terminal or terminal["result"] != 101 or terminal["ordinal"] != count or terminal["list_count"] != count:
            errors.append("query completion not confirmed")
        if not end or end["ordinal"] != count or end["result"] != count or end["list_count"] != count or count > begin["result"]:
            errors.append("incomplete fill or count mismatch")
        if count and begin["offset"] + count - 1 > 0x7FFFFFFF:
            errors.append("absolute index overflow")
        identities = [(item["path"], item["cue"]) for item in window["rows"]]
        if len(set(identities)) != count:
            errors.append("duplicate path/cue")
        results.append(dict(
            begin_seq=begin["seq"], end_seq=None if end is None else end["seq"],
            frame=begin["frame"], statement=begin["statement"], list=begin["list"],
            folder=begin["path"], offset=begin["offset"], requested_count=begin["result"], rows=count,
            accepted_completed_window=not errors, errors=sorted(set(errors)),
            mapping=[] if errors else [dict(index=begin["offset"] + index, path=item["path"], cue=item["cue"])
                                      for index, item in enumerate(window["rows"])],
        ))
    return sorted(results, key=lambda row: row["begin_seq"]), unmatched


def _playback_copies(records, integrity_ok):
    active, finished = {}, []
    for row in records:
        if row["kind"] == "playback_begin":
            copy = dict(begin=row, end=None, errors=[], overlaps=False)
            for other in active.values():
                copy["overlaps"] = other["overlaps"] = True
                if row["frame"] == other["begin"]["frame"]:
                    copy["errors"].append("reused playback frame before end")
                    other["errors"].append("reused playback frame before end")
            if row["seq"] in active:
                old = active.pop(row["seq"])
                old["errors"].append("duplicate playback begin sequence")
                finished.append(old)
            active[row["seq"]] = copy
        elif row["kind"] == "playback_end":
            copy = active.pop(row["statement"], None)
            if copy is None:
                for other in finished:
                    if other["begin"] is not None and other["begin"]["seq"] == row["statement"]:
                        other["errors"].append("duplicate playback end")
                copy = dict(begin=None, end=None, errors=["no matching playback begin"], overlaps=False)
            copy["end"] = row
            finished.append(copy)
    finished.extend(active.values())
    results = []
    for copy in finished:
        begin, end, errors = copy["begin"], copy["end"], copy["errors"]
        if not integrity_ok:
            errors.append("trace integrity not confirmed")
        if begin is not None:
            if (not begin["frame"] or begin["caller"] not in PLAYBACK_CALLERS or begin["result"] != 0xA88
                    or begin["truncated"] or not begin["path"]):
                errors.append("invalid playback begin")
            if end and any(end[key] != begin[key] for key in ("frame", "caller")):
                errors.append("playback scope changed")
        if end is None:
            errors.append("missing playback end")
        elif end["statement"] == 0xFFFFFFFF:
            errors.append("playback begin reservation failed")
        results.append(dict(
            begin_seq=None if begin is None else begin["seq"], end_seq=None if end is None else end["seq"],
            frame=(begin or end)["frame"], caller=(begin or end)["caller"],
            byte_count=None if begin is None else begin["result"],
            source_identity=None if begin is None else dict(path=begin["path"], cue=begin["cue"]),
            return_value=None if end is None else end["result"],
            overlapping_copy_observations=copy["overlaps"], accepted_pair=not errors, errors=sorted(set(errors)),
        ))
    return sorted(results, key=lambda row: row["begin_seq"] if row["begin_seq"] is not None else row["end_seq"])


def summary(records):
    """Describe immutable trace observations, with no invented live generations."""
    records = list(records)
    result = _integrity(records)
    result["producer_windows"], result["unmatched_producer_events"] = _producer_windows(records, result["accepted_prefix"])
    result["playback_copies"] = _playback_copies(records, result["accepted_prefix"])
    result["limitations"] = list(LIMITATIONS)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    parser.add_argument("--events", action="store_true", help="print one JSON object per raw observation")
    args = parser.parse_args(argv)
    try:
        rows = list(decode(args.log.read_bytes()))
    except (OSError, ValueError) as error:
        parser.exit(2, f"invalid bridge trace: {error}\n")
    if args.events:
        for row in rows:
            print(json.dumps(row, ensure_ascii=False))
    else:
        print(json.dumps(summary(rows), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
