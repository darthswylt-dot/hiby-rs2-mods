"""Synthetic wire tests: no device, binary fixture, or live-ownership assumptions."""

import contextlib
import io
import json
import struct
import unittest
from unittest import mock

import decode_reveal_bridge_diag as decoder


def event(sequence, kind, **changes):
    values = {field: 0 for field in decoder.FIELDS}
    values.update(magic=int.from_bytes(b"RBRG", "little"), version=1, event=kind, seq=sequence, frame=0x1000)
    path = ""
    if kind <= 4:
        values.update(statement=0x2000, list=0x3000, caller=decoder.PRODUCER_CALLERS[0])
        if kind == 1:
            values["result"], path = 1, "\\Music\\Slayer\\*"
        elif kind == 2:
            values["list_count"], path = 1, "\\Music\\Slayer\\01.flac"
        else:
            values.update(ordinal=1, result=101 if kind == 3 else 1, list_count=1)
    elif kind in (5, 6):
        values["caller"] = decoder.PLAYBACK_CALLERS[0]
        values["result"] = 0xA88 if kind == 5 else 0xADD468
        if kind == 5:
            path = "\\Music\\Slayer\\01.flac"
    elif kind == 7:
        values.update(statement=0x4000, list=0x5000, mode=2, ordinal=10, result=20, caller=0x1234)
    elif kind == 8:
        values.update(list=0x6000, caller=0x1234)
    elif kind == 9:
        values.update(statement=0x7000, list=0x6000, caller=0x1234)
    elif kind == 10:
        values.update(frame=0x6000, statement=0x8000, list=0x3000, mode=2, ordinal=80, result=260, caller=0x1234)
        path = "\\Music\\Slayer\\*"
    path = changes.pop("path", path)
    if kind == 2:
        values["result"] = changes.get("ordinal", 0)
    values.update(changes)
    result = bytearray(decoder.RECORD)
    struct.pack_into("<16I", result, 0, *(values[key] & 0xFFFFFFFF for key in decoder.FIELDS))
    encoded = path.encode("utf-16le")
    if len(encoded) > 518:
        raise ValueError("test path too long")
    result[0x40:0x40 + len(encoded)] = encoded
    return bytes(result)


def status(reserved, drained=None, **changes):
    values = dict(magic=int.from_bytes(b"RBST", "little"), version=1, reserved=reserved,
                  drained=reserved if drained is None else drained, overflow=0, contention_loss=0,
                  io_error=0, capacity=decoder.CAPACITY)
    values.update(changes)
    return struct.pack("<8I", *(values[key] for key in decoder.STATUS_FIELDS))


def patch_word(raw, field, value):
    result = bytearray(raw)
    struct.pack_into("<I", result, decoder.FIELDS.index(field) * 4, value)
    return bytes(result)


def report(records, final=True):
    data = b"".join(records)
    if final:
        data += status(sum(raw[:4] == b"RBRG" for raw in records))
    return decoder.summary(decoder.decode(data))


def window(start=0, **changes):
    return [event(start, 1, **changes), event(start + 1, 2, **changes),
            event(start + 2, 3, **changes), event(start + 3, 4, **changes)]


class DecodeWireTests(unittest.TestCase):
    def assert_bad(self, raw, message=None):
        with self.assertRaises(ValueError) as caught:
            list(decoder.decode(raw))
        if message:
            self.assertIn(message, str(caught.exception))

    def test_empty_input(self):
        self.assertEqual(list(decoder.decode(b"")), [])

    def test_all_event_kinds_and_status(self):
        data = b"".join(event(index - 1, index) for index in range(1, 11)) + status(10)
        rows = list(decoder.decode(data))
        self.assertEqual([row["kind"] for row in rows], [*decoder.KINDS.values(), "status"])
        self.assertTrue(all("magic" not in row for row in rows))

    def test_unknown_magic_and_trailing_junk(self):
        for raw in (b"WHAT", event(0, 1) + b"x", status(0) + b"RBRG"):
            with self.subTest(raw=raw[:4]):
                self.assert_bad(raw, "bad/truncated")

    def test_all_truncation_lengths(self):
        for raw in (event(0, 1), status(0)):
            for end in range(1, len(raw)):
                with self.subTest(length=len(raw), end=end):
                    self.assert_bad(raw[:end])

    def test_version_and_event_rejection(self):
        for kind in (0, 11, 0xFFFFFFFF):
            self.assert_bad(patch_word(event(0, 1), "event", kind), "unknown event")
        self.assert_bad(patch_word(event(0, 1), "version", 2), "version")
        self.assert_bad(status(0, version=2), "version")

    def test_metadata_flags_capacity_and_reserved(self):
        for field, value in (("seq", decoder.CAPACITY), ("truncated", 2), ("reserved", 1)):
            self.assert_bad(patch_word(event(0, 1), field, value), "metadata")
        self.assert_bad(status(0, capacity=512), "counters")
        self.assert_bad(status(decoder.CAPACITY + 1), "counters")
        self.assert_bad(status(1, drained=2), "counters")
        for field in decoder.LOSS_FIELDS:
            self.assert_bad(status(0, **{field: 2}), "flags")

    def test_record_and_path_padding(self):
        raw = bytearray(event(0, 1))
        raw[-1] = 1
        self.assert_bad(bytes(raw), "record padding")
        raw = bytearray(event(0, 6))
        raw[0x44] = 65
        self.assert_bad(bytes(raw), "path padding")

    def test_unterminated_and_invalid_utf16(self):
        raw = bytearray(event(0, 1))
        raw[0x40:0x248] = b"a\0" * 260
        self.assert_bad(bytes(raw), "unterminated")
        raw = bytearray(event(0, 1, path=""))
        raw[0x40:0x42] = b"\0\xd8"
        self.assert_bad(bytes(raw), "UTF-16")

    def test_truncation_and_maximum_path(self):
        for flag in (0, 1):
            row = next(decoder.decode(event(0, 1, path="a" * 259, truncated=flag)))
            self.assertEqual(len(row["path"]), 259)
            self.assertEqual(row["truncated"], flag)
        self.assert_bad(event(0, 1, truncated=1), "truncated path length")

    def test_unicode_and_signed_values(self):
        row = next(decoder.decode(event(0, 2, path="\\音楽\\Песня😀.flac", cue=-2, result=-1)))
        self.assertEqual(row["cue"], -2)
        self.assertEqual(row["result"], -1)
        self.assertIn("😀", row["path"])
        row = next(decoder.decode(event(0, 7, ordinal=-3, result=-4)))
        self.assertEqual((row["ordinal"], row["result"]), (-3, -4))
        row = next(decoder.decode(event(0, 10, offset=-8, ordinal=-1, result=-2)))
        self.assertEqual((row["offset"], row["ordinal"], row["result"]), (-8, -1, -2))

    def test_pointer_result_remains_unsigned(self):
        row = next(decoder.decode(event(1, 6, statement=0xFFFFFFFF, result=0xF0000000)))
        self.assertEqual(row["result"], 0xF0000000)
        self.assertEqual(row["statement"], 0xFFFFFFFF)

    def test_negative_list_count(self):
        self.assert_bad(event(0, 2, list_count=-1), "negative list count")

    def test_unused_event_fields_and_unexpected_paths(self):
        for kind in (3, 4, 6, 7, 8, 9):
            with self.subTest(kind=kind):
                self.assert_bad(event(0, kind, path="x"), "unexpected event path")
                self.assert_bad(event(0, kind, cue=1), "unused event fields")
        for kind, field in ((1, "cue"), (5, "list"), (5, "statement"), (6, "mode"),
                            (7, "list_count"), (8, "statement"), (9, "offset"), (10, "cue")):
            self.assert_bad(event(0, kind, **{field: 1}), "unused event fields")

    def test_touch_mode_and_nullable_refresh_list(self):
        for mode in (0, 1, 4, 0xFFFFFFFF):
            self.assert_bad(event(0, 7, mode=mode), "raw touch mode")
        self.assertEqual(next(decoder.decode(event(0, 10, list=0)))["list"], 0)


class IntegrityTests(unittest.TestCase):
    def test_empty_status_is_integral_but_not_evidence_of_work(self):
        result = report([status(0)], final=False)
        self.assertTrue(result["accepted_prefix"])
        self.assertEqual(result["event_count"], 0)
        self.assertEqual(result["producer_windows"], [])

    def test_good_interleaved_statuses(self):
        result = report([status(2, drained=0), event(0, 7), status(2, drained=1), event(1, 7, mode=3)])
        self.assertTrue(result["accepted_prefix"])
        self.assertEqual(result["counts"]["touch"], 2)

    def test_empty_missing_or_unsettled_final_status(self):
        for records in ([], [event(0, 7)], [status(1, drained=0), event(0, 7)],
                        [event(0, 7), status(2, drained=1)]):
            with self.subTest(records=len(records)):
                self.assertFalse(report(records, final=False)["accepted_prefix"])

    def test_sequence_gap_duplicate_and_out_of_order(self):
        for sequences in ((1,), (0, 2), (0, 0), (1, 0)):
            result = report([event(sequence, 7) for sequence in sequences])
            self.assertFalse(result["accepted_prefix"])
            self.assertIn("sequence gap, duplicate, or mixed runs", result["errors"])

    def test_reused_run_and_counter_reversal(self):
        for records in ([event(0, 7), status(1), event(0, 7), status(1)],
                        [status(2, drained=0), status(1, drained=0)]):
            result = report(records, final=False)
            self.assertFalse(result["accepted_prefix"])
            if len(records) == 2:
                self.assertIn("counter reversal or mixed runs", result["errors"])

    def test_drain_must_match_events_at_each_status(self):
        result = report([status(1), event(0, 7)])
        self.assertFalse(result["accepted_prefix"])
        self.assertIn("drain/export mismatch", result["errors"])

    def test_loss_is_sticky(self):
        for field in decoder.LOSS_FIELDS:
            result = report([status(0, **{field: 1}), status(0)], final=False)
            self.assertFalse(result["accepted_prefix"])
            self.assertIn("reported loss", result["errors"])
            self.assertIn("counter reversal or mixed runs", result["errors"])


class ProducerTests(unittest.TestCase):
    def test_completed_window_is_not_folder_generation_certificate(self):
        result = report(window(offset=7))
        observed = result["producer_windows"][0]
        self.assertTrue(observed["accepted_completed_window"])
        self.assertEqual(observed["mapping"][0]["index"], 7)
        self.assertNotIn("generation", observed)
        self.assertNotIn("total_count", observed)
        self.assertTrue(any("generation" in limitation for limitation in result["limitations"]))

    def test_append_returns_ordinal_with_zero_valid_for_first_row(self):
        records = [event(0, 1, result=2), event(1, 2),
                   event(2, 2, ordinal=1, list_count=2, path="\\Music\\Slayer\\02.flac"),
                   event(3, 3, ordinal=2, list_count=2), event(4, 4, ordinal=2, result=2, list_count=2)]
        self.assertTrue(report(records)["producer_windows"][0]["accepted_completed_window"])
        records[2] = patch_word(records[2], "result", 0)
        self.assertFalse(report(records)["producer_windows"][0]["accepted_completed_window"])

    def test_failed_append_count_scope_and_begin(self):
        for index, field, value in ((1, "result", -1), (1, "ordinal", 1), (1, "list_count", 2),
                                    (1, "offset", 1), (1, "mode", 1), (1, "caller", 1),
                                    (0, "ordinal", 1), (0, "list_count", 1), (0, "mode", 1),
                                    (0, "result", -1), (0, "offset", -1), (0, "caller", 1)):
            records = window()
            records[index] = patch_word(records[index], field, value & 0xFFFFFFFF)
            with self.subTest(index=index, field=field):
                self.assertFalse(report(records)["producer_windows"][0]["accepted_completed_window"])

    def test_empty_and_truncated_paths(self):
        for kind in (1, 2):
            for path, truncated in (("", 0), ("a" * 259, 1)):
                records = window()
                records[kind - 1] = event(kind - 1, kind, path=path, truncated=truncated)
                self.assertFalse(report(records)["producer_windows"][0]["accepted_completed_window"])

    def test_terminal_and_end_contract(self):
        for index, field, value in ((2, "result", 100), (2, "ordinal", 2), (2, "list_count", 2),
                                    (3, "result", 0), (3, "ordinal", 0), (3, "list_count", 0),
                                    (0, "result", 0)):
            records = window()
            records[index] = patch_word(records[index], field, value)
            self.assertFalse(report(records)["producer_windows"][0]["accepted_completed_window"])

    def test_missing_terminal_end_and_orphan(self):
        self.assertFalse(report(window()[:2])["producer_windows"][0]["accepted_completed_window"])
        self.assertFalse(report([event(0, 1), event(1, 2), event(2, 4)])["producer_windows"][0]["accepted_completed_window"])
        result = report([event(0, 2)])
        self.assertEqual(result["producer_windows"], [])
        self.assertEqual(result["unmatched_producer_events"][0]["seq"], 0)

    def test_duplicate_terminal_and_row_after_terminal(self):
        for middle in ((3, 3), (3, 2)):
            records = [event(0, 1), event(1, 2), event(2, middle[0]), event(3, middle[1]), event(4, 4)]
            self.assertFalse(report(records)["producer_windows"][0]["accepted_completed_window"])

    def test_event_after_end_rejects_corresponding_window(self):
        for kind in (2, 3, 4):
            result = report(window() + [event(4, kind)])
            self.assertFalse(result["producer_windows"][0]["accepted_completed_window"])
            self.assertEqual(len(result["unmatched_producer_events"]), 1)

    def test_orphan_on_same_list_rejects_active_window(self):
        records = [event(0, 1), event(1, 2, frame=0x1111, statement=0x2222), event(2, 2),
                   event(3, 3), event(4, 4)]
        self.assertFalse(report(records)["producer_windows"][0]["accepted_completed_window"])

    def test_duplicate_identity(self):
        records = [event(0, 1, result=2), event(1, 2), event(2, 2, ordinal=1, list_count=2),
                   event(3, 3, ordinal=2, list_count=2), event(4, 4, ordinal=2, result=2, list_count=2)]
        result = report(records)["producer_windows"][0]
        self.assertIn("duplicate path/cue", result["errors"])
        self.assertEqual(result["mapping"], [])

    def test_same_path_distinct_cues_allowed(self):
        records = [event(0, 1, result=2), event(1, 2), event(2, 2, ordinal=1, list_count=2, cue=1),
                   event(3, 3, ordinal=2, list_count=2), event(4, 4, ordinal=2, result=2, list_count=2)]
        self.assertTrue(report(records)["producer_windows"][0]["accepted_completed_window"])

    def test_overlapping_list_and_reused_frame_rejected(self):
        for changes in ({"frame": 0x1111, "statement": 0x2222}, {"statement": 0x2222, "list": 0x3333}, {}):
            records = [event(0, 1), event(1, 1, **changes), event(2, 2, **changes),
                       event(3, 3, **changes), event(4, 4, **changes)]
            windows = report(records)["producer_windows"]
            self.assertEqual(len(windows), 2)
            self.assertTrue(all(not item["accepted_completed_window"] for item in windows))

    def test_sequential_reused_addresses_are_separate_windows_not_generations(self):
        windows = report(window() + window(4))["producer_windows"]
        self.assertEqual(len(windows), 2)
        self.assertTrue(all(item["accepted_completed_window"] for item in windows))
        self.assertEqual([item["begin_seq"] for item in windows], [0, 4])

    def test_loss_rejects_otherwise_good_window(self):
        result = report(window() + [status(4, io_error=1)], final=False)
        self.assertFalse(result["producer_windows"][0]["accepted_completed_window"])

    def test_empty_window(self):
        records = [event(0, 1, result=0), event(1, 3, ordinal=0, list_count=0),
                   event(2, 4, ordinal=0, list_count=0, result=0)]
        observed = report(records)["producer_windows"][0]
        self.assertTrue(observed["accepted_completed_window"])
        self.assertEqual(observed["mapping"], [])

    def test_absolute_index_overflow_rejected(self):
        self.assertTrue(report(window(offset=0x7FFFFFFF))["producer_windows"][0]["accepted_completed_window"])
        records = [event(0, 1, offset=0x7FFFFFFF, result=2), event(1, 2, offset=0x7FFFFFFF),
                   event(2, 2, offset=0x7FFFFFFF, ordinal=1, list_count=2, cue=1),
                   event(3, 3, offset=0x7FFFFFFF, ordinal=2, list_count=2),
                   event(4, 4, offset=0x7FFFFFFF, ordinal=2, result=2, list_count=2)]
        result = report(records)["producer_windows"][0]
        self.assertFalse(result["accepted_completed_window"])


class PlaybackAndMixedTests(unittest.TestCase):
    def test_valid_pair_reports_source_not_global_identity(self):
        result = report([event(0, 5, cue=8), event(1, 6, statement=0)])
        pair = result["playback_copies"][0]
        self.assertTrue(pair["accepted_pair"])
        self.assertEqual(pair["source_identity"]["cue"], 8)
        self.assertEqual(pair["return_value"], 0xADD468)
        self.assertNotIn("current_identity", result)

    def test_missing_before_and_after(self):
        for records in ([event(0, 5)], [event(0, 6)], [event(0, 6), event(1, 5)]):
            self.assertTrue(all(not pair["accepted_pair"] for pair in report(records)["playback_copies"]))

    def test_failed_prepare_reservation(self):
        pair = report([event(0, 6, statement=0xFFFFFFFF)])["playback_copies"][0]
        self.assertIn("playback begin reservation failed", pair["errors"])

    def test_copy_size_caller_source_and_scope_rejection(self):
        for before, after in (({"result": 4}, {}), ({"caller": 1}, {}), ({"path": ""}, {}),
                              ({"path": "a" * 259, "truncated": 1}, {}), ({}, {"frame": 3}),
                              ({"path": "", "truncated": 1}, {}),
                              ({}, {"caller": decoder.PLAYBACK_CALLERS[1]})):
            pair = report([event(0, 5, **before), event(1, 6, **after)])["playback_copies"][0]
            self.assertFalse(pair["accepted_pair"])

    def test_overlapping_distinct_frames_pair_without_global_order_claim(self):
        pairs = report([event(0, 5), event(1, 5, frame=0x1111),
                        event(2, 6, statement=1, frame=0x1111), event(3, 6, statement=0)])["playback_copies"]
        self.assertTrue(all(pair["accepted_pair"] for pair in pairs))
        self.assertTrue(all(pair["overlapping_copy_observations"] for pair in pairs))

    def test_reused_frame_and_duplicate_end(self):
        pairs = report([event(0, 5), event(1, 5), event(2, 6, statement=1),
                        event(3, 6, statement=0), event(4, 6, statement=0)])["playback_copies"]
        self.assertEqual(len(pairs), 3)
        self.assertTrue(all(not pair["accepted_pair"] for pair in pairs))

    def test_duplicate_end_rejects_original_pair(self):
        pairs = report([event(0, 5), event(1, 6), event(2, 6)])["playback_copies"]
        self.assertEqual(len(pairs), 2)
        self.assertTrue(all(not pair["accepted_pair"] for pair in pairs))

    def test_loss_rejects_otherwise_good_pair(self):
        pair = report([event(0, 5), event(1, 6), status(2, contention_loss=1)], final=False)["playback_copies"][0]
        self.assertFalse(pair["accepted_pair"])

    def test_good_mixed_sequence(self):
        records = [status(0), event(0, 1, result=2), event(1, 5, cue=5), event(2, 7), event(3, 2),
                   event(4, 10, offset=-8), event(5, 2, ordinal=1, list_count=2, path="\\Music\\Slayer\\02.flac"),
                   event(6, 6, statement=1), event(7, 3, ordinal=2, list_count=2),
                   event(8, 4, ordinal=2, result=2, list_count=2), event(9, 7, mode=3), event(10, 9), event(11, 8)]
        result = report(records)
        self.assertTrue(result["accepted_prefix"])
        self.assertTrue(result["producer_windows"][0]["accepted_completed_window"])
        self.assertTrue(result["playback_copies"][0]["accepted_pair"])
        self.assertEqual(result["event_count"], 12)
        self.assertEqual(result["counts"]["touch"], 2)
        self.assertEqual(result["counts"]["refresh"], 1)

    def test_cli_json_report_and_events(self):
        raw = event(0, 7) + status(1)
        for arguments in (["ignored.bin"], ["ignored.bin", "--events"]):
            output = io.StringIO()
            with mock.patch.object(decoder.Path, "read_bytes", return_value=raw), contextlib.redirect_stdout(output):
                decoder.main(arguments)
            if "--events" in arguments:
                self.assertEqual([json.loads(line)["kind"] for line in output.getvalue().splitlines()], ["touch", "status"])
            else:
                self.assertTrue(json.loads(output.getvalue())["accepted_prefix"])

    def test_cli_rejects_invalid_log(self):
        output = io.StringIO()
        with mock.patch.object(decoder.Path, "read_bytes", return_value=b"bad"), contextlib.redirect_stderr(output):
            with self.assertRaises(SystemExit) as caught:
                decoder.main(["ignored.bin"])
        self.assertEqual(caught.exception.code, 2)
        self.assertIn("invalid bridge trace", output.getvalue())


if __name__ == "__main__":
    unittest.main()
