#!/usr/bin/env python3
"""Proposed offline fill-event validation; not a live-cache implementation."""
import unittest


def validate_fill(offset, initial_count, events, produced, final_count, complete):
    """Accept only an observed complete fill of an initially empty list.

    Event = (ordinal, append_result, exact_path, cue). No pointers are retained.
    This is a proposed protocol, not a decoder of existing SCRL v1 records.
    """
    if offset < 0 or initial_count != 0 or not complete or produced < 0:
        return None
    if produced != len(events) or final_count != produced:
        return None
    mapping = {}
    for expected, (ordinal, result, path, cue) in enumerate(events):
        if ordinal != expected or result != expected or not path:
            return None
        identity = (path, cue)
        if identity in mapping:
            return None
        mapping[identity] = offset + ordinal
    return mapping


class Tests(unittest.TestCase):
    def test_zero_append_result_and_nonzero_offset(self):
        self.assertEqual(validate_fill(512, 0, [(0, 0, 'x', 7)], 1, 1, True), {('x', 7): 512})

    def test_failed_append_can_still_increase_producer_count(self):
        self.assertIsNone(validate_fill(0, 0, [(0, 0, 'x', 0), (1, -1, 'x', 1),
                                             (2, 1, 'x', 2)], 3, 2, True))

    def test_missing_reordered_or_duplicated_events(self):
        for events in ([(1, 1, 'x', 1)], [(1, 1, 'x', 1), (0, 0, 'x', 0)],
                       [(0, 0, 'x', 0), (0, 0, 'x', 0)]):
            self.assertIsNone(validate_fill(0, 0, events, 2, 2, True))

    def test_not_ready_from_pointer_publication(self):
        self.assertIsNone(validate_fill(0, 0, [(0, 0, 'x', 0)], 1, 1, False))
        self.assertIsNone(validate_fill(0, 1, [(0, 1, 'x', 0)], 1, 2, True))

    def test_clear_same_address_requires_new_session(self):
        first = validate_fill(0, 0, [(0, 0, 'old', 0)], 1, 1, True)
        second = validate_fill(512, 0, [(0, 0, 'new', 0)], 1, 1, True)
        self.assertEqual(first, {('old', 0): 0})
        self.assertEqual(second, {('new', 0): 512})
        self.assertNotIn(('old', 0), second)


if __name__ == '__main__': unittest.main()
