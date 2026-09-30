#!/usr/bin/env python3
"""Offline conservative cache-index model, NOT a device memory reader."""
import unittest


def locate(capacity, start, slots, extra, path, cue):
    """Inputs must be an already consistent snapshot. None means unproven.

    slots maps cache slots to (path, cue); extra holds (absolute index,path,cue).
    Exact matches deliberately reject prefix-only paths and conflicting data.
    This model neither calls getters nor validates live object lifetimes.
    """
    if capacity <= 0 or start < 0 or not path:
        return None
    entries = {}
    for slot, identity in slots.items():
        index = start + slot
        if slot < 0 or slot >= capacity or index % capacity != slot:
            return None
        entries[index] = identity
    for index, item_path, item_cue in extra:
        identity = (item_path, item_cue)
        if index < 0 or (index in entries and entries[index] != identity):
            return None
        entries[index] = identity
    matches = [index for index, identity in entries.items() if identity == (path, cue)]
    return matches[0] if len(matches) == 1 else None


class Tests(unittest.TestCase):
    def test_cue_not_row(self):
        slayer = {i: ('Slayer.flac', i) for i in range(13)}
        sleep = {0: ('covers', -2), **{i + 1: ('Sleep.flac', i) for i in range(6)}}
        self.assertEqual(locate(512, 0, slayer, [], 'Slayer.flac', 5), 5)
        self.assertEqual(locate(512, 0, sleep, [], 'Sleep.flac', 0), 1)

    def test_nonzero_window_and_extra(self):
        self.assertEqual(locate(512, 512, {7: ('x', 2)}, [], 'x', 2), 519)
        self.assertEqual(locate(512, 512, {}, [(8, 'x', 2)], 'x', 2), 8)

    def test_fail_closed(self):
        for capacity, start, slots, extra in (
            (0, 0, {}, []), (512, -1, {}, []),
            (512, 1, {0: ('x', 2)}, []),
            (512, 0, {0: ('x', 2), 1: ('x', 2)}, []),
            (512, 0, {0: ('x', 2)}, [(0, 'other', 2)]),
            (512, 0, {}, [(-1, 'x', 2)]),
        ):
            self.assertIsNone(locate(capacity, start, slots, extra, 'x', 2))
        self.assertIsNone(locate(512, 0, {0: ('x-long', 2)}, [], 'x', 2))
        self.assertIsNone(locate(512, 0, {0: ('x', 3)}, [], 'x', 2))

    def test_duplicate_copy_same_index_is_not_second_match(self):
        self.assertEqual(locate(512, 0, {0: ('x', 2)}, [(0, 'x', 2)], 'x', 2), 0)


if __name__ == '__main__': unittest.main()
