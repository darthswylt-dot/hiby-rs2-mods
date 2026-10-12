#!/usr/bin/env python3
"""Sequential bridge-event tests, not a simulation of stock thread ownership."""

from dataclasses import replace
from itertools import permutations
import unittest

from folderfollow_reveal_model import (
    Geometry, Identity, RevealModel, Snapshot, ViewGeneration, validate_action,
)
from folderfollow_reveal_publication import RowPublication


FOLDER = '\\SD1\\Slayer\\*'
VIEW = ViewGeneration(FOLDER, 1, 1)
# Same backing file, deliberately non-row cue numbers.
ROWS = tuple(Identity('\\SD1\\Slayer\\Album.flac', cue)
             for cue in (9, 4, 21, 2, 17))


class RowPublicationTests(unittest.TestCase):
    def setUp(self):
        self.p = RowPublication()
        self.assertTrue(self.p.activate(VIEW))

    def begin(self, **changes):
        args = dict(total_count=len(ROWS), requested_count=len(ROWS))
        args.update(changes)
        return self.p.begin(self.p.view, **args)

    def append(self, ticket, i, **changes):
        args = dict(ordinal=i, identity=ROWS[i], result=i, list_count=i + 1)
        args.update(changes)
        return self.p.append(ticket, **args)

    def complete(self):
        ticket = self.begin()
        for i in range(len(ROWS)):
            self.assertTrue(self.append(ticket, i))
            self.assertIsNone(self.p.rows)
        self.assertTrue(self.p.terminal(ticket, result=101, ordinal=5, list_count=5))
        self.assertIsNone(self.p.rows)
        return self.p.finish(ticket, result=5, list_count=5)

    def test_publish_only_after_terminal_and_end_and_locate_by_path_cue(self):
        rows = self.complete()
        self.assertEqual(rows.entries, ROWS)
        self.assertEqual(rows.generation, VIEW)
        self.assertEqual(rows.locate(ROWS[4]), 4)
        self.assertIs(rows, self.p.rows)
        self.assertIsNot(rows.entries[0], ROWS[0])

    def test_empty_complete_folder(self):
        t = self.begin(total_count=0, requested_count=0)
        self.assertTrue(self.p.terminal(t, result=101, ordinal=0, list_count=0))
        self.assertEqual(self.p.finish(t, result=0, list_count=0).entries, ())

    def test_begin_rejects_partial_window_and_invalid_counts(self):
        for changed in ({'offset': 1}, {'mode': 1}, {'initial_count': 1},
                        {'requested_count': 4}, {'total_count': 513},
                        {'requested_count': 513}, {'total_count': -1},
                        {'total_count': True}, {'offset': False}):
            with self.subTest(changed=changed):
                self.setUp()
                self.assertIsNone(self.begin(**changed))
                self.assertIsNone(self.p.rows)
                self.assertIsNone(self.begin())

    def test_maximum_bound_and_actual_row_count(self):
        t = self.begin(total_count=512, requested_count=512)
        for i in range(512):
            self.assertTrue(self.p.append(
                t, ordinal=i, identity=replace(ROWS[0], cue=i),
                result=i, list_count=i + 1))
        self.assertTrue(self.p.terminal(t, result=101, ordinal=512, list_count=512))
        self.assertEqual(len(self.p.finish(t, result=512, list_count=512).entries), 512)

    def test_row_mismatches_poison_generation(self):
        for changed in ({'ordinal': 1}, {'result': -1}, {'result': True},
                        {'list_count': 0}, {'identity': Identity('', 0)},
                        {'identity': Identity('x\0y', 0)},
                        {'identity': Identity('x', True)},
                        {'identity': Identity('x' * 260, 0)},
                        {'identity': Identity('\ud800', 0)}):
            with self.subTest(changed=changed):
                self.setUp()
                t = self.begin()
                self.assertFalse(self.append(t, 0, **changed))
                self.assertFalse(self.append(t, 0))
                self.assertIsNone(self.p.finish(t, result=0, list_count=0))

    def test_utf16_limit_counts_code_units_not_python_characters(self):
        t = self.begin(total_count=1, requested_count=1)
        self.assertFalse(self.append(t, 0, identity=Identity('\U0001F600' * 130, 0)))

    def test_duplicate_identity_not_confused_with_reused_backing_file(self):
        t = self.begin()
        self.assertTrue(self.append(t, 0))
        self.assertFalse(self.append(t, 1, identity=ROWS[0]))
        self.assertIsNone(self.p.rows)

    def test_missing_or_duplicate_terminal_and_late_row(self):
        t = self.begin()
        self.assertIsNone(self.p.finish(t, result=0, list_count=0))
        for late in ('terminal', 'row'):
            self.setUp()
            t = self.begin()
            self.assertTrue(self.p.terminal(t, result=101, ordinal=0, list_count=0))
            if late == 'terminal':
                self.assertFalse(self.p.terminal(t, result=101, ordinal=0, list_count=0))
            else:
                self.assertFalse(self.append(t, 0))
            self.assertIsNone(self.p.rows)

    def test_terminal_error_or_count_mismatch(self):
        for changed in ({'result': 100}, {'result': -1}, {'ordinal': 1},
                        {'list_count': 1}, {'ordinal': False}):
            self.setUp()
            t = self.begin()
            args = dict(result=101, ordinal=0, list_count=0)
            args.update(changed)
            self.assertFalse(self.p.terminal(t, **args))

    def test_success_terminal_does_not_make_partial_fill_complete(self):
        t = self.begin()
        self.assertTrue(self.append(t, 0))
        self.assertTrue(self.p.terminal(t, result=101, ordinal=1, list_count=1))
        self.assertIsNone(self.p.finish(t, result=1, list_count=1))

    def test_end_count_and_return_are_independently_required(self):
        for result, count in ((0, 1), (1, 0), (True, 1)):
            self.setUp()
            t = self.begin(total_count=1, requested_count=1)
            self.assertTrue(self.append(t, 0))
            self.assertTrue(self.p.terminal(t, result=101, ordinal=1, list_count=1))
            self.assertIsNone(self.p.finish(t, result=result, list_count=count))

    def test_overlap_cannot_relabel_first_fill(self):
        old = self.begin()
        self.assertIsNone(self.begin())
        self.assertFalse(self.append(old, 0))
        self.assertIsNone(self.begin())
        self.assertTrue(self.p.activate(replace(VIEW, contents_epoch=2)))
        self.assertIsNotNone(self.begin())

    def test_invalidation_at_each_stage_discards_late_old_events(self):
        for stage in range(8):
            with self.subTest(stage=stage):
                self.setUp()
                old = self.begin()
                for i in range(min(stage, 5)):
                    self.append(old, i)
                if stage >= 6:
                    self.p.terminal(old, result=101, ordinal=5, list_count=5)
                if stage >= 7:
                    self.p.finish(old, result=5, list_count=5)
                new_view = replace(VIEW, contents_epoch=2)
                self.assertTrue(self.p.activate(new_view))
                current = self.begin()
                self.assertFalse(self.append(old, 0))
                self.assertFalse(self.p.terminal(old, result=101, ordinal=5, list_count=5))
                self.assertIsNone(self.p.finish(old, result=5, list_count=5))
                self.assertIsNone(self.p.begin(VIEW, total_count=5, requested_count=5))
                self.assertTrue(self.append(current, 0))
                self.assertIsNone(self.p.error)
                self.assertIsNone(self.p.rows)

    def test_reported_loss_clears_ready_or_loading_snapshot(self):
        for ready in (False, True):
            self.setUp()
            self.complete() if ready else self.begin()
            self.p.lost_event()
            self.assertIsNone(self.p.rows)
            self.assertIsNone(self.begin())

    def test_reused_generation_rejected_even_after_deactivation(self):
        self.complete()
        self.assertTrue(self.p.activate(None))
        self.assertFalse(self.p.activate(VIEW))
        self.assertIsNone(self.p.view)
        self.assertIsNone(self.p.rows)
        self.assertFalse(self.p.activate(replace(VIEW, view_epoch=2)))
        self.assertTrue(self.p.activate(replace(VIEW, view_epoch=2, contents_epoch=2)))

    def test_repeated_end_or_begin_revokes_current_snapshot(self):
        for event in ('end', 'begin', 'row'):
            self.setUp()
            self.complete()
            if event == 'end':
                self.p.finish(1, result=5, list_count=5)
            elif event == 'begin':
                self.begin()
            else:
                self.append(1, 0)
            self.assertIsNone(self.p.rows)

    def test_ticket_exhaustion_does_not_wrap_after_new_generation(self):
        self.p = RowPublication(ticket_limit=1)
        self.p.activate(VIEW)
        self.assertEqual(self.begin(), 1)
        self.p.activate(replace(VIEW, contents_epoch=2))
        self.assertIsNone(self.begin())
        self.assertEqual(self.p.error, 'ticket-exhausted')
        self.p.activate(replace(VIEW, contents_epoch=3))
        self.assertIsNone(self.begin())

    def test_boolean_ticket_is_not_integer_ticket_one(self):
        self.begin()
        self.assertFalse(self.append(True, 0))
        self.assertTrue(self.append(1, 0))

    def test_invalid_constructor_and_generation(self):
        for limit in (0, -1, True, 1 << 31):
            with self.assertRaises(ValueError):
                RowPublication(limit)
        for generation in (object(), replace(VIEW, contents_epoch=True),
                           replace(VIEW, folder='x' * 260 + '\\*')):
            self.assertFalse(self.p.activate(generation))
            self.assertIsNone(self.p.rows)

    def test_malformed_equal_generation_does_not_start_fill(self):
        self.assertIsNone(self.p.begin(
            replace(VIEW, contents_epoch=True), total_count=5, requested_count=5))
        self.assertIsNotNone(self.begin())

    def test_only_append_terminal_end_order_can_publish_one_row(self):
        for order in permutations(('append', 'terminal', 'end')):
            with self.subTest(order=order):
                self.setUp()
                t = self.begin(total_count=1, requested_count=1)
                for event in order:
                    if event == 'append':
                        self.append(t, 0, identity=replace(ROWS[0], cue=-1))
                    elif event == 'terminal':
                        self.p.terminal(t, result=101, ordinal=1, list_count=1)
                    else:
                        self.p.finish(t, result=1, list_count=1)
                self.assertEqual(self.p.rows is not None,
                                 order == ('append', 'terminal', 'end'))

    def test_published_rows_integrate_with_reveal_and_cancel_before_act(self):
        self.complete()
        model = RevealModel()
        first = Snapshot(ROWS[0], self.p.view, 0, self.p.rows, Geometry(0, 80, 260))
        model.observe(first)
        current = replace(first, playback=ROWS[4])
        model.observe(current)
        action = model.observe(current).action
        self.assertEqual(action.row, 4)
        self.assertEqual(action.target_y, 140)
        self.assertTrue(validate_action(action, current))
        self.p.activate(replace(VIEW, contents_epoch=2))
        self.assertFalse(validate_action(
            action, replace(current, view=self.p.view, rows=self.p.rows)))


if __name__ == '__main__':
    unittest.main()
