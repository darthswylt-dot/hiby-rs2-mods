#!/usr/bin/env python3
"""Offline reveal-policy contracts only; these tests do not access a player."""
from dataclasses import replace
import unittest

from folderfollow_reveal_model import (
    CompletedRows,
    Geometry,
    Identity,
    RevealModel,
    Snapshot,
    ViewGeneration,
    minimal_reveal,
    validate_action,
)


FOLDER = r"0:\Slayer\Show No Mercy\*"
MEDIA = r"0:\Slayer\Show No Mercy\Show No Mercy.flac"


def identity(cue=0, path=MEDIA):
    return Identity(path, cue)


def generation(folder=FOLDER, view_epoch=1, contents_epoch=1):
    return ViewGeneration(folder, view_epoch, contents_epoch)


def complete_rows(view=None, entries=None):
    view = generation() if view is None else view
    entries = tuple(identity(cue) for cue in range(13)) if entries is None else entries
    return CompletedRows.from_fill(
        view, entries, tuple(range(len(entries))), total_count=len(entries),
        final_count=len(entries), terminal=101
    )


def snapshot(cue=0, *, view=None, rows=None, geometry=None, manual_epoch=0):
    view = generation() if view is None else view
    rows = complete_rows(view) if rows is None else rows
    geometry = Geometry(0, 80, 260) if geometry is None else geometry
    return Snapshot(identity(cue), view, manual_epoch, rows, geometry)


class GeometryTests(unittest.TestCase):
    def test_minimal_downward_reveal(self):
        for row, expected in ((3, 60), (5, 220), (12, 780)):
            with self.subTest(row=row):
                self.assertEqual(minimal_reveal(row, 13, Geometry(0, 80, 260)), expected)

    def test_already_visible_does_not_move(self):
        for row in (1, 2, 3):
            with self.subTest(row=row):
                self.assertEqual(minimal_reveal(row, 13, Geometry(60, 80, 260)), 60)

    def test_minimal_upward_reveal(self):
        self.assertEqual(minimal_reveal(2, 13, Geometry(400, 80, 260)), 160)

    def test_last_row_clamps_to_actual_content_end(self):
        self.assertEqual(minimal_reveal(12, 13, Geometry(200, 80, 260)), 780)

    def test_short_folder_stays_at_zero(self):
        self.assertEqual(minimal_reveal(1, 2, Geometry(0, 80, 260)), 0)

    def test_invalid_indices_counts_and_dimensions(self):
        for row, count, geometry in (
            (-1, 13, Geometry(0, 80, 260)),
            (13, 13, Geometry(0, 80, 260)),
            (0, 0, Geometry(0, 80, 260)),
            (0, -1, Geometry(0, 80, 260)),
            (0, 13, Geometry(0, 0, 260)),
            (0, 13, Geometry(0, -80, 260)),
            (0, 13, Geometry(0, 80, 0)),
            (0, 13, Geometry(0, 80, -260)),
            (0, 13, Geometry(0, 80, 79)),
        ):
            with self.subTest(row=row, count=count, geometry=geometry):
                self.assertIsNone(minimal_reveal(row, count, geometry))

    def test_signed_overflow_rejected(self):
        self.assertIsNone(minimal_reveal(2, 13, Geometry(0, 1 << 30, 260)))
        self.assertIsNone(minimal_reveal(1, 13, Geometry(0, 80, 1 << 31)))

    def test_gesture_overscroll_rejected(self):
        self.assertIsNone(minimal_reveal(5, 13, Geometry(-28, 80, 260)))
        self.assertIsNone(minimal_reveal(5, 13, Geometry(781, 80, 260)))

    def test_non_integer_geometry_and_row_rejected(self):
        for row, count, geometry in (
            (True, 13, Geometry(0, 80, 260)),
            (5.0, 13, Geometry(0, 80, 260)),
            (5, 13.0, Geometry(0, 80, 260)),
            (5, 13, Geometry(False, 80, 260)),
            (5, 13, Geometry(0, 80.0, 260)),
            (5, 13, Geometry(0, 80, 260.0)),
        ):
            with self.subTest(row=row, count=count, geometry=geometry):
                self.assertIsNone(minimal_reveal(row, count, geometry))


class CompletedRowsTests(unittest.TestCase):
    def test_complete_fill_accepted(self):
        rows = complete_rows()
        self.assertIsNotNone(rows)
        self.assertEqual(rows.entries, tuple(identity(cue) for cue in range(13)))

    def test_retains_immutable_copy(self):
        entries = [identity(0), identity(1)]
        rows = complete_rows(entries=entries)
        self.assertIsNotNone(rows)
        entries[0] = identity(12)
        self.assertEqual(rows.entries, (identity(0), identity(1)))
        with self.assertRaises((AttributeError, TypeError)):
            rows.entries = ()

    def test_empty_complete_folder_is_valid(self):
        self.assertIsNotNone(complete_rows(entries=()))

    def test_exactly_512_rows_allowed_but_more_rejected(self):
        self.assertIsNotNone(complete_rows(entries=tuple(identity(cue) for cue in range(512))))
        self.assertIsNone(complete_rows(entries=tuple(identity(cue) for cue in range(513))))

    def test_duplicate_identity_rejected(self):
        self.assertIsNone(complete_rows(entries=(identity(1), identity(1))))

    def test_same_path_different_cues_accepted(self):
        self.assertIsNotNone(complete_rows(entries=(identity(0), identity(1))))

    def test_distinct_paths_same_cue_accepted(self):
        self.assertIsNotNone(complete_rows(entries=(identity(0), identity(0, MEDIA + ".other"))))

    def test_empty_path_rejected(self):
        self.assertIsNone(complete_rows(entries=(identity(0, ""),)))

    def test_nul_path_or_unrepresentable_cue_rejected(self):
        for entry in (identity(0, MEDIA + "\0"), identity(1 << 31), identity(-(1 << 31) - 1)):
            with self.subTest(entry=entry):
                self.assertIsNone(complete_rows(entries=(entry,)))

    def test_partial_nonzero_window_and_wrong_mode_rejected(self):
        entries = (identity(0), identity(1))
        base = dict(total_count=2, final_count=2, terminal=101)
        for changed in (
            {"terminal": 0},
            {"terminal": -1},
            {"offset": 512},
            {"offset": -1},
            {"initial_count": 1},
            {"mode": 1},
            {"total_count": 1},
            {"total_count": 3},
            {"total_count": -1},
            {"final_count": 1},
            {"final_count": 3},
            {"final_count": -1},
        ):
            with self.subTest(changed=changed):
                self.assertIsNone(CompletedRows.from_fill(generation(), entries, (0, 1), **(base | changed)))

    def test_failed_missing_reordered_or_duplicate_append_results_rejected(self):
        entries = (identity(0), identity(1))
        for results in ((0, -1), (0,), (1, 0), (0, 0), (0, 1, 2)):
            with self.subTest(results=results):
                self.assertIsNone(CompletedRows.from_fill(
                    generation(), entries, results, total_count=2,
                    final_count=2, terminal=101
                ))

    def test_completion_evidence_must_be_explicit(self):
        with self.assertRaises(TypeError):
            CompletedRows.from_fill(generation(), (), (), total_count=0)

    def test_booleans_are_not_valid_append_ordinals(self):
        self.assertIsNone(CompletedRows.from_fill(
            generation(), (identity(0),), (False,), total_count=1,
            final_count=1, terminal=101
        ))


class TransitionTests(unittest.TestCase):
    def setUp(self):
        self.model = RevealModel()
        self.assertIsNone(self.model.observe(snapshot()).action)

    def stable_change(self, snap=None):
        snap = snapshot(5) if snap is None else snap
        self.assertIsNone(self.model.observe(snap).action)
        return self.model.observe(snap)

    def test_first_observation_is_baseline_even_when_offscreen(self):
        model = RevealModel()
        for _ in range(3):
            self.assertIsNone(model.observe(snapshot(12)).action)

    def test_change_requires_two_observations_and_one_action(self):
        snap = snapshot(5)
        decision = self.stable_change(snap)
        self.assertIsNotNone(decision.action)
        self.assertEqual(decision.action.identity, identity(5))
        self.assertEqual(decision.action.row, 5)
        self.assertEqual(decision.action.target_y, 220)
        self.assertEqual(decision.action.geometry.scroll_y, 0)
        for _ in range(4):
            self.assertIsNone(self.model.observe(snap).action)

    def test_pause_or_repeated_identity_never_recenters(self):
        self.stable_change()
        manually_moved = snapshot(5, geometry=Geometry(0, 80, 260), manual_epoch=1)
        for _ in range(4):
            self.assertIsNone(self.model.observe(manually_moved).action)

    def test_already_visible_transition_consumed(self):
        self.assertIsNone(self.stable_change(snapshot(1)).action)
        for _ in range(3):
            self.assertIsNone(self.model.observe(snapshot(1, geometry=Geometry(400, 80, 260))).action)

    def test_directory_before_cue_shifts_actual_row(self):
        folder = r"0:\Sleep\*"
        path = r"0:\Sleep\Sleep.flac"
        view = generation(folder)
        entries = (identity(-2, r"0:\Sleep\covers\*"),) + tuple(identity(cue, path) for cue in range(6))
        rows = complete_rows(view, entries)
        model = RevealModel()
        model.observe(Snapshot(identity(0, path), view, 0, rows, Geometry(0, 80, 260)))
        snap = Snapshot(identity(5, path), view, 0, rows, Geometry(0, 80, 260))
        self.assertIsNone(model.observe(snap).action)
        action = model.observe(snap).action
        self.assertIsNotNone(action)
        self.assertEqual(action.row, 6)
        self.assertEqual(action.target_y, 300)

    def test_cue_number_is_not_assumed_to_be_row(self):
        entries = tuple(identity(cue) for cue in (0, 90, 30, 20, 10, 7))
        rows = complete_rows(entries=entries)
        decision = self.stable_change(snapshot(7, rows=rows))
        self.assertIsNotNone(decision.action)
        self.assertEqual(decision.action.row, 5)
        self.assertEqual(decision.action.target_y, 220)

    def test_missing_exact_identity_does_not_fallback_to_cue(self):
        entries = tuple(identity(cue, MEDIA + ".other") for cue in range(13))
        snap = snapshot(5, rows=complete_rows(entries=entries))
        for _ in range(12):
            self.assertIsNone(self.model.observe(snap).action)

    def test_missing_rows_can_complete_during_bounded_wait(self):
        pending = replace(snapshot(5), rows=None)
        self.assertIsNone(self.model.observe(pending).action)
        self.assertIsNone(self.model.observe(pending).action)
        self.assertIsNotNone(self.model.observe(snapshot(5)).action)

    def test_wait_timeout_consumes_transition(self):
        model = RevealModel(max_wait_ticks=3)
        model.observe(snapshot())
        pending = replace(snapshot(5), rows=None)
        for _ in range(6):
            self.assertIsNone(model.observe(pending).action)
        for _ in range(4):
            self.assertIsNone(model.observe(snapshot(5)).action)

    def test_manual_change_cancels_pending_and_consumes_identity(self):
        pending = replace(snapshot(5), rows=None)
        self.model.observe(pending)
        self.assertIsNone(self.model.observe(replace(pending, manual_epoch=1)).action)
        for _ in range(4):
            self.assertIsNone(self.model.observe(snapshot(5, manual_epoch=1)).action)

    def test_view_or_contents_generation_change_cancels_pending(self):
        for changed_view in (generation(view_epoch=2), generation(contents_epoch=2)):
            with self.subTest(view=changed_view):
                model = RevealModel()
                model.observe(snapshot())
                model.observe(replace(snapshot(5), rows=None))
                changed = snapshot(5, view=changed_view)
                for _ in range(4):
                    self.assertIsNone(model.observe(changed).action)

    def test_manual_change_after_confirmation_cancels_readiness_wait(self):
        pending = replace(snapshot(5), rows=None)
        self.model.observe(pending)
        self.model.observe(pending)
        self.assertIsNone(self.model.observe(replace(pending, manual_epoch=1)).action)
        for _ in range(4):
            self.assertIsNone(self.model.observe(snapshot(5, manual_epoch=1)).action)

    def test_track_change_during_ongoing_manual_input_is_consumed(self):
        # A gesture may already be active when a new track is first observed;
        # its epoch need not change again before the next timer tick.
        active = replace(snapshot(5), manual_active=True)
        for _ in range(3):
            self.assertIsNone(self.model.observe(active).action)
        for _ in range(4):
            self.assertIsNone(self.model.observe(snapshot(5)).action)

    def test_ongoing_manual_input_cancels_ready_wait_without_epoch_change(self):
        pending = replace(snapshot(5), rows=None)
        self.model.observe(pending)
        self.model.observe(pending)
        self.assertIsNone(self.model.observe(
            replace(snapshot(5), manual_active=True)).action)
        self.assertIsNone(self.model.observe(snapshot(5)).action)

    def test_inactive_transition_does_not_defer_to_reopen(self):
        inactive = replace(snapshot(5), view=None, rows=None, geometry=None)
        for _ in range(2):
            self.assertIsNone(self.model.observe(inactive).action)
        for _ in range(4):
            self.assertIsNone(self.model.observe(snapshot(5)).action)

    def test_nonmatching_folder_transition_consumed(self):
        other = generation(r"0:\Sleep\*")
        for _ in range(2):
            self.assertIsNone(self.model.observe(snapshot(5, view=other)).action)
        for _ in range(4):
            self.assertIsNone(self.model.observe(snapshot(5)).action)

    def test_folder_comparison_is_exact_not_case_folded(self):
        other = generation(FOLDER.lower())
        for _ in range(4):
            self.assertIsNone(self.model.observe(snapshot(5, view=other)).action)

    def test_empty_identity_resets_baseline(self):
        self.assertIsNone(self.model.observe(replace(snapshot(), playback=identity(0, ""))).action)
        for _ in range(3):
            self.assertIsNone(self.model.observe(snapshot(5)).action)
        self.assertIsNotNone(self.stable_change(snapshot(12)).action)

    def test_transient_new_identity_returning_to_baseline_never_jumps(self):
        self.assertIsNone(self.model.observe(snapshot(5)).action)
        self.assertIsNone(self.model.observe(snapshot()).action)
        self.assertIsNone(self.model.observe(snapshot()).action)

    def test_changing_candidate_restarts_two_observation_requirement(self):
        self.assertIsNone(self.model.observe(snapshot(5)).action)
        self.assertIsNone(self.model.observe(snapshot(12)).action)
        action = self.model.observe(snapshot(12)).action
        self.assertIsNotNone(action)
        self.assertEqual(action.row, 12)

    def test_stale_map_generation_never_scrolls(self):
        stale = complete_rows(generation(contents_epoch=99))
        snap = snapshot(5, rows=stale)
        for _ in range(12):
            self.assertIsNone(self.model.observe(snap).action)

    def test_invalid_geometry_never_scrolls(self):
        snap = snapshot(5, geometry=Geometry(0, 0, 260))
        for _ in range(12):
            self.assertIsNone(self.model.observe(snap).action)


class RevalidationTests(unittest.TestCase):
    def setUp(self):
        self.model = RevealModel()
        self.model.observe(snapshot())
        self.snap = snapshot(5)
        self.model.observe(self.snap)
        self.action = self.model.observe(self.snap).action
        self.assertIsNotNone(self.action)

    def test_identical_snapshot_accepts(self):
        self.assertTrue(validate_action(self.action, self.snap))

    def test_playback_change_rejected(self):
        self.assertFalse(validate_action(self.action, replace(self.snap, playback=identity(6))))

    def test_path_change_with_same_cue_rejected(self):
        self.assertFalse(validate_action(self.action, replace(self.snap, playback=identity(5, MEDIA + ".other"))))

    def test_generation_change_rejected(self):
        for view in (generation(view_epoch=2), generation(contents_epoch=2)):
            with self.subTest(view=view):
                self.assertFalse(validate_action(self.action, replace(self.snap, view=view)))

    def test_manual_epoch_change_rejected(self):
        self.assertFalse(validate_action(self.action, replace(self.snap, manual_epoch=1)))

    def test_ongoing_or_unknown_manual_input_rejected(self):
        for active in (True, None, 0):
            with self.subTest(manual_active=active):
                self.assertFalse(validate_action(
                    self.action, replace(self.snap, manual_active=active)))

    def test_geometry_change_rejected(self):
        for geometry in (Geometry(60, 80, 260), Geometry(0, 81, 260), Geometry(0, 80, 261)):
            with self.subTest(geometry=geometry):
                self.assertFalse(validate_action(self.action, replace(self.snap, geometry=geometry)))

    def test_changed_mapping_same_generation_rejected(self):
        entries = tuple(identity(cue) for cue in (0, 1, 2, 3, 5, 4, 6, 7, 8, 9, 10, 11, 12))
        changed = replace(self.snap, rows=complete_rows(entries=entries))
        self.assertFalse(validate_action(self.action, changed))

    def test_missing_map_view_or_geometry_rejected(self):
        for changed in ({"rows": None}, {"view": None}, {"geometry": None}):
            with self.subTest(changed=changed):
                self.assertFalse(validate_action(self.action, replace(self.snap, **changed)))

    def test_tampered_target_or_row_rejected(self):
        for changed in ({"target_y": 0}, {"row": 6}):
            with self.subTest(changed=changed):
                self.assertFalse(validate_action(replace(self.action, **changed), self.snap))

    def test_invalid_geometry_and_none_target_cannot_compare_as_valid(self):
        geometry = Geometry(0, 0, 260)
        invalid_action = replace(self.action, geometry=geometry, target_y=None)
        invalid_snapshot = replace(self.snap, geometry=geometry)
        self.assertFalse(validate_action(invalid_action, invalid_snapshot))

    def test_numerically_equal_non_integer_target_rejected(self):
        self.assertFalse(validate_action(replace(self.action, target_y=220.0), self.snap))


if __name__ == "__main__":
    unittest.main()
