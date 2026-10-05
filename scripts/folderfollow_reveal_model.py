#!/usr/bin/env python3
"""Executable, host-only specification for one-shot Files row reveal.

No ADB, firmware patch, live pointer reader, or UI calls. All inputs must be
owned, coherent copies. Epochs are abstract non-reused generation tokens: the
firmware adapter that could safely supply them has NOT been implemented.
Passing these model checks is not proof of live lifetime or synchronization.
"""

from __future__ import annotations

from dataclasses import dataclass


INT_MAX = (1 << 31) - 1
MAX_ROWS = 512  # Initial scope: a complete zero-offset folder, not a window.


def _integer(value: object, low: int = 0, high: int = INT_MAX) -> bool:
    return type(value) is int and low <= value <= high


@dataclass(frozen=True)
class Identity:
    path: str
    cue: int

    def valid(self) -> bool:
        return (isinstance(self.path, str) and bool(self.path)
                and '\0' not in self.path
                and _integer(self.cue, -(1 << 31)))

    def folder(self) -> str | None:
        """Exact firmware spelling only; no case, separator or prefix folding."""
        if not self.valid():
            return None
        parent, separator, leaf = self.path.rpartition('\\')
        if not parent or not separator or not leaf or '*' in leaf:
            return None
        return parent + '\\*'


@dataclass(frozen=True)
class ViewGeneration:
    folder: str
    view_epoch: int
    contents_epoch: int

    def valid(self) -> bool:
        return (isinstance(self.folder, str) and len(self.folder) > 2
                and self.folder.endswith('\\*') and '\0' not in self.folder
                and _integer(self.view_epoch) and _integer(self.contents_epoch))


@dataclass(frozen=True)
class CompletedRows:
    """Copied complete fill, usable only under an externally proven epoch.

    The constructor validates representation, not producer completion. Use
    from_fill for the model's completion checks. Neither route establishes
    that a recorded fill is still the active live list.
    """

    generation: ViewGeneration
    entries: tuple[Identity, ...]

    def __post_init__(self) -> None:
        # Copy caller-owned containers; never retain a mutable row list.
        object.__setattr__(self, 'entries', tuple(self.entries))
        if (not self.generation.valid() or len(self.entries) > MAX_ROWS
                or any(not isinstance(row, Identity) or not row.valid()
                       for row in self.entries)
                or len(set(self.entries)) != len(self.entries)):
            raise ValueError('invalid or ambiguous completed row representation')

    @classmethod
    def from_fill(cls, generation, entries, append_results, *, total_count,
                  final_count, terminal, offset=0, initial_count=0, mode=0):
        """Reject partial/failed/windowed fills; integer append zero is success.

        Inputs correspond to one already validated, non-interleaved producer
        session with no lost records. Total must belong to that same folder
        generation, not a stale cache-owner field. See the integration note.
        """
        entries, append_results = tuple(entries), tuple(append_results)
        if (type(terminal) is not int or terminal != 101
                or type(offset) is not int or offset != 0
                or type(initial_count) is not int or initial_count != 0
                or type(mode) is not int or mode != 0
                or not _integer(total_count, 0, MAX_ROWS)
                or not _integer(final_count, 0, MAX_ROWS)
                or total_count != len(entries)
                or final_count != len(entries)
                or len(append_results) != len(entries)
                or any(type(result) is not int or result != ordinal
                       for ordinal, result in enumerate(append_results))):
            return None
        try:
            return cls(generation, entries)
        except (AttributeError, TypeError, ValueError):
            return None

    def locate(self, identity: Identity) -> int | None:
        # Uniqueness was checked at creation; row zero is not a missing result.
        try:
            return self.entries.index(identity)
        except ValueError:
            return None


@dataclass(frozen=True)
class Geometry:
    scroll_y: int
    pitch: int
    height: int


def minimal_reveal(row: int, count: int, geometry: Geometry) -> int | None:
    """Return bounded minimal y, unchanged y if visible, None if unsupported.

    The Files setter does not clamp the measured flags=2 case. Do not use its
    raw extent (observed zero) or 'repair' a user's transient overscroll here.
    All arithmetic must also be safe for a later signed 32-bit implementation.
    Rows taller than the viewport are deliberately outside this first model.
    """
    y, pitch, height = geometry.scroll_y, geometry.pitch, geometry.height
    if (not _integer(count, 1, MAX_ROWS) or not _integer(row, 0, count - 1)
            or not _integer(pitch, 1) or not _integer(height, pitch)
            or not _integer(y) or count > INT_MAX // pitch):
        return None
    extent = count * pitch
    limit = max(0, extent - height)
    if y > limit or y > INT_MAX - height:
        return None
    top, bottom = row * pitch, (row + 1) * pitch
    if top < y:
        target = top
    elif bottom > y + height:
        target = bottom - height
    else:
        return y
    return min(limit, max(0, target))


@dataclass(frozen=True)
class Snapshot:
    playback: Identity | None
    view: ViewGeneration | None
    manual_epoch: int
    rows: CompletedRows | None = None
    geometry: Geometry | None = None
    # Explicit adapter input, including gesture settling/coasting if applicable.
    # Unchanged y or an unchanged epoch does not prove that manual input ended.
    manual_active: bool = False


@dataclass(frozen=True)
class Action:
    identity: Identity
    rows: CompletedRows
    manual_epoch: int
    geometry: Geometry
    row: int
    target_y: int


@dataclass(frozen=True)
class Decision:
    reason: str
    action: Action | None = None


def validate_action(action: Action, current: Snapshot) -> bool:
    """Model a final pre-act check, NOT a lock or an atomic live transaction.

    Rejection consumes the one-shot attempt; the caller must not cache/retry
    this action. A real adapter must maintain ownership/serialization through
    setter and refresh, not merely compare snapshots and hope for stability.
    """
    if (not isinstance(action.rows, CompletedRows)
            or not isinstance(action.geometry, Geometry)
            or not isinstance(action.identity, Identity)
            or not _integer(action.target_y)):
        return False
    target = minimal_reveal(action.row, len(action.rows.entries), action.geometry)
    return (target is not None and target == action.target_y
            and current.playback == action.identity
            and current.view == action.rows.generation
            and current.rows == action.rows
            and _integer(current.manual_epoch)
            and current.manual_epoch == action.manual_epoch
            and current.manual_active is False
            and current.geometry == action.geometry
            and action.identity.folder() == action.rows.generation.folder
            and action.rows.locate(action.identity) == action.row
            and action.target_y != action.geometry.scroll_y)


@dataclass
class _Pending:
    identity: Identity
    view: ViewGeneration | None
    manual_epoch: int
    ticks_left: int


class RevealModel:
    """Baseline, confirm a change, then make at most one reveal proposal.

    Observe every coherent playback sample, even outside Files. The first
    sample only establishes a baseline. A new identity needs two consecutive
    equal samples; this filters jitter but is NOT an atomic playback read.
    Navigation, generation changes, manual input and unsupported scopes
    consume the transition. Missing ready rows may wait a bounded number of
    observations, but must never survive any of those cancellation events.
    max_wait_ticks is a policy budget, not a verified hardware timer interval.
    """

    def __init__(self, max_wait_ticks: int = 8):
        if not _integer(max_wait_ticks, 1):
            raise ValueError('max_wait_ticks must be a positive integer')
        self.max_wait_ticks = max_wait_ticks
        self._committed: Identity | None = None
        self._last_seen: Identity | None = None
        self._candidate: _Pending | None = None
        self._pending: _Pending | None = None
        self._previous: tuple[ViewGeneration | None, int] | None = None

    def observe(self, snapshot: Snapshot) -> Decision:
        context = (snapshot.view, snapshot.manual_epoch)
        interaction = self._previous is not None and context != self._previous
        self._previous = context

        identity = snapshot.playback
        if (not _integer(snapshot.manual_epoch) or identity is None
                or not identity.valid() or identity.folder() is None):
            self._committed = self._last_seen = None
            self._candidate = self._pending = None
            return Decision('no-valid-playback')

        # Cancel even before the second sample, not just after confirmation.
        if interaction or snapshot.manual_active is not False:
            if self._candidate is not None:
                self._candidate.view = None
            self._pending = None

        if self._committed is None:
            self._committed = self._last_seen = identity
            return Decision('baseline')

        if identity != self._last_seen:
            self._last_seen = identity
            self._pending = None
            self._candidate = None
            if identity == self._committed:
                return Decision('returned-to-baseline')
            view = snapshot.view
            eligible = (not interaction and snapshot.manual_active is False
                        and view is not None and view.valid()
                        and identity.folder() == view.folder)
            self._candidate = _Pending(identity, view if eligible else None,
                                       snapshot.manual_epoch, self.max_wait_ticks)
            return Decision('await-stable-identity')

        if self._candidate is not None:
            self._committed = identity  # Consume even inactive/cancelled changes.
            self._pending, self._candidate = self._candidate, None

        pending = self._pending
        if pending is None:
            return Decision('unchanged-or-cancelled')
        if (pending.view is None or pending.view != snapshot.view
                or pending.manual_epoch != snapshot.manual_epoch):
            self._pending = None
            return Decision('cancelled-context')

        pending.ticks_left -= 1
        if snapshot.rows is None or snapshot.geometry is None:
            if pending.ticks_left <= 0:
                self._pending = None
                return Decision('readiness-expired')
            return Decision('await-ready-rows')

        # Ready data is evaluated once, including missing/invalid targets.
        self._pending = None
        rows, geometry = snapshot.rows, snapshot.geometry
        if rows.generation != pending.view:
            return Decision('stale-rows')
        row = rows.locate(identity)
        if row is None:
            return Decision('missing-row')
        target = minimal_reveal(row, len(rows.entries), geometry)
        if target is None:
            return Decision('invalid-geometry')
        if target == geometry.scroll_y:
            return Decision('already-visible')
        return Decision('reveal', Action(identity, rows, snapshot.manual_epoch,
                                         geometry, row, target))
