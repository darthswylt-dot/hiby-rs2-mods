#!/usr/bin/env python3
"""Host-only producer publication protocol over already-owned scalar copies.

Each method models one serialized bridge event. This is NOT a thread-safe
mailbox, live pointer reader, firmware hook, or source of owner generations.
The bridge must invalidate BEFORE stock mutation and supply coherent inputs.
No stock post-fill/wake-up result substitutes for the explicit terminal event.
"""

from dataclasses import dataclass, field

from folderfollow_reveal_model import (
    CompletedRows, Identity, INT_MAX, MAX_ROWS, ViewGeneration,
)


def _int(value, low=0, high=INT_MAX):
    return type(value) is int and low <= value <= high


def _path(value):
    if type(value) is not str or not value or '\0' in value:
        return False
    try:
        return len(value.encode('utf-16-le')) <= 259 * 2
    except UnicodeEncodeError:
        return False


@dataclass
class _Fill:
    total: int
    rows: list[Identity] = field(default_factory=list)
    identities: set[Identity] = field(default_factory=set)
    terminal: bool = False


class RowPublication:
    """One bounded fill per externally established content generation.

    Content epochs must strictly increase globally for this instance, even
    across view replacement. Tickets are issued here and never reused; old
    events cannot relabel data with a new generation. A fault requires a new
    externally verified generation, not another post-fill callback. Outstanding
    immutable snapshots remain values, not authority to operate on a view.
    """

    def __init__(self, ticket_limit=INT_MAX):
        if not _int(ticket_limit, 1):
            raise ValueError('ticket limit must be a positive signed word')
        self._limit = ticket_limit
        self._serial = 0
        self._epoch = -1
        self._view = None
        self._ticket = None
        self._fill = None
        self._rows = None
        self._started = False
        self._error = None

    @property
    def view(self):
        return self._view

    @property
    def rows(self):
        return self._rows

    @property
    def error(self):
        return self._error

    def _fail(self, reason):
        self._fill = self._rows = None
        self._error = reason

    def activate(self, generation):
        """Cancel before owner/scope mutation; None deactivates the consumer.

        A nonnull generation is supplied by the bridge, not inferred from
        list addresses, names, total counts or a later resolve-by-name callback.
        """
        self._view = self._ticket = self._fill = self._rows = None
        self._started = False
        self._error = None
        if generation is None:
            return True
        if (type(generation) is not ViewGeneration or not generation.valid()
                or not _path(generation.folder)
                or generation.contents_epoch <= self._epoch):
            self._fail('invalid-or-reused-generation')
            return False
        self._epoch = generation.contents_epoch
        self._view = generation
        return True

    def begin(self, generation, *, total_count, requested_count,
              offset=0, initial_count=0, mode=0):
        # A late begin belonging to another generation must not destroy the
        # current generation. Same-generation reentry, however, is a fault.
        if (type(generation) is not ViewGeneration or not generation.valid()
                or self._view is None or generation != self._view):
            return None
        if self._error is not None:
            return None
        if self._started:
            self._fail('repeated-or-overlapping-fill')
            return None
        self._started = True
        if (not _int(total_count, 0, MAX_ROWS)
                or not _int(requested_count, 0, MAX_ROWS)
                or requested_count < total_count
                or any(type(v) is not int or v != 0
                       for v in (offset, initial_count, mode))):
            self._fail('unsupported-fill')
            return None
        if self._serial == self._limit:
            self._fail('ticket-exhausted')
            return None
        self._serial += 1
        self._ticket = self._serial
        self._fill = _Fill(total_count)
        return self._ticket

    def _current(self, ticket):
        if not _int(ticket, 1) or ticket != self._ticket:
            return None  # Stale generation's late event, no current mutation.
        if self._fill is None:
            self._fail('event-outside-fill')
        return self._fill

    def append(self, ticket, *, ordinal, identity, result, list_count):
        fill = self._current(ticket)
        if fill is None:
            return False
        n = len(fill.rows)
        if (fill.terminal or n >= fill.total
                or not _int(ordinal) or ordinal != n
                or not _int(result) or result != n
                or not _int(list_count) or list_count != n + 1
                or type(identity) is not Identity or not identity.valid()
                or not _path(identity.path) or identity in fill.identities):
            self._fail('row-or-append-mismatch')
            return False
        copied = Identity(identity.path, identity.cue)
        fill.rows.append(copied)
        fill.identities.add(copied)
        return True

    def terminal(self, ticket, *, result, ordinal, list_count):
        fill = self._current(ticket)
        if fill is None:
            return False
        n = len(fill.rows)
        if (fill.terminal or type(result) is not int or result != 101
                or not _int(ordinal) or ordinal != n
                or not _int(list_count) or list_count != n):
            self._fail('query-completion-not-confirmed')
            return False
        fill.terminal = True
        return True

    def finish(self, ticket, *, result, list_count):
        fill = self._current(ticket)
        if fill is None:
            return None
        n = len(fill.rows)
        if (not fill.terminal or not _int(result) or result != n
                or not _int(list_count) or list_count != n or n != fill.total):
            self._fail('incomplete-fill')
            return None
        self._rows = CompletedRows.from_fill(
            self._view, fill.rows, range(n), total_count=fill.total,
            final_count=list_count, terminal=101)
        self._fill = None
        return self._rows

    def lost_event(self):
        """Bridge-reported loss/uncertainty poisons this content generation."""
        self._fail('lost-or-uncertain-event')
