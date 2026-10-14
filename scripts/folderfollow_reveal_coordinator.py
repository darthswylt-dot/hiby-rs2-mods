"""Host-only event coordinator for one-use, cancellation-fenced reveal proposals.

Inputs are already-owned, coherent values delivered in serialized order.
The epochs below belong to this MODEL, not to observed stock pointer values.
Actual firmware hooks, complete invalidation coverage, cross-thread handoff,
and UI ownership through consume/setter/refresh are NOT implemented here.
No pointer reader, UI callback, device access, installer or firmware builder.
"""
from dataclasses import dataclass

from folderfollow_reveal_model import (
    Action, Geometry, Identity, INT_MAX, RevealModel, Snapshot, ViewGeneration,
    validate_action,
)
from folderfollow_reveal_playback import PlaybackPublication
from folderfollow_reveal_publication import RowPublication


@dataclass(frozen=True, eq=False)
class ViewHandle:
    epoch: int


@dataclass(frozen=True, eq=False)
class FillHandle:
    generation: ViewGeneration
    ticket: int


@dataclass(frozen=True, eq=False)
class RevealProposal:
    action: Action
    fence: int
    playback_revision: int


@dataclass(frozen=True)
class CoordinatorDecision:
    reason: str
    proposal: RevealProposal | None = None


def _folder(value):
    if type(value) is not str:
        return False
    try:
        return (ViewGeneration(value, 0, 0).valid()
                and len(value.encode('utf-16-le')) <= 259 * 2)
    except UnicodeEncodeError:
        return False


class RevealCoordinator:
    """Serialize model events, not real stock threads.

    Call activate/replace_contents BEFORE scope/list mutation, using a handle
    captured for that owner; never relabel a late worker job with current scope.
    For a single mutation with an owned pre-copy value, pair playback_begin
    BEFORE its writer/clear with playback_finish after coherent completion.
    For a proved whole logical update, use playback_update_begin/finish and
    submit only its coherent final value; inner writes must be independently
    admitted as belonging to that update, not passed as nested BEGINs here.
    Input uncertainty disables this instance.
    `consume` merely validates a one-use model value: a real adapter still
    needs an owned UI transaction extending across the subsequent UI calls.
    """

    def __init__(self, *, epoch_limit=INT_MAX, max_wait_ticks=8):
        if type(epoch_limit) is not int or not 1 <= epoch_limit <= INT_MAX:
            raise ValueError('invalid epoch limit')
        self._limit = epoch_limit
        self._serial = 0
        self._fatal = None
        self._model = RevealModel(max_wait_ticks)
        self._publication = RowPublication(ticket_limit=epoch_limit)
        self._playback = PlaybackPublication(ticket_limit=epoch_limit)
        self._view = self._generation = self._fill = None
        self._geometry = self._issued = None
        self._interaction = None  # Unknown is never idle.
        self._manual_epoch = 0
        self._playback_fence = None

    @property
    def generation(self):
        return self._generation

    @property
    def rows(self):
        return self._publication.rows

    @property
    def error(self):
        return self._fatal or self._playback.error or self._publication.error

    @property
    def manual_active(self):
        return self._interaction != (False, False, True)

    def _disable(self, reason):
        if type(reason) is not str or not reason:
            reason = 'lost-or-uncertain-event'
        self._fatal = self._fatal or reason
        self._issued = self._view = self._generation = self._fill = None
        self._geometry = None
        self._playback_fence = None
        self._model.cancel_pending()
        self._publication.activate(None)
        self._playback.invalidate(reason)

    def _change(self):
        self._issued = None
        self._model.cancel_pending()
        if self._fatal is not None:
            return False
        if self._serial == self._limit:
            self._disable('coordinator-epoch-exhausted')
            return False
        self._serial += 1
        return True

    def _baseline(self):
        self._model.reset_baseline(self._playback.identity if self._playback.ready else None)

    def activate(self, folder):
        """New owner, even for the same path; prior handles can never revive."""
        if not self._change():
            return None
        self._publication.activate(None)
        self._view = self._generation = self._fill = self._geometry = None
        self._baseline()
        if not _folder(folder):
            return None
        self._view = ViewHandle(self._serial)
        self._generation = ViewGeneration(folder, self._serial, self._serial)
        self._publication.activate(self._generation)
        return self._view

    def replace_contents(self, view, folder=None):
        """Invalidate before rebind/refill/sort, never from a later callback."""
        if self._view is None or view is not self._view:
            return None
        folder = self._generation.folder if folder is None else folder
        if not self._change():
            return None
        self._fill = self._geometry = None
        self._baseline()
        if not _folder(folder):
            self._publication.activate(None)
            self._view = self._generation = None
            return None
        self._generation = ViewGeneration(folder, view.epoch, self._serial)
        self._publication.activate(self._generation)
        return self._generation

    def close(self, view):
        if self._view is None or view is not self._view:
            return False
        self._change()
        self._publication.activate(None)
        self._view = self._generation = self._fill = self._geometry = None
        self._baseline()
        return True

    def begin_fill(self, generation, **metadata):
        if self._fatal or self._generation is None or generation is not self._generation:
            return None
        ticket = self._publication.begin(generation, **metadata)
        if ticket is None:
            self._change()
            return None
        self._fill = FillHandle(generation, ticket)
        return self._fill

    def _current_fill(self, fill):
        return (self._fill is not None and fill is self._fill
                and fill.generation is self._generation and not self._fatal)

    def append(self, fill, **metadata):
        if not self._current_fill(fill):
            return False
        ok = self._publication.append(fill.ticket, **metadata)
        if not ok:
            self._change()
        return ok

    def terminal(self, fill, **metadata):
        if not self._current_fill(fill):
            return False
        ok = self._publication.terminal(fill.ticket, **metadata)
        if not ok:
            self._change()
        return ok

    def finish_fill(self, fill, **metadata):
        if not self._current_fill(fill):
            return None
        rows = self._publication.finish(fill.ticket, **metadata)
        if rows is None:
            self._change()
        return rows

    def playback_begin(self, identity):
        if not self._change():
            return None
        # Do not feed a transient None to RevealModel: that would erase the
        # old baseline and turn every new track into a non-revealing baseline.
        ticket = self._playback.begin(identity)
        self._playback_fence = self._serial if ticket is not None else None
        return ticket

    def playback_finish(self, ticket):
        if self._fatal:
            return False
        return self._playback_finished(self._playback.finish(ticket), succeeded=True)

    def playback_update_begin(self):
        """Begin a whole update; intermediate clears do not erase baseline.

        Actual entry/exit grouping, nested-writer ownership and a coherent
        FINAL sample remain adapter obligations, not consequences of this API.
        """
        if not self._change():
            return None
        ticket = self._playback.begin_update()
        self._playback_fence = self._serial if ticket is not None else None
        return ticket

    def playback_update_finish(self, ticket, identity, *, succeeded):
        if self._fatal:
            return False
        if type(succeeded) is not bool:
            self.uncertain('unknown-playback-update-outcome')
            return False
        return self._playback_finished(
            self._playback.finish_update(ticket, identity), succeeded=succeeded)

    def _playback_finished(self, ok, *, succeeded):
        fence, self._playback_fence = self._playback_fence, None
        if not ok:
            self._change()
        elif (self._playback.identity is None or self._view is None
              or self.manual_active or fence != self._serial or not succeeded):
            # Also consume any lifecycle/gesture change during publication,
            # even when its final scalar state returned to the original value.
            # A failed stock update is not permission to reveal its descriptor.
            self._baseline()
        return ok

    def interaction(self, *, contact, animation, settled):
        """Owned recognized state, including stationary contact and inertia.

        This method is NOT a safe implementation of G/A/K pointer sampling.
        Normal release is not enough while animation/settling remains active.
        """
        state = (contact, animation, settled)
        if any(type(value) is not bool for value in state):
            self.uncertain('unknown-input-state')
            return False
        if self._fatal:
            return False
        if state != self._interaction:
            if not self._change():
                return False
            self._manual_epoch = self._serial
            self._interaction = state
            # Consume even a publication not yet seen by the policy. Merely
            # cancelling its candidate is insufficient before first observe.
            self._baseline()
        return True

    def uncertain(self, reason='lost-or-uncertain-event'):
        """Missing invalidation/contact/writer coverage cannot mean idle."""
        self._disable(reason)

    def _snapshot(self, geometry):
        return Snapshot(self._playback.identity, self._generation,
                        self._manual_epoch, self.rows, geometry, self.manual_active)

    def observe(self, view, geometry):
        self._issued = None  # Proposals are not cached across UI observations.
        if self.error:
            return CoordinatorDecision('disabled-or-invalid-publication')
        if self._view is None or view is not self._view:
            return CoordinatorDecision('inactive-view')
        if not self._playback.ready:
            return CoordinatorDecision('await-playback-publication')
        if type(geometry) is not Geometry:
            self._baseline()
            return CoordinatorDecision('invalid-geometry')
        self._geometry = geometry
        decision = self._model.observe(self._snapshot(geometry))
        if decision.action is None:
            return CoordinatorDecision(decision.reason)
        self._issued = RevealProposal(decision.action, self._serial, self._playback.revision)
        return CoordinatorDecision(decision.reason, self._issued)

    def consume(self, proposal, view, geometry):
        """Consume on EVERY attempt, including rejection; no UI side effects.

        Requires fresh owned geometry at the final UI transaction boundary.
        Returned Action does not retain any live stock object or authorize a
        later/out-of-transaction setter call. The live boundary is still open.
        """
        issued, self._issued = self._issued, None
        if (issued is None or proposal is not issued or self.error
                or self._view is None or view is not self._view
                or not self._playback.ready or self.manual_active
                or type(geometry) is not Geometry
                or issued.fence != self._serial
                or issued.playback_revision != self._playback.revision
                or not validate_action(issued.action, self._snapshot(geometry))):
            return None
        return issued.action
