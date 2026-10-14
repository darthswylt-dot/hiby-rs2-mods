#!/usr/bin/env python3
"""Host-only, fail-closed publication of an owned playback identity.

Methods model serialized, correctly delivered mutation events. This is NOT a
thread-safe live mailbox, firmware hook, pointer reader, or proof that real
playback copies are coherent. The adapter must deliver BEGIN before stock
mutation and END after that same mutation completes, including clear writes.
The deferred API instead brackets one proved logical update, whose admitted
inner writes are not separate publications. Coherent final identity and inner
ownership remain adapter requirements, not consequences of this host model.
"""

from folderfollow_reveal_model import Identity, INT_MAX


def _integer(value, low=0, high=INT_MAX):
    return type(value) is int and low <= value <= high


def _supported(identity):
    if identity is None:
        return True
    if (type(identity) is not Identity or type(identity.path) is not str
            or not identity.valid()):
        return False
    try:
        return len(identity.path.encode('utf-16-le')) <= 259 * 2
    except UnicodeEncodeError:
        return False


class PlaybackPublication:
    """Publish only a copied value from one uniquely paired mutation.

    Every BEGIN attempt withdraws the current value and advances revision,
    including same-value writes and invalid/overlapping BEGINs. Successful
    BEGINs use that revision as a non-reused ticket. Both counters share the
    signed-word bound configured by ticket_limit; exhaustion saturates and
    permanently disables publication rather than wrapping.

    Any protocol fault is permanent for this instance. There is no reset or
    automatic recovery; constructing another object is not a live recovery
    protocol. A ready None is an explicitly completed clear, unlike not-ready
    None while a mutation is pending or after a fault. A retained value is not
    permission to act: consumers must also recheck readiness and revision.
    """

    def __init__(self, ticket_limit=INT_MAX):
        if not _integer(ticket_limit, 1):
            raise ValueError('ticket limit must be a positive signed word')
        self._limit = ticket_limit
        self._revision = 0
        self._identity = None
        self._ready = False
        self._ticket = None
        self._pending = None
        self._deferred = False
        self._error = None

    @property
    def identity(self) -> Identity | None:
        return self._identity

    @property
    def ready(self) -> bool:
        return self._ready

    @property
    def revision(self) -> int:
        return self._revision

    @property
    def error(self) -> str | None:
        return self._error

    def _fail(self, reason):
        self._identity = self._pending = self._ticket = None
        self._deferred = False
        self._ready = False
        if self._error is None:
            self._error = reason

    def begin(self, identity: Identity | None) -> int | None:
        """Revoke first, then retain an owned pre-copy value for one END.

        The input is already coherent: copying these scalar fields does not
        establish synchronization with a real writer. Unsupported inputs poison
        this instance, so a later valid write cannot silently restore it.
        """
        return self._begin(identity, deferred=False)

    def begin_update(self) -> int | None:
        """Withdraw for one whole logical update whose final value is unknown.

        Intermediate preparation clears/recopies are not completed clears or
        independent publications. Their admission under this same update must
        be established by the adapter, never inferred from value/caller-PC
        equality. No identity can be read until finish_update supplies the
        coherent, owned FINAL value. This method does not prove that ownership.
        """
        return self._begin(None, deferred=True)

    def _begin(self, identity, *, deferred):
        self._identity = None
        self._ready = False
        if self._revision == self._limit:
            self._fail('revision-exhausted')
            return None
        self._revision += 1
        if self._error is not None:
            return None
        if self._ticket is not None:
            self._fail('overlapping-playback-mutation')
            return None
        if not _supported(identity):
            self._fail('unsupported-playback-identity')
            return None
        self._pending = (None if identity is None
                         else Identity(identity.path, identity.cue))
        self._deferred = deferred
        self._ticket = self._revision
        return self._ticket

    def finish(self, ticket: int) -> bool:
        """Publish only the exact outstanding ticket, never a stale callback."""
        return self._finish(ticket, None, deferred=False)

    def finish_update(self, ticket: int, identity: Identity | None) -> bool:
        """Publish an owned final sample, not a retained BEGIN source.

        A complete outer update with an empty FINAL identity is a real clear.
        In-flight empty values never reach here. Outcome eligibility is a
        separate coordinator decision; a failure return is not reveal consent.
        """
        return self._finish(ticket, identity, deferred=True)

    def _finish(self, ticket, identity, *, deferred):
        if self._error is not None:
            self._fail(self._error)
            return False
        if (not _integer(ticket, 1) or self._ticket is None
                or ticket != self._ticket):
            self._fail('unexpected-playback-completion')
            return False
        if self._deferred != deferred:
            self._fail('playback-completion-mode-mismatch')
            return False
        if deferred:
            if not _supported(identity):
                self._fail('unsupported-final-playback-identity')
                return False
            self._pending = (None if identity is None
                             else Identity(identity.path, identity.cue))
        self._identity = self._pending
        self._ready = True
        self._pending = self._ticket = None
        self._deferred = False
        return True

    def invalidate(self, reason='lost-or-uncertain-playback') -> None:
        """Withdraw and permanently disable after missing/uncertain events."""
        if type(reason) is not str or not reason:
            reason = 'lost-or-uncertain-playback'
        self._fail(reason)
