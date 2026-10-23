#!/usr/bin/env python3
"""Owned, head-retained paint-queue protocol for the host model only.

One ordinary host Lock serializes every operation on this instance, including
producers, claim/ack, purge and retirement. It does not serialize native148
and native13C, establish stock writer coverage, or replace a native lock-order
and lifecycle proof. Inputs must ALREADY be coherent, owned scalar values.
Copying them here does not make a native pointer read coherent or retain an
engine/controller. No pointer dereference, callback, UI action or firmware
integration occurs. Returned values never confer native/UI authority.
"""

from dataclasses import dataclass
from threading import Lock

from folderfollow_reveal_model import INT_MAX


U32_MAX = (1 << 32) - 1


def _word(value, label):
    if type(value) is not int or not 0 <= value <= U32_MAX:
        raise ValueError(f'{label} must be an unsigned 32-bit integer')
    return value


def _name(value, label='name'):
    if type(value) is not str or not value or '\0' in value:
        raise ValueError(f'{label} must be a nonempty owned string')
    try:
        size = len(value.encode('utf-8'))
    except UnicodeEncodeError as error:
        raise ValueError(f'{label} contains an unpaired surrogate') from error
    if size > 255:
        raise ValueError(f'{label} exceeds 255 UTF-8 bytes')
    return value


def _rectangle(value):
    # Exact builtins only: never invoke caller iteration/equality hooks inside
    # the queue lock. Acquisition coherence remains the caller's obligation.
    if type(value) not in (list, tuple) or len(value) != 4:
        raise ValueError('rectangle must contain four owned unsigned words')
    return tuple(_word(word, 'rectangle word') for word in value)


@dataclass(frozen=True, eq=False)
class OwnerHandle:
    ticket: int
    name: str
    engine_word: int


@dataclass(frozen=True)
class PaintPayload:
    controller_word: int
    engine_word: int
    name: str
    rectangle: tuple[int, int, int, int]
    metadata: int


@dataclass(frozen=True, eq=False)
class PaintClaim:
    entry_id: int
    owner: OwnerHandle
    payload: PaintPayload


@dataclass(frozen=True)
class Completion:
    entry_id: int
    outcome: str


@dataclass(frozen=True)
class Cancellation:
    queued_ids: tuple[int, ...] = ()
    claimed_id: int | None = None
    retired_owner_ids: tuple[int, ...] = ()


@dataclass(frozen=True)
class QueueSnapshot:
    pending_ids: tuple[int, ...]
    active_id: int | None
    active_cancelled: bool
    owner_count: int
    serial: int
    error: str | None
    closed: bool
    native_record_lease_proven: bool = False
    native_payload_coherence_proven: bool = False
    native_object_lifetime_proven: bool = False
    current_owner_proven: bool = False
    request_freshness_proven: bool = False
    contents_current: bool = False
    coherent_capture: bool = False
    autoscroll_authorized: bool = False


@dataclass
class _Owner:
    ticket: int
    handle: OwnerHandle
    name: str
    engine_word: int
    retired: bool = False


@dataclass
class _Entry:
    ticket: int
    owner_ticket: int
    payload: PaintPayload


@dataclass
class _Active:
    entry: _Entry
    claim: PaintClaim
    cancelled: bool = False


class PaintQueue:
    """Bounded host FIFO with one exact, head-retained active claim.

    Claim atomically chooses the head and makes an immutable consumer copy,
    but retains that exact entry until its acknowledgement. Another consumer
    receives None while a claim is active, including after cancellation.
    Purge/retire remove only unclaimed matching entries and cancel the active
    one. Its eventual ack removes only that entry, never a different head.

    Owner and entry tickets share one persistent non-wrapping counter. Both
    registered owner states and pending entries are independently bounded by
    capacity. Retired owners remain registered until explicit release, and a
    cancelled active entry occupies capacity until its acknowledgement.
    Exact issued objects, not numeric ticket equality, admit handles.

    The caller reports complete only after finishing its own uses. A lost ack
    therefore blocks the retained head and its owner indefinitely: no timeout
    or force-takeover invents completion. Fresh owners may reuse identical raw
    words while an old generation is retired; this is NOT a native alias/lease
    solution. Even a successful release_owner only drops host bookkeeping. It
    never invokes a callback, frees native memory, or authorizes such a free.
    """

    def __init__(self, controller_word=0, capacity=64, ticket_limit=INT_MAX):
        controller_word = _word(controller_word, 'controller word')
        for value, label in ((capacity, 'capacity'), (ticket_limit, 'ticket limit')):
            if type(value) is not int or not 1 <= value <= INT_MAX:
                raise ValueError(f'{label} must be a positive signed word')
        self._controller = controller_word
        self._capacity, self._limit = capacity, ticket_limit
        self._lock = Lock()
        self._owners = {}
        self._entries = []
        self._active = None
        self._serial = 0
        self._error = None
        self._closed = False

    def _owner(self, handle):
        # Never read caller-controlled fields or invoke its hash/equality.
        if type(handle) is OwnerHandle:
            for owner in self._owners.values():
                if owner.handle is handle:
                    return owner
        return None

    def _cancel(self, selected):
        retired = []
        for ticket in selected:
            owner = self._owners[ticket]
            if not owner.retired:
                owner.retired = True
                retired.append(ticket)
        active = self._active
        claimed = None
        if active is not None and active.entry.owner_ticket in selected:
            active.cancelled = True
            claimed = active.entry.ticket
        kept, removed = [], []
        for entry in self._entries:
            if (entry.owner_ticket in selected
                    and (active is None or entry is not active.entry)):
                removed.append(entry.ticket)
            else:
                kept.append(entry)
        self._entries = kept
        return Cancellation(tuple(removed), claimed, tuple(sorted(retired)))

    def _terminal(self, reason):
        self._error = self._error or reason
        return self._cancel(set(self._owners))

    def _ticket(self):
        if self._serial == self._limit:
            self._terminal('ticket-exhausted')
            return None
        self._serial += 1
        return self._serial

    def open_owner(self, name, engine_word):
        """Issue an abstract host owner generation, NOT a native lifetime lease."""
        name, engine_word = _name(name), _word(engine_word, 'engine word')
        with self._lock:
            if self._closed or self._error or len(self._owners) == self._capacity:
                return None
            ticket = self._ticket()
            if ticket is None:
                return None
            handle = OwnerHandle(ticket, name, engine_word)
            self._owners[ticket] = _Owner(ticket, handle, name, engine_word)
            return handle

    def enqueue(self, owner, rectangle, *, metadata=0):
        rectangle, metadata = _rectangle(rectangle), _word(metadata, 'metadata')
        with self._lock:
            state = self._owner(owner)
            if (self._closed or self._error or state is None or state.retired
                    or len(self._entries) == self._capacity):
                return None
            ticket = self._ticket()
            if ticket is None:
                return None
            payload = PaintPayload(self._controller, state.engine_word,
                                   state.name, rectangle, metadata)
            self._entries.append(_Entry(ticket, state.ticket, payload))
            return ticket

    def claim(self):
        """Atomically retain the head for one consumer; never expose native bytes."""
        with self._lock:
            if self._closed or self._error or self._active or not self._entries:
                return None
            entry = self._entries[0]
            source = entry.payload
            payload = PaintPayload(source.controller_word, source.engine_word,
                                   source.name, source.rectangle, source.metadata)
            claim = PaintClaim(entry.ticket, self._owners[entry.owner_ticket].handle,
                               payload)
            self._active = _Active(entry, claim)
            return claim

    def complete(self, claim, *, succeeded):
        """Ack one exact claim, even after cancellation; this performs no UI work."""
        if type(succeeded) is not bool:
            raise ValueError('succeeded must be an explicit boolean')
        with self._lock:
            active = self._active
            if active is None or claim is not active.claim:
                return None
            # Remove by exact retained-entry identity, not by current index0,
            # matching fields, externally supplied ticket or pointer address.
            for index, entry in enumerate(self._entries):
                if entry is active.entry:
                    del self._entries[index]
                    break
            else:
                raise AssertionError('internal active entry was lost')
            self._active = None
            outcome = ('cancelled' if active.cancelled else
                       'completed' if succeeded else 'failed')
            return Completion(active.entry.ticket, outcome)

    def purge(self, name):
        """Retire ALL matching generations and cancel queued/in-flight work."""
        name = _name(name)
        with self._lock:
            selected = {ticket for ticket, owner in self._owners.items()
                        if owner.name == name}
            return self._cancel(selected)

    def retire(self, owner):
        with self._lock:
            state = self._owner(owner)
            return self._cancel({state.ticket}) if state is not None else Cancellation()

    def release_owner(self, owner):
        """Forget retired host bookkeeping once unreferenced, not release native memory."""
        with self._lock:
            state = self._owner(owner)
            if (state is None or not state.retired
                    or any(entry.owner_ticket == state.ticket for entry in self._entries)
                    or (self._active is not None
                        and self._active.entry.owner_ticket == state.ticket)):
                return False
            del self._owners[state.ticket]
            return True

    def close(self):
        with self._lock:
            self._closed = True
            return self._cancel(set(self._owners))

    def uncertain(self, reason):
        reason = _name(reason, 'uncertainty reason')
        with self._lock:
            return self._terminal(reason)

    def snapshot(self):
        with self._lock:
            active = self._active
            return QueueSnapshot(
                tuple(entry.ticket for entry in self._entries),
                active.entry.ticket if active is not None else None,
                active.cancelled if active is not None else False,
                len(self._owners), self._serial, self._error, self._closed)
