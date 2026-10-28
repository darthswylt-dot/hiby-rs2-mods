#!/usr/bin/env python3
"""Compose bounded cooperative operation accounting, never native retention.

The new ledger/FIFO72/mutex are distinct from the preceding FIFO68 transport.
Only this explicit API participates. No stock worker, cleanup/free, constructor
caller, UI action or firmware image is changed. A positive quiescent result is
local accounting, not permission to free the externally retained native bundle.
"""

import reveal_constructor_capture_stage as constructors
import reveal_deferred_queue_mips as transport
import reveal_retained_operations_mips as operations


def assemble(receipt_address, binding_address, owner_address, controller_address,
             registry_mutex_address, paint_mutex_address, code_base,
             queue_address, transport_mutex_address, fault_address,
             ledger_address, retained_queue_address, retained_mutex_address, *,
             capacity=16, owner_capacity=16, ticket_limit=transport.MAX_TICKET,
             queue_capacity=64, transport_capacity=40, operation_capacity=16,
             retained_capacity=40, cleanup_intent_address=None,
             following_code_bytes=0):
    """Return emitted bytes/fixture redirects, with no state allocation or I/O.

    All generated outer RX guards cover this exact composition. The constructor
    additionally excludes the new ledger/header/mutex. Inherited internal
    entries still require their documented heap/data/stack nonaliasing premises.
    The optional retained intent word enables a historical captured-identity
    cleanup intent, never native detach/destructor or free permission. None
    preserves previous emitted bytes and labels; its new word must remain
    retained and initially0.

    following_code_bytes advertises an exactly appended RX tail. Zero preserves
    preceding bytes/labels; the composer must append that entire advertised tail.
    """
    if (type(following_code_bytes) is not int or following_code_bytes < 0
            or following_code_bytes % 4):
        raise ValueError('following code bytes must be a nonnegative aligned integer')
    args = (receipt_address, binding_address, owner_address, controller_address,
            registry_mutex_address, paint_mutex_address, code_base,
            queue_address, transport_mutex_address, fault_address)
    extra_data = ((ledger_address, operations.memory_bytes(operation_capacity)),
                  (retained_queue_address, transport.QUEUE_BYTES),
                  (retained_mutex_address, transport.MUTEX_BYTES))
    if cleanup_intent_address is not None:
        extra_data += ((cleanup_intent_address, 4),)
    options = dict(capacity=capacity, owner_capacity=owner_capacity,
                   ticket_limit=ticket_limit, queue_capacity=queue_capacity,
                   transport_capacity=transport_capacity,
                   extra_protected_data=extra_data)
    initial = constructors.assemble(*args, **options)
    prefix_bytes = len(initial['code'])
    entries = initial['owner_labels']
    core_args = (*args[:6], code_base + prefix_bytes, *args[7:],
                 ledger_address, retained_queue_address, retained_mutex_address,
                 initial['envelope_labels']['pack'],
                 initial['envelope_labels']['dispatch'], entries['complete'],
                 entries['retire'], entries['drained'])
    core_options = dict(capacity=capacity, owner_capacity=owner_capacity,
                        ticket_limit=ticket_limit,
                        operation_capacity=operation_capacity,
                        retained_capacity=retained_capacity,
                        cleanup_intent_address=cleanup_intent_address)
    provisional, labels = operations.assemble(*core_args, **core_options)
    prefix = constructors.assemble(*args, **options,
                                   following_code_bytes=len(provisional) + following_code_bytes)
    if len(prefix['code']) != prefix_bytes or prefix['labels'] != initial['labels']:
        raise ValueError('constructor layout changed while protecting operations RX')
    protected = (code_base, prefix_bytes + len(provisional) + following_code_bytes)
    if prefix['protected_code_extent'] != protected:
        raise ValueError('constructor prefix does not protect exact operations RX')
    emitted, final_labels = operations.assemble(
        *core_args, **core_options, protected_code=protected)
    if len(emitted) != len(provisional) or final_labels != labels:
        raise ValueError('operations layout changed with full RX protection')
    return dict(prefix, code=prefix['code'] + emitted,
                retained_labels=labels, retained_code_bytes=len(emitted),
                constructor_prefix_code_bytes=prefix_bytes,
                ledger_address=ledger_address,
                retained_queue_address=retained_queue_address,
                retained_mutex_address=retained_mutex_address,
                operation_capacity=operation_capacity,
                retained_capacity=retained_capacity,
                cleanup_intent_address=cleanup_intent_address,
                labels={**prefix['labels'],
                        **{'retained_' + name: value for name, value in labels.items()}},
                protected_code_extent=protected)
