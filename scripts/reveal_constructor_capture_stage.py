#!/usr/bin/env python3
"""Compose an explicit diagnostic capture of native43AD00 construction.

This preserves native continuation, including its unchecked post-registration
lookup/UI/error paths. It does not retain native allocations, repair failures,
install a worker/constructor hook or provide error isolation or UI authority.
"""

import reveal_deferred_queue_stage as queues
import reveal_deferred_queue_mips as transport
import reveal_constructor_capture_mips as constructor


def assemble(receipt_address, binding_address, owner_address, controller_address,
             registry_mutex_address, paint_mutex_address, code_base,
             queue_address, transport_mutex_address, fault_address, *,
             capacity=16, owner_capacity=16, ticket_limit=transport.MAX_TICKET,
             queue_capacity=64, transport_capacity=40, following_code_bytes=0,
             extra_protected_data=()):
    """Return bytes/fixture hooks, protecting an exactly appended optional tail.

    Zero/empty defaults preserve all preceding bytes and labels. The composing
    caller must append the exact advertised tail. Additional data exclusions
    extend the constructor's own outer guards, not every inherited internal
    entry's mapping, nonaliasing or nested-stack premises.
    """
    if (type(following_code_bytes) is not int or following_code_bytes < 0
            or following_code_bytes % 4):
        raise ValueError('following code bytes must be a nonnegative aligned integer')
    if type(extra_protected_data) is not tuple:
        raise ValueError('extra protected data must be a tuple of aligned extents')
    args = (receipt_address, binding_address, owner_address, controller_address,
            registry_mutex_address, paint_mutex_address, code_base,
            queue_address, transport_mutex_address, fault_address)
    options = dict(capacity=capacity, owner_capacity=owner_capacity,
                   ticket_limit=ticket_limit, queue_capacity=queue_capacity,
                   transport_capacity=transport_capacity)
    initial = queues.assemble(*args, **options)
    prefix_bytes = len(initial['code'])
    constructor_args = (*args[:6], code_base + prefix_bytes,
                        initial['capture_labels']['register'])
    constructor_options = dict(
        capacity=capacity, owner_capacity=owner_capacity, ticket_limit=ticket_limit,
        protected_data=((queue_address, transport.QUEUE_BYTES),
                        (transport_mutex_address, transport.MUTEX_BYTES),
                        (fault_address, 4)) + extra_protected_data)
    provisional, labels = constructor.assemble(*constructor_args, **constructor_options)
    prefix = queues.assemble(*args, **options,
                             following_code_bytes=len(provisional) + following_code_bytes)
    if len(prefix['code']) != prefix_bytes or prefix['labels'] != initial['labels']:
        raise ValueError('queue layout changed while protecting constructor RX')
    protected = (code_base, prefix_bytes + len(provisional) + following_code_bytes)
    if prefix['protected_code_extent'] != protected:
        raise ValueError('queue prefix does not protect exact composed constructor RX')
    emitted, final_labels = constructor.assemble(
        *constructor_args, **constructor_options, protected_code=protected)
    if len(emitted) != len(provisional) or final_labels != labels:
        raise ValueError('constructor layout changed with full RX protection')
    return dict(prefix, code=prefix['code'] + emitted,
                constructor_labels=labels,
                constructor_hooks=constructor.hook_words(labels),
                constructor_code_bytes=len(emitted),
                queue_prefix_code_bytes=prefix_bytes,
                labels={**prefix['labels'],
                        **{'constructor_' + name: value for name, value in labels.items()}},
                protected_code_extent=protected)
