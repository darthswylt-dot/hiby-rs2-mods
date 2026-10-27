#!/usr/bin/env python3
"""Compose a checked, separate preallocated transport queue prototype.

All cooperating access must use the same retained initialized dedicated mutex.
Native table/chunk/controller/engine/mutex/stack storage and complete lock graph
remain caller premises. This is not an explorer worker/queue installer, mutex
constructor, scheduler, destructor, native lifetime lease or UI admission gate.
"""

import reveal_deferred_envelope_stage as envelopes
import reveal_deferred_queue_mips as transport


def assemble(receipt_address, binding_address, owner_address, controller_address,
             registry_mutex_address, paint_mutex_address, code_base,
             queue_address, transport_mutex_address, fault_address, *,
             capacity=16, owner_capacity=16, ticket_limit=transport.MAX_TICKET,
             queue_capacity=64, transport_capacity=40):
    """Return bytes/labels; caller retains typed FIFO, raw mutex and fault word."""
    args = (receipt_address, binding_address, owner_address, controller_address,
            registry_mutex_address, paint_mutex_address, code_base)
    options = dict(capacity=capacity, owner_capacity=owner_capacity,
                   ticket_limit=ticket_limit, queue_capacity=queue_capacity)
    initial = envelopes.assemble(*args, **options)
    prefix_bytes = len(initial['code'])
    queue_args = (*args[:-1], code_base + prefix_bytes, queue_address,
                  transport_mutex_address, fault_address,
                  initial['envelope_labels']['pack'],
                  initial['envelope_labels']['dispatch'])
    queue_options = dict(capacity=capacity, owner_capacity=owner_capacity,
                         ticket_limit=ticket_limit,
                         transport_capacity=transport_capacity)
    provisional, labels = transport.assemble(*queue_args, **queue_options)
    prefix = envelopes.assemble(*args, **options,
                                following_code_bytes=len(provisional))
    if len(prefix['code']) != prefix_bytes or prefix['labels'] != initial['labels']:
        raise ValueError('envelope layout changed while protecting queue RX')
    protected = (code_base, prefix_bytes + len(provisional))
    if prefix['protected_code_extent'] != protected:
        raise ValueError('envelope prefix does not protect the exact composed RX')
    emitted, final_labels = transport.assemble(
        *queue_args, **queue_options, protected_code=protected)
    if len(emitted) != len(provisional) or final_labels != labels:
        raise ValueError('queue layout changed with full RX protection')
    return dict(prefix, code=prefix['code'] + emitted,
                queue_labels=labels, queue_code_bytes=len(emitted),
                envelope_prefix_code_bytes=prefix_bytes,
                queue_address=queue_address,
                transport_mutex_address=transport_mutex_address,
                fault_address=fault_address,
                transport_capacity=transport_capacity,
                labels={**prefix['labels'],
                        **{'queue_' + name: value for name, value in labels.items()}},
                protected_code_extent=protected)
