#!/usr/bin/env python3
"""Compose separate historical birth FIFO84, not stock worker/UI integration.

BCAP token/event plus an owned 36-byte payload travel as BQ84 through a dedicated
preallocated native FIFO and checked ordinary T. Pop exports owned diagnostics;
it does not publish paint, query native liveness or acknowledge completion.
No existing queue format, firmware image or player state is changed.
"""

import reveal_birth_capture_stage as capture_stage
import reveal_birth_queue_mips as queue


def assemble(receipt_address, binding_address, owner_address, controller_address,
             registry_mutex_address, paint_mutex_address, code_base,
             lifecycle_address, queue_address, transport_mutex_address,
             fault_address, *, capacity=16, lifecycle_capacity=16,
             owner_capacity=16, ticket_limit=capture_stage.owners.MAX_TICKET,
             queue_capacity=64, transport_capacity=40, following_code_bytes=0):
    """Return guarded local bytes, entry labels and the preceding coherent hooks.

    Q/T/fault are independent retained allocations, not any preceding FIFO68,
    operation72 or native worker queue. Correct initialization, table/chunk/heap
    retention and nonaliasing, all cooperative users, sufficient native stacks
    and coordinated whole-instance isolation after raw errors remain premises.
    Optional following RX is protected but not appended. Zero preserves the
    preceding default bytes and labels.
    """
    if (type(following_code_bytes) is not int or following_code_bytes < 0
            or following_code_bytes % 4):
        raise ValueError('following code bytes must be a nonnegative aligned integer')
    args = (receipt_address, binding_address, owner_address, controller_address,
            registry_mutex_address, paint_mutex_address, code_base, lifecycle_address)
    options = dict(capacity=capacity, lifecycle_capacity=lifecycle_capacity,
                   owner_capacity=owner_capacity, ticket_limit=ticket_limit,
                   queue_capacity=queue_capacity,
                   extra_protected_data=((queue_address, queue.QUEUE_BYTES),
                                         (transport_mutex_address, queue.MUTEX_BYTES),
                                         (fault_address, 4)))
    initial = capture_stage.assemble(*args, **options)
    if (initial['registry_release_checked'] is not True
            or initial['birth_capture_historical_only'] is not True):
        raise ValueError('birth queue requires actual checked historical birth capture')
    prefix_bytes = len(initial['code'])
    core_args = (*args[:6], lifecycle_address, code_base + prefix_bytes,
                 queue_address, transport_mutex_address, fault_address,
                 initial['capture_labels']['native_return'])
    core_options = dict(capacity=capacity, lifecycle_capacity=lifecycle_capacity,
                        owner_capacity=owner_capacity,
                        transport_capacity=transport_capacity)
    provisional, labels = queue.assemble(*core_args, **core_options)
    protected = (code_base, prefix_bytes + len(provisional) + following_code_bytes)
    prefix = capture_stage.assemble(
        *args, **options,
        following_code_bytes=len(provisional) + following_code_bytes)
    if (len(prefix['code']) != prefix_bytes or prefix['labels'] != initial['labels']
            or prefix['protected_code_extent'] != protected):
        raise ValueError('birth capture layout changed while protecting queue RX')
    emitted, final_labels = queue.assemble(
        *core_args, **core_options, protected_code=protected)
    if len(emitted) != len(provisional) or final_labels != labels:
        raise ValueError('birth queue layout changed with exact complete RX')
    return dict(
        prefix, code=prefix['code'] + emitted,
        birth_queue_labels=labels, birth_queue_code_bytes=len(emitted),
        birth_queue_prefix_code_bytes=prefix_bytes,
        birth_queue_element_bytes=queue.ENVELOPE_BYTES,
        birth_queue_historical_only=True, protected_code_extent=protected,
        labels={**prefix['labels'],
                **{'birth_queue_' + name: address for name, address in labels.items()}})
