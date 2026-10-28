#!/usr/bin/env python3
"""Compose historical FIFO-to-history comparison, not native UI admission.

The exact queued birth token selects its recorded lifecycle row. Both the
queue payload and retirement-observation metadata leave as an owned snapshot;
neither a matching history nor successful extraction establishes native life.
No firmware image, producer/worker route or player state is changed.
"""

import reveal_birth_queue_stage as queue_stage
import reveal_birth_consumer_mips as consumer
import reveal_paint_retirement_mips as owners


def assemble(receipt_address, binding_address, owner_address, controller_address,
             registry_mutex_address, paint_mutex_address, code_base,
             lifecycle_address, queue_address, transport_mutex_address,
             fault_address, *, capacity=16, lifecycle_capacity=16,
             owner_capacity=16, ticket_limit=owners.MAX_TICKET,
             queue_capacity=64, transport_capacity=40):
    """Return local code, explicit take entry and unchanged coherent fixture hooks.

    The consumer drains into private storage before acquiring R, never nesting
    T and R. An exact historical comparison is diagnostic, not a retained native
    handle or permission to paint, unlink, free or continue after a raw error.
    All ownership, initialization, retention and full-stack premises of the
    preceding queue still apply. No additional shared allocation is introduced.
    """
    args = (receipt_address, binding_address, owner_address, controller_address,
            registry_mutex_address, paint_mutex_address, code_base,
            lifecycle_address, queue_address, transport_mutex_address, fault_address)
    options = dict(capacity=capacity, lifecycle_capacity=lifecycle_capacity,
                   owner_capacity=owner_capacity, ticket_limit=ticket_limit,
                   queue_capacity=queue_capacity, transport_capacity=transport_capacity)
    initial = queue_stage.assemble(*args, **options)
    if (initial['registry_release_checked'] is not True
            or initial['birth_queue_historical_only'] is not True):
        raise ValueError('birth consumer requires checked historical FIFO transport')
    prefix_bytes = len(initial['code'])
    core_args = (*args[:6], lifecycle_address, code_base + prefix_bytes,
                 queue_address, transport_mutex_address, fault_address,
                 initial['birth_queue_labels']['pop'],
                 initial['capture_labels']['native_return'])
    core_options = dict(capacity=capacity, lifecycle_capacity=lifecycle_capacity,
                        owner_capacity=owner_capacity)
    provisional, labels = consumer.assemble(*core_args, **core_options)
    protected = (code_base, prefix_bytes + len(provisional))
    prefix = queue_stage.assemble(
        *args, **options, following_code_bytes=len(provisional))
    if (len(prefix['code']) != prefix_bytes or prefix['labels'] != initial['labels']
            or prefix['protected_code_extent'] != protected):
        raise ValueError('birth queue layout changed while protecting consumer RX')
    emitted, final_labels = consumer.assemble(
        *core_args, **core_options, protected_code=protected)
    if len(emitted) != len(provisional) or final_labels != labels:
        raise ValueError('birth consumer layout changed with exact complete RX')
    return dict(
        prefix, code=prefix['code'] + emitted,
        birth_consumer_labels=labels, birth_consumer_code_bytes=len(emitted),
        birth_consumer_prefix_code_bytes=prefix_bytes,
        birth_consumer_output_bytes=consumer.OUTPUT_BYTES,
        birth_consumer_historical_only=True, protected_code_extent=protected,
        labels={**prefix['labels'],
                **{'birth_consumer_' + name: address for name, address in labels.items()}})
