#!/usr/bin/env python3
"""Compose explicit owned deferred envelopes, never a native worker installer.

Creation captures require observed raw registry release. Envelope pack/dispatch
carry the exact captured pair and payload as values, not a pointer/name lookup.
Native FIFO arbitration/pop/guard/lifetime remains a cooperative caller duty;
this composer neither adds locks nor wires the original explorer action queue.
"""

import reveal_creation_capture_stage as creation
import reveal_deferred_envelope_mips as envelope


def assemble(receipt_address, binding_address, owner_address, controller_address,
             registry_mutex_address, paint_mutex_address, code_base, *,
             capacity=16, owner_capacity=16, ticket_limit=envelope.MAX_TICKET,
             queue_capacity=64, following_code_bytes=0):
    """Return capture/pack/consume code protecting an exactly appended RX tail.

    Zero preserves all preceding bytes/labels. A caller advertising a nonzero
    tail must append that exact extent and independently validate its entries.
    This does not extend every inherited internal entry's data/stack premises.
    """
    if (type(following_code_bytes) is not int or following_code_bytes < 0
            or following_code_bytes % 4):
        raise ValueError('following code bytes must be a nonnegative aligned integer')
    args = (receipt_address, binding_address, owner_address, controller_address,
            registry_mutex_address, paint_mutex_address, code_base)
    options = dict(capacity=capacity, owner_capacity=owner_capacity,
                   ticket_limit=ticket_limit, queue_capacity=queue_capacity,
                   checked_registry_release=True)
    initial = creation.assemble(*args, **options)
    prefix_bytes = len(initial['code'])
    envelope_args = (*args[:-1], code_base + prefix_bytes,
                     initial['adapter_labels']['publish'])
    envelope_options = dict(capacity=capacity, owner_capacity=owner_capacity,
                            ticket_limit=ticket_limit)
    provisional, labels = envelope.assemble(*envelope_args, **envelope_options)
    # The preceding source-taking entries must also reject aliases into this
    # new tail. The prefix's zero-default extension changes only RX literals,
    # not its layout, imports, default bytes or original native call routes.
    prefix = creation.assemble(*args, **options,
                               following_code_bytes=len(provisional) + following_code_bytes)
    if len(prefix['code']) != prefix_bytes or prefix['labels'] != initial['labels']:
        raise ValueError('capture layout changed while protecting envelope RX')
    protected = (code_base, prefix_bytes + len(provisional) + following_code_bytes)
    if prefix['protected_code_extent'] != protected:
        raise ValueError('capture prefix does not protect the exact composed RX')
    emitted, final_labels = envelope.assemble(
        *envelope_args, **envelope_options, protected_code=protected)
    if len(emitted) != len(provisional) or final_labels != labels:
        raise ValueError('envelope layout changed with full RX protection')
    return dict(prefix, code=prefix['code'] + emitted,
                envelope_labels=labels, envelope_code_bytes=len(emitted),
                capture_prefix_code_bytes=prefix_bytes,
                labels={**prefix['labels'],
                        **{'envelope_' + name: value for name, value in labels.items()}},
                protected_code_extent=protected)
