#!/usr/bin/env python3
"""Compose a read-only historical-binding/current-ring comparison, not unlink.

Matching current scalar fields cannot establish continuous native incarnation:
an allocator can reuse both node and engine addresses. No native deletion,
name lookup, lifecycle installation, safe-free permission or image I/O occurs.
"""

import reveal_retained_operations_stage as retained
import reveal_registry_identity_mips as identity


def assemble(receipt_address, binding_address, owner_address, controller_address,
             registry_mutex_address, paint_mutex_address, code_base,
             queue_address, transport_mutex_address, fault_address,
             ledger_address, retained_queue_address, retained_mutex_address,
             cleanup_intent_address, *, capacity=16, owner_capacity=16,
             ticket_limit=identity.MAX_TICKET, queue_capacity=64,
             transport_capacity=40, operation_capacity=16, retained_capacity=40,
             max_nodes=64):
    """Return guarded emitted bytes and local fixture hooks, never install them.

    A genuinely exported, coherent, exclusive CINT is a caller premise, not
    authenticated by tags. Retained mapped native list/storage and complete
    common R synchronization remain external duties. This adds no native writes.
    """
    args = (receipt_address, binding_address, owner_address, controller_address,
            registry_mutex_address, paint_mutex_address, code_base,
            queue_address, transport_mutex_address, fault_address,
            ledger_address, retained_queue_address, retained_mutex_address)
    options = dict(capacity=capacity, owner_capacity=owner_capacity,
                   ticket_limit=ticket_limit, queue_capacity=queue_capacity,
                   transport_capacity=transport_capacity,
                   operation_capacity=operation_capacity,
                   retained_capacity=retained_capacity,
                   cleanup_intent_address=cleanup_intent_address)
    initial = retained.assemble(*args, **options)
    prefix_bytes = len(initial['code'])
    core_args = (*args[:6], code_base + prefix_bytes, *args[7:],
                 cleanup_intent_address)
    core_options = dict(capacity=capacity, owner_capacity=owner_capacity,
                        ticket_limit=ticket_limit,
                        operation_capacity=operation_capacity,
                        max_nodes=max_nodes)
    provisional, labels = identity.assemble(*core_args, **core_options)
    prefix = retained.assemble(*args, **options,
                               following_code_bytes=len(provisional))
    if len(prefix['code']) != prefix_bytes or prefix['labels'] != initial['labels']:
        raise ValueError('retained layout changed while protecting identity audit RX')
    protected = (code_base, prefix_bytes + len(provisional))
    if prefix['protected_code_extent'] != protected:
        raise ValueError('retained prefix does not protect exact identity audit RX')
    emitted, final_labels = identity.assemble(
        *core_args, **core_options, protected_code=protected)
    if len(emitted) != len(provisional) or final_labels != labels:
        raise ValueError('identity audit layout changed with full RX protection')
    return dict(prefix, code=prefix['code'] + emitted,
                identity_labels=labels, identity_code_bytes=len(emitted),
                retained_prefix_code_bytes=prefix_bytes, max_nodes=max_nodes,
                labels={**prefix['labels'],
                        **{'identity_' + name: value for name, value in labels.items()}},
                protected_code_extent=protected)
