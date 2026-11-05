#!/usr/bin/env python3
"""Append a buffer-detaching worker tail to the protected dialog stage."""

import reveal_dialog_retention_gate_stage as retention_stage
import reveal_worker_terminal_tail_mips as tail
import reveal_registry_receipt_mips as receipt
import reveal_registry_owner_mips as bindings
import reveal_registry_lifecycle_mips as lifecycle
import reveal_paint_retirement_mips as owners
import reveal_birth_queue_mips as queue


def assemble(receipt_address, binding_address, owner_address, controller_address,
             registry_mutex_address, paint_mutex_address, code_base,
             lifecycle_address, queue_address, transport_mutex_address,
             fault_address, *, guard_address, retry_limit=8, capacity=16,
             lifecycle_capacity=16, owner_capacity=16, ticket_limit=owners.MAX_TICKET,
             queue_capacity=64, transport_capacity=40, following_code_bytes=0):
    """Return33 native and seven generated coherent pairs, without activation.

    The new tail does not claim Q or turn a C release into a join. Its buffer
    capture/clear must be permitted by the genuine H and independent buffer
    lifetimes and by external field observers. The inherited process-lifetime
    Q setup and every native ownership/lifetime limitation still apply.
    """
    if (type(following_code_bytes) is not int or following_code_bytes < 0
            or following_code_bytes % 4):
        raise ValueError('following code bytes must be a nonnegative aligned integer')
    if type(retry_limit) is not int or not 1 <= retry_limit <= 64:
        raise ValueError('retry limit must be an integer in1..64')
    args = (receipt_address, binding_address, owner_address, controller_address,
            registry_mutex_address, paint_mutex_address, code_base,
            lifecycle_address, queue_address, transport_mutex_address, fault_address)
    options = dict(guard_address=guard_address, retry_limit=retry_limit,
                   capacity=capacity, lifecycle_capacity=lifecycle_capacity,
                   owner_capacity=owner_capacity, ticket_limit=ticket_limit,
                   queue_capacity=queue_capacity, transport_capacity=transport_capacity)
    initial = retention_stage.assemble(*args, **options)
    if (initial['unconfirmed_dialog_unlock_suppressed'] is not True
            or initial['known_dialog_outer_frees_guarded'] is not True):
        raise ValueError('worker tail requires the protected retention stage')
    prefix_bytes = len(initial['code'])
    extra = ((receipt_address, receipt.memory_bytes(capacity)),
             (binding_address, bindings.memory_bytes(capacity)),
             (owner_address, owners.memory_bytes(owner_capacity)),
             (paint_mutex_address, receipt.MUTEX_BYTES),
             (lifecycle_address, lifecycle.memory_bytes(lifecycle_capacity)),
             (queue_address, queue.QUEUE_BYTES),
             (transport_mutex_address, queue.MUTEX_BYTES), (fault_address, 4))
    core_args = (controller_address, registry_mutex_address,
                 code_base + prefix_bytes, guard_address)
    provisional, labels = tail.assemble(*core_args, extra_protected_data=extra)
    protected = (code_base, prefix_bytes + len(provisional) + following_code_bytes)
    prefix = retention_stage.assemble(
        *args, **options, following_code_bytes=len(provisional) + following_code_bytes)
    if (len(prefix['code']) != prefix_bytes or prefix['labels'] != initial['labels']
            or prefix['protected_code_extent'] != protected):
        raise ValueError('retention layout changed while protecting worker tail RX')
    emitted, final_labels = tail.assemble(
        *core_args, extra_protected_data=extra, protected_code=protected)
    if len(emitted) != len(provisional) or final_labels != labels:
        raise ValueError('worker tail layout changed with complete RX')
    hooks = tail.hook_words(final_labels)
    if set(hooks) & set(prefix['coherent_hooks']):
        raise ValueError('worker tail conflicts with preceding hooks')
    return dict(
        prefix, code=prefix['code'] + emitted,
        worker_terminal_tail_labels=final_labels,
        worker_terminal_tail_code_bytes=len(emitted),
        worker_terminal_tail_prefix_code_bytes=prefix_bytes,
        worker_terminal_tail_hooks=hooks,
        worker_terminal_tail_source_words={pc: words for pc, words in tail.HOOKS.values()},
        worker_post_terminal_release_H_access_removed=True,
        worker_tail_field_detached_before_release=True,
        worker_termination_proven=False, worker_terminal_release_proven=False,
        worker_buffer_free_authority_proven=False,
        worker_terminal_release_status_masked=True,
        native_coherent_hooks={**prefix['native_coherent_hooks'], **hooks},
        generated_coherent_hooks=dict(prefix['generated_coherent_hooks']),
        coherent_hooks={**prefix['coherent_hooks'], **hooks},
        protected_code_extent=protected,
        labels={**prefix['labels'], **{'worker_terminal_tail_' + name: address
                                      for name, address in final_labels.items()}})
