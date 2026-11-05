#!/usr/bin/env python3
"""Add admission protection for only the checked47D720 factory."""

import reveal_worker_terminal_tail_stage as parent_stage
import reveal_factory_admission_gate_mips as gates
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
    """Return36 native plus seven generated coherent pairs, without setup.

    Refusal safety was checked only for the two encoded47D720 direct callers.
    Other factories/aliases remain unguarded. The native body and startup wait
    have no new time bound, and an admitted stuck body retains Q=BUSY.
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
    initial = parent_stage.assemble(*args, **options)
    if (initial['unconfirmed_dialog_unlock_suppressed'] is not True
            or initial['worker_post_terminal_release_H_access_removed'] is not True):
        raise ValueError('factory admission requires the protected worker-tail stage')
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
    provisional, labels = gates.assemble(*core_args, retry_limit=retry_limit,
                                         extra_protected_data=extra)
    protected = (code_base, prefix_bytes + len(provisional) + following_code_bytes)
    prefix = parent_stage.assemble(
        *args, **options, following_code_bytes=len(provisional) + following_code_bytes)
    if (len(prefix['code']) != prefix_bytes or prefix['labels'] != initial['labels']
            or prefix['protected_code_extent'] != protected):
        raise ValueError('worker-tail layout changed while protecting admission RX')
    emitted, final_labels = gates.assemble(
        *core_args, retry_limit=retry_limit, protected_code=protected,
        extra_protected_data=extra)
    if len(emitted) != len(provisional) or final_labels != labels:
        raise ValueError('factory admission layout changed with complete RX')
    hooks = gates.hook_words(final_labels)
    if set(hooks) & set(prefix['coherent_hooks']):
        raise ValueError('factory admission conflicts with preceding hooks')
    return dict(
        prefix, code=prefix['code'] + emitted,
        factory_admission_gate_labels=final_labels,
        factory_admission_gate_code_bytes=len(emitted),
        factory_admission_gate_prefix_code_bytes=prefix_bytes,
        factory_admission_gate_hooks=hooks,
        factory_admission_gate_source_words={pc: pair for pc, pair in gates.HOOKS.values()},
        guarded_factory_address=gates.HOOKS['enter'][0],
        factory_refusal_direct_callers_checked=gates.CHECKED_CALLERS,
        known_factory_admission_guarded=True, all_dialog_factories_guarded=False,
        factory_body_runtime_bounded=False,
        factory_refusal_universal_caller_safety_proven=False,
        native_factory_cleanup_rolled_back=False,
        native_coherent_hooks={**prefix['native_coherent_hooks'], **hooks},
        generated_coherent_hooks=dict(prefix['generated_coherent_hooks']),
        coherent_hooks={**prefix['coherent_hooks'], **hooks},
        protected_code_extent=protected,
        labels={**prefix['labels'], **{'factory_admission_gate_' + name: address
                                      for name, address in final_labels.items()}})
