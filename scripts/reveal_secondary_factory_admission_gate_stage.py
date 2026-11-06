#!/usr/bin/env python3
"""Protect a second checked factory using the same process-lifetime Q."""

import reveal_factory_admission_gate_stage as parent_stage
import reveal_secondary_factory_admission_gate_mips as gates
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
    """Return39 native plus seven generated pairs; three factories stay outside.

    The existing47D720 gate is preserved. Secondary refusal is checked through
    4F8760 and4A326C only; an encoded census is not computed-caller validation.
    Native startup can still retain BUSY indefinitely. No runtime setup occurs.
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
    if (initial['known_factory_admission_guarded'] is not True
            or initial['guarded_factory_address'] != 0x47D720):
        raise ValueError('secondary admission requires the preceding checked factory')
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
        raise ValueError('factory layout changed while protecting secondary admission RX')
    emitted, final_labels = gates.assemble(
        *core_args, retry_limit=retry_limit, protected_code=protected,
        extra_protected_data=extra)
    if len(emitted) != len(provisional) or final_labels != labels:
        raise ValueError('secondary admission layout changed with complete RX')
    hooks = gates.hook_words(final_labels)
    if set(hooks) & set(prefix['coherent_hooks']):
        raise ValueError('secondary factory admission conflicts with preceding hooks')
    return dict(
        prefix, code=prefix['code'] + emitted,
        secondary_factory_admission_gate_labels=final_labels,
        secondary_factory_admission_gate_code_bytes=len(emitted),
        secondary_factory_admission_gate_prefix_code_bytes=prefix_bytes,
        secondary_factory_admission_gate_hooks=hooks,
        secondary_factory_admission_gate_source_words={pc: pair for pc, pair in gates.HOOKS.values()},
        secondary_guarded_factory_address=gates.HOOKS['enter'][0],
        secondary_factory_refusal_direct_callers_checked=gates.CHECKED_CALLERS,
        secondary_factory_refusal_wrapper_callers_checked=gates.CHECKED_WRAPPER_CALLERS,
        guarded_factory_addresses=(initial['guarded_factory_address'], gates.HOOKS['enter'][0]),
        known_secondary_factory_admission_guarded=True,
        all_dialog_factories_guarded=False,
        native_coherent_hooks={**prefix['native_coherent_hooks'], **hooks},
        generated_coherent_hooks=dict(prefix['generated_coherent_hooks']),
        coherent_hooks={**prefix['coherent_hooks'], **hooks},
        protected_code_extent=protected,
        labels={**prefix['labels'], **{'secondary_factory_admission_gate_' + name: address
                                      for name, address in final_labels.items()}})
