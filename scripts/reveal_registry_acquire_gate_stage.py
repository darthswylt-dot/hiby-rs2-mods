#!/usr/bin/env python3
"""Compose two bounded pre-mutation raw-acquire gates, not caller isolation.

Only registration and name-selected deletion gain the explicit admission
checks. Other native teardown paths and ignored caller results remain unsafe.
This is an offline instruction-fetch composition, never an installer, native
lifetime certificate, UI integration or whole-instance quarantine mechanism.
"""

import reveal_birth_consumer_stage as consumer_stage
import reveal_registry_acquire_gate_mips as gates
import reveal_registry_receipt_mips as receipt
import reveal_registry_owner_mips as bindings
import reveal_registry_lifecycle_mips as lifecycle
import reveal_paint_retirement_mips as owners
import reveal_birth_queue_mips as queue


def assemble(receipt_address, binding_address, owner_address, controller_address,
             registry_mutex_address, paint_mutex_address, code_base,
             lifecycle_address, queue_address, transport_mutex_address,
             fault_address, *, capacity=16, lifecycle_capacity=16,
             owner_capacity=16, ticket_limit=owners.MAX_TICKET,
             queue_capacity=64, transport_capacity=40, following_code_bytes=0):
    """Return local bytes and a complete, explicitly opt-in fixture hook map.

    The native prologues have already written their frames before these gates.
    Genuine retained, mapped, nonaliasing native and architectural-save frames
    are therefore hard prerequisites, not established by these hooks. Denied
    acquisition does not unlock or isolate an uncertain instance, and native
    callers can still ignore the error and continue unsafe object work.
    Optional following RX is protected but not appended. Its zero default
    preserves this composition's preceding bytes and labels.
    """
    if (type(following_code_bytes) is not int or following_code_bytes < 0
            or following_code_bytes % 4):
        raise ValueError('following code bytes must be a nonnegative aligned integer')
    args = (receipt_address, binding_address, owner_address, controller_address,
            registry_mutex_address, paint_mutex_address, code_base,
            lifecycle_address, queue_address, transport_mutex_address, fault_address)
    options = dict(capacity=capacity, lifecycle_capacity=lifecycle_capacity,
                   owner_capacity=owner_capacity, ticket_limit=ticket_limit,
                   queue_capacity=queue_capacity, transport_capacity=transport_capacity)
    initial = consumer_stage.assemble(*args, **options)
    if (initial['registry_release_checked'] is not True
            or initial['birth_consumer_historical_only'] is not True):
        raise ValueError('acquire gates require coherent checked lifecycle observers')
    prefix_bytes = len(initial['code'])
    extra = ((receipt_address, receipt.memory_bytes(capacity)),
             (binding_address, bindings.memory_bytes(capacity)),
             (owner_address, owners.memory_bytes(owner_capacity)),
             (paint_mutex_address, receipt.MUTEX_BYTES),
             (lifecycle_address, lifecycle.memory_bytes(lifecycle_capacity)),
             (queue_address, queue.QUEUE_BYTES),
             (transport_mutex_address, queue.MUTEX_BYTES), (fault_address, 4))
    core_args = (controller_address, registry_mutex_address, code_base + prefix_bytes)
    provisional, labels = gates.assemble(*core_args, extra_protected_data=extra)
    protected = (code_base, prefix_bytes + len(provisional) + following_code_bytes)
    prefix = consumer_stage.assemble(
        *args, **options,
        following_code_bytes=len(provisional) + following_code_bytes)
    if (len(prefix['code']) != prefix_bytes or prefix['labels'] != initial['labels']
            or prefix['protected_code_extent'] != protected):
        raise ValueError('consumer layout changed while protecting acquire-gate RX')
    emitted, final_labels = gates.assemble(
        *core_args, extra_protected_data=extra, protected_code=protected)
    if len(emitted) != len(provisional) or final_labels != labels:
        raise ValueError('acquire-gate layout changed with exact complete RX')
    hooks = gates.hook_words(final_labels)
    if set(hooks) & set(prefix['coherent_hooks']):
        raise ValueError('acquire gates conflict with preceding coherent hook sites')
    return dict(
        prefix, code=prefix['code'] + emitted,
        acquire_gate_labels=final_labels, acquire_gate_code_bytes=len(emitted),
        acquire_gate_prefix_code_bytes=prefix_bytes, acquire_gate_hooks=hooks,
        registration_and_delete_acquire_gated=True,
        native_callers_isolated=False, native_lifetime_proven=False,
        coherent_hooks={**prefix['coherent_hooks'], **hooks},
        protected_code_extent=protected,
        labels={**prefix['labels'],
                **{'acquire_gate_' + name: address
                   for name, address in final_labels.items()}})
