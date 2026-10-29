#!/usr/bin/env python3
"""Compose scoped constructor continuation stops, not outer-caller isolation.

Only genuine registration returns in two native constructors gain a status
check. A stopped constructor still returns its saved engine scalar. Native
outer callers, skipped-registration paths and masked release failures remain
unchanged. This offline composition neither installs hooks nor enables UI.
"""

import reveal_registry_acquire_gate_stage as acquire_stage
import reveal_constructor_continuation_gate_mips as gates
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
    """Return local code and all twenty coherent instruction-fetch hook pairs.

    Genuine retained mapped nonaliasing native136/128 and private192 frames
    remain hard premises. The new gates classify only saved U/RA and V0, not
    engine liveness, raw release, V1, or ownership of escaped aliases. They
    suppress local UI/name work on a classified nonzero registration result,
    without freeing or changing the native engine-pointer return convention.
    Optional following RX is protected but not appended. Zero preserves this
    composition's preceding bytes and labels.
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
    initial = acquire_stage.assemble(*args, **options)
    if (initial['registration_and_delete_acquire_gated'] is not True
            or initial['registry_release_checked'] is not True):
        raise ValueError('constructor stops require coherent checked acquire gates')
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
    prefix = acquire_stage.assemble(
        *args, **options,
        following_code_bytes=len(provisional) + following_code_bytes)
    if (len(prefix['code']) != prefix_bytes or prefix['labels'] != initial['labels']
            or prefix['protected_code_extent'] != protected):
        raise ValueError('acquire-gate layout changed while protecting constructor RX')
    emitted, final_labels = gates.assemble(
        *core_args, extra_protected_data=extra, protected_code=protected)
    if len(emitted) != len(provisional) or final_labels != labels:
        raise ValueError('constructor-gate layout changed with exact complete RX')
    hooks = gates.hook_words(final_labels)
    if set(hooks) & set(prefix['coherent_hooks']):
        raise ValueError('constructor gates conflict with preceding coherent hook sites')
    return dict(
        prefix, code=prefix['code'] + emitted,
        constructor_continuation_gate_labels=final_labels,
        constructor_continuation_gate_code_bytes=len(emitted),
        constructor_continuation_gate_prefix_code_bytes=prefix_bytes,
        constructor_continuation_gate_hooks=hooks,
        constructor_status_continuations_gated=True,
        constructor_engine_return_preserved=True,
        native_callers_isolated=False, raw_release_proven=False,
        native_lifetime_proven=False,
        coherent_hooks={**prefix['coherent_hooks'], **hooks},
        protected_code_extent=protected,
        labels={**prefix['labels'],
                **{'constructor_continuation_gate_' + name: address
                   for name, address in final_labels.items()}})
