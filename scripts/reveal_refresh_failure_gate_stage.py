#!/usr/bin/env python3
"""Compose a scoped stop before refresh recreates a view after deletion fails.

The native destructor call has already executed. This local successor adds
one return check before refresh masks that result and may create a new view.
Earlier effects and higher callback handling remain outside this late stop.
Nothing installs these redirects or creates a firmware image.
"""

import reveal_delete_release_gate_stage as delete_stage
import reveal_refresh_failure_gate_mips as gates
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
    """Return local code and24 native plus one generated coherent hook pairs.

    The selected refresh return is saved S2=pinned U, RA=4ACD94 and nonzero
    V0. It skips local recreation and offset restoration through the genuine
    native1160-byte epilogue. Other routes retain their original branch and
    single V0=1 delay effect. Complete mapped retained writable nonaliasing
    native/private frames and all inherited premises remain mandatory.
    Optional following RX is protected but not appended; zero is the default.
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
    initial = delete_stage.assemble(*args, **options)
    if (initial['delete_release_failure_propagated'] is not True
            or initial['destructor_delete_failure_continuation_stopped'] is not True):
        raise ValueError('refresh stop requires coherent preceding destructor gates')
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
    prefix = delete_stage.assemble(
        *args, **options,
        following_code_bytes=len(provisional) + following_code_bytes)
    if (len(prefix['code']) != prefix_bytes or prefix['labels'] != initial['labels']
            or prefix['protected_code_extent'] != protected):
        raise ValueError('delete-release layout changed while protecting refresh RX')
    emitted, final_labels = gates.assemble(
        *core_args, extra_protected_data=extra, protected_code=protected)
    if len(emitted) != len(provisional) or final_labels != labels:
        raise ValueError('refresh-gate layout changed with exact complete RX')
    hooks = gates.hook_words(final_labels)
    if set(hooks) & set(prefix['coherent_hooks']):
        raise ValueError('refresh gate conflicts with preceding hook sites')
    return dict(
        prefix, code=prefix['code'] + emitted,
        refresh_failure_gate_labels=final_labels,
        refresh_failure_gate_code_bytes=len(emitted),
        refresh_failure_gate_prefix_code_bytes=prefix_bytes,
        refresh_failure_gate_hooks=hooks,
        refresh_destructor_failure_continuation_stopped=True,
        destructor_entry_fenced=False, earlier_cleanup_rolled_back=False,
        native_callers_isolated=False, raw_release_proven=False,
        native_lifetime_proven=False, partial_graph_cleanup_proven=False,
        native_coherent_hooks={**prefix['native_coherent_hooks'], **hooks},
        generated_coherent_hooks=dict(prefix['generated_coherent_hooks']),
        coherent_hooks={**prefix['coherent_hooks'], **hooks},
        protected_code_extent=protected,
        labels={**prefix['labels'],
                **{'refresh_failure_gate_' + name: address
                   for name, address in final_labels.items()}})
