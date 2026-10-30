#!/usr/bin/env python3
"""Compose a late destructor continuation stop, not a cleanup entry fence.

Only the selected explorer destructor's explicit nonzero name-delete return
skips its remaining local resource cleanup. Earlier effects are not undone,
masked errors still forward, and no graph is reclaimed or retained here.
This offline composition neither installs hooks nor executes native cleanup.
"""

import reveal_registry_release_gate_stage as release_stage
import reveal_destructor_continuation_gate_mips as gates
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
    """Return local code and22 native plus one generated coherent hook pairs.

    The name-delete call and earlier destructor work have already happened.
    The gate reads only saved S1/RA/V0 and skips the remaining local continuation
    on a matching error. Native1208 and private192 frames must be genuinely
    mapped retained writable and nonaliasing. No malformed-SP recovery, graph
    cleanup permission, caller isolation or rollback is established. Optional
    following RX is protected but not appended; zero preserves default bytes.
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
    initial = release_stage.assemble(*args, **options)
    if (initial['registration_and_delete_acquire_gated'] is not True
            or initial['registration_release_failure_propagated'] is not True):
        raise ValueError('destructor stop requires coherent preceding registry gates')
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
    prefix = release_stage.assemble(
        *args, **options,
        following_code_bytes=len(provisional) + following_code_bytes)
    if (len(prefix['code']) != prefix_bytes or prefix['labels'] != initial['labels']
            or prefix['protected_code_extent'] != protected):
        raise ValueError('release layout changed while protecting destructor RX')
    emitted, final_labels = gates.assemble(
        *core_args, extra_protected_data=extra, protected_code=protected)
    if len(emitted) != len(provisional) or final_labels != labels:
        raise ValueError('destructor-gate layout changed with exact complete RX')
    hooks = gates.hook_words(final_labels)
    if set(hooks) & set(prefix['coherent_hooks']):
        raise ValueError('destructor gate conflicts with preceding hook sites')
    return dict(
        prefix, code=prefix['code'] + emitted,
        destructor_continuation_gate_labels=final_labels,
        destructor_continuation_gate_code_bytes=len(emitted),
        destructor_continuation_gate_prefix_code_bytes=prefix_bytes,
        destructor_continuation_gate_hooks=hooks,
        destructor_delete_failure_continuation_stopped=True,
        destructor_entry_fenced=False, earlier_cleanup_rolled_back=False,
        native_callers_isolated=False, raw_release_proven=False,
        native_lifetime_proven=False, partial_graph_cleanup_proven=False,
        native_coherent_hooks={**prefix['native_coherent_hooks'], **hooks},
        generated_coherent_hooks=dict(prefix['generated_coherent_hooks']),
        coherent_hooks={**prefix['coherent_hooks'], **hooks},
        protected_code_extent=protected,
        labels={**prefix['labels'],
                **{'destructor_continuation_gate_' + name: address
                   for name, address in final_labels.items()}})
