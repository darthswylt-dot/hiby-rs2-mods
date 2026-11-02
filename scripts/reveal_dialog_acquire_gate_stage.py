#!/usr/bin/env python3
"""Compose checked acquisition admission for the native dialog+10 call site.

The source mutex load and actual raw service each run once. A local denial
returns before graph/callback cleanup without an unlock or destruction. This
does not handle callback-error release, earlier +0C/worker use or outer frees.
Nothing installs these redirects or alters a saved firmware image.
"""

import reveal_refresh_callback_gate_stage as callback_stage
import reveal_dialog_acquire_gate_mips as gates
import reveal_registry_retirement_mips as retirement
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
    """Return local code and26 native plus three generated coherent pairs.

    All genuine47C740+10 invocations receive this same-invocation protocol;
    U/R remain static exclusions, not runtime dialog or mutex pins. Genuine
    mapped writable retained D104/W32/private192 frames, live initialized
    ordinary M, transitive ABI/stack cooperation and coherent redirects are
    HARD premises. No ownership/lifetime or outer-caller isolation is proved.
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
    initial = callback_stage.assemble(*args, **options)
    if (initial['refresh_callback_failure_continuations_stopped'] is not True
            or initial['registration_and_delete_acquire_gated'] is not True):
        raise ValueError('dialog acquisition requires coherent preceding callbacks and observers')
    prefix_bytes = len(initial['code'])
    legacy_entries = {name: initial['retirement_labels'][name]
                      for name in ('raw_call', 'raw_return')}
    extra = ((receipt_address, receipt.memory_bytes(capacity)),
             (binding_address, bindings.memory_bytes(capacity)),
             (owner_address, owners.memory_bytes(owner_capacity)),
             (paint_mutex_address, receipt.MUTEX_BYTES),
             (lifecycle_address, lifecycle.memory_bytes(lifecycle_capacity)),
             (queue_address, queue.QUEUE_BYTES),
             (transport_mutex_address, queue.MUTEX_BYTES), (fault_address, 4))
    core_args = (controller_address, registry_mutex_address, code_base + prefix_bytes,
                 *legacy_entries.values())
    provisional, labels = gates.assemble(*core_args, extra_protected_data=extra)
    protected = (code_base, prefix_bytes + len(provisional) + following_code_bytes)
    prefix = callback_stage.assemble(
        *args, **options,
        following_code_bytes=len(provisional) + following_code_bytes)
    if (len(prefix['code']) != prefix_bytes or prefix['labels'] != initial['labels']
            or prefix['protected_code_extent'] != protected):
        raise ValueError('callback layout changed while protecting dialog acquisition RX')
    emitted, final_labels = gates.assemble(
        *core_args, extra_protected_data=extra, protected_code=protected)
    if len(emitted) != len(provisional) or final_labels != labels:
        raise ValueError('dialog acquisition layout changed with exact complete RX')
    hooks = gates.hook_words(final_labels)
    expected_old = retirement.hook_words(prefix['retirement_labels'])
    replaced = {}
    for name in ('raw_call', 'raw_return'):
        pc = retirement.HOOKS[name][0]
        pair = expected_old[pc]
        if (prefix['coherent_hooks'].get(pc) != pair
                or prefix['native_coherent_hooks'].get(pc) != pair):
            raise ValueError('unknown preceding dialog acquisition raw observer')
        replaced[pc] = pair
    if set(hooks) & (set(prefix['coherent_hooks']) - set(replaced)):
        raise ValueError('dialog acquisition gates conflict with preceding hook sites')
    return dict(
        prefix, code=prefix['code'] + emitted,
        dialog_acquire_gate_labels=final_labels,
        dialog_acquire_gate_code_bytes=len(emitted),
        dialog_acquire_gate_prefix_code_bytes=prefix_bytes,
        dialog_acquire_gate_hooks=hooks,
        dialog_acquire_gate_replaced_hooks=replaced,
        dialog_acquire_gate_legacy_entries=legacy_entries,
        dialog_acquire_failure_admission_gated=True,
        destructor_entry_fenced=False, earlier_cleanup_rolled_back=False,
        native_callers_isolated=False, raw_release_proven=False,
        native_lifetime_proven=False, partial_graph_cleanup_proven=False,
        native_coherent_hooks={**prefix['native_coherent_hooks'], **hooks},
        generated_coherent_hooks=dict(prefix['generated_coherent_hooks']),
        coherent_hooks={**prefix['coherent_hooks'], **hooks},
        protected_code_extent=protected,
        labels={**prefix['labels'],
                **{'dialog_acquire_gate_' + name: address
                   for name, address in final_labels.items()}})
