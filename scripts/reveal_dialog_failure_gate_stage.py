#!/usr/bin/env python3
"""Compose a classified dialog error exit and qualified single raw release.

Only two generated callback-abort pairs are spliced. No generic native dialog
result check, image edit, hook installation or outer object isolation is added.
"""

import struct

import reveal_dialog_acquire_gate_stage as acquire_stage
import reveal_dialog_failure_gate_mips as gates
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
    """Return local code and26 native plus five generated coherent pairs.

    Actual callback failure classification comes from the inherited return
    route. Continuous same-thread ordinary-M ownership across the callback,
    initialized retained M and genuine mapped/nonaliasing frames are HARD
    premises, not consequences of ADMITTED. Optional following RX is protected
    but not appended. This is no whole-instance cleanup or lifetime policy.
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
    if (initial['dialog_acquire_failure_admission_gated'] is not True
            or initial['refresh_callback_failure_continuations_stopped'] is not True):
        raise ValueError('dialog failure exit requires coherent acquisition and callbacks')
    prefix_bytes = len(initial['code'])
    parents = tuple(initial['refresh_callback_gate_labels'][name]
                    for name in ('first_abort_return', 'second_abort_return'))
    extra = ((receipt_address, receipt.memory_bytes(capacity)),
             (binding_address, bindings.memory_bytes(capacity)),
             (owner_address, owners.memory_bytes(owner_capacity)),
             (paint_mutex_address, receipt.MUTEX_BYTES),
             (lifecycle_address, lifecycle.memory_bytes(lifecycle_capacity)),
             (queue_address, queue.QUEUE_BYTES),
             (transport_mutex_address, queue.MUTEX_BYTES), (fault_address, 4))
    core_args = (controller_address, registry_mutex_address,
                 code_base + prefix_bytes, *parents)
    provisional, labels = gates.assemble(*core_args, extra_protected_data=extra)
    protected = (code_base, prefix_bytes + len(provisional) + following_code_bytes)
    prefix = acquire_stage.assemble(
        *args, **options,
        following_code_bytes=len(provisional) + following_code_bytes)
    if (len(prefix['code']) != prefix_bytes or prefix['labels'] != initial['labels']
            or prefix['protected_code_extent'] != protected):
        raise ValueError('acquisition layout changed while protecting dialog failure RX')
    emitted, final_labels = gates.assemble(
        *core_args, extra_protected_data=extra, protected_code=protected)
    if len(emitted) != len(provisional) or final_labels != labels:
        raise ValueError('dialog failure layout changed with exact complete RX')
    hooks = gates.hook_words(final_labels, *parents)
    if set(hooks) & set(prefix['coherent_hooks']):
        raise ValueError('dialog failure splices conflict with preceding hooks')
    patched, source_words = bytearray(prefix['code']), {}
    for pc, expected in zip(parents, (gates.PARENT_FIRST_PAIR, gates.PARENT_SECOND_PAIR)):
        actual = struct.unpack_from('<2I', prefix['code'], pc - code_base)
        if actual != expected:
            raise ValueError('unknown preceding callback abort pair')
        source_words[pc] = actual
        struct.pack_into('<2I', patched, pc - code_base, *hooks[pc])
    return dict(
        prefix, code=bytes(patched) + emitted,
        dialog_failure_gate_labels=final_labels,
        dialog_failure_gate_code_bytes=len(emitted),
        dialog_failure_gate_prefix_code_bytes=prefix_bytes,
        dialog_failure_gate_hooks=hooks,
        dialog_failure_gate_source_words=source_words,
        dialog_failure_gate_parent_abort_addresses=parents,
        dialog_callback_failure_cleanup_stopped=True,
        dialog_callback_failure_exact_result_preserved=True,
        dialog_failure_release_attempt_guarded=True,
        destructor_entry_fenced=False, earlier_cleanup_rolled_back=False,
        native_callers_isolated=False, raw_release_proven=False,
        native_lifetime_proven=False, partial_graph_cleanup_proven=False,
        native_coherent_hooks=dict(prefix['native_coherent_hooks']),
        generated_coherent_hooks={**prefix['generated_coherent_hooks'], **hooks},
        coherent_hooks={**prefix['coherent_hooks'], **hooks},
        protected_code_extent=protected,
        labels={**prefix['labels'],
                **{'dialog_failure_gate_' + name: address
                   for name, address in final_labels.items()}})
