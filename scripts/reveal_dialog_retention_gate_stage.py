#!/usr/bin/env python3
"""Compose no-unlock error retention and serialized known outer consumers."""

import struct

import reveal_dialog_failure_gate_stage as failure_stage
import reveal_dialog_retention_gate_mips as gates
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
    """Return32 native and seven generated coherent pairs, no runtime setup.

    The separate guard4 must be mapped process-lifetime storage initialized0
    before quiescent coherent activation. QUARANTINED is not reset by this
    module. All known outer callers must enter/leave through these gates;
    foreign/computed entries and external H aliases are not universally fenced.
    """
    if (type(following_code_bytes) is not int or following_code_bytes < 0
            or following_code_bytes % 4):
        raise ValueError('following code bytes must be a nonnegative aligned integer')
    if type(retry_limit) is not int or not 1 <= retry_limit <= 64:
        raise ValueError('retry limit must be an integer in1..64')
    args = (receipt_address, binding_address, owner_address, controller_address,
            registry_mutex_address, paint_mutex_address, code_base,
            lifecycle_address, queue_address, transport_mutex_address, fault_address)
    options = dict(capacity=capacity, lifecycle_capacity=lifecycle_capacity,
                   owner_capacity=owner_capacity, ticket_limit=ticket_limit,
                   queue_capacity=queue_capacity, transport_capacity=transport_capacity)
    initial = failure_stage.assemble(*args, **options)
    if (initial['dialog_callback_failure_cleanup_stopped'] is not True
            or initial['dialog_acquire_failure_admission_gated'] is not True):
        raise ValueError('retention requires coherent failure and acquisition gates')
    prefix_bytes = len(initial['code'])
    callback = initial['dialog_failure_gate_labels']['error_return']
    denied = initial['dialog_acquire_gate_labels']['gate_denied']
    extra = ((receipt_address, receipt.memory_bytes(capacity)),
             (binding_address, bindings.memory_bytes(capacity)),
             (owner_address, owners.memory_bytes(owner_capacity)),
             (paint_mutex_address, receipt.MUTEX_BYTES),
             (lifecycle_address, lifecycle.memory_bytes(lifecycle_capacity)),
             (queue_address, queue.QUEUE_BYTES),
             (transport_mutex_address, queue.MUTEX_BYTES), (fault_address, 4))
    core_args = (controller_address, registry_mutex_address, code_base + prefix_bytes,
                 callback, denied, guard_address)
    provisional, labels = gates.assemble(*core_args, retry_limit=retry_limit,
                                         extra_protected_data=extra)
    protected = (code_base, prefix_bytes + len(provisional) + following_code_bytes)
    prefix = failure_stage.assemble(
        *args, **options, following_code_bytes=len(provisional) + following_code_bytes)
    if (len(prefix['code']) != prefix_bytes or prefix['labels'] != initial['labels']
            or prefix['protected_code_extent'] != protected):
        raise ValueError('failure layout changed while protecting retention RX')
    emitted, final_labels = gates.assemble(
        *core_args, retry_limit=retry_limit, protected_code=protected,
        extra_protected_data=extra)
    if len(emitted) != len(provisional) or final_labels != labels:
        raise ValueError('retention layout changed with complete RX')
    hooks = gates.hook_words(final_labels, callback, denied)
    if set(hooks) & set(prefix['coherent_hooks']):
        raise ValueError('retention gates conflict with preceding hooks')
    patched, source_words = bytearray(prefix['code']), {}
    for pc, expected in ((callback, gates.PARENT_CALLBACK_PAIR),
                         (denied, gates.PARENT_DENIED_PAIR)):
        actual = struct.unpack_from('<2I', prefix['code'], pc - code_base)
        if actual != expected:
            raise ValueError('unknown inherited retention source pair')
        source_words[pc] = actual
        struct.pack_into('<2I', patched, pc - code_base, *hooks[pc])
    resume = struct.unpack_from('<I', prefix['code'], denied - code_base + 8)[0]
    if resume != gates.PARENT_DENIED_RESUME:
        raise ValueError('unknown inherited denial resume instruction')
    native = {pc: pair for pc, pair in hooks.items() if gates.NATIVE_RX[0] <= pc < gates.NATIVE_RX[1]}
    generated = {pc: pair for pc, pair in hooks.items() if pc not in native}
    return dict(
        prefix, code=bytes(patched) + emitted,
        dialog_retention_gate_labels=final_labels,
        dialog_retention_gate_code_bytes=len(emitted),
        dialog_retention_gate_prefix_code_bytes=prefix_bytes,
        dialog_retention_gate_hooks=hooks,
        dialog_retention_gate_source_words=source_words,
        dialog_retention_gate_parent_error_return=callback,
        dialog_retention_gate_parent_gate_denied=denied,
        dialog_retention_gate_denied_resume_word=resume,
        guard_address=guard_address, guard_bytes=4, guard_initial_value=0,
        guard_retry_limit=retry_limit, guard_runtime_reset_supported=False,
        unconfirmed_dialog_unlock_suppressed=True,
        known_dialog_outer_frees_guarded=True, known_dialog_reentry_guarded=True,
        known_dialog_close_facade_guarded=True,
        dialog_ownership_proven=False, dialog_failure_release_attempt_guarded=False,
        native_callers_isolated=False, raw_release_proven=False,
        native_lifetime_proven=False, partial_graph_cleanup_proven=False,
        earlier_cleanup_rolled_back=False, destructor_entry_fenced=False,
        native_coherent_hooks={**prefix['native_coherent_hooks'], **native},
        generated_coherent_hooks={**prefix['generated_coherent_hooks'], **generated},
        coherent_hooks={**prefix['coherent_hooks'], **hooks},
        protected_code_extent=protected,
        labels={**prefix['labels'], **{'dialog_retention_gate_' + name: address
                                      for name, address in final_labels.items()}})
