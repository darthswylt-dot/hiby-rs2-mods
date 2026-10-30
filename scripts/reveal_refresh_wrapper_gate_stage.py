#!/usr/bin/env python3
"""Compose an invocation-local wrapper exit after classified refresh failure.

One generated restore pair is spliced after the existing pinned-U failure
decision. Its genuine refresh saved return can select a pure wrapper unwind,
without another result mailbox, object lookup or native call. These local
bytes and metadata do not install hooks or provide whole-instance isolation.
"""

import struct

import reveal_refresh_failure_gate_stage as refresh_stage
import reveal_refresh_wrapper_gate_mips as gates
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
    """Return local code and24 native plus two generated coherent hook pairs.

    The parent has already classified the genuine failed refresh invocation
    and retained its192-byte architectural save. Only native saved caller
    4AD8E0 selects a return rewrite. Native refresh1160 and wrapper48 frames
    must also be mapped, writable, retained and independently nonaliasing for
    their live use. No frame authentication, rollback or caller isolation is
    supplied. Optional following RX is protected but not appended.
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
    initial = refresh_stage.assemble(*args, **options)
    if (initial['refresh_destructor_failure_continuation_stopped'] is not True
            or initial['delete_release_failure_propagated'] is not True):
        raise ValueError('wrapper stop requires coherent preceding refresh failure')
    prefix_bytes = len(initial['code'])
    stopped = initial['refresh_failure_gate_labels']['gate_stopped']
    extra = ((receipt_address, receipt.memory_bytes(capacity)),
             (binding_address, bindings.memory_bytes(capacity)),
             (owner_address, owners.memory_bytes(owner_capacity)),
             (paint_mutex_address, receipt.MUTEX_BYTES),
             (lifecycle_address, lifecycle.memory_bytes(lifecycle_capacity)),
             (queue_address, queue.QUEUE_BYTES),
             (transport_mutex_address, queue.MUTEX_BYTES), (fault_address, 4))
    core_args = (controller_address, registry_mutex_address,
                 code_base + prefix_bytes, stopped)
    provisional, labels = gates.assemble(*core_args, extra_protected_data=extra)
    protected = (code_base, prefix_bytes + len(provisional) + following_code_bytes)
    prefix = refresh_stage.assemble(
        *args, **options,
        following_code_bytes=len(provisional) + following_code_bytes)
    if (len(prefix['code']) != prefix_bytes or prefix['labels'] != initial['labels']
            or prefix['protected_code_extent'] != protected):
        raise ValueError('refresh layout changed while protecting wrapper RX')
    emitted, final_labels = gates.assemble(
        *core_args, extra_protected_data=extra, protected_code=protected)
    if len(emitted) != len(provisional) or final_labels != labels:
        raise ValueError('wrapper helper layout changed with exact complete RX')
    hooks = gates.hook_words(final_labels, stopped)
    if set(hooks) & set(prefix['coherent_hooks']):
        raise ValueError('generated wrapper splice conflicts with preceding hook sites')
    offset = stopped - code_base
    source_words = struct.unpack_from('<2I', prefix['code'], offset)
    resume_word = struct.unpack_from('<I', prefix['code'], offset + 8)[0]
    if source_words != gates.PARENT_STOP_PAIR or resume_word != 0x8FA8008C:
        raise ValueError('unknown generated refresh stop restore words')
    patched = bytearray(prefix['code'])
    struct.pack_into('<2I', patched, offset, *hooks[stopped])
    return dict(
        prefix, code=bytes(patched) + emitted,
        refresh_wrapper_gate_labels=final_labels,
        refresh_wrapper_gate_code_bytes=len(emitted),
        refresh_wrapper_gate_prefix_code_bytes=prefix_bytes,
        refresh_wrapper_gate_hooks=hooks,
        refresh_wrapper_gate_source_words={stopped: source_words},
        refresh_wrapper_gate_parent_stopped_address=stopped,
        refresh_wrapper_gate_resume_word=resume_word,
        refresh_wrapper_failure_continuation_stopped=True,
        refresh_wrapper_exact_result_preserved=True,
        destructor_entry_fenced=False, earlier_cleanup_rolled_back=False,
        native_callers_isolated=False, raw_release_proven=False,
        native_lifetime_proven=False, partial_graph_cleanup_proven=False,
        native_coherent_hooks=dict(prefix['native_coherent_hooks']),
        generated_coherent_hooks={**prefix['generated_coherent_hooks'], **hooks},
        coherent_hooks={**prefix['coherent_hooks'], **hooks},
        protected_code_extent=protected,
        labels={**prefix['labels'],
                **{'refresh_wrapper_gate_' + name: address
                   for name, address in final_labels.items()}})
