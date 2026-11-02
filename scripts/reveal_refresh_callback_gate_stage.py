#!/usr/bin/env python3
"""Compose private callback exits after an already classified wrapper error.

Only the wrapper helper's generated abort-address materialization is spliced.
The two exact callback returns can select pure native callback epilogues;
other callers and dialog synchronization remain outside this local stop.
Nothing installs these redirects or creates a firmware image.
"""

import struct

from build_reveal_bridge_diag import b
import reveal_refresh_wrapper_gate_stage as wrapper_stage
import reveal_refresh_wrapper_gate_mips as wrapper
import reveal_refresh_callback_gate_mips as gates
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
    """Return local code and24 native plus three generated coherent pairs.

    The parent already classified the genuine pinned-U failed refresh and its
    C->W saved return. This helper follows only W's actual saved callback RA.
    Genuine mapped retained writable nonaliasing private192/C1160/W48 and
    selected callback5312/40 frames are HARD premises. No object lifetime,
    rollback, safe retry/free or enclosing dialog cleanup policy is proved.
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
    initial = wrapper_stage.assemble(*args, **options)
    if (initial['refresh_wrapper_failure_continuation_stopped'] is not True
            or initial['refresh_wrapper_exact_result_preserved'] is not True):
        raise ValueError('callback stop requires coherent preceding wrapper failure')
    prefix_bytes = len(initial['code'])
    selected = initial['refresh_wrapper_gate_labels']['selected']
    parent_abort = initial['refresh_wrapper_gate_labels']['abort_return']
    extra = ((receipt_address, receipt.memory_bytes(capacity)),
             (binding_address, bindings.memory_bytes(capacity)),
             (owner_address, owners.memory_bytes(owner_capacity)),
             (paint_mutex_address, receipt.MUTEX_BYTES),
             (lifecycle_address, lifecycle.memory_bytes(lifecycle_capacity)),
             (queue_address, queue.QUEUE_BYTES),
             (transport_mutex_address, queue.MUTEX_BYTES), (fault_address, 4))
    core_args = (controller_address, registry_mutex_address,
                 code_base + prefix_bytes, selected, parent_abort)
    provisional, labels = gates.assemble(*core_args, extra_protected_data=extra)
    protected = (code_base, prefix_bytes + len(provisional) + following_code_bytes)
    prefix = wrapper_stage.assemble(
        *args, **options,
        following_code_bytes=len(provisional) + following_code_bytes)
    if (len(prefix['code']) != prefix_bytes or prefix['labels'] != initial['labels']
            or prefix['protected_code_extent'] != protected):
        raise ValueError('wrapper layout changed while protecting callback RX')
    emitted, final_labels = gates.assemble(
        *core_args, extra_protected_data=extra, protected_code=protected)
    if len(emitted) != len(provisional) or final_labels != labels:
        raise ValueError('callback helper layout changed with exact complete RX')
    hooks = gates.hook_words(final_labels, selected)
    if set(hooks) & set(prefix['coherent_hooks']):
        raise ValueError('generated callback splice conflicts with preceding hook sites')
    offset = selected - code_base
    source_words = struct.unpack_from('<2I', prefix['code'], offset)
    resume_word = struct.unpack_from('<I', prefix['code'], offset + 8)[0]
    abort_words = struct.unpack_from('<2I', prefix['code'], parent_abort - code_base)
    expected_abort = (b.j_type(2, wrapper.WRAPPER_EPILOGUE), wrapper.WRAPPER_RA_DELAY)
    if (source_words != gates.parent_stop_pair(parent_abort)
            or resume_word != gates.PARENT_RESUME_WORD
            or abort_words != expected_abort):
        raise ValueError('unknown generated wrapper selected, resume or abort words')
    patched = bytearray(prefix['code'])
    struct.pack_into('<2I', patched, offset, *hooks[selected])
    return dict(
        prefix, code=bytes(patched) + emitted,
        refresh_callback_gate_labels=final_labels,
        refresh_callback_gate_code_bytes=len(emitted),
        refresh_callback_gate_prefix_code_bytes=prefix_bytes,
        refresh_callback_gate_hooks=hooks,
        refresh_callback_gate_source_words={selected: source_words},
        refresh_callback_gate_parent_selected_address=selected,
        refresh_callback_gate_parent_abort_return_address=parent_abort,
        refresh_callback_gate_parent_abort_words=abort_words,
        refresh_callback_gate_resume_word=resume_word,
        refresh_callback_failure_continuations_stopped=True,
        refresh_callback_exact_result_preserved=True,
        destructor_entry_fenced=False, earlier_cleanup_rolled_back=False,
        native_callers_isolated=False, raw_release_proven=False,
        native_lifetime_proven=False, partial_graph_cleanup_proven=False,
        native_coherent_hooks=dict(prefix['native_coherent_hooks']),
        generated_coherent_hooks={**prefix['generated_coherent_hooks'], **hooks},
        coherent_hooks={**prefix['coherent_hooks'], **hooks},
        protected_code_extent=protected,
        labels={**prefix['labels'],
                **{'refresh_callback_gate_' + name: address
                   for name, address in final_labels.items()}})
