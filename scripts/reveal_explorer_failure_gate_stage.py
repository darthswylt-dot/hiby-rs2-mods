#!/usr/bin/env python3
"""Compose one invocation-local explorer abort, not graph rollback/isolation.

The generated first-constructor stop's initial restore pair is explicitly
spliced. A matching explorer call returns through its existing NULL epilogue;
other callers retain the old engine-pointer return. Earlier allocations,
resource aliases and mutations remain. Nothing installs or runs these bytes.
"""

import struct

import reveal_constructor_continuation_gate_stage as constructor_stage
import reveal_explorer_failure_gate_mips as gate
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
    """Return local code and twenty native plus one generated coherent pair.

    The parent has already saved its192-byte architectural frame and classified
    a genuine pinned-U nonzero registration result. The new helper may retarget
    only the current constructor's private saved return slot. Stock constructor
    unwind then reaches stock explorer NULL unwind, without later graph work.
    Native136 and explorer6096 frames must also be genuine mapped retained and
    independently nonaliasing. No malformed-stack recovery or cleanup follows.
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
    initial = constructor_stage.assemble(*args, **options)
    if (initial['constructor_status_continuations_gated'] is not True
            or initial['constructor_engine_return_preserved'] is not True):
        raise ValueError('explorer stop requires coherent scoped constructor stops')
    prefix_bytes = len(initial['code'])
    stopped = initial['constructor_continuation_gate_labels']['first_gate_stopped']
    extra = ((receipt_address, receipt.memory_bytes(capacity)),
             (binding_address, bindings.memory_bytes(capacity)),
             (owner_address, owners.memory_bytes(owner_capacity)),
             (paint_mutex_address, receipt.MUTEX_BYTES),
             (lifecycle_address, lifecycle.memory_bytes(lifecycle_capacity)),
             (queue_address, queue.QUEUE_BYTES),
             (transport_mutex_address, queue.MUTEX_BYTES), (fault_address, 4))
    core_args = (controller_address, registry_mutex_address,
                 code_base + prefix_bytes, stopped)
    provisional, labels = gate.assemble(*core_args, extra_protected_data=extra)
    protected = (code_base, prefix_bytes + len(provisional) + following_code_bytes)
    prefix = constructor_stage.assemble(
        *args, **options,
        following_code_bytes=len(provisional) + following_code_bytes)
    if (len(prefix['code']) != prefix_bytes or prefix['labels'] != initial['labels']
            or prefix['protected_code_extent'] != protected):
        raise ValueError('constructor layout changed while protecting explorer RX')
    emitted, final_labels = gate.assemble(
        *core_args, extra_protected_data=extra, protected_code=protected)
    if len(emitted) != len(provisional) or final_labels != labels:
        raise ValueError('explorer helper layout changed with exact complete RX')
    hooks = gate.hook_words(final_labels, stopped)
    if set(hooks) & set(prefix['coherent_hooks']):
        raise ValueError('generated explorer splice conflicts with preceding hook sites')
    offset = stopped - code_base
    source_words = struct.unpack_from('<2I', prefix['code'], offset)
    if source_words != gate.PARENT_STOP_PAIR:
        raise ValueError('unknown generated constructor stop restore pair')
    patched = bytearray(prefix['code'])
    struct.pack_into('<2I', patched, offset, *hooks[stopped])
    return dict(
        prefix, code=bytes(patched) + emitted,
        explorer_failure_gate_labels=final_labels,
        explorer_failure_gate_code_bytes=len(emitted),
        explorer_failure_gate_prefix_code_bytes=prefix_bytes,
        explorer_failure_gate_hooks=hooks,
        explorer_failure_gate_source_words={stopped: source_words},
        native_coherent_hooks=dict(prefix['coherent_hooks']),
        generated_coherent_hooks=dict(hooks),
        explorer_failed_registration_continuation_stopped=True,
        explorer_returns_native_null_on_classified_failure=True,
        partial_graph_cleanup_proven=False,
        native_callers_isolated=False, raw_release_proven=False,
        native_lifetime_proven=False,
        coherent_hooks={**prefix['coherent_hooks'], **hooks},
        protected_code_extent=protected,
        labels={**prefix['labels'],
                **{'explorer_failure_gate_' + name: address
                   for name, address in final_labels.items()}})
