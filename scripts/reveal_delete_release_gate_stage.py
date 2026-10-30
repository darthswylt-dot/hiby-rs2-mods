#!/usr/bin/env python3
"""Compose one destructor-scoped name-delete release result, without rollback.

Four existing redirects gain preserving dispatchers and one common delete-tail
pair gains fresh witness selection. The actual raw call and preceding observers
still execute once with their native architecture and return PCs. These local
bytes and metadata supply no installer, firmware image or device operation.
"""

import reveal_destructor_continuation_gate_stage as destructor_stage
import reveal_destructor_continuation_gate_mips as destructor
import reveal_delete_release_gate_mips as gates
import reveal_registry_release_gate_mips as release
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
    """Return local code and23 native plus one generated coherent hook pairs.

    Only the exact493F4C destructor return for pinned U receives this private
    five-phase release result. Earlier unlink/free effects remain. Genuine
    retained mapped writable nonaliasing simultaneously live native56,
    destructor1208, facade32, raw32 and private192 frames, coherent redirects
    and transitive ABI/stack cooperation are HARD premises. Popped deletion
    storage is deliberately reused by the later facade/raw frames. No layout
    check proves native lifetime,
    authenticates a fabricated frame or repairs missing partial activation.
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
    initial = destructor_stage.assemble(*args, **options)
    if (initial['destructor_delete_failure_continuation_stopped'] is not True
            or initial['registration_release_failure_propagated'] is not True
            or initial['registration_and_delete_acquire_gated'] is not True):
        raise ValueError('delete release propagation requires coherent preceding gates')
    prefix_bytes = len(initial['code'])
    legacy_entries = {
        'begin': initial['retirement_labels']['delete_begin'],
        'raw_release_call': initial['registry_release_gate_labels']['raw_release_call'],
        'raw_release_return': initial['registry_release_gate_labels']['raw_release_return'],
        'complete': initial['destructor_continuation_gate_labels']['gate'],
    }
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
    prefix = destructor_stage.assemble(
        *args, **options,
        following_code_bytes=len(provisional) + following_code_bytes)
    if (len(prefix['code']) != prefix_bytes or prefix['labels'] != initial['labels']
            or prefix['protected_code_extent'] != protected):
        raise ValueError('destructor layout changed while protecting delete-release RX')
    emitted, final_labels = gates.assemble(
        *core_args, extra_protected_data=extra, protected_code=protected)
    if len(emitted) != len(provisional) or final_labels != labels:
        raise ValueError('delete-release layout changed with exact complete RX')
    hooks = gates.hook_words(final_labels)
    expected_old = {
        retirement.HOOKS['delete_begin'][0]: retirement.hook_words(
            prefix['retirement_labels'])[retirement.HOOKS['delete_begin'][0]],
        **{release.HOOKS[name][0]: release.hook_words(
            prefix['registry_release_gate_labels'])[release.HOOKS[name][0]]
           for name in ('raw_release_call', 'raw_release_return')},
        **destructor.hook_words(prefix['destructor_continuation_gate_labels']),
    }
    replaced = {}
    for pc, pair in expected_old.items():
        if (prefix['coherent_hooks'].get(pc) != pair
                or prefix['native_coherent_hooks'].get(pc) != pair):
            raise ValueError('unknown preceding delete-release delegate hook')
        replaced[pc] = pair
    if set(hooks) & (set(prefix['coherent_hooks']) - set(replaced)):
        raise ValueError('delete-release gates conflict with a preceding hook site')
    return dict(
        prefix, code=prefix['code'] + emitted,
        delete_release_gate_labels=final_labels,
        delete_release_gate_code_bytes=len(emitted),
        delete_release_gate_prefix_code_bytes=prefix_bytes,
        delete_release_gate_hooks=hooks,
        delete_release_gate_replaced_hooks=replaced,
        delete_release_gate_legacy_entries=legacy_entries,
        destructor_name_delete_release_gated=True,
        delete_release_failure_propagated=True,
        destructor_entry_fenced=False, earlier_cleanup_rolled_back=False,
        native_callers_isolated=False, raw_release_proven=False,
        native_lifetime_proven=False, partial_graph_cleanup_proven=False,
        native_coherent_hooks={**prefix['native_coherent_hooks'], **hooks},
        generated_coherent_hooks=dict(prefix['generated_coherent_hooks']),
        coherent_hooks={**prefix['coherent_hooks'], **hooks},
        protected_code_extent=protected,
        labels={**prefix['labels'],
                **{'delete_release_gate_' + name: address
                   for name, address in final_labels.items()}})
