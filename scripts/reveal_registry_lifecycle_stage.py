#!/usr/bin/env python3
"""Offline field-correlated birth/retirement observations, NOT native lifetime.

The four known retirement frontiers are observed under fresh checked R before
their first unlink, or conservatively before an outer loop releases R. Selected
retirement is not proof of deletion. Missing events can still miscorrelate
reused addresses: neither a healthy table nor state1 grants live/free authority.
No constructor/explorer integration, image I/O, installer or device operation.
"""

import reveal_creation_capture_stage as creation
import reveal_registry_receipt_mips as receipt
import reveal_registry_owner_mips as bindings
import reveal_paint_retirement_mips as owners
import reveal_registry_lifecycle_mips as lifecycle
import reveal_registry_retirement_mips as retirement


def assemble(receipt_address, binding_address, owner_address, controller_address,
             registry_mutex_address, paint_mutex_address, code_base,
             lifecycle_address, *, capacity=16, lifecycle_capacity=16,
             owner_capacity=16, ticket_limit=owners.MAX_TICKET, queue_capacity=64,
             birth_commit_callback=None, following_code_bytes=0,
             extra_protected_data=()):
    """Return local bytes/labels and coherent instruction-fetch overrides only.

    All eleven retirement redirects plus the existing receipt/release redirects
    must be coherent. The two global raw-acquire overrides are the new dispatch
    entries; they chain to old receipt entries on registration/unknown routes.
    Private/transitive stack retention, real initialized ordinary R, stable
    fields, common synchronization and safe native continuation remain premises.
    An optional birth commit callback must lie entirely within the explicitly
    advertised following RX tail, outside this stage's actual emitted bytes.
    Zero/None preserve preceding bytes/labels; no following bytes are appended.
    """
    if (type(following_code_bytes) is not int or following_code_bytes < 0
            or following_code_bytes % 4):
        raise ValueError('following code bytes must be a nonnegative aligned integer')
    if (type(extra_protected_data) is not tuple
            or any(type(extent) is not tuple or len(extent) != 2
                   or any(type(value) is not int for value in extent)
                   or extent[1] <= 0 or extent[1] % 4
                   for extent in extra_protected_data)):
        raise ValueError('extra protected data must be a tuple of aligned extents')
    state_bytes = lifecycle.memory_bytes(lifecycle_capacity)
    args = (receipt_address, binding_address, owner_address, controller_address,
            registry_mutex_address, paint_mutex_address, code_base)
    options = dict(capacity=capacity, owner_capacity=owner_capacity,
                   ticket_limit=ticket_limit, queue_capacity=queue_capacity,
                   checked_registry_release=True,
                   extra_protected_data=((lifecycle_address, state_bytes),
                                         *extra_protected_data))
    initial = creation.assemble(*args, **options)
    initial_end = code_base + len(initial['code'])
    issue_base = initial['issuer_labels']['issue']
    probe, _ = receipt.assemble(
        receipt_address, controller_address, registry_mutex_address,
        initial['receipt_labels']['begin'], capacity=capacity,
        publication_callback=(issue_base, issue_base, initial['issuer_code_bytes']),
        birth_callback=(initial_end, initial_end, 4))
    prefix_bytes = len(initial['code']) + len(probe) - initial['receipt_code_bytes']
    life_base = code_base + prefix_bytes
    extra = ((receipt_address, receipt.memory_bytes(capacity)),
             (binding_address, bindings.memory_bytes(capacity)),
             (owner_address, owners.memory_bytes(owner_capacity)),
             (paint_mutex_address, receipt.MUTEX_BYTES), *extra_protected_data)
    life_args = (lifecycle_address, controller_address, registry_mutex_address,
                 life_base)
    life_options = dict(capacity=lifecycle_capacity, extra_protected_data=extra,
                        birth_commit_callback=birth_commit_callback)
    provisional, life_labels = lifecycle.assemble(*life_args, **life_options)
    # Resolve the unchanged prefix labels with the actual birth sink before
    # passing their exact addresses to the new raw-hook dispatcher.
    prefix = creation.assemble(
        *args, **options, following_code_bytes=len(provisional),
        birth_callback=(life_labels['observe_birth'], life_base, len(provisional)))
    if len(prefix['code']) != prefix_bytes:
        raise ValueError('creation layout changed with lifecycle birth callback')
    bridge_base = life_base + len(provisional)
    bridge_args = (controller_address, registry_mutex_address, bridge_base)
    bridge_options = dict(
        callback=(life_labels['observe_retirement'], life_base, len(provisional)),
        fallback=(prefix['receipt_labels']['raw_call'],
                  prefix['receipt_labels']['raw_return'], code_base, prefix_bytes),
        extra_protected_data=((lifecycle_address, state_bytes), *extra))
    bridge_provisional, bridge_labels = retirement.assemble(
        *bridge_args, **bridge_options)
    tail_bytes = len(provisional) + len(bridge_provisional)
    actual_bytes = prefix_bytes + tail_bytes
    protected = (code_base, actual_bytes + following_code_bytes)
    if birth_commit_callback is not None:
        _, callback_start, callback_bytes = birth_commit_callback
        if (callback_start < code_base + actual_bytes
                or callback_start + callback_bytes > code_base + protected[1]):
            raise ValueError('birth commit callback must be in advertised following RX tail')
    core, final_life_labels = lifecycle.assemble(
        *life_args, **life_options, protected_code=protected)
    bridges, final_bridge_labels = retirement.assemble(
        *bridge_args, **bridge_options, protected_code=protected)
    if (len(core) != len(provisional) or final_life_labels != life_labels
            or len(bridges) != len(bridge_provisional)
            or final_bridge_labels != bridge_labels):
        raise ValueError('lifecycle layout changed with exact full RX protection')
    final_prefix = creation.assemble(
        *args, **options, following_code_bytes=tail_bytes + following_code_bytes,
        birth_callback=(life_labels['observe_birth'], life_base, len(core)))
    if (len(final_prefix['code']) != prefix_bytes
            or final_prefix['labels'] != prefix['labels']
            or final_prefix['protected_code_extent'] != protected):
        raise ValueError('creation prefix does not protect exact lifecycle RX')
    retirement_hooks = retirement.hook_words(bridge_labels)
    coherent_hooks = {**receipt.hook_words(final_prefix['receipt_labels']),
                      **final_prefix['release_hooks'], **retirement_hooks}
    return dict(
        final_prefix, code=final_prefix['code'] + core + bridges,
        lifecycle_labels=life_labels, retirement_labels=bridge_labels,
        lifecycle_code_bytes=len(core), retirement_code_bytes=len(bridges),
        lifecycle_prefix_code_bytes=prefix_bytes,
        lifecycle_memory_bytes=state_bytes, lifecycle_observation_only=True,
        retirement_hooks=retirement_hooks, coherent_hooks=coherent_hooks,
        protected_code_extent=protected,
        labels={**final_prefix['labels'],
                **{'lifecycle_' + name: address for name, address in life_labels.items()},
                **{'retirement_' + name: address for name, address in bridge_labels.items()}})
