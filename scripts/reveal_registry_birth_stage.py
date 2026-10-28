#!/usr/bin/env python3
"""Compose independent historical birth observations, never native liveness.

Actual native4389E0 publishes before either observer. The early callback
records its owned event even when the older receipt/binding/owner quota denies
issuance. No tombstone, live-identity query, native cleanup hook, lifetime lease,
image builder or device operation is supplied. Failed native raw acquisition
can still publish without observation; this is not complete birth coverage.
"""

import reveal_creation_capture_stage as creation
import reveal_registry_receipt_mips as receipt
import reveal_registry_owner_mips as bindings
import reveal_paint_retirement_mips as owners
import reveal_registry_birth_mips as birth


def assemble(receipt_address, binding_address, owner_address, controller_address,
             registry_mutex_address, paint_mutex_address, code_base,
             birth_address, *, capacity=16, birth_capacity=16,
             owner_capacity=16, ticket_limit=owners.MAX_TICKET, queue_capacity=64):
    """Return pure emitted code and fixture labels, with exact outer RX guards.

    This separate branch composes the explicit registration capture, not the
    native constructor/explorer or later cleanup-intent/registry comparison.
    The new state is excluded by the outer capture and birth callback guards;
    inherited internal-entry/heap/transitive-stack nonalias premises still
    apply. It does not extend every preceding adapter or native method guard.
    """
    birth_bytes = birth.memory_bytes(birth_capacity)
    args = (receipt_address, binding_address, owner_address, controller_address,
            registry_mutex_address, paint_mutex_address, code_base)
    options = dict(capacity=capacity, owner_capacity=owner_capacity,
                   ticket_limit=ticket_limit, queue_capacity=queue_capacity,
                   checked_registry_release=True,
                   extra_protected_data=((birth_address, birth_bytes),))
    initial = creation.assemble(*args, **options)
    # Resolve only the optional receipt block's instruction count first. The
    # placeholder is beyond the existing prefix, outside the receipt fragment;
    # no provisional composition or callback is executed or exported.
    initial_end = code_base + len(initial['code'])
    issue_base = initial['issuer_labels']['issue']
    probe, _ = receipt.assemble(
        receipt_address, controller_address, registry_mutex_address,
        initial['receipt_labels']['begin'], capacity=capacity,
        publication_callback=(issue_base, issue_base, initial['issuer_code_bytes']),
        birth_callback=(initial_end, initial_end, 4))
    prefix_bytes = (len(initial['code']) + len(probe)
                    - initial['receipt_code_bytes'])
    birth_base = code_base + prefix_bytes
    birth_options = dict(
        capacity=birth_capacity,
        extra_protected_data=(
            (receipt_address, receipt.memory_bytes(capacity)),
            (binding_address, bindings.memory_bytes(capacity)),
            (owner_address, owners.memory_bytes(owner_capacity)),
            (paint_mutex_address, receipt.MUTEX_BYTES)))
    birth_args = (birth_address, controller_address, registry_mutex_address,
                  birth_base)
    provisional, labels = birth.assemble(*birth_args, **birth_options)
    protected = (code_base, prefix_bytes + len(provisional))
    observed, final_labels = birth.assemble(
        *birth_args, **birth_options, protected_code=protected)
    if len(observed) != len(provisional) or final_labels != labels:
        raise ValueError('birth layout changed while protecting full RX')
    prefix = creation.assemble(
        *args, **options, following_code_bytes=len(observed),
        birth_callback=(labels['observe'], birth_base, len(observed)))
    if len(prefix['code']) != prefix_bytes:
        raise ValueError('creation layout changed while adding birth callback')
    if prefix['protected_code_extent'] != protected:
        raise ValueError('creation prefix does not guard full birth RX')
    return dict(
        prefix, code=prefix['code'] + observed,
        birth_labels=labels, birth_code_bytes=len(observed),
        birth_memory_bytes=birth_bytes, birth_history_only=True,
        birth_prefix_code_bytes=prefix_bytes,
        labels={**prefix['labels'],
                **{'birth_' + name: address for name, address in labels.items()}},
        protected_code_extent=protected)
