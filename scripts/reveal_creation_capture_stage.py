#!/usr/bin/env python3
"""Compose an emitted per-invocation historical creation capture, offline only.

The explicit registration wrapper calls the actual native registration body.
Its owned frame receives a pair from the issuer commit callback, not a Python
observation, latest table scan or raw-engine lookup. By default the record says
RELEASE_UNOBSERVED: native registry unlock still masks its actual raw result.
The explicit checked_registry_release option adds three local observers and
gates export on the actual same-invocation raw release result, not that mask.
This is not native explorer transport, a lease, release certificate or image.
"""

import reveal_paint_retirement_mips as owner
import reveal_registry_receipt_mips as receipt
import reveal_registry_owner_mips as issuer
import reveal_owner_carrier_mips as producer
import reveal_creation_capture_mips as capture


def assemble(receipt_address, binding_address, owner_address, controller_address,
             registry_mutex_address, paint_mutex_address, code_base, *,
             capacity=16, owner_capacity=16, ticket_limit=owner.MAX_TICKET,
             queue_capacity=64, checked_registry_release=False):
    """Return local bytes/labels; all old composers and default bytes stay old."""
    extents = [('receipt', receipt_address, receipt.memory_bytes(capacity)),
               ('bindings', binding_address, issuer.memory_bytes(capacity)),
               ('owners', owner_address, owner.memory_bytes(owner_capacity)),
               ('controller', controller_address, receipt.CONTROLLER_BYTES),
               ('registry mutex', registry_mutex_address, receipt.MUTEX_BYTES),
               ('paint mutex', paint_mutex_address, receipt.MUTEX_BYTES)]
    for name, start, size in extents:
        if (type(start) is not int or not 0 < start <= 0xFFFFFFFC
                or start % 4 or start + size > 0x100000000):
            raise ValueError(name + ' must have a nonwrapping aligned extent')
        if max(start, receipt.NATIVE_RX[0]) < min(start + size, receipt.NATIVE_RX[1]):
            raise ValueError(name + ' overlaps pinned native RX')
    for index, (name, start, size) in enumerate(extents):
        for other_name, other, other_size in extents[index + 1:]:
            if max(start, other) < min(start + size, other + other_size):
                raise ValueError(name + ' overlaps ' + other_name)
    if (type(code_base) is not int or not 0 < code_base < 0x10000000
            or code_base % 4):
        raise ValueError('code must be aligned in the native jump region')

    kernel, owner_labels = owner.assemble(
        owner_address, controller_address, code_base, capacity=queue_capacity,
        owner_capacity=owner_capacity, ticket_limit=ticket_limit,
        checked_mutex=True, expected_mutex_address=paint_mutex_address)
    capture_base = code_base + len(kernel)
    capture_args = (receipt_address, binding_address, owner_address,
                    controller_address, registry_mutex_address,
                    paint_mutex_address, capture_base)
    capture_options = dict(capacity=capacity, owner_capacity=owner_capacity,
                           ticket_limit=ticket_limit,
                           checked_registry_release=checked_registry_release)
    provisional, capture_labels = capture.assemble(*capture_args, **capture_options)
    issuer_base = capture_base + len(provisional)
    issue, issuer_labels = issuer.assemble(
        binding_address, owner_address, controller_address, registry_mutex_address,
        paint_mutex_address, issuer_base, owner_labels['open_owner'],
        capacity=capacity, owner_capacity=owner_capacity, ticket_limit=ticket_limit,
        commit_callback=(capture_labels['sink'], capture_base, len(provisional)))
    receipt_base = issuer_base + len(issue)
    observe, receipt_labels = receipt.assemble(
        receipt_address, controller_address, registry_mutex_address, receipt_base,
        capacity=capacity, publication_callback=(issuer_labels['issue'], issuer_base,
                                                 len(issue)))
    prefix_bytes = len(kernel) + len(provisional) + len(issue) + len(observe)
    adapter, adapter_labels = producer.assemble(
        binding_address, owner_address, controller_address, registry_mutex_address,
        paint_mutex_address, code_base + prefix_bytes, owner_labels['publish'],
        capacity=capacity, owner_capacity=owner_capacity, ticket_limit=ticket_limit,
        protected_prefix=(code_base, prefix_bytes),
        receipt_extent=(receipt_address, receipt.memory_bytes(capacity)))
    total_bytes = prefix_bytes + len(adapter)
    # A fixed-width RX guard changes only its literals. Reassemble with the
    # exact complete code extent, not just this fragment or a bare entrypoint.
    captured, final_labels = capture.assemble(
        *capture_args, **capture_options, protected_code=(code_base, total_bytes))
    if len(captured) != len(provisional) or final_labels != capture_labels:
        raise ValueError('capture layout changed after full RX protection')
    code = kernel + captured + issue + observe + adapter
    end = code_base + len(code)
    if end > 0x10000000:
        raise ValueError('composed capture code leaves the native jump region')
    for name, start, size in extents:
        if max(code_base, start) < min(end, start + size):
            raise ValueError('composed capture code overlaps ' + name)
    if max(code_base, receipt.NATIVE_RX[0]) < min(end, receipt.NATIVE_RX[1]):
        raise ValueError('composed capture code overlaps pinned native RX')
    groups = dict(owner=owner_labels, capture=capture_labels, issue=issuer_labels,
                  receipt=receipt_labels, carrier=adapter_labels)
    return dict(
        code=code, code_base=code_base,
        labels={prefix + '_' + key: value for prefix, labels in groups.items()
                for key, value in labels.items()},
        owner_labels=owner_labels, capture_labels=capture_labels,
        issuer_labels=issuer_labels, receipt_labels=receipt_labels,
        adapter_labels=adapter_labels,
        kernel_code_bytes=len(kernel), capture_code_bytes=len(captured),
        issuer_code_bytes=len(issue), receipt_code_bytes=len(observe),
        adapter_code_bytes=len(adapter), creation_code_bytes=prefix_bytes,
        registry_release_checked=checked_registry_release,
        release_hooks=(capture.hook_words(capture_labels)
                       if checked_registry_release else {}),
        owner_memory_bytes=owner.memory_bytes(owner_capacity),
        binding_memory_bytes=issuer.memory_bytes(capacity),
        receipt_memory_bytes=receipt.memory_bytes(capacity),
        protected_code_extent=(code_base, len(code)))
