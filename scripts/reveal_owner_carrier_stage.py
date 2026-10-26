#!/usr/bin/env python3
"""Compose an explicit captured-carrier producer fixture, not native transport.

The existing native producer ABI/callers, object layouts and image builders are
unchanged. The caller must capture (binding sequence, owner) at creation and
retain that exact pair with a coherent owned36 payload. A historical table or
raw engine/name/node lookup cannot manufacture that capture. No file, device,
native free or UI operation is performed here.
"""

import reveal_registry_owner_stage as creation
import reveal_registry_receipt_mips as receipt
import reveal_registry_owner_mips as bindings
import reveal_paint_retirement_mips as owner
import reveal_owner_carrier_mips as carrier


def assemble(receipt_address, binding_address, owner_address, controller_address,
             registry_mutex_address, paint_mutex_address, code_base, *,
             capacity=16, owner_capacity=16, ticket_limit=owner.MAX_TICKET,
             queue_capacity=64):
    """Return in-memory creation code plus a separate explicit producer entry."""
    result = creation.assemble(
        receipt_address, binding_address, owner_address, controller_address,
        registry_mutex_address, paint_mutex_address, code_base, capacity=capacity,
        owner_capacity=owner_capacity, ticket_limit=ticket_limit,
        queue_capacity=queue_capacity)
    previous_code = result['code']
    adapter_base = code_base + len(previous_code)
    adapter_code, adapter_labels = carrier.assemble(
        binding_address, owner_address, controller_address, registry_mutex_address,
        paint_mutex_address, adapter_base, result['owner_labels']['publish'],
        capacity=capacity, owner_capacity=owner_capacity, ticket_limit=ticket_limit,
        protected_prefix=(code_base, len(previous_code)),
        receipt_extent=(receipt_address, receipt.memory_bytes(capacity)))
    code = previous_code + adapter_code
    end = code_base + len(code)
    if end > 0x10000000:
        raise ValueError('composed carrier code leaves native jump region')
    extents = [('receipt', receipt_address, receipt.memory_bytes(capacity)),
               ('bindings', binding_address, bindings.memory_bytes(capacity)),
               ('owners', owner_address, owner.memory_bytes(owner_capacity)),
               ('controller', controller_address, receipt.CONTROLLER_BYTES),
               ('registry mutex', registry_mutex_address, receipt.MUTEX_BYTES),
               ('paint mutex', paint_mutex_address, receipt.MUTEX_BYTES)]
    for name, start, size in extents:
        if max(code_base, start) < min(end, start + size):
            raise ValueError('composed carrier code overlaps ' + name)
    if max(code_base, receipt.NATIVE_RX[0]) < min(end, receipt.NATIVE_RX[1]):
        raise ValueError('composed carrier code overlaps pinned native RX')
    return dict(result, code=code, adapter_labels=adapter_labels,
                adapter_code_bytes=len(adapter_code), creation_code_bytes=len(previous_code),
                labels={**result['labels'], **{'carrier_' + key: value
                                               for key, value in adapter_labels.items()}})
