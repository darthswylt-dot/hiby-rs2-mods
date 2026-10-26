#!/usr/bin/env python3
"""Compose standalone offline receipt/issuance code, never an ELF/image stage.

No file is read/written, no installer is called and no device is accessed.
The result is for local instruction fixtures only. Generation bindings are
historical scalar accounting, not native release/lifetime or producer authority.
The four receipt redirects, stable initialized distinct mutexes, real import
semantics, outer13C guard and retained disjoint stack/storage remain premises.
"""

import reveal_paint_retirement_mips as owner
import reveal_registry_receipt_mips as receipt
import reveal_registry_owner_mips as issuer


def assemble(receipt_address, binding_address, owner_address, controller_address,
             registry_mutex_address, paint_mutex_address, code_base, *,
             capacity=16, owner_capacity=16, ticket_limit=owner.MAX_TICKET,
             queue_capacity=64):
    """Return contiguous kernel+issuer+receipt bytes/labels for a local fixture."""
    extents = [('receipt', receipt_address, receipt.memory_bytes(capacity)),
               ('binding', binding_address, issuer.memory_bytes(capacity)),
               ('owner', owner_address, owner.memory_bytes(owner_capacity)),
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

    kernel_code, owner_labels = owner.assemble(
        owner_address, controller_address, code_base, owner_capacity=owner_capacity,
        ticket_limit=ticket_limit, capacity=queue_capacity, checked_mutex=True,
        expected_mutex_address=paint_mutex_address)
    issuer_base = code_base + len(kernel_code)
    issuer_code, issuer_labels = issuer.assemble(
        binding_address, owner_address, controller_address, registry_mutex_address,
        paint_mutex_address, issuer_base, owner_labels['open_owner'],
        capacity=capacity, owner_capacity=owner_capacity, ticket_limit=ticket_limit)
    receipt_base = issuer_base + len(issuer_code)
    receipt_code, receipt_labels = receipt.assemble(
        receipt_address, controller_address, registry_mutex_address, receipt_base,
        capacity=capacity, publication_callback=(issuer_labels['issue'], issuer_base,
                                                 len(issuer_code)))
    code = kernel_code + issuer_code + receipt_code
    end = code_base + len(code)
    if end > 0x10000000:
        raise ValueError('composed code leaves the native jump region')
    for name, start, size in extents:
        if max(code_base, start) < min(end, start + size):
            raise ValueError('composed code overlaps ' + name)
    if max(code_base, receipt.NATIVE_RX[0]) < min(end, receipt.NATIVE_RX[1]):
        raise ValueError('composed code overlaps pinned native RX')
    labels = {**{'owner_' + key: value for key, value in owner_labels.items()},
              **{'issue_' + key: value for key, value in issuer_labels.items()},
              **{'receipt_' + key: value for key, value in receipt_labels.items()}}
    return dict(code=code, labels=labels, owner_labels=owner_labels,
                issuer_labels=issuer_labels, receipt_labels=receipt_labels,
                owner_memory_bytes=owner.memory_bytes(owner_capacity),
                binding_memory_bytes=issuer.memory_bytes(capacity),
                receipt_memory_bytes=receipt.memory_bytes(capacity),
                kernel_code_bytes=len(kernel_code), issuer_code_bytes=len(issuer_code),
                receipt_code_bytes=len(receipt_code), code_base=code_base)
