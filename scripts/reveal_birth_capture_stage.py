#!/usr/bin/env python3
"""Compose an owned historical birth-token handoff, not native lifetime.

The token comes from the exact emitted lifecycle birth commit, never a latest
table search. An explicit wrapper exports a separate BCAP only after checked
registration return with raw R release zero. No queue/carrier format, native
constructor/explorer, cleanup, image or player state is changed.
"""

import reveal_registry_lifecycle_stage as lifecycle_stage
import reveal_registry_lifecycle_mips as lifecycle
import reveal_registry_receipt_mips as receipt
import reveal_registry_owner_mips as bindings
import reveal_paint_retirement_mips as owners
import reveal_birth_capture_mips as capture


def assemble(receipt_address, binding_address, owner_address, controller_address,
             registry_mutex_address, paint_mutex_address, code_base,
             lifecycle_address, *, capacity=16, lifecycle_capacity=16,
             owner_capacity=16, ticket_limit=owners.MAX_TICKET, queue_capacity=64,
             following_code_bytes=0, extra_protected_data=()):
    """Return guarded local code, explicit entry labels and coherent fixture hooks.

    The commit callback receives an owned per-invocation snapshot and the actual
    newly minted token. Existing logical owner/paint issuance is independent:
    BCAP grants no P health, live incarnation, native reference or UI authority.
    Zero/empty optional following RX and fixed-data exclusions preserve all
    preceding bytes/labels. Following bytes are protected but not appended.
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
    args = (receipt_address, binding_address, owner_address, controller_address,
            registry_mutex_address, paint_mutex_address, code_base, lifecycle_address)
    options = dict(capacity=capacity, lifecycle_capacity=lifecycle_capacity,
                   owner_capacity=owner_capacity, ticket_limit=ticket_limit,
                   queue_capacity=queue_capacity,
                   extra_protected_data=extra_protected_data)
    initial = lifecycle_stage.assemble(*args, **options)
    if initial['registry_release_checked'] is not True:
        raise ValueError('birth capture requires checked registry release')
    initial_end = code_base + len(initial['code'])
    extra = ((receipt_address, receipt.memory_bytes(capacity)),
             (binding_address, bindings.memory_bytes(capacity)),
             (owner_address, owners.memory_bytes(owner_capacity)),
             (paint_mutex_address, receipt.MUTEX_BYTES), *extra_protected_data)
    # Resolve the opt-in callback's instruction count without executing or
    # exporting a provisional callback/composition. Its temporary RX word is
    # beyond the existing stage and hence outside this lifecycle fragment.
    probe, _ = lifecycle.assemble(
        lifecycle_address, controller_address, registry_mutex_address,
        initial['lifecycle_labels']['observe_birth'],
        capacity=lifecycle_capacity, extra_protected_data=extra,
        birth_commit_callback=(initial_end, initial_end, 4))
    prefix_bytes = (len(initial['code']) + len(probe)
                    - initial['lifecycle_code_bytes'])
    capture_base = code_base + prefix_bytes
    capture_args = (receipt_address, binding_address, owner_address,
                    controller_address, registry_mutex_address,
                    paint_mutex_address, lifecycle_address, capture_base,
                    initial['capture_labels']['register'],
                    initial['capture_labels']['native_return'])
    capture_options = dict(capacity=capacity, lifecycle_capacity=lifecycle_capacity,
                           owner_capacity=owner_capacity, ticket_limit=ticket_limit,
                           extra_protected_data=extra_protected_data)
    provisional, labels = capture.assemble(*capture_args, **capture_options)
    protected = (code_base, prefix_bytes + len(provisional) + following_code_bytes)
    prefix = lifecycle_stage.assemble(
        *args, **options,
        following_code_bytes=len(provisional) + following_code_bytes,
        birth_commit_callback=(labels['birth_sink'], capture_base, len(provisional)))
    if (len(prefix['code']) != prefix_bytes
            or prefix['registry_release_checked'] is not True
            or prefix['capture_labels'] != initial['capture_labels']
            or prefix['protected_code_extent'] != protected):
        raise ValueError('lifecycle layout changed with exact birth handoff tail')
    emitted, final_labels = capture.assemble(
        *capture_args, **capture_options, protected_code=protected)
    if len(emitted) != len(provisional) or final_labels != labels:
        raise ValueError('birth capture layout changed with full RX protection')
    return dict(
        prefix, code=prefix['code'] + emitted,
        birth_capture_labels=labels, birth_capture_code_bytes=len(emitted),
        birth_capture_prefix_code_bytes=prefix_bytes,
        birth_capture_output_bytes=capture.OUTPUT_BYTES,
        birth_capture_historical_only=True,
        labels={**prefix['labels'],
                **{'birth_capture_' + name: address for name, address in labels.items()}},
        protected_code_extent=protected)
