#!/usr/bin/env python3
"""Reject-only age diagnostics for an already-owned renderer snapshot.

This is a HOST-ONLY annotation, not a new firmware stage or UI gate. The
existing strict decoder remains authoritative and its output/rejections stay
unchanged. Global known-boundary interference is NOT proof that this native
owner's contents changed. No evidence of interference means UNPROVEN, never
fresh, accepted, current, retained, coherent or authorized.
"""
import argparse
import json
from pathlib import Path

import decode_reveal_renderer_transport_stage as previous
import folderfollow_reveal_lineage_mips as lineage
import reveal_queue_birth_mips as birth
import reveal_renderer_transport_mips as renderer


FORMAT = 'request-age-rejection-v1'
REVISION_MAX = 0x7FFFFFFF
AUTHORITY_FLAGS = ('current_owner_proven', 'contents_current', 'coherent_capture',
                   'autoscroll_authorized', 'request_freshness_proven')
UNPROVEN_GATES = (
    'original-playback-and-ui-cause-unproved',
    'complete-native-writer-and-cancellation-coverage-unproved',
    'retained-native-owner-and-live-borrow-unproved',
    'coherent-capture-and-owned-ui-transaction-unproved',
)
LIMITATIONS = (
    'Reject-only global known-boundary evidence is not proof of changed contents for this particular native owner.',
    'A legitimate new request queued behind another renderer can be rejected by this conservative global counter.',
    'Known UI revision/scope samples are not proven to observe every playback publication; equal intervals cannot recover the original playback cause.',
    'No extra known crossing observed means unproven, not fresh or authorized; all UI authority stays false.',
    'Revision and packed-scope fields are separate loads, not an atomic snapshot or mutually convertible clocks.',
    'Producer RETURN may follow the consumer/renderer and is never a pre-render time edge.',
    'Renderer entry contributes one own known increment; arithmetic only locates extra negative evidence and does not relax prior literal equality.',
    'Final counter growth may be ordinary later worker/postfill/bind work and is not assigned to the pre-render interval.',
    'Unknown, full, synthetic, unassociated and incomplete histories remain unadmitted; empty output is not coverage.',
    'No native firmware bytes, payload capture policy, source hook, owner lifetime or active UI behavior is changed.',
)


def _denied(item):
    item.update({field: False for field in AUTHORITY_FLAGS})
    item['decision'] = 'deny'
    return item


def _sample(role, namespace, event):
    state = event['scope']
    return dict(role=role, namespace=namespace, id=event['seq'], revision=event['revision'],
                scope_state=state, scope_issued=state & 0xFFFF, scope_active=state >> 16)


def _ref(sample):
    return {key: sample[key] for key in ('role', 'namespace', 'id')}


def _assess_result(parent):
    """Annotate a STRICT previous result; this private helper never mutates it.

    Public input is exclusively raw owned bytes through decode(), not a caller-
    supplied result dictionary. Follow canonical event IDs, not mutable summary
    claims, native addresses, journal reservation clocks or current-name lookup.
    """
    births = {item['seq']: item for item in parent['queue_birth_observation']['events']}
    transported = {item['seq']: item for item in parent['queue_transport_observation']['events']}
    rendered = {item['seq']: item for item in parent['renderer_transport_observation']['events']}
    receipts = {item['id']: item for item in parent['receipts']}
    requests, associated_roots, associated_births, associated_outers = [], set(), set(), set()
    for event in rendered.values():
        if event['kind'] != renderer.RENDER:
            continue
        outer = rendered[event['parent']]
        callback = transported[event['transport']]
        helper = transported[callback['parent']]
        borrow = transported[helper['parent']]
        install = transported[borrow['parent']]
        enqueue = births[install['parent']]
        root_birth = births[enqueue['parent']]
        root = receipts[event['lineage']]
        associated_roots.add(root['id'])
        associated_births.add(root_birth['seq'])
        associated_outers.add(outer['seq'])
        path = [
            _sample('birth', 'LQBR', root_birth), _sample('enqueue', 'LQBR', enqueue),
            _sample('install', 'LQTR', install), _sample('borrow', 'LQTR', borrow),
            _sample('helper', 'LQTR', helper), _sample('callback', 'LQTR', callback),
            _sample('outer', 'LQRD', outer),
        ]
        late = _sample('early-renderer', 'LQRD', event)
        evidence, rejection_reasons = [], []
        known_conflict, source_conflict = False, False

        def reject(reason):
            if reason not in rejection_reasons:
                rejection_reasons.append(reason)

        def inspect_edge(before, after, phase, *, revisions=True):
            nonlocal known_conflict, source_conflict
            for field, kind in (('revision', 'revision-advance'), ('scope_issued', 'scope-ticket-advance')):
                if field == 'revision' and not revisions:
                    continue
                delta = after[field] - before[field]
                if delta > 0:
                    known_conflict = True
                    evidence.append(dict(kind=kind, phase=phase, before=_ref(before), after=_ref(after), delta=delta))
                    reject('known-' + kind + '-' + phase)
                elif delta < 0:
                    # Public strict decoding already rejects these regressions.
                    # Keep this private assessment fail-closed if misused.
                    source_conflict = True
                    evidence.append(dict(kind='unsupported-counter-order', counter=field,
                                         phase=phase, before=_ref(before), after=_ref(after)))
                    reject('unsupported-causal-counter-order')

        for before, after in zip(path, path[1:]):
            inspect_edge(before, after, 'before-outer')
        # There is no packed-scope sample at the original entry ticket. Compare
        # scope observations independently; NEVER synthesize entry scope=0.
        inspect_edge(path[-1], late, 'outer-to-renderer', revisions=False)
        entry, outer_revision = root['original_entry_revision'], outer['revision']
        expected_entry = outer_revision + 1 if outer_revision < REVISION_MAX else None
        extra_entry, early_advance = None, None
        if not entry:
            reject('renderer-entry-frontier-unavailable')
        elif expected_entry is None or entry < expected_entry:
            source_conflict = True
            reject('unsupported-renderer-entry-step')
            evidence.append(dict(kind='unsupported-entry-order', outer_revision=outer_revision,
                                 original_entry_revision=entry, expected_entry_revision=expected_entry))
        else:
            extra_entry = entry - expected_entry
            if extra_entry:
                known_conflict = True
                reject('extra-known-increment-before-renderer-entry')
                evidence.append(dict(kind='extra-entry-increment', phase='outer-to-entry',
                                     outer=outer['seq'], lineage=root['id'], delta=extra_entry))
        # A positive but source-inconsistent ticket is no better interval
        # origin than zero: its apparent delta may just be the normal own
        # entry increment. Refuse the order without inventing extra activity.
        if entry and expected_entry is not None and entry >= expected_entry:
            early_advance = event['revision'] - entry
            if early_advance > 0:
                known_conflict = True
                reject('known-revision-advance-during-early-renderer')
                evidence.append(dict(kind='revision-advance', phase='entry-to-early-renderer',
                                     lineage=root['id'], renderer=event['seq'], delta=early_advance))
            elif early_advance < 0:
                source_conflict = True
                early_advance = None
                reject('unsupported-renderer-entry-step')
        # Saturation is never masked back to zero or called an ordinary step.
        if expected_entry is None:
            reject('renderer-entry-positive-step-unavailable')
        samples = [*path, late]
        active = [sample for sample in samples if sample['scope_active']]
        for sample in active:
            evidence.append(dict(kind='known-scope-active', sample=_ref(sample),
                                 active=sample['scope_active'], issued=sample['scope_issued']))
        if active:
            reject('known-scope-active-sample')
        if not parent['native_scope']['scope_quiet']:
            reject('snapshot-known-scope-not-quiet')
        producer_returns = [item for item in births.values()
                            if item['kind'] == birth.RETURN and item['parent'] == enqueue['seq']]
        birth_events = [item for item in births.values() if item['origin'] == root_birth['seq']]
        complete_enqueue = ([item['kind'] for item in birth_events]
                            == [birth.BIRTH, birth.ENQUEUE_BEGIN, birth.RETURN])
        unique_return = producer_returns[0] if len(producer_returns) == 1 else None
        return_matches = unique_return is not None and unique_return['result'] == install['node']
        complete = complete_enqueue and return_matches
        if not complete:
            reject('producer-observation-incomplete')
        unproven = list(UNPROVEN_GATES)
        if not entry:
            unproven.append('original-renderer-entry-ticket-unknown')
        elif expected_entry is None or entry < expected_entry:
            unproven.append('original-renderer-entry-order-unsupported')
        requests.append(_denied(dict(
            lineage=root['id'], birth=root_birth['seq'], callback=callback['seq'],
            outer=outer['seq'], renderer=event['seq'],
            status='rejected' if rejection_reasons else 'unproven',
            known_boundary_conflict=known_conflict, source_order_conflict=source_conflict,
            observed_known_scope_active=bool(active),
            pre_outer_revision_advance=outer_revision - root_birth['revision'],
            expected_entry_revision=expected_entry, original_entry_revision=entry,
            extra_pre_entry_increments=extra_entry, early_renderer_revision_advance=early_advance,
            scope_ticket_advance=late['scope_issued'] - path[0]['scope_issued'],
            birth_revision=root_birth['revision'], outer_revision=outer_revision,
            renderer_revision=event['revision'], final_known_revision=parent['known_contents_revision'],
            later_revision_advance=parent['known_contents_revision'] - event['revision'],
            producer_return_observed=bool(producer_returns),
            producer_return_sequences=[item['seq'] for item in producer_returns],
            producer_return_samples=[_sample('producer-return-unordered-to-consumer', 'LQBR', item)
                                     for item in producer_returns],
            observed_enqueue_sequence_complete=complete_enqueue, append_return_matches_node=return_matches,
            renderer_root_associated=True, observation_complete=complete,
            rejection_reasons=rejection_reasons, unproven_reasons=unproven,
            samples=samples, evidence=evidence)))
    roots = [item['id'] for item in receipts.values() if item['kind'] in (lineage.RENDER, lineage.INITIAL)]
    return _denied(dict(
        format=FORMAT, source_format=parent['format'], mode='host-only-reject-only', requests=requests,
        rejected_count=sum(item['status'] == 'rejected' for item in requests),
        unproven_count=sum(item['status'] == 'unproven' for item in requests),
        known_boundary_conflict_count=sum(item['known_boundary_conflict'] for item in requests),
        unassociated_lineage_roots=[token for token in roots if token not in associated_roots],
        unassociated_births=[item['seq'] for item in births.values()
                             if item['kind'] == birth.BIRTH and item['seq'] not in associated_births],
        unassociated_outers=[item['seq'] for item in rendered.values()
                            if item['kind'] == renderer.OUTER and item['seq'] not in associated_outers],
        complete_request_coverage_proven=False, scope_quiet=parent['native_scope']['scope_quiet'],
        limitations=list(LIMITATIONS)))


def decode(data, *, capacity=1024, row_capacity=1024, operation_capacity=1024,
           scope_capacity=1024, birth_capacity=1024, transport_capacity=1024, renderer_capacity=1024):
    """Strictly decode raw owned bytes, then add a deny-only assessment.

    The source format, all prior structures/flags/reasons and snapshot layout
    remain unchanged. Result dictionaries are not accepted as public inputs.
    """
    result = previous.decode(data, capacity=capacity, row_capacity=row_capacity,
                             operation_capacity=operation_capacity, scope_capacity=scope_capacity,
                             birth_capacity=birth_capacity, transport_capacity=transport_capacity,
                             renderer_capacity=renderer_capacity)
    result['request_age_assessment'] = _assess_result(result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', type=Path)
    for name in previous.CAPACITY_NAMES:
        parser.add_argument('--' + name, type=int, default=1024)
    args = parser.parse_args(argv)
    try:
        result = decode(args.snapshot.read_bytes(), **{
            name.replace('-', '_'): getattr(args, name.replace('-', '_')) for name in previous.CAPACITY_NAMES})
    except (OSError, ValueError) as error:
        parser.exit(2, str(error) + '\n')
    print(json.dumps(result, ensure_ascii=True, indent=2))


if __name__ == '__main__':
    main()
