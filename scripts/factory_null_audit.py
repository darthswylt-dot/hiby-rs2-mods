#!/usr/bin/env python3
"""Verify caller census and instruction evidence for three manual NULL audits.

This read-only report checks that no encoded direct caller is omitted and that
recorded source words match the pinned image. Classifications are manual
analysis, not an automatically proved whole-program NULL policy. Computed
callers, imports, dynamic object lifetimes and arbitrary source changes remain
outside that evidence. No runtime gate, firmware or device operation is added.
"""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import struct

from mips_static_trace import Elf32


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'artifacts/import-20261001/hiby_player_02fd.bin'
SOURCE_SHA256 = '02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87'
SOURCE_BYTES = 7133528
FACTORIES = {0x47D180: 51, 0x47D960: 157, 0x47DCE0: 21}
CLASSES = frozenset(('null_dereference', 'discarded', 'propagated', 'null_guarded', 'unresolved'))
MANIFESTS = tuple(ROOT / f'notes/folderfollow-factory-{suffix}-null-audit.json'
                  for suffix in ('d180', 'd960', 'dce0'))
CALLBACK_BINDINGS = ROOT / 'notes/folderfollow-factory-callback-binding-audit.json'
CALLBACK_SLOTS = (0x24, 0x274, 0x2A4)
RESOLVED_IMPORT_ARCHIVE = ROOT / 'artifacts/rs2_14_import_libraries_20261106'


def literal_callback_store_inventory(image):
    """Encoded word matches in file-backed PF_X, not all runtime writes.

    Partial-store matches have literal immediates within the four-byte slot.
    Shifted bases, stores starting earlier, copies, imports and reachability
    are outside this syntactic inventory. Non-SP does not imply heap/object.
    """
    matches = {slot: {'sw': [], 'partial': []} for slot in CALLBACK_SLOTS}
    for first, last in image.executable_ranges():
        for pc in range(first, last, 4):
            word = image.word(pc)
            op, immediate = word >> 26, word & 0xFFFF
            if op not in (40, 41, 42, 43, 46):
                continue
            for slot in CALLBACK_SLOTS:
                if op == 43 and immediate == slot:
                    matches[slot]['sw'].append((pc, word))
                elif op != 43 and slot <= immediate < slot + 4:
                    matches[slot]['partial'].append((pc, word))
    result = {}
    for slot, kinds in matches.items():
        row = {}
        for name, words in kinds.items():
            row[name + '_count'] = len(words)
            row['non_sp_' + name + '_count'] = sum((word >> 21) & 31 != 29
                                                     for _, word in words)
            row[name + '_pc_word_sha256'] = hashlib.sha256(
                b''.join(struct.pack('<II', pc, word) for pc, word in words)).hexdigest()
        result[f'{slot:#x}'] = row
    return result


def verify_callback_bindings(document, image, factory_documents, inventory=None):
    """Pin selected assignments and consumer coverage, never runtime binding."""
    if type(document) is not dict or document.get('source_sha256') != SOURCE_SHA256:
        raise ValueError('callback binding audit has no matching source hash')
    for flag in ('runtime_binding_proven', 'closed_write_set_proven',
                 'universal_refusal_safety_proven', 'classification_promoted'):
        if document.get(flag) is not False:
            raise ValueError('source binding audit cannot promote runtime safety')
    lifecycle = document.get('publication_and_lifetime')
    if (type(lifecycle) is not dict or lifecycle.get('execution_ordering_proven') is not False
            or lifecycle.get('concurrent_reentry_feasibility_proven') is not False):
        raise ValueError('source publication order does not prove runtime scheduling')
    inventory = literal_callback_store_inventory(image) if inventory is None else inventory
    if document.get('literal_store_inventory') != inventory:
        raise ValueError('literal callback store inventory changed')
    expected = {hex_word(row['callsite']): hex_word(row['unresolved_boundary']['pc'])
                for factory in factory_documents for row in factory['callers']
                if row['classification'] == 'unresolved'
                and row['unresolved_boundary']['kind'] == 'computed_callback'}
    rows = document.get('consumer_frontiers')
    if type(rows) is not list:
        raise ValueError('callback consumer frontiers must be a list')
    seen, frontiers = {}, set()
    for row in rows:
        if type(row) is not dict:
            raise ValueError('callback frontier requires a source record')
        slot, load, call = (hex_word(row.get(key)) for key in ('slot', 'load_pc', 'call_pc'))
        if slot not in CALLBACK_SLOTS or call in frontiers:
            raise ValueError('unknown or duplicate callback frontier')
        frontiers.add(call)
        word = image.word(load)
        if (word >> 26 != 35 or (word >> 21) & 31 != 4
                or (word >> 16) & 31 != 25 or word & 0xFFFF != slot
                or image.word(call) != 0x0320F809 or not load < call):
            raise ValueError('callback frontier must load its slot and JALR T9')
        evidence = _binding_evidence_sites(row)
        if not set(range(load, call + 8, 4)) <= evidence:
            raise ValueError('callback frontier requires its full local load/call/delay evidence')
        consumers = row.get('consumers')
        if type(consumers) is not list or not consumers:
            raise ValueError('callback frontier requires its consumers')
        for consumer in consumers:
            site = hex_word(consumer)
            if site in seen or expected.get(site) != call:
                raise ValueError('callback consumer invented, duplicated or moved')
            seen[site] = call
    if seen != expected or not expected:
        raise ValueError('callback binding audit omits computed consumers')
    candidates = document.get('selected_assignment_candidates')
    if type(candidates) is not list or not candidates:
        raise ValueError('callback binding audit requires selected source assignments')
    writers, behaviors = set(), Counter()
    for row in candidates:
        if type(row) is not dict:
            raise ValueError('selected callback assignment requires a source record')
        start, store, slot, target = (hex_word(row.get(key))
                                      for key in ('materialization_pc', 'store_pc', 'slot', 'target'))
        behavior = row.get('target_behavior')
        if (slot not in CALLBACK_SLOTS or store in writers or start % 4 or store % 4
                or not 8 <= store - start <= 0x40
                or behavior not in ('native_value_kill', 'opaque_before_kill')
                or type(row.get('notes')) is not str or not row['notes'].strip()):
            raise ValueError('invalid or duplicate selected callback assignment')
        writers.add(store)
        high, low, assignment = image.word(start), image.word(start + 4), image.word(store)
        signed = low & 0xFFFF
        signed -= 0x10000 if signed & 0x8000 else 0
        materialized_target = (((high & 0xFFFF) << 16) + signed) & 0xFFFFFFFF
        if (high & 0xFFFF0000 != 0x3C020000 or low & 0xFFFF0000 != 0x24420000
                or materialized_target != target
                or assignment >> 26 != 43 or (assignment >> 16) & 31 != 2
                or (assignment >> 21) & 31 == 29 or assignment & 0xFFFF != slot
                or any(image.word(pc) >> 26 not in (43, 57)
                       for pc in range(start + 8, store, 4))
                or not any(first <= target < last for first, last in image.executable_ranges())):
            raise ValueError('selected callback assignment is not the recorded native constant')
        evidence = _binding_evidence_sites(row)
        if not (set(range(start, store + 4, 4)) | {target}) <= evidence:
            raise ValueError('selected assignment requires all materialization and target words')
        behaviors[behavior] += 1
    evidence = list(_evidence(document))
    for pc, word in evidence:
        if pc % 4 or image.word(pc) != word:
            raise ValueError(f'callback binding evidence changed at {pc:#x}')
    return dict(computed_consumers=len(seen), local_frontiers=len(frontiers),
                selected_assignment_candidates=len(candidates),
                target_behaviors=dict(behaviors), evidence_words_verified=len(evidence),
                literal_store_inventory=inventory, runtime_binding_proven=False,
                closed_write_set_proven=False, universal_refusal_safety_proven=False,
                classification_promoted=False)


def _binding_evidence_sites(row):
    records = row.get('evidence')
    if (type(records) is not list or not records
            or any(type(record) is not dict or not {'pc', 'word'} <= record.keys()
                   for record in records)):
        raise ValueError('callback record requires explicit instruction evidence')
    return {hex_word(record['pc']) for record in records}


def hex_word(value):
    if (type(value) is not str or not re.fullmatch(r'0x[0-9a-fA-F]{1,8}', value)):
        raise ValueError('expected a 32-bit hexadecimal string')
    return int(value, 16)


def source_image(path=SOURCE):
    image = Elf32(Path(path))
    if (len(image.data) != SOURCE_BYTES
            or hashlib.sha256(image.data).hexdigest() != SOURCE_SHA256):
        raise ValueError('NULL audit requires the preserved 02fd source image')
    return image


def direct_callers(image):
    result = {factory: set() for factory in FACTORIES}
    for first, last in image.executable_ranges():
        for pc in range(first, last, 4):
            word = image.word(pc)
            if word >> 26 not in (2, 3):
                continue
            target = ((pc + 4) & 0xF0000000) | ((word & 0x3FFFFFF) << 2)
            if target in result:
                result[target].add(pc)
    if any(len(result[factory]) != count for factory, count in FACTORIES.items()):
        raise ValueError('encoded caller census changed')
    return result


def _evidence(value):
    if isinstance(value, dict):
        if 'pc' in value and 'word' in value:
            yield hex_word(value['pc']), hex_word(value['word'])
        for child in value.values():
            yield from _evidence(child)
    elif isinstance(value, list):
        for child in value:
            yield from _evidence(child)


def verify_manifest(document, image, census):
    if type(document) is not dict or document.get('source_sha256') != SOURCE_SHA256:
        raise ValueError('manifest has no matching source hash')
    factory = hex_word(document.get('factory'))
    if factory not in FACTORIES:
        raise ValueError('unknown factory in NULL audit')
    rows = document.get('callers')
    if type(rows) is not list:
        raise ValueError('caller records must be a list')
    sites, counts = [], Counter()
    for row in rows:
        if (type(row) is not dict or type(row.get('classification')) is not str
                or row['classification'] not in CLASSES):
            raise ValueError('unknown caller classification')
        site = hex_word(row.get('callsite'))
        sites.append(site)
        counts[row['classification']] += 1
        if type(row.get('notes')) is not str or not row['notes'].strip():
            raise ValueError('caller classification requires its analysis notes')
        if type(row.get('evidence')) is not list or len(row['evidence']) < 2:
            raise ValueError('caller requires concrete instruction evidence')
        evidence_sites = set()
        for item in row['evidence']:
            if type(item) is not dict or not {'pc', 'word'} <= item.keys():
                raise ValueError('caller evidence requires explicit PC/word records')
            evidence_sites.add(hex_word(item['pc']))
            hex_word(item['word'])
        if len(evidence_sites) < 2:
            raise ValueError('caller requires distinct instruction evidence')
        if not {site, site + 4} <= evidence_sites:
            raise ValueError('caller evidence must include its call and delay slot')
        if row['classification'] == 'null_guarded':
            if (row.get('null_guard_observed') is not True
                    or row.get('null_path_locally_closed') is not True):
                raise ValueError('NULL-guarded classification requires explicit local closure')
            guard = hex_word(row.get('null_guard_pc'))
            continuation = hex_word(row.get('null_continuation'))
            branch = image.word(guard)
            op, rs, rt = branch >> 26, (branch >> 21) & 31, (branch >> 16) & 31
            if op not in (4, 5) or {rs, rt} != {0, 2}:
                raise ValueError('NULL guard must compare V0 with zero')
            offset = branch & 0xFFFF
            offset -= 0x10000 if offset & 0x8000 else 0
            expected = guard + 4 + offset * 4 if op == 4 else guard + 8
            if (continuation != expected
                    or not {guard, guard + 4, continuation} <= evidence_sites):
                raise ValueError('NULL continuation must match the actual branch and evidence')
        if row['classification'] == 'unresolved':
            boundary = row.get('unresolved_boundary')
            if (type(boundary) is not dict
                    or boundary.get('kind') not in ('import', 'computed_callback')):
                raise ValueError('unresolved caller requires its concrete indirect frontier')
            frontier = hex_word(boundary.get('pc'))
            instruction = hex_word(boundary.get('word'))
            if (instruction != image.word(frontier) or instruction >> 26 != 0
                    or instruction & 63 not in (8, 9)
                    or (instruction >> 21) & 31 != 25
                    or not {frontier, frontier + 4} <= evidence_sites):
                raise ValueError('unresolved frontier must pin its JR/JALR T9 and delay')
    if len(set(sites)) != len(sites) or set(sites) != census[factory]:
        raise ValueError('manifest omits, duplicates or invents encoded callers')
    evidence = list(_evidence(document))
    for pc, word in evidence:
        if pc % 4 or image.word(pc) != word:
            raise ValueError(f'NULL audit instruction evidence changed at {pc:#x}')
    return dict(factory=f'{factory:#x}', encoded_direct_callers=len(sites),
                classifications={name: counts[name] for name in sorted(CLASSES)},
                evidence_words_verified=len(evidence),
                all_encoded_callers_listed=True, universal_refusal_safety_proven=False,
                runtime_guard_added=False)


def report():
    image = source_image()
    census = direct_callers(image)
    documents = [json.loads(path.read_text(encoding='utf-8')) for path in MANIFESTS]
    results = [verify_manifest(document, image, census) for document in documents]
    if {item['factory'] for item in results} != {f'{pc:#x}' for pc in FACTORIES}:
        raise ValueError('expected exactly the three remaining factory audits')
    return dict(source_sha256=SOURCE_SHA256, factories=results,
                total_encoded_callers=sum(item['encoded_direct_callers'] for item in results),
                classification_method='manual source review with checked word evidence',
                callback_binding_audit=verify_callback_bindings(
                    json.loads(CALLBACK_BINDINGS.read_text(encoding='utf-8')), image, documents),
                universal_refusal_safety_proven=False, runtime_guards_added=False)


def verify_resolved_imports(document, archive=RESOLVED_IMPORT_ARCHIVE):
    """Match the observed bindings to captured library bytes and audited prefixes."""
    capture = document.get('resolved_import_follow_up', {})
    for flag in ('lazy_resolution_proven', 'mutex_progress_proven',
                 'universal_refusal_safety_proven'):
        if capture.get(flag) is not False:
            raise ValueError('the observed import audit requires its explicit limits')
    known = {0xA5BC68: ('memset', 'libc-2.16.so', 0xA6FB18),
             0xA5B968: ('pthread_mutex_lock', 'libpthread-2.16.so', 0xA6FA58)}
    expected = {hex_word(row['callsite']): hex_word(row['unresolved_boundary']['pc'])
                for row in document['callers'] if row['classification'] == 'unresolved'
                and row['unresolved_boundary']['kind'] == 'import'}
    seen, checked = {}, []
    libraries = capture.get('libraries')
    if type(libraries) is not list or len(libraries) != len(known):
        raise ValueError('expected both captured imports')
    for record in libraries:
        frontier = hex_word(record.get('frontier'))
        slot = hex_word(record.get('got_slot'))
        if (known.get(frontier) != (record.get('symbol'), record.get('file'), slot)
                or record.get('version') != 'GLIBC_2.0'):
            raise ValueError('unexpected captured import identity')
        path = Path(archive) / record['file']
        if not path.is_file():
            raise ValueError(f'missing captured library {path}')
        library = Elf32(path)
        if (len(library.data) != record.get('bytes')
                or hashlib.sha256(library.data).hexdigest() != record.get('sha256')
                or library.endian != '<' or library.u16(0x10) != 3 or library.u16(0x12) != 8):
            raise ValueError(f'captured library bytes do not match {path.name}')
        entry, overwrite, base, target = (hex_word(record.get(key)) for key in
                                         ('export', 'first_overwrite', 'rx_mapping_start',
                                          'observed_target'))
        symbol = hex_word(record.get('dynamic_symbol_entry'))
        version = hex_word(record.get('version_entry'))
        attributes = library.word(symbol + 12)
        if (library.word(symbol + 4) != entry or attributes & 0xF != 2
                or attributes >> 16 == 0 or library.u16(library.va_to_off(version)) != 2):
            raise ValueError('captured dynamic symbol entry changed')
        if (base + entry != target or entry % 4 or overwrite % 4
                or not 0 <= overwrite - entry <= 0x40
                or not any(va == offset == 0 and flags & 1 and overwrite + 4 <= size
                           for va, offset, size, _, flags in library.loads)):
            raise ValueError('observed target does not match the captured RX mapping')
        prefix = record.get('prefix', [])
        offsets = [hex_word(item.get('offset')) for item in prefix]
        if offsets != list(range(entry, overwrite + 4, 4)) or any(
                library.word(offset) != hex_word(item.get('word'))
                for offset, item in zip(offsets, prefix)):
            raise ValueError('audited library prefix changed or is incomplete')
        sites = [hex_word(site) for site in record.get('direct_sites', [])]
        for site in sites:
            if site in seen or expected.get(site) != frontier:
                raise ValueError('direct import caller duplicated, invented or moved')
            seen[site] = frontier
        checked.append(dict(symbol=record['symbol'], observed_target=f'{target:#x}',
                            first_overwrite=f'{overwrite:#x}', direct_sites=len(sites)))
    if seen != expected or len(seen) != 18:
        raise ValueError('resolved audit must cover all 18 direct import sites')
    completion = [hex_word(site) for site in capture.get('completion_sites', [])]
    known_completion = {hex_word(site) for group in document['outer_consumer_follow_up']['groups']
                        if group['upper_outcome'] == 'live_at_memset_import'
                        for site in group['sites']}
    if len(completion) != 5 or set(completion) != known_completion:
        raise ValueError('resolved audit must match the five known completion paths')
    return dict(overwritten_with_observed_resolved_targets=len(seen),
                known_upper_completion_paths=len(completion), checked_libraries=checked,
                unresolved_computed_sites=sum(row['classification'] == 'unresolved'
                                              and row['unresolved_boundary']['kind'] == 'computed_callback'
                                              for row in document['callers']),
                lazy_resolution_proven=False, mutex_progress_proven=False,
                universal_refusal_safety_proven=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Verify factory caller and import evidence')
    parser.add_argument('--resolved-imports', action='store_true',
                        help='also check the two locally captured RS2 1.4 libraries')
    options = parser.parse_args()
    result = report()
    if options.resolved_imports:
        document = json.loads(MANIFESTS[1].read_text(encoding='utf-8'))
        result['resolved_import_audit'] = verify_resolved_imports(document)
    print(json.dumps(result, ensure_ascii=False, indent=2))
