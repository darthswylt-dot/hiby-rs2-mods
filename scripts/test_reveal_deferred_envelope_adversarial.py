#!/usr/bin/env python3
"""Adverse owned68 transport boundaries, not concurrency/lifetime authority.

Inputs and native FIFO operations remain caller-exclusive/coherent/serialized.
Instruction-boundary mutations are bounded negative/snapshot cases, not a real
scheduler. Controlled REMOVE substitution checks only the caller's no-dispatch
branch, not a failure mode of the actual native remover. READY/CONSUMED is local
attempt accounting: arbitrary record clones are deliberately not authenticated.
No native grow/retry/free/recovery, firmware installation or device I/O occurs.
"""

import hashlib
import unittest

from build_reveal_bridge_diag import b
import reveal_creation_capture_mips as capture
import reveal_creation_capture_stage as creation
import reveal_deferred_envelope_mips as core
import reveal_deferred_envelope_stage as stage
import reveal_owner_carrier_mips as producer
import reveal_paint_retirement_mips as owner
import reveal_registry_receipt_mips as receipt
import test_folderfollow_reveal_static_contract as source
import test_reveal_deferred_envelope_mips as f


ARGS = (f.STATE, f.BIND_STATE, f.OWNER_STATE, f.CONTROLLER,
        f.REGISTRY_MUTEX, f.PAINT_MUTEX, f.CODE)


class AdversarialDeferredMachine(f.DeferredEnvelopeMachine):
    """Choose both ambiguous raw outcomes without guessing an unlock."""

    def __init__(self, image, **options):
        self.registry_release_failure_releases = True
        self.registry_acquire_failure_holds = False
        super().__init__(image, **options)

    def service(self, target):
        pointer, held = self.r[4], self.registry_held
        super().service(target)
        if pointer == f.REGISTRY_MUTEX:
            if (target == f.RAW_UNLOCK and self.release
                    and not self.registry_release_failure_releases):
                self.registry_held = held
            if (target == f.RAW_LOCK and self.acquire
                    and self.registry_acquire_failure_holds):
                self.registry_held = True


class DeferredEnvelopeAdversarialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = source.SOURCE.read_bytes()
        digest = hashlib.sha256(cls.image).hexdigest()
        if digest != source.SOURCE_SHA256 or len(cls.image) != source.SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: {digest}, size {len(cls.image)}')

    def machine(self, **options):
        return AdversarialDeferredMachine(self.image, **options)

    def prepare(self, machine, *, captured=f.OUTPUT, output=f.ENVELOPE):
        self.assertEqual(machine.invoke_register(output=captured), (0, captured))
        self.assertEqual(machine.pack_payload(captured=captured, output=output),
                         (output, 0))
        self.assertEqual(machine.captured_carriers, [])

    def extents(self, machine):
        return ((f.CODE, len(machine.code)),
                (f.STATE, machine.composition['receipt_memory_bytes']),
                (f.BIND_STATE, machine.composition['binding_memory_bytes']),
                (f.OWNER_STATE, machine.composition['owner_memory_bytes']),
                (f.CONTROLLER, receipt.CONTROLLER_BYTES),
                (f.REGISTRY_MUTEX, receipt.MUTEX_BYTES),
                (f.PAINT_MUTEX, receipt.MUTEX_BYTES),
                (receipt.NATIVE_RX[0], receipt.NATIVE_RX[1] - receipt.NATIVE_RX[0]))

    def assert_preflight_denied(self, machine, result):
        self.assertEqual(result, (0, 0))
        self.assertEqual(machine.reads, [])
        self.assertEqual(machine.writes, [])
        self.assertEqual(machine.raw_events, [])
        self.assertEqual(machine.binding_accesses, [])
        self.assertEqual(machine.owner_accesses, [])
        self.assertEqual(machine.journal_accesses, [])

    def schema_pc(self, machine, label):
        start = machine.envelope_labels[label]
        end = (machine.envelope_labels['dispatch'] if label == 'pack'
               else f.CODE + len(machine.code))
        expected = b.lw(8, core.COPY + core.MAGIC, 29)
        matches = [pc for pc in range(start, end, 4)
                   if machine.word(pc) == expected]
        self.assertEqual(len(matches), 1)
        return matches[0]

    def test_pack_protects_all_data_rx_and_tails_before_any_access(self):
        m = self.machine()
        self.assertEqual(m.invoke_register(), (0, f.OUTPUT))
        m.payload()
        for start, size in self.extents(m):
            for field in ('captured', 'payload', 'output', 'stack'):
                with self.subTest(start=hex(start), size=size, field=field):
                    last = start + size - 4
                    value = ((last & ~7) + core.FRAME if field == 'stack'
                             else last)
                    m.clear_events()
                    self.assert_preflight_denied(m, m.invoke_pack(**{field: value}))

    def test_dispatch_protects_all_data_rx_and_tails_before_any_access(self):
        m = self.machine()
        self.prepare(m)
        for start, size in self.extents(m):
            for field in ('envelope', 'stack'):
                with self.subTest(start=hex(start), size=size, field=field):
                    last = start + size - 4
                    value = ((last & ~7) + core.FRAME if field == 'stack'
                             else last)
                    m.clear_events()
                    options = {field: value}
                    self.assert_preflight_denied(m, m.invoke_dispatch(**options))

    def test_pack_inputs_output_and_frame_must_be_pairwise_disjoint(self):
        m = self.machine()
        self.assertEqual(m.invoke_register(), (0, f.OUTPUT))
        m.payload()
        cases = ({'captured': f.OWNED_INPUT},
                 {'payload': f.OUTPUT + 28},
                 {'output': f.OUTPUT + 28},
                 {'output': f.OWNED_INPUT + 32},
                 {'captured': f.STACK - core.FRAME},
                 {'payload': f.STACK - 4},
                 {'output': f.STACK - core.FRAME})
        for options in cases:
            with self.subTest(options=options):
                m.clear_events()
                self.assert_preflight_denied(m, m.invoke_pack(**options))
        m.clear_events()
        self.assert_preflight_denied(
            m, m.invoke_dispatch(f.STACK - core.FRAME))

    def test_invalid_null_unaligned_wrap_and_stack_extents_deny_before_access(self):
        m = self.machine()
        for options in ({'captured': 0}, {'payload': 0}, {'output': 0},
                        {'captured': f.OUTPUT + 1}, {'payload': f.OWNED_INPUT + 1},
                        {'output': f.ENVELOPE + 1}, {'captured': 0xFFFFFFF0},
                        {'payload': 0xFFFFFFF0}, {'output': 0xFFFFFFF0},
                        {'stack': 0}, {'stack': core.FRAME - 8},
                        {'stack': f.STACK + 4}, {'controller': 0}):
            with self.subTest(options=options):
                m.clear_events()
                self.assert_preflight_denied(m, m.invoke_pack(**options))
        for options in ({'envelope': 0}, {'envelope': f.ENVELOPE + 1},
                        {'envelope': 0xFFFFFFF0}, {'stack': 0},
                        {'stack': core.FRAME - 8}, {'stack': f.STACK + 4},
                        {'controller': 0}):
            with self.subTest(options=options):
                m.clear_events()
                self.assert_preflight_denied(m, m.invoke_dispatch(**options))

    def test_valid_extent_ending_exactly_at_unsigned32_boundary_is_not_wrap(self):
        for field, size in (('captured', 32), ('payload', 36), ('output', 68)):
            with self.subTest(field=field):
                m = self.machine()
                self.assertEqual(m.invoke_register(), (0, f.OUTPUT))
                m.payload()
                address = 0x100000000 - size
                m.map(address, size)
                if field != 'output':
                    original = f.OUTPUT if field == 'captured' else f.OWNED_INPUT
                    for index, word in enumerate(m.words_at(original, size // 4)):
                        m.put(address + 4 * index, word, 4)
                self.assertEqual(m.invoke_pack(**{field: address}),
                                 (address if field == 'output' else f.ENVELOPE, 0))
                envelope = address if field == 'output' else f.ENVELOPE
                self.assertEqual(m.invoke_dispatch(envelope), (2, 0))

    def test_output_exactly_adjacent_to_full_composed_rx_is_admitted(self):
        for side in ('before', 'after'):
            with self.subTest(side=side):
                m = self.machine()
                self.assertEqual(m.invoke_register(), (0, f.OUTPUT))
                m.payload()
                output = (f.CODE - 68 if side == 'before'
                          else f.CODE + len(m.code))
                m.map(output, 68)
                self.assertEqual(m.invoke_pack(output=output), (output, 0))
                self.assertEqual(m.invoke_dispatch(output), (2, 0))

    def test_each_capture_schema_domain_denies_pack_without_output_stores(self):
        changes = ((core.MAGIC, 0), (core.FLAGS, 1),
                   (core.CONTROLLER, f.CONTROLLER + 4), (core.NATIVE_RESULT, 1),
                   (core.BINDING_SEQUENCE, 0), (core.BINDING_SEQUENCE, 17),
                   (core.OWNER, 0), (core.OWNER, 0x80000000),
                   (core.RECEIPT_SEQUENCE, 0), (core.RECEIPT_SEQUENCE, 17),
                   (core.ENGINE, f.ENGINE ^ 1))
        for offset, value in changes:
            with self.subTest(offset=offset, value=value):
                m = self.machine()
                self.assertEqual(m.invoke_register(), (0, f.OUTPUT))
                m.payload()
                m.put(f.OUTPUT + offset, value, 4)
                m.clear_events()
                self.assertEqual(m.invoke_pack(), (0, 0))
                self.assertEqual(m.envelope_words(), (0,) * 17)
                self.assertEqual([event for event in m.envelope_accesses
                                  if event[0] == 'write'], [])
                self.assertEqual(m.raw_events, [])

    def test_invalid_dispatch_schema_never_consumes_or_calls_publisher(self):
        changes = ((core.MAGIC, core.CONSUMED_MAGIC), (core.FLAGS, 1),
                   (core.CONTROLLER, f.CONTROLLER + 4), (core.NATIVE_RESULT, 1),
                   (core.BINDING_SEQUENCE, 0), (core.BINDING_SEQUENCE, 17),
                   (core.OWNER, 0), (core.OWNER, 0x80000000),
                   (core.RECEIPT_SEQUENCE, 0), (core.RECEIPT_SEQUENCE, 17),
                   (core.ENGINE, f.ENGINE ^ 1))
        for offset, value in changes:
            with self.subTest(offset=offset, value=value):
                m = self.machine()
                self.prepare(m)
                m.put(f.ENVELOPE + offset, value, 4)
                expected = m.envelope_words()
                m.clear_events()
                self.assertEqual(m.invoke_dispatch(), (0, 0))
                self.assertEqual(m.envelope_words(), expected)
                self.assertEqual([event for event in m.envelope_accesses
                                  if event[0] == 'write'], [])
                self.assertEqual(m.raw_events, [])

    def test_every_initial_dirty_output_word_is_refused_before_source_copy(self):
        for offset in range(0, 68, 4):
            with self.subTest(offset=offset):
                m = self.machine()
                m.put(f.ENVELOPE + offset, 1, 4)
                m.clear_events()
                self.assertEqual(m.invoke_pack(), (0, 0))
                self.assertEqual(m.writes, [])
                self.assertFalse(any(f.OUTPUT <= address < f.OUTPUT + 32
                                     or f.OWNED_INPUT <= address < f.OWNED_INPUT + 36
                                     for address, _ in m.reads))
                self.assertEqual(m.raw_events, [])

    def test_every_output_word_is_rechecked_after_the_private_snapshot(self):
        for offset in range(0, 68, 4):
            with self.subTest(offset=offset):
                m = self.machine()
                self.assertEqual(m.invoke_register(), (0, f.OUTPUT))
                m.payload()
                schema_pc = self.schema_pc(m, 'pack')

                def poison(machine, pc):
                    if pc == schema_pc:
                        machine.put(f.ENVELOPE + offset, 1, 4)

                m.on_instruction = poison
                m.clear_events()
                self.assertEqual(m.invoke_pack(), (0, 0))
                self.assertEqual(m.envelope_words(), tuple(
                    int(index * 4 == offset) for index in range(17)))
                writes = [event for event in m.envelope_accesses
                          if event[0] == 'write']
                self.assertEqual(len(writes), 1)  # only controlled poison
                self.assertEqual(writes[0][2], f.ENVELOPE + offset)
                self.assertEqual(m.raw_events, [])

    def test_pack_uses_snapshot_not_late_capture_or_payload_source_reads(self):
        m = self.machine()
        self.assertEqual(m.invoke_register(), (0, f.OUTPUT))
        expected = (*m.outwords(), *f.PAYLOAD)
        m.payload()
        schema_pc = self.schema_pc(m, 'pack')

        def mutate(machine, pc):
            if pc == schema_pc:
                for address, count in ((f.OUTPUT, 8), (f.OWNED_INPUT, 9)):
                    for index in range(count):
                        machine.put(address + 4 * index, f.MASK, 4)

        m.on_instruction = mutate
        self.assertEqual(m.invoke_pack(), (f.ENVELOPE, 0))
        self.assertEqual(m.envelope_words(), expected)

    def test_dispatch_uses_private_snapshot_after_all_source_words_change(self):
        m = self.machine()
        self.prepare(m)
        schema_pc = self.schema_pc(m, 'dispatch')

        def mutate(machine, pc):
            if pc == schema_pc:
                for offset in range(0, 68, 4):
                    machine.put(f.ENVELOPE + offset, f.MASK, 4)

        m.on_instruction = mutate
        self.assertEqual(m.invoke_dispatch(), (2, 0))
        self.assertEqual(m.words_at(m.head(), 11), (*f.PAYLOAD, 2, 1))
        self.assertEqual(m.peek(f.ENVELOPE), core.CONSUMED_MAGIC)

    def test_consume_precedes_first_raw_call_and_has_no_late_source_access(self):
        m = self.machine()
        self.prepare(m)
        boundaries = []

        def observe(machine, target):
            if target == f.RAW_LOCK and machine.r[4] == f.REGISTRY_MUTEX:
                boundaries.append((machine.peek(f.ENVELOPE),
                                   len(machine.envelope_accesses)))

        m.on_service = observe
        m.clear_events()
        self.assertEqual(m.invoke_dispatch(), (2, 0))
        self.assertEqual(boundaries,
                         [(core.CONSUMED_MAGIC, len(m.envelope_accesses))])
        self.assertEqual([(event[0], event[1]) for event in m.raw_events],
                         [(f.RAW_LOCK, f.REGISTRY_MUTEX),
                          (f.RAW_LOCK, f.PAINT_MUTEX),
                          (f.RAW_UNLOCK, f.PAINT_MUTEX),
                          (f.RAW_UNLOCK, f.REGISTRY_MUTEX)])

    def test_raw_registry_acquire_errors_do_not_guess_unlock_even_if_guard_may_hold(self):
        for status in (1, 0x82, f.MASK):
            for holds in (False, True):
                with self.subTest(status=status, holds=holds):
                    m = self.machine()
                    self.prepare(m)
                    m.acquire, m.registry_acquire_failure_holds = status, holds
                    m.clear_events()
                    self.assertEqual(m.invoke_dispatch(), (0, status))
                    self.assertEqual(m.peek(f.ENVELOPE), core.CONSUMED_MAGIC)
                    self.assertEqual(m.registry_held, holds)
                    self.assertEqual(m.binding_accesses, [])
                    self.assertEqual(m.owner_accesses, [])
                    self.assertEqual(len(m.raw_events), 1)

    def test_raw_registry_release_ambiguity_has_no_late_source_or_shared_access(self):
        for status in (1, 0x82, f.MASK):
            for releases in (False, True):
                with self.subTest(status=status, releases=releases):
                    m = self.machine()
                    self.prepare(m)
                    m.release = status
                    m.registry_release_failure_releases = releases
                    boundaries = []

                    def observe(machine, target):
                        if target == f.RAW_UNLOCK and machine.r[4] == f.REGISTRY_MUTEX:
                            boundaries.append((len(machine.binding_accesses),
                                               len(machine.owner_accesses),
                                               len(machine.journal_accesses),
                                               len(machine.envelope_accesses)))

                    m.on_service = observe
                    m.clear_events()
                    self.assertEqual(m.invoke_dispatch(), (0, status))
                    self.assertEqual(m.count(), 1)
                    self.assertEqual(m.registry_held, not releases)
                    self.assertEqual(boundaries, [(len(m.binding_accesses),
                                                   len(m.owner_accesses),
                                                   len(m.journal_accesses),
                                                   len(m.envelope_accesses))])

    def test_raw_paint_acquire_errors_consume_without_owner_access_or_guessed_unlock(self):
        for status in (1, 0x82, f.MASK):
            for holds in (False, True):
                with self.subTest(status=status, holds=holds):
                    m = self.machine()
                    self.prepare(m)
                    m.paint_acquire_result = status
                    m.paint_acquire_failure_holds = holds
                    m.clear_events()
                    self.assertEqual(m.invoke_dispatch(), (0, status))
                    self.assertEqual(m.peek(f.ENVELOPE), core.CONSUMED_MAGIC)
                    self.assertEqual(m.paint_held, holds)
                    self.assertEqual(m.owner_accesses, [])
                    self.assertEqual(m.binding_header(), (1, 1, status, 0))
                    self.assertEqual([(event[0], event[1]) for event in m.raw_events],
                                     [(f.RAW_LOCK, f.REGISTRY_MUTEX),
                                      (f.RAW_LOCK, f.PAINT_MUTEX),
                                      (f.RAW_UNLOCK, f.REGISTRY_MUTEX)])

    def test_raw_paint_release_ambiguity_ends_owner_and_envelope_access(self):
        for status in (1, 0x82, f.MASK):
            for releases in (False, True):
                with self.subTest(status=status, releases=releases):
                    m = self.machine()
                    self.prepare(m)
                    m.paint_release_result = status
                    m.paint_release_failure_releases = releases
                    boundaries = []

                    def observe(machine, target):
                        if target == f.RAW_UNLOCK and machine.r[4] == f.PAINT_MUTEX:
                            boundaries.append((len(machine.owner_accesses),
                                               len(machine.envelope_accesses)))

                    m.on_service = observe
                    m.clear_events()
                    self.assertEqual(m.invoke_dispatch(), (0, status))
                    self.assertEqual(m.count(), 1)
                    self.assertEqual(m.paint_held, not releases)
                    self.assertEqual(m.binding_header(), (1, 1, status, 0))
                    self.assertEqual(boundaries, [(len(m.owner_accesses),
                                                   len(m.envelope_accesses))])

    def test_active_old_cancelled_ack_cannot_remove_new_equal_engine_publication(self):
        m = self.machine()
        self.prepare(m)
        self.assertEqual(m.invoke_dispatch(), (2, 0))
        self.assertEqual(m.claim(), (f.OWNER_STATE + owner.COPY, 2))
        old_deferred = f.ENVELOPE + 68
        self.assertEqual(m.pack_payload(output=old_deferred), (old_deferred, 0))
        self.assertEqual(m.enqueue(old_deferred), 0)
        self.assertEqual(m.retire(1), (1, 0))
        new_capture, new_envelope = f.OUTPUT + 32, f.ENVELOPE + 136
        self.prepare(m, captured=new_capture, output=new_envelope)
        self.assertEqual(m.outwords(new_capture)[4:7], (2, 3, 2))
        self.assertEqual(m.enqueue(new_envelope), 1)
        self.assertEqual(m.pop_dispatch(), (0, 0))
        self.assertEqual(m.pop_dispatch(), (4, 1))
        self.assertEqual(m.complete(4), (0, 0))
        self.assertEqual(m.complete(2), (3, 0))
        self.assertEqual(m.claim(), (f.OWNER_STATE + owner.COPY, 4))
        self.assertEqual(m.complete(2), (0, 0))
        self.assertEqual(m.complete(4), (1, 0))
        self.assertEqual(m.count(), 0)

    def test_cloned_ready_records_are_not_a_global_deduplication_boundary(self):
        m = self.machine()
        self.prepare(m)
        self.assertEqual(m.enqueue(), 0)
        self.assertEqual(m.enqueue(), 1)  # actual native value copy twice
        self.assertEqual(m.pop_dispatch(), (2, 0))
        self.assertEqual(m.pop_dispatch(), (3, 1))
        self.assertEqual(m.count(), 2)
        self.assertEqual(m.peek(f.WORK), core.CONSUMED_MAGIC)
        self.assertEqual(m.peek(f.WORK + 68), core.CONSUMED_MAGIC)
        self.assertEqual(m.invoke_dispatch(f.WORK), (0, 0))

    def test_controlled_nonzero_remove_substitute_never_dispatches_snapshot(self):
        m = self.machine()
        self.prepare(m)
        self.assertEqual(m.enqueue(), 0)
        # Explicit in-memory control-flow substitute, NOT an observed native
        # removal error and NOT permission to retry the native list operation.
        m.patches[f.REMOVE] = b.addiu(2, 0, 22)
        m.patches[f.REMOVE + 4] = b.r_type(31, 0, 0, 8)
        m.patches[f.REMOVE + 8] = 0
        m.clear_events()
        self.assertEqual(m.pop_dispatch(), (0, 22))
        self.assertEqual(m.transport_count(), 1)
        self.assertEqual(m.count(), 0)
        self.assertEqual(m.peek(f.WORK), core.READY_MAGIC)
        self.assertNotIn(m.envelope_labels['dispatch'], m.trace)
        self.assertEqual(m.raw_events, [])

    def test_invalid_transport_head_is_not_removed_or_dispatched(self):
        m = self.machine()
        self.prepare(m)
        self.assertEqual(m.enqueue(), 0)
        m.put(m.transport_element() + core.FLAGS, 1, 4)
        m.clear_events()
        self.assertEqual(m.pop_dispatch(), (0, 0))
        self.assertEqual(m.transport_count(), 1)
        self.assertNotIn(f.REMOVE, m.trace)
        self.assertNotIn(m.envelope_labels['dispatch'], m.trace)
        self.assertEqual(m.envelope_words(f.WORK), (0,) * 17)
        self.assertEqual(m.raw_events, [])

    def test_prior_source_taking_entries_reject_new_tail_aliases(self):
        m = self.machine()
        tail = f.CODE + m.composition['capture_prefix_code_bytes']
        for address in (tail, f.CODE + len(m.code) - 4):
            for field in ('descriptor', 'output', 'stack'):
                with self.subTest(address=hex(address), field=field):
                    value = ((address & ~7) + capture.FRAME
                             if field == 'stack' else address)
                    m.clear_events()
                    self.assertEqual(m.invoke_register(**{field: value}), (f.MASK, 0))
                    self.assertEqual(m.writes, [])
                    self.assertEqual(m.raw_events, [])
                    self.assertEqual(m.native_entries, [])
            for field in ('payload', 'stack'):
                with self.subTest(address=hex(address), field=field):
                    value = ((address & ~7) + producer.FRAME
                             if field == 'stack' else address)
                    m.clear_events()
                    options = {'stack': value} if field == 'stack' else {}
                    payload = f.OWNED_INPUT if field == 'stack' else value
                    self.assertEqual(m.invoke_adapter(payload, 1, 1, **options), (0, 0))
                    self.assertEqual(m.writes, [])
                    self.assertEqual(m.raw_events, [])

    def test_following_code_descriptor_rejects_types_alignment_overflow_and_data_alias(self):
        producer_args = (f.BIND_STATE, f.OWNER_STATE, f.CONTROLLER,
                         f.REGISTRY_MUTEX, f.PAINT_MUTEX, f.CODE + 0x20000, f.CODE)
        for value in (True, False, -4, 1, 2, 1.0, '4', None, 0x10000000):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    creation.assemble(*ARGS, following_code_bytes=value)
                with self.assertRaises(ValueError):
                    producer.assemble(*producer_args, following_code_bytes=value)
        previous = creation.assemble(*ARGS)
        reach_receipt = f.STATE - f.CODE - len(previous['code']) + 4
        with self.assertRaises(ValueError):
            creation.assemble(*ARGS, following_code_bytes=reach_receipt)
        emitted, _ = producer.assemble(*producer_args)
        reach_receipt = f.STATE - producer_args[-2] - len(emitted) + 4
        with self.assertRaises(ValueError):
            producer.assemble(*producer_args, following_code_bytes=reach_receipt)

    def test_zero_default_extension_keeps_both_prior_capture_golden_hashes(self):
        for checked, size, digest in (
                (False, 22676, '90be0fdb56fa349782d7a5b89009661ca26484ad1beed25fb8628ddfc2383da5'),
                (True, 25716, '3c7b26a00fbd17bcd6c86719c21fa7ee5120ecaefcce1b4d9d6fb14332e6721c')):
            with self.subTest(checked=checked):
                implicit = creation.assemble(*ARGS, checked_registry_release=checked)
                explicit = creation.assemble(*ARGS, checked_registry_release=checked,
                                             following_code_bytes=0)
                self.assertEqual(implicit, explicit)
                self.assertEqual(len(implicit['code']), size)
                self.assertEqual(hashlib.sha256(implicit['code']).hexdigest(), digest)
        producer_args = (f.BIND_STATE, f.OWNER_STATE, f.CONTROLLER,
                         f.REGISTRY_MUTEX, f.PAINT_MUTEX, f.CODE + 0x20000, f.CODE)
        self.assertEqual(producer.assemble(*producer_args),
                         producer.assemble(*producer_args, following_code_bytes=0))

    def test_protected_code_descriptor_rejects_malformed_or_incomplete_extents(self):
        arguments = (*ARGS[:-1], f.CODE + 0x20000, f.CODE)
        for descriptor in ((), (f.CODE,), [f.CODE, 0x30000],
                           (True, 0x30000), (f.CODE, True),
                           (f.CODE + 1, 0x30000), (f.CODE, 0),
                           (f.CODE, 3), (f.CODE, 4),
                           (0xFFFFFFFC, 8), (0x4389E0, 0x20000),
                           (f.CODE + 0x20000, 0x10000),
                           (f.CODE, f.STATE - f.CODE + 4)):
            with self.subTest(descriptor=descriptor):
                with self.assertRaises(ValueError):
                    core.assemble(*arguments, protected_code=descriptor)

    def test_static_core_configuration_denies_aliases_and_invalid_domains(self):
        arguments = [*ARGS[:-1], f.CODE + 0x20000, f.CODE]
        for index, value in ((0, f.BIND_STATE), (1, f.OWNER_STATE),
                             (2, f.CONTROLLER), (3, f.REGISTRY_MUTEX),
                             (4, f.PAINT_MUTEX), (5, f.REGISTRY_MUTEX),
                             (6, f.STATE), (7, 0x4389E0),
                             (7, f.CODE + 0x20000)):
            with self.subTest(index=index, value=hex(value)):
                invalid = arguments.copy()
                invalid[index] = value
                with self.assertRaises(ValueError):
                    core.assemble(*invalid)
        for options in ({'capacity': True}, {'capacity': 0}, {'capacity': 1025},
                        {'owner_capacity': True}, {'owner_capacity': 0},
                        {'ticket_limit': True}, {'ticket_limit': 0},
                        {'ticket_limit': 0x80000000}):
            with self.subTest(options=options):
                with self.assertRaises(ValueError):
                    core.assemble(*arguments, **options)

    def test_composer_extends_all_prior_rx_guards_without_adding_shared_state(self):
        combined = stage.assemble(*ARGS)
        prefix = creation.assemble(*ARGS, checked_registry_release=True,
                                   following_code_bytes=combined['envelope_code_bytes'])
        self.assertEqual(combined['code'][:len(prefix['code'])], prefix['code'])
        self.assertEqual(combined['protected_code_extent'],
                         (f.CODE, len(combined['code'])))
        for name in ('owner_memory_bytes', 'binding_memory_bytes',
                     'receipt_memory_bytes', 'release_hooks'):
            self.assertEqual(combined[name], prefix[name])
        self.assertEqual(combined['registry_release_checked'], True)
        self.assertEqual(combined['capture_prefix_code_bytes'], len(prefix['code']))
        self.assertEqual(combined['envelope_labels']['pack'],
                         f.CODE + len(prefix['code']))

    def test_non_dense_owner_serial_is_carried_without_assuming_it_equals_sequence(self):
        m = self.machine()
        self.prepare(m)
        self.assertEqual(m.invoke_dispatch(), (2, 0))
        second_capture, second_envelope = f.OUTPUT + 32, f.ENVELOPE + 68
        self.prepare(m, captured=second_capture, output=second_envelope)
        self.assertEqual(m.envelope_words(second_envelope)[4:7], (2, 3, 2))
        self.assertEqual(m.invoke_dispatch(second_envelope), (4, 1))
        self.assertEqual(m.words_at(m.queue_element(1), 11), (*f.PAYLOAD, 4, 3))
        self.assertEqual(m.captured_carriers, [])


if __name__ == '__main__':
    unittest.main()
