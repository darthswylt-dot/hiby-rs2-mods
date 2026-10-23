#!/usr/bin/env python3
"""Execute explicit transport hooks and inspected native queue instructions.

Allocator/cache/geometry helpers are explicit fixtures. Native callback ENTRY
executes through 439EC8; its remaining name/widget body is the prior mock,
not an execution or identity proof of the native renderer/UI. No device I/O.
"""
import hashlib
import struct
import unittest

import build_reveal_queue_transport_stage as stage
import decode_reveal_queue_transport_stage as decoder
import test_reveal_queue_birth_stage as birth_tests
from verify_reveal_queue_transport_stage import verify


gap = birth_tests.gap
CAPACITIES = dict(capacity=16, row_capacity=16, operation_capacity=16,
                  scope_capacity=16, birth_capacity=32, transport_capacity=64)


class TransportMachine(birth_tests.BirthMachine):
    def __init__(self, image, meta):
        super().__init__(image, meta)
        self.callback_ids = []
        self.repeat_callbacks = 1

    def consume(self, stack=gap.ENGINE_STACK):
        # A separate stack is required for the explicit interleaving fixture;
        # reusing a still-live producer's stack would overwrite its locals.
        self.r[29], self.r[31], self.r[21], self.r[16] = stack, gap.RETURN, gap.ENGINE, gap.SURFACE
        self.run_at(0x8B4740, 0x8B478C)

    def external(self, target):
        if target != 0x439EC0:
            super().external(target)
            return
        saved, hi, lo = self.r.copy(), self.hi, self.lo
        for _ in range(self.repeat_callbacks):
            self.r = saved.copy()
            self.run_at(0x439EC0, 0x439EC8)
            expected = saved.copy()
            expected[29] -= 0x38
            if (self.r, self.hi, self.lo) != (expected, hi, lo):
                raise AssertionError('callback entry changed native ABI beyond its original prologue')
            if self.get(self.r[29] + 0x34, 4) != saved[31]:
                raise AssertionError('callback original saved RA changed')
            self.callback_ids.append(self.get(self.r[29] + 0x14, 4))
            # Explicit fixture boundary: skip native lookup/widget body and
            # simulate its eventual frame pop with the prior hostile stub.
            self.r = saved.copy()
            super().external(target)
        # hostile_result has set the native callback return; callee-saved
        # registers and SP are still exactly those of the helper invocation.


class RevealQueueTransportStageTests(unittest.TestCase):
    sequence = birth_tests.RevealQueueBirthStageTests.sequence
    prepare = birth_tests.RevealQueueBirthStageTests.prepare
    render = birth_tests.RevealQueueBirthStageTests.render
    entry = birth_tests.RevealQueueBirthStageTests.entry
    borrow = birth_tests.RevealQueueBirthStageTests.borrow
    record = birth_tests.RevealQueueBirthStageTests.record
    producer = birth_tests.RevealQueueBirthStageTests.producer
    event_site = birth_tests.RevealQueueBirthStageTests.event_site
    event_words = birth_tests.RevealQueueBirthStageTests.event_words
    event_bytes = birth_tests.RevealQueueBirthStageTests.event_bytes
    fill_rows = birth_tests.RevealQueueBirthStageTests.fill_rows
    call_fill = birth_tests.RevealQueueBirthStageTests.call_fill
    call_post = birth_tests.RevealQueueBirthStageTests.call_post
    address = birth_tests.RevealQueueBirthStageTests.address
    original = birth_tests.RevealQueueBirthStageTests.original

    @classmethod
    def setUpClass(cls):
        cls.source = gap.history.prior.rows.lineage_tests.SOURCE.read_bytes()
        cls.image, cls.meta = stage.build(cls.source, **CAPACITIES)

    def machine(self, **overrides):
        if not overrides:
            return TransportMachine(self.image, self.meta)
        options = dict(CAPACITIES, **overrides)
        image, meta = stage.build(self.source, **options)
        return TransportMachine(image, meta)

    def decode(self, m):
        return decoder.decode(m.snapshot(), **{key: m.meta[key] for key in CAPACITIES})

    def journal(self, m):
        return self.decode(m)['queue_transport_observation']

    def count(self, m):
        return m.get(m.meta['transport_buffer'], 4)

    def test_exact_enqueue_install_is_prepublication_and_node_only_grows(self):
        m = self.machine()
        seen = []

        def publication(pc):
            if pc in (0x8B3D24, 0x8B3D4C):
                seen.append((pc, self.count(m), m.get(m.r[2] + 16, 4)))

        m.before_instruction = publication
        self.assertEqual(m.enqueue(), 0)
        node, fields = m.queue()[0]
        event = self.journal(m)['events'][0]
        self.assertEqual(m.allocation_attempts, [16, 20])
        self.assertEqual(m.quad(fields[0]), (1, 2, 8, 8))
        self.assertEqual(fields[1:], (gap.OLD_METADATA, 0, 0))
        self.assertEqual((event['kind'], event['parent'], event['origin'], event['node']), (1, 2, 1, node))
        self.assertEqual((event['frame'], event['upstream']),
                         (gap.ENGINE_STACK - 0x40 - 0x28, gap.ENGINE_STACK - 0x40))
        self.assertEqual(m.get(node + 16, 4), 1)
        self.assertEqual(seen, [(0x8B3D4C, 1, 1)])

    def test_native_consumer_transports_explicit_birth_to_separate_callback_receipt(self):
        m = self.machine()
        m.enqueue()
        node, fields = m.queue()[0]
        pointers = {address for address, _ in m.queue_allocations}
        m.reads.clear()
        m.consume()
        observed = self.journal(m)
        events, chain = observed['events'], observed['chains'][0]
        self.assertEqual([event['kind'] for event in events], [1, 2, 3, 4])
        self.assertEqual([event['parent'] for event in events], [2, 1, 2, 3])
        self.assertEqual([event['origin'] for event in events], [1] * 4)
        self.assertEqual([event['node'] for event in events], [node] * 4)
        self.assertEqual([event['copy'] for event in events], [fields[0]] * 4)
        self.assertEqual([event['frame'] for event in events[1:]],
                         [gap.ENGINE_STACK, gap.ENGINE_STACK - 0xB8, gap.ENGINE_STACK - 0xB8 - 0x38])
        self.assertEqual(m.callback_ids, [4])
        self.assertTrue(chain['observed_birth_to_callback_chain'])
        self.assertTrue(chain['observation_complete'])
        self.assertTrue(chain['producer_return_observed'])
        self.assertTrue(chain['known_boundary_unchanged'])
        self.assertEqual(sum(address == node + 16 for address, _ in m.reads), 1)
        self.assertFalse(any(fields[0] + 16 <= address < fields[0] + 20 for address, _ in m.reads))
        self.assertTrue(pointers.issubset(set(m.freed)))
        self.assertEqual(m.get(gap.ENGINE + 0x34, 4), 0)
        self.assertFalse(self.decode(m)['renderer_identity_associated'])
        self.assertFalse(chain['request_freshness_proven'])

    def test_multiple_callbacks_keep_one_helper_and_distinct_invocation_ids(self):
        m = self.machine()
        m.repeat_callbacks = 2  # Explicit geometry-split callback-body fixture.
        m.enqueue()
        m.consume()
        report = self.journal(m)
        self.assertEqual([event['kind'] for event in report['events']], [1, 2, 3, 4, 4])
        self.assertEqual(m.callback_ids, [4, 5])
        self.assertEqual([chain['helper'] for chain in report['chains']], [3, 3])
        self.assertTrue(all(chain['observation_complete'] for chain in report['chains']))

    def test_helper_prologue_once_preserves_arguments_and_later_native_saved_ra(self):
        m = self.machine()
        seen = {}

        def boundary(pc):
            if pc == 0x8B3FA0:
                seen['before'], seen['hi'], seen['lo'] = m.r.copy(), m.hi, m.lo
            elif pc == 0x8B3FA8:
                expected = seen['before'].copy()
                expected[29] -= 0xB8
                self.assertEqual((m.r, m.hi, m.lo), (expected, seen['hi'], seen['lo']))
                self.assertEqual(m.get(m.r[29] + 0xB0, 4), expected[22])
                seen['carrier'] = m.get(m.r[29] + 0x14, 4)
            elif pc == 0x8B3FB4:
                self.assertEqual(m.get(m.r[29] + 0xB4, 4), 0x8B4764)

        m.enqueue()
        m.before_instruction = boundary
        m.consume()
        self.assertEqual(seen['carrier'], 3)

    def test_incoming_a3_is_preserved_for_first_native_geometry_call(self):
        m = self.machine()
        for index, value in enumerate((1, 2, 8, 8)):
            m.put(gap.INPUT + index * 4, value, 4)
        m.r[29], m.r[31], m.r[4:8] = gap.ENGINE_STACK, gap.RETURN, [gap.ENGINE, gap.INPUT, 0, 0x13572468]
        observed = []

        def geometry(pc):
            if pc == 0x8B3FD8:
                observed.append(m.r[7])

        m.before_instruction = geometry
        m.run_at(0x8B3FA0, gap.RETURN)
        self.assertEqual(observed, [0x13572468])
        self.assertEqual(m.callback_ids, [0])

    def test_actual_full_tail_branch_still_observes_following_queued_nodes(self):
        m = self.machine()
        m.enqueue()
        m.r[29], m.r[31], m.r[21], m.r[16] = gap.ENGINE_STACK, gap.RETURN, gap.ENGINE, gap.SURFACE
        # The full-redraw callback itself is a separate unbound entry. This
        # executes its actual later C+34 load/branch into the queued loop.
        m.run_at(0x8B49B8, 0x8B478C)
        self.assertEqual(m.callback_ids, [4])
        self.assertTrue(self.journal(m)['chains'][0]['observation_complete'])
        self.assertEqual(m.get(gap.ENGINE + 0x34, 4), 0)

    def test_postallocation_unknown_route_zeroes_tail_and_preserves_ra_and_all_registers(self):
        m = self.machine()
        node = m.allocation(20)
        m.put(node + 16, 0x12345678, 4)
        m.r[29], m.r[2] = gap.ENGINE_STACK, node
        m.put(gap.ENGINE_STACK + 0x24, gap.RETURN, 4)
        m.put(gap.ENGINE_STACK + 0x3C, 0xDEADBEEF, 4)
        expected, hi, lo = m.r.copy(), m.hi, m.lo
        expected[31] = gap.RETURN
        m.reads.clear()
        m.run_at(0x8B3CE8, 0x8B3CF0)
        self.assertEqual((m.r, m.hi, m.lo), (expected, hi, lo))
        self.assertEqual(m.get(node + 16, 4), 0)
        self.assertEqual(self.count(m), 0)
        self.assertFalse(any(address == gap.ENGINE_STACK + 0x3C for address, _ in m.reads))

    def test_postallocation_zero_preserves_original_delay_ra_and_never_accesses_tail(self):
        m = self.machine()
        m.r[29], m.r[2] = gap.ENGINE_STACK, 0
        m.put(gap.ENGINE_STACK + 0x24, gap.RETURN, 4)
        expected, hi, lo = m.r.copy(), m.hi, m.lo
        expected[31] = gap.RETURN
        m.reads.clear()
        m.writes.clear()
        m.run_at(0x8B3CE8, 0x8B3D2C)
        self.assertEqual((m.r, m.hi, m.lo), (expected, hi, lo))
        self.assertFalse(any(address == 16 for address, _ in m.reads))
        self.assertEqual(m.writes, [])

    def test_allocator_failures_keep_native_returns_and_do_not_invent_install(self):
        for failed, result, attempts in ((1, 0xFFFFFFFF, [16]), (2, 0, [16, 20])):
            with self.subTest(failed=failed):
                m = self.machine()
                m.fail_allocation = failed
                self.assertEqual(m.enqueue(), result)
                self.assertEqual(m.allocation_attempts, attempts)
                self.assertEqual(self.count(m), 0)
                self.assertEqual(m.queue(), [])
                self.assertFalse(m.freed)  # Original node-failure leak unchanged.

    def test_unknown_generic_caller_cannot_reuse_a_stale_identity(self):
        m = self.machine()
        m.enqueue()
        node, _ = m.queue()[0]
        m.consume()
        before = self.count(m)
        m.allocation = lambda size: node
        head = gap.INPUT  # Separate non-paint generic-list head fixture.
        m.put(head, 0, 4)
        m.r[29], m.r[31], m.r[4:7] = gap.ENGINE_STACK, gap.RETURN, [head, gap.NAME, 0x1234]
        m.run_at(0x8B3CC0, gap.RETURN)
        self.assertEqual(m.r[2], node)
        self.assertEqual(m.get(head, 4), node)
        self.assertEqual(m.get(node + 16, 4), 0)
        self.assertEqual(self.count(m), before)

    def test_all_addresses_reused_by_new_enqueue_still_have_new_explicit_ids(self):
        m = self.machine()
        m.enqueue()
        first = [(address, size) for address, size in m.queue_allocations]
        m.consume()
        reused = iter(address for address, _ in first)
        m.allocation = lambda size: next(reused)
        m.enqueue()
        self.assertEqual(m.queue_allocations[:2], m.queue_allocations[2:])
        self.assertEqual(m.get(first[1][0] + 16, 4), 5)
        m.consume()
        chains = self.journal(m)['chains']
        self.assertEqual([(chain['birth'], chain['install'], chain['callback']) for chain in chains],
                         [(1, 1, 4), (4, 5, 8)])
        self.assertEqual(m.callback_ids, [4, 8])
        self.assertTrue(all(chain['observation_complete'] for chain in chains))

    def test_synthetic_helper_uses_ordinary_rect_and_no_parent_carrier_or_node_tail(self):
        m = self.machine()
        for index, value in enumerate((1, 2, 8, 8)):
            m.put(gap.INPUT + index * 4, value, 4)
        m.r[29], m.r[31], m.r[4:7] = gap.ENGINE_STACK, gap.RETURN, [gap.ENGINE, gap.INPUT, 0]
        m.put(gap.ENGINE_STACK + 0x14, 0xDEADBEEF, 4)
        m.reads.clear()
        m.run_at(0x8B3FA0, gap.RETURN)
        self.assertEqual(self.count(m), 0)
        self.assertEqual(m.callback_ids, [0])
        self.assertEqual(len(m.paints), 1)
        self.assertFalse(any(address == gap.ENGINE_STACK + 0x14 for address, _ in m.reads))
        self.assertFalse(any(address == gap.ENGINE_STACK - 0xB8 + 0x14 for address, _ in m.reads))
        self.assertFalse(any(gap.INPUT + 16 <= address < gap.INPUT + 20 for address, _ in m.reads))

    def test_unknown_callback_gates_before_ancestor_carrier_reads(self):
        for ra, descriptor, engine, helper_ra in (
                (0x8B4998, None, gap.ENGINE, 0x8B4764),
                (0x8B40EC, gap.INPUT, gap.ENGINE, 0x8B4764),
                (0x8B40EC, None, gap.OWNER, 0x8B4764),
                (0x8B40EC, None, gap.ENGINE, 0x8B4A1C)):
            with self.subTest(ra=ra, descriptor=descriptor, engine=engine, helper_ra=helper_ra):
                m = self.machine()
                native_sp = gap.ENGINE_STACK - 0x38
                m.r[29], m.r[31], m.r[4], m.r[5], m.r[22] = (
                    gap.ENGINE_STACK, ra, engine, descriptor or native_sp + 0x90, gap.ENGINE)
                m.put(native_sp + 0xEC, helper_ra, 4)
                m.put(native_sp + 0x4C, 0xDEADBEEF, 4)
                expected, hi, lo = m.r.copy(), m.hi, m.lo
                expected[29] -= 0x38
                m.reads.clear()
                m.run_at(0x439EC0, 0x439EC8)
                self.assertEqual((m.r, m.hi, m.lo), (expected, hi, lo))
                self.assertEqual(m.get(native_sp + 0x14, 4), 0)
                self.assertFalse(any(address == native_sp + 0x4C for address, _ in m.reads))
                if ra != 0x8B40EC or descriptor is not None or engine != gap.ENGINE:
                    self.assertFalse(any(address == native_sp + 0xEC for address, _ in m.reads))

    def test_consumer_before_producer_return_is_not_rejected_or_fabricated(self):
        m = self.machine()
        partial = []

        def before_return(pc):
            if pc == 0x8B42F0 and not partial:
                saved, hi, lo = m.r.copy(), m.hi, m.lo
                m.consume(stack=gap.ENGINE_STACK - 0x800)
                partial.append(self.journal(m))
                m.r, m.hi, m.lo = saved, hi, lo

        m.before_instruction = before_return
        m.enqueue()
        chain = partial[0]['chains'][0]
        self.assertTrue(chain['observed_birth_to_callback_chain'])
        self.assertFalse(chain['producer_return_observed'])
        self.assertFalse(chain['observation_complete'])
        # This fixture keeps freed storage mapped. It makes NO native lease
        # or concurrent lifetime claim; only private journal causality is tested.
        self.assertTrue(self.journal(m)['chains'][0]['observation_complete'])

    def test_preexisting_full_flag_is_not_a_birth_and_does_not_delete_real_queue(self):
        m = self.machine()
        m.enqueue()
        before = self.count(m)
        node = m.queue()[0][0]
        m.enqueue(rectangle=None)
        m.enqueue(rectangle=None)
        self.assertEqual(self.count(m), before)
        self.assertEqual(m.queue()[0][0], node)
        self.assertEqual(m.allocation_attempts, [16, 20])
        self.assertEqual(m.get(gap.ENGINE + 0x3C, 4), 0x40000004)

    def test_changed_revision_records_old_request_without_relabelling_or_ui_authority(self):
        m = self.machine()
        m.enqueue()
        m.reset()
        m.consume()
        result = self.decode(m)
        chains = result['queue_transport_observation']['chains']
        self.assertEqual([chain['birth'] for chain in chains], [1, 4])
        self.assertTrue(all(chain['observed_birth_to_callback_chain'] for chain in chains))
        self.assertTrue(all(not chain['known_boundary_unchanged'] for chain in chains))
        self.assertTrue(all(not chain['request_freshness_proven'] for chain in chains))
        self.assertFalse(result['renderer_identity_associated'])
        self.assertFalse(result['autoscroll_authorized'])

    def test_unknown_zero_tail_is_ignored_but_invalid_nonzero_tail_faults_without_suppressing_native_work(self):
        for value in (0, 0x12345678):
            with self.subTest(value=value):
                m = self.machine()
                m.enqueue()
                node = m.queue()[0][0]
                m.put(node + 16, value, 4)
                m.consume()
                self.assertEqual(m.callback_ids, [0])
                self.assertEqual(len(m.paints), 1)
                self.assertEqual(m.get(gap.ENGINE + 0x34, 4), 0)
                self.assertIn(node, m.freed)
                if value:
                    self.assertEqual(self.count(m), 0xFFFFFFFF)
                    with self.assertRaises(ValueError):
                        self.decode(m)
                else:
                    self.assertEqual(self.count(m), 1)
                    self.assertEqual(self.journal(m)['chains'], [])

    def test_exhausted_faulted_birth_or_transport_journals_do_not_suppress_native_queue(self):
        for case in ('transport', 'birth', 'capacity'):
            with self.subTest(case=case):
                m = self.machine(transport_capacity=1) if case == 'capacity' else self.machine()
                if case != 'capacity':
                    m.put(m.meta[case + '_buffer'], 0xFFFFFFFF, 4)
                self.assertEqual(m.enqueue(), 0)
                node = m.queue()[0][0]
                if case != 'capacity':
                    self.assertEqual(m.get(node + 16, 4), 0)
                m.consume()
                self.assertEqual(m.callback_ids, [0])
                self.assertEqual(len(m.paints), 1)
                self.assertEqual(m.allocation_attempts, [16, 20])
                with self.assertRaises(ValueError):
                    self.decode(m)

    def test_prior_birth_image_is_byte_identical(self):
        image, _ = stage.previous.build(self.source)
        self.assertEqual(hashlib.sha256(image).hexdigest(),
                         '3f4d975087af7d31e2b60b6a0d6c5762585acd02658ed36cefb2152a78b79c7d')

    def test_exact_image_inventory_normalized_source_and_mutations(self):
        meta = verify(self.source, self.image, **CAPACITIES)
        self.assertEqual(len(stage.HOOKS), 33)
        self.assertTrue(meta['native_allocations_extended'])
        self.assertFalse(meta['allocation_outcomes_preserved'])
        golden, _ = stage.normalize_source(self.source)
        self.assertEqual(stage.build(golden, **CAPACITIES)[0], self.image)
        for pc in (0x8B3CCC, 0x8B3CE8, 0x8B42E8, 0x8B42EC, 0x8B475C, 0x8B4760, 0x439EC0):
            changed = bytearray(self.image)
            changed[pc - stage.BASE] ^= 1
            with self.subTest(pc=pc), self.assertRaises(ValueError):
                verify(self.source, changed, **CAPACITIES)

    def test_bad_inputs_active_modes_capacities_and_aliases_refused(self):
        for enabled in (True, 1, 0, None, 'yes'):
            with self.assertRaises(ValueError):
                stage.build(self.source, enable_reveal=enabled)
        for value in (0, -1, True, None, 1.5):
            with self.assertRaises(ValueError):
                stage.build(self.source, transport_capacity=value)
        for source in (self.image, self.source[:-1], bytes(len(self.source))):
            with self.assertRaises(ValueError):
                stage.build(source)
        regions = [self.meta[key] for key in ('buffer', 'row_buffer', 'contents_revision_buffer',
                                             'operation_buffer', 'scope_buffer', 'birth_buffer')]
        code, target = self.meta['code_base'], self.meta['transport_buffer']
        for address in (True, -4, target + 1, *regions, code, code - 4, 0xFFFFFFFC):
            with self.subTest(address=address), self.assertRaises(ValueError):
                stage.assemble(*regions, address, code, **CAPACITIES)


if __name__ == '__main__':
    unittest.main()
