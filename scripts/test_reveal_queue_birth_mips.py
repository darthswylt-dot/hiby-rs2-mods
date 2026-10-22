#!/usr/bin/env python3
"""Execute the emitted queue journal; no native queue or pointer is mapped."""

import struct
import unittest

import reveal_queue_birth_mips as queue
import test_reveal_lineage_rows_mips as harness


CODE, RETURN, STACK, PARAMS = harness.CODE, harness.RETURN, harness.STACK, harness.PARAMS
JOURNAL, REVISION, SCOPE = 0xBD4000, 0xBF8000, 0xBF8010
ENGINE, INPUT, COPY, METADATA, FRAME = 0xBAD10000, 0xBAD20000, 0xBAD30000, 0x87654321, 0xBAD40000
MASK = 0xFFFFFFFF


class Memory(harness.Memory):
    def __init__(self, capacity=32):
        self.capacity, self.regions, self.accesses, self.version = capacity, {}, [], 0
        self.map(JOURNAL, queue.memory_bytes(capacity))
        self.map(REVISION, 16)
        self.map(SCOPE, 16)
        self.map(STACK - 0x1000, 0x2000)
        self.map(PARAMS, 28)

    def write(self, address, value, size=4):
        super().write(address, value, size)
        self.version += 1


class QueueMachine(harness.RowsMachine):
    def __init__(self, shared=None, *, capacity=32):
        self.shared = shared if shared is not None else Memory(capacity)
        self.code, self.labels = queue.assemble(JOURNAL, REVISION, SCOPE, CODE,
                                               self.shared.capacity)
        self.words = struct.unpack('<%dI' % (len(self.code) // 4), self.code)
        self.r = [0] + [0x11000000 + reg for reg in range(1, 32)]
        self.r[29], self.r[31] = STACK, RETURN
        self.hi, self.lo = 0x13579BDF, 0x2468ACE0
        self.reservation = None
        self.sc_failures = self.sc_attempts = 0
        self.pc, self.delay_target, self.steps = RETURN, None, 0
        self.trace, self.calls = [], []

    def metadata(self, *, engine=ENGINE, input=INPUT, copy=0, metadata=METADATA,
                 frame=FRAME, site=queue.BIRTH_SITE, result=0):
        values = (engine, input, copy, metadata, frame, site, result)
        for index, value in enumerate(values):
            self.shared.write(PARAMS + 4 * index, value)
        return tuple(value & MASK for value in values)

    def capture(self, kind=queue.BIRTH, parent=0, params=PARAMS):
        return self.call('capture', kind, parent, params)

    def birth(self, **kwargs):
        self.metadata(**kwargs)
        return self.capture()

    def enqueue(self, parent=1, **kwargs):
        self.metadata(copy=COPY, site=queue.ENQUEUE_SITE, **kwargs)
        return self.capture(queue.ENQUEUE_BEGIN, parent)

    def returned(self, parent=2, **kwargs):
        self.metadata(copy=COPY, site=queue.RETURN_SITE, **kwargs)
        return self.capture(queue.RETURN, parent)

    @staticmethod
    def record_address(sequence):
        return JOURNAL + queue.HEADER + (sequence - 1) * queue.RECORD

    def record(self, sequence):
        start = queue.HEADER + (sequence - 1) * queue.RECORD
        return bytes(self.shared.regions[JOURNAL][start:start + queue.RECORD])


class QueueCoreTests(unittest.TestCase):
    def test_exact_three_records_root_and_raw_result_schema(self):
        m = QueueMachine()
        m.shared.write(REVISION, 5)
        m.shared.write(SCOPE, 0x10002)
        self.assertEqual(m.birth(), 1)
        m.shared.write(REVISION, 6)
        self.assertEqual(m.enqueue(), 2)
        self.assertEqual(m.returned(result=-1), 3)
        for sequence, kind, parent, copy, site, result, revision in (
                (1, 1, 0, 0, queue.BIRTH_SITE, 0, 5),
                (2, 2, 1, COPY, queue.ENQUEUE_SITE, 0, 6),
                (3, 3, 2, COPY, queue.RETURN_SITE, MASK, 6)):
            self.assertEqual(struct.unpack('<16I', m.record(sequence)),
                             (queue.MAGIC, kind, parent, 1, sequence, ENGINE,
                              INPUT, copy, METADATA, FRAME, site, result,
                              revision, 0x10002, 0, 0))
        self.assertEqual(m.shared.regions[JOURNAL][4:16], bytes(12))

    def test_zero_parent_descendants_ignored_before_metadata_read(self):
        for kind in (queue.ENQUEUE_BEGIN, queue.RETURN):
            m = QueueMachine()
            m.shared.accesses.clear()
            self.assertEqual(m.capture(kind, 0, 0xBAD00000), 0)
            self.assertEqual(m.shared.read(JOURNAL), 0)
            self.assertFalse(any(address >= 0xBAD00000 for _, address, _ in m.shared.accesses))

    def test_unsupported_kind_and_bad_owned_block_fault_before_metadata_reads(self):
        for kind, parent, params in ((0, 0, PARAMS), (4, 0, PARAMS), (MASK, 0, PARAMS),
                                     (1, 1, PARAMS), (1, 0, 0), (1, 0, PARAMS + 1)):
            m = QueueMachine()
            m.shared.accesses.clear()
            self.assertEqual(m.capture(kind, parent, params), 0)
            self.assertEqual(m.shared.read(JOURNAL), queue.FAULT)
            self.assertFalse(any(access == 'read' and PARAMS <= address < PARAMS + 28
                                 for access, address, _ in m.shared.accesses))

    def test_birth_scalar_protocol_faults(self):
        cases = ({'engine': 0}, {'engine': ENGINE + 1}, {'input': 0},
                 {'input': INPUT + 2}, {'frame': 0}, {'frame': FRAME + 1},
                 {'copy': COPY}, {'result': 1}, {'site': queue.BIRTH_SITE + 4})
        for changes in cases:
            with self.subTest(changes=changes):
                m = QueueMachine()
                self.assertEqual(m.birth(**changes), 0)
                self.assertEqual(m.shared.read(JOURNAL), queue.FAULT)

    def test_enqueue_has_exact_parent_binding_and_copy_protocol(self):
        cases = ({'engine': ENGINE + 4}, {'input': INPUT + 4},
                 {'metadata': METADATA + 1}, {'frame': FRAME + 4},
                 {'copy': 0}, {'copy': COPY + 1}, {'result': 1},
                 {'site': queue.ENQUEUE_SITE + 4})
        for changes in cases:
            m = QueueMachine()
            m.birth()
            args = dict(copy=COPY, site=queue.ENQUEUE_SITE)
            args.update(changes)
            m.metadata(**args)
            self.assertEqual(m.capture(queue.ENQUEUE_BEGIN, 1), 0)
            self.assertEqual(m.shared.read(JOURNAL), queue.FAULT)

    def test_return_binds_exact_copy_and_all_inherited_scalars(self):
        for changes in ({'engine': ENGINE + 4}, {'input': INPUT + 4},
                        {'metadata': 0}, {'frame': FRAME + 4}, {'copy': COPY + 4},
                        {'site': queue.RETURN_SITE + 4}):
            m = QueueMachine()
            m.birth()
            m.enqueue()
            args = dict(copy=COPY, site=queue.RETURN_SITE, result=7)
            args.update(changes)
            m.metadata(**args)
            self.assertEqual(m.capture(queue.RETURN, 2), 0)
            self.assertEqual(m.shared.read(JOURNAL), queue.FAULT)

    def test_actual_append_result_is_not_a_success_gate(self):
        for result in (0, 1, 0x7FFFFFFF, 0x80000000, MASK):
            m = QueueMachine()
            m.birth()
            m.enqueue()
            self.assertEqual(m.returned(result=result), 3)
            self.assertEqual(m.field(3, queue.RESULT), result)

    def test_wrong_kind_out_of_range_unpublished_and_foreign_parent_fault(self):
        for kind, parent in ((2, 2), (2, 33), (2, MASK), (2, ENGINE), (3, 1)):
            m = QueueMachine()
            m.birth()
            m.metadata(copy=COPY, site=queue.ENQUEUE_SITE if kind == 2 else queue.RETURN_SITE)
            self.assertEqual(m.capture(kind, parent), 0)
            self.assertEqual(m.shared.read(JOURNAL), queue.FAULT)
        m = QueueMachine()
        m.birth()
        m.shared.write(m.record_address(1), 0)
        self.assertEqual(m.enqueue(), 0)
        self.assertEqual(m.shared.read(JOURNAL), queue.FAULT)

    def test_parent_root_and_published_binding_corruption_faults(self):
        for slot, field, value in ((1, queue.ORIGIN, 2), (1, queue.PARENT, 1),
                                   (1, queue.SEQ, 2), (1, queue.SITE, 0),
                                   (1, queue.INPUT, 0), (1, queue.RESERVED[0], 1),
                                   (2, queue.ORIGIN, 2), (2, queue.PARENT, 2),
                                   (2, queue.ENGINE, ENGINE + 4), (2, queue.COPY, 0),
                                   (2, queue.RESULT, 1), (2, queue.RESERVED[1], 1)):
            m = QueueMachine()
            m.birth()
            m.enqueue()
            m.shared.write(m.record_address(slot) + field, value)
            self.assertEqual(m.returned(), 0)
            self.assertEqual(m.shared.read(JOURNAL), queue.FAULT)

    def test_revision_zero_max_and_scope_busy_are_valid_historical_samples(self):
        for revision in (0, 1, 0x7FFFFFFF):
            for scope in (0, 1, 0x10001, 0x7FFF7FFF, 0x7FFFFFFF):
                m = QueueMachine()
                m.shared.write(REVISION, revision)
                m.shared.write(SCOPE, scope)
                self.assertEqual(m.birth(), 1)
                self.assertEqual(m.field(1, queue.REVISION), revision)
                self.assertEqual(m.field(1, queue.SCOPE), scope)

    def test_malformed_revision_or_scope_faults_before_reservation(self):
        for address, value in ((REVISION, 0x80000000), (REVISION, MASK),
                               (SCOPE, MASK), (SCOPE, 0x80000000),
                               (SCOPE, 0x10000), (SCOPE, 0x20001)):
            m = QueueMachine()
            m.shared.write(address, value)
            self.assertEqual(m.birth(), 0)
            self.assertEqual(m.shared.read(JOURNAL), queue.FAULT)
            self.assertEqual(m.record(1), bytes(queue.RECORD))

    def test_samples_freeze_but_later_valid_revision_or_scope_does_not_gate(self):
        m = QueueMachine()
        m.metadata()
        m.shared.write(REVISION, 3)
        m.shared.write(SCOPE, 0x10002)
        m.start('capture', 1, 0, PARAMS).until('capture_publish')
        m.shared.write(REVISION, 4)
        m.shared.write(SCOPE, 2)
        self.assertEqual(m.run_to_return(), 1)
        self.assertEqual((m.field(1, queue.REVISION), m.field(1, queue.SCOPE)), (3, 0x10002))

    def test_owned_metadata_is_copied_once_before_reservation(self):
        m = QueueMachine()
        before = m.metadata()
        m.shared.accesses.clear()
        m.start('capture', 1, 0, PARAMS).until('reserve_ll')
        m.metadata(input=INPUT + 4, metadata=0)
        self.assertEqual(m.run_to_return(), 1)
        words = struct.unpack('<16I', m.record(1))
        self.assertEqual(words[5:12], before)
        for offset in range(0, 28, 4):
            self.assertEqual(m.shared.accesses.count(('read', PARAMS + offset, 4)), 1)

    def test_duplicates_are_raw_evidence_not_reused_identity(self):
        m = QueueMachine()
        self.assertEqual(m.birth(), 1)
        self.assertEqual(m.enqueue(), 2)
        self.assertEqual(m.enqueue(), 3)
        self.assertEqual(m.returned(parent=2), 4)
        self.assertEqual(m.returned(parent=2), 5)
        self.assertEqual(m.shared.read(JOURNAL), 5)
        self.assertEqual([m.field(i, queue.SEQ) for i in range(1, 6)], list(range(1, 6)))
        self.assertNotIn('ready', m.labels)
        self.assertNotIn('reset', m.labels)

    def test_distinct_births_with_equal_native_addresses_keep_exact_parent_identity(self):
        m = QueueMachine()
        self.assertEqual(m.birth(), 1)
        self.assertEqual(m.birth(), 2)
        self.assertEqual(m.enqueue(parent=1), 3)
        self.assertEqual(m.enqueue(parent=2), 4)
        self.assertEqual(m.returned(parent=4), 5)
        self.assertEqual(m.returned(parent=3), 6)
        self.assertEqual([m.field(i, queue.ORIGIN) for i in range(1, 7)],
                         [1, 2, 1, 2, 2, 1])
        self.assertEqual([m.field(i, queue.PARENT) for i in range(1, 7)],
                         [0, 0, 1, 2, 4, 3])

    def test_paused_issued_parent_is_not_guessed_from_matching_native_scalars(self):
        shared = Memory()
        first, other = QueueMachine(shared), QueueMachine(shared)
        first.metadata()
        first.start('capture', 1, 0, PARAMS).until('capture_publish')
        self.assertEqual(shared.read(JOURNAL), 1)
        self.assertEqual(first.field(1, queue.MAGIC_OFFSET), 0)
        self.assertEqual(other.enqueue(parent=1), 0)
        self.assertEqual(shared.read(JOURNAL), queue.FAULT)
        self.assertEqual(first.run_to_return(), 0)
        self.assertEqual(first.field(1, queue.MAGIC_OFFSET), 0)

    def test_capacity_exact_and_permanent_loss_never_reuses_history(self):
        for capacity in (1, 2, 32, 1024):
            m = QueueMachine(capacity=capacity)
            for sequence in range(1, capacity + 1):
                self.assertEqual(m.birth(), sequence)
            first = m.record(1)
            self.assertEqual(m.birth(), 0)
            self.assertEqual(m.shared.read(JOURNAL), queue.FAULT)
            self.assertEqual(m.birth(), 0)
            self.assertEqual(m.record(1), first)

    def test_bounded_sc_retry_last_success_and_competing_allocations(self):
        for failures in (7, 8):
            m = QueueMachine()
            m.sc_failures = failures
            self.assertEqual(m.birth(), 1 if failures == 7 else 0)
            self.assertEqual(m.sc_attempts, 8)
            self.assertEqual(m.shared.read(JOURNAL), 1 if failures == 7 else queue.FAULT)
        shared = Memory()
        first, second = QueueMachine(shared), QueueMachine(shared)
        first.start('reserve').until('reserve_sc')
        second.start('reserve').until('reserve_sc')
        self.assertEqual(first.run_to_return(), first.record_address(1))
        self.assertEqual(second.run_to_return(), second.record_address(2))
        self.assertEqual(shared.read(JOURNAL), 2)

    def test_global_fault_before_magic_leaves_unpublished_slot(self):
        for address in (JOURNAL, REVISION, SCOPE):
            m = QueueMachine()
            m.metadata()
            m.start('capture', 1, 0, PARAMS).until('capture_publish')
            m.shared.write(address, MASK)
            self.assertEqual(m.run_to_return(), 0)
            self.assertEqual(m.field(1, queue.MAGIC_OFFSET), 0)
            self.assertEqual(m.shared.read(JOURNAL), queue.FAULT)

    def test_fault_at_every_capture_instruction_cannot_be_erased(self):
        probe = QueueMachine()
        probe.birth()
        for boundary in range(len(probe.trace) + 1):
            shared = Memory()
            m, invalidator = QueueMachine(shared), QueueMachine(shared)
            m.metadata()
            m.start('capture', 1, 0, PARAMS)
            for _ in range(boundary):
                m.step()
            invalidator.call('invalidate')
            m.run_to_return()
            self.assertEqual(shared.read(JOURNAL), queue.FAULT, boundary)
            self.assertEqual(m.call('reserve'), 0)

    def test_abi_and_only_private_owned_or_own_stack_accesses(self):
        for entry, args in (('capture', (1, 0, PARAMS)), ('capture', (2, 1, PARAMS)),
                            ('validate', (1, 1)), ('validate', (MASK, 2)),
                            ('reserve', ()), ('invalidate', ())):
            m = QueueMachine()
            m.birth()
            m.metadata(copy=COPY, site=queue.ENQUEUE_SITE)
            before, hi, lo = m.r.copy(), m.hi, m.lo
            m.shared.accesses.clear()
            m.call(entry, *args)
            for register in (*range(16, 24), 26, 27, 28, 29, 30, 31):
                self.assertEqual(m.r[register], before[register], (entry, register))
            self.assertEqual((m.hi, m.lo), (hi, lo))
            self.assertFalse(any(address >= 0xBAD00000 for _, address, _ in m.shared.accesses))

    def test_magic_last_and_allocator_plain_store_is_only_terminal_fault(self):
        m = QueueMachine()
        m.metadata()
        m.shared.accesses.clear()
        m.capture()
        writes = [(address, size) for access, address, size in m.shared.accesses
                  if access == 'write' and m.record_address(1) <= address < m.record_address(2)]
        self.assertEqual(writes[-1], (m.record_address(1), 4))
        stores = [(index, word >> 26) for index, word in enumerate(m.words)
                  if word >> 26 in (0x2B, 0x38) and (word >> 21) & 31 == 8
                  and word & 0xFFFF == 0]
        self.assertEqual([op for _, op in stores], [0x38, 0x2B])
        self.assertEqual(CODE + stores[-1][0] * 4, m.labels['fault_store'])

    def test_no_external_calls_and_all_delay_slots_explicit_nop(self):
        m = QueueMachine()
        for index, word in enumerate(m.words):
            op, rs = word >> 26, (word >> 21) & 31
            if op in (2, 3):
                pc = CODE + index * 4
                target = ((pc + 4) & 0xF0000000) | ((word & 0x3FFFFFF) << 2)
                self.assertTrue(CODE <= target < CODE + len(m.code))
                self.assertEqual(m.words[index + 1], 0)
            if op == 0 and word & 63 == 8:
                self.assertEqual(rs, 31)
                self.assertEqual(m.words[index + 1], 0)

    def test_layout_types_wrap_overlap_and_jump_region(self):
        self.assertEqual(queue.memory_bytes(), 65552)
        self.assertEqual(queue.MAGIC.to_bytes(4, 'little'), b'LQBR')
        defaults = dict(journal_address=JOURNAL, revision_address=REVISION,
                        scope_address=SCOPE, code_base=CODE)
        for name, values in (
                ('capacity', (0, -1, True, 1.0, queue.MAX_CAPACITY + 1)),
                ('journal_address', (True, 1, 0xFFFFFFFC, REVISION, SCOPE)),
                ('revision_address', (True, 1, 0xFFFFFFFC, JOURNAL, SCOPE)),
                ('scope_address', (True, 1, 0xFFFFFFFC, JOURNAL, REVISION)),
                ('code_base', (True, 1, 0xFFFFFFFC, JOURNAL, REVISION, SCOPE, 0x0FFFFF00))):
            for value in values:
                args = dict(defaults)
                args[name] = value
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    queue.assemble(**args)
        for value in (0, -1, True, 1.0, queue.MAX_CAPACITY + 1):
            with self.assertRaises(ValueError):
                queue.memory_bytes(value)


if __name__ == '__main__':
    unittest.main()
