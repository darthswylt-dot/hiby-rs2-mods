#!/usr/bin/env python3
"""Execute raw operation capture plus the actual private lineage validator."""

import struct
import unittest

import folderfollow_reveal_lineage_mips as lineage
import reveal_operation_journal_mips as operation
import test_reveal_lineage_rows_mips as row_harness


LINEAGE, CODE, RETURN = row_harness.LINEAGE, row_harness.CODE, row_harness.RETURN
LINEAGE_CAPACITY, STACK, PARAMS = 32, row_harness.STACK, row_harness.PARAMS
JOURNAL = LINEAGE + lineage.memory_bytes(LINEAGE_CAPACITY)
REVISION, WORKER, JOB, VIEW, PANEL, DEST = 0xBF8000, 0x2100000, 0xBAD10000, 0xBAD20000, 0xBAD30000, 0xBAD40000
MASK = 0xFFFFFFFF


class Memory(row_harness.Memory):
    def __init__(self, capacity=32):
        self.capacity, self.regions, self.accesses, self.version = capacity, {}, [], 0
        self.map(LINEAGE, lineage.memory_bytes(LINEAGE_CAPACITY))
        self.map(JOURNAL, operation.memory_bytes(capacity))
        self.map(REVISION, 16)
        self.map(STACK - 0x1000, 0x2000)
        self.map(PARAMS, 28)


class OperationMachine(row_harness.RowsMachine):
    def __init__(self, shared=None, *, capacity=32):
        self.shared = shared if shared is not None else Memory(capacity)
        kernel, entries = lineage.build_lineage(LINEAGE, CODE, capacity=LINEAGE_CAPACITY)
        journal, labels = operation.assemble(
            LINEAGE, entries, JOURNAL, REVISION, CODE + len(kernel), self.shared.capacity)
        self.code = kernel + journal
        self.labels = {'lineage_' + name: address for name, address in entries.items()}
        self.labels.update(labels)
        self.words = struct.unpack('<%dI' % (len(self.code) // 4), self.code)
        self.r = [0] + [0x11000000 + reg for reg in range(1, 32)]
        self.r[29], self.r[31] = STACK, RETURN
        self.hi, self.lo = 0x13579BDF, 0x2468ACE0
        self.reservation = None
        self.sc_failures = self.sc_attempts = 0
        self.pc, self.delay_target, self.steps = RETURN, None, 0
        self.trace, self.calls = [], []

    def borrow(self, *, worker=WORKER, job=JOB, view=VIEW, panel=PANEL):
        parent = 0
        for kind in (lineage.RENDER, lineage.BORROW):
            slot = self.call('lineage_reserve', kind, parent, view, panel)
            if not slot:
                raise AssertionError('fixture allocation failed')
            parent = self.r[3]
            for field, value in ((lineage.STACK, worker), (lineage.JOB, job)):
                self.shared.write(slot + field, value)
            self.shared.write(slot, lineage.MAGIC)
        self.metadata(job=job, view=view, panel=panel)
        return parent

    def metadata(self, *, job=JOB, site=0x48EC48, result=0, callee=0x48D280,
                 panel=PANEL, dest=DEST, view=VIEW):
        values = (job, site, result, callee, panel, dest, view)
        for index, value in enumerate(values):
            self.shared.write(PARAMS + index * 4, value)
        return tuple(value & MASK for value in values)

    def capture(self, kind=operation.FILL_BEGIN, borrow=2, worker=WORKER, params=PARAMS):
        return self.call('capture', kind, borrow, worker, params)

    @staticmethod
    def record_address(sequence):
        return JOURNAL + operation.HEADER + (sequence - 1) * operation.RECORD

    def record(self, sequence):
        data = self.shared.regions[JOURNAL]
        start = operation.HEADER + (sequence - 1) * operation.RECORD
        return bytes(data[start:start + operation.RECORD])


class OperationCoreTests(unittest.TestCase):
    def test_exact_schema_original_borrow_raw_results_and_reserved_zero(self):
        m = OperationMachine()
        borrow = m.borrow()
        m.metadata(result=-1)
        m.shared.write(REVISION, 19)
        self.assertEqual(m.capture(borrow=borrow), 0)
        self.assertEqual(struct.unpack('<16I', m.record(1)),
                         (operation.MAGIC, 1, borrow, 1, 1, JOB, WORKER,
                          0x48EC48, MASK, 0x48D280, PANEL, DEST, VIEW, 19, 0, 0))
        self.assertEqual(m.shared.regions[JOURNAL][4:16], bytes(12))

    def test_all_seven_kinds_are_raw_not_completion_or_phase_authority(self):
        m = OperationMachine()
        m.borrow()
        for kind in range(1, 8):
            m.metadata(result=MASK if kind % 2 else 0x80000000)
            m.shared.write(REVISION, kind - 1)
            m.capture(kind)
            words = struct.unpack('<16I', m.record(kind))
            self.assertEqual((words[1], words[2], words[3], words[13]), (kind, 2, kind, kind - 1))
            self.assertEqual(words[8], MASK if kind % 2 else 0x80000000)

    def test_duplicates_missing_begin_and_error_order_remain_raw_evidence(self):
        m = OperationMachine()
        m.borrow()
        for kind in (7, 6, 6, 2, 1):
            m.capture(kind)
        self.assertEqual(m.shared.read(JOURNAL), 5)
        self.assertEqual([m.field(i, operation.KIND) for i in range(1, 6)], [7, 6, 6, 2, 1])
        self.assertNotIn('finish', m.labels)
        self.assertNotIn('ready', m.labels)

    def test_zero_borrow_ignored_before_any_owned_metadata_or_private_lookup(self):
        m = OperationMachine()
        m.shared.accesses.clear()
        m.capture(kind=MASK, borrow=0, worker=0xBAD00000, params=0xBAD00000)
        reads = [(address, size) for kind, address, size in m.shared.accesses if kind == 'read']
        self.assertTrue(all(STACK - operation.CALL_FRAME <= address < STACK for address, _ in reads))
        self.assertEqual(m.shared.read(JOURNAL), 0)

    def test_invalid_kinds_and_metadata_alignment_fault_without_metadata_reads(self):
        for kind, params in ((0, PARAMS), (8, PARAMS), (MASK, PARAMS), (1, 0), (1, PARAMS + 1)):
            m = OperationMachine()
            m.borrow()
            m.shared.accesses.clear()
            m.capture(kind, params=params)
            self.assertEqual(m.shared.read(JOURNAL), operation.FAULT)
            self.assertFalse(any(kind == 'read' and PARAMS <= address < PARAMS + 28
                                 for kind, address, _ in m.shared.accesses))

    def test_forged_wrong_kind_or_unpublished_borrow_faults_validation(self):
        for token in (1, 3, 33, MASK, JOB):
            m = OperationMachine()
            m.borrow()
            m.capture(borrow=token)
            self.assertEqual(m.shared.read(JOURNAL), operation.FAULT)
            self.assertEqual(m.shared.read(LINEAGE), lineage.FAULT)
        m = OperationMachine()
        m.borrow()
        m.shared.write(LINEAGE + lineage.HEADER + lineage.RECORD, 0)
        m.capture()
        self.assertEqual(m.shared.read(JOURNAL), operation.FAULT)

    def test_exact_worker_and_job_mismatch_faults_without_native_reads(self):
        for worker, job in ((WORKER + 4, JOB), (WORKER, JOB + 4)):
            m = OperationMachine()
            m.borrow()
            m.metadata(job=job)
            m.capture(worker=worker)
            self.assertEqual(m.shared.read(JOURNAL), operation.FAULT)
            self.assertEqual(m.shared.read(LINEAGE), 2)

    def test_binding_requires_original_panel_and_view_not_new_pointer_match(self):
        for panel, view in ((PANEL + 4, VIEW), (PANEL, VIEW + 4)):
            m = OperationMachine()
            m.borrow()
            m.metadata(panel=panel, view=view)
            m.capture(operation.BIND_BEGIN)
            self.assertEqual(m.shared.read(JOURNAL), operation.FAULT)
        m = OperationMachine()
        m.borrow()
        m.metadata(panel=0, view=0, dest=MASK)
        m.capture(operation.BIND_RETURN)  # Other event semantics belong to decoder.
        self.assertEqual(m.shared.read(JOURNAL), 1)

    def test_revision_zero_max_and_malformed_high_bits(self):
        for value in (0, 1, 0x7FFFFFFF):
            m = OperationMachine()
            m.borrow()
            m.shared.write(REVISION, value)
            m.capture()
            self.assertEqual(m.field(1, operation.REVISION), value)
        for value in (0x80000000, 0xFFFFFFFE, MASK):
            m = OperationMachine()
            m.borrow()
            m.shared.write(REVISION, value)
            m.capture()
            self.assertEqual(m.shared.read(JOURNAL), operation.FAULT)
            self.assertEqual(m.record(1), bytes(operation.RECORD))

    def test_owned_metadata_copied_once_and_frozen_before_allocation(self):
        m = OperationMachine()
        m.borrow()
        before = m.metadata(result=23)
        m.shared.accesses.clear()
        m.start('capture', 1, 2, WORKER, PARAMS).until('reserve_ll')
        m.metadata(result=99, site=0)
        m.run_to_return()
        words = struct.unpack('<16I', m.record(1))
        self.assertEqual((words[5], *words[7:13]), before)
        for offset in range(0, 28, 4):
            self.assertEqual(m.shared.accesses.count(('read', PARAMS + offset, 4)), 1)

    def test_later_revision_is_historical_not_a_same_revision_gate(self):
        m = OperationMachine()
        m.borrow()
        m.shared.write(REVISION, 3)
        m.start('capture', 1, 2, WORKER, PARAMS).until('capture_publish')
        m.shared.write(REVISION, 4)
        m.run_to_return()
        self.assertEqual(m.field(1, operation.REVISION), 3)
        self.assertEqual(m.shared.read(JOURNAL), 1)

    def test_fault_before_publication_keeps_magic_zero(self):
        for address in (LINEAGE, JOURNAL, REVISION):
            m = OperationMachine()
            m.borrow()
            m.start('capture', 1, 2, WORKER, PARAMS).until('capture_publish')
            m.shared.write(address, MASK)
            m.run_to_return()
            self.assertEqual(m.field(1, operation.MAGIC_OFFSET), 0)
            self.assertEqual(m.shared.read(JOURNAL), operation.FAULT)

    def test_capacity_exact_then_permanent_exhaustion_no_reuse(self):
        for capacity in (1, 2, 32, 1024):
            m = OperationMachine(capacity=capacity)
            m.borrow()
            for sequence in range(1, capacity + 1):
                m.capture()
                self.assertEqual(m.field(sequence, operation.SEQ), sequence)
            m.capture()
            self.assertEqual(m.shared.read(JOURNAL), operation.FAULT)
            first = m.record(1)
            m.capture()
            self.assertEqual(m.record(1), first)

    def test_sc_retry_budget_last_success_and_competing_reservations(self):
        for failures in (7, 8):
            m = OperationMachine()
            m.borrow()
            m.sc_attempts = 0
            m.sc_failures = failures
            m.capture()
            self.assertEqual(m.sc_attempts, 8)
            self.assertEqual(m.shared.read(JOURNAL), 1 if failures == 7 else operation.FAULT)
        shared = Memory()
        a, other = OperationMachine(shared), OperationMachine(shared)
        a.start('reserve').until('reserve_sc')
        other.start('reserve').until('reserve_sc')
        self.assertEqual(a.run_to_return(), a.record_address(1))
        self.assertEqual(other.run_to_return(), other.record_address(2))
        self.assertEqual(shared.read(JOURNAL), 2)

    def test_invalidation_at_every_capture_instruction_never_erases_fault(self):
        probe = OperationMachine()
        probe.borrow()
        probe.capture()
        for boundary in range(len(probe.trace) + 1):
            with self.subTest(boundary=boundary):
                shared = Memory()
                a, invalidator = OperationMachine(shared), OperationMachine(shared)
                a.borrow()
                a.start('capture', 1, 2, WORKER, PARAMS)
                for _ in range(boundary):
                    a.step()
                invalidator.call('invalidate')
                a.run_to_return()
                self.assertEqual(shared.read(JOURNAL), operation.FAULT)
                self.assertEqual(a.call('reserve'), 0)

    def test_abi_and_all_reads_are_private_owned_metadata_or_own_stack(self):
        for entry, args in (('capture', (1, 2, WORKER, PARAMS)),
                            ('capture', (4, 2, WORKER, PARAMS)),
                            ('capture', (1, MASK, WORKER, PARAMS)),
                            ('reserve', ()), ('invalidate', ())):
            m = OperationMachine()
            m.borrow()
            before, hi, lo = m.r.copy(), m.hi, m.lo
            m.shared.accesses.clear()
            m.call(entry, *args)
            for reg in (*range(16, 24), 26, 27, 28, 29, 30, 31):
                self.assertEqual(m.r[reg], before[reg], (entry, reg))
            self.assertEqual((m.hi, m.lo), (hi, lo))
            self.assertTrue(all(address < 0xBAD00000 for _, address, _ in m.shared.accesses))
            self.assertFalse(any(address == WORKER for _, address, _ in m.shared.accesses))

    def test_magic_is_last_record_write_and_only_sticky_plain_allocator_store(self):
        m = OperationMachine()
        m.borrow()
        m.shared.accesses.clear()
        m.capture()
        writes = [(address, size) for kind, address, size in m.shared.accesses
                  if kind == 'write' and m.record_address(1) <= address < m.record_address(2)]
        self.assertEqual(writes[-1], (m.record_address(1), 4))
        stores = [(i, word >> 26) for i, word in enumerate(m.words)
                  if word >> 26 in (0x2B, 0x38) and (word >> 21) & 31 == 8
                  and word & 0xFFFF == 0 and CODE + 4 * i >= m.labels['capture']]
        self.assertEqual([op for _, op in stores], [0x38, 0x2B])
        self.assertEqual(CODE + stores[-1][0] * 4, m.labels['fault_store'])

    def test_only_private_validator_external_to_journal_no_native_calls(self):
        m = OperationMachine()
        start = (m.labels['capture'] - CODE) // 4
        for index in range(start, len(m.words)):
            word, pc = m.words[index], CODE + index * 4
            op, rs = word >> 26, (word >> 21) & 31
            if op in (2, 3):
                target = ((pc + 4) & 0xF0000000) | ((word & 0x3FFFFFF) << 2)
                self.assertTrue(m.labels['capture'] <= target < CODE + len(m.code)
                                or target == m.labels['lineage_validate'])
                self.assertEqual(m.words[index + 1], 0)
            if op == 0:
                self.assertIn(word & 63, (0, 2, 8, 15, 0x21, 0x2B))
                if word & 63 == 8:
                    self.assertEqual(rs, 31)

    def test_layout_types_wrap_overlap_and_validator_region(self):
        kernel, entries = lineage.build_lineage(LINEAGE, CODE)
        defaults = dict(lineage_address=LINEAGE, lineage_entries=entries,
                        journal_address=JOURNAL, revision_address=REVISION,
                        code_base=CODE + len(kernel))
        self.assertEqual(operation.memory_bytes(), 65552)
        self.assertEqual(operation.MAGIC.to_bytes(4, 'little'), b'LOPR')
        for name, values in (
                ('capacity', (0, -1, True, 1.0, operation.MAX_CAPACITY + 1)),
                ('lineage_address', (True, 1, 0xFFFFFFFC, JOURNAL, REVISION)),
                ('journal_address', (True, 1, 0xFFFFFFFC, LINEAGE, REVISION)),
                ('revision_address', (True, 1, 0xFFFFFFFC, JOURNAL - 4, LINEAGE - 4)),
                ('code_base', (True, 1, 0xFFFFFFFC, LINEAGE, JOURNAL, REVISION, 0x1C700000)),
                ('lineage_entries', ({}, None, {'validate': JOURNAL}, {'validate': True}))):
            for value in values:
                args = dict(defaults)
                args[name] = value
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    operation.assemble(**args)
        for bad in (0, -1, True, 1.0, operation.MAX_CAPACITY + 1):
            with self.assertRaises(ValueError):
                operation.memory_bytes(bad)


if __name__ == '__main__':
    unittest.main()
