#!/usr/bin/env python3
"""Execute the raw journal and its real private lineage validator together.

No native SQL/list/UI call is simulated by this leaf-core suite. Current
producer-frame/count inputs are bounded mapped fixtures. Shared LL/SC models
coherent allocator stores, not target hardware caches or object lifetime.
"""

import struct
import unittest

import folderfollow_reveal_lineage_mips as lineage
import reveal_lineage_rows_mips as rows
from test_folderfollow_reveal_guard_mips import GuardMachine


LINEAGE, CODE, RETURN = 0xBD4000, 0xC70000, 0xDEAD0000
LINEAGE_CAPACITY = 32
JOURNAL = LINEAGE + lineage.memory_bytes(LINEAGE_CAPACITY)
STACK, PRODUCER_SP, PARAMS, DESTINATION, STATEMENT = 0x2003000, 0x2100000, 0x2200000, 0x2300000, 0xDEAD4000
MASK = 0xFFFFFFFF


class Memory:
    def __init__(self, capacity=32):
        self.capacity = capacity
        self.regions = {}
        self.accesses = []
        self.version = 0
        self.map(LINEAGE, lineage.memory_bytes(LINEAGE_CAPACITY))
        self.map(JOURNAL, rows.memory_bytes(capacity))
        self.map(STACK - 0x1000, 0x2000)
        self.map(PRODUCER_SP, 0xB00)
        self.map(PARAMS, 16)
        self.map(DESTINATION, 16)

    def map(self, base, size):
        if any(max(base, old) < min(base + size, old + len(data))
               for old, data in self.regions.items()):
            raise AssertionError('overlapping memory fixture')
        self.regions[base] = bytearray(size)

    def region(self, address, size):
        if size not in (1, 2, 4) or address % size:
            raise AssertionError('unaligned access')
        for base, data in self.regions.items():
            if base <= address <= base + len(data) - size:
                return data, address - base
        raise AssertionError('unmapped access ' + hex(address))

    def read(self, address, size=4):
        data, offset = self.region(address, size)
        self.accesses.append(('read', address, size))
        return int.from_bytes(data[offset:offset + size], 'little')

    def write(self, address, value, size=4):
        data, offset = self.region(address, size)
        self.accesses.append(('write', address, size))
        data[offset:offset + size] = (value & ((1 << (8 * size)) - 1)).to_bytes(size, 'little')
        if address in (LINEAGE, JOURNAL):
            self.version += 1


class RowsMachine(GuardMachine):
    def __init__(self, shared=None, *, capacity=32):
        self.shared = shared if shared is not None else Memory(capacity)
        kernel, entries = lineage.build_lineage(LINEAGE, CODE, capacity=LINEAGE_CAPACITY)
        journal, labels = rows.assemble(LINEAGE, entries, JOURNAL, CODE + len(kernel),
                                        capacity=self.shared.capacity)
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

    def start(self, entry, *args):
        if self.pc != RETURN:
            raise AssertionError('context already running')
        for index, value in enumerate(args):
            self.r[4 + index] = value & MASK
        self.pc = self.labels[entry]
        self.delay_target = None
        self.steps = 0
        self.trace = []
        return self

    def step(self):
        if self.pc == RETURN:
            return False
        if not CODE <= self.pc < CODE + len(self.code) or self.pc % 4:
            raise AssertionError('unexpected transfer ' + hex(self.pc))
        self.steps += 1
        if self.steps > 20000:
            raise AssertionError('execution budget exceeded')
        word = self.words[(self.pc - CODE) // 4]
        self.trace.append((self.pc, word))
        op, rs, rt = word >> 26, (word >> 21) & 31, (word >> 16) & 31
        if self.delay_target is not None:
            if op in (2, 3, 4, 5) or (op == 0 and word & 63 in (8, 9)):
                raise AssertionError('control transfer in delay slot')
            target, self.delay_target = self.delay_target, None
            self.plain(word)
            self.pc = target
        elif op in (4, 5):
            taken = (self.r[rs] == self.r[rt]) == (op == 4)
            offset = word & 0xFFFF
            offset -= 0x10000 if offset & 0x8000 else 0
            self.delay_target = self.pc + 4 + offset * 4 if taken else self.pc + 8
            self.pc += 4
        elif op in (2, 3) or (op == 0 and word & 63 == 8):
            target = (((self.pc + 4) & 0xF0000000) | ((word & 0x3FFFFFF) << 2)
                      if op in (2, 3) else self.r[rs])
            if target != RETURN and not CODE <= target < CODE + len(self.code):
                raise AssertionError('external/native call ' + hex(target))
            if op == 3:
                self.r[31] = self.pc + 8
                self.calls.append(target)
            self.delay_target, self.pc = target, self.pc + 4
        else:
            self.plain(word)
            self.pc += 4
        return True

    def call(self, entry, *args):
        self.start(entry, *args)
        return self.run_to_return()

    def producer(self, *, frame=PRODUCER_SP, destination=DESTINATION, statement=STATEMENT,
                 offset=0, request=512):
        parent = 0
        for kind in (lineage.RENDER, lineage.BORROW, lineage.QUERY, lineage.PRODUCER):
            slot = self.call('lineage_reserve', kind, parent, 0x1111, 0x2222)
            if not slot:
                raise AssertionError('fixture lineage allocation failed')
            parent = self.r[3]
            for field, value in ((lineage.STACK, frame), (lineage.DEST, destination),
                                 (lineage.STMT, statement), (lineage.OFFSET, offset),
                                 (lineage.REQUEST, request)):
                self.shared.write(slot + field, value)
            self.shared.write(slot, lineage.MAGIC)
        self.shared.write(PRODUCER_SP + 0x18, parent)
        self.shared.write(PRODUCER_SP + 0xAD8, offset)
        self.metadata(statement, destination, 0, 0)
        return parent

    def metadata(self, statement=STATEMENT, destination=DESTINATION, ordinal=0, mode=0):
        for index, value in enumerate((statement, destination, ordinal, mode)):
            self.shared.write(PARAMS + index * 4, value)

    def path(self, value, *, terminated=True):
        encoded = value.encode('utf-16le', errors='surrogatepass')
        if len(encoded) > rows.PATH_BYTES:
            raise AssertionError('fixture path exceeds descriptor field')
        for index in range(0, len(encoded), 2):
            self.shared.write(PRODUCER_SP + 0x24 + index,
                              int.from_bytes(encoded[index:index + 2], 'little'), 2)
        if terminated and len(encoded) < rows.PATH_BYTES:
            self.shared.write(PRODUCER_SP + 0x24 + len(encoded), 0, 2)

    def capture(self, event=rows.ROW, result=0, frame=PRODUCER_SP):
        return self.call('capture', event, frame, result, PARAMS)

    @staticmethod
    def record_address(sequence):
        return JOURNAL + rows.HEADER + (sequence - 1) * rows.RECORD

    def record(self, sequence):
        data = self.shared.regions[JOURNAL]
        offset = rows.HEADER + (sequence - 1) * rows.RECORD
        return bytes(data[offset:offset + rows.RECORD])

    def field(self, sequence, offset):
        return self.shared.read(self.record_address(sequence) + offset)

    def assert_no_descriptor_or_count_reads(self, test):
        test.assertFalse(any(kind == 'read' and (address == DESTINATION + 12
                         or PRODUCER_SP + 0x24 <= address < PRODUCER_SP + 0x24 + 520
                         or address == PRODUCER_SP + 0x444)
                         for kind, address, _ in self.shared.accesses))


class RowsCoreTests(unittest.TestCase):
    def test_raw_row_exact_schema_parent_and_signed_bits(self):
        m = RowsMachine()
        token = m.producer(offset=3, request=500)
        m.metadata(ordinal=7)
        m.path('/storage/Show No Mercy/01.flac')
        m.shared.write(DESTINATION + 12, 8)
        m.shared.write(PRODUCER_SP + 0x444, -1)
        self.assertEqual(m.capture(result=-1), 0)
        expected = (rows.MAGIC, rows.ROW, token, 1, PRODUCER_SP, STATEMENT,
                    DESTINATION, 0, 3, 7, MASK, MASK, 0, 8, 1, 0)
        self.assertEqual(struct.unpack_from('<16I', m.record(1)), expected)
        self.assertEqual(m.record(1)[64:584].decode('utf-16le').rstrip('\0'),
                         '/storage/Show No Mercy/01.flac')
        self.assertEqual(m.record(1)[584:], bytes(8))
        self.assertEqual(m.shared.regions[JOURNAL][4:16], bytes(12))

    def test_four_events_preserve_raw_results_and_nonrow_never_reads_descriptor(self):
        m = RowsMachine()
        m.producer()
        m.path('a.flac')
        m.shared.write(PRODUCER_SP + 0x444, 0x80000000)
        results = (0, 101, 19, -1)
        for event, result in zip((rows.ROW, rows.TERMINAL, rows.RESET, rows.END), results):
            m.shared.accesses.clear()
            m.capture(event, result)
            self.assertEqual(m.field(event, rows.RESULT), result & MASK)
            self.assertEqual(m.field(event, rows.KIND), event)
            if event != rows.ROW:
                self.assertEqual(m.record(event)[rows.PATH:], bytes(rows.RECORD - rows.PATH))
                self.assertEqual(m.field(event, rows.CUE), 0)
                self.assertFalse(any(kind == 'read' and address in (PRODUCER_SP + 0x24, PRODUCER_SP + 0x444)
                                     for kind, address, _ in m.shared.accesses))

    def test_empty_terminal_and_error_end_are_raw_not_readiness(self):
        m = RowsMachine()
        m.producer(request=0)
        m.capture(rows.TERMINAL, 101)
        m.capture(rows.RESET, 0)
        m.capture(rows.END, 0)
        self.assertEqual(m.shared.read(JOURNAL), 3)
        m.capture(rows.END, -1)  # Duplicate/error deliberately remains evidence.
        self.assertEqual(m.shared.read(JOURNAL), 4)
        self.assertEqual(m.field(4, rows.RESULT), MASK)

    def test_path_lengths_bounded_truncation_and_no_read_past_260_units(self):
        for length in (0, 1, 258, 259, 260):
            m = RowsMachine()
            m.producer()
            m.path('x' * length, terminated=length < 260)
            m.shared.accesses.clear()
            m.capture()
            reads = [address for kind, address, size in m.shared.accesses
                     if kind == 'read' and size == 2]
            self.assertEqual(len(reads), min(length + 1, 260))
            self.assertLessEqual(max(reads), PRODUCER_SP + 0x24 + 518)
            self.assertEqual(m.field(1, rows.TRUNCATED), int(length == 260))
            self.assertEqual(m.record(1)[64:64 + min(length, 259) * 2],
                             ('x' * min(length, 259)).encode('utf-16le'))
            self.assertEqual(m.record(1)[64 + min(length, 259) * 2:584],
                             bytes(520 - min(length, 259) * 2))

    def test_raw_surrogate_and_signed_cue_are_not_silently_normalized(self):
        for cue in (0, -1, -0x80000000, 0x7FFFFFFF):
            m = RowsMachine()
            m.producer()
            m.path('\ud800x')
            m.shared.write(PRODUCER_SP + 0x444, cue)
            m.capture()
            self.assertEqual(m.field(1, rows.CUE), cue & MASK)
            self.assertEqual(m.record(1)[64:68], b'\x00\xd8x\x00')

    def test_unsupported_mode_precedes_unmapped_frame_or_destination_reads(self):
        for mode in (1, 15, MASK):
            m = RowsMachine()
            m.metadata(destination=0xBAD00000, mode=mode)
            m.shared.accesses.clear()
            m.capture(frame=0xBAD00000)
            self.assertEqual(m.shared.read(JOURNAL), 0)
            self.assertFalse(any(kind == 'read' and address >= 0xBAD00000
                                 for kind, address, _ in m.shared.accesses))
            m.assert_no_descriptor_or_count_reads(self)

    def test_zero_ticket_ignored_before_offset_descriptor_or_count_reads(self):
        m = RowsMachine()
        m.metadata(destination=0xBAD00000)
        m.shared.accesses.clear()
        m.capture()
        self.assertEqual(m.shared.read(JOURNAL), 0)
        self.assertNotIn(('read', PRODUCER_SP + 0xAD8, 4), m.shared.accesses)
        m.assert_no_descriptor_or_count_reads(self)

    def test_forged_unpublished_and_wrong_kind_producer_fault_both_ledgers(self):
        for bad in (1, 33, 0x80000000, MASK):
            m = RowsMachine()
            m.producer()
            m.shared.write(PRODUCER_SP + 0x18, bad)
            m.shared.accesses.clear()
            m.capture()
            self.assertEqual(m.shared.read(JOURNAL), rows.FAULT)
            self.assertEqual(m.shared.read(LINEAGE), lineage.FAULT)
            m.assert_no_descriptor_or_count_reads(self)
        m = RowsMachine()
        token = m.producer()
        m.shared.write(LINEAGE + lineage.HEADER + (token - 1) * lineage.RECORD, 0)
        m.shared.accesses.clear()
        m.capture()
        self.assertEqual(m.shared.read(JOURNAL), rows.FAULT)
        m.assert_no_descriptor_or_count_reads(self)

    def test_frame_statement_destination_offset_mismatch_before_native_payload_reads(self):
        for field, value in ((lineage.STACK, PRODUCER_SP + 8), (lineage.STMT, STATEMENT + 4),
                              (lineage.DEST, DESTINATION + 4), (lineage.OFFSET, 1)):
            m = RowsMachine()
            token = m.producer()
            slot = LINEAGE + lineage.HEADER + (token - 1) * lineage.RECORD
            m.shared.write(slot + field, value)
            m.shared.accesses.clear()
            m.capture()
            self.assertEqual(m.shared.read(JOURNAL), rows.FAULT)
            # The lineage record itself remains valid historical evidence.
            self.assertEqual(m.shared.read(LINEAGE), 4)
            m.assert_no_descriptor_or_count_reads(self)

    def test_current_ordinal_is_not_compared_to_original_request(self):
        m = RowsMachine()
        m.producer(request=512)
        for ordinal in (0, 7, MASK):
            m.metadata(ordinal=ordinal)
            m.capture(rows.END, ordinal)
        self.assertEqual(m.shared.read(JOURNAL), 3)
        self.assertEqual([m.field(index, rows.ORDINAL) for index in (1, 2, 3)], [0, 7, MASK])

    def test_duplicate_and_gap_events_get_new_ids_without_native_ready_claim(self):
        m = RowsMachine()
        m.producer()
        for ordinal in (0, 0, 5):
            m.metadata(ordinal=ordinal)
            m.capture()
        self.assertEqual([m.field(index, rows.SEQ) for index in (1, 2, 3)], [1, 2, 3])
        self.assertEqual([m.field(index, rows.ORDINAL) for index in (1, 2, 3)], [0, 0, 5])
        self.assertEqual(m.shared.read(JOURNAL), 3)

    def test_capacity_exhaustion_never_reuses_slot_or_erases_old_magic(self):
        m = RowsMachine(capacity=2)
        m.producer()
        m.capture(rows.TERMINAL, 101)
        m.capture(rows.RESET, 0)
        first, second = m.record(1), m.record(2)
        m.capture(rows.END, 0)
        self.assertEqual(m.shared.read(JOURNAL), rows.FAULT)
        self.assertEqual((m.record(1), m.record(2)), (first, second))
        m.capture()
        self.assertEqual((m.record(1), m.record(2)), (first, second))
        self.assertEqual(m.shared.read(LINEAGE), 4)

    def test_full_default_capacity_allocates_exact_nonoverlapping_records(self):
        m = RowsMachine(capacity=rows.DEFAULT_CAPACITY)
        for sequence in range(1, rows.DEFAULT_CAPACITY + 1):
            self.assertEqual(m.call('reserve'), m.record_address(sequence))
            self.assertEqual(m.r[3], sequence)
        self.assertEqual(m.call('reserve'), 0)
        self.assertEqual(m.shared.read(JOURNAL), rows.FAULT)

    def test_fault_at_each_capture_instruction_never_restores_allocator(self):
        template = RowsMachine()
        template.producer()
        template.path('x')
        initial = {base: bytes(data) for base, data in template.shared.regions.items()}
        template.capture()
        for boundary in range(len(template.trace) + 1):
            with self.subTest(boundary=boundary):
                shared = Memory()
                for base, data in initial.items():
                    shared.regions[base][:] = data
                a, invalidator = RowsMachine(shared), RowsMachine(shared)
                a.start('capture', rows.ROW, PRODUCER_SP, 0, PARAMS)
                for _ in range(boundary):
                    a.step()
                invalidator.call('invalidate')
                a.run_to_return()
                self.assertEqual(shared.read(JOURNAL), rows.FAULT)
                self.assertEqual(a.call('reserve'), 0)

    def test_bounded_sc_loss_fault_and_final_attempt_success(self):
        for failures in (7, 8):
            m = RowsMachine()
            m.producer()
            m.sc_attempts = 0
            m.sc_failures = failures
            m.capture(rows.END, 0)
            self.assertEqual(m.sc_attempts, 8)
            self.assertEqual(m.shared.read(JOURNAL), 1 if failures == 7 else rows.FAULT)
            self.assertEqual(m.field(1, rows.MAGIC_OFFSET), rows.MAGIC if failures == 7 else 0)

    def test_fault_between_reservation_ll_sc_cannot_be_erased(self):
        shared = Memory()
        a, invalidator = RowsMachine(shared), RowsMachine(shared)
        a.start('reserve').until('reserve_sc')
        invalidator.call('invalidate')
        self.assertEqual(a.run_to_return(), 0)
        self.assertEqual(shared.read(JOURNAL), rows.FAULT)

    def test_competing_reservations_are_distinct(self):
        shared = Memory()
        a, b = RowsMachine(shared), RowsMachine(shared)
        a.start('reserve').until('reserve_sc')
        b.start('reserve').until('reserve_sc')
        self.assertEqual(a.run_to_return(), a.record_address(1))
        self.assertEqual(b.run_to_return(), b.record_address(2))
        self.assertEqual((a.r[3], b.r[3]), (1, 2))

    def test_fault_before_publication_withholds_magic(self):
        for ledger in ('journal', 'lineage'):
            m = RowsMachine()
            m.producer()
            m.path('a')
            m.start('capture', rows.ROW, PRODUCER_SP, 0, PARAMS).until('capture_publish')
            m.shared.write(JOURNAL if ledger == 'journal' else LINEAGE, MASK)
            m.run_to_return()
            self.assertEqual(m.shared.read(JOURNAL), rows.FAULT)
            self.assertEqual(m.field(1, rows.MAGIC_OFFSET), 0)

    def test_fault_after_publication_keeps_magic_but_revokes_evidence_admission(self):
        m = RowsMachine()
        m.producer()
        m.capture()
        m.call('invalidate')
        self.assertEqual(m.field(1, rows.MAGIC_OFFSET), rows.MAGIC)
        self.assertEqual(m.shared.read(JOURNAL), rows.FAULT)
        m.shared.accesses.clear()
        m.capture()
        m.assert_no_descriptor_or_count_reads(self)

    def test_bad_event_state_and_nonfresh_slot_fault(self):
        for event in (0, 5, MASK):
            m = RowsMachine()
            m.metadata()
            m.capture(event)
            self.assertEqual(m.shared.read(JOURNAL), rows.FAULT)
        for state in (33, 0x80000000, MASK):
            m = RowsMachine()
            m.shared.write(JOURNAL, state)
            self.assertEqual(m.call('reserve'), 0)
            self.assertEqual(m.shared.read(JOURNAL), rows.FAULT)
        m = RowsMachine()
        m.shared.write(m.record_address(1), rows.MAGIC)
        self.assertEqual(m.call('reserve'), 0)
        self.assertEqual(m.shared.read(JOURNAL), rows.FAULT)

    def test_abi_and_only_expected_reads_writes_and_private_calls(self):
        for event in (rows.ROW, rows.TERMINAL, rows.RESET, rows.END):
            m = RowsMachine()
            m.producer()
            m.path('a')
            m.shared.accesses.clear()
            m.calls.clear()
            before, hi, lo = m.r.copy(), m.hi, m.lo
            m.capture(event, -1)
            for reg in (*range(16, 24), 26, 27, 28, 29, 30, 31):
                self.assertEqual(m.r[reg], before[reg], (event, reg))
            self.assertEqual((m.hi, m.lo), (hi, lo))
            self.assertEqual(m.calls, [m.labels['lineage_validate'], m.labels['reserve']])
            for kind, address, _ in m.shared.accesses:
                if kind == 'write':
                    self.assertTrue(JOURNAL <= address < JOURNAL + rows.memory_bytes(32)
                                    or STACK - rows.CALL_FRAME <= address < STACK)
                self.assertNotEqual(address, STATEMENT)

    def test_schema_layout_and_bad_configuration(self):
        self.assertEqual(rows.memory_bytes(), 16 + 592 * 1024)
        self.assertEqual(rows.MAGIC.to_bytes(4, 'little'), b'LROW')
        self.assertEqual(rows.PATH + rows.PATH_BYTES + 8, rows.RECORD)
        _, entries = lineage.build_lineage(LINEAGE, CODE, capacity=LINEAGE_CAPACITY)
        arguments = dict(lineage_address=LINEAGE, lineage_entries=entries,
                         journal_address=JOURNAL, code_base=CODE + 0x1000)
        for name, values in (('lineage_address', (True, -4, 1, 0x100000000, JOURNAL)),
                             ('lineage_entries', ({}, None, {'validate': 1}, {'validate': 0x10000000})),
                             ('journal_address', (True, -4, 1, 0xFFFFFFFC, LINEAGE, CODE + 0x1000)),
                             ('code_base', (True, -4, 1, 0xFFFFFFFC, 0x0FFFFFFC, JOURNAL)),
                             ('capacity', (True, 0, -1, rows.MAX_CAPACITY + 1))):
            for value in values:
                kwargs = dict(arguments)
                kwargs[name] = value
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    rows.assemble(**kwargs)

    def test_only_private_validate_call_and_no_unknown_instructions(self):
        kernel, entries = lineage.build_lineage(LINEAGE, CODE, capacity=LINEAGE_CAPACITY)
        start = CODE + len(kernel)
        code, labels = rows.assemble(LINEAGE, entries, JOURNAL, start, capacity=32)
        words = struct.unpack('<%dI' % (len(code) // 4), code)
        external_calls = []
        counter_stores = []
        for index, word in enumerate(words):
            pc, op, rs = start + index * 4, word >> 26, (word >> 21) & 31
            if op in (2, 3):
                target = ((pc + 4) & 0xF0000000) | ((word & 0x3FFFFFF) << 2)
                self.assertEqual(words[index + 1], 0)
                if not start <= target < start + len(code):
                    self.assertEqual(op, 3)
                    external_calls.append(target)
            elif op in (4, 5):
                delta = word & 0xFFFF
                delta -= 0x10000 if delta & 0x8000 else 0
                self.assertTrue(start <= pc + 4 + delta * 4 < start + len(code))
                self.assertEqual(words[index + 1], 0)
            elif op == 0:
                self.assertIn(word & 63, (0, 2, 8, 15, 0x21, 0x2B))
                if word & 63 == 8:
                    self.assertEqual(rs, 31)
            else:
                self.assertIn(op, (9, 11, 12, 13, 15, 0x23, 0x25, 0x29, 0x2B, 0x30, 0x38))
            if op in (0x2B, 0x38) and rs == 8 and word & 0xFFFF == 0:
                counter_stores.append((op, pc))
        self.assertEqual(external_calls, [entries['validate']])
        self.assertEqual(counter_stores, [(0x38, labels['reserve_sc']), (0x2B, labels['fault_store'])])


if __name__ == '__main__':
    unittest.main()
