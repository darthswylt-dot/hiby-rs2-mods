#!/usr/bin/env python3
"""Execute transport with the real private birth core, no native objects mapped."""

import struct
import unittest

import reveal_queue_birth_mips as birth
import reveal_queue_transport_mips as transport
import test_reveal_lineage_rows_mips as harness


CODE, RETURN, STACK, PARAMS = harness.CODE, harness.RETURN, harness.STACK, harness.PARAMS
BIRTH, JOURNAL, REVISION, SCOPE = 0xBD4000, 0xBE8000, 0xBFA000, 0xBFA010
BIRTH_CAPACITY = 32
ENGINE, INPUT, COPY, METADATA, NODE = (
    0xBAD10000, 0xBAD20000, 0xBAD30000, 0x87654321, 0xBAD50000)
UPSTREAM, BORROW_FRAME = 0xBAD40000, 0xBAD60000
INSTALL_FRAME = UPSTREAM - 0x28
HELPER_FRAME, CALLBACK_FRAME = BORROW_FRAME - 0xB8, BORROW_FRAME - 0xB8 - 0x38
MASK = 0xFFFFFFFF


class Memory(harness.Memory):
    def __init__(self, capacity=32):
        self.capacity, self.regions, self.accesses, self.version = capacity, {}, [], 0
        self.map(BIRTH, birth.memory_bytes(BIRTH_CAPACITY))
        self.map(JOURNAL, transport.memory_bytes(capacity))
        self.map(REVISION, 16)
        self.map(SCOPE, 16)
        self.map(STACK - 0x1000, 0x2000)
        self.map(PARAMS, 28)

    def write(self, address, value, size=4):
        super().write(address, value, size)
        self.version += 1


class TransportMachine(harness.RowsMachine):
    def __init__(self, shared=None, *, capacity=32):
        self.shared = shared if shared is not None else Memory(capacity)
        kernel, birth_labels = birth.assemble(BIRTH, REVISION, SCOPE, CODE,
                                              BIRTH_CAPACITY)
        emitted, labels = transport.assemble(
            JOURNAL, BIRTH, birth_labels, REVISION, SCOPE, CODE + len(kernel),
            self.shared.capacity)
        self.code, self.birth_labels = kernel + emitted, birth_labels
        self.transport_base, self.transport_code = CODE + len(kernel), emitted
        self.labels = {'birth_' + name: address for name, address in birth_labels.items()}
        self.labels.update(labels)
        self.words = struct.unpack('<%dI' % (len(self.code) // 4), self.code)
        self.r = [0] + [0x11000000 + reg for reg in range(1, 32)]
        self.r[29], self.r[31] = STACK, RETURN
        self.hi, self.lo = 0x13579BDF, 0x2468ACE0
        self.reservation = None
        self.sc_failures = self.sc_attempts = 0
        self.pc, self.delay_target, self.steps = RETURN, None, 0
        self.trace, self.calls = [], []

    def metadata(self, *, engine=ENGINE, node=NODE, copy=COPY, metadata=METADATA,
                 frame=INSTALL_FRAME, upstream=UPSTREAM, site=transport.INSTALL_SITE):
        values = (engine, node, copy, metadata, frame, upstream, site)
        for index, value in enumerate(values):
            self.shared.write(PARAMS + 4 * index, value)
        return tuple(value & MASK for value in values)

    def birth_metadata(self, *, engine=ENGINE, input=INPUT, copy=0,
                       metadata=METADATA, frame=UPSTREAM, site=birth.BIRTH_SITE,
                       result=0):
        for index, value in enumerate((engine, input, copy, metadata, frame, site, result)):
            self.shared.write(PARAMS + 4 * index, value)

    def enqueue_birth(self):
        self.birth_metadata()
        root = self.call('birth_capture', birth.BIRTH, 0, PARAMS)
        self.birth_metadata(copy=COPY, site=birth.ENQUEUE_SITE)
        return self.call('birth_capture', birth.ENQUEUE_BEGIN, root, PARAMS)

    def capture(self, kind=transport.INSTALL, parent=2, params=PARAMS):
        return self.call('capture', kind, parent, params)

    def install(self, parent=2, **kwargs):
        self.metadata(**kwargs)
        return self.capture(parent=parent)

    def borrowed(self, parent=1, **kwargs):
        options = dict(frame=BORROW_FRAME, upstream=0, site=transport.BORROW_SITE)
        options.update(kwargs)
        self.metadata(**options)
        return self.capture(transport.BORROW, parent)

    def helper(self, parent=2, **kwargs):
        options = dict(frame=HELPER_FRAME, upstream=BORROW_FRAME, site=transport.HELPER_SITE)
        options.update(kwargs)
        self.metadata(**options)
        return self.capture(transport.HELPER, parent)

    def callback(self, parent=3, **kwargs):
        options = dict(frame=CALLBACK_FRAME, upstream=HELPER_FRAME, site=transport.CALLBACK_SITE)
        options.update(kwargs)
        self.metadata(**options)
        return self.capture(transport.CALLBACK, parent)

    def chain(self):
        self.enqueue_birth()
        return self.install(), self.borrowed(), self.helper(), self.callback()

    @staticmethod
    def record_address(sequence):
        return JOURNAL + transport.HEADER + (sequence - 1) * transport.RECORD

    @staticmethod
    def birth_address(sequence):
        return BIRTH + birth.HEADER + (sequence - 1) * birth.RECORD

    def record(self, sequence):
        start = transport.HEADER + (sequence - 1) * transport.RECORD
        return bytes(self.shared.regions[JOURNAL][start:start + transport.RECORD])


class TransportCoreTests(unittest.TestCase):
    def test_exact_four_kind_schema_and_external_origin(self):
        m = TransportMachine()
        m.enqueue_birth()
        m.shared.write(REVISION, 5)
        m.shared.write(SCOPE, 0x10002)
        self.assertEqual((m.install(), m.borrowed(), m.helper(), m.callback()), (1, 2, 3, 4))
        for sequence, kind, parent, frame, upstream, site in (
                (1, 1, 2, INSTALL_FRAME, UPSTREAM, transport.INSTALL_SITE),
                (2, 2, 1, BORROW_FRAME, 0, transport.BORROW_SITE),
                (3, 3, 2, HELPER_FRAME, BORROW_FRAME, transport.HELPER_SITE),
                (4, 4, 3, CALLBACK_FRAME, HELPER_FRAME, transport.CALLBACK_SITE)):
            self.assertEqual(struct.unpack('<16I', m.record(sequence)),
                             (transport.MAGIC, kind, parent, 1, sequence, ENGINE,
                              NODE, COPY, METADATA, frame, site, upstream,
                              5, 0x10002, 0, 0))
            self.assertEqual(m.call('validate', sequence, kind), m.record_address(sequence))
        self.assertEqual(m.shared.regions[JOURNAL][4:16], bytes(12))

    def test_all_unknown_zero_parents_skip_before_metadata_reads(self):
        for kind in range(1, 5):
            m = TransportMachine()
            m.shared.accesses.clear()
            self.assertEqual(m.capture(kind, 0, 0xBAD00000), 0)
            self.assertEqual(m.shared.read(JOURNAL), 0)
            self.assertFalse(any(address >= 0xBAD00000 for _, address, _ in m.shared.accesses))

    def test_invalid_kind_or_owned_metadata_faults_without_dereference(self):
        for kind, parent, params in ((0, 0, PARAMS), (5, 0, PARAMS), (MASK, 0, PARAMS),
                                     (1, 2, 0), (2, 1, PARAMS + 1)):
            m = TransportMachine()
            m.shared.accesses.clear()
            self.assertEqual(m.capture(kind, parent, params), 0)
            self.assertEqual(m.shared.read(JOURNAL), transport.FAULT)
            self.assertFalse(any(access == 'read' and PARAMS <= address < PARAMS + 28
                                 for access, address, _ in m.shared.accesses))

    def test_install_matches_exact_external_enqueue_and_frame_relation(self):
        changes = ({'engine': 0}, {'engine': ENGINE + 1}, {'engine': ENGINE + 4},
                   {'node': 0}, {'node': NODE + 1}, {'copy': 0}, {'copy': COPY + 1},
                   {'copy': COPY + 4}, {'metadata': METADATA + 1}, {'frame': 0},
                   {'frame': INSTALL_FRAME + 4}, {'upstream': UPSTREAM + 4},
                   {'frame': 0xFFFFFFF0, 'upstream': 0x18},
                   {'site': transport.INSTALL_SITE + 4})
        for args in changes:
            with self.subTest(args=args):
                m = TransportMachine()
                m.enqueue_birth()
                self.assertEqual(m.install(**args), 0)
                self.assertEqual(m.shared.read(JOURNAL), transport.FAULT)

    def test_install_rejects_wrong_kind_unpublished_out_of_range_external_parent(self):
        for parent in (1, 3, BIRTH_CAPACITY + 1, MASK, ENGINE):
            m = TransportMachine()
            m.enqueue_birth()
            self.assertEqual(m.install(parent=parent), 0)
            self.assertEqual(m.shared.read(JOURNAL), transport.FAULT)
        m = TransportMachine()
        m.enqueue_birth()
        m.shared.write(m.birth_address(2) + birth.MAGIC_OFFSET, 0)
        self.assertEqual(m.install(), 0)
        self.assertEqual(m.shared.read(JOURNAL), transport.FAULT)

    def test_descendant_exact_immutable_binding_and_site(self):
        for event in ('borrowed', 'helper', 'callback'):
            for changes in ({'engine': ENGINE + 4}, {'node': NODE + 4},
                            {'copy': COPY + 4}, {'metadata': 0}, {'site': 0},
                            {'frame': 0}, {'frame': BORROW_FRAME + 1}):
                with self.subTest(event=event, changes=changes):
                    m = TransportMachine()
                    m.chain()
                    self.assertEqual(getattr(m, event)(**changes), 0)
                    self.assertEqual(m.shared.read(JOURNAL), transport.FAULT)

    def test_borrow_frame_is_not_install_frame_and_no_upstream_is_admitted(self):
        m = TransportMachine()
        m.enqueue_birth()
        m.install()
        self.assertEqual(m.borrowed(frame=0x12340000), 2)
        self.assertNotEqual(m.field(2, transport.FRAME), m.field(1, transport.FRAME))
        m = TransportMachine()
        m.enqueue_birth()
        m.install()
        self.assertEqual(m.borrowed(upstream=INSTALL_FRAME), 0)

    def test_helper_and_callback_require_nonwrapping_exact_stack_relationships(self):
        for event, changes in (
                ('helper', {'frame': HELPER_FRAME + 4}),
                ('helper', {'upstream': BORROW_FRAME + 4}),
                ('helper', {'frame': 0xFFFFFFF8, 'upstream': 0xB0}),
                ('callback', {'frame': CALLBACK_FRAME + 4}),
                ('callback', {'upstream': HELPER_FRAME + 4}),
                ('callback', {'frame': 0xFFFFFFF8, 'upstream': 0x30})):
            m = TransportMachine()
            m.chain()
            self.assertEqual(getattr(m, event)(**changes), 0)
            self.assertEqual(m.shared.read(JOURNAL), transport.FAULT)

    def test_wrapping_frame_sums_fault_even_when_every_other_binding_matches(self):
        m = TransportMachine()
        m.birth_metadata(frame=0x18)
        self.assertEqual(m.call('birth_capture', birth.BIRTH, 0, PARAMS), 1)
        m.birth_metadata(frame=0x18, copy=COPY, site=birth.ENQUEUE_SITE)
        self.assertEqual(m.call('birth_capture', birth.ENQUEUE_BEGIN, 1, PARAMS), 2)
        self.assertEqual(m.install(frame=0xFFFFFFF0, upstream=0x18), 0)
        self.assertEqual(m.shared.read(JOURNAL), transport.FAULT)

        m = TransportMachine()
        m.enqueue_birth()
        m.install()
        self.assertEqual(m.borrowed(frame=0xB0), 2)
        self.assertEqual(m.helper(frame=0xFFFFFFF8, upstream=0xB0), 0)
        self.assertEqual(m.shared.read(JOURNAL), transport.FAULT)

        m = TransportMachine()
        m.enqueue_birth()
        m.install()
        self.assertEqual(m.borrowed(frame=0xE8), 2)
        self.assertEqual(m.helper(frame=0x30, upstream=0xE8), 3)
        self.assertEqual(m.callback(frame=0xFFFFFFF8, upstream=0x30), 0)
        self.assertEqual(m.shared.read(JOURNAL), transport.FAULT)

    def test_transport_wrong_parent_kind_range_foreign_or_unpublished_fault(self):
        for kind, parent in ((2, 2), (2, 33), (2, MASK), (2, NODE), (3, 1), (4, 2)):
            m = TransportMachine()
            m.chain()
            frames = {2: (BORROW_FRAME, 0, transport.BORROW_SITE),
                      3: (HELPER_FRAME, BORROW_FRAME, transport.HELPER_SITE),
                      4: (CALLBACK_FRAME, HELPER_FRAME, transport.CALLBACK_SITE)}
            frame, upstream, site = frames[kind]
            m.metadata(frame=frame, upstream=upstream, site=site)
            self.assertEqual(m.capture(kind, parent), 0)
            self.assertEqual(m.shared.read(JOURNAL), transport.FAULT)
        m = TransportMachine()
        m.enqueue_birth()
        m.install()
        m.shared.write(m.record_address(1), 0)
        self.assertEqual(m.borrowed(), 0)

    def test_validate_checks_all_ancestors_not_only_requested_record(self):
        corruptions = (
            (1, transport.PARENT, 1), (1, transport.ORIGIN, 2),
            (1, transport.ENGINE, ENGINE + 4), (1, transport.NODE, 0),
            (1, transport.FRAME, INSTALL_FRAME + 4), (1, transport.UPSTREAM, 0),
            (1, transport.SITE, 0), (1, transport.RESERVED[0], 1),
            (2, transport.PARENT, 2), (2, transport.ORIGIN, 2),
            (2, transport.NODE, NODE + 4), (2, transport.COPY, COPY + 4),
            (2, transport.METADATA, 0), (2, transport.UPSTREAM, 1),
            (2, transport.REVISION, 0x80000000), (2, transport.SCOPE, 0x10000),
            (3, transport.KIND, 2), (3, transport.FRAME, HELPER_FRAME + 4),
            (3, transport.UPSTREAM, BORROW_FRAME + 4), (3, transport.SEQ, 1),
            (4, transport.MAGIC_OFFSET, 0), (4, transport.RESERVED[1], 1),
            (4, transport.FRAME, CALLBACK_FRAME + 4), (4, transport.UPSTREAM, 0))
        for sequence, field, value in corruptions:
            with self.subTest(sequence=sequence, field=field, value=value):
                m = TransportMachine()
                m.chain()
                m.shared.write(m.record_address(sequence) + field, value)
                self.assertEqual(m.call('validate', 4, transport.CALLBACK), 0)
                self.assertEqual(m.shared.read(JOURNAL), transport.FAULT)

    def test_external_birth_corruption_revokes_existing_transport_ancestry(self):
        for sequence, field, value in ((1, birth.ORIGIN, 2), (1, birth.FRAME, 0),
                                       (1, birth.INPUT, 0), (2, birth.COPY, COPY + 4),
                                       (2, birth.METADATA, 0), (2, birth.RESERVED[0], 1)):
            m = TransportMachine()
            m.chain()
            m.shared.write(m.birth_address(sequence) + field, value)
            self.assertEqual(m.call('validate', 4, transport.CALLBACK), 0)
            self.assertEqual(m.shared.read(JOURNAL), transport.FAULT)

    def test_validate_zero_bad_expected_kind_and_invalid_id_fault(self):
        for ticket, kind in ((0, 1), (1, 0), (1, 5), (1, MASK), (MASK, 1), (33, 1)):
            m = TransportMachine()
            m.chain()
            self.assertEqual(m.call('validate', ticket, kind), 0)
            self.assertEqual(m.shared.read(JOURNAL), transport.FAULT)

    def test_revision_max_and_busy_scope_are_samples_not_admission(self):
        for revision in (0, 1, 0x7FFFFFFF):
            for scope in (0, 1, 0x10001, 0x7FFF7FFF, 0x7FFFFFFF):
                m = TransportMachine()
                m.enqueue_birth()
                m.shared.write(REVISION, revision)
                m.shared.write(SCOPE, scope)
                self.assertEqual(m.install(), 1)
                self.assertEqual((m.field(1, transport.REVISION), m.field(1, transport.SCOPE)),
                                 (revision, scope))

    def test_bad_current_revision_scope_or_birth_fault_invalidates_before_reserve(self):
        for address, value in ((REVISION, 0x80000000), (REVISION, MASK),
                               (SCOPE, MASK), (SCOPE, 0x80000000),
                               (SCOPE, 0x10000), (SCOPE, 0x20001), (BIRTH, MASK)):
            m = TransportMachine()
            m.enqueue_birth()
            m.shared.write(address, value)
            self.assertEqual(m.install(), 0)
            self.assertEqual(m.shared.read(JOURNAL), transport.FAULT)
            self.assertEqual(m.record(1), bytes(transport.RECORD))

    def test_samples_freeze_without_valid_current_equality_requirement(self):
        m = TransportMachine()
        m.enqueue_birth()
        m.metadata()
        m.shared.write(REVISION, 5)
        m.shared.write(SCOPE, 0x10002)
        m.start('capture', 1, 2, PARAMS).until('capture_publish')
        m.shared.write(REVISION, 9)
        m.shared.write(SCOPE, 2)
        self.assertEqual(m.run_to_return(), 1)
        self.assertEqual((m.field(1, transport.REVISION), m.field(1, transport.SCOPE)),
                         (5, 0x10002))

    def test_metadata_copied_once_before_reservation(self):
        m = TransportMachine()
        m.enqueue_birth()
        expected = m.metadata()
        m.shared.accesses.clear()
        m.start('capture', 1, 2, PARAMS).until('reserve_ll')
        m.metadata(node=NODE + 4, metadata=0)
        self.assertEqual(m.run_to_return(), 1)
        self.assertEqual(struct.unpack('<16I', m.record(1))[5:12],
                         expected[:5] + (expected[6], expected[5]))
        for offset in range(0, 28, 4):
            self.assertEqual(m.shared.accesses.count(('read', PARAMS + offset, 4)), 1)

    def test_equal_native_addresses_never_reuse_ticket_and_external_origin_is_exact(self):
        m = TransportMachine()
        first = m.enqueue_birth()
        second = m.enqueue_birth()
        self.assertEqual((first, second), (2, 4))
        self.assertEqual(m.install(parent=first), 1)
        self.assertEqual(m.install(parent=second), 2)
        self.assertEqual(m.borrowed(parent=2), 3)
        self.assertEqual(m.borrowed(parent=1), 4)
        self.assertEqual(m.helper(parent=4), 5)
        self.assertEqual(m.helper(parent=3), 6)
        self.assertEqual([m.field(i, transport.PARENT) for i in range(1, 7)],
                         [2, 4, 2, 1, 4, 3])
        self.assertEqual([m.field(i, transport.ORIGIN) for i in range(1, 7)],
                         [1, 3, 3, 1, 1, 3])

    def test_duplicate_event_is_raw_new_identity_not_pointer_registry(self):
        m = TransportMachine()
        m.enqueue_birth()
        self.assertEqual((m.install(), m.install()), (1, 2))
        self.assertEqual((m.borrowed(parent=1), m.borrowed(parent=1)), (3, 4))
        self.assertEqual((m.helper(parent=3), m.helper(parent=3)), (5, 6))
        self.assertEqual((m.callback(parent=5), m.callback(parent=5)), (7, 8))
        self.assertNotIn('ready', m.labels)
        self.assertNotIn('reset', m.labels)

    def test_issued_unpublished_parent_is_not_guessed_from_native_scalars(self):
        shared = Memory()
        first, second = TransportMachine(shared), TransportMachine(shared)
        first.enqueue_birth()
        first.metadata()
        first.start('capture', 1, 2, PARAMS).until('capture_publish')
        self.assertEqual(shared.read(JOURNAL), 1)
        self.assertEqual(second.borrowed(parent=1), 0)
        self.assertEqual(shared.read(JOURNAL), transport.FAULT)
        self.assertEqual(first.run_to_return(), 0)
        self.assertEqual(first.field(1, transport.MAGIC_OFFSET), 0)

    def test_capacity_and_permanent_fault_do_not_reuse_first_record(self):
        for capacity in (1, 2, 32, 1024):
            m = TransportMachine(capacity=capacity)
            m.enqueue_birth()
            for sequence in range(1, capacity + 1):
                self.assertEqual(m.install(), sequence)
            first = m.record(1)
            self.assertEqual(m.install(), 0)
            self.assertEqual(m.shared.read(JOURNAL), transport.FAULT)
            self.assertEqual(m.install(), 0)
            self.assertEqual(m.record(1), first)

    def test_nonzero_reserved_slot_magic_is_permanent_loss_not_overwrite(self):
        m = TransportMachine()
        m.enqueue_birth()
        m.shared.write(m.record_address(1), transport.MAGIC)
        before = m.record(1)
        self.assertEqual(m.install(), 0)
        self.assertEqual(m.shared.read(JOURNAL), transport.FAULT)
        self.assertEqual(m.record(1), before)

    def test_bounded_llsc_last_attempt_and_competing_allocators(self):
        for failures in (7, 8):
            m = TransportMachine()
            m.enqueue_birth()
            m.sc_failures, m.sc_attempts = failures, 0
            self.assertEqual(m.install(), 1 if failures == 7 else 0)
            self.assertEqual(m.sc_attempts, 8)
            self.assertEqual(m.shared.read(JOURNAL), 1 if failures == 7 else transport.FAULT)
        shared = Memory()
        first, second = TransportMachine(shared), TransportMachine(shared)
        first.start('reserve').until('reserve_sc')
        second.start('reserve').until('reserve_sc')
        self.assertEqual(first.run_to_return(), first.record_address(1))
        self.assertEqual(second.run_to_return(), second.record_address(2))
        self.assertEqual(shared.read(JOURNAL), 2)

    def test_fault_before_magic_prevents_publication(self):
        for address in (JOURNAL, BIRTH, REVISION, SCOPE):
            m = TransportMachine()
            m.enqueue_birth()
            m.metadata()
            m.start('capture', 1, 2, PARAMS).until('capture_publish')
            m.shared.write(address, MASK)
            self.assertEqual(m.run_to_return(), 0)
            self.assertEqual(m.field(1, transport.MAGIC_OFFSET), 0)
            self.assertEqual(m.shared.read(JOURNAL), transport.FAULT)

    def test_fault_at_each_install_instruction_is_sticky(self):
        probe = TransportMachine()
        probe.enqueue_birth()
        probe.install()
        for boundary in range(len(probe.trace) + 1):
            shared = Memory()
            m, invalidator = TransportMachine(shared), TransportMachine(shared)
            m.enqueue_birth()
            m.metadata()
            m.start('capture', 1, 2, PARAMS)
            for _ in range(boundary):
                m.step()
            invalidator.call('invalidate')
            m.run_to_return()
            self.assertEqual(shared.read(JOURNAL), transport.FAULT, boundary)
            self.assertEqual(m.call('reserve'), 0)

    def test_abi_all_entries_and_no_native_scalar_dereferences(self):
        for entry, args in (('capture', (1, 2, PARAMS)), ('capture', (2, 1, PARAMS)),
                            ('validate', (4, 4)), ('validate', (MASK, 1)),
                            ('reserve', ()), ('invalidate', ())):
            m = TransportMachine()
            m.chain()
            m.metadata(frame=BORROW_FRAME, upstream=0, site=transport.BORROW_SITE)
            if entry == 'capture' and args[0] == 1:
                m.metadata()
            before, hi, lo = m.r.copy(), m.hi, m.lo
            m.shared.accesses.clear()
            m.call(entry, *args)
            for register in (*range(16, 24), 26, 27, 28, 29, 30, 31):
                self.assertEqual(m.r[register], before[register], (entry, register))
            self.assertEqual((m.hi, m.lo), (hi, lo))
            self.assertFalse(any(address >= 0xBAD00000 for _, address, _ in m.shared.accesses))

    def test_magic_last_and_only_plain_state_store_is_fault(self):
        m = TransportMachine()
        m.enqueue_birth()
        m.metadata()
        m.shared.accesses.clear()
        m.capture()
        writes = [(address, size) for access, address, size in m.shared.accesses
                  if access == 'write' and m.record_address(1) <= address < m.record_address(2)]
        self.assertEqual(writes[-1], (m.record_address(1), 4))
        words = struct.unpack('<%dI' % (len(m.transport_code) // 4), m.transport_code)
        stores = [(index, word >> 26) for index, word in enumerate(words)
                  if word >> 26 in (0x2B, 0x38) and (word >> 21) & 31 == 8
                  and word & 0xFFFF == 0]
        self.assertEqual([op for _, op in stores], [0x38, 0x2B])
        self.assertEqual(m.transport_base + stores[-1][0] * 4, m.labels['fault_store'])

    def test_external_call_allowlist_and_explicit_nop_delay_slots(self):
        m = TransportMachine()
        words = struct.unpack('<%dI' % (len(m.transport_code) // 4), m.transport_code)
        external = []
        for index, word in enumerate(words):
            op, rs = word >> 26, (word >> 21) & 31
            if op in (2, 3):
                pc = m.transport_base + index * 4
                target = ((pc + 4) & 0xF0000000) | ((word & 0x3FFFFFF) << 2)
                if not m.transport_base <= target < m.transport_base + len(m.transport_code):
                    external.append(target)
                    self.assertEqual(op, 3)
                self.assertEqual(words[index + 1], 0)
            if op in (4, 5) or (op == 0 and word & 63 == 8):
                if op == 0:
                    self.assertEqual(rs, 31)
                self.assertEqual(words[index + 1], 0)
        self.assertEqual(external, [m.birth_labels['validate']] * 2)

    def test_layout_types_capacity_wrap_overlap_external_entry_and_jump_region(self):
        self.assertEqual(transport.memory_bytes(), 65552)
        self.assertEqual(transport.MAGIC.to_bytes(4, 'little'), b'LQTR')
        defaults = dict(journal_address=JOURNAL, birth_address=BIRTH,
                        birth_entries={'validate': CODE - 0x100},
                        revision_address=REVISION, scope_address=SCOPE, code_base=CODE)
        for name, values in (
                ('capacity', (0, -1, True, 1.0, transport.MAX_CAPACITY + 1)),
                ('journal_address', (True, 1, 0xFFFFFFFC, REVISION, SCOPE, BIRTH)),
                ('birth_address', (True, 1, 0xFFFFFFFC, JOURNAL, REVISION, SCOPE)),
                ('revision_address', (True, 1, 0xFFFFFFFC, JOURNAL, SCOPE, BIRTH)),
                ('scope_address', (True, 1, 0xFFFFFFFC, JOURNAL, REVISION, BIRTH)),
                ('code_base', (True, 1, 0xFFFFFFFC, JOURNAL, REVISION, SCOPE,
                               BIRTH, 0x0FFFFF00)),
                ('birth_entries', (None, {}, {'validate': True}, {'validate': 1},
                                   {'validate': 0}, {'validate': CODE},
                                   {'validate': JOURNAL}, {'validate': BIRTH},
                                   {'validate': 0x1C700000}))):
            for value in values:
                args = dict(defaults)
                args[name] = value
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    transport.assemble(**args)
        for value in (0, -1, True, 1.0, transport.MAX_CAPACITY + 1):
            with self.assertRaises(ValueError):
                transport.memory_bytes(value)


if __name__ == '__main__':
    unittest.main()
