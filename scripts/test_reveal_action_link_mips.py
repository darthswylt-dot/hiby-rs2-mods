#!/usr/bin/env python3
"""Execute action ancestry with real private BIRTH validation, no native map.

The fixture models bounded coherent instruction interleavings, not hardware
cache behavior, actual queues, borrowed payload coherence or UI authority.
"""

import struct
import unittest

import reveal_action_link_mips as link
import reveal_queue_birth_mips as birth
import test_reveal_lineage_rows_mips as harness


CODE, RETURN, STACK, PARAMS = harness.CODE, harness.RETURN, harness.STACK, harness.PARAMS
BIRTH, JOURNAL, REVISION, SCOPE = 0xBD4000, 0xBE8000, 0xBFA000, 0xBFA010
BIRTH_CAPACITY, MASK = 32, 0xFFFFFFFF
WORKER, QUEUE, SOURCE_FRAME = 0xBAD10000, 0xBAD20000, 0xBAD30000
WORKER_FRAME, ACTION_RECORD, PAINT_RECORD = 0xBAD50000, 0xBAD60000, 0xBAD70000
EXPLORER_FRAME, PAINT_FRAME = WORKER_FRAME - 0x40, WORKER_FRAME - 0x80
RESOURCE, NODE, CONTROLLER, CONSUMER_FRAME = (
    0xBAD80000, 0xBAD90000, 0xBADA0000, 0xBADB0000)
BIRTH_FRAME, PARAM1 = CONSUMER_FRAME - 0x68, 0x87654321


class Memory(harness.Memory):
    def __init__(self, capacity=32):
        self.capacity, self.regions, self.accesses, self.version = capacity, {}, [], 0
        self.map(BIRTH, birth.memory_bytes(BIRTH_CAPACITY))
        self.map(JOURNAL, link.memory_bytes(capacity))
        self.map(REVISION, 16)
        self.map(SCOPE, 16)
        self.map(STACK - 0x1000, 0x2000)
        self.map(PARAMS, link.METADATA_WORDS * 4)

    def write(self, address, value, size=4):
        super().write(address, value, size)
        self.version += 1


class ActionLinkMachine(harness.RowsMachine):
    def __init__(self, shared=None, *, capacity=32):
        self.shared = shared if shared is not None else Memory(capacity)
        kernel, entries = birth.assemble(BIRTH, REVISION, SCOPE, CODE, BIRTH_CAPACITY)
        emitted, labels = link.assemble(JOURNAL, BIRTH, entries, CODE + len(kernel),
                                        self.shared.capacity)
        self.code, self.birth_labels = kernel + emitted, entries
        self.link_base, self.link_code = CODE + len(kernel), emitted
        self.labels = {'birth_' + name: value for name, value in entries.items()}
        self.labels.update(labels)
        self.words = struct.unpack('<%dI' % (len(self.code) // 4), self.code)
        self.r = [0] + [0x11000000 + reg for reg in range(1, 32)]
        self.r[29], self.r[31] = STACK, RETURN
        self.hi, self.lo = 0x13579BDF, 0x2468ACE0
        self.reservation = None
        self.sc_failures = self.sc_attempts = 0
        self.pc, self.delay_target, self.steps = RETURN, None, 0
        self.trace, self.calls = [], []

    def metadata(self, values):
        for index, field in enumerate(link.METADATA_FIELDS):
            self.shared.write(PARAMS + 4 * index, values[field])

    def values(self, kind):
        values = dict.fromkeys(link.METADATA_FIELDS, 0)
        values.update({link.WORKER: WORKER, link.SOURCE_FRAME: SOURCE_FRAME,
                       link.ACTION: 1, link.PARAM1: PARAM1, link.PARAM2: 0})
        if kind == link.SOURCE:
            values.update({link.QUEUE: QUEUE, link.RECORD: SOURCE_FRAME + 0x18,
                           link.FRAME: SOURCE_FRAME, link.SITE: link.SOURCE_SITE,
                           link.CALLER: 0x42D61C})
        elif kind == link.DELIVERY:
            values.update({link.QUEUE: QUEUE, link.RECORD: ACTION_RECORD,
                           link.FRAME: WORKER_FRAME, link.SITE: link.DELIVERY_SITE})
        elif kind == link.EXPLORER:
            values.update({link.QUEUE: QUEUE, link.RECORD: ACTION_RECORD,
                           link.FRAME: EXPLORER_FRAME, link.SITE: link.EXPLORER_SITE,
                           link.CALLER: 0x4BAA68, link.RESOURCE: RESOURCE, link.NODE: NODE})
        elif kind == link.PAINT:
            values.update({link.RECORD: PAINT_FRAME + 0x18, link.FRAME: PAINT_FRAME,
                           link.SITE: link.PAINT_SITE, link.CALLER: link.PAINT_CALLERS[0],
                           link.RESOURCE: RESOURCE, link.NODE: NODE,
                           link.CONTROLLER: CONTROLLER, link.ENGINE: NODE,
                           link.INPUT: PAINT_FRAME + 0x58})
        elif kind in (link.PAINT_DELIVERY, link.BIRTH_LINK):
            values.update({link.RECORD: PAINT_RECORD,
                           link.FRAME: CONSUMER_FRAME if kind == link.PAINT_DELIVERY else BIRTH_FRAME,
                           link.SITE: link.PAINT_DELIVERY_SITE if kind == link.PAINT_DELIVERY else link.BIRTH_SITE,
                           link.CALLER: 0x43C918 if kind == link.PAINT_DELIVERY else 0x45987C,
                           link.RESOURCE: RESOURCE, link.NODE: NODE,
                           link.CONTROLLER: CONTROLLER, link.ENGINE: NODE,
                           link.INPUT: PAINT_RECORD + 0xC,
                           link.BIRTH: 0 if kind == link.PAINT_DELIVERY else 1})
        return values

    def capture(self, kind=link.SOURCE, parent=0, *, changes=None, params=PARAMS):
        values = self.values(kind)
        values.update(changes or {})
        self.metadata(values)
        return self.call('capture', kind, parent, params)

    def make_birth(self, **changes):
        values = dict(engine=NODE, input=PAINT_RECORD + 0xC, copy=0, metadata=0,
                      frame=BIRTH_FRAME, site=birth.BIRTH_SITE, result=0)
        values.update(changes)
        for index, value in enumerate(values.values()):
            self.shared.write(PARAMS + 4 * index, value)
        return self.call('birth_capture', birth.BIRTH, 0, PARAMS)

    def chain(self, stop=link.BIRTH_LINK):
        if stop == link.BIRTH_LINK:
            self.make_birth()
        return tuple(self.capture(kind, 0 if kind == link.SOURCE else kind - 1)
                     for kind in range(1, stop + 1))

    @staticmethod
    def record_address(sequence):
        return JOURNAL + link.HEADER + (sequence - 1) * link.RECORD_BYTES

    def record(self, sequence):
        start = link.HEADER + (sequence - 1) * link.RECORD_BYTES
        return bytes(self.shared.regions[JOURNAL][start:start + link.RECORD_BYTES])


class ActionLinkCoreTests(unittest.TestCase):
    def test_exact_six_kind_schema_and_real_external_birth(self):
        m = ActionLinkMachine()
        self.assertEqual(m.chain(), (1, 2, 3, 4, 5, 6))
        for kind in range(1, 7):
            values = m.values(kind)
            self.assertEqual(struct.unpack('<24I', m.record(kind)),
                             (link.MAGIC, kind, 0 if kind == 1 else kind - 1, 1,
                              kind, *(values[field] for field in link.METADATA_FIELDS), 0, 0))
            self.assertEqual(m.call('validate', kind, kind), m.record_address(kind))
        self.assertEqual(m.shared.regions[JOURNAL][4:16], bytes(12))

    def test_missing_parent_is_unknown_before_owned_metadata_read(self):
        for kind in range(2, 7):
            m = ActionLinkMachine()
            m.shared.accesses.clear()
            self.assertEqual(m.call('capture', kind, 0, 0xBAD00000), 0)
            self.assertEqual(m.shared.read(JOURNAL), 0)
            self.assertFalse(any(address >= 0xBAD00000 for _, address, _ in m.shared.accesses))

    def test_bad_kind_parent_owned_address_and_wrap_fault_before_copy(self):
        for kind, parent, params in ((0, 0, PARAMS), (7, 0, PARAMS), (MASK, 0, PARAMS),
                                     (1, 1, PARAMS), (1, 0, 0), (1, 0, PARAMS + 1),
                                     (1, 0, 0xFFFFFFC0), (1, 0, 0xFFFFFFFC)):
            with self.subTest(kind=kind, parent=parent, params=params):
                m = ActionLinkMachine()
                m.shared.accesses.clear()
                self.assertEqual(m.call('capture', kind, parent, params), 0)
                self.assertEqual(m.shared.read(JOURNAL), link.FAULT)
                self.assertFalse(any(access == 'read' and PARAMS <= address < PARAMS + 68
                                     for access, address, _ in m.shared.accesses))

    def test_source_classification_is_only_exact_general_action_one_intent(self):
        for field, value in ((link.CALLER, 0), (link.CALLER, 0x42CC20),
                             (link.SITE, link.SOURCE_SITE + 4), (link.ACTION, 0),
                             (link.ACTION, 5), (link.PARAM2, 1), (link.FRAME, 0),
                             (link.SOURCE_FRAME, SOURCE_FRAME + 4),
                             (link.RECORD, SOURCE_FRAME + 0x1C), (link.QUEUE, 0),
                             (link.WORKER, WORKER + 1), (link.ENGINE, NODE),
                             (link.METADATA, 1), (link.BIRTH, 1)):
            with self.subTest(field=field, value=value):
                m = ActionLinkMachine()
                self.assertEqual(m.capture(changes={field: value}), 0)
                self.assertEqual(m.shared.read(JOURNAL), link.FAULT)

    def test_each_descendant_checks_kind_site_frame_and_immutable_payload(self):
        for kind in range(2, 7):
            for field, value in ((link.SITE, 0), (link.CALLER, 0xDEADBEEF),
                                 (link.SOURCE_FRAME, SOURCE_FRAME + 4),
                                 (link.WORKER, WORKER + 4), (link.ACTION, 5),
                                 (link.PARAM1, PARAM1 + 1), (link.PARAM2, 1),
                                 (link.FRAME, 0), (link.FRAME, 3)):
                with self.subTest(kind=kind, field=field):
                    m = ActionLinkMachine()
                    m.chain(kind - 1)
                    if kind == 6:
                        m.make_birth()
                    self.assertEqual(m.capture(kind, kind - 1, changes={field: value}), 0)
                    self.assertEqual(m.shared.read(JOURNAL), link.FAULT)

    def test_exact_frame_arithmetic_and_record_ownership_rejects_wrap(self):
        for kind, changes in (
                (1, {link.FRAME: 0xFFFFFFF0, link.SOURCE_FRAME: 0xFFFFFFF0,
                     link.RECORD: 8}),
                (3, {link.FRAME: EXPLORER_FRAME + 4}),
                (4, {link.FRAME: PAINT_FRAME + 4}),
                (4, {link.INPUT: PAINT_FRAME + 0x54}),
                (5, {link.INPUT: PAINT_RECORD + 0x10}),
                (6, {link.FRAME: BIRTH_FRAME + 4})):
            with self.subTest(kind=kind, changes=changes):
                m = ActionLinkMachine()
                if kind > 1:
                    m.chain(kind - 1)
                if kind == 6:
                    m.make_birth()
                self.assertEqual(m.capture(kind, 0 if kind == 1 else kind - 1,
                                           changes=changes), 0)
                self.assertEqual(m.shared.read(JOURNAL), link.FAULT)

    def test_strict_snapshot_extent_repros_fault_before_publishing(self):
        cases = ((1, {link.FRAME: 0xFFFFFFE4, link.SOURCE_FRAME: 0xFFFFFFE4,
                      link.RECORD: 0xFFFFFFFC}),
                 (1, {link.FRAME: 0xFFFFFFC4, link.SOURCE_FRAME: 0xFFFFFFC4,
                      link.RECORD: 0xFFFFFFDC}),
                 (3, {link.FRAME: 0xFFFFFFC4}),
                 (4, {link.FRAME: 0xFFFFFF9C, link.RECORD: 0xFFFFFFB4,
                      link.INPUT: 0xFFFFFFF4}),
                 (5, {link.RECORD: 0xFFFFFFF0, link.INPUT: 0xFFFFFFFC}),
                 (5, {link.RECORD: 0xFFFFFFE0, link.INPUT: 0xFFFFFFEC}),
                 (6, {link.FRAME: 0xFFFFFF9C}))
        for kind, changes in cases:
            with self.subTest(kind=kind, changes=changes):
                m = ActionLinkMachine()
                if kind > 1:
                    m.chain(kind - 1)
                if kind == 6:
                    m.make_birth(frame=changes[link.FRAME])
                self.assertEqual(m.capture(kind, kind - 1, changes=changes), 0)
                self.assertEqual(m.shared.read(JOURNAL), link.FAULT)
                self.assertEqual(m.record(kind), bytes(link.RECORD_BYTES))

    def test_extent_validation_rechecks_published_ancestors(self):
        for sequence, changes in (
                (1, {link.FRAME: 0xFFFFFFC4, link.SOURCE_FRAME: 0xFFFFFFC4,
                     link.RECORD: 0xFFFFFFDC}),
                (3, {link.FRAME: 0xFFFFFFC4}),
                (4, {link.FRAME: 0xFFFFFF9C, link.RECORD: 0xFFFFFFB4,
                     link.INPUT: 0xFFFFFFF4}),
                (5, {link.RECORD: 0xFFFFFFE0, link.INPUT: 0xFFFFFFEC}),
                (6, {link.FRAME: 0xFFFFFF9C})):
            with self.subTest(sequence=sequence):
                m = ActionLinkMachine()
                m.chain()
                for field, value in changes.items():
                    m.shared.write(m.record_address(sequence) + field, value)
                self.assertEqual(m.call('validate', 6, 6), 0)
                self.assertEqual(m.shared.read(JOURNAL), link.FAULT)

    def test_nonwrapping_u32_extent_boundaries_match_strict_snapshot_decoder(self):
        import decode_reveal_action_link as decoder

        def decodes(m):
            result = decoder.decode(bytes(m.shared.regions[JOURNAL]),
                                    birth_data=bytes(m.shared.regions[BIRTH]),
                                    capacity=m.shared.capacity,
                                    birth_capacity=BIRTH_CAPACITY)
            self.assertEqual(result['counter'], m.shared.read(JOURNAL))
            self.assertEqual(result['decision'], 'deny')

        m = ActionLinkMachine()
        self.assertEqual(m.capture(changes={link.FRAME: 0xFFFFFFC0,
                                           link.SOURCE_FRAME: 0xFFFFFFC0,
                                           link.RECORD: 0xFFFFFFD8}), 1)
        self.assertEqual(m.call('validate', 1, 1), m.record_address(1))
        decodes(m)  # SOURCE extent ends exactly at 2**32, not beyond it.

        m = ActionLinkMachine()
        m.capture()
        self.assertEqual(m.capture(2, 1, changes={link.FRAME: 0xFFFFFFFC}), 2)
        self.assertEqual(m.capture(3, 2, changes={link.FRAME: 0xFFFFFFBC}), 3)
        self.assertEqual(m.capture(4, 3, changes={link.FRAME: 0xFFFFFF7C,
                                                link.RECORD: 0xFFFFFF94,
                                                link.INPUT: 0xFFFFFFD4}), 4)
        self.assertEqual(m.call('validate', 4, 4), m.record_address(4))
        decodes(m)  # Highest frame ancestry allowed by worker+40/+80.

        m = ActionLinkMachine()
        m.chain(4)
        self.assertEqual(m.capture(5, 4, changes={link.RECORD: 0xFFFFFFDC,
                                                link.INPUT: 0xFFFFFFE8}), 5)
        self.assertEqual(m.call('validate', 5, 5), m.record_address(5))
        decodes(m)  # Extended paint element ends exactly at 2**32.

        m = ActionLinkMachine()
        m.chain(4)
        self.assertEqual(m.capture(5, 4, changes={link.FRAME: 0xFFFFFFFC}), 5)
        self.assertEqual(m.make_birth(frame=0xFFFFFF94), 1)
        self.assertEqual(m.capture(6, 5, changes={link.FRAME: 0xFFFFFF94}), 6)
        self.assertEqual(m.call('validate', 6, 6), m.record_address(6))
        decodes(m)  # Highest BIRTH frame compatible with its parent frame.

    def test_both_native_paint_callers_are_admitted(self):
        for caller in link.PAINT_CALLERS:
            m = ActionLinkMachine()
            m.chain(3)
            self.assertEqual(m.capture(4, 3, changes={link.CALLER: caller}), 4)
            self.assertEqual(m.call('validate', 4, 4), m.record_address(4))

    def test_no_pointer_key_join_and_wrong_kind_missing_or_future_parent_refused(self):
        for kind, parent in ((2, 2), (2, 32), (2, MASK), (3, 1), (4, 2), (6, 4)):
            with self.subTest(kind=kind, parent=parent):
                m = ActionLinkMachine()
                m.chain(5)
                self.assertEqual(m.capture(kind, parent), 0)
                self.assertEqual(m.shared.read(JOURNAL), link.FAULT)

    def test_birth_link_requires_exact_external_birth_and_scalar_bindings(self):
        for changes in ({'engine': NODE + 4}, {'input': PAINT_RECORD + 0x10},
                        {'metadata': 1}, {'frame': BIRTH_FRAME + 4}):
            with self.subTest(changes=changes):
                m = ActionLinkMachine()
                m.chain(5)
                m.make_birth(**changes)
                self.assertEqual(m.capture(6, 5), 0)
                self.assertEqual(m.shared.read(JOURNAL), link.FAULT)
        for ticket in (0, 2, MASK):
            m = ActionLinkMachine()
            m.chain(5)
            m.make_birth()
            self.assertEqual(m.capture(6, 5, changes={link.BIRTH: ticket}), 0)
            self.assertEqual(m.shared.read(JOURNAL), link.FAULT)

    def test_ancestry_revalidation_detects_every_ancestor_corruption(self):
        fields = (link.MAGIC_OFFSET, link.KIND, link.PARENT, link.ORIGIN, link.SEQ,
                  link.WORKER, link.QUEUE, link.RECORD, link.SOURCE_FRAME,
                  link.FRAME, link.SITE, link.CALLER, link.ACTION, link.PARAM1,
                  link.PARAM2, link.RESOURCE, link.NODE, link.CONTROLLER,
                  link.ENGINE, link.INPUT, link.METADATA, link.BIRTH, *link.RESERVED)
        # A fresh scalar may vary in an honest chain, but changing only its
        # historical record must break a schema, inherited equality or BIRTH
        # binding. Every field of every ancestor is tested independently.
        for sequence in range(1, 7):
            for field in fields:
                with self.subTest(sequence=sequence, field=field):
                    m = ActionLinkMachine()
                    m.chain()
                    address = m.record_address(sequence) + field
                    m.shared.write(address, m.shared.read(address) ^ 4)
                    self.assertEqual(m.call('validate', 6, 6), 0)
                    self.assertEqual(m.shared.read(JOURNAL), link.FAULT)

    def test_external_birth_later_corruption_or_global_fault_invalidates_descendant(self):
        for field, value in ((birth.MAGIC_OFFSET, 0), (birth.ENGINE, NODE + 4),
                             (birth.INPUT, 0), (birth.METADATA, 1), (birth.FRAME, 4)):
            m = ActionLinkMachine()
            m.chain()
            m.shared.write(BIRTH + birth.HEADER + field, value)
            self.assertEqual(m.call('validate', 6, 6), 0)
            self.assertEqual(m.shared.read(JOURNAL), link.FAULT)
        m = ActionLinkMachine()
        m.chain()
        m.shared.write(BIRTH, birth.FAULT)
        self.assertEqual(m.call('validate', 6, 6), 0)
        self.assertEqual(m.shared.read(JOURNAL), link.FAULT)

    def test_metadata_copied_once_and_private_record_is_frozen(self):
        m = ActionLinkMachine()
        values = m.values(1)
        m.metadata(values)
        m.shared.accesses.clear()
        m.start('capture', 1, 0, PARAMS).until('reserve_ll')
        for field in values:
            m.shared.write(PARAMS + field - link.WORKER, 0)
        self.assertEqual(m.run_to_return(), 1)
        self.assertEqual(struct.unpack('<24I', m.record(1))[5:22],
                         tuple(values[field] for field in link.METADATA_FIELDS))
        for index in range(link.METADATA_WORDS):
            self.assertEqual(m.shared.accesses.count(('read', PARAMS + index * 4, 4)), 1)

    def test_identical_source_payload_has_distinct_ids_and_no_address_reuse(self):
        m = ActionLinkMachine()
        self.assertEqual((m.capture(), m.capture(), m.capture()), (1, 2, 3))
        self.assertEqual([m.field(i, link.ORIGIN) for i in range(1, 4)], [1, 2, 3])
        self.assertEqual(m.capture(2, 1), 4)
        self.assertEqual(m.capture(2, 2), 5)
        self.assertEqual([m.field(i, link.ORIGIN) for i in (4, 5)], [1, 2])

    def test_stride_capacity_terminal_exhaustion_and_dirty_magic_refusal(self):
        for capacity in (1, 2, 32):
            m = ActionLinkMachine(capacity=capacity)
            for ticket in range(1, capacity + 1):
                self.assertEqual(m.capture(), ticket)
                self.assertEqual(m.field(ticket, link.SEQ), ticket)
            before = bytes(m.shared.regions[JOURNAL])
            self.assertEqual(m.capture(), 0)
            self.assertEqual(m.shared.read(JOURNAL), link.FAULT)
            self.assertEqual(bytes(m.shared.regions[JOURNAL][4:]), before[4:])
        m = ActionLinkMachine()
        m.shared.write(m.record_address(1), link.MAGIC)
        self.assertEqual(m.capture(), 0)
        self.assertEqual(m.shared.read(JOURNAL), link.FAULT)

    def test_bounded_llsc_retries_and_competing_reservations(self):
        for failures in (0, 7, 8, 100):
            m = ActionLinkMachine()
            m.sc_failures = failures
            self.assertEqual(m.capture(), 1 if failures < 8 else 0)
            self.assertEqual(m.sc_attempts, min(failures + 1, 8))
        shared = Memory()
        first, second = ActionLinkMachine(shared), ActionLinkMachine(shared)
        first.start('reserve').until('reserve_sc')
        second.start('reserve').until('reserve_sc')
        self.assertEqual(first.run_to_return(), first.record_address(1))
        self.assertEqual(second.run_to_return(), second.record_address(2))
        self.assertEqual((first.sc_attempts, second.sc_attempts), (1, 2))

    def test_reserved_unpublished_parent_cannot_be_used(self):
        shared = Memory()
        first, second = ActionLinkMachine(shared), ActionLinkMachine(shared)
        second.r[29] = STACK + 0x800
        first.metadata(first.values(1))
        first.start('capture', 1, 0, PARAMS).until('capture_publish')
        self.assertEqual(first.field(1, link.MAGIC_OFFSET), 0)
        self.assertEqual(second.capture(2, 1), 0)
        self.assertEqual(shared.read(JOURNAL), link.FAULT)
        self.assertEqual(first.run_to_return(), 0)
        self.assertEqual(first.field(1, link.MAGIC_OFFSET), 0)

    def test_fault_before_and_after_final_check_never_repairs_header(self):
        for label, expected_magic in (('capture_publish', 0),
                                      ('capture_magic_store', link.MAGIC)):
            shared = Memory()
            first, invalidator = ActionLinkMachine(shared), ActionLinkMachine(shared)
            first.metadata(first.values(1))
            first.start('capture', 1, 0, PARAMS).until(label)
            invalidator.call('invalidate')
            first.run_to_return()
            self.assertEqual(shared.read(JOURNAL), link.FAULT)
            self.assertEqual(first.field(1, link.MAGIC_OFFSET), expected_magic)
            self.assertEqual(first.call('reserve'), 0)

    def test_fault_at_every_source_capture_instruction_is_terminal(self):
        probe = ActionLinkMachine()
        probe.capture()
        for boundary in range(len(probe.trace) + 1):
            shared = Memory()
            m, invalidator = ActionLinkMachine(shared), ActionLinkMachine(shared)
            m.metadata(m.values(1))
            m.start('capture', 1, 0, PARAMS)
            for _ in range(boundary):
                m.step()
            invalidator.call('invalidate')
            m.run_to_return()
            self.assertEqual(shared.read(JOURNAL), link.FAULT, boundary)
            self.assertEqual(m.call('reserve'), 0, boundary)

    def test_bad_validate_ticket_kind_and_allocator_state_are_terminal(self):
        for ticket, kind in ((0, 1), (1, 0), (1, 7), (1, MASK),
                             (2, 1), (MASK, 1), (1, 2)):
            m = ActionLinkMachine()
            m.capture()
            self.assertEqual(m.call('validate', ticket, kind), 0)
            self.assertEqual(m.shared.read(JOURNAL), link.FAULT)
        for state in (33, 0x7FFFFFFF, 0x80000000, MASK):
            m = ActionLinkMachine()
            m.shared.write(JOURNAL, state)
            self.assertEqual(m.capture(), 0)
            self.assertEqual(m.shared.read(JOURNAL), link.FAULT)

    def test_external_birth_unpublished_and_wrong_kind_are_not_ancestry(self):
        for unpublished in (True, False):
            m = ActionLinkMachine()
            m.chain(5)
            m.make_birth()
            if unpublished:
                m.shared.write(BIRTH + birth.HEADER, 0)
                ticket = 1
            else:
                for index, value in enumerate((NODE, PAINT_RECORD + 0xC, 0xBADD0000,
                                               0, BIRTH_FRAME, birth.ENQUEUE_SITE, 0)):
                    m.shared.write(PARAMS + 4 * index, value)
                ticket = m.call('birth_capture', birth.ENQUEUE_BEGIN, 1, PARAMS)
                self.assertEqual(ticket, 2)
            self.assertEqual(m.capture(6, 5, changes={link.BIRTH: ticket}), 0)
            self.assertEqual(m.shared.read(JOURNAL), link.FAULT)

    def test_all_entry_abi_preserves_o32_callee_saved_sp_ra_hi_lo(self):
        for entry, args in (('capture', (1, 0, PARAMS)), ('validate', (1, 1)),
                            ('reserve', ()), ('invalidate', ())):
            m = ActionLinkMachine()
            if entry == 'validate':
                m.capture()
            else:
                m.metadata(m.values(1))
            before = m.r[:], m.hi, m.lo
            m.call(entry, *args)
            for reg in (*range(16, 24), 28, 29, 30, 31):
                self.assertEqual(m.r[reg], before[0][reg], (entry, reg))
            self.assertEqual((m.hi, m.lo), before[1:])

    def test_full_ancestry_and_external_validator_preserve_abi(self):
        m = ActionLinkMachine()
        m.chain()
        before = m.r[:], m.hi, m.lo
        self.assertEqual(m.call('validate', 6, 6), m.record_address(6))
        for reg in (*range(16, 24), 28, 29, 30, 31):
            self.assertEqual(m.r[reg], before[0][reg], reg)
        self.assertEqual((m.hi, m.lo), before[1:])

    def test_no_native_pointer_dereferences_or_native_calls(self):
        m = ActionLinkMachine()
        m.chain()
        m.call('validate', 6, 6)
        self.assertEqual(set(m.shared.regions),
                         {BIRTH, JOURNAL, REVISION, SCOPE, STACK - 0x1000, PARAMS})
        for target in m.calls:
            self.assertTrue(CODE <= target < CODE + len(m.code))
        words = struct.unpack('<%dI' % (len(m.link_code) // 4), m.link_code)
        self.assertFalse(any(word >> 26 == 0 and word & 63 == 9 for word in words))

    def test_configuration_domains_and_overlaps(self):
        for capacity in (0, -1, True, 1.0, link.MAX_CAPACITY + 1):
            with self.assertRaises(ValueError):
                link.memory_bytes(capacity)
        valid = (JOURNAL, BIRTH, {'validate': CODE}, CODE + 0x1000)
        for index, value in ((0, True), (0, JOURNAL + 1), (0, 0xFFFFFFFC),
                             (1, JOURNAL), (1, -4), (2, {}),
                             (2, {'validate': 0}), (2, {'validate': 0x10000000}),
                             (2, {'validate': JOURNAL}), (3, BIRTH),
                             (3, JOURNAL), (3, 0xFFFFFFFC)):
            args = list(valid)
            args[index] = value
            with self.subTest(index=index, value=value):
                with self.assertRaises(ValueError):
                    link.assemble(*args, capacity=32)


if __name__ == '__main__':
    unittest.main()
