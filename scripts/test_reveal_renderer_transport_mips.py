#!/usr/bin/env python3
"""Execute LQRD with real private LQBR/LQTR/LNRG cores, no native objects mapped."""

import struct
import unittest

import folderfollow_reveal_lineage_mips as lineage
import reveal_queue_transport_mips as transport
import reveal_renderer_transport_mips as renderer
import test_reveal_queue_transport_mips as queue_harness


CODE, RETURN, STACK, PARAMS = (
    queue_harness.CODE, queue_harness.RETURN, queue_harness.STACK, queue_harness.PARAMS)
QUEUE, BIRTH, REVISION, SCOPE = (
    queue_harness.JOURNAL, queue_harness.BIRTH, queue_harness.REVISION, queue_harness.SCOPE)
LINEAGE, JOURNAL, LINEAGE_CAPACITY = 0xBF4000, 0xC10000, 32
ENGINE = queue_harness.ENGINE
CALLBACK_FRAME = queue_harness.CALLBACK_FRAME
OUTER_FRAME, RENDER_FRAME = CALLBACK_FRAME - 0x200, CALLBACK_FRAME - 0x230
DESCRIPTOR, INPUT = CALLBACK_FRAME + 0x18, CALLBACK_FRAME + 0x90
WIDGET, CONTROLLER, VIEW, PANEL, CACHE = 0xBAD70000, 0xBAD80000, 0xBAD90000, 0xBADA0000, 0xBADB0000
JOB = VIEW + 0x38A4
MASK = 0xFFFFFFFF


class Memory(queue_harness.Memory):
    def __init__(self, capacity=32):
        super().__init__(capacity=32)
        self.renderer_capacity = capacity
        self.map(LINEAGE, lineage.memory_bytes(LINEAGE_CAPACITY))
        self.map(JOURNAL, renderer.memory_bytes(capacity))
        self.regions[PARAMS] = bytearray(renderer.METADATA_WORDS * 4)


class RendererMachine(queue_harness.TransportMachine):
    def __init__(self, shared=None, *, capacity=32):
        super().__init__(shared if shared is not None else Memory(capacity))
        queue_labels = {name: self.labels[name]
                        for name in ('capture', 'validate', 'reserve', 'invalidate')}
        lineage_code, lineage_labels = lineage.build_lineage(
            LINEAGE, CODE + len(self.code), LINEAGE_CAPACITY)
        self.code += lineage_code
        self.renderer_base = CODE + len(self.code)
        emitted, labels = renderer.assemble(
            JOURNAL, QUEUE, queue_labels, LINEAGE, lineage_labels,
            REVISION, SCOPE, self.renderer_base, self.shared.renderer_capacity)
        self.renderer_code = emitted
        self.code += emitted
        self.labels = {name: value for name, value in self.labels.items() if name.startswith('birth_')}
        self.labels.update({'queue_' + name: value for name, value in queue_labels.items()})
        self.labels.update({'lineage_' + name: value for name, value in lineage_labels.items()})
        self.labels.update(labels)
        self.queue_labels, self.lineage_labels = queue_labels, lineage_labels
        self.words = struct.unpack('<%dI' % (len(self.code) // 4), self.code)

    def queue_chain(self):
        external = self.enqueue_birth()
        parent = external
        for kind, frame, upstream, site in (
                (transport.INSTALL, queue_harness.INSTALL_FRAME,
                 queue_harness.UPSTREAM, transport.INSTALL_SITE),
                (transport.BORROW, queue_harness.BORROW_FRAME, 0, transport.BORROW_SITE),
                (transport.HELPER, queue_harness.HELPER_FRAME,
                 queue_harness.BORROW_FRAME, transport.HELPER_SITE),
                (transport.CALLBACK, CALLBACK_FRAME,
                 queue_harness.HELPER_FRAME, transport.CALLBACK_SITE)):
            queue_harness.TransportMachine.metadata(self, frame=frame, upstream=upstream, site=site)
            parent = self.call('queue_capture', kind, parent, PARAMS)
            if not parent:
                raise AssertionError('private queue fixture failed')
        return parent

    def root(self, *, frame=RENDER_FRAME, view=VIEW, panel=PANEL, job=JOB,
             site=renderer.LINEAGE_SITE, entry_revision=3, kind=lineage.RENDER):
        slot = self.call('lineage_reserve', kind, 0, view, panel)
        token = self.r[3]
        if not slot:
            raise AssertionError('lineage fixture failed')
        for field, value in ((lineage.STACK, frame), (lineage.JOB, job),
                             (lineage.SITE, site), (60, entry_revision)):
            self.shared.write(slot + field, value)
        self.shared.write(slot, lineage.MAGIC)
        return token

    def prepare(self):
        return self.queue_chain(), self.root()

    def metadata(self, *, engine=ENGINE, widget=WIDGET, view=0, panel=0,
                 frame=OUTER_FRAME, upstream=CALLBACK_FRAME, descriptor=DESCRIPTOR,
                 input=INPUT, controller=CONTROLLER, job=0, lineage=0,
                 cache=0, site=renderer.OUTER_SITE):
        values = (engine, widget, view, panel, frame, upstream, descriptor,
                  input, controller, job, lineage, cache, site)
        for index, value in enumerate(values):
            self.shared.write(PARAMS + 4 * index, value)
        return tuple(value & MASK for value in values)

    def capture(self, kind=renderer.OUTER, parent=4, params=PARAMS):
        return self.call('capture', kind, parent, params)

    def outer(self, parent=4, **kwargs):
        self.metadata(**kwargs)
        return self.capture(parent=parent)

    def rendered(self, parent=1, **kwargs):
        options = dict(view=VIEW, panel=PANEL, frame=RENDER_FRAME, upstream=OUTER_FRAME,
                       job=JOB, lineage=1, cache=CACHE, site=renderer.RENDER_SITE)
        options.update(kwargs)
        self.metadata(**options)
        return self.capture(renderer.RENDER, parent)

    def chain(self):
        self.prepare()
        return self.outer(), self.rendered()

    @staticmethod
    def record_address(sequence):
        return JOURNAL + renderer.HEADER + (sequence - 1) * renderer.RECORD

    @staticmethod
    def queue_address(sequence):
        return QUEUE + transport.HEADER + (sequence - 1) * transport.RECORD

    @staticmethod
    def root_address(sequence=1):
        return LINEAGE + lineage.HEADER + (sequence - 1) * lineage.RECORD

    def record(self, sequence):
        start = renderer.HEADER + (sequence - 1) * renderer.RECORD
        return bytes(self.shared.regions[JOURNAL][start:start + renderer.RECORD])


class RendererTransportCoreTests(unittest.TestCase):
    def test_exact_two_receipts_bind_callback_and_existing_render_root(self):
        m = RendererMachine()
        m.prepare()
        m.shared.write(REVISION, 5)
        m.shared.write(SCOPE, 0x10002)
        self.assertEqual((m.outer(), m.rendered()), (1, 2))
        self.assertEqual(struct.unpack('<24I', m.record(1)),
                         (renderer.MAGIC, 1, 4, 1, 1, 4, 0, ENGINE, WIDGET, 0, 0,
                          OUTER_FRAME, CALLBACK_FRAME, DESCRIPTOR, INPUT, CONTROLLER,
                          0, 5, 0x10002, 0, renderer.OUTER_SITE, 0, 0, 0))
        self.assertEqual(struct.unpack('<24I', m.record(2)),
                         (renderer.MAGIC, 2, 1, 1, 2, 4, 1, ENGINE, WIDGET, VIEW, PANEL,
                          RENDER_FRAME, OUTER_FRAME, DESCRIPTOR, INPUT, CONTROLLER,
                          JOB, 5, 0x10002, CACHE, renderer.RENDER_SITE, 0, 0, 0))
        self.assertEqual(m.call('validate', 1, renderer.OUTER), m.record_address(1))
        self.assertEqual(m.call('validate', 2, renderer.RENDER), m.record_address(2))
        self.assertEqual(m.shared.regions[JOURNAL][4:16], bytes(12))

    def test_zero_parents_ignore_before_owned_metadata_reads_for_both_kinds(self):
        for kind in (renderer.OUTER, renderer.RENDER):
            m = RendererMachine()
            m.shared.accesses.clear()
            self.assertEqual(m.capture(kind, 0, 0xBAD00000), 0)
            self.assertEqual(m.shared.read(JOURNAL), 0)
            self.assertFalse(any(address >= 0xBAD00000 for _, address, _ in m.shared.accesses))

    def test_bad_kinds_or_owned_blocks_fault_before_metadata_reads(self):
        for kind, parent, params in ((0, 0, PARAMS), (3, 0, PARAMS), (MASK, 0, PARAMS),
                                     (1, 4, 0), (2, 1, PARAMS + 1)):
            m = RendererMachine()
            m.shared.accesses.clear()
            self.assertEqual(m.capture(kind, parent, params), 0)
            self.assertEqual(m.shared.read(JOURNAL), renderer.FAULT)
            self.assertFalse(any(access == 'read' and PARAMS <= address < PARAMS + 52
                                 for access, address, _ in m.shared.accesses))

    def test_outer_exact_external_callback_kind_scalar_and_frame_binding(self):
        cases = ({'engine': ENGINE + 4}, {'engine': 0}, {'engine': ENGINE + 1},
                 {'widget': 0}, {'widget': WIDGET + 1}, {'controller': 0},
                 {'controller': CONTROLLER + 2}, {'frame': 0}, {'frame': OUTER_FRAME + 4},
                 {'upstream': CALLBACK_FRAME + 4}, {'descriptor': DESCRIPTOR + 4},
                 {'input': INPUT + 4}, {'view': VIEW}, {'panel': PANEL},
                 {'job': JOB}, {'lineage': 1}, {'cache': CACHE}, {'site': renderer.OUTER_SITE + 4})
        for options in cases:
            with self.subTest(options=options):
                m = RendererMachine()
                m.prepare()
                self.assertEqual(m.outer(**options), 0)
                self.assertEqual(m.shared.read(JOURNAL), renderer.FAULT)

    def test_outer_rejects_wrong_kind_out_of_range_foreign_or_unpublished_parent(self):
        for parent in (1, 2, 3, 5, 33, MASK, ENGINE):
            m = RendererMachine()
            m.prepare()
            self.assertEqual(m.outer(parent=parent), 0)
            self.assertEqual(m.shared.read(JOURNAL), renderer.FAULT)
        m = RendererMachine()
        m.prepare()
        m.shared.write(m.queue_address(4), 0)
        self.assertEqual(m.outer(), 0)
        self.assertEqual(m.shared.read(JOURNAL), renderer.FAULT)

    def test_render_exact_inherited_binding_frame_view_job_and_cache(self):
        cases = ({'engine': ENGINE + 4}, {'widget': WIDGET + 4},
                 {'descriptor': DESCRIPTOR + 4}, {'input': INPUT + 4},
                 {'controller': CONTROLLER + 4}, {'view': 0}, {'view': VIEW + 1},
                 {'view': VIEW + 4}, {'panel': 0}, {'panel': PANEL + 4},
                 {'frame': RENDER_FRAME + 4}, {'upstream': OUTER_FRAME + 4},
                 {'job': JOB + 4}, {'lineage': 0}, {'lineage': 2},
                 {'cache': 0}, {'cache': CACHE + 1}, {'site': renderer.RENDER_SITE + 4})
        for options in cases:
            with self.subTest(options=options):
                m = RendererMachine()
                m.prepare()
                m.outer()
                self.assertEqual(m.rendered(**options), 0)
                self.assertEqual(m.shared.read(JOURNAL), renderer.FAULT)

    def test_render_wrong_or_unpublished_parent_is_not_recovered_by_equal_addresses(self):
        for parent in (2, 3, 33, MASK, ENGINE):
            m = RendererMachine()
            m.chain()
            self.assertEqual(m.rendered(parent=parent), 0)
            self.assertEqual(m.shared.read(JOURNAL), renderer.FAULT)
        m = RendererMachine()
        m.prepare()
        m.outer()
        m.shared.write(m.record_address(1), 0)
        self.assertEqual(m.rendered(), 0)

    def test_existing_lineage_root_requires_all_exact_native_scalars_and_root_type(self):
        changes = ({'kind': lineage.INITIAL}, {'frame': RENDER_FRAME + 4},
                   {'view': VIEW + 4}, {'panel': PANEL + 4}, {'job': JOB + 4},
                   {'site': renderer.LINEAGE_SITE + 4}, {'entry_revision': 0x80000000})
        for options in changes:
            m = RendererMachine()
            m.queue_chain()
            m.root(**options)
            m.outer()
            self.assertEqual(m.rendered(), 0)
            self.assertEqual(m.shared.read(JOURNAL), renderer.FAULT)
        for field, value in ((lineage.PARENT, 1), (lineage.ORIGIN, 2), (lineage.MAGIC_OFFSET, 0)):
            m = RendererMachine()
            m.prepare()
            m.shared.write(m.root_address() + field, value)
            m.outer()
            self.assertEqual(m.rendered(), 0)
            self.assertEqual(m.shared.read(JOURNAL), renderer.FAULT)

    def test_root_entry_revision_is_only_a_domain_check_not_current_equality(self):
        for entry_revision in (0, 1, 3, 0x7FFFFFFF):
            m = RendererMachine()
            m.queue_chain()
            m.root(entry_revision=entry_revision)
            m.shared.write(REVISION, 9)
            self.assertEqual((m.outer(), m.rendered()), (1, 2))
            self.assertEqual(m.field(2, renderer.REVISION), 9)

    def test_all_stack_coordinate_descriptor_and_job_sums_reject_wrap(self):
        for options in ({'frame': 0xFFFFFF00, 'upstream': 0x100,
                         'descriptor': 0x118, 'input': 0x190},
                        {'frame': 0xFFFFFDFC, 'upstream': 0xFFFFFFFC,
                         'descriptor': 0x14, 'input': 0x8C},
                        {'frame': 0xFFFFFDC0, 'upstream': 0xFFFFFFC0,
                         'descriptor': 0xFFFFFFD8, 'input': 0x50}):
            m = RendererMachine()
            m.prepare()
            self.assertEqual(m.outer(**options), 0)
            self.assertEqual(m.shared.read(JOURNAL), renderer.FAULT)
        m = RendererMachine()
        m.prepare()
        m.outer()
        self.assertEqual(m.rendered(view=0xFFFFE000, job=0x18A4), 0)
        self.assertEqual(m.shared.read(JOURNAL), renderer.FAULT)

    def test_validate_checks_own_parent_and_both_external_ancestries(self):
        changes = ((1, renderer.PARENT, 3), (1, renderer.ORIGIN, 2),
                   (1, renderer.TRANSPORT, 3), (1, renderer.LINEAGE, 1),
                   (1, renderer.SITE, 0), (1, renderer.FRAME, OUTER_FRAME + 4),
                   (1, renderer.UPSTREAM, CALLBACK_FRAME + 4),
                   (1, renderer.DESCRIPTOR, DESCRIPTOR + 4), (1, renderer.INPUT, INPUT + 4),
                   (1, renderer.WIDGET, 0), (1, renderer.CONTROLLER, CONTROLLER + 1),
                   (1, renderer.VIEW, VIEW), (1, renderer.PANEL, PANEL), (1, renderer.JOB, JOB),
                   (1, renderer.CACHE, CACHE), (1, renderer.RESERVED[0], 1),
                   (1, renderer.REVISION, 0x80000000), (1, renderer.SCOPE, 0x10000),
                   (2, renderer.PARENT, 2), (2, renderer.ORIGIN, 2),
                   (2, renderer.TRANSPORT, 1), (2, renderer.LINEAGE, 2),
                   (2, renderer.SEQ, 1), (2, renderer.ENGINE, ENGINE + 4),
                   (2, renderer.WIDGET, WIDGET + 4), (2, renderer.VIEW, VIEW + 4),
                   (2, renderer.PANEL, PANEL + 4), (2, renderer.FRAME, RENDER_FRAME + 4),
                   (2, renderer.UPSTREAM, OUTER_FRAME + 4), (2, renderer.JOB, JOB + 4),
                   (2, renderer.SITE, 0), (2, renderer.CACHE, 0), (2, renderer.RESERVED[2], 1))
        for sequence, field, value in changes:
            with self.subTest(sequence=sequence, field=field):
                m = RendererMachine()
                m.chain()
                m.shared.write(m.record_address(sequence) + field, value)
                self.assertEqual(m.call('validate', 2, renderer.RENDER), 0)
                self.assertEqual(m.shared.read(JOURNAL), renderer.FAULT)
        for address, value in ((RendererMachine.queue_address(1) + transport.NODE, 0),
                               (RendererMachine.queue_address(4) + transport.FRAME, CALLBACK_FRAME + 4),
                               (RendererMachine.root_address() + lineage.SITE, 0),
                               (RendererMachine.root_address() + lineage.JOB, JOB + 4),
                               (RendererMachine.root_address() + 60, 0x80000000)):
            m = RendererMachine()
            m.chain()
            m.shared.write(address, value)
            self.assertEqual(m.call('validate', 2, renderer.RENDER), 0)
            self.assertEqual(m.shared.read(JOURNAL), renderer.FAULT)

    def test_validate_bad_kind_id_and_unpublished_record_fault(self):
        for ticket, kind in ((0, 1), (1, 0), (1, 3), (1, MASK), (MASK, 1), (33, 1), (2, 1)):
            m = RendererMachine()
            m.chain()
            self.assertEqual(m.call('validate', ticket, kind), 0)
            self.assertEqual(m.shared.read(JOURNAL), renderer.FAULT)
        m = RendererMachine()
        m.chain()
        m.shared.write(m.record_address(2), 0)
        self.assertEqual(m.call('validate', 2, 2), 0)

    def test_current_revision_and_busy_scope_are_historical_samples(self):
        for revision in (0, 1, 0x7FFFFFFF):
            for scope in (0, 1, 0x10001, 0x7FFF7FFF, 0x7FFFFFFF):
                m = RendererMachine()
                m.prepare()
                m.shared.write(REVISION, revision)
                m.shared.write(SCOPE, scope)
                self.assertEqual((m.outer(), m.rendered()), (1, 2))
                self.assertEqual((m.field(2, renderer.REVISION), m.field(2, renderer.SCOPE)),
                                 (revision, scope))

    def test_bad_current_revision_scope_or_external_fault_prevents_allocation(self):
        for address, value in ((REVISION, 0x80000000), (REVISION, MASK),
                               (SCOPE, MASK), (SCOPE, 0x80000000), (SCOPE, 0x10000),
                               (SCOPE, 0x20001), (QUEUE, MASK), (LINEAGE, MASK)):
            m = RendererMachine()
            m.prepare()
            m.shared.write(address, value)
            self.assertEqual(m.outer(), 0)
            self.assertEqual(m.shared.read(JOURNAL), renderer.FAULT)
            self.assertEqual(m.record(1), bytes(renderer.RECORD))

    def test_samples_freeze_without_becoming_equality_admission(self):
        m = RendererMachine()
        m.prepare()
        m.metadata()
        m.shared.write(REVISION, 3)
        m.shared.write(SCOPE, 0x10002)
        m.start('capture', 1, 4, PARAMS).until('capture_publish')
        m.shared.write(REVISION, 7)
        m.shared.write(SCOPE, 2)
        self.assertEqual(m.run_to_return(), 1)
        self.assertEqual((m.field(1, renderer.REVISION), m.field(1, renderer.SCOPE)), (3, 0x10002))

    def test_owned_thirteen_words_copied_once_and_native_metadata_never_reread(self):
        m = RendererMachine()
        m.prepare()
        values = m.metadata()
        m.shared.accesses.clear()
        m.start('capture', 1, 4, PARAMS).until('reserve_ll')
        m.metadata(widget=WIDGET + 4, input=0)
        self.assertEqual(m.run_to_return(), 1)
        for index, value in enumerate(values):
            field = (renderer.ENGINE, renderer.WIDGET, renderer.VIEW, renderer.PANEL,
                     renderer.FRAME, renderer.UPSTREAM, renderer.DESCRIPTOR, renderer.INPUT,
                     renderer.CONTROLLER, renderer.JOB, renderer.LINEAGE, renderer.CACHE,
                     renderer.SITE)[index]
            self.assertEqual(m.field(1, field), value)
            self.assertEqual(m.shared.accesses.count(('read', PARAMS + index * 4, 4)), 1)

    def test_duplicates_and_aba_equal_addresses_get_fresh_exact_ids(self):
        m = RendererMachine()
        callback = m.queue_chain()
        second = m.queue_chain()
        self.assertEqual((callback, second), (4, 8))
        first_root, second_root = m.root(), m.root()
        self.assertEqual((first_root, second_root), (1, 2))
        self.assertEqual((m.outer(parent=4), m.outer(parent=8)), (1, 2))
        self.assertEqual(m.rendered(parent=2, lineage=2), 3)
        self.assertEqual(m.rendered(parent=1, lineage=1), 4)
        self.assertEqual(m.rendered(parent=1, lineage=1), 5)
        self.assertEqual([m.field(i, renderer.ORIGIN) for i in range(1, 6)], [1, 3, 3, 1, 1])
        self.assertEqual([m.field(i, renderer.TRANSPORT) for i in range(1, 6)], [4, 8, 8, 4, 4])
        self.assertEqual([m.field(i, renderer.PARENT) for i in range(1, 6)], [4, 8, 2, 1, 1])
        self.assertEqual([m.field(i, renderer.LINEAGE) for i in range(3, 6)], [2, 1, 1])
        self.assertNotIn('ready', m.labels)
        self.assertNotIn('reset', m.labels)

    def test_issued_unpublished_parent_is_not_guessed_from_equal_scalar_bindings(self):
        shared = Memory()
        first, second = RendererMachine(shared), RendererMachine(shared)
        first.prepare()
        first.metadata()
        first.start('capture', 1, 4, PARAMS).until('capture_publish')
        self.assertEqual(shared.read(JOURNAL), 1)
        self.assertEqual(second.rendered(), 0)
        self.assertEqual(shared.read(JOURNAL), renderer.FAULT)
        self.assertEqual(first.run_to_return(), 0)
        self.assertEqual(first.field(1, renderer.MAGIC_OFFSET), 0)

    def test_capacity_96byte_stride_nonreuse_and_permanent_loss(self):
        for capacity in (1, 2, 32, 1024):
            m = RendererMachine(capacity=capacity)
            m.prepare()
            for sequence in range(1, capacity + 1):
                self.assertEqual(m.outer(), sequence)
                self.assertEqual(m.field(sequence, renderer.SEQ), sequence)
            first = m.record(1)
            self.assertEqual(m.outer(), 0)
            self.assertEqual(m.shared.read(JOURNAL), renderer.FAULT)
            self.assertEqual(m.outer(), 0)
            self.assertEqual(m.record(1), first)

    def test_reserved_nonzero_magic_cannot_be_overwritten(self):
        m = RendererMachine()
        m.prepare()
        m.shared.write(m.record_address(1), renderer.MAGIC)
        before = m.record(1)
        self.assertEqual(m.outer(), 0)
        self.assertEqual(m.shared.read(JOURNAL), renderer.FAULT)
        self.assertEqual(m.record(1), before)

    def test_bounded_llsc_retry_last_success_and_competing_allocators(self):
        for failures in (7, 8):
            m = RendererMachine()
            m.prepare()
            m.sc_failures, m.sc_attempts = failures, 0
            self.assertEqual(m.outer(), 1 if failures == 7 else 0)
            self.assertEqual(m.sc_attempts, 8)
            self.assertEqual(m.shared.read(JOURNAL), 1 if failures == 7 else renderer.FAULT)
        shared = Memory()
        first, second = RendererMachine(shared), RendererMachine(shared)
        first.start('reserve').until('reserve_sc')
        second.start('reserve').until('reserve_sc')
        self.assertEqual(first.run_to_return(), first.record_address(1))
        self.assertEqual(second.run_to_return(), second.record_address(2))
        self.assertEqual(shared.read(JOURNAL), 2)

    def test_global_fault_before_magic_keeps_reserved_record_unpublished(self):
        for address in (JOURNAL, QUEUE, LINEAGE, REVISION, SCOPE):
            m = RendererMachine()
            m.prepare()
            m.metadata()
            m.start('capture', 1, 4, PARAMS).until('capture_publish')
            m.shared.write(address, MASK)
            self.assertEqual(m.run_to_return(), 0)
            self.assertEqual(m.field(1, renderer.MAGIC_OFFSET), 0)
            self.assertEqual(m.shared.read(JOURNAL), renderer.FAULT)

    def test_fault_at_every_outer_capture_instruction_remains_terminal(self):
        probe = RendererMachine()
        probe.prepare()
        probe.outer()
        for boundary in range(len(probe.trace) + 1):
            shared = Memory()
            m, invalidator = RendererMachine(shared), RendererMachine(shared)
            m.prepare()
            m.metadata()
            m.start('capture', 1, 4, PARAMS)
            for _ in range(boundary):
                m.step()
            invalidator.call('invalidate')
            m.run_to_return()
            self.assertEqual(shared.read(JOURNAL), renderer.FAULT, boundary)
            self.assertEqual(m.call('reserve'), 0)

    def test_all_public_entry_abi_and_only_owned_private_or_own_stack_access(self):
        for entry, args in (('capture', (1, 4, PARAMS)), ('capture', (2, 1, PARAMS)),
                            ('validate', (1, 1)), ('validate', (2, 2)),
                            ('validate', (MASK, 1)), ('reserve', ()), ('invalidate', ())):
            m = RendererMachine()
            m.chain()
            if entry == 'capture' and args[0] == 2:
                m.metadata(view=VIEW, panel=PANEL, frame=RENDER_FRAME, upstream=OUTER_FRAME,
                           job=JOB, lineage=1, cache=CACHE, site=renderer.RENDER_SITE)
            else:
                m.metadata()
            before, hi, lo = m.r.copy(), m.hi, m.lo
            m.shared.accesses.clear()
            m.call(entry, *args)
            for register in (*range(16, 24), 26, 27, 28, 29, 30, 31):
                self.assertEqual(m.r[register], before[register], (entry, register))
            self.assertEqual((m.hi, m.lo), (hi, lo))
            self.assertFalse(any(address >= 0xBAD00000 for _, address, _ in m.shared.accesses))

    def test_magic_last_and_the_only_plain_state_store_is_terminal_fault(self):
        m = RendererMachine()
        m.prepare()
        m.metadata()
        m.shared.accesses.clear()
        m.capture()
        writes = [(address, size) for access, address, size in m.shared.accesses
                  if access == 'write' and m.record_address(1) <= address < m.record_address(2)]
        self.assertEqual(writes[-1], (m.record_address(1), 4))
        words = struct.unpack('<%dI' % (len(m.renderer_code) // 4), m.renderer_code)
        stores = [(index, word >> 26) for index, word in enumerate(words)
                  if word >> 26 in (0x2B, 0x38) and (word >> 21) & 31 == 8
                  and word & 0xFFFF == 0]
        self.assertEqual([op for _, op in stores], [0x38, 0x2B])
        self.assertEqual(m.renderer_base + stores[-1][0] * 4, m.labels['fault_store'])

    def test_only_two_external_private_validators_and_explicit_nop_delay_slots(self):
        m = RendererMachine()
        words = struct.unpack('<%dI' % (len(m.renderer_code) // 4), m.renderer_code)
        calls = []
        for index, word in enumerate(words):
            op, rs = word >> 26, (word >> 21) & 31
            if op in (2, 3):
                pc = m.renderer_base + index * 4
                target = ((pc + 4) & 0xF0000000) | ((word & 0x3FFFFFF) << 2)
                if not m.renderer_base <= target < m.renderer_base + len(m.renderer_code):
                    calls.append(target)
                    self.assertEqual(op, 3)
                self.assertEqual(words[index + 1], 0)
            if op in (4, 5) or (op == 0 and word & 63 == 8):
                if op == 0:
                    self.assertEqual(rs, 31)
                self.assertEqual(words[index + 1], 0)
        self.assertCountEqual(calls, [m.queue_labels['validate']] * 2
                              + [m.lineage_labels['validate']] * 2)

    def test_layout_types_capacities_wrap_overlap_external_validators_jump_region(self):
        self.assertEqual(renderer.memory_bytes(), 98320)
        self.assertEqual(renderer.MAGIC.to_bytes(4, 'little'), b'LQRD')
        defaults = dict(journal_address=JOURNAL, transport_address=QUEUE,
                        transport_entries={'validate': CODE - 0x100}, lineage_address=LINEAGE,
                        lineage_entries={'validate': CODE - 0x200}, revision_address=REVISION,
                        scope_address=SCOPE, code_base=CODE)
        for name, values in (
                ('capacity', (0, -1, True, 1.0, renderer.MAX_CAPACITY + 1)),
                ('journal_address', (True, 1, 0xFFFFFFFC, QUEUE, LINEAGE, REVISION, SCOPE)),
                ('transport_address', (True, 1, 0xFFFFFFFC, JOURNAL, LINEAGE, REVISION, SCOPE)),
                ('lineage_address', (True, 1, 0xFFFFFFFC, JOURNAL, QUEUE, REVISION, SCOPE)),
                ('revision_address', (True, 1, 0xFFFFFFFC, JOURNAL, QUEUE, LINEAGE, SCOPE)),
                ('scope_address', (True, 1, 0xFFFFFFFC, JOURNAL, QUEUE, LINEAGE, REVISION)),
                ('code_base', (True, 1, 0xFFFFFFFC, JOURNAL, QUEUE, LINEAGE, REVISION,
                               SCOPE, 0x0FFFFF00)),
                ('transport_entries', (None, {}, {'validate': True}, {'validate': 1},
                                       {'validate': 0}, {'validate': CODE},
                                       {'validate': JOURNAL}, {'validate': QUEUE},
                                       {'validate': CODE - 0x200}, {'validate': 0x1C700000})),
                ('lineage_entries', (None, {}, {'validate': True}, {'validate': 1},
                                     {'validate': 0}, {'validate': CODE},
                                     {'validate': JOURNAL}, {'validate': LINEAGE},
                                     {'validate': CODE - 0x100}, {'validate': 0x1C700000}))):
            for value in values:
                args = dict(defaults)
                args[name] = value
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    renderer.assemble(**args)
        for value in (0, -1, True, 1.0, renderer.MAX_CAPACITY + 1):
            with self.assertRaises(ValueError):
                renderer.memory_bytes(value)


if __name__ == '__main__':
    unittest.main()
