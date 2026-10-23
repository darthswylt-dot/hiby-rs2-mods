#!/usr/bin/env python3
"""Source/emission premises for a host-only, reject-only request-age report.

The existing renderer-transport image is assembled only in memory. No new
builder, firmware hook, BSS layout, native behavior or device operation is
introduced here. Counter gaps exclude known histories; no matching arithmetic
can prove a fresh UI cause, owner, native lifetime or coherent acquisition.
"""

import hashlib
import struct
import unittest

import build_reveal_renderer_transport_stage as existing
import reveal_contents_revision_mips as revision
import test_folderfollow_reveal_static_contract as source
import test_reveal_contents_revision_contract as boundary
import test_reveal_contents_revision_mips as counter_fixture
import test_reveal_renderer_transport_stage as renderer_fixture
from build_reveal_bridge_diag import b


CAPACITIES = dict(capacity=2, row_capacity=2, operation_capacity=2,
                  scope_capacity=2, birth_capacity=2, transport_capacity=2,
                  renderer_capacity=2)


class RevealRequestAgeContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = source.SOURCE.read_bytes()
        digest = hashlib.sha256(cls.source).hexdigest()
        if digest != source.SOURCE_SHA256 or len(cls.source) != source.SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: SHA-256 {digest}, '
                                 f'size {len(cls.source)}')
        cls.elf = source.Elf32(source.SOURCE)
        # Existing, unchanged builder; no output file or new firmware format.
        cls.image, cls.meta = existing.build(cls.source, **CAPACITIES)
        cls.labels = cls.meta['labels']

    reachable = boundary.RevealContentsRevisionContractTests.reachable
    dominated = boundary.RevealContentsRevisionContractTests.dominated

    def anchors(self, values):
        for pc, expected in values.items():
            with self.subTest(pc=f'{pc:#x}'):
                self.assertEqual(self.elf.word(pc), expected)

    def emitted_word(self, pc):
        return struct.unpack_from('<I', self.image,
                                  self.meta['code_offset'] + pc - self.meta['code_base'])[0]

    def routine(self, label, native_resume):
        start = self.labels[label]
        for pc in range(start, start + 0x400, 4):
            if self.emitted_word(pc) == b.j_type(2, native_resume):
                self.assertEqual(self.emitted_word(pc + 4), 0)
                return [(at, self.emitted_word(at)) for at in range(start, pc + 8, 4)]
        self.fail('missing bounded native resume for ' + label)

    @staticmethod
    def calls(words):
        return [((pc + 4) & 0xF0000000) | ((word & 0x3FFFFFF) << 2)
                for pc, word in words if word >> 26 == 3]

    def machine(self):
        return renderer_fixture.RendererMachine(self.image, self.meta)

    def entry(self, machine):
        frame = renderer_fixture.gap.ENGINE_STACK
        machine.r[29], machine.r[31] = frame + 0x30, renderer_fixture.gap.RETURN
        machine.run_at(0x4906F8, 0x490700)
        return frame

    def test_existing_source_and_native_entry_pair_remain_pinned(self):
        self.anchors({0x4906F8: 0x27BDFFD0, 0x4906FC: 0xAFBF002C,
                      0x438248: 0x00C0A021, 0x43824C: 0x00E08821,
                      0x490758: 0x00408021, 0x49076C: 0xAE113B50})
        words = self.routine('contents_render_entry', 0x490700)
        self.assertEqual([word for _, word in words[:3]],
                         [0x27BDFFD0, 0xAFBF002C, 0x27BDFF80])
        self.assertNotEqual(self.labels['contents_render_entry'],
                            self.labels['contents_legacy_render_entry'])

    def test_original_entry_emits_exactly_one_bump_and_never_chains_legacy_entry(self):
        words = self.routine('contents_render_entry', 0x490700)
        self.assertEqual(self.calls(words), [self.labels['contents_bump']])
        jumps = [((pc + 4) & 0xF0000000) | ((word & 0x3FFFFFF) << 2)
                 for pc, word in words if word >> 26 == 2]
        self.assertEqual(jumps, [0x490700])
        self.assertNotIn(self.labels['contents_legacy_render_entry'], jumps)
        stores = [(pc, word) for pc, word in words if word == 0xAFA20090]
        self.assertEqual(stores, [(self.labels['contents_render_scope_quiet'], 0xAFA20090)])

    def test_scope_gate_can_only_erase_the_returned_entry_ticket_before_its_store(self):
        words = self.routine('contents_render_entry', 0x490700)
        call_index = next(i for i, (pc, word) in enumerate(words)
                          if word == b.j_type(3, self.labels['contents_bump']))
        scope_address = self.meta['scope_buffer']
        expected = [0, b.lui(8, scope_address >> 16), b.ori(8, 8, scope_address & 0xFFFF),
                    0x0000000F, b.lw(8, 0, 8), 0x00084402,
                    0x11000002, 0, 0x00001021, 0xAFA20090]
        self.assertEqual([word for _, word in words[call_index + 1:call_index + 11]], expected)
        # No current-revision reload can replace the helper's own return;
        # active/fault high bits select zero, not a fabricated fresh stamp.

    def test_entry_bumps_once_and_active_scope_erases_without_reusing_other_carrier(self):
        frame = renderer_fixture.gap.ENGINE_STACK
        for scope_state, stamp in ((0, 1), (0x10001, 0), (0xFFFFFFFF, 0)):
            with self.subTest(scope_state=scope_state):
                m = self.machine()
                m.put(self.meta['scope_buffer'], scope_state, 4)
                m.put(frame + 0x14, 0xCAFEBABE, 4)
                self.entry(m)
                self.assertEqual(m.get(self.meta['contents_revision_buffer'], 4), 1)
                self.assertEqual(m.get(frame + 0x10, 4), stamp)
                self.assertEqual(m.get(frame + 0x14, 4), 0xCAFEBABE)

    def test_another_bump_after_own_return_does_not_restamp_original_entry(self):
        m = self.machine()
        injected = []

        def interleave(pc):
            if pc == self.labels['contents_render_scope_quiet'] and not injected:
                injected.append(pc)
                saved, hi, lo = m.r.copy(), m.hi, m.lo
                m.r[31] = renderer_fixture.gap.RETURN
                m.run_at(self.labels['contents_bump'], renderer_fixture.gap.RETURN)
                m.r, m.hi, m.lo = saved, hi, lo

        m.before_instruction = interleave
        frame = self.entry(m)
        self.assertTrue(injected)
        self.assertEqual(m.get(self.meta['contents_revision_buffer'], 4), 2)
        self.assertEqual(m.get(frame + 0x10, 4), 1)

    def test_counter_issues_unique_tickets_and_saturates_without_mask_or_wrap(self):
        shared = counter_fixture.SharedState()
        one, two = counter_fixture.RevisionMachine(shared), counter_fixture.RevisionMachine(shared)
        one.start('bump').until('bump_sc')
        two.start('bump').until('bump_sc')
        self.assertEqual((one.run_to_return(), two.run_to_return(), shared.counter), (1, 2, 2))
        saturated = counter_fixture.RevisionMachine(
            counter_fixture.SharedState(revision.REVISION_MASK - 1))
        self.assertEqual(saturated.call('bump'), 0x7FFFFFFF)
        self.assertEqual(saturated.call('bump'), 0)
        self.assertEqual(saturated.shared.counter, revision.FAULT)
        self.assertEqual(saturated.call('bump'), 0)
        self.assertEqual(saturated.shared.counter, revision.FAULT)
        # Failed/exhausted marks are not wrapped or masked back into tickets.

    def test_named_entry_cfg_orders_outer_original_entry_root_and_later_observer(self):
        self.dominated(0x438200, 0x4388B8, 0x438248, 0x438740)
        self.anchors({0x438740: 0x0320F809, 0x438744: 0x02002821})
        self.dominated(0x4906E0, 0x490898, 0x4906F8, 0x490758, 0x49076C)
        self.dominated(0x4906E0, 0x490898, 0x490758, 0x49076C)
        # Applies only to this exact named-entry chain, not unknown native
        # callers, callee behavior, UI ownership or first physical execution.

    def test_producer_return_is_after_append_but_not_a_pre_renderer_timestamp(self):
        self.anchors({
            0x8B42E8: 0x0C22CF30, 0x8B42EC: 0xAE22000C,
            0x8B42F0: 0x8E280000, 0x8B42F4: 0x8E240004,
            0x8B3D24: 0xACE2000C, 0x8B3D4C: 0xAE020000,
            0x8B4754: 0x8FC50000, 0x8B4758: 0x8FC60004,
            0x8B475C: 0x0C22CFE8, 0x8B4760: 0x02A02021,
        })
        self.assertEqual(0x8B42E8 + 8, 0x8B42F0)
        # Another invocation can consume a linked node before this caller
        # resumes at42F0. Source instruction order creates no cross-thread
        # RETURN-before-callback law. Existing lifetime premises still apply.

    def test_worker_postfill_and_bind_have_their_own_later_known_bumps(self):
        self.anchors({
            0x48D280: 0x08123420, 0x48D284: 0,
            0x48D080: 0x27BDFFC0, 0x48D084: 0xAFBF003C,
            0x48F880: 0x27BDFFD0, 0x48F884: 0xAFBF002C,
            0x4A0EE0: 0x27BDFFC0, 0x4A0EE4: 0xAFB1002C,
        })
        for label, resume in (('contents_worker_entry', 0x48D088),
                              ('contents_postfill', 0x48F888),
                              ('contents_native_bind', 0x4A0EE8)):
            with self.subTest(label=label):
                self.assertEqual(self.calls(self.routine(label, resume)),
                                 [self.labels['contents_bump']])
        # These later operation phases cannot retrospectively date a queued
        # cause. The exact observed sequence already checks their own+1/+2/+3.

    def test_scope_begin_and_revision_are_separate_ordered_updates_not_one_clock(self):
        for label, resume in (('contents_reset', 0x491248),
                              ('contents_reconcile', 0x4919E8)):
            with self.subTest(label=label):
                self.assertEqual(self.calls(self.routine(label, resume)),
                                 [self.labels['scope_begin'], self.labels['contents_bump']])
        # The active/issued update occurs inside begin, BEFORE the independent
        # revision call. Its new tickets can therefore coexist with old REV.
        start = self.labels['scope_reset_return']
        words = []
        for pc in range(start, start + 0x300, 4):
            word = self.emitted_word(pc)
            words.append((pc, word))
            if word == 0x03E00008:
                break
        self.assertEqual(self.calls(words),
                         [self.labels['contents_bump'], self.labels['scope_end']])
        # Exit advances revision before clearing active. No strict equality
        # or fixed ratio between scope-issued and contents revision follows.


if __name__ == '__main__':
    unittest.main()
