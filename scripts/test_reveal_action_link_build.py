#!/usr/bin/env python3
"""Exact offline action-link image/schema checks; no device or file output."""
import hashlib
import struct
import unittest

import build_reveal_action_link_stage as stage
import reveal_action_link_mips as core
from test_folderfollow_reveal_static_contract import SOURCE
from verify_reveal_action_link_stage import verify


CAPACITIES = dict(capacity=2, row_capacity=2, operation_capacity=2, scope_capacity=2,
                  birth_capacity=8, transport_capacity=8, renderer_capacity=4,
                  playback_dispatch_capacity=2, action_link_capacity=16)


class RevealActionLinkBuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SOURCE.read_bytes()
        cls.image, cls.meta = stage.build(cls.source, **CAPACITIES)

    def emitted(self, pc):
        return struct.unpack_from('<I', self.image,
                                  self.meta['code_offset'] + pc - self.meta['code_base'])[0]

    def test_exact_layout_native_widths_and_control_flow_inventory(self):
        checked = verify(self.source, self.image, **CAPACITIES)
        self.assertEqual(len(stage.HOOKS), 42)
        self.assertEqual(len(stage.NEW_HOOKS), 5)
        self.assertEqual(checked['action_link_memory_bytes'], 16 + 96 * 16)
        self.assertEqual(checked['action_link_buffer'], self.meta['playback_dispatch_buffer']
                         + self.meta['playback_dispatch_memory_bytes'])
        self.assertEqual(checked['action_element_bytes'], 20)
        self.assertEqual(checked['paint_element_bytes'], 36)
        self.assertFalse(checked['autoscroll'])
        self.assertFalse(checked['notification_currentness_proven'])
        self.assertFalse(checked['native_paint_payload_lease_proven'])
        self.assertEqual(len(checked['indirect_dispatch_tails']), 2)
        self.assertEqual(sorted(checked['external_calls']), [0x5C31C0, 0x6F7CA0])
        self.assertEqual(len(checked['indirect_append_calls']), 1)

    def test_previous_dispatch_default_stays_byte_identical(self):
        image, _ = stage.previous.build(self.source)
        self.assertEqual(hashlib.sha256(image).hexdigest(),
                         'a9a6f02fd48a3b57e27e3bb19c9e8c2b8329b6602cc12988091dfbb98c2abe2c')
        golden, _ = stage.normalize_source(self.source)
        self.assertEqual(stage.build(golden, **CAPACITIES)[0], self.image)

    def test_only_the_birth_private_capture_call_is_redirected(self):
        start, stop = self.meta['labels']['birth_entry'], self.meta['labels']['birth_enqueue_begin']
        new_call = stage.b.j_type(3, self.meta['labels']['action_birth_capture'])
        old_call = stage.b.j_type(3, self.meta['labels']['queue_birth_capture'])
        calls = [pc for pc in range(start, stop, 4) if self.emitted(pc) == new_call]
        self.assertEqual(calls, [self.meta['labels']['action_birth_private_call']])
        self.assertFalse(any(self.emitted(pc) == old_call for pc in range(start, stop, 4)))
        helper = self.meta['labels']['action_birth_capture']
        done = self.meta['labels']['action_birth_done']
        self.assertEqual(sum(self.emitted(pc) == old_call for pc in range(helper, done, 4)), 1)
        self.assertEqual(self.emitted(calls[0] + 4), 0)

    def test_native_calls_delay_slots_and_capacity_requests_remain_exact(self):
        golden, _ = stage.normalize_source(self.source)
        for pc in (0x4BACD8, 0x4BACDC, 0x4BAA60, 0x4BAA64, 0x490A08,
                   0x490A0C, 0x490A58, 0x490A5C, 0x43C8A4, 0x43C8A8,
                   0x439924, 0x439928, 0x4399F0, 0x4399F4, 0x43C968,
                   0x43C96C, 0x459874, 0x459878, 0x8B4294, 0x8B42E8,
                   0x8B42EC, 0x4BAAEC, 0x439858):
            with self.subTest(pc=hex(pc)):
                self.assertEqual(self.image[pc - stage.BASE:pc - stage.BASE + 4],
                                 golden[pc - stage.BASE:pc - stage.BASE + 4])

    def test_all_added_native_hooks_replay_source_pairs_before_private_work(self):
        for name, (_, pair) in stage.NEW_HOOKS.items():
            pc = self.meta['labels'][name]
            with self.subTest(name=name):
                self.assertEqual([self.emitted(pc), self.emitted(pc + 4)], list(pair))
                self.assertEqual(self.emitted(pc + 8), stage.b.addiu(29, 29, -stage.FRAME))

    def test_tampered_width_hook_native_call_and_private_link_are_refused(self):
        for pc in (0x4BAAF4, 0x439844, 0x4BACBC, 0x4BACD8, 0x4BACDC,
                   0x4BA96C, 0x4909A4, 0x43C868, 0x4399E8, 0x4399F0,
                   0x459874, self.meta['labels']['action_birth_private_call']):
            changed = bytearray(self.image)
            offset = (pc - stage.BASE if pc < self.meta['code_base'] else
                      self.meta['code_offset'] + pc - self.meta['code_base'])
            changed[offset] ^= 1
            with self.subTest(pc=hex(pc)), self.assertRaises(ValueError):
                verify(self.source, changed, **CAPACITIES)

    def test_active_modes_bad_sources_and_capacities_are_refused(self):
        for value in (True, 0, 1, None, 'yes'):
            with self.assertRaises(ValueError):
                stage.build(self.source, enable_reveal=value)
        for value in (0, -1, True, None, 1.5, core.MAX_CAPACITY + 1):
            with self.assertRaises(ValueError):
                stage.build(self.source, **dict(CAPACITIES, action_link_capacity=value))
        for raw in (self.image, self.source[:-1], bytes(len(self.source))):
            with self.assertRaises(ValueError):
                stage.build(raw, **CAPACITIES)

    def test_private_region_alias_wrap_and_code_overlap_are_refused(self):
        names = ('buffer', 'row_buffer', 'contents_revision_buffer', 'operation_buffer',
            'scope_buffer', 'birth_buffer', 'transport_buffer', 'renderer_transport_buffer',
            'playback_dispatch_buffer')
        addresses = [self.meta[name] for name in names]
        code, journal = self.meta['code_base'], self.meta['action_link_buffer']
        for address in (True, -4, journal + 1, *addresses, code, code - 4, 0xFFFFFFFC):
            with self.subTest(address=address), self.assertRaises(ValueError):
                stage.assemble(addresses, address, code, **CAPACITIES)


if __name__ == '__main__':
    unittest.main()
