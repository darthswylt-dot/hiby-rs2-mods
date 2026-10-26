#!/usr/bin/env python3
"""Bounded native/source and emitted-callee premises for local owner issuance.

This is not an exhaustive indirect lock-order, runtime alias, scheduler,
initialized-mutex, stack-lifetime or native-generation-carrier proof. No source
image, hook, native producer, destructor or UI path is modified by these checks.
"""

import hashlib
import struct
import unittest

import reveal_paint_retirement_mips as owner
import reveal_registry_owner_mips as issue
import reveal_registry_owner_stage as stage
import reveal_registry_receipt_mips as receipt
import test_folderfollow_reveal_static_contract as source


class RegistryOwnerContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.elf = source.Elf32(source.SOURCE)
        digest = hashlib.sha256(cls.elf.data).hexdigest()
        if digest != source.SOURCE_SHA256 or len(cls.elf.data) != source.SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: SHA-256 {digest}, '
                                 f'size {len(cls.elf.data)}')

    def words(self, start, expected):
        for index, word in enumerate(expected):
            pc = start + index * 4
            with self.subTest(pc=f'{pc:#x}'):
                self.assertEqual(self.elf.word(pc), word)

    def test_registry_publication_is_complete_before_its_native_unlock_call(self):
        self.words(0x438A48, [0x8E030038, 0xAE020038,
                              0xAC450000, 0xAC430004,
                              0xAC620000, 0x8E190278,
                              0x0320F809, 0x02002021])
        self.assertEqual(receipt.HOOKS['published'],
                         (0x438A58, (0xAC620000, 0x8E190278)))
        self.assertEqual(issue.PUBLICATION_SITE, 0x438A5C)
        # This local callback adds13C->148 nesting after the final link store;
        # it does not observe successful native13C release at this point.

    def test_known_paint_sections_do_not_load_a_nested_registry_callback(self):
        for start, end in ((0x4398A0, 0x4398F0), (0x439900, 0x43994C),
                            (0x439960, 0x4399AC), (0x4399C0, 0x439A0C)):
            with self.subTest(start=f'{start:#x}'):
                registry_loads = []
                for pc in range(start, end, 4):
                    word = self.elf.word(pc)
                    if (word >> 26 == 35 and (word >> 16) & 31 == 25
                            and word & 0xFFFF in (0x274, 0x278)):
                        registry_loads.append(pc)
                self.assertEqual(registry_loads, [])
        # Callee/list/heap bounds and exact calls are pinned by the earlier
        # test_reveal_paint_queue_lock_contract module. This bounded absence
        # cannot classify arbitrary rebound callbacks or establish no cycles.

    def test_known_controller_teardown_releases_paint_before_later_registry_lock(self):
        self.words(0x43CB80, [0x02202021, 0x0C10E628, 0xAE20012C,
                              0x8E390274, 0x02202021,
                              0x0320F809, 0x26320034])
        self.words(0x4398CC, [0x8E190288, 0x02002021,
                              0x0320F809, 0xAE000128])
        self.words(0x4398E8, [0x03E00008, 0x27BD0020])
        # Sequential148 then13C is not a reverse nested148->13C edge. Earlier
        # outer shutdown mutations and arbitrary workers remain uncovered.

    def test_native_constructor_callbacks_load_distinct_mutex_fields_not_a_recursive_contract(self):
        self.words(0x437D28, [0x0C119B68, 0x8C84013C])
        self.words(0x437CE8, [0x0C119B68, 0x8C840148])
        self.words(0x437DA8, [0x0C119B70, 0x8C84013C])
        self.words(0x437D68, [0x0C119B70, 0x8C840148])
        self.words(0x466D74, [0x00402021, 0x00002821, 0x0C296E28])
        # Distinct fields do not prove distinct live allocations. The stage
        # separately rejects overlapping24-byte object extents at emission.

    def test_checked_open_owner_reachable_external_calls_are_only_raw_mutex_services(self):
        composition = stage.assemble(0x1F50000, 0x1F80000, 0x1F70000,
                                     0x1800000, 0x1F20300, 0x1F20200, 0x1E80000)
        data, base = composition['code'], composition['code_base']
        kernel_end = base + composition['kernel_code_bytes']
        todo = [composition['owner_labels']['open_owner']]
        visited, external = set(), set()
        while todo:
            pc = todo.pop()
            if pc in visited:
                continue
            self.assertTrue(base <= pc < kernel_end, hex(pc))
            visited.add(pc)
            word = struct.unpack_from('<I', data, pc - base)[0]
            opcode, function = word >> 26, word & 63
            if opcode in (2, 3):
                destination = ((pc + 4) & 0xF0000000) | ((word & 0x3FFFFFF) << 2)
                if opcode == 3:
                    external.add(destination)
                    todo.append(pc + 8)
                else:
                    todo.append(destination)
            elif opcode in (1, 4, 5, 6, 7):
                immediate = word & 0xFFFF
                if immediate & 0x8000:
                    immediate -= 0x10000
                todo.extend((pc + 8, pc + 4 + immediate * 4))
            elif opcode == 0 and function == 8:
                self.assertEqual((word >> 21) & 31, 31)
            else:
                self.assertFalse(opcode == 0 and function == 9,
                                 'unclassified indirect call in open_owner CFG')
                todo.append(pc + 4)
        self.assertEqual(external, {owner.RAW_LOCK, owner.RAW_UNLOCK})
        # Both outcomes of every local conditional are visited, including
        # shared failure/unlock/restore paths. Imported services are the bound
        # analysis boundary, not a promise about pthread internals/scheduling.

    def test_owned_callback_snapshots_do_not_overlap_argument_homes_or_register_saves(self):
        for module, offset, size in ((receipt, receipt.CALLBACK_REQUEST_OFFSET,
                                      receipt.CALLBACK_REQUEST_BYTES),
                                     (issue, issue.SNAPSHOT, issue.REQUEST_BYTES)):
            with self.subTest(module=module.__name__):
                occupied = {word for saved in (*module.SAVE.values(), module.HI, module.LO)
                            for word in range(saved, saved + 4)}
                self.assertGreaterEqual(offset, 16)
                self.assertLessEqual(offset + size, module.FRAME)
                self.assertFalse(occupied.intersection(range(offset, offset + size)))
                self.assertEqual(module.FRAME % 8, 0)
        self.assertEqual(owner.FRAME % 8, 0)
        # Separate retained nested frames are additive; these offsets do not
        # establish available stack across native/library or unrelated calls.


if __name__ == '__main__':
    unittest.main()
