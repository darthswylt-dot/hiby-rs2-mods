#!/usr/bin/env python3
"""Execute the native worker frame and its bounded terminal tail.

The actual 47C580 prologue, including its delay-slot S1 save, executes through
the call to a bounded 466C40 service. A fixed cut at 47C5B0 then enters the
terminal frontier at 47C6E8. No earlier worker loop, +10 release, completion
handshake or thread termination is certified by that cut.

The native 466DC0 wrapper executes through its raw A5B830 service and its
forced-zero return. Raw release and free are explicit hostile-ABI substitutes;
the free service is not a native allocator or free-authority proof. H, its
nonnull buffer and the live stack are independently mapped. This small
interpreter is independent of the preceding stages' execution fixtures.
"""

import hashlib
from pathlib import Path
import struct
import unittest

from mips_static_trace import Elf32
import reveal_worker_terminal_tail_mips as core
import reveal_worker_terminal_tail_stage as stage
import test_reveal_dialog_retention_gate_mips as full_fixture


MASK = 0xFFFFFFFF
IMAGE = Path(__file__).resolve().parents[1] / 'artifacts/import-20261001/hiby_player_02fd.bin'
IMAGE_SHA256 = '02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87'
CONTROLLER, REGISTRY_MUTEX, GUARD = 0x1800000, 0x1F20300, 0x1F20900
CODE, DIALOG, MUTEX, BUFFER = 0x1E98324, 0x1D04000, 0x1D04100, 0x1D04200
STACK, RETURN = 0x2003000, 0xF001000
WORKER_ENTRY, PROLOGUE_END, TERMINAL = 0x47C580, 0x47C5B0, 0x47C6E8
LOG, RAW_RELEASE, FREE = 0x466C40, 0xA5B830, 0x466A80
FREE_RESULT, BAD_BUFFER = 0x9A000001, 0xDEADBEEF
SAVES = {16: 0x1C, 17: 0x20, 18: 0x24, 19: 0x28,
         20: 0x2C, 21: 0x30, 31: 0x34}


class MemoryFault(RuntimeError):
    def __init__(self, address, operation):
        self.address, self.operation = address, operation
        super().__init__(f'{operation} of unmapped or invalid word at {address:08X}')


class WorkerTerminalMachine:
    """Word-only bounded interpreter; no emitted-code or CPU-result cache."""

    def __init__(self, image, code, labels, *, hooked=True, buffer=BUFFER,
                 raw_status=0, invalidate_after_release=None, violate_s1=False):
        self.image, self.code, self.labels = image, code, labels
        self.patches = {}
        if hooked:
            for pc, pair in core.hook_words(labels).items():
                self.patches.update({pc + index * 4: word
                                     for index, word in enumerate(pair)})
        self.regions = {DIALOG: bytearray(128), MUTEX: bytearray(32),
                        BUFFER: bytearray(64), STACK - 0x1000: bytearray(0x1100)}
        self.r = [0 if register == 0 else 0x11000000 + register * 0x101
                  for register in range(32)]
        self.r[4], self.r[29], self.r[31] = DIALOG, STACK, RETURN
        self.hi, self.lo = 0x12345678, 0x89ABCDEF
        self.caller = self.r.copy()
        self.raw_status, self.invalidate_after_release = raw_status, invalidate_after_release
        self.violate_s1 = violate_s1
        self.pc, self.accesses, self.trace, self.services, self.frees = 0, [], [], [], []
        self.release_boundary, self.release_h_field = None, None
        self.seed(DIALOG + 0x0C, MUTEX)
        self.seed(DIALOG + 0x10, MUTEX + 0x40)
        self.seed(DIALOG + 0x14, buffer)
        self.seed(BUFFER, 0xAABBCCDD)

        # Run the actual native W56 prologue and its outgoing call. The fixed
        # subsequent cut models only the terminal frontier, never the loop.
        self.run_at(WORKER_ENTRY, PROLOGUE_END)
        self.prologue_trace = tuple(self.trace)
        self.prologue_services = tuple(self.services)
        self.worker_sp = self.r[29]
        for register in range(17, 22):
            self.r[register] = 0xCC000000 + register
        self.accesses.clear()
        self.trace.clear()
        self.services.clear()

    def locate(self, address):
        if address % 4:
            raise MemoryFault(address, 'unaligned access')
        for base, data in self.regions.items():
            if base <= address and address + 4 <= base + len(data):
                return data, address - base
        raise MemoryFault(address, 'access')

    def peek(self, address):
        data, offset = self.locate(address)
        return struct.unpack_from('<I', data, offset)[0]

    def seed(self, address, value):
        data, offset = self.locate(address)
        struct.pack_into('<I', data, offset, value & MASK)

    def read(self, address):
        self.accesses.append(('read', self.pc, address))
        return self.peek(address)

    def write(self, address, value):
        self.accesses.append(('write', self.pc, address))
        self.seed(address, value)

    def word(self, pc):
        if pc in self.patches:
            return self.patches[pc]
        if CODE <= pc < CODE + len(self.code):
            return struct.unpack_from('<I', self.code, pc - CODE)[0]
        allowed = ((WORKER_ENTRY, PROLOGUE_END), (TERMINAL, 0x47C72C),
                   (0x466DC0, 0x466DE0))
        if any(start <= pc < end for start, end in allowed):
            return self.image.word(pc)
        raise AssertionError(f'fixture reached an unbounded native instruction: {pc:08X}')

    def plain(self, word, pc):
        self.pc = pc
        self.trace.append(pc)
        op, rs, rt = word >> 26, (word >> 21) & 31, (word >> 16) & 31
        imm, fn, rd = word & 0xFFFF, word & 63, (word >> 11) & 31
        signed = imm - 0x10000 if imm & 0x8000 else imm
        if word in (0, 0xF):
            # SYNC is traced as an ordering instruction. This interpreter
            # supplies no target-cache or inter-core ordering proof.
            pass
        elif op == 9:
            self.r[rt] = (self.r[rs] + signed) & MASK
        elif op == 15:
            self.r[rt] = imm << 16
        elif op == 35:
            self.r[rt] = self.read((self.r[rs] + signed) & MASK)
        elif op == 43:
            self.write((self.r[rs] + signed) & MASK, self.r[rt])
        elif op == 0 and fn == 0x21:
            self.r[rd] = (self.r[rs] + self.r[rt]) & MASK
        else:
            raise AssertionError(f'unsupported plain instruction {word:08X} at {pc:08X}')
        self.r[0] = 0

    def hostile_result(self, value, tag):
        # O32 callees may clobber caller registers, HI/LO and the four outgoing
        # homes. S1 and all other callee-saved registers remain intact.
        for register in (*range(1, 16), 24, 25):
            self.r[register] = (0xBA000000 + tag * 0x100 + register) & MASK
        self.r[2], self.r[3] = value & MASK, 0xBAD00003
        self.hi, self.lo = 0xCAFE0000 + tag, 0xFACE0000 + tag
        for index in range(4):
            self.write(self.r[29] + index * 4, 0xDB000000 + tag * 0x100 + index)

    def service(self, target):
        self.pc = target
        self.services.append((target, self.r[4], self.r[29], self.r[31]))
        if target == RAW_RELEASE:
            # This host-side snapshot observes instruction order; it is not
            # a native read, nor evidence that the mutex is held or initialized.
            self.release_h_field = self.peek(DIALOG + 0x14)
            self.hostile_result(self.raw_status, 2)
            if self.violate_s1:
                self.r[17] = BAD_BUFFER
            if self.invalidate_after_release == 'unmap':
                del self.regions[DIALOG]
            elif self.invalidate_after_release == 'poison':
                self.regions[DIALOG][:] = struct.pack('<I', BAD_BUFFER) * 32
            self.release_boundary = len(self.accesses)
        elif target == FREE:
            pointer = self.r[4]
            if pointer != BUFFER or BUFFER not in self.regions:
                raise MemoryFault(pointer, 'bounded free')
            self.frees.append(pointer)
            del self.regions[BUFFER]
            self.hostile_result(FREE_RESULT, 3)
        elif target == LOG:
            self.hostile_result(0, 1)
        else:
            raise AssertionError(f'unbounded service {target:08X}')

    def run_at(self, start, stop=RETURN):
        pc = start
        for _ in range(1000):
            if pc == stop:
                self.pc = pc
                return self.r[2]
            if pc in (LOG, RAW_RELEASE, FREE):
                self.service(pc)
                pc = self.r[31]
                continue
            word = self.word(pc)
            op, rs, rt, fn = word >> 26, (word >> 21) & 31, (word >> 16) & 31, word & 63
            if op in (2, 3, 4) or (op == 0 and fn == 8):
                self.trace.append(pc)
                if op in (2, 3):
                    destination = ((pc + 4) & 0xF0000000) | ((word & 0x3FFFFFF) << 2)
                    if op == 3:
                        self.r[31] = pc + 8
                elif op == 4:
                    imm = word & 0xFFFF
                    signed = imm - 0x10000 if imm & 0x8000 else imm
                    destination = pc + 4 + signed * 4 if self.r[rs] == self.r[rt] else pc + 8
                else:
                    destination = self.r[rs]
                self.plain(self.word(pc + 4), pc + 4)
                pc = destination & MASK
            else:
                self.plain(word, pc)
                pc += 4
        raise AssertionError('bounded terminal instruction budget exhausted')

    def terminal(self, stop=RETURN):
        return self.run_at(TERMINAL, stop)

    def service_arguments(self):
        # The generated caller's saved return differs intentionally. Service
        # order, argument and actual outgoing SP remain directly comparable.
        return [event[:3] for event in self.services]

    def post_release_h_accesses(self):
        assert self.release_boundary is not None
        return [event for event in self.accesses[self.release_boundary:]
                if DIALOG <= event[2] < DIALOG + 128]


class WorkerTerminalTailTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = Elf32(IMAGE)
        if hashlib.sha256(cls.image.data).hexdigest() != IMAGE_SHA256:
            raise AssertionError('worker fixture requires the preserved 02fd source image')
        cls.code, cls.labels = core.assemble(CONTROLLER, REGISTRY_MUTEX, CODE, GUARD)

    def machine(self, **options):
        return WorkerTerminalMachine(self.image, self.code, self.labels, **options)

    def assert_native_restoration(self, machine):
        self.assertEqual(machine.r[29], STACK)
        self.assertEqual(machine.r[31], RETURN)
        for register in (*range(16, 24), 28, 30):
            self.assertEqual(machine.r[register], machine.caller[register], f'register {register}')
        for register, offset in SAVES.items():
            self.assertEqual(machine.peek(machine.worker_sp + offset), machine.caller[register])
        self.assertIn(0x47C71C, machine.trace)
        self.assertIn(0x47C728, machine.trace)

    def assert_no_post_release_h_or_fixed_storage(self, machine):
        self.assertEqual(machine.post_release_h_accesses(), [])
        self.assertFalse(any(address in (CONTROLLER, REGISTRY_MUTEX, GUARD)
                             for _, _, address in machine.accesses))

    def test_actual_worker_prologue_establishes_the_saved_s1_and_ra(self):
        machine = self.machine()
        self.assertEqual(machine.worker_sp, STACK - 56)
        self.assertEqual(machine.peek(machine.worker_sp + 0x20), machine.caller[17])
        self.assertEqual(machine.peek(machine.worker_sp + 0x34), RETURN)
        self.assertEqual(machine.prologue_trace, tuple(range(WORKER_ENTRY, PROLOGUE_END, 4)))
        self.assertEqual([event[0] for event in machine.prologue_services], [LOG])
        self.assertEqual(machine.prologue_services[0][2:], (STACK - 56, PROLOGUE_END))

    def test_null_buffer_matches_native_results_and_restores_the_real_worker_frame(self):
        native, guarded = self.machine(hooked=False, buffer=0), self.machine(buffer=0)
        native.terminal()
        guarded.terminal()
        self.assertEqual((guarded.r, guarded.hi, guarded.lo), (native.r, native.hi, native.lo))
        self.assertEqual(guarded.service_arguments(), native.service_arguments())
        self.assertEqual([event[0] for event in guarded.services], [RAW_RELEASE])
        self.assertEqual(guarded.frees, [])
        self.assertEqual(guarded.peek(DIALOG + 0x14), 0)
        self.assert_native_restoration(guarded)
        self.assert_no_post_release_h_or_fixed_storage(guarded)

    def test_nonnull_buffer_matches_native_services_results_and_saved_registers(self):
        native, guarded = self.machine(hooked=False), self.machine()
        native.terminal()
        guarded.terminal()
        self.assertEqual((guarded.r, guarded.hi, guarded.lo), (native.r, native.hi, native.lo))
        self.assertEqual(guarded.service_arguments(), native.service_arguments())
        self.assertEqual([event[0] for event in guarded.services], [RAW_RELEASE, FREE])
        self.assertEqual(guarded.frees, [BUFFER])
        self.assertEqual(guarded.peek(DIALOG + 0x14), 0)
        self.assert_native_restoration(guarded)
        self.assert_no_post_release_h_or_fixed_storage(guarded)

    def test_pointer_is_detached_before_release_and_held_in_saved_s1_scratch(self):
        guarded = self.machine()
        guarded.terminal(stop=self.labels['captured'])
        self.assertEqual(guarded.r[17], BUFFER)
        self.assertEqual(guarded.peek(DIALOG + 0x14), 0)
        self.assertEqual(guarded.services, [])
        self.assertEqual([event[2] for event in guarded.accesses if event[0] == 'read'],
                         [DIALOG + 0x0C, DIALOG + 0x14])
        self.assertEqual([event[2] for event in guarded.accesses if event[0] == 'write'],
                         [DIALOG + 0x14])
        guarded.run_at(self.labels['captured'])
        native = self.machine(hooked=False)
        native.terminal()
        self.assertEqual((guarded.release_h_field, native.release_h_field), (0, BUFFER))
        self.assertEqual(guarded.services[0][1:], (MUTEX, STACK - 56 - 32, 0x466DD0))
        self.assertIn(0x466DD4, guarded.trace)
        self.assertEqual(guarded.trace.count(TERMINAL + 4), 1)
        self.assert_native_restoration(guarded)

    def test_native_masked_wrapper_still_overwrites_each_chosen_raw_error_with_zero(self):
        for status in (1, 16, MASK):
            with self.subTest(status=status):
                native = self.machine(hooked=False, buffer=0, raw_status=status)
                guarded = self.machine(buffer=0, raw_status=status)
                native.terminal()
                guarded.terminal()
                self.assertEqual(guarded.r[2:4], [0, 0xBAD00003])
                self.assertEqual((guarded.r, guarded.hi, guarded.lo), (native.r, native.hi, native.lo))
                self.assertEqual([event[0] for event in guarded.services], [RAW_RELEASE])
                self.assert_native_restoration(guarded)

    def test_raw_errors_do_not_add_retries_or_change_the_existing_optional_free_policy(self):
        for status in (1, 16, MASK):
            with self.subTest(status=status):
                native = self.machine(hooked=False, raw_status=status)
                guarded = self.machine(raw_status=status)
                native.terminal()
                guarded.terminal()
                self.assertEqual(guarded.service_arguments(), native.service_arguments())
                self.assertEqual(guarded.frees, [BUFFER])
                self.assertEqual(guarded.r[2], FREE_RESULT)
                self.assertEqual((guarded.r, guarded.hi, guarded.lo), (native.r, native.hi, native.lo))
                self.assert_no_post_release_h_or_fixed_storage(guarded)

    def test_unmapped_h_after_release_breaks_native_tail_but_not_captured_buffer_tail(self):
        native = self.machine(hooked=False, invalidate_after_release='unmap')
        with self.assertRaises(MemoryFault) as failed:
            native.terminal()
        self.assertEqual(failed.exception.address, DIALOG + 0x14)
        guarded = self.machine(invalidate_after_release='unmap')
        guarded.terminal()
        self.assertEqual(guarded.frees, [BUFFER])
        self.assert_native_restoration(guarded)
        self.assert_no_post_release_h_or_fixed_storage(guarded)

    def test_null_capture_also_needs_no_h_after_release(self):
        native = self.machine(hooked=False, buffer=0, invalidate_after_release='unmap')
        with self.assertRaises(MemoryFault) as failed:
            native.terminal()
        self.assertEqual(failed.exception.address, DIALOG + 0x14)
        guarded = self.machine(buffer=0, invalidate_after_release='unmap')
        guarded.terminal()
        self.assertEqual(guarded.frees, [])
        self.assert_native_restoration(guarded)
        self.assert_no_post_release_h_or_fixed_storage(guarded)

    def test_poisoned_h_cannot_replace_the_captured_pointer_after_release(self):
        native = self.machine(hooked=False, invalidate_after_release='poison')
        with self.assertRaises(MemoryFault) as failed:
            native.terminal()
        self.assertEqual((failed.exception.address, failed.exception.operation),
                         (BAD_BUFFER, 'bounded free'))
        guarded = self.machine(invalidate_after_release='poison')
        guarded.terminal()
        self.assertEqual(guarded.frees, [BUFFER])
        self.assertEqual(guarded.peek(DIALOG + 0x14), BAD_BUFFER)
        self.assert_native_restoration(guarded)
        self.assert_no_post_release_h_or_fixed_storage(guarded)

    def test_missing_redirect_leaves_the_original_post_release_h_access(self):
        machine = self.machine(hooked=False, invalidate_after_release='unmap')
        self.assertEqual(len(machine.code), 56)  # Merely present helper bytes do not activate it.
        with self.assertRaises(MemoryFault) as failed:
            machine.terminal()
        self.assertEqual(failed.exception.address, DIALOG + 0x14)
        self.assertNotIn(self.labels['entry'], machine.trace)
        self.assertEqual([event[0] for event in machine.services], [RAW_RELEASE])

    def test_h_must_still_be_valid_when_the_helper_captures_its_field(self):
        machine = self.machine()
        machine.terminal(stop=self.labels['entry'])  # Original H+0C delay load already ran.
        del machine.regions[DIALOG]
        with self.assertRaises(MemoryFault) as failed:
            machine.run_at(self.labels['entry'])
        self.assertEqual(failed.exception.address, DIALOG + 0x14)
        self.assertEqual(machine.services, [])

    def test_callee_abi_violation_is_a_counterexample_to_s1_retention(self):
        machine = self.machine(violate_s1=True)
        with self.assertRaises(MemoryFault) as failed:
            machine.terminal()
        self.assertEqual((failed.exception.address, failed.exception.operation),
                         (BAD_BUFFER, 'bounded free'))
        self.assertEqual(machine.frees, [])
        self.assert_no_post_release_h_or_fixed_storage(machine)


class WorkerTerminalStageMachine(full_fixture.DialogRetentionGateMachine):
    """Use the full composition, including both inherited raw-release hooks.

    Only the 41 unchanged parent assemblers use their existing pure fixture
    cache during construction. The new core/stage remain unwrapped, and no
    native instruction or service outcome is memoized.
    """

    def __init__(self, image, *, dialog_release=0):
        with full_fixture._fixture_assembly_cache(True):
            super().__init__(image, assembly_cache=False, dialog_release=dialog_release,
                             dialog_release_failure_releases=False)
            composition = stage.assemble(
                *full_fixture.STAGE_ARGS, guard_address=full_fixture.GUARD,
                transport_capacity=self.peek(full_fixture.QUEUE + 8))
        self.composition = composition
        self.code = self.code_bytes = composition['code']
        self.labels = composition['labels']
        for name, labels in composition.items():
            if name.endswith('_labels'):
                setattr(self, name, labels)
        for pc, words in composition['coherent_hooks'].items():
            for index, word in enumerate(words):
                self.patches[pc + index * 4] = word

    def external(self, target):
        if target == LOG:
            self.calls.append(target)
            self.hostile_result(0)
            return
        if target == core.RELEASE:
            # Preserve the emitted JAL's actual caller and stack. Both native
            # 466DC8/DD0 redirects remain active inside this complete wrapper.
            self.calls.append(target)
            caller = self.r[31]
            self.run_at(target, caller)
            return
        return super().external(target)

    def seed_worker_terminal(self, *, buffer):
        worker_mutex = full_fixture.previous.previous.WORKER_MUTEX
        self.put(full_fixture.DIALOG + 0x0C, worker_mutex, 4)
        self.put(full_fixture.DIALOG + 0x14, buffer, 4)
        self.mutex_held[worker_mutex] = True  # Explicit chosen service premise.
        self.r[4], self.r[29], self.r[31] = (
            full_fixture.DIALOG, full_fixture.STACK, full_fixture.RETURN)
        saved = self.r.copy()
        self.run_at(WORKER_ENTRY, PROLOGUE_END)
        for register in range(17, 22):
            self.r[register] = 0xCC100000 + register
        self.clear_events()
        return saved, worker_mutex


class WorkerTerminalStageIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = IMAGE.read_bytes()
        if hashlib.sha256(cls.image).hexdigest() != IMAGE_SHA256:
            raise AssertionError('worker integration requires the preserved 02fd source image')

    def assert_integrated_result(self, machine, saved, worker_mutex, status, buffer,
                                 *, dialog_mapped=True):
        self.assertEqual((machine.r[29], machine.r[31]),
                         (full_fixture.STACK, full_fixture.RETURN))
        for register in (*range(16, 24), 28, 30):
            self.assertEqual(machine.r[register], saved[register], register)
        self.assertEqual(machine.dialog_raw_events,
                         [(RAW_RELEASE, worker_mutex, full_fixture.STACK - 56 - 32,
                           0x466DD0, status)])
        self.assertEqual(machine.freed, [buffer] if buffer else [])
        if dialog_mapped:
            self.assertEqual(machine.words_at(full_fixture.DIALOG + 0x14, 1), (0,))
        else:
            self.assertNotIn(full_fixture.DIALOG, machine.regions)
        self.assertEqual(machine.r[2], 0)
        self.assertEqual(machine.guard_value(), full_fixture.core.QUARANTINED)
        # The raw-return hook replays DD0/DD4 inside its dispatcher, then
        # resumes DD8. Trace PCs therefore include DD8, not displaced DD4.
        # The inherited trace also records the owning JR, not its SP+=56
        # delay's PC; final SP and the source contract verify that delay.
        for pc in (0x466DC0, 0x466DC8, 0x466DD0, 0x466DD8, 0x47C708, 0x47C724):
            self.assertIn(pc, machine.trace)
        for pc in (0x466DC8, 0x466DD0):
            pair = machine.composition['coherent_hooks'][pc]
            dispatch = ((pc + 4) & 0xF0000000) | ((pair[0] & 0x3FFFFFF) << 2)
            self.assertIn(dispatch, machine.trace)
        for label in ('entry', 'captured', 'release_return', 'finish'):
            self.assertIn(machine.worker_terminal_tail_labels[label], machine.trace)
        self.assertNotIn((full_fixture.GUARD, 4), machine.reads)
        self.assertFalse(any(address == full_fixture.GUARD for address, _, _ in machine.writes))

    def test_full_composition_null_tail_uses_foreign_raw_dispatch_and_keeps_quarantine(self):
        original_core, original_stage = core.assemble, stage.assemble
        machine = WorkerTerminalStageMachine(self.image)
        saved, worker_mutex = machine.seed_worker_terminal(buffer=0)
        machine.put(full_fixture.GUARD, full_fixture.core.QUARANTINED, 4)
        machine.clear_events()
        machine.run_at(TERMINAL, full_fixture.RETURN)
        self.assert_integrated_result(machine, saved, worker_mutex, 0, 0)
        self.assertIs(core.assemble, original_core)
        self.assertIs(stage.assemble, original_stage)

    def test_full_composition_raw_error_stays_masked_without_new_release_or_free_policy(self):
        machine = WorkerTerminalStageMachine(self.image, dialog_release=22)
        saved, worker_mutex = machine.seed_worker_terminal(buffer=full_fixture.OPERATION)
        machine.put(full_fixture.GUARD, full_fixture.core.QUARANTINED, 4)
        machine.clear_events()
        machine.run_at(TERMINAL, full_fixture.RETURN)
        self.assert_integrated_result(machine, saved, worker_mutex, 22, full_fixture.OPERATION)
        self.assertTrue(machine.mutex_held[worker_mutex])
        self.assertEqual(machine.calls.count(RAW_RELEASE), 1)
        self.assertEqual(machine.calls.count(FREE), 1)

    def test_full_composition_raw_return_dispatch_needs_no_h_after_service(self):
        machine = WorkerTerminalStageMachine(self.image)
        saved, worker_mutex = machine.seed_worker_terminal(buffer=full_fixture.OPERATION)
        machine.put(full_fixture.GUARD, full_fixture.core.QUARANTINED, 4)
        machine.clear_events()
        boundary = []

        def remove_dialog(current, target):
            if target == RAW_RELEASE:
                self.assertEqual(current.r[4], worker_mutex)
                self.assertEqual(current.words_at(full_fixture.DIALOG + 0x14, 1), (0,))
                boundary.append((len(current.reads), len(current.writes)))
                del current.regions[full_fixture.DIALOG]

        machine.on_service = remove_dialog
        machine.run_at(TERMINAL, full_fixture.RETURN)
        self.assertEqual(len(boundary), 1)
        read_at, write_at = boundary[0]
        first, last = full_fixture.DIALOG, full_fixture.DIALOG + 0x100
        self.assertFalse(any(first <= address < last
                             for address, size in machine.reads[read_at:]))
        self.assertFalse(any(first <= address < last
                             for address, value, size in machine.writes[write_at:]))
        self.assert_integrated_result(machine, saved, worker_mutex, 0,
                                      full_fixture.OPERATION, dialog_mapped=False)


if __name__ == '__main__':
    unittest.main()
