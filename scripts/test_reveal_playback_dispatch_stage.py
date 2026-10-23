#!/usr/bin/env python3
"""Execute relocated callback boundaries, not stock callback bodies or a UI.

Original target/context loads, nonnull branches, emitted observers and native
continuations execute. Synthetic callback instructions and two hostile native
continuation stubs bound the test. Odd targets are only observed at transfer,
not fetched/emulated; no instruction-mode/exception or lifetime proof follows.
"""
import hashlib
import struct
import unittest

import build_reveal_playback_dispatch_stage as stage
import decode_reveal_playback_dispatch as decoder
import reveal_playback_dispatch_mips as core
import test_reveal_lineage_stage as harness
import test_folderfollow_reveal_static_contract as source
from verify_reveal_playback_dispatch_stage import verify


CAPACITIES = dict(capacity=2, row_capacity=2, operation_capacity=2, scope_capacity=2,
                  birth_capacity=2, transport_capacity=2, renderer_capacity=2,
                  playback_dispatch_capacity=4)
PLAYER, DESCRIPTOR = 0xADD368, 0xADD468
TARGET, NESTED_TARGET, CONTEXT = 0x1F40000, 0x1F41000, 0xBAD00041
STACK = harness.STACK


class TargetBoundary(Exception):
    """Stop the original linked-call harness after its real JALR delay."""


class DispatchMachine(harness.LineageMachine):
    def __init__(self, image, meta):
        super().__init__(image, meta)
        self.map(PLAYER, 0x1E68)
        self.callback_words = {target + i * 4: word
            for target in (TARGET, NESTED_TARGET)
            for i, word in enumerate((stage.b.lui(2, 0x8765), stage.b.ori(2, 2, 0x4321),
                                      stage.b.r_type(2, 0, 0, 0x11),
                                      stage.b.r_type(4, 0, 0, 0x13), 0x03E00008, 0))}
        self.native_calls = []
        self.trace = []
        self.on_instruction = None
        self.before_instruction = self.observe
        self.target_boundary = None

    def run_at(self, pc, stop):
        prior = self.target_boundary
        self.target_boundary = stop
        try:
            # The shared interpreter routes original external JALR through
            # external() but follows emitted JR directly. Intercept only the
            # requested stop boundary, AFTER target/RA/delay computation, so
            # both versions expose the same pre-target instruction state.
            try:
                super().run_at(pc, stop)
            except TargetBoundary:
                pass
        finally:
            self.target_boundary = prior

    def word(self, pc):
        if pc in self.callback_words:
            return self.callback_words[pc]
        return super().word(pc)

    def observe(self, pc):
        self.trace.append(pc)
        if self.on_instruction:
            self.on_instruction(pc)

    def external(self, target):
        if target == self.target_boundary:
            raise TargetBoundary()
        if target in (0x42B140, 0x42CA00):
            self.native_calls.append((target, self.r[4:8].copy(), self.r[31]))
            self.hostile_result(0xCAFEBABE)
            return
        super().external(target)

    def setup(self, name, *, target=TARGET, context=CONTEXT, frame=STACK):
        self.r[29], self.r[31], self.r[20] = frame, 0x13572468, 0xAE0000
        self.r[17 if name == 'fast' else 16] = PLAYER
        self.put(PLAYER + 0xBA0, target, 4)
        self.put(PLAYER + 0xB98, context, 4)

    def enter(self, name, *, target=TARGET, context=CONTEXT, frame=STACK):
        self.setup(name, target=target, context=context, frame=frame)
        self.run_at(0x42CBFC if name == 'fast' else 0x42D690,
                    target if target else self.return_pc(name))

    @staticmethod
    def return_pc(name):
        return 0x42CC14 if name == 'fast' else 0x42D6A8

    def journal(self):
        return self.memory(self.meta['playback_dispatch_buffer'], self.meta['playback_dispatch_memory_bytes'])

    def memory(self, address, size):
        region, offset = self.region(address, size)
        return bytes(region[offset:offset + size])


class RevealPlaybackDispatchStageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = source.SOURCE.read_bytes()
        cls.image, cls.meta = stage.build(cls.source, **CAPACITIES)

    def machine(self, *, original=False, **options):
        if options:
            image, meta = stage.build(self.source, **dict(CAPACITIES, **options))
        else:
            image, meta = self.image, self.meta
        return DispatchMachine(self.source if original else image, meta)

    def decoded(self, machine):
        return decoder.decode(machine.journal(), capacity=machine.meta['playback_dispatch_capacity'])

    def test_original_target_entry_state_matches_every_register_and_hilo(self):
        for name in ('fast', 'general'):
            for context in (0, CONTEXT, 0xFFFFFFFF):
                with self.subTest(name=name, context=context):
                    original, observed = self.machine(original=True), self.machine()
                    original.enter(name, context=context)
                    observed.enter(name, context=context)
                    self.assertEqual((observed.r, observed.hi, observed.lo),
                                     (original.r, original.hi, original.lo))
                    self.assertEqual(observed.r[31], observed.return_pc(name))
                    self.assertEqual(observed.r[4:6], [context, DESCRIPTOR])
                    self.assertEqual(observed.r[25], TARGET)

    def test_exact_records_bind_only_their_own_intent_not_playback_or_paint(self):
        machine = self.machine()
        for name in ('fast', 'general'):
            machine.enter(name)
        result = self.decoded(machine)
        self.assertEqual(result['counter'], 2)
        for index, event in enumerate(result['events'], 1):
            site = core.FAST_SITE if index == 1 else core.GENERAL_SITE
            self.assertEqual((event['seq'], event['origin'], event['parent']), (index, index, 0))
            self.assertEqual((event['frame'], event['site'], event['return_pc'], event['target'],
                              event['context'], event['descriptor'], event['player']),
                             (STACK, site, site + 8, TARGET, CONTEXT, DESCRIPTOR, PLAYER))
            self.assertEqual(event['decision'], 'deny')
            self.assertFalse(event['callback_completion_proven'])
            self.assertFalse(event['birth_parent_associated'])

    def test_null_original_target_branch_skips_observer_without_reading_context(self):
        for name in ('fast', 'general'):
            machine = self.machine()
            machine.enter(name, target=0)
            self.assertEqual(self.decoded(machine)['events'], [])
            self.assertNotIn((PLAYER + 0xB98, 4), machine.reads)
            self.assertNotIn(machine.labels['playback_' + name + '_dispatch'], machine.trace)

    def test_target_and_context_load_once_no_new_descriptor_or_target_dereference(self):
        for name in ('fast', 'general'):
            machine = self.machine()
            machine.enter(name)
            native_reads = [(address, size) for address, size in machine.reads
                            if not (self.meta['buffer'] <= address < self.meta['buffer'] + self.meta['memory_bytes']
                                    or 0x2000000 <= address < 0x200C000)]
            self.assertEqual(native_reads, [(PLAYER + 0xBA0, 4), (PLAYER + 0xB98, 4)])

    def test_changed_global_slots_after_native_loads_cannot_restamp_frozen_arguments(self):
        for name in ('fast', 'general'):
            machine = self.machine()
            injected = []

            def change(pc):
                if pc == machine.labels['playback_' + name + '_dispatch'] and not injected:
                    injected.append(pc)
                    machine.put(PLAYER + 0xBA0, NESTED_TARGET, 4)
                    machine.put(PLAYER + 0xB98, 0, 4)

            machine.on_instruction = change
            machine.enter(name)
            self.assertTrue(injected)
            event = self.decoded(machine)['events'][0]
            self.assertEqual((event['target'], event['context']), (TARGET, CONTEXT))
            self.assertEqual(machine.r[25], TARGET)
            self.assertEqual(machine.r[4], CONTEXT)

    def test_callback_returns_directly_to_original_continuation_with_opaque_result(self):
        for name in ('fast', 'general'):
            original, observed = self.machine(original=True), self.machine()
            for machine in (original, observed):
                machine.enter(name)
                machine.run_at(TARGET, machine.return_pc(name))
            self.assertEqual((observed.r, observed.hi, observed.lo),
                             (original.r, original.hi, original.lo))
            self.assertEqual(observed.r[2], 0x87654321)
            self.assertEqual(observed.hi, 0x87654321)
            self.assertEqual(observed.lo, CONTEXT)
            # No post-callback observer or inferred completion record exists.
            self.assertEqual(self.decoded(observed)['counter'], 1)

    def test_original_post_callback_call_and_arguments_are_unchanged(self):
        for name in ('fast', 'general'):
            original, observed = self.machine(original=True), self.machine()
            for machine in (original, observed):
                machine.enter(name)
                machine.run_at(TARGET, machine.return_pc(name))
                machine.run_at(machine.return_pc(name), 0x42CC20 if name == 'fast' else 0x42D6B0)
            self.assertEqual(observed.native_calls, original.native_calls)
            self.assertEqual(len(observed.native_calls), 1)
            self.assertEqual((observed.r, observed.hi, observed.lo),
                             (original.r, original.hi, original.lo))

    def test_fault_exhaustion_and_failed_sc_never_veto_native_dispatch(self):
        for name in ('fast', 'general'):
            for mode in ('fault', 'full', 'sc-failure'):
                with self.subTest(name=name, mode=mode):
                    original, observed = self.machine(original=True), self.machine()
                    journal = observed.meta['playback_dispatch_buffer']
                    if mode == 'fault':
                        observed.put(journal, core.FAULT, 4)
                    elif mode == 'full':
                        observed.put(journal, CAPACITIES['playback_dispatch_capacity'], 4)
                    else:
                        observed.sc_failures = core.RETRIES
                    original.enter(name)
                    observed.enter(name)
                    self.assertEqual((observed.r, observed.hi, observed.lo),
                                     (original.r, original.hi, original.lo))
                    self.assertEqual(observed.get(journal, 4), core.FAULT)
                    observed.run_at(TARGET, observed.return_pc(name))
                    self.assertEqual(observed.r[2], 0x87654321)
                    with self.assertRaises(ValueError):
                        self.decoded(observed)

    def test_bad_diagnostic_binding_does_not_rewrite_original_native_arguments(self):
        for name in ('fast', 'general'):
            original, observed = self.machine(original=True), self.machine()
            for machine in (original, observed):
                machine.setup(name)
                machine.r[20] = 0xAF0000  # deliberate unsupported descriptor binding
                machine.run_at(0x42CBFC if name == 'fast' else 0x42D690, TARGET)
            self.assertEqual((observed.r, observed.hi, observed.lo),
                             (original.r, original.hi, original.lo))
            self.assertEqual(observed.r[5], 0xAED468)
            self.assertEqual(observed.get(observed.meta['playback_dispatch_buffer'], 4), core.FAULT)

    def test_raw_odd_or_unknown_target_is_recorded_without_fetch_or_instruction_mode_claim(self):
        for target in (TARGET + 1, TARGET + 2, 0xFFFFFFFF):
            original, observed = self.machine(original=True), self.machine()
            original.enter('fast', target=target)
            observed.enter('fast', target=target)
            self.assertEqual(observed.r, original.r)
            self.assertEqual(self.decoded(observed)['events'][0]['target'], target)

    def test_reentered_dispatches_have_distinct_ids_without_native_frame_carrier(self):
        machine = self.machine()
        nested = []

        def reenter(pc):
            if pc == TARGET and not nested:
                nested.append(pc)
                saved, hi, lo = machine.r.copy(), machine.hi, machine.lo
                machine.enter('general', target=NESTED_TARGET, context=0, frame=STACK - 0x400)
                machine.run_at(NESTED_TARGET, machine.return_pc('general'))
                machine.r, machine.hi, machine.lo = saved, hi, lo

        machine.on_instruction = reenter
        machine.enter('fast')
        machine.run_at(TARGET, machine.return_pc('fast'))
        self.assertEqual(nested, [TARGET])
        events = self.decoded(machine)['events']
        self.assertEqual([(e['seq'], e['kind'], e['frame'], e['parent']) for e in events],
                         [(1, core.FAST, STACK, 0), (2, core.GENERAL, STACK - 0x400, 0)])
        self.assertEqual(machine.r[29], STACK)
        self.assertEqual(machine.r[31], machine.return_pc('fast'))

    def test_no_existing_native_low_stack_token_is_overwritten(self):
        for name in ('fast', 'general'):
            machine = self.machine()
            for offset in (0x10, 0x14, 0x18):
                machine.put(STACK + offset, 0xCAF00000 + offset, 4)
            machine.enter(name)
            self.assertEqual([machine.get(STACK + offset, 4) for offset in (0x10, 0x14, 0x18)],
                             [0xCAF00010, 0xCAF00014, 0xCAF00018])

    def test_exact_image_verifier_layout_and_previous_default_hash(self):
        checked = verify(self.source, self.image, **CAPACITIES)
        self.assertEqual(len(stage.HOOKS), 37)
        self.assertEqual(len(checked['indirect_dispatch_tails']), 2)
        self.assertEqual(checked['playback_dispatch_memory_bytes'], 16 + 64 * 4)
        self.assertFalse(checked['autoscroll'])
        self.assertFalse(checked['playback_paint_cause_associated'])
        self.assertEqual(stage.build(stage.normalize_source(self.source)[0], **CAPACITIES)[0], self.image)
        self.assertEqual(hashlib.sha256(stage.previous.build(self.source)[0]).hexdigest(),
                         'f42fac46890dc2eadbeba88f90ce5b82857d3045752b974b15d04bef263d2244')

    def test_tampered_original_calls_wrappers_and_indirect_tails_are_refused(self):
        for pc in (0x42CBFC, 0x42CC00, 0x42CC08, 0x42CC0C, 0x42CC10, 0x42CC14,
                   0x42CC18, 0x42D614, 0x42D690, 0x42D69C, 0x42D6A0, 0x42D6A4,
                   self.meta['labels']['playback_fast_dispatch'],
                   self.meta['labels']['playback_general_dispatch_jump']):
            changed = bytearray(self.image)
            offset = (pc - stage.BASE if pc < self.meta['code_base'] else
                      self.meta['code_offset'] + pc - self.meta['code_base'])
            changed[offset] ^= 1
            with self.subTest(pc=hex(pc)), self.assertRaises(ValueError):
                verify(self.source, changed, **CAPACITIES)

    def test_active_modes_invalid_sources_and_capacities_are_refused(self):
        for value in (True, 0, 1, None, 'yes'):
            with self.assertRaises(ValueError):
                stage.build(self.source, enable_reveal=value)
        for value in (0, -1, True, None, 1.5, core.MAX_CAPACITY + 1):
            with self.assertRaises(ValueError):
                stage.build(self.source, **dict(CAPACITIES, playback_dispatch_capacity=value))
        for raw in (self.image, self.source[:-1], bytes(len(self.source))):
            with self.assertRaises(ValueError):
                stage.build(raw, **CAPACITIES)

    def test_private_region_alias_wrap_and_code_overlap_are_refused(self):
        names = ('buffer', 'row_buffer', 'contents_revision_buffer', 'operation_buffer',
                 'scope_buffer', 'birth_buffer', 'transport_buffer', 'renderer_transport_buffer')
        addresses = [self.meta[name] for name in names]
        address, code = self.meta['playback_dispatch_buffer'], self.meta['code_base']
        for value in (True, -4, address + 1, *addresses, code, code - 4, 0xFFFFFFFC):
            with self.subTest(address=value), self.assertRaises(ValueError):
                stage.assemble(*addresses, value, code, **CAPACITIES)


if __name__ == '__main__':
    unittest.main()
