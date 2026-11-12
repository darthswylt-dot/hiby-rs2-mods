#!/usr/bin/env python3
"""Run native QR destruction without releasing the shared response pair."""

import unittest

import factory_null_audit as audit
import reveal_tidal_qr_shared_release_mips as guard
import reveal_tidal_response_reader_bridge_mips as session
from test_factory_d180_qr_continuation import SIDE_PAYLOAD
from test_factory_d180_tidal_response_lifecycle import NEW_FOLLOWUP, NEW_RESPONSE, OLD_FOLLOWUP, OLD_RESPONSE, SESSION
from test_factory_null_audit import ALLOCATION, CONTEXT, HANDLE, RETURN, STACK
from test_reveal_tidal_response_reader_bridge_mips import CODE_BASE, MUTEX, ReaderBridgeMachine
from test_reveal_tidal_retained_readers_mips import CALLBACK, RESULT, RetainedMachine


DESTROY, OWNER_FLAG = 0x500CE0, CONTEXT + 0x208


class NativeTidalQrSharedReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = audit.source_image()
        cls.code, cls.patches = guard.assemble(MUTEX, CODE_BASE)

    def machine(self, *, mode=2, alias=SESSION, payload=True, side=True,
                machine_type=ReaderBridgeMachine):
        machine = machine_type(self.image, self.code, self.patches)
        machine.put(ALLOCATION - 4, 0x1A8, 4)
        machine.put(ALLOCATION, mode, 4)
        machine.put(ALLOCATION + 0x18C, alias, 4)
        machine.put(HANDLE + 0x48, CONTEXT, 4)
        machine.put(HANDLE + 0x4C, ALLOCATION if payload else 0, 4)
        machine.put(HANDLE + 0x54, ALLOCATION, 4)
        machine.put(OWNER_FLAG, 0, 4)
        if side:
            machine.map(SIDE_PAYLOAD - 4, 8)
            machine.put(SIDE_PAYLOAD - 4, 4, 4)
            machine.put(SIDE_PAYLOAD, 0x12345678, 4)
        machine.put(HANDLE + 0x58, SIDE_PAYLOAD if side else 0, 4)
        machine.calls.clear()
        machine.accesses.clear()
        return machine

    def assert_native_tail(self, machine, *, payload=True, side=True):
        expected = ([ALLOCATION] if payload else []) + ([SIDE_PAYLOAD] if side else [])
        self.assertEqual(machine.releases, expected)
        self.assertEqual(machine.raw_releases, [address - 4 for address in expected])
        self.assertEqual(machine.response_releases, [])
        self.assertEqual(machine.get(HANDLE + 0x4C, 4), 0)
        self.assertEqual(machine.get(HANDLE + 0x58, 4), 0)
        self.assertEqual(machine.get(OWNER_FLAG, 4), 1)
        self.assertEqual((machine.r[29], machine.r[31]), (STACK, RETURN))

    def test_composer_adds_exactly_one_pinned_redirect_without_helper_bytes(self):
        prefix, original = guard.retained.assemble(MUTEX, CODE_BASE)
        self.assertEqual(self.code, prefix)
        self.assertEqual(len(self.patches), len(original) + 1)
        self.assertEqual(guard.ORIGINAL, (self.image.word(guard.SITE), self.image.word(guard.SITE + 4)))
        self.assertEqual(self.image.word(guard.SITE + 8), guard.ORIGINAL_DELAY)
        self.assertEqual(self.patches[guard.SITE][0], guard.ORIGINAL)
        self.assertEqual({site: value for site, value in self.patches.items() if site != guard.SITE}, original)

    def test_ordinary_and_tidal_destruction_keep_shared_slots_and_native_owned_tail(self):
        for mode, alias in ((0, 0), (2, SESSION), (2, 0)):
            with self.subTest(mode=mode, alias=hex(alias)):
                machine = self.machine(mode=mode, alias=alias)
                registers = machine.r[16:20]
                control = [machine.get(MUTEX + offset, 4) for offset in range(0, session.CONTROL_BYTES, 4)]
                machine.stock(DESTROY, HANDLE)
                self.assert_native_tail(machine)
                self.assertEqual(machine.r[16:20], registers)
                self.assertEqual(machine.slots(), (OLD_RESPONSE, OLD_FOLLOWUP))
                self.assertEqual(machine.get(session.SESSION_SLOT, 4), SESSION)
                self.assertEqual([machine.get(MUTEX + offset, 4) for offset in range(0, session.CONTROL_BYTES, 4)], control)
                # Native ownership tail does not clear the separate H+54 alias.
                self.assertEqual(machine.get(HANDLE + 0x54, 4), ALLOCATION)
                self.assertEqual(machine.mutex_events, [])

    def test_an_unmapped_old_session_alias_is_never_read_or_dereferenced(self):
        retired = 0x12000000
        machine = self.machine(alias=retired)
        machine.stock(DESTROY, HANDLE)
        self.assert_native_tail(machine)
        self.assertFalse(any(address in (ALLOCATION + 0x18C, retired, retired + 0x18)
                             for _, _, address, _ in machine.accesses))
        self.assertEqual(machine.slots(), (OLD_RESPONSE, OLD_FOLLOWUP))

    def test_ordinary_qr_matches_the_unmodified_native_destructor(self):
        guarded = self.machine(mode=0, alias=0)
        native = self.machine(mode=0, alias=0)
        native.replacements.pop(guard.SITE)
        native.replacements.pop(guard.SITE + 4)
        for machine in (native, guarded):
            machine.stock(DESTROY, HANDLE)
        self.assertEqual((guarded.r, guarded.hi, guarded.lo), (native.r, native.hi, native.lo))
        self.assertEqual(guarded.releases, native.releases)
        self.assertEqual(guarded.raw_releases, native.raw_releases)
        self.assertEqual(guarded.response_releases, native.response_releases)
        for address in (HANDLE + 0x4C, HANDLE + 0x54, HANDLE + 0x58, OWNER_FLAG,
                        SESSION + 0x18, SESSION + 0x1C):
            self.assertEqual(guarded.get(address, 4), native.get(address, 4))

    def test_old_payload_cannot_clear_a_new_generation_at_the_same_session_address(self):
        machine = self.machine(alias=SESSION)
        # The payload still has only its old pointer; simulate a new generation
        # reusing that address. Destruction must not infer ownership from it.
        machine.put(MUTEX + session.GENERATION, 2, 4)
        machine.put(SESSION + 0x18, NEW_RESPONSE, 4)
        machine.put(SESSION + 0x1C, NEW_FOLLOWUP, 4)
        machine.stock(DESTROY, HANDLE)
        self.assert_native_tail(machine)
        self.assertEqual(machine.slots(), (NEW_RESPONSE, NEW_FOLLOWUP))
        self.assertEqual(machine.get(MUTEX + session.GENERATION, 4), 2)
        self.assertEqual(machine.get(session.SESSION_SLOT, 4), SESSION)

    def test_absent_payload_and_optional_side_payload_keep_native_cleanup(self):
        for payload, side in ((False, False), (False, True), (True, False)):
            with self.subTest(payload=payload, side=side):
                machine = self.machine(payload=payload, side=side)
                machine.stock(DESTROY, HANDLE)
                self.assert_native_tail(machine, payload=payload, side=side)
                self.assertEqual(machine.slots(), (OLD_RESPONSE, OLD_FOLLOWUP))

    def test_null_dialog_keeps_the_native_noop(self):
        machine = self.machine()
        before, hi, lo = machine.r.copy(), machine.hi, machine.lo
        before[4] = 0
        machine.stock(DESTROY, 0)
        self.assertEqual((machine.r, machine.hi, machine.lo), (before, hi, lo))
        self.assertEqual(machine.releases, [])
        self.assertEqual(machine.response_releases, [])
        self.assertEqual(machine.get(OWNER_FLAG, 4), 0)

    def test_dialog_destruction_during_a_retained_service_keeps_the_reader_pair_live(self):
        machine = self.machine(machine_type=RetainedMachine)
        observed = []

        def dismiss_during_read(_):
            dialog = machine.fork_cpu()
            dialog.r[29] = STACK + 0x5000
            dialog.stock(DESTROY, HANDLE)
            self.assertEqual(dialog.releases, [ALLOCATION, SIDE_PAYLOAD])
            self.assertEqual(dialog.response_releases, [])
            observed.append((machine.get(MUTEX + session.BORROWS, 4), machine.slots()))

        machine.on_reader_service = dismiss_during_read
        self.assertEqual(machine.stock(CALLBACK, *machine.arguments(CALLBACK)), RESULT)
        self.assertEqual(observed, [(1, (OLD_RESPONSE, OLD_FOLLOWUP))])
        self.assertEqual(machine.get(MUTEX + session.BORROWS, 4), 0)
        self.assertEqual(machine.slots(), (OLD_RESPONSE, OLD_FOLLOWUP))


if __name__ == '__main__':
    unittest.main()
