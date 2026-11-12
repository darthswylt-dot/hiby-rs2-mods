#!/usr/bin/env python3
"""Run early queue sealing through selected native session close paths.

The STOP substitute executes the pinned queue-destroy suffix after the stated
worker-stop premise. Earlier pool destruction, opaque teardown and successful
worker completion are not emulated. Retired ring storage rejects access, and
gate LL/SC uses the shared reservation domain from the operation fixture.
This is one-lifetime admission sealing, without initialization/reopen support.
"""

import unittest

import factory_null_audit as audit
import reveal_tidal_queue_close_seal_mips as sealing
import reveal_tidal_queue_operations_mips as operations
import reveal_tidal_request_identity_mips as identity
import reveal_tidal_response_reader_bridge_mips as session
from test_factory_d180_qr_continuation import MESSAGE, QUEUE, QUEUE_SLOT
from test_factory_d180_tidal_response_lifecycle import SESSION
from test_factory_null_audit import RETURN, STACK
from test_factory_tidal_queue_transport import DESTROY, OUTPUT, QueuePause
from test_reveal_tidal_queue_operations_mips import GATE, QueueOperationsMachine
from test_reveal_tidal_response_reader_bridge_mips import CODE_BASE, MUTEX, NATIVE_TOP
from test_reveal_tidal_session_disposal_mips import DisposalMachine


STOP, NEW_SESSION = 0x4556E0, 0x1D10000


class QueueCloseMachine(QueueOperationsMachine, DisposalMachine):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.stop_gate_values = []
        self.early_seal_values = []

    def external(self, target):
        if target in (0x448280, 0x457300):
            self.early_seal_values.append((target, self.get(GATE, 4)))
            if self.held or self.get(GATE, 4) != sealing.SEALED:
                raise AssertionError('first native teardown precedes seal or session unlock')
        if target == STOP:
            if self.held:
                raise AssertionError('native shutdown held the session mutex')
            self.calls.append(target)
            self.stop_gate_values.append(self.get(GATE, 4))
            if self.get(GATE, 4) != sealing.SEALED:
                raise AssertionError('queue destruction began before the admission seal')
            self.teardown_events.append(target)
            # Execute the actual global load, NULL check, destroy call and
            # its delay at 455748..45575B. Stop/join and earlier pools remain
            # premises, rather than inventing a successful native handshake.
            saved_s0, saved_s1, saved_ra = self.r[16], self.r[17], self.r[31]
            self.r[16], self.r[17] = QUEUE_SLOT, 0xB90000
            self.run_at(0x455748, 0x45575C)
            self.r[16], self.r[17], self.r[31] = saved_s0, saved_s1, saved_ra
            self.hostile_result(0)
        elif target == DESTROY:
            self.calls.append(target)
            self.run_at(target, self.r[31])
        else:
            super().external(target)


class NativeTidalQueueCloseSealTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = audit.source_image()
        cls.code, cls.patches = sealing.assemble(MUTEX, CODE_BASE, queue_gate_address=GATE)

    def machine(self):
        return QueueCloseMachine(self.image, self.code, self.patches)

    def close(self, machine, site=None):
        frame = machine.seed_native_frame()
        machine.run_at(site or session.CLOSE_SITES[0][0], RETURN)
        return frame

    def assert_no_teardown(self, machine, diagnostic):
        self.assertEqual((machine.r[2], machine.r[3]), (0xFFFFFFFF, diagnostic))
        self.assertEqual((machine.r[29], machine.r[31]), (NATIVE_TOP, RETURN))
        self.assertEqual(machine.teardown_events, [])
        self.assertEqual(machine.stop_gate_values, [])
        self.assertEqual(machine.releases, [])

    def test_protocol_and_native_destroy_suffix_words_are_pinned(self):
        self.assertEqual(len(self.patches), 47)
        self.assertEqual(session.QUEUE_SEALED, sealing.SEALED)
        self.assertEqual(session.QUEUE_CLAIM_ATTEMPTS, operations.MAX_ATTEMPTS)
        for site, pair in operations.HOOKS:
            self.assertEqual(self.patches[site][0], pair)
        self.assertEqual([self.image.word(pc) for pc in (0x455748, 0x45574C, 0x455750,
                                                        0x455754, 0x455758)],
                         [0x8E249250, 0x10800003, 0, 0x0C1141F8, 0])
        for address in (GATE + 1, MUTEX, CODE_BASE, CODE_BASE + len(self.code) - 4):
            with self.subTest(address=hex(address)), self.assertRaises(ValueError):
                sealing.assemble(MUTEX, CODE_BASE, queue_gate_address=address)

    def test_both_complete_close_routes_destroy_ring_and_keep_seal_through_finish(self):
        for site, _, _ in session.CLOSE_SITES:
            with self.subTest(site=hex(site)):
                machine = self.machine()
                self.close(machine, site)
                self.assertEqual(machine.early_seal_values[0],
                                 (0x448280 if site == session.CLOSE_SITES[0][0] else 0x457300,
                                  sealing.SEALED))
                self.assertEqual(machine.stop_gate_values, [sealing.SEALED])
                self.assertEqual(machine.retired_queues, {QUEUE})
                self.assertEqual(machine.get(QUEUE_SLOT, 4), QUEUE)  # Native stale slot persists.
                self.assertEqual(machine.get(GATE, 4), sealing.SEALED)
                self.assertEqual(machine.get(MUTEX + session.LIFECYCLE, 4), session.EMPTY)
                self.assertEqual(machine.get(session.SESSION_SLOT, 4), 0)
                self.assertEqual(machine.releases.count(QUEUE), 1)
                self.assertEqual(machine.releases.count(SESSION), 1)
                self.assertEqual((machine.r[29], machine.r[31]), (NATIVE_TOP, RETURN))

    def test_active_operation_refuses_close_before_teardown_then_allows_retry(self):
        machine = self.machine()
        machine.pause_post_in_write(0x450504)
        closer = machine.fork_cpu()
        self.close(closer)
        self.assert_no_teardown(closer, 16)
        self.assertEqual(machine.get(GATE, 4), operations.OWNED)
        self.assertEqual(machine.get(MUTEX + session.LIFECYCLE, 4), session.LIVE)
        machine.run_at(0x450504, RETURN)
        self.assertEqual(machine.get(GATE, 4), 0)
        self.assertEqual(machine.get(QUEUE + 16, 4), MESSAGE)
        self.close(closer)
        self.assertEqual(closer.retired_packets, {MESSAGE})
        self.assertEqual(closer.retired_queues, {QUEUE})
        self.assertEqual(closer.get(GATE, 4), sealing.SEALED)

    def test_previously_admitted_posts_with_captured_ring_refuse_after_close(self):
        for command in (0, 3):
            with self.subTest(command=command):
                machine = self.machine()
                machine.r[4:6] = [command, 0]
                machine.r[31] = RETURN
                machine.run_at(identity.POST, operations.WRITE_SITE)
                self.assertEqual(machine.r[4], QUEUE)  # Captured before retirement.
                closer = machine.fork_cpu()
                self.close(closer)
                self.assertEqual(machine.retired_queues, {QUEUE})
                machine.run_at(operations.WRITE_SITE, RETURN)
                self.assertEqual((machine.r[2], machine.r[3]), (0xFFFFFFFF, 16))
                self.assertEqual(machine.packet_allocations, [])
                self.assertEqual(machine.get(GATE, 4), sealing.SEALED)

    def test_previously_loaded_read_pointer_refuses_without_touching_retired_ring(self):
        machine = self.machine()
        machine.r[4:7] = [QUEUE, OUTPUT, 8]
        closer = machine.fork_cpu()
        self.close(closer)
        machine.run_at(operations.READ_SITE, operations.READ_SITE + 8)
        self.assertEqual((machine.r[2], machine.r[3]), (0xFFFFFFFF, 16))
        self.assertEqual(machine.copy_calls, [])
        self.assertEqual(machine.get(GATE, 4), sealing.SEALED)

    def test_session_identity_or_active_pin_refusal_does_not_seal_the_queue(self):
        for kind in ('writer', 'borrow', 'token'):
            with self.subTest(kind=kind):
                machine = self.machine()
                frame = machine.seed_native_frame()
                if kind == 'token':
                    machine.put(frame + session.TOKEN, 2, 4)
                else:
                    machine.put(MUTEX + (session.WRITER if kind == 'writer' else session.BORROWS), 1, 4)
                machine.run_at(session.CLOSE_SITES[0][0], RETURN)
                self.assert_no_teardown(machine, 116 if kind == 'token' else 16)
                self.assertEqual(machine.get(GATE, 4), 0)
                self.assertEqual(machine.get(MUTEX + session.LIFECYCLE, 4), session.LIVE)

    def test_raw_failure_before_or_after_seal_never_rolls_back_or_runs_teardown(self):
        for acquire, release in ((22, 0), (0, 1)):
            with self.subTest(acquire=acquire, release=release):
                machine = self.machine()
                machine.acquire_result, machine.release_result = acquire, release
                self.close(machine)
                self.assert_no_teardown(machine, acquire or release)
                self.assertEqual(machine.get(MUTEX + session.PHASE, 4), session.FAILED)
                self.assertEqual(machine.get(GATE, 4), 0 if acquire else sealing.SEALED)
                self.assertEqual(machine.get(MUTEX + session.LIFECYCLE, 4),
                                 session.LIVE if acquire else session.CLOSING)

    def test_bounded_seal_reservation_failure_refuses_and_final_attempt_can_succeed(self):
        machine = self.machine()
        machine.sc_failures = session.QUEUE_CLAIM_ATTEMPTS
        self.close(machine)
        self.assert_no_teardown(machine, 16)
        self.assertEqual(machine.sc_failures, 0)
        self.assertEqual(machine.get(GATE, 4), 0)
        self.assertEqual(machine.get(MUTEX + session.LIFECYCLE, 4), session.LIVE)
        machine.sc_failures = session.QUEUE_CLAIM_ATTEMPTS - 1
        self.close(machine)
        self.assertEqual(machine.sc_failures, 0)
        self.assertEqual(machine.get(GATE, 4), sealing.SEALED)

    def test_operation_winning_between_close_ll_and_sc_prevents_retirement(self):
        machine = self.machine()
        frame = machine.seed_native_frame()
        site = session.CLOSE_SITES[0][0]
        helper = (self.patches[site][1][0] & 0x3FFFFFF) << 2
        seal_sc = next(pc for pc in range(helper, helper + 768, 4)
                       if machine.word(pc) >> 26 == 0x38)
        machine.run_at(site, seal_sc)
        other = machine.fork_cpu()
        other.r[29], other.r[4], other.r[6] = STACK + 0x3800, QUEUE, 8
        other.pause_write_at = 0x450504
        try:
            with self.assertRaises(QueuePause):
                other.run_at(operations.WRITE_SITE, operations.WRITE_SITE + 8)
        finally:
            other.pause_write_at = None
        machine.run_at(seal_sc, RETURN)
        self.assert_no_teardown(machine, 16)
        self.assertEqual(machine.get(GATE, 4), operations.OWNED)
        self.assertEqual(machine.get(MUTEX + session.LIFECYCLE, 4), session.LIVE)
        other.run_at(0x450504, operations.WRITE_SITE + 8)
        self.assertEqual(machine.get(GATE, 4), 0)
        self.assertEqual(frame, NATIVE_TOP - session.NATIVE_FRAME)

    def test_later_session_publication_does_not_reopen_the_sealed_gate(self):
        machine = self.machine()
        self.close(machine)
        machine.map(NEW_SESSION - 4, 0x24)
        machine.put(NEW_SESSION - 4, 0x20, 4)
        machine.seed_native_frame(session=NEW_SESSION)
        machine.run_at(session.INIT_SITE, session.INIT_SITE + 8)
        site = session.PUBLISH_SITES[0][0]
        machine.run_at(site, site + 8)
        self.assertEqual(machine.get(MUTEX + session.GENERATION, 4), 2)
        self.assertEqual(machine.get(GATE, 4), sealing.SEALED)
        self.assertEqual(machine.stock(identity.POST, 0, 0), 0xFFFFFFFF)
        self.assertEqual(machine.r[3], 16)
        self.assertEqual(machine.packet_allocations, [])

    def test_close_winning_after_operation_ll_rejects_the_stale_sc_before_ring_access(self):
        machine = self.machine()
        helper = (self.patches[operations.WRITE_SITE][1][0] & 0x3FFFFFF) << 2
        operation_sc = next(pc for pc in range(helper, helper + 256, 4)
                            if machine.word(pc) >> 26 == 0x38)
        machine.r[4], machine.r[6] = QUEUE, 8
        machine.run_at(operations.WRITE_SITE, operation_sc)
        self.assertEqual(machine.get(GATE, 4), 0)
        closer = machine.fork_cpu()
        self.close(closer)
        self.assertEqual(machine.retired_queues, {QUEUE})
        machine.run_at(operation_sc, operations.WRITE_SITE + 8)
        self.assertEqual((machine.r[2], machine.r[3]), (0xFFFFFFFF, 16))
        self.assertEqual(machine.get(GATE, 4), sealing.SEALED)
        self.assertEqual(machine.packet_allocations, [])
        self.assertEqual(machine.copy_calls, [])


if __name__ == '__main__':
    unittest.main()
