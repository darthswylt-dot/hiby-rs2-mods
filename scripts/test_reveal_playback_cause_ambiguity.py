#!/usr/bin/env python3
"""Two modeled playback causes remain indistinguishable to current evidence.

PlaybackPublication below is the HOST model over owned identities, NOT stock
playback execution or a native notification producer. The immutable modeled
notification may name playback parent1 or parent2. Its source-shaped20-byte
UI message is deliberately UNLINKED and never consumed by the native fixture:
we do not invent a playback->0x140->FolderView edge.

The existing native-instruction renderer fixture independently receives the
same paint enqueue. Its callback/outer/renderer boundaries execute, with its
documented geometry/resource/SQL suffix stubs. Public raw request-age decoding
observes identical bytes in both worlds. This is an information/provenance
counterexample, not proof that either schedule occurred on hardware.
No firmware output, device, network, installer or UI action.
"""

from dataclasses import FrozenInstanceError, dataclass
import struct
import unittest

import decode_reveal_request_age as age
from folderfollow_reveal_model import Identity
from folderfollow_reveal_playback import PlaybackPublication
import test_reveal_renderer_transport_stage as native_fixture


A = Identity('\\SD1\\Slayer\\Show No Mercy\\01.flac', -1)
B = Identity('\\SD1\\Slayer\\Show No Mercy\\02.flac', 17)

# Shape only: the source474380 constructor has zero word0, event at4,
# scalar parameters at8/C and a time word at10. This equal opaque time value
# is fixture input, not an observed tick or a causal generation. The message
# is not delivered to454200/453940 or used to trigger the native paint below.
UNLINKED_UI_MESSAGE = struct.pack('<5I', 0, 0x140, 0, 7, 0x12345678)
CAPACITIES = dict(native_fixture.CAPACITIES)


@dataclass(frozen=True)
class ModeledPlaybackReceipt:
    ticket: int
    identity: Identity


@dataclass(frozen=True)
class ModeledNotification:
    notification_id: int
    playback_parent: int
    unlinked_message: bytes


@dataclass(frozen=True)
class ModeledWorld:
    receipts: tuple[ModeledPlaybackReceipt, ...]
    notification: ModeledNotification
    current_identity: Identity
    current_revision: int
    current_ready: bool
    model_timeline: tuple[str, ...]
    ui_revisions_during_model_publications: tuple[int, ...]


def modeled_world(playback_parent, machine):
    """Create the hidden cause outside native memory, with explicit ownership.

    Both histories publish A/1 then B/2. Only the modeled notification's
    creation point/immutable parent differs. Calling this function does not
    model a real firmware writer or notify the native fixture.
    """
    if playback_parent not in (1, 2):
        raise ValueError('the counterexample models exactly playback parents1/2')
    publication = PlaybackPublication()
    receipts, timeline, clocks = [], [], []
    notification = None
    revision_address = machine.meta['contents_revision_buffer']
    clocks.append(machine.get(revision_address, 4))
    for identity in (A, B):
        ticket = publication.begin(identity)
        if ticket is None or not publication.finish(ticket):
            raise AssertionError('owned host publication fixture failed')
        receipts.append(ModeledPlaybackReceipt(ticket, publication.identity))
        timeline.append('model-publication-' + str(ticket))
        clocks.append(machine.get(revision_address, 4))
        if ticket == playback_parent:
            notification = ModeledNotification(1, ticket, UNLINKED_UI_MESSAGE)
            timeline.append('model-notification-for-' + str(ticket))
    return ModeledWorld(tuple(receipts), notification, publication.identity,
                        publication.revision, publication.ready, tuple(timeline), tuple(clocks))


class RevealPlaybackCauseAmbiguityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture_class = native_fixture.RevealRendererTransportStageTests
        fixture_class.setUpClass()
        cls.fixture = fixture_class()

    def world_and_native_history(self, parent, *, rows=False):
        machine = self.fixture.machine()
        initial = machine.snapshot()
        world = modeled_world(parent, machine)
        # The modeled publication/notification has no installed native adapter
        # and changes neither private BSS nor any native message queue.
        self.assertEqual(machine.snapshot(), initial)
        self.assertEqual(machine.calls, [])
        # Independent, explicitly injected fixture paint; NOT notification
        # delivery, message dispatch, a playback callback or a UI scheduling test.
        machine.enqueue()
        machine.consume()
        if rows:
            root = machine.renderer_runs[0]['lineage']
            self.fixture.rows_from_root(machine, root)
        raw = machine.snapshot()
        decoded = age.decode(raw, **CAPACITIES)
        return world, machine, raw, decoded

    def two_worlds(self, *, rows=False):
        return (self.world_and_native_history(1, rows=rows),
                self.world_and_native_history(2, rows=rows))

    def assert_deny(self, result):
        self.assertEqual(result['decision'], 'deny')
        for flag in age.AUTHORITY_FLAGS:
            self.assertIs(result[flag], False, flag)

    def test_modeled_immutable_parents_differ_while_owned_current_publication_matches(self):
        older, newer = self.two_worlds()
        one, two = older[0], newer[0]
        self.assertEqual(one.receipts, two.receipts)
        self.assertEqual(one.receipts, (ModeledPlaybackReceipt(1, A), ModeledPlaybackReceipt(2, B)))
        self.assertEqual((one.notification.playback_parent, two.notification.playback_parent), (1, 2))
        for world in (one, two):
            self.assertEqual((world.current_identity, world.current_revision, world.current_ready), (B, 2, True))
            self.assertEqual(world.notification.notification_id, 1)
        self.assertNotEqual(one.model_timeline, two.model_timeline)
        self.assertEqual(one.model_timeline,
                         ('model-publication-1', 'model-notification-for-1', 'model-publication-2'))
        self.assertEqual(two.model_timeline,
                         ('model-publication-1', 'model-publication-2', 'model-notification-for-2'))

    def test_modeled_receipts_and_notification_parent_are_not_mutable_current_pointers(self):
        world, _, _, _ = self.world_and_native_history(1)
        with self.assertRaises(FrozenInstanceError):
            world.notification.playback_parent = 2
        with self.assertRaises(FrozenInstanceError):
            world.receipts[0].ticket = 2
        with self.assertRaises(FrozenInstanceError):
            world.receipts[0].identity.path = B.path
        self.assertIsInstance(world.notification.unlinked_message, bytes)
        self.assertEqual(world.receipts[0].identity, A)
        self.assertEqual(world.current_identity, B)

    def test_equal_source_shaped_message_does_not_serialize_its_modeled_parent(self):
        older, newer = self.two_worlds()
        self.assertEqual(older[0].notification.unlinked_message, newer[0].notification.unlinked_message)
        self.assertEqual(len(UNLINKED_UI_MESSAGE), 20)
        self.assertEqual(struct.unpack('<5I', UNLINKED_UI_MESSAGE),
                         (0, 0x140, 0, 7, 0x12345678))
        # Shape is not provenance: no claim that stock playback emitted this
        # message, nor that the renderer fixture ever consumed these20 bytes.
        for _, machine, _, _ in (older, newer):
            for absent in (0x474380, 0x454200, 0x453940, 0x42CAC0, 0x42CC60,
                           0x42CC0C, 0x42D6A0):
                self.assertNotIn(absent, machine.calls)

    def test_native_renderer_snapshots_and_public_age_results_are_byte_identical(self):
        older, newer = self.two_worlds()
        self.assertNotEqual(older[0].notification.playback_parent, newer[0].notification.playback_parent)
        self.assertEqual(older[2], newer[2])
        self.assertEqual(older[3], newer[3])
        self.assertEqual(older[3]['request_age_assessment'], newer[3]['request_age_assessment'])
        for _, machine, _, decoded in (older, newer):
            for native in (0x439EC0, 0x438200, 0x4906E0, 0x459340, 0xA5BEE0):
                self.assertEqual(machine.calls.count(native), 1)
            self.assertTrue(decoded['renderer_identity_associated'])
            self.assertTrue(decoded['renderer_transport_observation']['associations'][0]['observation_complete'])

    def test_unlinked_model_playback_changes_leave_the_same_ui_revision_unadvanced(self):
        for parent in (1, 2):
            with self.subTest(parent=parent):
                world, machine, _, decoded = self.world_and_native_history(parent)
                self.assertEqual([receipt.ticket for receipt in world.receipts], [1, 2])
                self.assertNotEqual(world.receipts[0].identity, world.receipts[1].identity)
                self.assertEqual(world.ui_revisions_during_model_publications, (0, 0, 0))
                self.assertEqual(machine.get(machine.meta['contents_revision_buffer'], 4), 1)
                self.assertEqual(decoded['known_contents_revision'], 1)
                request = decoded['request_age_assessment']['requests'][0]
                self.assertEqual((request['birth_revision'], request['outer_revision'],
                                  request['original_entry_revision'], request['renderer_revision']),
                                 (0, 0, 1, 1))
        # This proves independence in this explicit unlinked fixture, not that
        # every real playback transition leaves every native UI counter quiet.

    def test_no_known_age_conflict_is_unproven_deny_in_both_cause_worlds(self):
        for world, _, _, decoded in self.two_worlds():
            assessment = decoded['request_age_assessment']
            request = assessment['requests'][0]
            self.assertEqual(request['status'], 'unproven')
            self.assertFalse(request['known_boundary_conflict'])
            self.assertFalse(request['source_order_conflict'])
            self.assertEqual(request['extra_pre_entry_increments'], 0)
            self.assertEqual(request['early_renderer_revision_advance'], 0)
            self.assertIn('original-playback-and-ui-cause-unproved', request['unproven_reasons'])
            self.assertTrue(world.current_ready)
            self.assert_deny(assessment)
            self.assert_deny(request)
            for flag in age.AUTHORITY_FLAGS:
                self.assertIs(decoded[flag], False)

    def test_public_raw_report_explicitly_states_the_unobserved_playback_cause_limit(self):
        caveat = ('Known UI revision/scope samples are not proven to observe every playback publication; '
                  'equal intervals cannot recover the original playback cause.')
        for _, _, raw, _ in self.two_worlds():
            # Only owned native bytes enter the public API; neither the model
            # publication nor its hidden notification parent is passed in.
            decoded = age.decode(raw, **CAPACITIES)
            assessment = decoded['request_age_assessment']
            self.assertIn(caveat, assessment['limitations'])
            self.assert_deny(assessment)
            for request in assessment['requests']:
                self.assert_deny(request)

    def test_late_current_playback_ticket_would_choose_the_wrong_modeled_parent_in_one_world(self):
        older, newer = self.two_worlds()
        late_candidates = [world.current_revision for world, _, _, _ in (older, newer)]
        actual_modeled_parents = [world.notification.playback_parent for world, _, _, _ in (older, newer)]
        self.assertEqual(late_candidates, [2, 2])
        self.assertEqual(actual_modeled_parents, [1, 2])
        self.assertNotEqual(late_candidates[0], actual_modeled_parents[0])
        # Counterexample to late stamping only; this is not an implemented
        # adapter and does not attach either candidate to real native receipts.
        self.assertEqual(older[3]['request_age_assessment'], newer[3]['request_age_assessment'])

    def test_local_native_birth_number_is_not_a_cross_namespace_playback_parent(self):
        older, newer = self.two_worlds()
        birth_ids = [decoded['request_age_assessment']['requests'][0]['birth']
                     for _, _, _, decoded in (older, newer)]
        self.assertEqual(birth_ids, [1, 1])
        self.assertEqual([world.notification.playback_parent for world, _, _, _ in (older, newer)], [1, 2])
        for _, _, _, decoded in (older, newer):
            request = decoded['request_age_assessment']['requests'][0]
            for unobserved in ('playback_parent', 'playback_ticket', 'notification_parent',
                               'original_playback_cause'):
                self.assertNotIn(unobserved, request)
            self.assert_deny(request)

    def test_even_explicit_renderer_row_links_do_not_recover_the_unlinked_playback_parent(self):
        older, newer = self.two_worlds(rows=True)
        self.assertEqual(older[2], newer[2])
        self.assertEqual(older[3], newer[3])
        for _, _, _, decoded in (older, newer):
            linked = decoded['renderer_row_associations'][0]
            self.assertTrue(linked['observed_row_identity_associated'])
            self.assertEqual(linked['row_event_sequences'], [1])
            self.assertFalse(decoded['windows'][0]['complete'])
            self.assertIn('known-contents-boundary', decoded['windows'][0]['reasons'])
            request = decoded['request_age_assessment']['requests'][0]
            self.assertEqual(request['status'], 'unproven')
            self.assertFalse(request['known_boundary_conflict'])
            self.assertEqual(request['later_revision_advance'], 3)
            self.assert_deny(request)
            self.assertFalse(decoded['request_freshness_proven'])


if __name__ == '__main__':
    unittest.main()
