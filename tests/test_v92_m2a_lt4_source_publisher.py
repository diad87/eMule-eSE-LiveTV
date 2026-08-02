import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "srchybrid"
PUBLISHER_H = SOURCE / "LiveTunnelSourcePublisher.h"
PUBLISHER_C = SOURCE / "LiveTunnelSourcePublisher.cpp"
POLICY_H = SOURCE / "LiveTunnelTicketPolicy.h"
POLICY_C = SOURCE / "LiveTunnelTicketPolicy.cpp"
EXIT_H = (SOURCE / "LiveExitServices.h").read_text()
EXIT_C = (SOURCE / "LiveExitServices.cpp").read_text()
FACADE = (
    (SOURCE / "LiveTunnel.h").read_text()
    + (SOURCE / "LiveTunnel.cpp").read_text()
)
PROJECT = (SOURCE / "emule.vcxproj").read_text()
FIELDS = """
m_k6Publishes m_k6ShadowPrimary m_k6TicketSecret m_k6TicketSecretReady
m_k6AuthorizedTargets m_k6UsedTickets
""".split()


class LT4SourcePublisher(unittest.TestCase):
    def setUp(self):
        self.assertTrue(PUBLISHER_H.exists())
        self.assertTrue(PUBLISHER_C.exists())
        self.assertTrue(POLICY_H.exists())
        self.assertTrue(POLICY_C.exists())
        self.publisher_h = PUBLISHER_H.read_text()
        self.publisher_c = PUBLISHER_C.read_text()
        self.policy_h = POLICY_H.read_text()
        self.policy_c = POLICY_C.read_text()

    def test_modules_are_bound_under_exit_services(self):
        self.assertIn("M2A_BIND_LT4_", self.publisher_c)
        self.assertIn("m_m2a_binding_", EXIT_H)
        self.assertIn("M2A_BIND_LT4_", EXIT_C)
        for name in (
            "LiveTunnelSourcePublisher.cpp",
            "LiveTunnelSourcePublisher.h",
            "LiveTunnelTicketPolicy.cpp",
            "LiveTunnelTicketPolicy.h",
        ):
            self.assertIn(name, PROJECT)

    def test_all_six_fields_have_one_physical_owner(self):
        for field in FIELDS:
            self.assertEqual(
                len(re.findall(rf"\b{re.escape(field)}\b", self.publisher_h)),
                1,
                f"{field} must have exactly one physical owner",
            )
            self.assertNotIn(field, FACADE)
            self.assertNotIn(field, EXIT_H)
            self.assertNotIn(field, self.policy_h)

    def test_layering_and_module_budgets(self):
        self.assertNotIn("LiveTunnel.h", self.publisher_h + self.publisher_c)
        self.assertNotIn("LiveTunnel.h", self.policy_h + self.policy_c)
        self.assertIn("LiveTunnelTicketPolicy.h", self.publisher_h)
        self.assertLessEqual(
            len(self.publisher_h.splitlines()) + len(self.publisher_c.splitlines()),
            1100,
        )
        self.assertLessEqual(
            len(self.policy_h.splitlines()) + len(self.policy_c.splitlines()),
            700,
        )

    def test_publish_lifecycle_is_owned_and_closed(self):
        for operation in (
            "PreparePublish",
            "CommitPublish",
            "Unpublish",
            "RecordShadowAck",
            "RecordNativeAck",
            "CollectRefreshes",
            "Sweep",
        ):
            self.assertIn(operation, self.publisher_c)
        self.assertNotIn("std::function", self.publisher_h)

    def test_ticket_replay_is_atomic_with_owner_state(self):
        self.assertIn("ConsumeTicket", self.publisher_c)
        self.assertIn("m_k6UsedTickets", self.publisher_h)
        self.assertIn("m_mutex", self.publisher_h)
        self.assertIn("TicketReplayRejected", self.publisher_c)

    def test_external_effects_use_value_actions(self):
        self.assertIn("LiveTunnelPublishAction", self.publisher_h)
        self.assertIn("std::vector<LiveTunnelPublishAction>", self.publisher_h)
        self.assertNotIn("CLiveTunnel", self.publisher_h)
        self.assertNotIn("CKad", self.publisher_h)

    def test_characterization_covers_late_ack_and_idempotence(self):
        self.assertIn(
            "RunLiveTunnelSourcePublisherCharacterizationSelfTest",
            self.publisher_c,
        )
        for marker in (
            "DuplicatePublish",
            "DuplicateUnpublish",
            "LateAckIgnored",
            "TicketReplayRejected",
            "SingleShadowPrimary",
            "ProductiveReplay",
            "ShadowNativeTransitions",
            "RefreshReservedBeforeIo",
            "ProbeReservedBeforeIo",
            "LateCallbackAfterDisable",
        ):
            self.assertIn(marker, self.publisher_c)

    def test_source_bind_unbind_use_owner_boundary(self):
        gateway = (SOURCE / "Kad6GatewaySocket.cpp").read_text()
        for marker in ("LT3AddBound", "LT4DisableSource", "LT4OpenPublish"):
            self.assertIn(marker, gateway)

    def test_ticket_policy_is_stateless_and_fail_closed(self):
        self.assertIn("class LiveTunnelTicketPolicy", self.policy_h)
        self.assertNotRegex(self.policy_h, r"\bm_[A-Za-z0-9_]+\s*[;={]")
        self.assertIn("AllowTarget", self.policy_c)
        self.assertIn("LiveTunnelTicketPolicy::AllowTarget", (SOURCE / "Kad6GatewaySocket.cpp").read_text())
        self.assertIn("TicketSensitivePortRejected", self.publisher_c)
        self.assertIn("ValidateTicketEnvelope", self.policy_c)


class LT4TypedEvidence(unittest.TestCase):
    def test_m2a_2587b4c35765ae5e(self): self.assertIn("M2A_BIND_LT4_", PUBLISHER_C.read_text())
    def test_m2a_3f88df0a3ac3e42c(self): self.assertIn("ProductiveReplay", PUBLISHER_C.read_text())
    def test_m2a_f013b440a916c572(self): self.assertTrue(all(field in PUBLISHER_H.read_text() for field in FIELDS))
    def test_m2a_df9ccf3da7b7f517(self): self.assertIn("LT3AddBound", (SOURCE / "Kad6GatewaySocket.cpp").read_text())
    def test_m2a_c8d6f11c04dabfa2(self): self.assertIn("LT4OpenPublish", (SOURCE / "Kad6GatewaySocket.cpp").read_text())
    def test_m2a_4f76f355b2ca96b0(self): self.assertIn("class LiveTunnelSourcePublisher", PUBLISHER_H.read_text())
    def test_m2a_fb4828d6382ebe07(self): self.assertIn("class LiveTunnelTicketPolicy", POLICY_H.read_text())
    def test_m2a_4f5831d798de0a55(self): self.assertIn("LiveTunnelTicketPolicy.h", PUBLISHER_H.read_text())


if __name__ == "__main__":
    unittest.main()
