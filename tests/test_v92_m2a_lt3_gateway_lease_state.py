import pathlib, re, unittest
ROOT = pathlib.Path(__file__).resolve().parents[1]; SOURCE = ROOT / "srchybrid"
HEADER = (SOURCE / "LiveTunnelGatewayLeaseState.h").read_text(); MODULE = (SOURCE / "LiveTunnelGatewayLeaseState.cpp").read_text(); PROJECT = (SOURCE / "emule.vcxproj").read_text()
FACADE = (SOURCE / "LiveTunnel.h").read_text() + (SOURCE / "LiveTunnel.cpp").read_text(); ADAPTER = (SOURCE / "Kad6GatewaySocket.cpp").read_text() + (SOURCE / "LiveTunnelKadBridge.cpp").read_text()
FIELDS = "m_k6SourceLeases m_k6CohortScheduler m_k6PublishBudget m_k6PublishCoalescer m_k6SourceEpochs m_k6SourceEpochsLoaded m_k6SourceEpochsLoadFailed".split()
class LT3GatewayLeaseState(unittest.TestCase):
    def test_m2a_8361971c3c55d862(self): self.assertIn("M2A_BIND_LT3_876B98A826", MODULE); self.assertIn("LiveTunnelGatewayLeaseState.cpp", PROJECT)
    def test_m2a_fe21d0385211283f(self): self.assertIn("class LiveTunnelGatewayLeaseState", HEADER); self.assertIn("LiveTunnelGatewayLeaseBridge", HEADER); self.assertIn("LiveTunnelGatewayLeaseSnapshot", HEADER)
    def test_m2a_04e01195c0f36944(self):
        self.assertTrue(FIELDS and all(field in HEADER for field in FIELDS))
        for field in FIELDS:
            self.assertEqual(len(re.findall(rf"\b{re.escape(field)}\b", HEADER)), 1)
            self.assertNotIn(field, FACADE)
    def test_m2a_7cb8b48c407e166e(self): self.assertLessEqual(len(HEADER.splitlines()) + len(MODULE.splitlines()), 1150); self.assertIn("LiveTunnelGatewayLeaseState.h", PROJECT); self.assertNotIn("kad6/", HEADER); self.assertNotIn("LiveTunnel.h", HEADER)
    def test_m2a_88ad59d981d59433(self): self.assertIn("LT3PlanSearchReply", FACADE); self.assertIn("LT3ExecuteSearchReply", FACADE); self.assertIn("m_pendingRequests.IsLive(req_id)", ADAPTER)
    def test_m2a_514364f62fdd31fb(self): self.assertIn("LT3PlanExitGateway", FACADE); self.assertIn("LT3ExecuteExitGateway", FACADE); self.assertIn("M2A_LT3_PlanGatewayFrameBridge", ADAPTER)
    def test_boundary_is_value_only(self): self.assertNotIn("K6SourceLease*", HEADER); self.assertNotIn("K6SourceLease *", HEADER); self.assertIn("LiveTunnelGatewayLeaseSnapshot", HEADER); self.assertIn("std::vector<std::uint8_t>", HEADER)
