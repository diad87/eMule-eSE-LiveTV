import pathlib,re,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1];SRC=ROOT/"srchybrid"
H=(SRC/"LiveTunnelStreamFlow.h").read_text();C=(SRC/"LiveTunnelStreamFlow.cpp").read_text()
A=(SRC/"Kad6StreamTransportAdapter.cpp").read_text();K=(SRC/"Kad6GatewaySocket.cpp").read_text()
F=(SRC/"LiveTunnel.h").read_text()+(SRC/"LiveTunnel.cpp").read_text()
E=(SRC/"LiveExitServices.h").read_text()+(SRC/"LiveExitServices.cpp").read_text()
P=(SRC/"emule.vcxproj").read_text()
FIELDS="m_k6ExitStreams m_k6OriginStreams m_k6SendCredits m_k6ReceiveCredits m_k6FlowStreamsByCircuit".split()
class LT5StreamFlow(unittest.TestCase):
 def test_physical_owner_and_budget(self):
  for field in FIELDS:
   self.assertEqual(len(re.findall(rf"\b{field}\b",H)),1);self.assertNotIn(field,F)
  self.assertLessEqual(len(H.splitlines())+len(C.splitlines()),1200)
 def test_two_bound_modules_and_project(self):
  self.assertIn("M2A_BIND_LT5_AE4815B275",C+E);self.assertIn("M2A_BIND_LT5_AF2808989D",A+C)
  self.assertGreaterEqual(E.count("M2A_BIND_LT5_AE4815B275"),2);self.assertGreaterEqual(C.count("M2A_BIND_LT5_AF2808989D"),2)
  for name in ("LiveTunnelStreamFlow.cpp","Kad6StreamTransportAdapter.cpp"):self.assertIn(name,P)
 def test_closed_registration_and_credit_cleanup(self):
  for marker in ("Register","Remove","RegisterStream","RemoveStream","CreateExit","CreateOrigin","TakeExit","TakeOrigin"):self.assertIn(marker,A)
  self.assertNotIn("ForAdapter",H+E);self.assertNotRegex(H+E,r"LiveTunnel(?:Exit|Origin|Send|Receive|Flow)\\w*&")
 def test_stream_routes_left_the_coordinator(self):
  for name in ("ExitHandle_Kad6Dial","ActivateK6Inbound","OnK6ExitPacket"):
   self.assertNotIn(f"CLiveTunnel::{name}",F);self.assertIn(f"CLiveTunnel::{name}",K)
 def test_half_close_credit_and_late_socket_identity(self):
  for marker in ("HalfCloseExit","HalfCloseOrigin","CommitExitSend","CommitOriginSend","generation"):self.assertIn(marker,A+C)
  self.assertIn("LT5FindExit(m_streamId,this",K);self.assertIn("LT5FindOrigin(m_streamId,this",K)
  self.assertIn("OnK6ExitPacket(m_streamId",K);self.assertIn("K6SendEd2kFrameNoWait(m_streamId",K)
  self.assertIn("LT5FindExit(streamId,source",K);self.assertIn("LT5CommitOriginSend(source",F)
 def test_adapter_has_no_external_effects(self):
  for forbidden in ("SendK6GatewayPush","Disconnect(","InjectRawFrame","m_pendingLock","SetKad6"):self.assertNotIn(forbidden,A)
 def test_characterization_is_runtime_bound(self):
  for marker in ("RunLiveTunnelStreamFlowCharacterizationSelfTest","RunKad6StreamTransportAdapterCharacterizationSelfTest","InitialCredit","Accept(","Consume(","HalfCloseExit","CloseExit","CommitExitSend","CommitOriginSend"):self.assertIn(marker,C+A)
class LT5TypedEvidence(unittest.TestCase):
 def test_m2a_b8cea7b5a1086f24(self):self.assertIn("M2A_BIND_LT5_AF2808989D",A)
 def test_m2a_f11250c6e5435ecb(self):self.assertIn("M2A_BIND_LT5_AE4815B275",C)
 def test_m2a_9ad4a46cb1e9eca3(self):self.assertIn("LT5FindExit(m_streamId,this",K);self.assertIn("LT5FindOrigin(m_streamId,this",K)
 def test_m2a_6464359bd92ec86d(self):self.assertTrue(all(x in H for x in FIELDS))
 def test_m2a_2fd9073aa5b10256(self):self.assertIn("CLiveTunnel::ActivateK6Inbound",K)
 def test_m2a_c36b4e235a8e7d31(self):self.assertIn("CLiveTunnel::ExitHandle_Kad6Dial",K)
 def test_m2a_b7a05cea23a4fd8c(self):self.assertIn("CLiveTunnel::OnK6ExitPacket",K)
 def test_m2a_f0344019650805c0(self):self.assertIn("class Kad6StreamTransportAdapter",A.replace('.h','')+(SRC/"Kad6StreamTransportAdapter.h").read_text())
 def test_m2a_ab42833fb750cd28(self):self.assertIn("class LiveTunnelStreamFlow",H)
if __name__=="__main__":unittest.main()
