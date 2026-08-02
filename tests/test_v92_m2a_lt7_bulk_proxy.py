import pathlib,re,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]; SRC=ROOT/"srchybrid"
PH,PC=SRC/"LiveTunnelBulkProxy.h",SRC/"LiveTunnelBulkProxy.cpp"
AH,AC=SRC/"LiveTunnelBulkTransportAdapter.h",SRC/"LiveTunnelBulkTransportAdapter.cpp"
FACADE_HEADER=(SRC/"LiveTunnel.h").read_text()
FACADE=FACADE_HEADER+(SRC/"LiveTunnel.cpp").read_text()+(SRC/"LiveTunnelBulkFacade.inl").read_text()
PROJECT=(SRC/"emule.vcxproj").read_text()
FIELDS="""m_bulkReasm m_bulkReplay m_proxyIngestLock m_proxyKeys m_proxyFragReasm
m_proxyReady m_bulkSubs m_proxyRecent m_proxyCtl m_reassembly m_exitLiveSubs""".split()
class LT7BulkProxy(unittest.TestCase):
 def setUp(self):
  for p in (PH,PC,AH,AC): self.assertTrue(p.is_file(),f"missing {p.name}")
  self.ph,self.pc,self.ah,self.ac=(p.read_text() for p in (PH,PC,AH,AC))
 def test_eleven_fields_have_one_physical_owner(self):
  for f in FIELDS:
   self.assertEqual(len(re.findall(rf"\b{re.escape(f)}\b",self.ph)),1)
   self.assertNotRegex(FACADE_HEADER,rf"(?:std::map|std::deque|std::set|std::mutex|CCriticalSection)[^;\n]*\b{re.escape(f)}\b")
 def test_parent_and_transport_are_physically_bound(self):
  code=self.ph+self.pc+self.ah+self.ac+(SRC/"LiveExitServices.h").read_text()
  for marker in ("M2A_BIND_LT7_9EA638E856","M2A_BIND_LT7_CAC245F7E7",
                 "m_m2a_binding_9ea638e856","m_m2a_binding_cac245f7e7"): self.assertIn(marker,code)
  for name in ("LiveTunnelBulkProxy.cpp","LiveTunnelBulkTransportAdapter.cpp"): self.assertIn(name,PROJECT)
 def test_transport_facade_uses_bound_replay_adapter(self):
  for method in ("OnBulkCellReceived","SendBulkCellReverse","DeliverBulkData","BulkSubscribe","SendBulkNack"):
   self.assertIn(f"CLiveTunnel::{method}",FACADE)
  self.assertIn("AcceptReplay",self.ac)
 def test_proxy_facade_uses_extracted_state_without_reverse_includes(self):
  for method in ("DeliverBulkPlain","SweepBulkReasm","ExitProxyOnFragment","ProcessProxyIngest",
                 "ExitHandle_BulkSubscribe","ExitHandle_BulkNack","IngestRelayFragment","ExitHandle_LiveSubscribe"):
   self.assertIn(f"CLiveTunnel::{method}",FACADE)
  for concrete in ("LiveTunnel.h","Kad6GatewaySocket.h","ListenSocket.h"): self.assertNotIn(concrete,self.pc)
  self.assertNotIn("LiveTunnelBulkProxy.h",self.ac)
 def test_memory_and_replay_bounds_remain_enforced(self):
  code=self.pc+self.ac+self.ph+FACADE
  for marker in ("ESE_FRAG_MAX_CONCURRENT","ESE_FRAG_MAX_TOTAL","LT7_STATE(ProxyReadyQueue).size() > 64",
                 "LT7_STATE(ProxyRecentRecords).size() > 48","BulkReplayWindow","AcceptReplay","BULK_SUB_TTL_MS"): self.assertIn(marker,code)
 def test_external_callbacks_follow_snapshot_or_unlock(self):
  self.assertIn("std::vector<DeadProxy> dead",FACADE)
  self.assertRegex(FACADE,r"CSingleLock pending[\s\S]+?\n\s*\}\n[\s\S]{0,300}ExitProxyUnsubscribe")
  self.assertIn("ready.swap(LT7_STATE(ProxyReadyQueue))",FACADE)
 def test_productive_characterization_is_on_runtime_path(self):
  code=self.pc+self.ac; self.assertIn("RunLiveTunnelBulkProxyCharacterizationSelfTest",code)
  self.assertIn("RunLiveTunnelBulkStateCharacterizationSelfTest",FACADE)
  for marker in ("AcceptReplay(7, 100)","sequence = 200","AcceptFragment(","RemoveCircuitReassembly(7)","SweepRelayReassembly(10, 5)","Clear()"): self.assertIn(marker,code)
 def test_lt5_compatibility_bridge_remains_productive(self):
  k=(SRC/"Kad6GatewaySocket.cpp").read_text();self.assertIn("M2A_LT5CommitOriginSendCompat(m_exitServices,source,streamId,stream.generation",k);self.assertRegex((SRC/"LiveTunnel.cpp").read_text(),r"bool M2A_LT5CommitOriginSendCompat\([^)]*\)\{return exitServices\.LT5CommitOriginSend\(source,streamId,generation,0,bytes,remaining,quota,headroom\);\}")
 def test_budgets(self):
  self.assertLessEqual(len(self.ph.splitlines())+len(self.pc.splitlines()),1100)
  self.assertLessEqual(len(self.ah.splitlines())+len(self.ac.splitlines()),900)
class LT7TypedEvidence(unittest.TestCase):
 def test_m2a_9bf6e72ab0b92d23(self): self.assertIn("M2A_BIND_LT7_9EA638E856",PC.read_text())
 def test_m2a_8a7a23468fb0bff0(self): self.assertIn("M2A_BIND_LT7_CAC245F7E7",AC.read_text())
 def test_m2a_51677273a8941640(self): self.assertIn("LT7",PH.read_text()+PC.read_text())
 def test_m2a_3319ec69e12e92b9(self): self.assertTrue(all(f in PH.read_text() for f in FIELDS))
 def test_m2a_e9ebf476286cf919(self): self.assertIn("class LiveTunnelBulkProxy",PH.read_text())
 def test_m2a_34348d5d98795ade(self): self.assertIn("class LiveTunnelBulkTransportAdapter",AH.read_text())
if __name__=="__main__": unittest.main()
