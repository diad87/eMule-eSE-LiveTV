import pathlib,re,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1];SRC=ROOT/"srchybrid"
H,C=SRC/"LiveTunnelSearchService.h",SRC/"LiveTunnelSearchService.cpp"
P,I=SRC/"LiveTunnelSearchPort.h",SRC/"LiveTunnelSearchFacade.inl"
R=(SRC/"LiveRelayDispatcher.h").read_text()+(SRC/"LiveRelayDispatcher.cpp").read_text()
F=(SRC/"LiveTunnel.h").read_text()+(SRC/"LiveTunnel.cpp").read_text()
K=(SRC/"Kad6GatewaySocket.cpp").read_text();PROJECT=(SRC/"emule.vcxproj").read_text()
FIELDS=("m_searchJobs","m_k6SearchReplies")
class LT8SearchService(unittest.TestCase):
 def setUp(self):
  for p in (H,C,P,I):self.assertTrue(p.is_file(),f"missing {p.name}")
  self.h,self.c,self.p,self.i=(p.read_text() for p in (H,C,P,I))
 def test_two_fields_have_one_physical_owner(self):
  for field in FIELDS:
   self.assertEqual(len(re.findall(rf"\b{field}\b",self.h)),1)
   self.assertNotIn(field,F+K+self.i)
 def test_parent_binding_and_project_are_physical(self):
  code=self.h+self.c+R
  for marker in ("M2A_BIND_LT8_17641C1557","m_m2a_binding_17641c1557"):self.assertIn(marker,code)
  self.assertIn("LiveTunnelSearchService.cpp",PROJECT)
 def test_search_routes_left_the_coordinator_translation_unit(self):
  for method in ("ExitHandle_KadSearch","ExitHandle_KadSearchV2","ExitHandle_KadCancel",
                 "FinishDueSearchJobs","SendK6SearchResults","SerializeSearchResults",
                 "StopSearchJobKad","TunneledKadSearch","SendKadSearchV2NoWait"):
   self.assertIn(f"CLiveTunnel::{method}",self.i)
   self.assertNotIn(f"CLiveTunnel::{method}",F)
 def test_owner_has_closed_state_operations(self):
  code=self.h+self.c+self.p+R
  for marker in ("AddJob","UpdateJob","FindJob","TakeJob","TakeDue","AppendReply",
                 "TakeReply","SweepReplies","JobCount"):self.assertIn(marker,code)
  for forbidden in ("LiveTunnel.h","Kad6GatewaySocket.h","CUpDownClient","SendReply("):self.assertNotIn(forbidden,self.c)
 def test_result_bounds_and_cancel_are_characterized(self):
  code=self.c+self.i+K
  for marker in ("EmptySearch","ResultLimit","CanceledBeforeResponse","ByteExactSerialization",
                 "StrictExpiryBoundary","kK6SearchMaxResults","TUN_MSG_MAX_BYTES"):self.assertIn(marker,code)
  self.assertIn("RunLiveTunnelSearchServiceCharacterizationSelfTest",code)
 def test_dispatch_does_not_rebind_or_run_characterization(self):
  dispatch=R.split("bool LiveRelayDispatcher::DispatchExitPlain",1)[1].split("namespace {",1)[0]
  self.assertNotIn("M2A_BIND_LT8",dispatch);self.assertNotIn("RunLiveTunnelSearchServiceCharacterizationSelfTest",dispatch)
  self.assertIn("return RunLiveTunnelSearchServiceCharacterizationSelfTest();",R.split("bool RunLiveRelayDispatcherCharacterizationSelfTest()",1)[1])
 def test_budget(self):
  self.assertLessEqual(len(self.h.splitlines())+len(self.c.splitlines()),900)
class LT8TypedEvidence(unittest.TestCase):
 def test_m2a_9d23bbdd7ecfd1ae(self):self.assertIn("M2A_BIND_LT8_17641C1557",C.read_text())
 def test_m2a_2712cf26e8aad695(self):self.assertIn("LT8",H.read_text()+C.read_text())
 def test_m2a_04b5850b04cdd54a(self):self.assertTrue(all(f in H.read_text() for f in FIELDS))
 def test_m2a_89a42fee22dfa9c2(self):self.assertIn("CLiveTunnel::SendK6SearchResults",I.read_text())
 def test_m2a_7b7ff7d2da7cd42e(self):self.assertIn("class LiveTunnelSearchService",H.read_text())
if __name__=="__main__":unittest.main()
