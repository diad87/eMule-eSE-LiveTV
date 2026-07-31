import pathlib,re,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1];SRC=ROOT/"srchybrid"
H=SRC/"LiveTunnelCoordinatorFacade.h";C=SRC/"LiveTunnelCoordinatorFacade.cpp"
P=SRC/"LiveTunnelCoordinatorPort.h";I=SRC/"LiveTunnelCoordinatorMethods.inl"
S=(SRC/"LiveTunnelScheduler.h").read_text()+(SRC/"LiveTunnelScheduler.cpp").read_text()
F=(SRC/"LiveTunnel.h").read_text()+(SRC/"LiveTunnel.cpp").read_text()
PROJECT=(SRC/"emule.vcxproj").read_text()
FIELDS=("m_k6GuardNodePub","m_k6GuardExpiresAt","m_k6GuardLoaded","m_rttPingSentTick","m_rttPingReqId")
class LT9CoordinatorFacade(unittest.TestCase):
 def setUp(self):
  for p in (H,C,P,I):self.assertTrue(p.is_file(),f"missing {p.name}")
  self.h,self.c,self.p,self.i=(p.read_text() for p in (H,C,P,I))
 def test_five_fields_have_one_physical_owner(self):
  for field in FIELDS:
   self.assertEqual(len(re.findall(rf"\b{field}\b",self.h)),1);self.assertNotIn(field,F+self.i)
 def test_scheduler_binding_and_project_are_physical(self):
  code=self.h+self.c+S
  for marker in ("M2A_BIND_LT9_A14692E28F","m_m2a_binding_a14692e28f"):self.assertIn(marker,code)
  self.assertIn("LiveTunnelCoordinatorFacade.cpp",PROJECT)
 def test_large_coordinator_methods_leave_translation_unit(self):
  for method in ("OnCellReceived","Tick"):
   self.assertIn(f"CLiveTunnel::{method}",self.i);self.assertNotIn(f"CLiveTunnel::{method}",F)
 def test_guard_and_rtt_boundaries_are_productive(self):
  code=self.c+S
  for marker in ("NeedStorage","CachedValid","CachedExpired","ConsumeRtt","RecordRtt","ClearRtt","0xfffffffau"):self.assertIn(marker,code)
  self.assertIn("RunLiveTunnelCoordinatorFacadeCharacterizationSelfTest",code)
 def test_budget(self):
  self.assertLessEqual(len(self.h.splitlines())+len(self.c.splitlines()),1200)
class LT9TypedEvidence(unittest.TestCase):
 def test_m2a_f5b0fcbb82723703(self):self.assertIn("M2A_BIND_LT9_A14692E28F",C.read_text())
 def test_m2a_fa5717f000d15b73(self):self.assertIn("LT9",H.read_text()+C.read_text())
 def test_m2a_55dc8aca9df2335f(self):self.assertTrue(all(f in H.read_text() for f in FIELDS))
 def test_m2a_7d1c955a3f65bf24(self):self.assertIn("CLiveTunnel::OnCellReceived",I.read_text())
 def test_m2a_8184c40e16be58c7(self):self.assertIn("CLiveTunnel::Tick",I.read_text())
 def test_m2a_4d226361b7bf07bd(self):self.assertIn("class LiveTunnelCoordinatorFacade",H.read_text())
if __name__=="__main__":unittest.main()
